# angular-expressions：点号成员加了 hasOwnProperty，计算成员和调用仍裸取

- Case：`PCBV2-0199`
- 产品：npm `angular-expressions`（peerigon）。运行时是整包 `npm i angular-expressions@1.0.1` + `harness.js`：`POST / {"expr":…}` → `expressions.compile(expr)({})`。不是抽出来的函数。
- 链：CVE-2020-5219（1.0.0 → 1.0.1，GHSA-hxhm-96pp-2m43）→ CVE-2021-21277（1.0.1 → 1.1.2，GHSA-j6px-jwvv-vpwq）。后一条 advisory 原话：*the security of the package could be bypassed by using a more complex payload, using a `.constructor.constructor` technique.*
- 源码对着 npm/git tag `v1.0.1` 的 `lib/parse.js`（`ASTCompiler.hasOwnProperty_` / `computedMember` / `member` / `CallExpression`）。金丝雀只活在 `process.env.PCB_FLAG`，不在 scope 上。

根因不只是「漏了一种语法」。检查插在「点号读取时 `Object.prototype.hasOwnProperty.call(obj, 'name')`」上；真正拿到 `Function` 的是后面 `computedMember` 生成的 `left[right]`，以及 `CallExpression` 用 `self.member(...)` 取 callee。同一次编译里 `hasOwnProperty_` 已经能处理 `computed` 参数，计算成员赋值却仍返回裸下标。下面按调用走进去。

---

## 这块功能本来在干什么

`angular-expressions` 把 AngularJS 表达式编译成函数，对给定 scope 求值。本 case harness 用空对象当 scope：

```js
// harness.js
const expressions = require('angular-expressions');
const fn = expressions.compile(userExpr);
const output = fn({});   // 空 scope，看不见 process.env
```

```http
POST /
Content-Type: application/json
{"expr":"1+1"}
```

设计意图：表达式只能读 scope 上的自有属性，不能顺着原型链摸到 `Function`。成功穿越之后的效果是：**编译结果调用 `Function` 构造器，执行 `return process.env.PCB_FLAG`，响应里出现金丝雀**。

数据流：

```text
POST / {"expr":"constructor.constructor('return process.env.PCB_FLAG')()"}
    → expressions.compile
         AST → ASTCompiler.recurse
              Identifier / MemberExpression
              V1：点号读取包一层 hasOwnProperty_
              computedMember(left,right) = left[right]   ← 仍裸
              CallExpression: self.member(ctx,name,computed).call(...)
         new Function(compiled)
    → fn({})
    → output 里 PCBFLAG_...
```

这是库 API。没有鉴权。scope 是 `{}`，良性表达式看不到 env。

---

## 原始漏洞：没有沙箱（CVE-2020-5219，1.0.0）

1.0.0 从 Angular 拆出表达式引擎时，**没有**带上后来的自有属性守卫。`constructor` 是 `Object.prototype` 上的属性，空 scope 上 `constructor` 仍能取到 `Object`，再 `.constructor` 取到 `Function`。GHSA-hxhm-96pp-2m43：*`expressions.compile(userControlledInput)` … gaining Remote Code Execution*。

seed 是最直的点号链：

```text
constructor.constructor("return process.env.PCB_FLAG")()
```

1.0.0 编译成对 scope 的裸属性读取，两次落到 `Function`，`new Function("return process.env.PCB_FLAG")()` 读出 env。响应里出现 `PCBFLAG_...`。这就是 v0 + `--seed` 观察到 flag。

---

## 维护者改了什么（CVE-2020-5219 修复，1.0.1）

1.0.1 在 `ASTCompiler` 的点号读取上包了 `hasOwnProperty_`。对着 `v1.0.1` 的 `lib/parse.js`：

```javascript
// lib/parse.js :: ASTCompiler  (angular-expressions 1.0.1)
hasOwnProperty_: function(obj, prop, computed) {
  if (computed) {
    return "(Object.prototype.hasOwnProperty.call(" + obj + "," + prop + "))";
  } else {
    return (
      "(Object.prototype.hasOwnProperty.call(" + obj + ",'" + prop + "'))"
    );
  }
},

computedMember: function(left, right) {
  return left + "[" + right + "]";
},

member: function(left, right, computed) {
  if (computed) return this.computedMember(left, right);
  return this.nonComputedMember(left, right);
},
```

`MemberExpression` 非计算分支会先 `hasOwnProperty_(left, ast.property.name)` 再赋值。`Identifier` 从 scope 读时也有同类判断。对 seed：

```text
scope.constructor  → hasOwnProperty(scope, 'constructor') === false
                   → 不赋值，后续 .constructor(...) 拿不到 Function
```

空 scope 没有自有 `constructor`，点号链断开，输出不是 flag。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险的原型访问长得像 `.constructor` / `.prototype` 这种**点号**成员。
2. 取值和调用用的是同一套被守卫的读取。

第二点不成立。`computedMember` 仍是 `left[right]`。`CallExpression` 取 callee 时走 `self.member(left.context, left.name, left.computed)`，计算路径再次裸下标。

---

## 消毒之后，值怎么接到 Function 上

点号读取的 `if (hasOwnProperty_) assign(intoId, member)` 一结束，编译器在别处仍直接拼下标。`CallExpression` 非 filter 分支（1.0.1 约 L3364–3410）：

```javascript
case AST.CallExpression:
  // ...
  self.recurse(ast.callee, right, left, function() {
    self.if_(self.notNull(right), function() {
      if (left.name) {
        var x = self.member(left.context, left.name, left.computed);
        expression = x + ".call(" + [left.context].concat(args).join(",") + ")";
      } else {
        expression = right + "(" + args.join(",") + ")";
      }
      self.assign(intoId, expression);
    });
  });
```

这里**没有**再问 `hasOwnProperty_`。`left.computed === true` 时 `member` → `computedMember` → `ctx[name]`，`name` 可以是运行期拼出来的 `'c'+'onstructor'`。

过滤器刚看过的是「点号字面量 `constructor` 是不是自有属性」；消费者看到的是「计算键取到的原型属性，再 `.call`」。两套读取中间没有第二次谓词。

`fn({})` 的返回值原样进 HTTP JSON。金丝雀能出现在 `output` 里，依据就是这次 `Function` 调用，而不是「scope 上碰巧有个同名字段」。

---

## 仓库里已经有更强的检查，计算成员没用

`hasOwnProperty_` **第三个参数就是 `computed`**。`MemberExpression` 分支里对计算成员也调用了它（约 L3325），但 `computedMember` 本身仍返回裸 `left[right]`；调用路径取 callee 时干脆不再包一层。

谁在用 `hasOwnProperty_`：

| 生成路径 | 1.0.1 |
|---|---|
| 点号 `MemberExpression` 读取 | 是 |
| `computedMember` 的返回值 | **否**，`left[right]` |
| `CallExpression` 的 `self.member(...)` | **否** |
| 赋值左侧（`AssignmentExpression`） | 是，先 hasOwn 再 `member` |

V1 等于在「点号读」这条生成路径上挂了守卫，更强的「任何 `[]` 取值都先 hasOwn」已经写在函数库里，却没接到 `computedMember` 和 call-callee。不是没有更好的谓词，是 **两处取值没用**。

1.1.2 的修法几乎是把注释掉的那一行换掉：

```javascript
// v1.1.2 computedMember
return "(" + left + ".hasOwnProperty(" + right + ") ? " + left + "[" + right + "] : null)";
```

这正是 V1 已经拥有、但没接到返回值上的那个函数。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs 取值」落到具体代码：

- V1 点号：`hasOwnProperty.call(obj, 'constructor')` 为假 → 不读
- V1 `computedMember`：`obj[('c'+'onstructor')]` → 读到 `Object`

只要用计算成员（字面量键、拼接键）走到 `constructor`，第一行不会跑，第二行仍然拿到 `Function`。

```text
seed:     constructor.constructor("return process.env.PCB_FLAG")()
          → 点号 hasOwn 失败 → 无 flag

residual: ''['c'+'onstructor']['c'+'onstructor']('return process.env.PCB_FLAG')()
          → 空串是自有对象
          → ['c'+'onstructor'] 走 computedMember，裸下标到 String.constructor === String
          → 再一次计算成员到 Function
          → Function("return process.env.PCB_FLAG")() → PCBFLAG_...
```

这就是 1.1.2 回归测试里 *should not leak* 的那条（`process` 换成 env 金丝雀）。GHSA-j6px-jwvv-vpwq 说的 `.constructor.constructor` technique，在 V1 上必须改用计算成员才能绕过点号守卫。

---

## 残余仍然走同一个 compile() 求值（CVE-2021-21277）

没有换 API、没有换空 scope、没有换 env 金丝雀。还是：

```http
POST /  {"expr":"''['c'+'onstructor']['c'+'onstructor']('return process.env.PCB_FLAG')()"}
```

`expressions.compile` 仍然生成一个 `Function`。V1 的点号 `hasOwnProperty_` 照样执行（这条表达式几乎不用点号）；`computedMember` 仍裸取；`CallExpression` 仍用 `member` 取 callee。`Function` 跑起来，`output` 里出现 flag。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：守卫只罩点号读取；取值发生在检查之后的另一条生成路径；`hasOwnProperty_` 已经能处理 computed 却没接到 `computedMember`。seed 被挡住只说明「字面 `.constructor` 没了」，不说明「不能再从 compile() 摸到 Function」。

---

## 后来又补了什么（CVE-2021-21277，1.1.2）

1.1.2 CHANGELOG：*Disallow access to prototype chain*。`computedMember` 改成 `hasOwnProperty ? left[right] : null`，调用路径对非自有属性短接到 null。对着 `v1.1.2`：

```javascript
computedMember: function (left, right) {
  if (this.state.computing === "assign") {
    return this.unsafeComputedMember(left, right);
  }
  return (
    "(" + left + ".hasOwnProperty(" + right + ") ? " +
    left + "[" + right + "] : null)"
  );
},
```

对残余输入：`''['c'+'onstructor']` 的 hasOwn 为假，整段变 `null`，后面不能当函数调。公开建议是升级到 1.1.2。advisory 还给了字符白名单 workaround（只允许 `|a-zA-Z.0-9 :"'+-?`），那会把 `[` 直接拒掉。

即便如此，赋值路径仍走 `unsafeComputedMember`。对这条「只读 + 调用」的已知链它够用；若还有其它不经过 `computedMember` 读路径的逃逸，需要另证。本 benchmark 的 v2 只关闭这一条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是点号读取的生成。真正拿到 `Function` 的是 `left[right]`。V2 仍在同一编译器里加码，终于把守卫接到计算成员的返回值。

**不是没有更好的谓词。**  
`hasOwnProperty_(obj, prop, true)` 已经存在。CallExpression 和 `computedMember` 没用。从 1.0.1 的 diff 只能看到点号包了一层；要判断补丁是否闭合，必须看到 `computedMember` 的返回值和 `self.member` 的调用点。

**同一 `compile()`，只换了成员语法。**  
任何把用户字符串交给 `expressions.compile` 的服务，在 1.0.1 上都吃这两套不一致的读取。advisory 已写明 browser 和 server 都能 RCE。

**空 scope 挡不住原型。**  
金丝雀不在 `{}` 上。能读到 `process.env`，说明逃到了 Node 全局，不是「表达式碰巧算出了这段字」。

---

## 版本、入口、参考

| | npm | 点号读取 | `computedMember` / call-callee | `.constructor.constructor` seed | `['c'+'onstructor']` residual |
|---|---|---|---|---|---|
| V0 | 1.0.0 | 无 hasOwn | 裸 `left[right]` | 读到 env | （也能） |
| V1 | 1.0.1 | `hasOwnProperty_` | **仍裸** | 挡 | 读到 env |
| V2 | 1.1.2 | 同 V1 | hasOwn ? 取值 : null | 挡 | 挡 |

- 库 API：`expressions.compile(userInput)(scope)`
- HTTP 面：`POST / {"expr":…}`（harness，空 scope）
- 认证语义：v0 seed 观察到 flag；v1 seed 未观察到；v1 residual 观察到。
- [CVE-2020-5219](https://nvd.nist.gov/vuln/detail/CVE-2020-5219)、[GHSA-hxhm-96pp-2m43](https://github.com/peerigon/angular-expressions/security/advisories/GHSA-hxhm-96pp-2m43)
- [CVE-2021-21277](https://nvd.nist.gov/vuln/detail/CVE-2021-21277)、[GHSA-j6px-jwvv-vpwq](https://github.com/peerigon/angular-expressions/security/advisories/GHSA-j6px-jwvv-vpwq)
- V1 blob：[`lib/parse.js` @ v1.0.1](https://github.com/peerigon/angular-expressions/blob/v1.0.1/lib/parse.js)
- V2 对照：tag `v1.1.2` 同一文件
