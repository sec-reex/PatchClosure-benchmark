# dottie 2.0.4：只看 `pieces[0] === '__proto__'`，第二段照样能换原型

- Case：`PCBV2-0047`（`dottie-cve-2026-27837`）
- 产品：npm `dottie`（点分路径 get/set，Sequelize 依赖）。本 case 安装已发布包，HTTP `GET /probe?path=` 调真实的 `Dottie.set`。
- 链：CVE-2023-26132（2.0.3 → 2.0.4，commit `7d3aee1`：`if (pieces[0] === '__proto__') return;`）→ CVE-2026-27837 / GHSA-r5mx-6wc6-7h9w（2.0.7：每一段对照 `['__proto__','constructor','prototype']`）。advisory 标题即 *Incomplete fix for CVE-2023-26132*：*The prototype pollution guard ... only validates the first segment*。
- 源码对着 tag / npm `dottie@2.0.4`、`2.0.7` 的 `dottie.js`。本仓库 `patch.diff` 是 2.0.3→2.0.4 那一行，与上游一致。

2023 年 6 月，dottie 2.0.4 在 `Dottie.set` 拆完路径之后加了一行：第一段若是 `__proto__` 就直接 return。遍历循环仍对「当前结点上还不是 own 属性的键」执行 `current[piece] = {}`。`piece === '__proto__'` 时，这会触发 `__proto__` setter，把当前对象的原型换成新 `{}`，随后叶子写在这块新原型上。第一段叫 `x` 时，那一行 `pieces[0] === '__proto__'` 为 false；第二段 `__proto__` 仍走赋值。dottie 的污染是 **局部的**（换的是被走到的那个对象的 [[Prototype]]，不是全局 `Object.prototype`），advisory 也如此写。下面按 `set` 走进去、2.0.4 加了哪一行、循环如何建命名空间、`x.__proto__.pcbUnlock` 为什么还能让 `target.x` 继承到门闩键，把这三层写完。

---

## 这块功能本来在干什么

`Dottie.set(object, path, value)` 把 `a.b.c` 拆成段，沿对象往下走，缺了就建 `{}`，最后一段赋值。给嵌套 JSON / ORM 扁平字段用。若 path 来自用户，段名就是攻击面。

本 case 的 probe 对一个新鲜对象做 `Dottie.set(target, path, <trigger>)`，然后看 `pcbUnlock` 是不是 **继承来的**（非 own）。只有写落在原型上才放 `PCB_FLAG`。own 属性写 `a.b.pcbUnlock` 不会开门。

```http
GET /probe?path=__proto__.pcbUnlock
```

数据流：

```text
HTTP path
    → Dottie.set(object, path, value)
         pieces = path.split('.')
         V1：if (pieces[0] === '__proto__') return
         for each piece:
              若 !hasOwnProp(current, piece) 或 undefined：
                   current[piece] = {}          ← piece==='__proto__' 时换原型
              最后一段：current[piece] = value
              否则 current = current[piece]
    → 看 pcbUnlock 是否 inherited → 放 flag
```

设计意图：path 是业务对象上的点分字段。成功穿越之后的效果是 **被碰到的对象换了原型，门闩键出现在原型上**。

---

## 原始漏洞：没有原型检查（CVE-2023-26132，2.0.3）

2.0.3 的 `Dottie.set` 拆完立刻进循环。`__proto__` 对任意对象都不是 own 可枚举数据属性（有 setter），`hasOwnProp.call(current, '__proto__')` 为 false，于是：

```javascript
current['__proto__'] = {}
```

这不是在 current 上定义名为 `__proto__` 的 own 键，而是调用 [[SetPrototypeOf]]，current 的原型变成新 `{}`。下一轮 `pcbUnlock` 写在这块新原型上。`target` 自己继承到 `pcbUnlock`。2.0.3 上 seed 污染成功。这就是 v0 + `--seed` 退出码 0。

dottie **不会** 用这段路径去改 `Object.prototype`：它先换成一个全新的 `{}` 当原型。全局 `({}).pcbUnlock` 仍是 undefined。gate 必须读 **被 set 碰到的那个对象** 上的继承属性。这和 convict / jsonpointer 那些全局污染不同，和 GHSA-r5mx-6wc6-7h9w 一致。

---

## 维护者改了什么（CVE-2023-26132，2.0.4）

commit `7d3aee1` 只加一行，放在循环前：

```javascript
// dottie.js  Dottie.set  (dottie@2.0.4)
Dottie.set = function(object, path, value, options) {
  var pieces = Array.isArray(path) ? path : path.split('.'), current = object, piece, length = pieces.length;
  if (pieces[0] === '__proto__') return;

  if (typeof current !== 'object') {
      throw new Error('Parent is not an object.');
  }

  for (var index = 0; index < length; index++) {
    piece = pieces[index];

    if (
      !hasOwnProp.call(current, piece)
      || current[piece] === undefined
      || ((typeof current[piece] !== 'object' || current[piece] === null) && options && options.force === true)) {
      current[piece] = {};
    }

    if (index == (length - 1)) {
      current[piece] = value;
    } else {
      ...
      current = current[piece];
    }
  }
  current[piece] = value;
};
```

`transform` 里同样只对 `pieces[0] === '__proto__'` 做 `break`。没有 `constructor` / `prototype`，没有 `pieces.some(...)`。

对 seed `__proto__.pcbUnlock`：`pieces[0]` 就是 `'__proto__'`，立刻 return，循环不跑，没有换原型。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险段只会出现在 path 的第一段。
2. 危险名字只有 `__proto__`（advisory 后续说明 `constructor`/`prototype` 在 dottie 里会被 hasOwnProperty 分支建成普通 `{}`，不形成这条局部原型替换）。

第一点不成立。循环对每一段都可能执行 `current[piece] = {}`。

---

## 检查之后，非首段如何换原型

`pieces[0] === '__proto__'` 为 false 之后，循环从 index 0 正常走。`x.__proto__.pcbUnlock`：

```text
pieces = ['x', '__proto__', 'pcbUnlock']
pieces[0] === '__proto__'  → false

index 0, piece='x':
  target 没有 own 'x' → target.x = {}
  current = target.x

index 1, piece='__proto__':
  hasOwnProp(current, '__proto__') === false
  current['__proto__'] = {}     → 把 target.x 的 [[Prototype]] 换成新 {}
  不是最后一段 → current = current['__proto__']  → 现在 current 是那块新原型

index 2, piece='pcbUnlock':
  最后一段 → current['pcbUnlock'] = value
  即：新原型.pcbUnlock = value
```

之后 `target.x.pcbUnlock` 是继承来的，`hasOwnProperty('pcbUnlock')` 为 false。gate 认 inherited，放 flag。GHSA 给的例子是 `'a.__proto__.polluted'` / `'session.__proto__.isAdmin'`，同一段位移。

`transform` 对扁平键 `'user.__proto__.role'` 走同一套 `pieces[0]` 门闩，同样能在非首段换原型。本 case residual 打 `set`。

---

## 这个补丁挡住了什么、没挡住什么

- `pieces[0] === '__proto__'`：看第一段是不是这九个字符
- 循环里 `current[piece] = {}`：看这一段是不是 `__proto__` setter

只要 `__proto__` 不在下标 0，第一行放行，循环仍会在碰到该段时换原型。

没有对 `constructor`/`prototype` 的首段检查，是因为 dottie 的「缺键就 `= {}`」会在这些键上盖住一个普通对象，advisory 写明 **真正残差键是非首段 `__proto__`**。不要把别的库的 `constructor.prototype` 链硬套过来。

---

## 残余仍然走同一条 Dottie.set（CVE-2026-27837）

没有换 API。还是 `Dottie.set(target, path, ...)`。唯一差别是前面加了一段无害名字 `x.`。

`verify.sh` 的 residual 写死为 `x.__proto__.pcbUnlock`。和 GHSA 的 `a.__proto__.polluted` 同一构造。认证：v1 + `--residual` 退出码 0，probe 观察到 `PCBFLAG_...`。2.0.4、2.0.5、2.0.6 这行 guard 未改。

所以残余不是新洞面，而是同一 sink 上两件事叠在一起：谓词只读 `pieces[0]`；换原型发生在循环内部对 `__proto__` 的赋值。seed 被挡住只说明「第一段是 `__proto__` 的路径没了」，不说明「`set` 不能再让中间对象换原型」。

---

## 后来又补了什么（CVE-2026-27837，2.0.7）

commit `7e8fa13` 把一行换成「任一段命中三个危险名」：

```javascript
// Dottie.set  (dottie@2.0.7)
var DANGEROUS_KEYS = ['__proto__', 'constructor', 'prototype'];
if (pieces.some(function(p) { return DANGEROUS_KEYS.indexOf(p) !== -1; })) return;
```

`transform` 同样 `some` 后 `break`。`x.__proto__.pcbUnlock` 在入口 return，不写。公开建议升级到 2.0.7。

即便如此，这仍然是「拆段后扫名字」，循环里的 `current[piece] = {}` 没有改成 `Object.create(null)` 或避开 `__proto__` setter。对这条已知链它够用。本 benchmark 的 v2 只关闭这一条 reference residual。

---

## transform 复制了同一行

`Dottie.transform` 把 `{ 'a.b': 1 }` 收成嵌套对象，对含分隔符的键同样 `split`，2.0.4 里是：

```javascript
pieces = key.split(options.delimiter);
if (pieces[0] === '__proto__') break;
```

`break` 只跳出当前 key 的处理，而且同样只看首段。`'user.__proto__.role'` 的 `pieces[0]` 是 `'user'`，进入与 `set` 相同的 `current[piece] = {}` 循环，换 `transformed.user` 的原型。GHSA 把 `set` 和 `transform` 并列。本 case HTTP 只打 `set`；源码上 2.0.4–2.0.6 两处都是同一不完整谓词。2.0.7 两处都改成 `DANGEROUS_KEYS` + `some`。

循环末尾还有一次 `current[piece] = value`（函数最后一行，循环外）。对最后一段会赋两次，不影响原型替换是否发生。`hasOwnProp` 来自 `Object.prototype.hasOwnProperty`，文件头注释写了 IE 上对象自身可能没有这方法。`hasOwnProp.call(current, '__proto__')` 为 false，正是走进 `current[piece] = {}` 的条件。

`constructor` / `prototype` 作为中间段时，若 current 上还没有该 own 键，dottie 会赋一个普通 `{}`，把本来可能通向 `Function.prototype` 的链盖住。所以 GHSA 不把这两键当 2.0.4 的残差。不要用 convict 的 `this.constructor.prototype` 去测 dottie 2.0.4——那不是这条局部 `__proto__` setter 链。

局部污染的观察必须针对 **被改了 [[Prototype]] 的那个对象**（`target.x`），不是 `{}` 字面量。gate 若误写成读 `Object.prototype.pcbUnlock`，会把真残余判成失败。

把 2.0.3 / 2.0.4 / 2.0.7 的入口并排：

```javascript
// V0  2.0.3   无
var pieces = ... split('.'), current = object
for (...) { if (!hasOwnProp.call(current, piece) || ...) current[piece] = {} }

// V1  2.0.4
if (pieces[0] === '__proto__') return;
for (...) { ... current[piece] = {} }

// V2  2.0.7
var DANGEROUS_KEYS = ['__proto__', 'constructor', 'prototype'];
if (pieces.some(function(p) { return DANGEROUS_KEYS.indexOf(p) !== -1; })) return;
for (...) { ... current[piece] = {} }
```

三次都没改循环体。V1 等于假设攻击者会把 `__proto__` 放在用户能控制的路径的最左边。HTTP `?path=` 没有这个约定；`x.__proto__.pcbUnlock` 是合法点分路径。`Array.isArray(path)` 分支同样只看 `pieces[0]`，数组 `['x','__proto__','pcbUnlock']` 与字符串同构。

probe 读 inherited 的实现应对 `Object.prototype.hasOwnProperty.call(obj, 'pcbUnlock') === false && obj.pcbUnlock != null`。own 写 `target.pcbUnlock = ...` 不会开门。这把「业务 set 了一个字段」和「换了原型」分开。

`Dottie.get` 没有这行 guard，只 `object[names.pop()]`。污染发生在 `set`/`transform` 的写入。`Dottie.default` 内部调 `set`，同一谓词。2.0.4 的 `memoizePath` 只影响 `get` 的 split 缓存，与 `set` 无关。

路径可以是数组。`Dottie.set(obj, ['x','__proto__','pcbUnlock'], v)` 与点分字符串同构：`pieces[0]` 仍是 `'x'`。HTTP 若只接受字符串，residual 用 `x.__proto__.pcbUnlock` 即可；源码上数组形态不是另一条洞。

`set` 的 `options` 第四参本 case 不传。`force` 只影响「已有非对象」是否被盖掉，不增加第二道 `__proto__` 检查。分隔符在 `set` 里写死为点号，不能靠换 delimiter 躲开。`transform` 的 delimiter 选项不影响这条 HTTP 路径。

2.0.5 / 2.0.6 与 2.0.4 同一行 `pieces[0]` 检查，GHSA 把三者都标为受影响。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是循环前对 `pieces[0]` 的相等。真正换原型的是循环里 `current['__proto__'] = {}`。V2 仍在循环前加码，但扫了每一段。

**不是 2.0.4 完全没检查。**  
首段检查对 seed 有效。要判断是否闭合，必须看循环是否还对后续段执行同一条赋值。`transform` 复制了同一错误，修的时候两处一起改。

**同一 `set`、同一 `hasOwnProp` 分支，只换了 `__proto__` 的位置。**  
任何把用户 path 交给 `Dottie.set` / `Dottie.transform` 的应用，在 2.0.4–2.0.6 上都吃这一行。Sequelize 是高下载量下游，advisory 写了授权绕过场景。

**金丝雀要求 inherited 是有意的。**  
own 的 `pcbUnlock` 不放 flag。能读到它，说明写在原型上，不是普通嵌套字段。

`options.force === true` 会在「已有非对象值」上强行盖 `{}`，不改变 `__proto__` 段的 setter 语义。本 case 不传 force。`Dottie.memoizePath` 默认 true，只缓存 `get` 的 reverse split，`set` 每次都重新 `path.split('.')`。

`Dottie.exists` / `Dottie.find` 走 `get`，不写。污染只可能来自 `set`、`transform`、以及调用它们的 `default`。HTTP probe 只调用 `set`，与 seed/residual 的 path 差分对齐。

---

## 版本、入口、参考

| | 版本 | `Dottie.set` 入口 | 循环 `current[piece]= {}` | seed `__proto__.pcbUnlock` | residual `x.__proto__.pcbUnlock` |
|---|---|---|---|---|---|
| V0 | 2.0.3 | 无 | 会换原型 | 局部污染，读到 flag | （不必） |
| V1 | 2.0.4 | `pieces[0]==='__proto__'` | 同上 | 立即 return | 第二段换原型，读到 flag |
| V2 | 2.0.7 | `pieces.some(DANGEROUS_KEYS)` | 同上（到不了） | 挡 | 挡 |

- Web：`GET /probe?path=...`
- 认证（本平台）：v0 seed 观察到 flag；v1 seed 未观察到；v1 residual 观察到。
- [CVE-2023-26132](https://nvd.nist.gov/vuln/detail/CVE-2023-26132)、[CVE-2026-27837](https://nvd.nist.gov/vuln/detail/CVE-2026-27837)
- [GHSA-r5mx-6wc6-7h9w](https://github.com/mickhansen/dottie.js/security/advisories/GHSA-r5mx-6wc6-7h9w)
- commits：`7d3aee1`（V1）、`7e8fa1345a4b46325f0eab8d7aeb1c4deaefdb14`（V2）；`dottie.js` 的 `Dottie.set` / `Dottie.transform`
