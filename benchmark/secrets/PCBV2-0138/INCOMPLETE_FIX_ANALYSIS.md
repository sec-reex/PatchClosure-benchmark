# locutus parse_str：includes 换成 test，还是一条可改写的原型方法

- Case：`PCBV2-0138`
- 产品：npm `locutus`（把 PHP 等语言的标准库搬到 JavaScript）。应用侧是一个用 `parse_str` 解析查询串、再读新鲜对象上 `pcbUnlock` 做默认拒绝门闩的 HTTP 探针。
- 链：CVE-2026-25521（2.0.38 → 2.0.39，commit `042af9ca7f`）→ CVE-2026-33994（2.0.39…3.0.24 → 3.0.25，commit `345a6211e1` / PR #597）
- 源码对着 GitHub tag `v2.0.39` 的 `src/php/strings/parse_str.js`（函数 `parse_str`），以及 tag `v3.0.25` 的 `src/php/strings/parse_str.ts`。运行时装的是发布包本身（npm alias `locutus@2.0.38/2.0.39/3.0.25`），不是抽出来的函数。

2026 年 2 月，locutus 把 `parse_str` 里拦 `__proto__` / `constructor` / `prototype` 的检测从 `String.prototype.includes` 换成正则字面量的 `.test`。这挡住了「先改写 `includes` 再喂 `constructor[prototype][x]=1`」的那条链。NVD CVE-2026-25521 写的是 *it is still possible to pollute Object.prototype via a crafted input using String.prototype*。一个月后 GHSA-vc8f-x9pp-wf5p 指出：新守卫用的 `RegExp.prototype.test` 同样可写。NVD CVE-2026-33994 写明 *this vulnerability stems from an incomplete fix for CVE-2026-25521*，并写 *trading one hijackable built-in for another*。

根因不只是「正则比 includes 更安全」。检查插在「整段 key 字符串长什么样」这一层；真正写进对象的是后面的 `lastObj[key] = value`；同函数里已经能按段比较字符串，却把安全性交给一条可被改写的原型方法。下面按查询串走进去、2.0.39 改了哪一行、守卫之后谁真正赋值、更硬的谓词有没有挂上，把这几层写完。

---

## 这块功能本来在干什么

`locutus` 的 `php/strings/parse_str` 模仿 PHP：把 `a[b][c]=v` 这种查询串拆成嵌套赋值。很多应用拿它解析用户可控的 query / form。一份典型调用：

```javascript
const parse_str = require('locutus/php/strings/parse_str');
const result = {};
parse_str(userQuery, result);
// 随后读 result，或读一个新鲜对象上的继承属性
```

本 case 的 harness 不把污染当 RCE 用，而是做一个默认拒绝门闩：新鲜对象 `session = {}` 上没有自有 `pcbUnlock`；只有 `Object.prototype.pcbUnlock` 被写过，`session.pcbUnlock` 才为真，才放出 `PCB_FLAG`。

advisory 写明利用需要**链式前提**：先有另一个原型污染 gadget 改写守卫用的内建方法。harness 只在这一次 `parse_str` 调用周围改写指定内建（`String.prototype.includes` 或 `RegExp.prototype.test`），然后立刻恢复。每个版本的 `parse_str` 在该文件里只用一次对应方法，所以改写碰不到别的逻辑。测的是：这个版本的守卫在方法被劫持之后还是否成立。

数据流：

```text
HTTP ?override=&qs=
    → 按 override 临时改写内建方法
    → parse_str(qs, result)
         拆 & 和 =
         key = decodeURIComponent(...)
         V1：/__proto__|constructor|prototype/.test(key)   ← 补丁插在这里
         再按 [ ] 拆成 keys[]
         obj = result; 逐段 obj = obj[key]
         lastObj[key] = value                              ← 真正的写
    → 读 ({ }).pcbUnlock → 放行则返回 PCB_FLAG
```

没有登录。判断完全信任守卫对「危险 key」的读法，不信任同一进程里是否已有人改写了那条检测方法。

---

## 原始漏洞：includes 可被改写成永远 false（CVE-2026-25521，2.0.38）

2.0.38 在拆完 `key=value` 之后、按括号拆段之前，用三次 `includes`：

```javascript
// src/php/strings/parse_str.js  (locutus@2.0.38)
key = _fixStr(tmp[0])
value = tmp.length < 2 ? '' : _fixStr(tmp[1])

if (key.includes('__proto__') || key.includes('constructor') || key.includes('prototype')) {
  break
}
```

`String.prototype.includes` 可写。GHSA-rxrv-835q-v5mh 的 PoC 是：

```javascript
String.prototype.includes = () => false;
parse_str('constructor[prototype][polluted]=yes');
console.log(({}).polluted);  // 'yes'
```

本 case 的 seed：

```text
override = string-includes
qs       = constructor[prototype][pcbUnlock]=1
```

2.0.38 上守卫被劫持，循环走进 `obj.constructor` → `Function.prototype` 不对，走的是 `result.constructor`（Object 函数）→ `prototype`（Object.prototype）→ 写下 `pcbUnlock=1`。新鲜对象继承到它，门闩打开，响应里出现 `PCBFLAG_...`。

2.0.39 的 commit message 自己承认：*The existing prototype pollution fix used String.prototype.includes() ... An attacker can override String.prototype.includes = () => false before calling parse_str, completely bypassing the guard.* 他们以为换成 regex test 就「not vulnerable to String prototype tampering」。

---

## 维护者改了什么（CVE-2026-25521 修复，2.0.39）

commit `042af9ca7fde2ff599120783e720a17f335bb01c` 只换了一行。tag `v2.0.39` 的函数是：

```javascript
// src/php/strings/parse_str.js :: parse_str  (locutus@2.0.39)
const _fixStr = function (str) {
  return decodeURIComponent(str.replace(/\+/g, '%20'))
}
...
for (i = 0; i < sal; i++) {
  tmp = strArr[i].split('=')
  key = _fixStr(tmp[0])
  value = tmp.length < 2 ? '' : _fixStr(tmp[1])

  if (/__proto__|constructor|prototype/.test(key)) {
    break
  }
  ...
  obj = array
  for (j = 0, keysLen = keys.length; j < keysLen; j++) {
    key = keys[j].replace(/^['"]/, '').replace(/['"]$/, '')
    lastObj = obj
    ...
    if (new Object(obj[key]) !== obj[key]) {
      obj[key] = {}
    }
    obj = obj[key]
  }
  lastObj[key] = value
}
```

V1 正则的字面意思：整段 `key`（还没按 `[` 拆）里只要出现 `__proto__`、`constructor` 或 `prototype` 三个子串之一，就 `break` 掉这一对 `key=value`。检测手段从 `String.prototype.includes` 换成 `RegExp.prototype.test`。

对 seed 这种「只劫持 includes」的流量，它确实够用：

```text
qs: constructor[prototype][pcbUnlock]=1
includes 被改成 () => false
V1 的 /.../.test(key) 仍是真正的 RegExp.prototype.test
匹配到 constructor → break
result 上什么都不写
({}).pcbUnlock === undefined → denied
```

这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险的是 `String.prototype.includes` 这一条方法，不是「用原型方法做安全判断」这件事。
2. 正则字面量的 `.test` 不会被同一类劫持。

第二点不成立。`RegExp.prototype.test` 同样可写、同样在用户代码能碰到的原型上。更关键的是：这一行之后，代码仍然按拆出来的段做 `obj[key]` / `lastObj[key] = value`，那次赋值**不再做危险名检查**。

---

## 守卫之后，谁真正往原型上写

V1 的 `.test` 一结束（或被劫持成永远 false），同一个函数立刻用拆段后的 `key` 做属性访问。括号解析把 `constructor[prototype][pcbUnlock]` 变成 `['constructor','prototype','pcbUnlock']`，然后：

```text
obj = result                    // 用户给的普通对象
obj = obj['constructor']        // Object 函数
obj = obj['prototype']          // Object.prototype
lastObj['pcbUnlock'] = '1'      // 写到共享原型上
```

`new Object(obj[key]) !== obj[key]` 只用来判断「当前值是不是原始类型，是则换成 {}」，不会拒绝 `__proto__`。赋值发生在守卫之后，而且守卫看的是**整段尚未拆开的 key 字符串**，赋值看的是**每一段**。两套语义中间没有第二次谓词。

harness 的门闩读的是另一个新鲜对象：

```javascript
function readGatedSecret() {
  const session = {};
  if (session.pcbUnlock) {
    return FLAG;
  }
  return "denied";
}
```

金丝雀能出现在响应里，依据就是 `lastObj[key] = value` 落到了 `Object.prototype`，而不是 `result` 自己有一个叫 `pcbUnlock` 的自有属性。

---

## 仓库里已经有更硬的比较，V1 没用

V1 的循环稍后已经在逐段处理 `keys[j]`。那时 `key` 是普通字符串，完全可以做 `===` 或 `Set#has`。2.0.39 没有。维护者后来在 3.0.25 自己写出了更硬的谓词，说明这不是「语言里做不到」：

```typescript
// src/php/strings/parse_str.ts  (locutus@3.0.25)
const DANGEROUS_PARSE_STR_KEYS = new Set(['__proto__', 'constructor', 'prototype'])

function isDangerousParseStrKey(key: string): boolean {
  return DANGEROUS_PARSE_STR_KEYS.has(key)
}
```

`Set.prototype.has` 仍是原型方法，但 3.0.25 把检查放到**每个已规范化的段**上，并且在赋值前再查一次；advisory 写的是 *rejects dangerous key paths during parsed-segment assignment, so the sink itself is hardened even if RegExp.prototype.test has been tampered with beforehand*。`===` 是语言级运算符，不能被用户改写——GHSA-vc8f-x9pp-wf5p 的修复建议原文就是这句话。

V1 等于在调用方入口又做了一个**同样可劫持**的检测方法（只是换了内建），而赋值路径上那个「按段拒绝危险名」的检查始终没挂上。不是后来才发明 `Set#has`，是 **2.0.39 的赋值循环没用**。

即便 `.test` 没有被改写，只要赋值继续裸写 `lastObj[key]`，任何让整段 key 躲过正则、拆段后仍含 `__proto__` 的写法都会变成一次真实的原型写入。V1 正则是子串匹配，碰巧把 `constructor[prototype][...]` 整段挡住了；它挡住 seed，不是因为它在赋值处做了硬比较。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs 赋值」落到具体代码：

- `/__proto__|constructor|prototype/.test(key)`：看整段 key 字符串里有没有这三个子串；调用的是 `RegExp.prototype.test`
- `lastObj[key] = value`：看拆段之后对象上实际写了什么

只要构造一种前提，使 `.test` 永远返回 false，第一行会放行，第二行仍然走上 `constructor` / `__proto__`。

token 变换：

```text
seed qs:      constructor[prototype][pcbUnlock]=1
seed 前提:    String.prototype.includes = () => false
V1 之后:      .test 仍为真 → break → 不赋值

residual qs:  __proto__[pcbUnlock]=1
residual 前提: RegExp.prototype.test = () => false
V1 之后:      守卫认为「不危险」
              keys = ['__proto__', 'pcbUnlock']
              obj = result['__proto__'] === Object.prototype
              lastObj['pcbUnlock'] = '1'
```

advisory 的复现和 residual 同一构造：`parse_str('__proto__[polluted]=yes', result)`，在 `.test` 被改成 `return false` 之后 `({}).polluted === 'yes'`。本 case 只是把叶子换成 `pcbUnlock`。

V1 换掉的是「用哪一条内建方法做子串检测」；CVE-2026-25521 真正要拦的是「用户可控的 key 路径不能写到 Object.prototype」。后者在方法仍可劫持时原样还在。

---

## 残余仍然走同一条 parse_str 赋值路径（CVE-2026-33994）

没有换函数、没有换查询串语法、没有换门闩。还是：

```text
override = regexp-test
qs       = __proto__[pcbUnlock]=1
```

`parse_str` 仍然先跑那一行 `.test`；执行时 `RegExp.prototype.test` 已经是 `() => false`；整段 key 被认为安全；拆段后 `result['__proto__']` 走上 Object.prototype；`pcbUnlock` 被写上；新鲜对象继承到它，响应里出现 `PCBFLAG_...`。

本 case `verify.sh` 的 residual 把 candidate 写死在脚本里：`override=regexp-test` + `__proto__[pcbUnlock]=1`。和 GHSA-vc8f-x9pp-wf5p 的 PoC 同一构造。认证：v1 + `--residual` 退出码 0。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：安全判断调用了可写的原型方法；赋值发生在检查之后；检查看的是整段字符串，赋值看的是每一段。seed 被挡住只说明「includes 这条路没了」，不说明「不能再通过 parse_str 污染 Object.prototype」。

平台 verify 的 residual 打的就是这条 incomplete-fix 链上的同一 `parse_str` 赋值，不是另一条无关 sink。

---

## 后来又补了什么（CVE-2026-33994，3.0.25）

commit `345a6211e1e6f939f96a7090bfeff642c9fcf9e4` 把守卫从「调用 `.test`」改成「对每个规范化后的段做 `Set#has`」，并且在赋值前再查一次：

```typescript
// src/php/strings/parse_str.ts :: parse_str  (locutus@3.0.25)
let hasDangerousKey = false
for (const rawKey of keys) {
  const normalizedKey = rawKey.replace(/^['"]/, '').replace(/['"]$/, '')
  if (isDangerousParseStrKey(normalizedKey)) {
    hasDangerousKey = true
    break
  }
}
if (hasDangerousKey) {
  continue
}
...
if (isDangerousParseStrKey(key)) {
  skipAssignment = true
  break
}
...
if (skipAssignment || isDangerousParseStrKey(key)) {
  continue
}
lastObj[key] = value
```

对残余输入：即使 `.test` 被改成永远 false，拆出来的段 `__proto__` 仍被 `DANGEROUS_PARSE_STR_KEYS.has` 拒绝，循环 `continue`，不赋值。维护者在 advisory 里写了修复前后的复现：3.0.24 上 `({}).polluted === 'yes'`；3.0.25 上同一链式 PoC 不再污染。公开建议是升级到 `locutus@3.0.25`。

即便如此，`Set#has` 仍是原型方法。V2 的实质进步是：检查贴在赋值段上，不再依赖「某条检测 API 没被改写」。本 benchmark 的 v2 关闭这一条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是入口那一行「怎么检测子串」。真正污染原型的是 `lastObj[key] = value`。V2 才把拒绝挪到赋值段；V1 只换了检测 API。

**不是没有更好的谓词。**  
`key === '__proto__'` 或 `Set#has` 在 2.0.39 的逐段循环里就能写。GHSA 的修复建议写的就是 *use direct string comparison operators (`===`) in native control flow*。从 V1 的 diff 只能看到 `includes` 换成 `.test`；要判断补丁是否闭合，必须看到赋值循环和「检测方法是否可写」。

**同一函数、同一 `$key`，只换了劫持哪条内建。**  
任何把用户字符串传进 `parse_str` 的调用，在 2.0.39 上都吃这一行 `.test` 和同一次赋值。advisory 的链式模型假定进程里已有另一个污染 gadget——这在多包 Node 应用里是写明的前提，不是本 case 发明的。

**守卫看整段、赋值看分段。**  
V1 正则碰巧能挡住 `constructor[prototype][...]` 整段。它没有在 `keys[j]` 上做硬比较。residual 用 `__proto__[pcbUnlock]` 只是因为劫持 `.test` 之后整段检查失效，不必再绕正则。

**金丝雀在新鲜对象上是有意的。**  
`session = {}` 没有自有 `pcbUnlock`。能读到 flag，说明写到了共享原型，而不是 `result` 自己的命名空间。

---

## 版本、入口、参考

| | npm | 守卫 | 赋值 | includes 劫持 + `constructor[prototype][pcbUnlock]` | test 劫持 + `__proto__[pcbUnlock]` |
|---|---|---|---|---|---|
| V0 | 2.0.38 | `key.includes(...)` | 裸 `lastObj[key]=value` | 污染，放出 flag | （不必） |
| V1 | 2.0.39 | `/.../.test(key)` | 同上 | `.test` 仍匹配，break | 守卫失效，污染，放出 flag |
| V2 | 3.0.25 | `Set#has` 按段，赋值前再查 | 危险段 skip | 挡 | 挡 |

- Web：`GET /probe?override=...&qs=...`
- 认证（本平台）：v0 seed 观察到 flag；v1 seed 未观察到；v1 residual 观察到
- [CVE-2026-25521](https://nvd.nist.gov/vuln/detail/CVE-2026-25521)、[CVE-2026-33994](https://nvd.nist.gov/vuln/detail/CVE-2026-33994)
- [GHSA-rxrv-835q-v5mh](https://github.com/locutusjs/locutus/security/advisories/GHSA-rxrv-835q-v5mh)、[GHSA-vc8f-x9pp-wf5p](https://github.com/locutusjs/locutus/security/advisories/GHSA-vc8f-x9pp-wf5p)
- V1 commit：[042af9ca7f](https://github.com/locutusjs/locutus/commit/042af9ca7fde2ff599120783e720a17f335bb01c)
- V2 commit：[345a6211e1](https://github.com/locutusjs/locutus/commit/345a6211e1e6f939f96a7090bfeff642c9fcf9e4) / [PR #597](https://github.com/locutusjs/locutus/pull/597)
- 源码：`https://github.com/locutusjs/locutus/blob/v2.0.39/src/php/strings/parse_str.js`
