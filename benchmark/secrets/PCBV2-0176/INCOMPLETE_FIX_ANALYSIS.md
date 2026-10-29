# json-ptr：setValueAtPath 用 `===` 比字符串，数组段在 it[step] 上仍然污染

- Case：`PCBV2-0176`
- 产品：npm `json-ptr`（RFC 6901 JSON Pointer）。运行时是整包 `json-ptr@1.3.0` / `2.0.0` / `3.0.0`，Express 只把 JSON 交给 `JsonPointer.set({}, pointer, value, true)`。
- 链：CVE-2020-7766（1.3.0 → 2.0.0，SNYK-JS-JSONPTR-1016939）→ CVE-2021-23509（2.0.0 → 3.0.0，SNYK-JS-JSONPTR-1577291）
- 源码对着 npm `json-ptr@2.0.0` 的 `dist/util.js`（`setValueAtPath` / `unsetValueAtPath` / `decodePtrInit`）。金丝雀是 benign：`GET /check` 仅当 `({}).isAdmin === true` 时返回 `PCBFLAG_...`。

NVD 对 CVE-2021-23509 的原话：*A type confusion vulnerability can lead to a bypass of CVE-2020-7766 when the user-provided keys used in the pointer parameter are arrays.* Snyk PoC：`JsonPointer.set({}, [['__proto__'], 'polluted'], 'yes', true)`。

根因不只是「黑名单漏了」。检查插在「这段 step **严格等于** 字符串 `__proto__`」上；真正迈出目标的是后面的 `it = it[step]` / `it[step] = val`。`unsetValueAtPath` 在 V1 **完全没有** 这套守卫；`decodePointerSegments` 已经把非字符串段原样留下。下面按调用走进去。

---

## 这块功能本来在干什么

`JsonPointer.set(target, pointer, value, force)` 接受 JSON Pointer 字符串或**段数组**。`decodePtrInit` 若已经是数组就 `ptr.slice(0)`，否则才按 `/` 或 `#/` 解码。然后 `setValueAtPath` 沿段走，`force=true` 时补中间对象并写叶子。一次典型调用：

```js
const { JsonPointer } = require('json-ptr');
JsonPointer.set({}, '/user/role', 'editor', true);
// 或
JsonPointer.set({}, ['user', 'role'], 'editor', true);
```

本 case 的 HTTP 面：

```http
POST /set   {"pointer":["__proto__","isAdmin"],"value":true}
GET  /check
```

`server.js` 把 body 原样交给 `JsonPointer.set({}, pointer, value, true)`。`force=true` 是公开 API，缺中间层时必须靠它才能写到叶子——CVE-2020-7766 的 NVD 也写 *when the force flag is set to true*。

设计意图：pointer 只在传入文档里寻址，不能改 `Object.prototype`。成功穿越之后的效果是：**共享原型上多了 `isAdmin`**，`/check` 放出金丝雀。

数据流：

```text
POST /set  {pointer, value}
    → JsonPointer.set({}, pointer, value, true)
         path = decodePtrInit(pointer)          ← 数组则原样
         setValueAtPath(target, val, path, true)
              while cursor < len:
                   step = path[cursor]
                   if (step === '__proto__' || …) throw   ← V1 谓词
                   it[step] = {} | val                     ← 原生下标
                   it = it[step]
    → GET /check  读 ({}).isAdmin
```

不需要登录。污染是进程级的；每次探测前重启容器。

---

## 原始漏洞：段直接 it[step]（CVE-2020-7766，1.3.0）

1.3.0 的 `setValueAtPath` **没有** magic-property 守卫。NVD：*The function recursively set the property in the target object, however it does not properly check the key being set*。`force=true` 时在 `undefined` 上建 `{}` / `[]`，然后 `it[step] = val`。字符串段 `__proto__` 让 `it` 变成 `Object.prototype`。

本 case seed：

```http
POST /set  {"pointer":["__proto__","isAdmin"],"value":true}
```

V0 第一段无守卫，叶子写到原型。`GET /check` 放出 flag。这就是 v0 + `--seed` 观察到 `PCBFLAG_...`。

GHSA 范围写过 `< 2.1.0`，但 npm 没有 2.1.0 这个发布：版本从 1.3.0 跳到 2.0.0 再到 3.0.0。字符串守卫第一次出现在 2.0.0，所以 V1 钉 2.0.0。

---

## 维护者改了什么（CVE-2020-7766 修复，2.0.0）

2.0.0 在 `setValueAtPath` 每一步、任何下标之前加上严格等号：

```js
// dist/util.js :: setValueAtPath  (json-ptr@2.0.0)
function setValueAtPath(target, val, path, force = false) {
    ...
    while (++cursor < len) {
        step = path[cursor];
        if (step === '__proto__' || step === 'constructor' || step === 'prototype') {
            throw new Error('Attempted prototype pollution disallowed.');
        }
        if (Array.isArray(it)) {
            ...
        } else {
            if (typeof it[step] === 'undefined') {
                if (force) {
                    if (cursor === end) {
                        it[step] = val;
                        return undefined;
                    }
                    it = it[step] = {};
                    continue;
                }
                return undefined;
            }
            if (cursor === end) {
                rem = it[step];
                it[step] = val;
                break;
            }
            it = it[step];
        }
    }
    return rem;
}
```

V1 谓词的字面意思：

| 片段 | 含义 |
|---|---|
| `step === '__proto__'` | 严格相等，**不**做 ToString、不查 typeof |
| 命中则 `throw` | HTTP 层会看到 blocked |
| 只在 `setValueAtPath` | `unsetValueAtPath` 无此段 |

对 seed 这种全字符串 `["__proto__","isAdmin"]`，第一段 `=== '__proto__'` 为真，抛 `Attempted prototype pollution disallowed.`。`POST /set` 回 blocked，`/check` 为 `null`。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. pointer 的每一段都是 string（或至少和那三个字符串可比）。
2. 和 `'__proto__'` 严格不等的值，当下标用时也不会走到原型。

第二点不成立。`it[step]` 对数组 `["__proto__"]` 做 ToString，得到 `"__proto__"`。

---

## 检查之后，谁真正下标

`===` 一失败（即「不是那三个字符串」），同一个 while 立刻用 `step` 做属性访问。`force=true` 时还会 `it[step] = {}` 或 `it[step] = val`。

```text
pointer = [["__proto__"], "isAdmin"]
decodePtrInit → 原样数组（已经是 Array）
step = ["__proto__"]
["__proto__"] === '__proto__'   → false
it[step]                        → it["__proto__"] → Object.prototype
下一轮 step = "isAdmin"
it["isAdmin"] = true            // force，叶子
```

过滤器刚看过的是「step 的 JS 值是不是那三个字符串」；`[[Set]]` 看到的是 ToString 之后的名字。两套语义中间没有第二次谓词。

`decodePointerSegments` / `decodeFragmentSegments` 对非字符串段是：

```js
if (typeof segments[i] === 'string') {
    res[i] = replace(...);
} else {
    res[i] = segments[i];   // 数组段原样留下
}
```

库在解码层已经承认 path 里可以有非 string。V1 的守卫却只按 string 比较。

---

## 仓库里已经有更强的检查，set 没用、unset 更没用

同一份 `util.js` 里：

| 函数 | V1 的 proto 谓词 |
|---|---|
| `setValueAtPath` | `step === '__proto__' \|\| …` |
| `unsetValueAtPath` | **无**（直接 `it[step]` / `delete it[p]`） |
| `compilePointerDereference` | 把段拼进 `new Function`，另是一条面 |

V2 加上的 `typeof step !== 'string' && typeof step !== 'number'` 在 2.0.0 不存在。它比「再列几个危险字符串」更接近 JSON Pointer 的段类型（RFC 6901 的段是字符串）。不是仓库里只能做黑名单，是 **V1 选了最窄的 `===`**。

`unsetValueAtPath` 在 V1 连这层黑名单都没有。本 case residual 走的是 `set`，和 Snyk / NVD 的 bypass 同一条；若应用把用户 pointer 传给 `unset`，那是同文件里一条**更弱**的兄弟路径，不是平台另开的 sink。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs 下标」落到具体代码：

- `step === '__proto__'`：看 JS 值是否就是那个字符串
- `it[step] = val`：看 ToPropertyKey 之后写到哪

只要构造一种输入，使「严格相等」为假，但 ToString 仍是 `__proto__`，第一行会放行，第二行仍然写到原型。

Snyk 写明：字符串 `['__proto__', 'polluted']` 会抛；`[['__proto__'], 'polluted']` 写出 `yes`。

```text
POST /set
  pointer = [["__proto__"], "isAdmin"]
  value   = true
  force   = true

V1: ["__proto__"] === '__proto__' → false
it = {}["__proto__"] → Object.prototype
Object.prototype.isAdmin = true

GET /check → PCBFLAG_...
```

这正是 1.3.0 上 seed 用过的那种污染。过滤器认为自己已经把 `__proto__` 清干净了，实际上它只认识字符串形态，并且 `it[step]` 会把数组认回去。

---

## 残余仍然走同一个 setValueAtPath（CVE-2021-23509）

没有换静态方法、没有换 `force`、没有换观察点。还是：

```http
POST /set  {"pointer":[["__proto__"],"isAdmin"],"value":true}
GET  /check
```

`JsonPointer.set` 仍然 `decodePtrInit` → `setValueAtPath`。V1 那一行 `===` 对数组为假；`force=true` 把叶子写到 `Object.prototype`。

平台 residual 与不完整修复链是**同一 sink**（`setValueAtPath` 的段 walk），不是换到 `unset` 或 `compilePointerDereference`。NVD 的 bypass 条件就是 *pointer parameter are arrays*。

所以残余不是新洞面，而是同一 walk 上三件事叠在一起：谓词用严格等号比字符串；下标发生在检查之后且会强制类型；解码层已经允许非 string 段，守卫却当它们不存在。seed 被挡住只说明「字符串 `__proto__` 会抛」，不说明「不能再从 JsonPointer.set 写到 Object.prototype」。

---

## 后来又补了什么（CVE-2021-23509，3.0.0）

3.0.0（commit `5dc458f` / PR #42）在字符串黑名单**之前**加类型检查：

```ts
if (typeof step !== 'string' && typeof step !== 'number') {
    throw new TypeError('PathSegments must be a string or a number.');
}
if (step === '__proto__' || step === 'constructor' || step === 'prototype') {
    throw new Error('Attempted prototype pollution disallowed.');
}
```

对残余输入：`typeof ["__proto__"] === 'object'`，在任何 `it[step]` 之前抛 TypeError。`POST /set` 回 blocked，`/check` 为 `null`。公开建议是升级到 3.0.0。

即便如此，这仍然是「在下标之前限制段类型」。字符串 `__proto__` 仍靠后面的黑名单。对这条已知嵌套数组链它够用。本 benchmark 的 v2 关闭的是 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是「step 是不是三个字符串之一」。真正迈上原型的是 `it[step]`。V2 才承认段的 *类型* 也是安全边界。

**不是没有更好的谓词。**  
RFC 6901 的段是字符串；`typeof === 'string' | 'number'` 比黑名单更贴近 API 契约。`unsetValueAtPath` 在 V1 连黑名单都没有。从 V1 的 diff 只能看到 `setValueAtPath` 多了两段 `===`；要判断补丁是否闭合，必须看到 `it[step]` 对数组做什么，以及 `decodePtrInit` 是否原样保留数组。

**同一 `set()`、同一 pointer，只换了第一段的类型。**  
库公开接受 array pointer。任何把用户 JSON 当 pointer 传入且 `force=true` 的应用，在 2.0.0 上都吃这次 `===` 和同一次下标。

**force=true 是写叶子的开关，不是漏洞本身。**  
没有 force，缺中间层时函数直接 return。污染发生在 force 打开之后的 `it[step] = val`。NVD 把 force 写进 7766 的描述，bypass 并没有换这个开关。

**金丝雀挂在默认拒绝的授权位上是有意的。**  
新鲜进程没有 `Object.prototype.isAdmin`。能读到 flag，说明 `setValueAtPath` 写在了共享原型上。

---

## 版本、入口、参考

| | 版本 | `setValueAtPath` 谓词 | 下标 | 字符串 seed | 嵌套数组 residual |
|---|---|---|---|---|---|
| V0 | 1.3.0 | 无 | `it[step]` | 污染，`/check` 出 flag | （不必） |
| V1 | 2.0.0 | `step === '__proto__' \|\| …` | 同上 | 抛 Attempted prototype pollution | 数组 ToString 后污染 |
| V2 | 3.0.0 | 先 `typeof` 再字符串黑名单 | 同上 | 挡 | TypeError PathSegments… |

- 库 API：`JsonPointer.set(target, pointer, value, force)`（本 case HTTP：`POST /set`，`GET /check`）
- 观察：`GET /check` JSON 中的 `PCBFLAG_...`
- [CVE-2020-7766](https://nvd.nist.gov/vuln/detail/CVE-2020-7766)、[CVE-2021-23509](https://nvd.nist.gov/vuln/detail/CVE-2021-23509)
- [SNYK-JS-JSONPTR-1016939](https://snyk.io/vuln/SNYK-JS-JSONPTR-1016939)、[SNYK-JS-JSONPTR-1577291](https://snyk.io/vuln/SNYK-JS-JSONPTR-1577291)
- [GHSA-8gwj-8hxc-285w](https://github.com/advisories/GHSA-8gwj-8hxc-285w)
- V1 包：`npm:json-ptr@2.0.0` `dist/util.js`（[jsDelivr](https://cdn.jsdelivr.net/npm/json-ptr@2.0.0/dist/util.js)）
- V2 commit：[`5dc458f`](https://github.com/flitbit/json-ptr/commit/5dc458fbad1c382a2e3ca6d62e66ede3d92849ca) / [PR #42](https://github.com/flitbit/json-ptr/pull/42) tag `3.0.0`
