# deep-get-set：isSafeKey 用 `!==` 比字符串，`obj[key]` 把数组键强制回 `__proto__`

- Case：`PCBV2-0175`
- 产品：npm `deep-get-set`（按路径取值/赋值的小库）。运行时是 Packagist 式的整包 `deep-get-set@1.1.0` / `1.1.1` / `1.1.2`，Express 只把 JSON 交给 `deep({}, path, value)`。
- 链：CVE-2020-7715（1.1.0 → 1.1.1，SNYK-JS-DEEPGETSET-598666）→ CVE-2022-21231（1.1.1 → 1.1.2，SNYK-JS-DEEPGETSET-2342655）
- 源码对着 npm `deep-get-set@1.1.1` 的 `index.js`（`isSafeKey` / `set` / `get`）。金丝雀是 benign：`GET /check` 仅当 `({}).isAdmin === true` 时返回 `PCBFLAG_...`。

NVD / Snyk 对 CVE-2022-21231 的原话：*This vulnerability derives from an incomplete fix of CVE-2020-7715*。PoC：`deep({}, [["__proto__"], 'polluted'], 'success')`。

根因不只是「黑名单少写了几种键」。检查插在「这段 key **严格不等于** 字符串 `__proto__`」上；真正迈出目标对象的是后面的 `obj = obj[key]`。`get()` 已经同时用了 `hasOwnProp` 和 `isSafeKey`，`set()` 的叶子赋值甚至不再问 `isSafeKey`。下面按调用走进去。

---

## 这块功能本来在干什么

`deep(obj, path)` 按点分字符串或数组取值；三参数 `deep(obj, path, value)` 走 `set()`，沿路径建中间对象并写叶子。一次典型的库调用：

```js
const deep = require('deep-get-set');
deep({}, ['user', 'role'], 'editor');
```

本 case 的 HTTP 面：

```http
POST /set   {"path":["__proto__","isAdmin"],"value":true}
GET  /check
```

`server.js` 把 body 原样交给 `deep({}, path, value)`。`deep.p` 保持假值，中间层不会因为缺 own property 而新建 `{}`，于是 `obj['__proto__']` 读到的是真正的 `Object.prototype`。

设计意图：路径只在传入的那棵对象里走，不能改到共享原型。成功穿越之后的效果是：**`Object.prototype.isAdmin === true`**，随后任意新对象都继承到它，`/check` 放出金丝雀。

数据流：

```text
POST /set  {path, value}
    → deep({}, path, value)
         set(obj, path, value)
              keys = Array.isArray(path) ? path : path.split('.')
              for i in 0 .. keys.length-2:
                   if (!isSafeKey(keys[i])) return;     ← V1 谓词
                   obj = obj[keys[i]]                   ← 原生下标，数组会 ToString
              obj[keys[last]] = value                   ← 叶子不再问 isSafeKey
    → GET /check  读 ({}).isAdmin
```

不需要登录。污染是进程级的；每次探测前重启容器，好让 `Object.prototype` 干净。

---

## 原始漏洞：路径段直接 obj[key]（CVE-2020-7715，1.1.0）

1.1.0 的 `set()` **没有** `isSafeKey`。NVD：*All versions of package deep-get-set are vulnerable to Prototype Pollution via the main function*（当时尚未发布 1.1.1）。路径段 `__proto__` 让 `obj = obj[key]` 走到 `Object.prototype`，叶子写出任意属性。

本 case seed：

```http
POST /set  {"path":["__proto__","isAdmin"],"value":true}
```

V0 第一段 `__proto__` 无守卫，`obj` 变成 `Object.prototype`，`isAdmin = true`。`GET /check` 放出 flag。这就是 v0 + `--seed` 观察到 `PCBFLAG_...`。

---

## 维护者改了什么（CVE-2020-7715 修复，1.1.1）

1.1.1 增加字符串黑名单，并在 `set` 的中间层循环里提前 return；`get` 把同一谓词和 `hasOwnProp` 绑在一起：

```js
// index.js  (deep-get-set@1.1.1)
function isSafeKey (key) {
  return key !== '__proto__' && key !== 'prototype' && key !== 'constructor';
}

function set (obj, path, value) {
  var keys = Array.isArray(path) ? path : path.split('.');
  for (var i = 0; i < keys.length - 1; i++) {
    var key = keys[i];
    if (!isSafeKey(key)) return;
    if (deep.p && !hasOwnProp.call(obj, key)) obj[key] = {};
    obj = obj[key];
  }
  obj[keys[i]] = value;
  return value;
}
```

V1 谓词的字面意思：

| 片段 | 含义 |
|---|---|
| `key !== '__proto__'` | 严格不等，**不**做 ToString |
| 只在 `i < keys.length - 1` | 最后一段不检查 |
| 命中则 `return` | 静默，不抛错 |

对 seed 这种全字符串 `["__proto__","isAdmin"]`，第一段 `!== '__proto__'` 为假，`set` 直接返回，原型不被写。`POST /set` 仍可能回 `{ok:true}`（库不抛），但 `/check` 为 `null`。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险键的运行时类型是 string。
2. 和字符串 `__proto__` 严格不等的值，当下标用时也不会走到原型。

第二点不成立。`obj[key]` 会把 key 做 ToPropertyKey：数组 `["__proto__"]` 变成字符串 `"__proto__"`。

---

## 检查之后，谁真正下标

`isSafeKey` 一通过，同一轮循环立刻 `obj = obj[key]`。叶子是 `obj[keys[i]] = value`，**不再**调用 `isSafeKey`。

```text
path = [["__proto__"], "isAdmin"]
keys[0] = ["__proto__"]          // Array
["__proto__"] !== '__proto__'    // true，isSafeKey 放行
obj = obj[["__proto__"]]         // ToString → obj["__proto__"] → Object.prototype
obj["isAdmin"] = true            // 叶子未检查
```

过滤器刚看过的是「key 的 JS 值是不是那三个字符串」；`[[Get]]` / `[[Set]]` 看到的是 ToString 之后的属性名。两套语义中间没有第二次谓词。

`deep.p` 为假时，中间层不会 `obj[key] = {}`，因此 `obj['__proto__']` 不会被盖成普通 own 对象，走的是原型链上的 `Object.prototype`。这是库的默认，不是 harness 改出来的。

---

## 仓库里已经有更强的检查，set 没用全

同一份 `index.js` 里，`get()` 比 `set()` 严：

```js
function get (obj, path) {
  var keys = Array.isArray(path) ? path : path.split('.');
  for (var i = 0; i < keys.length; i++) {
    var key = keys[i];
    if (!obj || !hasOwnProp.call(obj, key) || !isSafeKey(key)) {
      obj = undefined;
      break;
    }
    obj = obj[key];
  }
  return obj;
}
```

`hasOwnProp.call(obj, key)` 在 `__proto__` 上对普通 `{}` 为假（`__proto__` 是继承来的访问器，不是 own）。若 `set` 也要求 own property，字符串 seed 和数组 seed 都走不进原型。V1 只把 `isSafeKey` 挂到 `set` 的中间层。

另外两处更强、当时没用的谓词：

| 谓词 | 谁在用 |
|---|---|
| `hasOwnProp.call(obj, key)` | 仅 `get` |
| `Array.isArray(key) && key[0] === '__proto__'` | V2 的 `isUnsafeKey`，V1 没有 |
| 叶子也跑 `isSafeKey` | V1 没有 |

不是仓库里想不出「键可能是数组」，是 **set 的比较语言比下标语言窄**。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs 下标」落到具体代码：

- `isSafeKey(key)`：`key !== '__proto__'`（以及 prototype / constructor）
- `obj[key]`：ToPropertyKey 后再取

只要构造一种输入，使「严格不等」为真，但 ToString 仍是 `__proto__`，第一行会放行，第二行仍然迈上原型。

Snyk PoC 的 `[["__proto__"], 'polluted']` 就是这样来的。嵌套数组当第一段：类型是 object，不是 string，黑名单全 miss；当下标用时变成 `"__proto__"`。

```text
POST /set
  path  = [["__proto__"], "isAdmin"]
  value = true

V1 isSafeKey(["__proto__"]) → true
obj = {}["__proto__"] → Object.prototype
Object.prototype.isAdmin = true

GET /check → PCBFLAG_...
```

这正是 1.1.0 上 seed 用过的那种污染。过滤器认为自己已经把 `__proto__` 清干净了，实际上它只认识字符串形态，并且 `obj[key]` 会把数组认回去。

---

## 残余仍然走同一个 set()（CVE-2022-21231）

没有换 API、没有换叶子属性、没有换观察点。还是：

```http
POST /set  {"path":[["__proto__"],"isAdmin"],"value":true}
GET  /check
```

`set()` 仍然先 `isSafeKey` 再 `obj[key]`。V1 那一行 `!==` 对数组为真；执行完之后 `obj` 已是 `Object.prototype`；叶子写出 `isAdmin`。

平台 residual 与不完整修复链是**同一 sink**（`set()` 的 key-walk + 叶子赋值），不是换到 `get()` 或另一条 merge API。Snyk 写明 *via the 'deep' function*，PoC 就是嵌套数组路径。

所以残余不是新洞面，而是同一 walk 上三件事叠在一起：谓词用严格等号比字符串；下标发生在检查之后且会强制类型；`get` 已经用了更强的 `hasOwnProp`，`set` 没用。seed 被挡住只说明「字符串 `__proto__` 没了」，不说明「不能再从 deep() 写到 Object.prototype」。

---

## 后来又补了什么（CVE-2022-21231，1.1.2）

1.1.2 把守卫改成先认数组：

```js
function isUnsafeKey (key) {
  return (Array.isArray(key) && key[0] === '__proto__')
    || key === '__proto__'
    || key === 'constructor'
    || key === 'prototype';
}
// set 循环里: if (isUnsafeKey(key)) return;
```

对残余输入：`keys[0]` 是 `["__proto__"]`，`Array.isArray && key[0] === '__proto__'` 为真，提前 return，叶子不会落到原型上。公开建议是升级到 1.1.2。

即便如此，这仍然是「在下标之前用黑名单近似危险键」。叶子段在 1.1.2 的 diff 里仍可能不跑同一函数（视发布字节而定）；`hasOwnProp` 也没有被搬到 `set`。对这条已知嵌套数组链它够用。本 benchmark 的 v2 关闭的是 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是「key 是不是这三个字符串」。真正迈上原型的是 `obj[key]` 的 ToPropertyKey。V2 仍在同一层加码（多认一种数组形状），没有改成 own-property 走法。

**不是没有更好的谓词。**  
`get()` 的 `hasOwnProp` 已经能挡住这条链。从 V1 的 diff 只能看到加了 `isSafeKey`；要判断补丁是否闭合，必须看到 `obj = obj[key]` 对非字符串 key 做什么。

**同一 `set()`、同一 `path`，只换了第一段的类型。**  
任何把用户 JSON 数组当 path 传进 `deep(obj, path, value)` 的应用，在 1.1.1 上都吃这次 `!==` 和同一次下标。库公开接受 array path，不是 harness 发明的。

**静默 return 让 HTTP 层看起来像成功。**  
`POST /set` 回 ok 不代表没污染，也不代表守卫没触发。观察点必须是原型上的属性，而不是 HTTP 状态。

**金丝雀挂在默认拒绝的授权位上是有意的。**  
新鲜进程没有 `Object.prototype.isAdmin`。能读到 flag，说明叶子写在了共享原型上，而不是 `{}` 的 own 槽。

---

## 版本、入口、参考

| | 版本 | `set()` 谓词 | 下标 | 字符串 seed | 嵌套数组 residual |
|---|---|---|---|---|---|
| V0 | 1.1.0 | 无 | `obj[key]` | 污染，`/check` 出 flag | （不必） |
| V1 | 1.1.1 | `isSafeKey`：`!==` 字符串 | 同上 | 静默 return | 数组 ToString 后污染 |
| V2 | 1.1.2 | `isUnsafeKey` 先认数组 | 同上 | 挡 | 挡 |

- 库 API：`deep(obj, path, value)` / `set()`（本 case HTTP：`POST /set`，`GET /check`）
- 观察：`GET /check` JSON 中的 `PCBFLAG_...`
- [CVE-2020-7715](https://nvd.nist.gov/vuln/detail/CVE-2020-7715)、[CVE-2022-21231](https://nvd.nist.gov/vuln/detail/CVE-2022-21231)
- [SNYK-JS-DEEPGETSET-598666](https://snyk.io/vuln/SNYK-JS-DEEPGETSET-598666)、[SNYK-JS-DEEPGETSET-2342655](https://snyk.io/vuln/SNYK-JS-DEEPGETSET-2342655)
- [GHSA-85cp-p426-42f5](https://github.com/advisories/GHSA-85cp-p426-42f5)
- V1 包：`npm:deep-get-set@1.1.1` `index.js`（[jsDelivr](https://cdn.jsdelivr.net/npm/deep-get-set@1.1.1/index.js)）
- V2 包：`npm:deep-get-set@1.1.2`
