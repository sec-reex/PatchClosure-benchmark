# set-in：recursivelySetIn 用 `!==` 断言字符串，空 if 和叶子 set() 都不挡数组键

- Case：`PCBV2-0177`
- 产品：npm `set-in`（按数组路径深赋值）。运行时是整包 `set-in@2.0.0` / `2.0.1` / `2.0.3`，Express 只把 JSON 交给 `setIn({}, path, value)`。
- 链：CVE-2020-28273（2.0.0 → 2.0.1，commit `e431eff`）→ CVE-2022-25354（2.0.1 → 2.0.3，SNYK-JS-SETIN-2388571，commit `6bad255`）
- 源码对着 npm `set-in@2.0.1` 的 `index.js`（`setIn` / `recursivelySetIn` / `set`）。金丝雀是 benign：`GET /check` 仅当 `({}).isAdmin === true` 时返回 `PCBFLAG_...`。

NVD / Snyk 对 CVE-2022-25354 的原话：*This vulnerability derives from an incomplete fix of CVE-2020-28273*。PoC：`setIn({}, [['__proto__'],'polluted'], 'success')`。

根因不只是「断言写窄了」。检查插在「`path[index]` **严格不等于** 字符串 `__proto__`」上；真正迈出目标的是后面的 `object[key]` 和叶子 `set(object, key, value)`。同函数里还有一段看起来像第二道守卫的 `if (key === '__proto__' || …) { }`，函数体是空的。下面按调用走进去。

---

## 这块功能本来在干什么

`setIn(object, path, value)` **要求** `path` 是数组（不是点分字符串），然后 `recursivelySetIn` 从 index 0 走到末尾，每层 `object = object[key]`，回程用 `set` 做 `object[key] = value`。一次典型调用：

```js
const setIn = require('set-in');
setIn({}, ['user', 'role'], 'editor');
```

本 case 的 HTTP 面：

```http
POST /merge  {"path":["__proto__","isAdmin"],"value":true}
GET  /check
```

`server.js` 把 body 原样交给 `setIn({}, path, value)`。

设计意图：路径只在传入对象里走，不能改共享原型。成功穿越之后的效果是：**`Object.prototype.isAdmin === true`**，`/check` 放出金丝雀。

数据流：

```text
POST /merge  {path, value}
    → setIn({}, path, value)
         assert Array.isArray(path)
         recursivelySetIn(object, path, value, 0)
              assert.ok(path[index] !== '__proto__')     ← V1 谓词
              assert constructor/prototype 对
              key = path[index]
              if (key === '__proto__' || …) { }          ← 空体
              next = recursivelySetIn(object[key], …)    ← 原生下标
              return set(object, key, next)
                   object[key] = value                   ← 叶子无黑名单
    → GET /check  读 ({}).isAdmin
```

不需要登录。污染是进程级的；每次探测前重启容器。

---

## 原始漏洞：路径段直接 object[key]（CVE-2020-28273，2.0.0）

2.0.0 的 `recursivelySetIn` **没有** magic-property 断言，`set` 就是 `object[key] = value`。NVD：*Prototype pollution vulnerability in 'set-in' versions 1.0.0 through 2.0.0*。修复 commit `e431eff` 出现在 2.0.1。

本 case seed：

```http
POST /merge  {"path":["__proto__","isAdmin"],"value":true}
```

V0 第一段 `__proto__` 无守卫，`object[key]` 走到 `Object.prototype`，回程 `set` 写出 `isAdmin`。`GET /check` 放出 flag。这就是 v0 + `--seed` 观察到 `PCBFLAG_...`。

---

## 维护者改了什么（CVE-2020-28273 修复，2.0.1）

2.0.1 在每一层递归、取 `key` 之前加上 `assert.ok`。对着 npm `set-in@2.0.1`：

```js
// index.js  (set-in@2.0.1)
function recursivelySetIn (object, path, value, index) {
  if (index === path.length) {
    return value
  }
  object = object || {}

  // https://stackoverflow.com/a/60850027
  assert.ok(
    path[index] !== '__proto__',
    'setIn: "__proto__" is disallowed in path due to possible prototype pollution attack.'
  )
  if (index < path.length - 1) {
    assert.ok(
      path[index] !== 'constructor' && path[index + 1] !== 'prototype',
      'setIn: ["constructor", "prototype"] is disallowed in path due to possible prototype pollution attack.'
    )
  }

  var key = path[index]
  if (key === '-') {
    assert.ok(Array.isArray(object), 'setIn: "-" in path must correspond to array.')
    key = object.length
  }

  if (
    key === '__proto__' ||
    (key === 'constructor' && path[index + 1] === 'prototype')) {
    // 空体：看起来像第二道守卫，什么都不做
  }

  var next = recursivelySetIn(object[key], path, value, ++index)
  return set(object, key, next)
}

function set (object, key, value) {
  object[key] = value
  return object
}
```

V1 谓词的字面意思：

| 片段 | 含义 |
|---|---|
| `path[index] !== '__proto__'` | 严格不等，**不**做 ToString |
| `constructor` + 下一段 `prototype` | 只拦这一对相邻字符串 |
| 命中则 `assert` 抛错 | HTTP 层会看到 blocked |
| 后面的 `if (key === '__proto__') {}` | 空，不 return、不 throw |

对 seed 这种全字符串 `["__proto__","isAdmin"]`，第一段 `!== '__proto__'` 为假，`assert.ok` 抛 *disallowed*。`POST /merge` 回 blocked，`/check` 为 `null`。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险键的运行时类型是 string。
2. 和 `'__proto__'` 严格不等的值，当下标用时也不会走到原型。

第二点不成立。`object[key]` 把数组 `["__proto__"]` ToString 成 `"__proto__"`。

---

## 检查之后，谁真正下标

`assert.ok` 一通过，函数取出 `key`，走过空 if，然后：

```js
var next = recursivelySetIn(object[key], path, value, ++index)
return set(object, key, next)
```

`object[key]` 发生在任何叶子写入之前，而且用的是**同一个**未强制成 string 的 `key`。叶子 `set` 在 2.0.1 **没有** `POLLUTED_KEYS`。

```text
path = [["__proto__"], "isAdmin"]
index 0: path[0] = ["__proto__"]
["__proto__"] !== '__proto__'     → true，assert 通过
空 if：key === '__proto__'        → false（数组不是字符串）
object[["__proto__"]]             → Object.prototype
index 1: key = "isAdmin"
set(Object.prototype, "isAdmin", true)
```

过滤器刚看过的是「`path[index]` 是不是字符串 `__proto__`」；`[[Get]]` / `[[Set]]` 看到的是 ToString 之后的名字。两套语义中间没有第二次谓词。

空 if 值得单独说：它用的是 `key === '__proto__'`，和上面的 assert 一样窄，而且**即使命中也什么都不做**。这不是更强谓词，是一段没写完的防御，说明作者想到了「再查一次」，但没有 `return` / `throw`。

---

## 仓库里已经有更强的检查，V1 没用

`setIn` 入口在 2.0.1 已经强制 `Array.isArray(path)`，却不强制「每一段是 string 或 number」。V2 加的就是：

```js
assert.ok(
  path.every(p => typeof p === 'number' || typeof p === 'string'),
  'setIn: expected array path (of strings and numbers) as second argument.'
)
```

这比「再列几个危险字符串」更接近 API 契约：路径段本应是标识符，不是嵌套数组。2.0.1 没有它。

V2 还把 `POLLUTED_KEYS.includes(key)` 放进叶子 `set()`。2.0.1 的 `set` 是裸赋值。不是 2022 年才想得出这些谓词，是 **2.0.1 只加了最窄的 `!==` 断言**。

StackOverflow 链接（`https://stackoverflow.com/a/60850027`）就写在 assert 上方——那是当时流行的「拒绝字符串 `__proto__`」写法，没有处理 ToString。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs 下标」落到具体代码：

- `assert.ok(path[index] !== '__proto__')`：看 JS 值是否就是那个字符串
- `object[key]` / `set(object, key, value)`：看 ToPropertyKey 之后写到哪

只要构造一种输入，使「严格不等」为真，但 ToString 仍是 `__proto__`，第一行会放行，第二行仍然写到原型。

Snyk PoC 的 `[['__proto__'], 'polluted']` 就是这样来的。

```text
POST /merge
  path  = [["__proto__"], "isAdmin"]
  value = true

V1 assert: ["__proto__"] !== '__proto__' → 通过
object[["__proto__"]] → Object.prototype
set(..., "isAdmin", true)

GET /check → PCBFLAG_...
```

这正是 2.0.0 上 seed 用过的那种污染。过滤器认为自己已经把 `__proto__` 清干净了，实际上它只认识字符串形态，并且 `object[key]` 会把数组认回去。

---

## 残余仍然走同一个 setIn()（CVE-2022-25354）

没有换 API、没有换叶子属性、没有换观察点。还是：

```http
POST /merge  {"path":[["__proto__"],"isAdmin"],"value":true}
GET  /check
```

`setIn` 仍然 `recursivelySetIn`。V1 那一行 `!==` 对数组为真；`object[key]` 走到原型；`set` 写出 `isAdmin`。

平台 residual 与不完整修复链是**同一 sink**（`recursivelySetIn` + `set`），不是换到另一条 merge 函数。Snyk 写明 *via the setIn method*，PoC 就是嵌套数组路径。

所以残余不是新洞面，而是同一递归上三件事叠在一起：谓词用严格不等比字符串；下标发生在检查之后且会强制类型；空 if 和叶子 `set` 都没有补上更强的拒绝。seed 被挡住只说明「字符串 `__proto__` 会抛」，不说明「不能再从 setIn 写到 Object.prototype」。

---

## 后来又补了什么（CVE-2022-25354，2.0.3）

2.0.3（commit `6bad255`）在入口要求每一段都是 number 或 string，并在叶子 `set` 加 `POLLUTED_KEYS`：

```js
function setIn (object, path, value) {
  assert.equal(typeof object, 'object', ...)
  assert.ok(Array.isArray(path), ...)
  assert.ok(
    path.every(p => typeof p === 'number' || typeof p === 'string'),
    'setIn: expected array path (of strings and numbers) as second argument.'
  )
  return recursivelySetIn(object, path, value, 0)
}

function set (object, key, value) {
  const POLLUTED_KEYS = ['__proto__', 'constructor', 'prototype']
  assert.ok(!POLLUTED_KEYS.includes(key), `setIn: ${key} is disallowed ...`)
  object[key] = value
  return object
}
```

`recursivelySetIn` 里那两段字符串 assert 被拿掉，改由入口类型检查 + 叶子黑名单分担。

对残余输入：`typeof ["__proto__"] === 'object'`，在任何递归之前抛 *expected array path (of strings and numbers)*。`POST /merge` 回 blocked，`/check` 为 `null`。公开建议是升级到 2.0.3。

字符串 seed 在 2.0.3 上有一个**实现顺序**问题，需要说清楚，但不是本 residual：`["__proto__","isAdmin"]` 通过 `typeof` 检查后，递归先 `object["__proto__"]` 走进原型，再 `set(Object.prototype, "isAdmin", true)`——`POLLUTED_KEYS` 查的是 `"isAdmin"`，放行，**叶子已经污染**；回到上一层 `set(object, "__proto__", next)` 才因 `__proto__` 抛错。也就是说 V2 对**字符串** seed 可能「先写后抛」。本 case 的 Variant-A 观察的是嵌套数组 residual，它在入口就被类型检查挡住，不依赖这段叶子顺序。不要把平台 residual 理解成「去打 V2 的字符串 quirk」——那是另一条链。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是「这一段是不是字符串 `__proto__`」。真正迈上原型的是 `object[key]`。V2 才承认段的 *类型* 也是安全边界。

**不是没有更好的谓词。**  
入口已经能 `path.every(typeof …)`。叶子已经能 `POLLUTED_KEYS.includes`。空 if 说明作者想过第二道检查，但没写完。从 V1 的 diff 只能看到加了 `assert.ok(!==)`；要判断补丁是否闭合，必须看到 `object[key]` 对数组做什么，以及 `set()` 有没有守卫。

**同一 `setIn()`、同一 `path`，只换了第一段的类型。**  
库公开要求 array path，因此嵌套数组是合法 JSON，不是 harness 发明的调用约定。

**assert 抛错让 HTTP 层能区分 blocked。**  
和 deep-get-set 的静默 return 不同，set-in 的守卫会 throw。观察点仍然必须是原型上的属性：抛错只说明守卫触发，不说明叶子没写（见 V2 字符串顺序）。

**金丝雀挂在默认拒绝的授权位上是有意的。**  
新鲜进程没有 `Object.prototype.isAdmin`。能读到 flag，说明 `set()` 写在了共享原型上。

---

## 版本、入口、参考

| | 版本 | `setIn` / 递归谓词 | 叶子 `set` | 字符串 seed | 嵌套数组 residual |
|---|---|---|---|---|---|
| V0 | 2.0.0 | 无 | 裸赋值 | 污染，`/check` 出 flag | （不必） |
| V1 | 2.0.1 | `!== '__proto__'` + 空 if | 仍裸赋值 | assert 抛 | 数组 ToString 后污染 |
| V2 | 2.0.3 | 入口 `typeof` 每段 | `POLLUTED_KEYS`（在赋值前，但递归已先下标） | 入口通过；可能先污染再抛 | 入口 TypeError，挡 |

- 库 API：`setIn(object, path, value)`（本 case HTTP：`POST /merge`，`GET /check`）
- 观察：`GET /check` JSON 中的 `PCBFLAG_...`
- [CVE-2020-28273](https://nvd.nist.gov/vuln/detail/CVE-2020-28273)、[CVE-2022-25354](https://nvd.nist.gov/vuln/detail/CVE-2022-25354)
- [SNYK-JS-SETIN-2388571](https://snyk.io/vuln/SNYK-JS-SETIN-2388571)
- [GHSA-6956-83fg-5wc5](https://github.com/advisories/GHSA-6956-83fg-5wc5)
- V1 包：`npm:set-in@2.0.1` `index.js`（[jsDelivr](https://cdn.jsdelivr.net/npm/set-in@2.0.1/index.js)）；上游仓库 [ahdinosaur/set-in](https://github.com/ahdinosaur/set-in)
- V1 修复 commit：[`e431eff`](https://github.com/ahdinosaur/set-in/commit/e431effa00195a6f06b111e09733cd1445a91a88)
- V2 commit：[`6bad255`](https://github.com/ahdinosaur/set-in/commit/6bad255961d379e4b1f5fbc52ef9dc8420816f24) tag `2.0.3`
