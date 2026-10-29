# set-value：`=== '__proto__'` 挡不住会被 ToString 的数组键

- Case：`PCBV2-0190`
- 产品：npm `set-value`（按路径写嵌套属性）。运行时 `set-value@3.0.0` / `@4.0.0` / `@4.0.1` 整包，经 `setValue(obj, path, value)` 调用，不是抽出来的一行比较。
- 链：CVE-2019-10747（3.0.0 → 4.0.0，`isUnsafeKey` 字符串黑名单）→ CVE-2021-23440（4.0.0 → 4.0.1，`validateKey` 先 `String(key)`）
- 源码对着 tag `4.0.0` / `4.0.1` 的 `index.js`。金丝雀是 benign：只有写到 `Object.prototype` 时，新鲜 `{}` 才能继承 `pcbUnlock`，门控才吐 `PCBFLAG_...`。

NVD / GHSA-4jqc-8m5r-9rpr 原话：*A type confusion vulnerability can lead to a bypass of CVE-2019-10747 when the user-provided keys used in the path parameter are arrays.* Snyk SNYK-JS-SETVALUE-1540541 把影响面写成 `<2.0.1, >=3.0.0 <4.0.1`，修复在 4.0.1。

根因不只是「漏了一种 path 写法」。检查插在 `key === '__proto__'` 这种**严格相等**上；真正走属性的是后面的 `obj[key]`。同文件里已经有把数组 `flat().map(String)` 的 `toString`，却只用来做 memo 缓存键。下面按调用走进去。

---

## 这块功能本来在干什么

`set-value` 的公开 API 是：

```js
const set = require('set-value');
set(target, path, value);
```

`path` 可以是点分字符串 `"a.b.c"`，也可以是段数组 `['a','b','c']`。库按段走，没有的中间层就 `obj[key] = {}`，最后一段赋值。设计意图：只改 `target` 自己的嵌套数据，不要碰到 `Object.prototype`。成功穿越之后的效果是：**最后一次赋值落在 `Object.prototype` 上**，之后任意 `{}` 都能读到那个键。

本 case HTTP 只是把 JSON path 转交给这个 API：

```http
GET /probe?spec=["__proto__","pcbUnlock"]     // seed，字符串段
GET /probe?spec=[["__proto__"],"pcbUnlock"]   // residual，数组段
```

数据流：

```text
setValue(target, path, TRIGGER)
    → keys = split(path)          // 数组 path 原样当 keys
    → 对每一段：
         validateKey(key)         ← V1：isUnsafeKey 用 ===
         obj = obj[key]           ← 引擎 ToString / [[Get]]
         最后一段 setProp(obj, key, value)
              obj[prop] = value
    → 若某段是 __proto__：obj 变成 Object.prototype
    → 新鲜 {} 继承 pcbUnlock === TRIGGER → 放出 PCBFLAG_...
```

没有鉴权概念。污染是全局的，harness 每次探完 `delete Object.prototype.pcbUnlock`。

---

## 原始漏洞：字符串 `__proto__` 直接走上去（CVE-2019-10747，3.0.0）

3.0.0 的 `set()` 对 path 分段后直接 `obj[key]`，没有 unsafe 检查。seed `"__proto__.pcbUnlock"` 第一段就是字符串 `'__proto__'`，`obj['__proto__']` 拿到 `Object.prototype`，再写 `pcbUnlock`。v0 上新鲜对象继承到触发值，门控放出 flag。

---

## 维护者改了什么（CVE-2019-10747 修复，4.0.0）

4.0.0 加了严格字符串比较，并在分段循环和 `setProp` 里调用：

```js
// index.js  (set-value 4.0.0)
const isUnsafeKey = key => {
  return key === '__proto__' || key === 'constructor' || key === 'prototype';
};

const validateKey = key => {
  if (isUnsafeKey(key)) {
    throw new Error(`Cannot set unsafe key: "${key}"`);
  }
};

const setValue = (obj, path, value, options) => {
  const keys = split(path, options);
  for (let i = 0; i < keys.length; i++) {
    const key = keys[i];
    validateKey(key);
    if (next === undefined) {
      setProp(obj, key, value, options);
      break;
    }
    if (!isObject(obj[key])) {
      obj[key] = {};
    }
    obj = obj[key];
  }
};
```

`split` 对数组 path 几乎原样返回：`const keys = Array.isArray(input) ? input : input.split(sep)`。段可以仍是数组。字符串 path 才会走 `input.split('.')` 和数字段转换；嵌套数组当段时，`typeof keys[i] !== 'string'` 让后面的 `isNumber` / 反斜杠拼接循环直接 `break`，数组原样进 `validateKey`。

V1 谓词的字面意思：键 **严格等于** 那三个字符串就抛。没有 `String(key)`，没有 `Object.prototype.hasOwnProperty` 意义上的「这个名字会不会碰到原型」。

对 seed 这种字符串段 `'__proto__'`，它确实够用：`key === '__proto__'` 为真，抛 `Cannot set unsafe key`，赋值不发生。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险键的运行时类型是 string。
2. `===` 挡得住之后，`obj[key]` 也不会再走到原型。

第二点不成立。`obj[['__proto__']]` 会把数组 ToString 成 `'__proto__'`。

---

## 检查之后谁真正写那个键

`validateKey` 一结束，同一轮循环立刻用**同一个** `key` 做属性访问：

```js
if (!isObject(obj[key])) {
  obj[key] = {};
}
obj = obj[key];
// 最后一段：
obj[prop] = value;
```

ECMAScript `[[Get]]` / `[[Set]]` 对非字符串、非 symbol 的键做 ToString。`['__proto__'].toString()` 是 `'__proto__'`（`Array.prototype.toString` → `join`）。过滤器刚看过的是「`key === '__proto__'` 这个布尔」；引擎看到的是 ToString 之后的属性名。中间没有第二次 `validateKey(String(key))`。

`split` 之后循环里 `next === undefined` 才 `setProp`。第一段是数组时：

```js
key  = ['__proto__']          // validateKey 放行
next = 'pcbUnlock'            // 还有下一段
obj  = obj[ ['__proto__'] ]   // → Object.prototype
// 下一轮：
key  = 'pcbUnlock'
validateKey('pcbUnlock')      // 不是三个禁名
setProp(Object.prototype, 'pcbUnlock', TRIGGER)
```

`setProp` 里会再调一次 `validateKey(prop)`，用的仍是那个数组，仍然 `!== '__proto__'`，仍然放行，然后 `obj[prop] = value` 写到原型上。`options.merge` 分支同样先 `validateKey` 再 `obj[prop] = merge(...)`，类型混淆一样成立；本 case 不走 merge，走默认赋值。`delete obj[prop]`（value 为 undefined）也会在通过守卫后作用到原型上，本 case 用的是写成触发值而不是删除。

---

## 仓库里已经有更强的规范化，validateKey 没用

同一份 `index.js` 顶部就有：

```js
const toString = input => {
  return Array.isArray(input) ? input.flat().map(String).join(',') : input;
};
```

它用在 `memoize` 的缓存键上，好让数组 path 也能进 `Map`。`validateKey` 不调用它。更巧的是 `memoize` 自己也会 `validateKey(key)`，但此时 `key` 已经是 `flat().join(',')` 的结果 `'__proto__,pcbUnlock'`，`=== '__proto__'` 为假——缓存路径上的那一次检查同样放行。4.0.1 的修复也不是复用 `toString`，而是在 `isUnsafeKey` 之前对非 string/number 做 `key = String(key)`——对 `['__proto__']` 来说，`String(['__proto__'])` 同样是 `'__proto__'`。

谁规范化（4.0.0）：

| 位置 | 是否 `String(key)` / `toString` |
|---|---|
| `memoize` 缓存键 | 是，`toString` |
| `split` 的数字段 | 把数字字符串变成 number |
| `validateKey` / `isUnsafeKey` | **否**，裸 `===` |
| `obj[key]` | 引擎隐式 ToString |

不是仓库里没有更好的谓词，是 **安全检查没用已经存在的规范化**。即便挡住数组，`constructor` / `prototype` 的其它包装对象仍可能靠同一套 ToString 钻；V2 只保证「先变成原始字符串再比」。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「严格相等 vs 属性键 ToString」落到具体 path：

- V1 过滤器：`key === '__proto__'`（数组是 false）
- `obj[key]`：`ToString(['__proto__']) === '__proto__'`，走到 `Object.prototype`

```text
seed（path = "__proto__.pcbUnlock" 或 ["__proto__","pcbUnlock"]）:
  key 是字符串 '__proto__'
  → validateKey 抛错 → 不污染

residual（path = [["__proto__"],"pcbUnlock"]）:
  第一段 key 是 ['__proto__']
  → ['__proto__'] === '__proto__' 为 false
  → obj[['__proto__']] → Object.prototype
  → 第二段写 pcbUnlock
```

advisory 说的就是「path 参数里的 key 是数组」。本 case 用嵌套数组当第一段，观察的是同一扇门。

---

## 残余仍然走同一条 setValue 赋值（CVE-2021-23440）

没有换 API、没有换 `pcbUnlock` 门控、没有换「新鲜 `{}` 读继承属性」。还是：

```js
setValue({}, [['__proto__'], 'pcbUnlock'], 'unlocked');
```

`setValue` 仍然 `split` → `validateKey` → `obj[key]`。V1 那一次 `===` 照样对数组为假；赋值照样落在 `Object.prototype`。平台残余和 seed 都是这个函数的原型污染。不是另一个 npm 包，也不是 `constructor.prototype` 另一条链（4.0.0 的 `=== 'constructor'` 同样挡不住数组包装，但本 case 用的是 `__proto__` 这一条公开 residual）。

seed 被挡住只说明「字符串 `__proto__` 没了」，不说明「不能再让 `obj[key]` 的 ToString 走到原型」。

---

## 后来又补了什么（CVE-2021-23440，4.0.1）

4.0.0 → 4.0.1 的 `index.js` **只改了** `validateKey`：

```js
// index.js  (set-value 4.0.1)
const validateKey = key => {
  if (typeof key !== 'string' && typeof key !== 'number') {
    key = String(key);
  }
  if (isUnsafeKey(key)) {
    throw new Error(`Cannot set unsafe key: "${key}"`);
  }
};
```

对残余输入：`String(['__proto__'])` 得到 `'__proto__'`，`isUnsafeKey` 为真，抛错，不污染。公开建议升级到 4.0.1（以及 2.0.1 / 3.0.3 对应分支）。

即便如此，这仍然是「在 `obj[key]` 之前把键变成原始字符串再比黑名单」。对本条数组键够用。本 benchmark 的 v2 只关闭这一条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是「键是不是这三个字面量」。真正碰到原型的是 `obj[key]` 的 ToString。V2 仍在 `validateKey` 加码，但终于先做语言层面的键转换。

**不是没有更好的规范化。**  
`toString` 已经为数组 path 写好。从 V1 的 diff 只能看到三个 `===`；要判断是否闭合，必须看到 `split` 原样保留非字符串段，以及 `obj[key]` 的 ToString。

**同一 `setValue`、同一 `validateKey`，只换了段的运行时类型。**  
字符串段撞黑名单；数组段绕过比较、在赋值时变回字符串。

**类型检查和属性键语义不是一层。**  
`===` 看的是 JS 值。属性名看的是 ToPropertyKey。两边各说各话时，黑名单是空的。

**金丝雀必须从新鲜对象上读到才算。**  
写在 `target.a.b.pcbUnlock` 上的自有属性不会让 `{}` 继承到。能放出 flag，说明写的是 `Object.prototype`——也就是 `validateKey` 放行了那次 `obj[key]`。harness 每次探完删除全局污染，避免下一次探针误报。

**`constructor` 走同一套 `===`。**  
`isUnsafeKey` 三个名字同一条严格相等。数组包装 `['constructor']` 在 4.0.0 上同样 `!== 'constructor'`，`obj[key]` 同样 ToString。本 case 用 `__proto__` 是因为 advisory / Snyk 写明的就是数组 key 绕过 10747；另外两条名字是同一扇门上的同一种类型混淆。

---

## 版本、入口、参考

| | 版本 | `validateKey` | `obj[key]` | 字符串 seed | 数组段 residual |
|---|---|---|---|---|---|
| V0 | 3.0.0 | 无 | 跟随 ToString | 污染，flag | （不必） |
| V1 | 4.0.0 | `key === '__proto__'` 等 | 同上 | 抛错 | 数组 ToString 后污染，flag |
| V2 | 4.0.1 | 先 `String(key)` 再比 | 同上 | 挡 | 抛错 |

- 库 API：`require('set-value')(obj, path, value)`；本 case HTTP：`GET /probe?spec=`
- [CVE-2019-10747](https://nvd.nist.gov/vuln/detail/CVE-2019-10747)、[CVE-2021-23440](https://nvd.nist.gov/vuln/detail/CVE-2021-23440)
- [GHSA-4jqc-8m5r-9rpr](https://github.com/advisories/GHSA-4jqc-8m5r-9rpr)
- [Snyk SNYK-JS-SETVALUE-1540541](https://security.snyk.io/vuln/SNYK-JS-SETVALUE-1540541)
- V1 源码：[`4.0.0` `index.js`](https://github.com/jonschlinkert/set-value/blob/4.0.0/index.js)
- V2 tag：[`4.0.1` `validateKey`](https://github.com/jonschlinkert/set-value/blob/4.0.1/index.js)
