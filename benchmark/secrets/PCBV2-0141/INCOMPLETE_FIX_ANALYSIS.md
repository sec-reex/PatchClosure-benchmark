# lodash merge：safeGet 只挡 __proto__，constructor.prototype 仍走进函数

- Case：`PCBV2-0141`
- 产品：npm `lodash`。应用侧是一个把用户 JSON 交给 `_.merge`、再读新鲜对象上 `pcbUnlock` 的 HTTP 探针。
- 链：CVE-2018-3721（4.17.4 → 4.17.5，引入 `safeGet`）→ CVE-2018-16487（4.17.5…4.17.10 → 4.17.11，去掉 `srcIndex &&` 对函数的原地合并）
- 源码对着发布包 `lodash@4.17.4` / `@4.17.5` / `@4.17.11` 的 `lodash.js`：`baseMergeDeep`、`safeGet`。运行时装的是发布包本身，不是抽出来的函数。

2018 年，lodash 给深度合并加了 `safeGet`：读 `object[key]` 时若 `key == '__proto__'` 就当 `undefined`。这挡住了 `{"__proto__":{"x":1}}` 这种 JSON 自有键走上 Object.prototype 的写法。Snyk / Sonatype 随后指出：`constructor` 不是 `__proto__`，`safeGet` 会返回真正的 `Object` 函数，而 4.17.5 对**第一个** source（`srcIndex === 0`）仍把函数当可合并对象原地递归。NVD CVE-2018-16487 写的是 *merge, mergeWith, and defaultsDeep can be tricked into adding or modifying properties of Object.prototype*；Snyk SNYK-JS-LODASH-73638 写明 *This is due to an incomplete fix to CVE-2018-3721*。Sonatype 进一步写：根因是 4.17.5 那次不完整修复**引入**的，受影响区间是 `[4.17.5, 4.17.11)`。

根因不只是「少写了一个危险键名」。检查插在「读 key 的时候要不要返回 undefined」这一层；真正往原型上写的是递归走进 `Object.prototype` 之后的叶子赋值；同函数里已经有「函数要不要先 clone」的分支，却被 `srcIndex &&` 在第一次合并时关掉。下面按 JSON 走进去、4.17.5 改了哪几行、safeGet 之后谁真正递归、更宽的 clone 谓词有没有挂上，把这几层写完。

---

## 这块功能本来在干什么

`_.merge(dest, source)` / `_.mergeWith` / `_.defaultsDeep` 递归把 source 的自有键抄进 dest。键名来自 JSON 时，`__proto__` 是普通自有键，不是引擎的 `[[Prototype]]` 槽——这正是污染能发生的前提。一次典型调用：

```javascript
_.merge({}, JSON.parse(req.body.payload));
```

本 case 的 harness 保证每次探测前 `Object.prototype.pcbUnlock` **不存在**，做成默认拒绝：新鲜 `({})` 读到的 `pcbUnlock` 为 `undefined` 就拒绝；只有 merge 把真值写到**共享原型**上，门闩才放出 `PCB_FLAG`。污染是全局的，每次探测后删掉。

数据流：

```text
HTTP JSON payload
    → _.merge({}, payload)
         baseMergeDeep
              V1：objValue = safeGet(object, key)     ← 补丁插在这里
                  srcValue = safeGet(source, key)
              若 src 是普通对象：
                  若 objValue 是函数且 srcIndex && ... → clone
                  否则 newValue = objValue            ← 可能是 Object 函数
              递归 mergeFunc(newValue, srcValue, ...)
              叶子：dest[key] = value                 ← 真正的写
    → 读 ({ }).pcbUnlock → 有则返回 PCB_FLAG
```

没有登录。判断完全信任 `safeGet` 对「危险键」的读法，不信任稍后对函数 `objValue` 是否原地递归。

---

## 原始漏洞：object[key] 直接走上 __proto__（CVE-2018-3721，4.17.4）

4.17.4 的 `baseMergeDeep` 裸读：

```javascript
// lodash.js :: baseMergeDeep  (lodash@4.17.4)
var objValue = object[key],
    srcValue = source[key],
    stacked = stack.get(srcValue);
```

JSON `{"__proto__":{"pcbUnlock":true}}` 解析后，`source` 上有一个**自有**键 `'__proto__'`。`object['__proto__']` 对普通 `{}` 返回 `Object.prototype`。递归把 `pcbUnlock` 写到原型上。

本 case 的 seed 就是这份 payload。4.17.4 上新鲜对象继承到 `pcbUnlock`，响应里出现 `PCBFLAG_...`。注意必须用 `JSON.parse`：对象字面量 `{__proto__: ...}` 在现代引擎里是改 `[[Prototype]]`，不会给 merge 一个自有键。

---

## 维护者改了什么（CVE-2018-3721 修复，4.17.5）

4.17.5 把两处读取换成 `safeGet`，并新增：

```javascript
// lodash.js :: safeGet  (lodash@4.17.5)
/**
 * Gets the value at `key`, unless `key` is "__proto__".
 */
function safeGet(object, key) {
  return key == '__proto__'
    ? undefined
    : object[key];
}
```

```javascript
// lodash.js :: baseMergeDeep  (lodash@4.17.5)
var objValue = safeGet(object, key),
    srcValue = safeGet(source, key),
    stacked = stack.get(srcValue);
```

V1 的字面意思：只有键名用 `==` 等于 `'__proto__'` 时读成 `undefined`，递归不会以 Object.prototype 当 `objValue` 起步。其它键，包括 `'constructor'`、`'prototype'`，原样 `object[key]`。

对 seed 这种明文 `__proto__` 键，它确实够用：

```text
payload: {"__proto__":{"pcbUnlock":true}}
safeGet(dest, '__proto__') === undefined
safeGet(src,  '__proto__') === undefined
递归没有可写的 dest 槽，pcbUnlock 不会出现在 Object.prototype
({}).pcbUnlock === undefined → denied
```

这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 能走到内建原型的键只有字面量 `'__proto__'`。
2. 读到函数当 `objValue` 时，后面的分支会把它 clone 成普通对象，不会原地合并进 `Object`。

第二点在 4.17.5 上对**第一个** source 不成立。同函数稍后有：

```javascript
else if (isPlainObject(srcValue) || isArguments(srcValue)) {
  newValue = objValue;
  if (isArguments(objValue)) {
    newValue = toPlainObject(objValue);
  }
  else if (!isObject(objValue) || (srcIndex && isFunction(objValue))) {
    newValue = initCloneObject(srcValue);
  }
}
```

`srcIndex && isFunction(objValue)`：第一次合并 `srcIndex === 0`，短路为 false，**不 clone**。`newValue` 保持为那个函数，递归继续往函数上合并。

---

## safeGet 之后，谁真正走进 Object.prototype

V1 的 `safeGet` 一放过 `'constructor'`，同一个 `baseMergeDeep` 立刻：

```text
key = 'constructor'
objValue = safeGet({}, 'constructor') === Object          // 函数
srcValue = { prototype: { pcbUnlock: true } }             // 普通对象
srcIndex === 0
srcIndex && isFunction(Object) === 0 && true === false
newValue = Object                                         // 不 clone
递归 merge(Object, { prototype: { pcbUnlock: true } })
  key = 'prototype'
  safeGet(Object, 'prototype') === Object.prototype
  叶子写 Object.prototype.pcbUnlock = true
```

`safeGet` 刚看过的是键名是不是 `'__proto__'`；递归看到的是 `Object` 函数上的 `'prototype'` 属性——那是语言自己的引用，不是用户对象上的普通槽。两套语义中间没有「不要把函数当 merge 目标」的第二次谓词（第一次 source 上被 `srcIndex &&` 关掉了）。

harness 的门闩读的是另一个新鲜对象。金丝雀能出现，依据就是叶子写到了共享原型，而不是 `_.merge` 的 dest 自己有一个 `pcbUnlock`。

---

## 仓库里已经有更强的 clone，第一次 source 没用

`isFunction(objValue)` 在 V1 就已经写在分支里，只是被 `srcIndex &&` 挡住。V2 去掉这个短路：

```javascript
// lodash.js :: baseMergeDeep  (lodash@4.17.11)
else if (!isObject(objValue) || isFunction(objValue)) {
  newValue = initCloneObject(srcValue);
}
```

谁在 V1 对函数 `objValue` 做 clone：

| 条件 | 会 `initCloneObject`？ |
|---|---|
| `srcIndex > 0` 且 `isFunction(objValue)` | 是 |
| `srcIndex === 0`（第一个 source，`_.merge` 的常态） | **否**，原地合并进函数 |

不是仓库里没有「函数不能当 merge 目标」这份谓词。V1 等于在读取层又做了一个**更窄**的特殊情况（只认 `__proto__`），而 clone 层那个更接近「不要走进内建」的检查在最常见的调用上没挂上。

`safeGet` 在 V2 仍然只挡 `__proto__`。V2 闭合 residual 靠的是 clone，不是把 `'constructor'` 加进 `safeGet`。这也是为什么后来还有 CVE-2019-10744（`defaultsDeep` 上另一条 constructor.prototype 面）——本 case 的 residual 故意用 `_.merge`，让 4.17.11 成为干净的负对照。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs 递归写」落到具体代码：

- `safeGet(object, key)`：看键名是不是 `'__proto__'`
- `newValue = objValue` 然后 `mergeFunc(newValue, srcValue)`：看递归实际走进哪个对象

只要用一条 `safeGet` 会原样返回、且最终能引用到 `Object.prototype` 的键链，第一行会放行，第二行仍然写到原型上。

token 变换：

```text
seed:     {"__proto__":{"pcbUnlock":true}}
V1:       safeGet(..., '__proto__') === undefined
          不走上 Object.prototype

residual: {"constructor":{"prototype":{"pcbUnlock":true}}}
V1:       safeGet({}, 'constructor') === Object
          srcIndex===0 → 不 clone
          safeGet(Object, 'prototype') === Object.prototype
          写下 pcbUnlock
```

JSON 过线时 `constructor` / `prototype` 都是普通自有键，不需要 `__proto__` 那种「JSON 自有键 vs 引擎槽」的把戏。HackerOne 380873 / Sonatype 写的就是这份 `{constructor:{prototype:{...}}}` 形状。

V1 拦的是「键名这两个字符序列 `__proto__`」；CVE-2018-3721 真正要拦的是「merge 不能改 Object.prototype」。后者在 `constructor.prototype` 链上原样还在。

---

## 残余仍然走同一条 merge 递归写路径（CVE-2018-16487）

没有换 API、没有换 sink、没有换门闩。还是 `_.merge` → `baseMergeDeep` → 叶子赋值：

```json
{"payload":{"constructor":{"prototype":{"pcbUnlock":true}}}}
```

`baseMergeDeep` 仍然先 `safeGet`；`'constructor'` 放过；第一次 source 不 clone 函数；递归走到 `Object.prototype`；`pcbUnlock` 被加上；新鲜对象继承到它，响应里出现 `PCBFLAG_...`。

本 case `verify.sh` 的 residual 把 candidate 写死在脚本里。和 Snyk / Sonatype / HackerOne 380873 的 constructor.prototype 形状同一构造。认证：v1 + `--residual` 退出码 0。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：`safeGet` 只认一个键名；走进原型靠的是语言自己的 `Object.prototype` 引用；「函数要 clone」已经写在分支里却被 `srcIndex &&` 在第一次合并时关掉。seed 被挡住只说明「`__proto__` 这个键没了」，不说明「不能再通过 merge 往 Object.prototype 上加属性」。

平台 verify 的 residual 打的就是这条 incomplete-fix 链上的同一 `baseMergeDeep` 写，不是另一条无关 sink。

---

## 后来又补了什么（CVE-2018-16487，4.17.11）

4.17.11 去掉 `srcIndex &&`，任何函数 `objValue` 都先 `initCloneObject`：

```javascript
- else if (!isObject(objValue) || (srcIndex && isFunction(objValue))) {
+ else if (!isObject(objValue) || isFunction(objValue)) {
    newValue = initCloneObject(srcValue);
  }
```

对残余输入：`objValue` 是 `Object` 函数 → `newValue` 是一份新鲜普通对象 → `{prototype:{pcbUnlock:true}}` 写到这份 clone 上，碰不到真正的 `Object.prototype`。`safeGet` 未改，seed 仍然挡。公开建议是升级到 4.17.11。

即便如此，`defaultsDeep` 在 4.17.11 上仍有独立的 constructor.prototype 面（CVE-2019-10744，4.17.12）。本 case 不用 `defaultsDeep`，V2 对这条 residual 是干净负对照。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是「读 key 时要不要假装没有」。真正改原型的是递归走进 `Object` 函数的 `prototype`。V2 改的是「函数要不要当 merge 目标」，比再往 `safeGet` 里堆键名更接近 sink。

**不是没有更好的谓词。**  
`isFunction(objValue) → initCloneObject` 已经写在 4.17.5 里。它比 `key == '__proto__'` 更接近「不要合并进内建」。从 V1 的 diff 只能看到加了 `safeGet`；要判断补丁是否闭合，必须看到 `srcIndex &&` 和 `Object.prototype` 这条引用链。

**同一函数、同一 `_.merge`，只换了 JSON 的第一层键名。**  
任何把用户对象传进 `merge` / `mergeWith` / `defaultsDeep` 的调用，在 4.17.5 上都吃这次 `safeGet` 和同一次递归。advisory 点名了三个函数。

**Sonatype 的版本区间值得对着源码看。**  
他们写根因**引入于** 4.17.5：4.17.4 用 `__proto__` 就能污，算 CVE-2018-3721；4.17.5–4.17.10 才是「修了 `__proto__`、留下 constructor」的 incomplete-fix 窗口。本 case 的 V0/V1/V2 正好卡在这三道门上。

**金丝雀是加属性，不是删。**  
`pcbUnlock` 事先不存在。能读到 flag，说明写到了共享原型，而不是 dest 自己的命名空间。

---

## 版本、入口、参考

| | npm | `safeGet` | 函数 `objValue` | seed `__proto__` | residual `constructor.prototype` |
|---|---|---|---|---|---|
| V0 | 4.17.4 | 无，裸 `object[key]` | 原地合并 | 污染，放出 flag | （不必） |
| V1 | 4.17.5 | `key == '__proto__'` → undefined | `srcIndex &&` 时才 clone | 挡 | 第一次 source 不 clone，污染，放出 flag |
| V2 | 4.17.11 | 同上 | 任意函数都 clone | 挡 | 挡 |

- Web：JSON `payload` 交给 `_.merge`
- 认证（本平台）：v0 seed 观察到 flag；v1 seed 未观察到；v1 residual 观察到
- [CVE-2018-3721](https://nvd.nist.gov/vuln/detail/CVE-2018-3721)、[CVE-2018-16487](https://nvd.nist.gov/vuln/detail/CVE-2018-16487)
- [Snyk SNYK-JS-LODASH-73638](https://security.snyk.io/vuln/SNYK-JS-LODASH-73638)
- [Sonatype 分析](https://www.sonatype.com/blog/cve-2018-16487-lodash-rce-prototype-pollution)
- [HackerOne 380873](https://hackerone.com/reports/380873)
- 源码：发布包 `lodash@4.17.5` 的 `lodash.js` `safeGet` / `baseMergeDeep`
