# lodash baseUnset：守卫只认 string，toKey 却把数组折回 __proto__

- Case：`PCBV2-0139`
- 产品：npm `lodash`。应用侧是一个把用户路径交给 `_.unset`、再读新鲜对象上种植锁 `pcbLocked` 的 HTTP 探针。
- 链：CVE-2025-13465（4.17.21 → 4.17.23，commit `edadd45`）→ CVE-2026-2950（4.17.23 → 4.18.1；advisory 写 4.18.0，本 case 用 4.18.1 因 4.18.0 随后 deprecated）
- 源码对着发布包 `lodash@4.17.21` / `@4.17.23` / `@4.18.1` 的 `lodash.js`：`baseUnset`、`parent`、`toKey`、`_.unset`。运行时装的是发布包本身，不是抽出来的函数。

2026 年 1 月，lodash 给 `baseUnset` 加了一圈路径段检查，想挡住 `_.unset(obj, '__proto__.toString')` 这种从共享原型上**删**属性的洞。GHSA-xxjr-mmjv-4gpg / CVE-2025-13465 写的是 *crafted paths which cause Lodash to delete methods from global prototypes*。两个月后 GHSA-f23m-r3pf-42rh 指出：那圈检查开头写了 `if (typeof key !== 'string') continue`，数组包一层的段会被跳过，而后面的 `toKey` 又把它折成 `'__proto__'`。NVD CVE-2026-2950 写明 *the fix for CVE-2025-13465 only guards against string key members*。

根因不只是「少判断了一种类型」。检查插在「段是不是字符串、是不是叫 `__proto__`」这一层；真正 `delete` 的是 `parent()` 走完之后的 `delete obj[toKey(last(path))]`；同文件里已经有 `toKey`，却只挂在 delete 上、不挂在守卫上。下面按路径走进去、4.17.23 改了哪一段、守卫之后谁真正 delete、更早的强制转换有没有挂上，把这几层写完。

---

## 这块功能本来在干什么

`_.unset(object, path)` / `_.omit` 按点号或数组路径删属性。路径可以是 `'a.b.c'`，也可以是 `['a','b','c']`，还可以是**混合数组**（某一段自己又是数组）。一次典型调用：

```javascript
_.unset(userDoc, req.body.path);
```

本 case 的 harness 在每次探测前把 `Object.prototype.pcbLocked = true` 种上，做成默认拒绝：新鲜对象继承到这把锁就拒绝；只有 `_.unset` 把锁从**原型上删掉**，门闩才放出 `PCB_FLAG`。污染是全局的，每次探测后恢复。

数据流：

```text
HTTP JSON path
    → _.unset(object, path)
         baseUnset
              path = castPath(path, object)
              V1：while 扫每一段
                   typeof key !== 'string' → continue     ← 补丁插在这里
                   key === '__proto__' → return false
              object = parent(object, path)               ← 内部再 toKey
              delete object[toKey(last(path))]            ← 真正的 delete
    → 读 ({ }).pcbLocked → 锁没了则返回 PCB_FLAG
```

没有登录。判断完全信任守卫对「段的 typeof」的读法，不信任稍后 `toKey` 会把同一段折成什么字符串。

---

## 原始漏洞：路径段直接拿去 delete（CVE-2025-13465，4.17.21）

4.17.21 的 `baseUnset` 没有原型检查：

```javascript
// lodash.js :: baseUnset  (lodash@4.17.21)
function baseUnset(object, path) {
  path = castPath(path, object);
  object = parent(object, path);
  return object == null || delete object[toKey(last(path))];
}
```

`parent` 用 `baseGet` 走到倒数第二段。`toKey` 把非 string / 非 symbol 折成字符串：

```javascript
// lodash.js :: toKey  (lodash@4.17.21，约 L6817–6823)
function toKey(value) {
  if (typeof value == 'string' || isSymbol(value)) {
    return value;
  }
  var result = (value + '');
  return (result == '0' && (1 / value) == -INFINITY) ? '-0' : result;
}
```

`['__proto__'] + ''` 在 JS 里是 `'__proto__'`（数组 `toString` 等于 `join(',')`）。于是：

```text
path = '__proto__.pcbLocked'
castPath → ['__proto__', 'pcbLocked']
parent → object['__proto__'] === Object.prototype
delete Object.prototype.pcbLocked
```

本 case 的 seed 就是这条字符串路径。4.17.21 上锁被删掉，响应里出现 `PCBFLAG_...`。GHSA-xxjr-mmjv-4gpg 描述的是同一 delete-on-prototype 效果（他们举的是 `toString` 一类内建方法）。

---

## 维护者改了什么（CVE-2025-13465 修复，4.17.23）

commit `edadd45`（*Prevent prototype pollution on baseUnset function*）在 `castPath` 之后、`parent` 之前加了一圈循环。发布包 `lodash@4.17.23` 的函数是：

```javascript
// lodash.js :: baseUnset  (lodash@4.17.23)
function baseUnset(object, path) {
  path = castPath(path, object);

  // Prevent prototype pollution, see: https://github.com/lodash/lodash/security/advisories/GHSA-xxjr-mmjv-4gpg
  var index = -1,
      length = path.length;

  if (!length) {
    return true;
  }

  var isRootPrimitive = object == null || (typeof object !== 'object' && typeof object !== 'function');

  while (++index < length) {
    var key = path[index];

    // skip non-string keys (e.g., Symbols, numbers)
    if (typeof key !== 'string') {
      continue;
    }

    if (key === '__proto__' && !hasOwnProperty.call(object, '__proto__')) {
      return false;
    }

    if (key === 'constructor' &&
        (index + 1) < length &&
        typeof path[index + 1] === 'string' &&
        path[index + 1] === 'prototype') {
      if (isRootPrimitive && index === 0) {
        continue;
      }
      return false;
    }
  }

  var obj = parent(object, path);
  return obj == null || delete obj[toKey(last(path))];
}
```

V1 循环的字面意思：

| 片段 | 含义 |
|---|---|
| `typeof key !== 'string'` | 非字符串段**跳过**，不当成危险 |
| `key === '__proto__'` | 字符串 `__proto__` 且不是自有属性 → 拒绝 |
| `constructor` + 下一段是字符串 `'prototype'` | 拒绝（根为原始值时第一段除外） |

对 seed 这种明文字符串路径，它确实够用：

```text
path: '__proto__.pcbLocked'
castPath → ['__proto__', 'pcbLocked']
typeof '__proto__' === 'string'
hasOwnProperty(object, '__proto__') 为 false
return false          // 不 delete
pcbLocked 还在 → denied
```

这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险段长得像字符串 `'__proto__'` 或字符串对 `'constructor'`/`'prototype'`。
2. 非字符串段不会在稍后被折成这两个名字。

第二点不成立。`toKey` 就在同一个文件里，delete 和 `parent`/`baseGet` 都会用它。循环用 `typeof` 决定「要不要检查」，sink 用 `toKey` 决定「实际访问哪个名字」。

---

## 守卫之后，谁真正 delete

V1 的 `while` 一结束（或某段被 `continue` 跳过），同一个函数立刻：

```javascript
var obj = parent(object, path);
return obj == null || delete obj[toKey(last(path))];
```

`parent` → `baseGet` 对每一段再做一次 `toKey`。所以守卫跳过的数组段，在真正走路时变成普通字符串键。`delete` 看的不是「循环里那个 typeof」，而是折完之后的属性名。

对残余路径 `[['__proto__'], 'pcbLocked']`：

```text
castPath 保持混合数组（已经是 array path）
path[0] = ['__proto__']          typeof === 'object' → continue
path[1] = 'pcbLocked'            普通字符串，不是 __proto__ / constructor
循环结束，没有 return false

parent(object, path)
  baseGet 第一段 toKey(['__proto__']) === '__proto__'
  走到 Object.prototype

delete Object.prototype[toKey('pcbLocked')]
  → delete Object.prototype.pcbLocked
```

过滤器认为自己已经把危险字符串段拦完了，实际上它刚跳过了唯一危险的那一段，并且 `parent` / `delete` 会按折完的名字访问。

---

## 仓库里已经有更强的转换，守卫没用

`toKey` 在 4.17.21 就存在，V1 的 delete 行继续调用它。V2 只是把同一函数挪到检查**之前**：

```javascript
// lodash.js :: baseUnset  (lodash@4.18.1)
while (++index < length) {
  var key = toKey(path[index]);   // 先折，再比

  if (key === '__proto__' && !hasOwnProperty.call(object, '__proto__')) {
    return false;
  }
  if ((key === 'constructor' || key === 'prototype') && index < length - 1) {
    return false;
  }
}
```

谁在 V1 调用 `toKey`：

| 位置 | 调用 `toKey`？ |
|---|---|
| 守卫循环 | **否**，用裸 `path[index]` + `typeof` |
| `parent` / `baseGet` | 是 |
| 最后的 `delete` | 是 |

不是仓库里没有「段要先规范化再判断」这份谓词。V1 等于在守卫里又做了一个**更弱**的类型门（非 string 当安全），而真正走路的那套转换始终在用。从 V1 的 diff 只能看到加了一圈 `typeof` / `===`；要判断补丁是否闭合，必须看到 `toKey(['__proto__']) === '__proto__'`。

注释写 *skip non-string keys (e.g., Symbols, numbers)*，假设的是「这些键不会指向原型」。数组不在举例里，但 `typeof [] === 'object'`，一样走 `continue`。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs delete」落到具体代码：

- 守卫：`typeof key === 'string'` 才看名字
- `parent` / `delete`：`toKey(段)` 之后按字符串访问

只要构造一种路径，使危险名字以**非 string** 的形态出现在守卫里、以 **string** 的形态出现在 sink 里，第一圈会放行，第二行仍然删到原型上。

token 变换：

```text
seed:     "__proto__.pcbLocked"
V1 守卫:  两段都是 string，第一段 === '__proto__' → return false

residual: [["__proto__"], "pcbLocked"]
V1 守卫:  第一段 typeof 'object' → continue
          第二段 'pcbLocked' 不是危险名
V1 sink:  toKey(['__proto__']) → '__proto__'
          delete Object.prototype.pcbLocked
```

JSON 过线时数组结构还在，所以 residual 必须走 JSON path，不能再写成点号字符串。GHSA-f23m-r3pf-42rh 原话：*an attacker can bypass the check by passing array-wrapped path segments*。

V1 拦的是「段的 typeof 是 string 且名字叫 `__proto__`」；CVE-2025-13465 真正要拦的是「delete 不能落到内建原型上」。后者在 `toKey` 仍能造出 `__proto__` 时原样还在。

---

## 残余仍然走同一条 unset delete 路径（CVE-2026-2950）

没有换 API、没有换 sink、没有换门闩。还是 `_.unset` → `baseUnset` → `parent` → `delete`：

```json
{"path": [["__proto__"], "pcbLocked"]}
```

`baseUnset` 仍然先跑那圈守卫；第一段被 `continue`；`parent` 用 `toKey` 走上 Object.prototype；`delete` 去掉 `pcbLocked`；新鲜对象不再继承锁，响应里出现 `PCBFLAG_...`。

本 case `verify.sh` 的 residual 把 candidate 写死在脚本里。和 advisory 描述的 array-wrapped 段同一构造。认证：v1 + `--residual` 退出码 0。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：守卫用 `typeof` 决定查不查；走路用 `toKey` 决定名字；`toKey` 已经存在却没挂在守卫上。seed 被挡住只说明「字符串 `__proto__` 没了」，不说明「不能再从 Object.prototype 上删属性」。

平台 verify 的 residual 打的就是这条 incomplete-fix 链上的同一 `baseUnset` delete，不是另一条无关 sink。

---

## 后来又补了什么（CVE-2026-2950，4.18.1）

4.18.0 / 4.18.1 在检查前先 `toKey`，并且把 `constructor` / `prototype` 当作中间段一律拒绝（不再要求下一段是字符串 `'prototype'`）：

```javascript
var key = toKey(path[index]);
if (key === '__proto__' && !hasOwnProperty.call(object, '__proto__')) {
  return false;
}
if ((key === 'constructor' || key === 'prototype') && index < length - 1) {
  return false;
}
```

对残余输入：`toKey(['__proto__'])` 先变成 `'__proto__'`，守卫拒绝，不 delete。advisory 写 *patched in 4.18.0*；4.18.0 随后因 breaking change 被 deprecated，本 case 的负对照用 4.18.1。公开建议是升级到 4.18.1 或更高。

即便如此，这仍然是「在 delete 之前多折一次再比名字」。`parent` 自己不再做第二套原型检查。对 array-wrapped `__proto__` 这条已知链它够用。本 benchmark 的 v2 只关闭这一条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是「段在检查时的 typeof」。真正逃到原型上的是 `toKey` + `delete`。V2 仍在同一函数加码，但终于先折再比。

**不是没有更好的谓词。**  
`toKey` 比 `typeof === 'string'` 更接近「这段最终会访问哪个名字」。它已经用在 delete 上。从 V1 的 diff 只能看到加了 `continue`；要判断补丁是否闭合，必须看到 `toKey([])` 的强制转换。

**同一函数、同一 `path`，只换了第一段的包装。**  
任何把用户路径传进 `_.unset` / `_.omit` 的调用，在 4.17.23 上都吃这圈 `typeof` 和同一次 `delete`。lodash 路径本来就接受混合数组，这不是新 API。

**`constructor` 那一支同样用 `typeof path[index+1] === 'string'`。**  
`[['constructor'], 'prototype', 'x']` 一类包装在 V1 上同样能让「constructor.prototype 链」检查失效。本 case 的 residual 用 `__proto__` 包装就够认证。

**金丝雀是删锁，不是加属性。**  
`pcbLocked` 先种在原型上。能读到 flag，说明 delete 落到了共享原型，而不是对象自己的自有槽。

---

## 版本、入口、参考

| | npm | `baseUnset` 守卫 | `toKey` 用在 | 字符串 `__proto__.pcbLocked` | 数组 `[['__proto__'],'pcbLocked']` |
|---|---|---|---|---|---|
| V0 | 4.17.21 | 无 | 仅 delete / parent | 删锁，放出 flag | （不必） |
| V1 | 4.17.23 | `typeof !== 'string'` 则 skip | 仍仅 delete / parent | return false | skip 后 delete，放出 flag |
| V2 | 4.18.1 | 先 `toKey` 再比 | 守卫 + delete | 挡 | 挡 |

- Web：JSON `path` 交给 `_.unset`
- 认证（本平台）：v0 seed 观察到 flag；v1 seed 未观察到；v1 residual 观察到
- [CVE-2025-13465](https://nvd.nist.gov/vuln/detail/CVE-2025-13465) / [GHSA-xxjr-mmjv-4gpg](https://github.com/lodash/lodash/security/advisories/GHSA-xxjr-mmjv-4gpg)
- [CVE-2026-2950](https://nvd.nist.gov/vuln/detail/CVE-2026-2950) / [GHSA-f23m-r3pf-42rh](https://github.com/lodash/lodash/security/advisories/GHSA-f23m-r3pf-42rh)
- V1 commit：`edadd45`（4.17.20…4.17.23 compare 可见）
- 源码：发布包 `lodash@4.17.23` 的 `lodash.js` `baseUnset`
