# immer：`p === "__proto__"` 比的是生钥匙，数组段会被 `get` 再字符串化

- Case：`PCBV2-0127`
- 产品：immer（不可变 state）。运行时是 npm `immer@7.0.15` / `8.0.1` / `9.0.6` 整包，Express `POST /apply` → 真实 `applyPatches`。
- 链：CVE-2020-28477（7.0.15 → 8.0.1，中间段 `p === "__proto__"`）→ CVE-2021-3757 / CVE-2021-23436（8.0.1 → 9.0.6，`p = "" + path[i]`，GHSA-c36v-fmgq-m8hx / GHSA-33f9-j839-rf8h）
- 源码对着 tag `v8.0.1` 的 `src/plugins/patches.ts`：`applyPatches_`。金丝雀通道是 `GET /check`：仅当 `({}).isAdmin === true`（原型被加上属性）才释放 `$PCB_FLAG`。

Snyk / NVD CVE-2021-23436 原话：*A type confusion vulnerability can lead to a bypass of CVE-2020-28477 when the user-provided keys used in the path parameter are arrays. In particular, this bypass is possible because the condition `(p === "__proto__" || p === "constructor")` in `applyPatches_` returns false if `p` is `['__proto__']`.*

根因不只是「少写了 `String()`」。检查插在「钥匙是不是这两个字符串」上；真正走原型的是后面的 `get(base, p)` / `base[key] = value`。JS 下标会把数组钥匙 `toString()` 成 `"__proto__"`。下面按请求走进去。

---

## 这块功能本来在干什么

`enablePatches()` 之后，`applyPatches(base, patches)` 按 RFC 6902 风格的 `{op, path, value}` 改一棵 state。`path` 是段数组，中间段用来走进树，最后一段用来赋值。一次典型 HTTP：

```http
POST /apply
{"patches":[{"op":"replace","path":["a","b"],"value":true}]}
```

服务用真实 `applyPatches({seeded:1}, patches)`。设计意图：补丁只能改这棵 fresh 对象上的 own 槽，不能改 `Object.prototype`。成功穿越之后的效果是：**`Object.prototype.isAdmin === true`，随后 `GET /check` 放出 flag**。

数据流（V1 = 8.0.1）：

```text
POST /apply  patches[].path
    → applyPatches_ (src/plugins/patches.ts)
         for i in 0 .. path.length-2:          ← 只守卫中间段
              p = path[i]                      ← 生值，不强制 string
              if p === "__proto__" || p === "constructor": die(24)
              base = get(base, p)              ← 下标会 ToString
         key = path[last]
         base[key] = value                     ← 叶子不守卫
    → GET /check  读 ({}).isAdmin
```

没有登录。污染是进程级的；oracle 每次 POST 前重启容器，避免 seed/residual 互相污染。

---

## 原始漏洞：中间段无守卫（CVE-2020-28477，7.0.15）

7.0.15 的中间循环就是 `base = get(base, path[i])`，没有魔术属性判断。Snyk 的 PoC：

```javascript
applyPatches({}, [{ op: 'replace', path: ['__proto__', 'polluted'], value: 'yes' }]);
```

`get(base, "__proto__")` 走到 `Object.prototype`，叶子把 `polluted` 写上去。本 case seed：

```text
path = ["__proto__", "isAdmin"], value = true
```

V0 上 `POST /apply` 成功，`GET /check` 返回 flag。

---

## 维护者改了什么（CVE-2020-28477 修复，8.0.1）

8.0.1 在**解引用之前**插入严格相等（tag `v8.0.1`）：

```typescript
// src/plugins/patches.ts :: applyPatches_  (immer v8.0.1)
    let base: any = draft
    for (let i = 0; i < path.length - 1; i++) {
      const parentType = getArchtype(base)
      const p = path[i]
      // See #738, avoid prototype pollution
      if (
        (parentType === ArchtypeObject || parentType === ArchtypeArray) &&
        (p === "__proto__" || p === "constructor")
      )
        die(24)
      if (typeof base === "function" && p === "prototype") die(24)
      base = get(base, p)
      if (typeof base !== "object") die(15, path.join("/"))
    }
    ...
    const key = path[path.length - 1]
    switch (op) {
      case REPLACE:
        ...
        return (base[key] = value)
```

`die(24)` 的文案是 *Patching reserved attributes like __proto__, prototype and constructor is not allowed*。对 seed：`p` 是字符串 `"__proto__"`，`===` 为真，抛错，`POST /apply` 被挡住，`/check` 仍是 `null`。这就是 v1 + `--seed` 退出码 10。

`constructor` 走同一条 `===`。数组段 `["constructor"]` 同样 `!== "constructor"`，却会在 `get` 时变成字符串 `"constructor"`。advisory 把两种都写进了 *if p is `['__proto__']` (or `['constructor']`)*。本 case 用 `__proto__` 是因为它能直接把 walk 送到 `Object.prototype`；`constructor` 会先走到 `Object` 构造器，叶子写的位置不同，观察通道也就不同。

补丁默认了两件事：

1. 危险钥匙的运行时类型是 string，而且等于这两个字面量之一。
2. 比较用的值和稍后 `get`/`[]` 用的值，对「是不是 `__proto__`」这个问题答案相同。

第二点在钥匙是数组时不成立。`===` 不强制转换；属性访问会。

守卫范围还有第三条：只跑 `i < path.length - 1`。叶子 `key` 从不进 `die(24)`。所以危险名必须当**中间段**，才能先走到原型再写叶子。`path: ["isAdmin"]` 单独一段只会在 `{seeded:1}` 上加 own 属性，污染不了原型。

---

## 检查之后谁真正解引用

`p === "__proto__"` 为假之后，同一轮循环立刻：

```text
base = get(base, p)
```

immer 的 `get` 对普通对象就是 `base[p]`。ECMA-262：ToPropertyKey。数组 `["__proto__"]` 的 `toString` 是 `"__proto__"`（`join`）。于是：

```text
p = ["__proto__"]
p === "__proto__"          → false     // 过滤器放行
base[p]                    → base["__proto__"]
                           → Object.prototype
```

下一轮结束，叶子 `key = "isAdmin"`，`base[key] = true` 写在原型上。过滤器刚看过的是「生值是不是字符串 `__proto__`」；下标看的是 ToString 之后的键。中间没有 `String(p)`。

---

## 仓库里已经有更强的检查，比较之前没用上

同一循环里已经有 `typeof base === "function" && p === "prototype"`，说明作者知道要拦魔术名。缺的是**比较前的规范化**。把钥匙先变成字符串：

```javascript
let p = "" + path[i]
```

之后 `=== "__proto__"` 对数组段也为真。这就是 9.0.6 唯一改动的那一个 token。也可以在 `get` 之前拒绝非 string/number 的段（JSON Patch 的 path 本应是 string 段）。V1 选择相信 `path[i]` 的运行时类型与属性键相同。

叶子仍然不守卫。即便 V2 强制了中间段，`path: ["__proto__"]` 这种**单段**叶子写在 8.x/9.x 的 `applyPatches_` 里仍然不进 `die(24)`——它不会先 `get` 到原型（没有中间段）。本 case 残余需要两段：中间数组 + 叶子 `isAdmin`。

---

## 这个补丁挡住了什么、没挡住什么

- V1 过滤器：`p === "__proto__"`（严格、无强制转换）
- `get(base, p)` / `base[key]`：ToPropertyKey

对 residual 把类型变换写全：

```text
JSON path[0]          = ["__proto__"]          // Array, length 1
typeof path[0]        = "object"
path[0] === "__proto__"  → false              // 守卫用的比较
String(path[0])       = "__proto__"           // Array.prototype.toString = join
get(base, path[0])    = base["__proto__"]     // 解引用用的键
                      = Object.prototype
path[1]               = "isAdmin"
Object.prototype.isAdmin = true
```

seed 的 `path[0]` 已经是 string，第一步就 `die(24)`，走不到 `get`。residual 让第一步和第二步对「这是不是 `__proto__`」给出相反答案。

advisory PoC 就是 `path: [['__proto__'], 'polluted']`。本 case 把叶子换成 `isAdmin`，好让 `/check` 当授权门。

---

## 残余仍然走同一条 applyPatches_ 中间循环（CVE-2021-3757 / 23436）

没有换 endpoint、没有换 `enablePatches`。还是：

```http
POST /apply
{"patches":[{"op":"replace","path":[["__proto__"],"isAdmin"],"value":true}]}
```

`applyPatches_` 照样跑 V1 那几行 `===`。数组段滑过去，`get` 走进原型，叶子写入。`GET /check` 看到继承来的 `isAdmin`，放出 flag。

本 case residual 与 Snyk 同一构造。认证：v1 + `--residual` 观察到 `PCBFLAG_...`。V2 上 `"" + ["__proto__"]` 得到 `"__proto__"`，`die(24)`，`/check` 为 null。

seed 被挡住只说明「字符串钥匙 `__proto__` 没了」，不说明「`applyPatches` 不能再写 `Object.prototype`」。

平台 verify 与这条链是同一 sink：真实 `applyPatches_` → 进程级原型 → `/check`。

---

## 后来又补了什么（CVE-2021-3757，9.0.6）

GHSA-c36v-fmgq-m8hx 钉 9.0.6。中间循环只改赋值：

```typescript
-      const p = path[i]
+      let p = "" + path[i]           // coerce key to string before the magic-property compare
       // See #738, avoid prototype pollution
       if (
         (parentType === ArchtypeObject || parentType === ArchtypeArray) &&
         (p === "__proto__" || p === "constructor")
       )
         die(24)
```

对残余：`"" + ["__proto__"] === "__proto__"`，在 `get` 之前抛错。公开建议 `immer@>=9.0.6`。

这仍然是「比较前把钥匙变成 string」，叶子循环不变。对本条 nested-array residual 够用。本 benchmark 的 v2 只关闭这一条。

---

## 从这条链还能看出什么

**维护者改错了哪一层。**  
他们改的是「生钥匙等不等于这两个字面量」。真正污染的是 `get`/`[]` 的 ToPropertyKey。V2 让比较层去迁就下标层的强制转换，而不是禁止非标量段。

**不是没有更好的谓词。**  
`String(p)` 或 `typeof p === "string"` 都比裸 `===` 更接近「属性名是什么」。从 8.0.1 的 diff 只能看到加上了 `===`；要判断是否闭合，必须看到 `get(base, p)` 在守卫失败之后仍用同一个 `p`。

**同一循环、只换了 JSON 里那一段的类型。**  
`["__proto__","isAdmin"]` 和 `[["__proto__"],"isAdmin"]` 对 `get` 是同一个键，对 `===` 不是。

**守卫范围不包括叶子。**  
设计上中间段才决定「走到哪颗对象」。污染必须用中间 `__proto__`。只扫叶子会漏；只扫中间、又不强制类型，也会漏。

**`get` 和 `===` 不是同一种「等于」。**  
`["__proto__"] === "__proto__"` 是 false。`obj[["__proto__"]]` 是 `obj["__proto__"]`。过滤器问的是前者，属性系统问的是后者。CVE 编号里的 type confusion（CWE-843）指的就是这件事：比较按 Array 做，访问按 String 做。

**JSON 允许 path 段不是 string。**  
RFC 6902 的 pointer 段是字符串；immer 的 JS API 接受任意值当段。V1 没把 JSON 里来的数组段当成非法输入，只当成「不等于 `"__proto__"` 的钥匙」。

**金丝雀不在 patch JSON 里是有意的。**  
body 只有 path/value。token 出现在 `/check`，说明有一次写落在了 `Object.prototype` 上——也就是过滤器放行了那次 `get`。

---

## 版本、入口、参考

| | 版本 | 中间段守卫 | seed 字符串 `__proto__` | residual 数组 `["__proto__"]` |
|---|---|---|---|---|
| V0 | 7.0.15 | 无 | 污染，flag | （不必） |
| V1 | 8.0.1 | `p === "__proto__"` 无强制转换 | die(24) | 污染，flag |
| V2 | 9.0.6 | `p = "" + path[i]` 再比较 | 挡 | die(24) |

- HTTP：`POST /apply` 然后 `GET /check`
- [CVE-2020-28477](https://github.com/advisories/GHSA-9qmh-276g-x5pj)、[CVE-2021-23436](https://nvd.nist.gov/vuln/detail/CVE-2021-23436)、[CVE-2021-3757](https://nvd.nist.gov/vuln/detail/CVE-2021-3757)
- [GHSA-33f9-j839-rf8h](https://github.com/advisories/GHSA-33f9-j839-rf8h)、[GHSA-c36v-fmgq-m8hx](https://github.com/advisories/GHSA-c36v-fmgq-m8hx)
- [Snyk SNYK-JS-IMMER-1540542](https://security.snyk.io/vuln/SNYK-JS-IMMER-1540542)
- 源码：[`v8.0.1` `applyPatches_`](https://github.com/immerjs/immer/blob/v8.0.1/src/plugins/patches.ts)
