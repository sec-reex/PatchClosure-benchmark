# dset：守卫比较的是原始键，赋值用的是 ToString 之后的键

- Case：`PCBV2-0062`
- 产品：npm `dset`（lukeed，深层赋值小工具）
- 链：字符串键守卫（3.0.0，commit `0a11c8a`；本 case V1 钉在 3.1.2）→ CVE-2024-21529（…3.1.3 → 3.1.4，commit `16d6154`）。CVE-2022-25645 修的是**另一份** `dset/merge` 拷贝循环（3.1.2，commit `2d156c7`），不是 `dset()` 本体。
- 源码对着 GitHub tag `v2.0.1` / `v3.1.2` / `v3.1.4` 的 `src/index.js`：`dset`。运行时是发布包本身，经 HTTP `/probe` 调用真实 `dset()`。

2021 年 1 月，`dset` 3.0.0 在键循环里加了 `if (k === '__proto__' || k === 'constructor' || k === 'prototype') break`。2022 年 CVE-2022-25645 修的是 `merge` 助手对 JSON 对象键的拷贝。2024 年 Snyk CVE-2024-21529 / SNYK-JS-DSET-7116691 给出的 PoC 是 `dset({}, [["__proto__"], "polluted"], true)`——第一段不是字符串。NVD 写 *via the dset function due improper user input sanitization*。3.1.4 把 `k = keys[i++]` 改成 `k = ''+keys[i++]`。

根因不只是「少写了 toString」。检查插在「`k` 是不是那三个字符串」这一层；真正做属性访问的是 `t[k]`，而 `[]` 会把键 ToPrimitive。同一次循环里，比较用的值和赋值用的值不是同一种类型。下面按一次 `dset` 走进去、V1 改了哪一行、检查之后谁去写 `Object.prototype`、仓库里已经有什么更早的强制转换、残余怎么用数组键把同一条污染打到 `pcbUnlock`。

---

## 这块功能本来在干什么

`dset(obj, keys, val)` 按点分路径或数组路径深层赋值，中间对象不存在就造出来。典型调用：

```javascript
dset(config, "user.name", "alice");
dset(config, ["user", "name"], "alice");
```

本 case 的应用侧拿它写用户控制的路径，然后用一份默认拒绝的门：只有 `Object.prototype.pcbUnlock` 变成真值才释放 `${PCB_FLAG}`。设计意图：路径段是普通自有属性名，写在传入的 `obj` 上。成功穿越之后的效果是 **路径走出这份对象，落到共享的 `Object.prototype` 上**，之后任意 `({})` 都继承到那个键。

数据流：

```text
HTTP /probe  JSON spec
    → dset(freshObj, keys, true)
         keys.split && keys = keys.split('.')
         k = keys[i++]                      ← V1 不强制字符串
         if (k === '__proto__' || ...) break
         t = t[k] = ...                     ← [] 会 ToString(k)
    → 若 t 走到 Object.prototype，叶赋值污染全局
    → 门控读 ({ }).pcbUnlock → 释放 PCB_FLAG
```

没有登录。污染是进程全局的，harness 每次探针后 `delete Object.prototype.pcbUnlock`。

---

## 原始漏洞：键循环没有任何危险名检查（V0 = 2.0.1）

2.0.1 的循环直接 `t[keys[i]]`：

```javascript
// src/index.js  (dset@2.0.1)
export default function (obj, keys, val) {
	keys.split && (keys=keys.split('.'));
	var i=0, l=keys.length, t=obj, x;
	for (; i < l; ++i) {
		x = t[keys[i]];
		t = t[keys[i]] = (i === l - 1 ? val : ...);
	}
}
```

字符串段 `"__proto__"` 让 `t["__proto__"]` 走到 `Object.prototype`，下一轮把 `pcbUnlock` 写上去。本 case 的 seed：

```text
keys = ["__proto__", "pcbUnlock"]
val  = true
```

2.0.1 没有 break。新鲜 `({})` 继承到 `pcbUnlock`，门放开。这就是 v0 + `--seed`。

说明（源码核实，不是 CVE 编号字面）：`dset()` 本体的字符串守卫来自 3.0.0（commit `0a11c8a`，*fix: break loop on unsafe keys*），不是 CVE-2022-25645 的 3.1.2。3.1.2 的 `2d156c7` 只在 `src/merge.js` 的 `for (k in b)` 拷贝循环里加了一道同类 `===` 判断，用来挡 `JSON.parse('{"__proto__":{"polluted":"Yes!"}}')` 这种「对象键在 merge 里递归」的写法。`dset@3.1.1` / `3.1.2` / `3.1.3` 的 `src/index.js` 字节相同：都是 `k = keys[i++]` 再 `===`。本 case 把 V1 钉在 3.1.2，是因为发布包里 `dset()` 已带字符串守卫，足以挡住 seed，又尚未做 `''+`。seed 代表「`__proto__` 段走进 `dset()`」这一类污染，**不声称**是 25645 的 merge PoC 逐字节复现。

---

## 维护者改了什么（字符串守卫，本 case V1 = 3.1.2）

3.1.2 的 `dset`：

```javascript
// src/index.js  (dset@v3.1.2)
export function dset(obj, keys, val) {
	keys.split && (keys=keys.split('.'));
	var i=0, l=keys.length, t=obj, x, k;
	while (i < l) {
		k = keys[i++];
		if (k === '__proto__' || k === 'constructor' || k === 'prototype') break;
		t = t[k] = (i === l) ? val : (typeof(x=t[k])===typeof(keys)) ? x
		          : (keys[i]*0 !== 0 || !!~(''+keys[i]).indexOf('.')) ? {} : [];
	}
}
```

`k = keys[i++]` 没有类型转换。`===` 对字符串以外的值恒为 false。对 seed：

```text
k = "__proto__"   （string）
k === '__proto__' → true → break
不写 pcbUnlock
```

这就是 v1 + `--seed` 被挡住。同一循环里，后面已经出现 `''+keys[i]`——用来判断下一段像不像数组下标。**当前**这段 `k` 却不转换。

补丁默认了两件事：

1. 危险段的运行时类型已经是 string（来自点分路径或字符串数组）。
2. `t[k]` 用的 `k` 和 `===` 用的 `k` 是同一个值、同一种语义。

第二点不成立。`t[k]` 在 `k` 是对象时会调用 `ToPrimitive` / `toString`。`["__proto__"].toString()` 是 `"__proto__"`。

---

## 检查之后，谁真正去写那个属性

`===` 一放过，同一行立刻 `t = t[k] = ...`。JavaScript 的属性访问把非字符串、非 symbol 的键转换成字符串：

```text
k = ["__proto__"]          // Array
k === '__proto__'          // false
t[k]  →  t[String(k)]  →  t["__proto__"]
```

若 `t` 是普通对象，`t["__proto__"]` 是 `[[Prototype]]` setter，得到 `Object.prototype`。下一轮 `k = "pcbUnlock"`（字符串，不是三个危险名），叶赋值写成 `Object.prototype.pcbUnlock = true`。

检查看见的是原始数组对象。`[]` 看见的是 ToString 之后的 `"__proto__"`。两套语义中间没有第二次 `===`。Snyk 的 PoC 正是：

```javascript
lib.dset({}, [["__proto__"], "polluted"], true)
```

本 case 把叶键换成 `pcbUnlock`，让默认拒绝门翻转为放行。

---

## 仓库里已经有强制转字符串，当前键没用

同一行后半已经写了 `(''+keys[i]).indexOf('.')`——对**下一段**做 `''+`。merge 助手（CVE-2022-25645）也在拷贝循环里拦危险名。3.1.4 的修复只是把 `''+` 挪到当前 `k` 上，一行：

```javascript
-		k = keys[i++];
+		k = ''+keys[i++];
```

不是仓库里没有「先变成字符串再比较」的写法，是 **守卫读的是强制转换之前的 `k`**。`''+` 对数组 `["__proto__"]` 的结果恰好是危险名本身。

即便没有 `''+`，用 `Object.hasOwn` / 拒绝非 string 段 / `Object.create(null)` 目标，也能切断这条链。V1 选了最窄的 `===` 三个字面量。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs 赋值」落到具体代码：

- V1 的 `k === '__proto__'`：看原始 `k` 是不是这三个字符串之一
- `t[k]`：看 ToString(k) 之后落到哪个属性

只要构造一种输入，使原始 `k` 不是字符串 `"__proto__"`，但 `String(k)` 是，第一行会放行，第二行仍然走进原型。

```text
keys = [["__proto__"], "pcbUnlock"]

i=0  k = ["__proto__"]
     ["__proto__"] === "__proto__"  → false
     t = t[["__proto__"]]           → Object.prototype

i=1  k = "pcbUnlock"
     不是危险名
     Object.prototype.pcbUnlock = true
```

字符变换发生在语言内部的 ToString，不在 dset 自己的代码里。V1 **不改写**键，只决定 break 还是赋值。

---

## 残余仍然走同一条 dset 键循环（CVE-2024-21529）

没有换函数、没有换叶键名、没有换门控。还是 `dset(obj, keys, true)` 写 `pcbUnlock`。只是第一段从字符串换成数组：

```text
spec = [["__proto__"], "pcbUnlock"]
```

V1 那一行 `===` 照样执行；执行完之后认为不是危险名；`t[k]` 把数组变成 `"__proto__"`；叶写到 `Object.prototype`；`({}).pcbUnlock` 为真，金丝雀放出。

Snyk advisory 的 PoC 与 3.1.4 测试 `should protect against ["__proto__"] assignment :: implicit string` 是同一构造。测试里断言 `input.__proto__` 不变、`{}.polluted` 仍是 `undefined`。把叶键换成 `pcbUnlock` 只改变门控读哪个名字，不改变「数组段 → ToString → 原型」这一跳。本文按 **v3.1.2 源码 + 公开 PoC** 推导。

`constructor` / `prototype` 两条字面量走同一 `===`。数组 `["constructor"]` 同样 `!== "constructor"`，却能让 `t[k]` 走到 `Object.prototype.constructor`。本 case residual 只用 `__proto__`，因为这是 Snyk PoC 和 3.1.4 新测试覆盖的那一条；另外两条是同一类型混淆，不另开洞面。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：比较用 `===`；赋值用 `[]` 的 ToString；同循环已经会对**下一段**做 `''+` 却不对当前段做。seed 被挡住只说明「字符串 `__proto__` 会 break」，不说明「不能再把原型写成带 `pcbUnlock`」。

---

## 后来又补了什么（CVE-2024-21529，3.1.4，commit 16d6154）

3.1.4 在比较**之前**强制字符串：

```javascript
// src/index.js  (dset@v3.1.4)
		k = ''+keys[i++];
		if (k === '__proto__' || k === 'constructor' || k === 'prototype') break;
```

对残余：`''+["__proto__"]` 得到 `"__proto__"`，break，不写。`merge.js` 做了同样的 `''+`。测试文件加上 implicit string 用例。公开建议是升级到 3.1.4。NVD 把修复 commit 记成 `16d6154e085bef01e99f01330e5a421a7f098afa`。

即便如此，这仍然是「三个名字的字符串黑名单」。对这条数组键链它够用。其它能让 `[]` 走到原型、却 ToString 不成这三个字面量的键（例如 `constructor` 的奇怪装箱）需要另证。本 benchmark 的 v2 只关闭 `[["__proto__"], ...]` 这一条。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是「`k` 是不是这三个字符串」。真正污染的是 `t[k]` 的 ToString 语义。V2 仍在同一层把 `k` 先变成字符串，没有禁止非 string 段，也没有 `Object.create(null)`。

**不是没有更好的谓词。**  
同循环已经对 `keys[i]` 做 `''+`。从 V1 的 diff 只能看到三行 `===`；要判断补丁是否闭合，必须看到 `k = keys[i++]` 没有转换，以及下一句 `t[k]` 会转换。

**同一函数、同一循环，只换了段的 JS 类型。**  
任何把用户数组交给 `dset()` 的入口，在 3.1.2 上都吃这次 `===` 和同一次 `t[k]`。JSON 若允许嵌套数组，HTTP 体就能直接送来 `[["__proto__"], ...]`。

**CVE-2022-25645 和这条链不是同一个函数。**  
25645 修 `merge` 的 `for-in`。21529 修 `dset` 的键类型。把 V1 钉在 3.1.2 是为了让「字符串 seed 被挡、数组 residual 仍过」落在同一份 `dset()` 上，不要把 merge 的修复误当成这条守卫的修复。

**金丝雀靠污染后的继承，不靠 obj 自有属性。**  
门控读的是新鲜 `({})`。能放出 flag，说明写到了 `Object.prototype`，而不是 `freshObj.pcbUnlock`。

**点分路径挡不住数组路径。**  
`keys.split && (keys=keys.split('.'))` 只在 `keys` 有 `split` 方法时把字符串切开。传入数组时这段是 no-op，段可以是任意 JS 值。HTTP JSON 里写 `[["__proto__"], "pcbUnlock"]` 不经过点分拆解，也没有机会在 split 阶段把嵌套数组压成字符串。守卫若只假设「调用方给的是 `"a.b.c"`」，就会漏掉数组 API——而这正是 `dset` 文档里的一等用法。

**比较和赋值必须对同一份键说话。**  
V2 的 `k = ''+keys[i++]` 让 `===` 和 `t[k]` 看到同一个字符串。V1 让它们看到两种类型。任何「先用 `===` 拦危险名、再用 `obj[k]` 写入」的循环，只要 `k` 可能不是 string，都会在这两步之间被 ToString 拆开。3.1.4 的测试标题 *implicit string* 指的就是这一步，不是又一个危险名字。

---

## 版本、入口、参考

| | npm | `dset()` 守卫 | 字符串 `__proto__` seed | 数组 `["__proto__"]` residual |
|---|---|---|---|---|
| V0 | 2.0.1 | 无 | 污染，开门 | （不必） |
| V1 | 3.1.2 | `k === '__proto__'`（无 `''+`） | break | `t[k]` ToString 后污染 |
| V2 | 3.1.4 | `k = ''+keys[i++]` 再比较 | 挡 | 转成字符串后 break |

- Web：`GET/POST /probe`（JSON `spec`）
- 源码：GitHub `lukeed/dset` tag `v3.1.2` 的 `src/index.js`
- [CVE-2024-21529](https://nvd.nist.gov/vuln/detail/CVE-2024-21529)、[CVE-2022-25645](https://github.com/advisories/GHSA-23wx-cgxq-vpwx)
- [Snyk SNYK-JS-DSET-7116691](https://security.snyk.io/vuln/SNYK-JS-DSET-7116691)（含 `[["__proto__"], "polluted"]` PoC）
- [commit 16d6154](https://github.com/lukeed/dset/commit/16d6154e085bef01e99f01330e5a421a7f098afa)（`''+`）
- [commit 2d156c7](https://github.com/lukeed/dset/commit/2d156c7f615877ad11d2586f54865ebdc11e4acc)（merge，CVE-2022-25645）
- [commit 0a11c8a](https://github.com/lukeed/dset/commit/0a11c8a)（3.0.0，字符串守卫首次出现）
