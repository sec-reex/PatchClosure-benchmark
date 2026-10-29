# minimist setKey：__proto__ 字符串挡了，constructor.prototype 仍走进 Object.prototype

- Case：`PCBV2-0144`
- 产品：npm `minimist`（CLI 参数解析）。应用侧是一个把 argv 交给真实 `minimist()`、再读新鲜对象上 `pcbUnlock` 的 HTTP 探针。
- 链：CVE-2020-7598（1.2.1 → 1.2.5 窗口内的 `__proto__` 字符串守卫；守卫本身始于 1.2.3）→ CVE-2021-44906（1.2.5 → 1.2.6，commit `7efb22a518`，`isConstructorOrProto`）
- 源码对着 GitHub tag `v1.2.5` 的 `index.js`：`setKey`。运行时装的是发布包本身（`minimist@1.2.1/1.2.5/1.2.6`），不是抽出来的函数。

2020 年，minimist 在 `setKey` 里加了 `if (key === '__proto__') return`，想挡住 `--__proto__.x` 这种点号路径走上 Object.prototype 的污染。Snyk 把后续的 CVE-2021-44906 写成 *a bypass to CVE-2020-7598*。Debian / GHSA-xvch-5gv4-984h 写明原修复不完整：守卫只看字符串 `'__proto__'`，不看 `constructor` / `prototype` 这条链。1.2.6 换成 `isConstructorOrProto(o, key)`。

根因不只是「少写了一个键名」。检查插在「这一段是不是字面量 `__proto__`」这一层；真正写到原型上的是 `o = o[key]` 走完之后的叶子赋值；同函数里已经有「若 `o` 已经是 Object.prototype 就换一份 `{}`」的谓词，却只挂在**最后一段**，并且中间段那次 `o[key] = {}` 对不可写的 `Object.prototype` 是静默空操作。下面按 argv 走进去、1.2.5 有哪几行、守卫之后谁真正赋值、更宽的 constructor 检查有没有挂上，把这几层写完。

V0 钉在 1.2.1 而不是 1.2.2：1.2.2 已经有一层 `o[key] === {}.__proto__` 的引用相等处理，会挡住明文 `--__proto__.x` seed，不是干净的「完全没有 __proto__ 处理」的 V0。1.2.3/1.2.4/1.2.5 的字符串守卫字节相同；V1 取最后一版 1.2.5，好让 V1→V2 正好卡在 CVE-2021-44906 那条边界上。

---

## 这块功能本来在干什么

`minimist(argv)` 把 `--a.b.c value` 拆成嵌套对象。点号键经 `key.split('.')` 变成路径，交给内部 `setKey(obj, keys, value)`：逐段 `o = o[key]`，没有则建 `{}`，最后一段赋值。一次典型调用：

```javascript
minimist(['--foo.bar', '1']);
// → { _: [], foo: { bar: 1 } }
```

本 case 的 harness 保证每次探测前后 `Object.prototype.pcbUnlock` 不存在，做成默认拒绝：新鲜 `({})` 读到的 `pcbUnlock` 为假就拒绝；只有 `setKey` 把真值写到**共享原型**上，门闩才放出 `PCB_FLAG`。

数据流：

```text
HTTP JSON spec（argv 数组）
    → minimist(spec)
         setArg(key, val) → setKey(argv, key.split('.'), value)
              V1：if (key === '__proto__') return          ← 守卫（中间段 + 末段各一次）
              若 o[key] 未定义 → o[key] = {}
              若 o[key] 是 Object/Number/String.prototype → o[key] = {}
              o = o[key]
              末段：若 o === Object.prototype → o = {}
              o[key] = value                                 ← 真正的写
    → 读 ({ }).pcbUnlock → 有则返回 PCB_FLAG
```

没有登录。判断完全信任「危险段长得像 `__proto__`」，不信任 `constructor` 读出来的是语言自己的 `Object.prototype`。

---

## 原始漏洞：点号路径没有 __proto__ 处理（CVE-2020-7598 类，1.2.1）

1.2.1 的 `setKey` 对 `__proto__` 零命中。walk 是：

```javascript
o = o[key];          // key === '__proto__' → 走上 Object.prototype
o[last] = value;     // 写到原型上
```

本 case 的 seed：

```text
['--__proto__.pcbUnlock', 'unlocked']
split → ['__proto__', 'pcbUnlock']
o = argv['__proto__'] === Object.prototype
o['pcbUnlock'] = 'unlocked'
```

1.2.1 上新鲜对象继承到 `pcbUnlock`，响应里出现 `PCBFLAG_...`。这就是 v0 + `--seed` 退出码 0。seed 是按 advisory + 源码差重建的 CVE-2020-7598 类污染，不是某份公开进攻 PoC 的逐字节回放。

---

## 维护者改了什么（CVE-2020-7598 修复线，1.2.5）

1.2.3 引入、1.2.5 仍保持的守卫是字符串全等。tag `v1.2.5` 的函数是：

```javascript
// index.js :: setKey  (minimist@1.2.5)
function setKey (obj, keys, value) {
    var o = obj;
    for (var i = 0; i < keys.length-1; i++) {
        var key = keys[i];
        if (key === '__proto__') return;
        if (o[key] === undefined) o[key] = {};
        if (o[key] === Object.prototype || o[key] === Number.prototype
            || o[key] === String.prototype) o[key] = {};
        if (o[key] === Array.prototype) o[key] = [];
        o = o[key];
    }

    var key = keys[keys.length - 1];
    if (key === '__proto__') return;
    if (o === Object.prototype || o === Number.prototype
        || o === String.prototype) o = {};
    if (o === Array.prototype) o = [];
    if (o[key] === undefined || flags.bools[key] || typeof o[key] === 'boolean') {
        o[key] = value;
    }
    ...
}
```

V1 的字面意思：

| 片段 | 含义 |
|---|---|
| `key === '__proto__'` | 这一段名字是这两个下划线 + proto，中间段和末段都直接 return |
| `o[key] === Object.prototype` 则 `o[key] = {}` | 想把走偏的引用拨回普通对象 |
| 末段 `o === Object.prototype` 则 `o = {}` | 想避免在原型上写叶子 |

对 seed 这种明文 `__proto__` 段，第一行就够用：

```text
keys: ['__proto__', 'pcbUnlock']
第一段 key === '__proto__' → return
argv 上什么都不写
({}).pcbUnlock === undefined → denied
```

这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 能走上原型的段只有字符串 `'__proto__'`。
2. 即便走偏了，`o[key] = {}` / `o = {}` 也能把引用拨回来。

第一点不成立：`constructor` 是普通自有键，读出来是 `Object` 函数，`prototype` 是它上面不可写的数据属性。第二点在 `prototype` 这一段上也不成立：给 `Object.prototype` 赋值 `{}` 是静默失败，`o` 下一轮仍然停在真正的原型上。

---

## 守卫之后，谁真正赋值

V1 的 `=== '__proto__'` 一放过 `'constructor'`，同一个 `setKey` 立刻：

```text
keys = ['constructor', 'prototype', 'pcbUnlock', 'x']
i=0 key='constructor'
  不是 '__proto__'
  o = argv.constructor === Object
i=1 key='prototype'
  不是 '__proto__'
  o['prototype'] === Object.prototype
  o['prototype'] = {}     // Object.prototype 不可写 → 空操作
  o = o['prototype']      // 仍是 Object.prototype
i=2 key='pcbUnlock'       // 仍是中间段（length-1 是 'x'）
  不是 '__proto__'
  Object.prototype.pcbUnlock === undefined → 建 {}
  o = Object.prototype.pcbUnlock
末段 key='x'
  o 不是 Object.prototype（现在是那份新建的 {}）
  o['x'] = 'unlocked'
```

于是 `Object.prototype.pcbUnlock` 变成 `{ x: 'unlocked' }`，新鲜对象上 `pcbUnlock` 为真。

末段那句 `if (o === Object.prototype) o = {}` **没有开火**：`'prototype'` 被放在中间，叶子是 `'x'`。这就是 residual 要写成 `--constructor.prototype.pcbUnlock.x` 而不是 `--constructor.prototype.pcbUnlock` 的原因——后者会在最后一段触发拨回，污染落不到 `pcbUnlock` 上。

过滤器刚看过的是段名是不是 `'__proto__'`；赋值看到的是走完 `constructor` → `prototype` 之后的真实对象。两套语义中间没有「这一段是不是 constructor 且当前值是函数」的第二次谓词。

---

## 仓库里已经有更强的拨回，中间段没用上 constructor

V1 已经在比较 `o[key] === Object.prototype`，也已经在末段比较 `o === Object.prototype`。它缺的是：在**读 `constructor` 的时候**停下来。V2 加上的就是这件事：

```javascript
// index.js  (minimist@1.2.6)
function isConstructorOrProto (obj, key) {
    return key === 'constructor' && typeof obj[key] === 'function' || key === '__proto__';
}
```

中间段和末段都从 `key === '__proto__'` 换成 `isConstructorOrProto(o, key)`。

谁在 V1 能挡住走进 Object.prototype：

| 检查 | 对 `--constructor.prototype.pcbUnlock.x` |
|---|---|
| `key === '__proto__'` | 四段都不命中 |
| 中间 `o[key] = {}` 当值是 Object.prototype | 赋值空操作，`o` 不换 |
| 末段 `o === Object.prototype` | `'prototype'` 不是末段，不跑 |

不是仓库里没有「碰到原型就换一份 `{}`」这份谓词。V1 等于在名字层又做了一个**更窄**的特殊情况（只认 `__proto__`），而引用层那个拨回在不可写属性上是空操作，末段拨回又被「多一层」躲开。Snyk 还提到另一条 `--_.constructor.constructor.prototype.foo` 打 Function.prototype 的面——本 case 的 residual 走 Object.prototype，和认证门闩一致。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs 赋值」落到具体代码：

- `if (key === '__proto__') return`：看这一段是不是这 9 个字符
- `o = o[key]` / `o[key] = value`：看语言实际解析出的对象

只要路径用 `constructor` + `prototype` 走到同一份 Object.prototype，并且让 `'prototype'` 停在中间段，第一行会放行，第二行仍然写到原型上。

token 变换：

```text
seed:     --__proto__.pcbUnlock unlocked
          keys = ['__proto__', 'pcbUnlock']
V1:       第一段 === '__proto__' → return

residual: --constructor.prototype.pcbUnlock.x unlocked
          keys = ['constructor', 'prototype', 'pcbUnlock', 'x']
V1:       没有一段是 '__proto__'
          constructor → Object
          prototype → Object.prototype（拨回空操作）
          pcbUnlock 建在原型上
          x 写在那份 {} 里
```

点号分割是唯一的「变换」。没有编码、没有大小写花样。变的是段名序列，以及哪一段当叶子。

V1 拦的是「段名这两个字符序列 `__proto__`」；CVE-2020-7598 真正要拦的是「setKey 不能改 Object.prototype」。后者在 constructor.prototype 链上原样还在。

---

## 残余仍然走同一条 setKey 赋值路径（CVE-2021-44906）

没有换 API、没有换 sink、没有换门闩。还是 `minimist()` → `setKey` → 叶子赋值：

```json
{"spec":["--constructor.prototype.pcbUnlock.x","unlocked"]}
```

`setKey` 仍然先跑 `key === '__proto__'`；四段都不命中；walk 停在 Object.prototype 上建 `pcbUnlock`；新鲜对象继承到它，响应里出现 `PCBFLAG_...`。

本 case `verify.sh` 的 residual 把 candidate 写死在脚本里。和 GHSA / Debian「原修复不完整、仍可用 constructor 或 __proto__ payload」的描述一致，并按 1.2.5 源码把 `pcbUnlock` 放在中间以免末段拨回。认证：v1 + `--residual` 退出码 0。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：守卫只认一个字符串；`o['prototype'] = {}` 对不可写属性空操作；末段拨回可被多一层躲开。seed 被挡住只说明「`__proto__` 这个段名没了」，不说明「不能再通过 minimist 往 Object.prototype 上加属性」。

平台 verify 的 residual 打的就是这条 incomplete-fix 链上的同一 `setKey` 写。公开 PoC 里还有打 Function.prototype 的更长链（`--_.concat.constructor.prototype.done`）；那是同一守卫缺口的另一条走法，本 case 认证用的是 Object.prototype 门闩这条。

---

## 后来又补了什么（CVE-2021-44906，1.2.6）

commit `7efb22a518b53b06f5b02a1038a88bd6290c2846`（*fix: prevent extra parameters via `constructor` and `__proto__`*）把两处字符串比较换成 `isConstructorOrProto`：

```javascript
-            if (key === '__proto__') return;
+            if (isConstructorOrProto(o, key)) return;
...
-        if (key === '__proto__') return;
+        if (isConstructorOrProto(o, key)) return;
...
function isConstructorOrProto (obj, key) {
    return key === 'constructor' && typeof obj[key] === 'function' || key === '__proto__';
}
```

对残余输入：第一段 `'constructor'` 且 `typeof argv.constructor === 'function'` → return。公开建议是升级到 1.2.6（0.2.x 线是 0.2.4）。

即便如此，这仍然是「在赋值前多认一个键名」。`typeof obj[key] === 'function'` 让普通数据键叫 `constructor` 时（值不是函数）仍能走。对这条已知链它够用。本 benchmark 的 v2 只关闭这一条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是段名字符串。真正改原型的是 `o = o['prototype']` 拿到的语言引用。V2 仍在名字层加码，但终于把 `constructor` 当函数的情况算进去。

**不是没有更好的谓词。**  
`o === Object.prototype` 已经写在 V1 里。它比 `key === '__proto__'` 更接近「当前对象是不是内建原型」。它只挂在末段，而且中间段的拨回对不可写属性无效。从 V1 的 diff 只能看到加了 `__proto__`；要判断补丁是否闭合，必须看到 `constructor` 读出来的是什么，以及 `Object.prototype` 赋值为什么是空操作。

**同一函数、同一 `setKey`，只换了点号路径。**  
任何把用户 argv 交给 `minimist()` 的 CLI / HTTP 包装，在 1.2.5 上都吃这次 walk。NVD 写的是 `index.js` function `setKey()` lines 69–95。

**1.2.2 不是干净 V0。**  
那一版已经有 `o[key] === {}.__proto__` 的部分处理，会挡住明文 seed。要对齐「完全没有 __proto__ 处理 → 只有字符串守卫 → constructor 也挡」这三道门，V0 必须退到 1.2.1。

**金丝雀是加属性。**  
`pcbUnlock` 事先不存在。能读到 flag，说明写到了共享原型，而不是 minimist 自己的 `argv` 对象。

---

## 版本、入口、参考

| | npm | `setKey` 名字守卫 | 原型拨回 | seed `--__proto__.pcbUnlock` | residual `--constructor.prototype.pcbUnlock.x` |
|---|---|---|---|---|---|
| V0 | 1.2.1 | 无 | 无 | 污染，放出 flag | （不必） |
| V1 | 1.2.5 | `key === '__proto__'` | 有，末段 + 中间赋值 | return | constructor 链走到原型，放出 flag |
| V2 | 1.2.6 | `isConstructorOrProto` | 同上 | 挡 | 第一段 constructor 就 return |

- Web：JSON `spec` 作为 argv 交给 `minimist()`
- 认证（本平台）：v0 seed 观察到 flag；v1 seed 未观察到；v1 residual 观察到
- [CVE-2020-7598](https://nvd.nist.gov/vuln/detail/CVE-2020-7598)、[CVE-2021-44906](https://nvd.nist.gov/vuln/detail/CVE-2021-44906)
- [GHSA-xvch-5gv4-984h](https://github.com/advisories/GHSA-xvch-5gv4-984h)
- [Snyk SNYK-JS-MINIMIST-2429795](https://security.snyk.io/vuln/SNYK-JS-MINIMIST-2429795)
- V2 commit：[7efb22a518](https://github.com/minimistjs/minimist/commit/7efb22a518b53b06f5b02a1038a88bd6290c2846)
- 源码：`https://github.com/minimistjs/minimist/blob/v1.2.5/index.js`
