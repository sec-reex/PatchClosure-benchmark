# @adobe/css-tools：修了 @import 回溯，selector 的 `\(.*?\)` 没动

- Case：`PCBV2-0183`
- 产品：npm 包 `@adobe/css-tools`（CSS 解析器，jest-dom 等依赖）。运行时是官方 tarball 4.3.0 / 4.3.1 / 4.3.2，经 `css.parse(string)` 同步跑在 Node 事件循环上。本文只根据补丁后的正则和仍会回溯的那条模式写，不在本机跑解析、不挂起进程。
- 链：CVE-2023-26364（4.3.0 → 4.3.1，GHSA-hpx4-r86g-5jrg）→ CVE-2023-48631（4.3.1 → 4.3.2，GHSA-prr3-c3m5-p7q2）
- 源码对着 npm `@adobe/css-tools@4.3.1` 的 `dist/index.cjs`（GitHub 当时没有 4.3.x tag）：`_compileAtrule`、`commentre`、`selector()`。

NVD CVE-2023-48631：*@adobe/css-tools versions 4.3.1 and earlier are affected by an Improper Input Validation vulnerability that could result in a denial of service while attempting to parse CSS.* 4.3.1 正是 26364 的「已修复」版本。同一 `parse()` 里另一条正则原样留下。

根因不只是「还有一条 ReDoS」。检查（26364）插在「at-rule 必须在 `;` 或字符串末尾结束」以及「注释用线性扫描」上；真正吃 selector 输入的是后面那次 `.replace(/("|')...|\(.*?\)/g)`。V1 没碰这行。下面按 `css.parse` 走进去。

---

## 这块功能本来在干什么

`css.parse(source)` 把样式表切成 at-rule 和 rule。rule 先 `selector()` 再 `declaration()`。带逗号的选择器要在引号和括号里把逗号藏起来，再 `split(',')`。

一次典型调用：

```js
const css = require('@adobe/css-tools');
css.parse('@import "theme.css"; a, b { color: red }');
```

`atrule()` 在 `@` 处试 `@import` / `@charset` / `@namespace`（都由 `_compileAtrule` 编译出一条正则）。普通规则走 `selector()`。两条路径都是同步正则，挂住就挂住整个事件循环。

设计意图：解析合法 CSS；选择器里 `nth-child(2,3)`、`[data-x="a,b"]` 的逗号不是选择器分隔符。成功穿越之后的效果是：**正则引擎在失败的匹配上指数/平方回溯，`parse()` 迟迟不返回。**

数据流：

```text
css.parse(userCss)
    → stylesheet / rules
         atrule? → _compileAtrule("import") 的 RegExp.match   ← 26364 改这里
         rule    → selector()
                      若含 ','：
                        .replace(/("|')(?:\\\1|.)*?\1|\(.*?\)/g, ...)
                                                      ^^^^^^^^  ← 4.3.1 原样
                      split(',')
```

没有鉴权。谁能把字符串喂给 `parse`，谁就能驱动 CPU。

---

## 原始漏洞：缺分号的 @import 指数回溯（CVE-2023-26364，4.3.0）

4.3.0 的非块 at-rule：

```js
const re = new RegExp(
  "^@" + name + "\\s*((:?[^;'\"]|\"(?:\\\\\"|[^\"])*?\"|'(?:\\\\'|[^'])*?')+);"
);
```

`(:?[^;'"])` 里 `:?` 可空，`:` 既能当可选冒号、又能当 `[^;'"]`。一串 `::::` 有 Fibonacci 多种切法。末尾**必须** `;`；输入 `@import ::::...`（无分号）时整次匹配失败，引擎把切法穷尽。

同文件注释剥离：

```js
const commentre = /\/\*[^*]*\*+([^/*][^*]*\*+)*\//g;
```

经典嵌套量词，未闭合注释上灾难回溯。

seed 形状（公开讨论 / 本 case 机制描述）：

```text
@import  +  ':'×40     （无分号，长度约 48）
```

4.3.0 上 `_compileAtrule("import")` 指数回溯。不要在主机上复现这条。

---

## 维护者改了什么（CVE-2023-26364 修复，4.3.1）

at-rule 捕获组改成非捕获，终结子改成 `(?:;|$)`：

```js
// dist/index.cjs  (@adobe/css-tools@4.3.1)
function _compileAtrule(name) {
    const re = new RegExp(
      "^@" + name + "\\s*((?::?[^;'\"]|\"(?:\\\\\"|[^\"])*?\"|'(?:\\\\'|[^'])*?')+)(?:;|$)"
    );
```

`$` 让贪心的 `(?::?[^;'"])+` 在输入末尾可以成功，不必为了那个永远配不上的 `;` 穷尽切法。colon 炸弹变成近似线性。

注释：

```js
const commentre = /\/\*[^]*?(?:\*\/|$)/g;
```

懒惰 `[^]*?` + 明确终结，线性。

GHSA-hpx4-r86g-5jrg 把 4.3.1 标成 26364 的 patched version。seed 在 4.3.1 上很快返回（或解析失败但不爆 CPU）。这就是 v1 + `--seed` 退出码 10 的含义：at-rule 那条指数路径闭合了。

补丁默认：灾难回溯就在 `_compileAtrule` 和 `commentre` 里。`selector()` 那一行不在 diff 里。

---

## 检查之后，谁还在跑正则

`parse()` 对同一份字符串继续往下走。含逗号的选择器进入 4.3.0 和 4.3.1 **字节级相同** 的替换：

```js
// dist/index.cjs :: selector()  (4.3.0 与 4.3.1)
    function selector() {
        const m = match(/^([^{]+)/);
        ...
        const res = trim(m[0]).replace(commentre, "");
        if (res.indexOf(",") === -1) return [res];
        return res
            .replace(/("|')(?:\\\1|.)*?\1|\(.*?\)/g, (m) => m.replace(/,/g, "\u200C"))
            .split(",")
            .map((s) => trim(s.replace(/\u200C/g, ",")));
    }
```

注释写着 `\(.*?\) => Handle the ()`。`.*?` 懒惰，但 **全局** 扫描：每个未闭合的 `(` 都让引擎从该点扫到字符串末尾找 `)`，找不到再从下一个 `(` 重来。n 个 `(` 大约 O(n²) 次对尾部的扫描。

`rule()` 在 `selector()` 之后才读 `{`。输入 `a,((((...{` 会先走完这次 replace。at-rule 那条 V1 正则根本不看这段。

对 `@import` 炸弹，4.3.1 的 `match(re)` 在 `$` 处成功（或作为 at-rule 消费掉输入前缀），解析器不再为 `;` 回溯。同一 `parse()` 若后面还跟 `a,(((`，会再进 `selector()`。seed 可以做成「只有 at-rule、没有逗号选择器」，所以 V1 上 seed 快、残余慢，并不矛盾。

平方回溯的常数比指数小，所以残余用更长的 `(` 跑（10⁵ 量级）才能在计时上拉开；指数 seed 用 40 个冒号就够。长度不同不是换了洞面，是两条正则的复杂度不同。

把 `selector()` 那次 replace 拆开看：

```text
正则:  /("|')(?:\\\1|.)*?\1|\(.*?\)/g
输入:  a, + '('×n + {}

引号支:  配不上（没有引号）
括号支:  每个 '(' 启动 \( .*? \)
         找不到 ')' → 扫到 EOS 失败
         lastIndex 前进 1，下一个 '(' 再扫一遍剩余
```

`/g` 保证每个开括号都是一次独立的失败扫描。V1 的 at-rule `$` 终结符改变不了这支的失败路径。

`atrule()` 的尝试顺序是 keyframes/media/…/import。残余 `a,(((` 第一个字符不是 `@`，整段 at-rule 函数直接返回，CPU 全部花在 `selector()`。seed 以 `@import` 开头，根本不进 `selector()`。同一 `parse()`，入口字符决定打中哪条正则。

4.3.1 的 `commentre` 已是 `/\/\*[^]*?(?:\*\/|$)/g`。残余不依赖注释。若有人把 26364 理解成「CSS 解析 ReDoS 已修」，打开 `dist/index.cjs` 搜 `\(.*?\)` 仍能命中 `selector()`——这就是 incomplete-fix 的静态判据，不必跑容器。

---

## 仓库里已经有更强的做法，selector 没用

V1 刚把注释和 at-rule 改成「懒惰扫描 + 显式终结符 / `$`」。同一文件里 selector 仍用回溯正则处理括号。

更强的做法（4.3.2 才写上）：引号继续用正则，括号用下标循环 `findClosingParenthese`，按深度线性扫。4.3.1 里没有这个函数。不是解析器不会手写扫描，是 **26364 只改了当时报过来的两条正则**。

`res.indexOf(",") === -1` 是快路径：没有逗号就不跑那次 replace。残余必须带逗号，才能进灾难分支——这是谓词覆盖不到的入口条件，不是另一套安全检查。

`commentre` 在 `selector()` 里也会跑一次（先剥注释再看逗号）。V1 把注释正则换成线性之后，残余不再能靠未闭合 `/*` 卡住 selector 前半段；必须靠 `\(.*?\)`。这正好说明 26364 改到了 selector 用得到的 commentre，但没改 selector 自己的括号分支。

`("|')(?:\\\1|.)*?\1` 处理引号，本身是另一条懒惰匹配。残余用未闭合括号而不是未闭合引号，是因为全局扫描下每个 `(` 都独立失败一次；引号分支有成对 `\1` 终结，模式不同。4.3.2 保留了引号正则，只拆掉括号分支。

---

## 这个补丁挡住了什么、没挡住什么

- `_compileAtrule` 的 `(?:;|$)`：看 @import 在缺分号时会不会穷尽 `:?` 切分
- `selector()` 的 `|\(.*?\)` + `/g`：看未闭合括号会不会对每个 `(` 扫一遍到 EOS

第一行与第二行是 **同一 `parse()` 里的两条正则**。26364 闭合第一条；第二条在 4.3.1 上与 4.3.0 相同。

残余形状：

```text
'a,' + '('×N + '{}'
```

逗号迫使 `selector()` 走 replace；没有 `)`，每个 `(` 触发一次到末尾的 `.*?` 失败。N 取到 10⁵ 量级时是平方级 CPU，不是 at-rule 那种指数。本文不给出可在主机上挂死 Node 的复现步骤。

平台 seed 打 at-rule；平台残余打 selector。二者都是 `css.parse` 这一个包 API，不是换了一个产品入口。要说 sink：残余命中的是 **sibling 正则**，不是 26364 改过的那一行。这正是 incomplete-fix 链本身（只修了报过来的模式）。

---

## 残余仍然走 css.parse → selector()（CVE-2023-48631）

没有换包、没有换 `parse`。还是用户 CSS 字符串。V1 的 `_compileAtrule` 对这段输入很快失败或不当 at-rule，解析继续进入 `rule` → `selector`。4.3.1 上那次 `replace` 与未打补丁时一样平方回溯。

GHSA-prr3-c3m5-p7q2 把 affected 写成 `<4.3.2`，即包括 4.3.1。Snyk / NVD 写 4.3.1 and earlier。

4.3.1 发行说明只提 26364 的 at-rule/comment。`selector()` 的注释块（Optimization 1/2、Handle the ()）从 4.3.0 原样留到 4.3.1，里面还写着「No greedy capture」当优化——懒惰 `.*?` 在失败路径上并不线性。V2 删掉这支时，才承认括号不该交给回溯引擎。

---

## 后来又补了什么（CVE-2023-48631，4.3.2）

4.3.2 从替换正则里拿掉 `|\(.*?\)`，括号改手写扫描：

```js
.replace(/("|')(?:\\\1|.)*?\1/g, (m) => m.replace(/,/g, "\u200C"))
// 另：findClosingParenthese(str, start, depth) 线性走嵌套括号
```

未闭合的 `(` 不再驱动回溯引擎。公开建议升到 4.3.2。本 benchmark 的 v2 关闭这条括号残余；at-rule 那条在 4.3.1 已经线性。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是当时能打出超时的那两条正则。`parse()` 里凡是 `new RegExp` / 字面量 `/.../` 都是同步 CPU。V2 仍在 selector 这一层换实现，没有给 `parse` 加时间预算。

**不是没有更好的谓词。**  
线性扫描括号的写法并不神秘，4.3.2 就写了。从 4.3.1 的 diff 只能看到 at-rule 和 commentre；要判断是否闭合，必须把 `selector()` 那一行和 4.3.0 并排，确认 `|\(.*?\)` 还在。

**同一 `parse()`、两条灾难模式。**  
seed 用 `@` + 冒号；残余用逗号 + 括号。共享的是事件循环，不是同一条正则。平台若只测 seed，会误以为 4.3.1 已「修完 ReDoS」。

**快路径把残余限制在带逗号的选择器。**  
没有 `,` 的纯 `(` 跑不会进 replace。这不是安全设计，是性能优化，恰好成了残余的触发条件。

**不要在评测机上对 V0 跑 seed、对 V1 跑残余。**  
指数和平方回溯都会钉死单线程 Node。结论来自正则结构和 advisory，不来自本机计时。

**`$` 只救了 at-rule。**  
`(?:;|$)` 让 `@import ::::` 在 EOS 成功匹配，切分不必穷尽。`selector()` 的 `.*?` 没有等价的「失败就停」终结：找不到 `)` 时每个起点仍扫到 EOS。把 26364 的修法（加 `$`）套到括号分支上并不自动成立。

**GitHub 4.3.x tag 当时缺失。**  
V1 源码以 npm tarball `dist/index.cjs` 为准（unpkg `@adobe/css-tools@4.3.1`）。仓库源文件若与 dist 不一致，运行时仍是这份 CJS——`css.parse` 的入口是 `exports`/`main` 指向的 dist。

---

## 版本、入口、参考

| | npm | `_compileAtrule` | `commentre` | `selector()` `\(.*?\)` | colon @import seed | 逗号+`(` residual |
|---|---|---|---|---|---|---|
| V0 | 4.3.0 | 必 `;`，指数 | 嵌套量词 | 有 | 挂 | 平方（同 V1） |
| V1 | 4.3.1 | `(?:;|$)`，线性 | 懒惰线性 | **仍有** | 快 | 平方 |
| V2 | 4.3.2 | 同 V1 | 同 V1 | **删除**，手写括号 | 快 | 线性 |

- 包 API：`require('@adobe/css-tools').parse(css)`
- [CVE-2023-26364](https://nvd.nist.gov/vuln/detail/CVE-2023-26364)、[GHSA-hpx4-r86g-5jrg](https://github.com/adobe/css-tools/security/advisories/GHSA-hpx4-r86g-5jrg)
- [CVE-2023-48631](https://nvd.nist.gov/vuln/detail/CVE-2023-48631)、[GHSA-prr3-c3m5-p7q2](https://github.com/adobe/css-tools/security/advisories/GHSA-prr3-c3m5-p7q2)
- V1 blob：npm `@adobe/css-tools@4.3.1` → [`dist/index.cjs`](https://unpkg.com/@adobe/css-tools@4.3.1/dist/index.cjs)（`_compileAtrule`、`selector` 的 replace）
- V2：npm `4.3.2` 同路径（`\(.*?\)` 已删）
