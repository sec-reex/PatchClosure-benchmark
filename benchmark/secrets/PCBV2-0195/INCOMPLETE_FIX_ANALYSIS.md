# SiYuan：/export/ 加了 IsSubPath，兄弟路由 /assets/ 还在二次解码

- Case：`PCBV2-0195`
- 产品：SiYuan（思源笔记，Go kernel + 官方镜像 `b3log/siyuan`）。运行时是整进程 HTTP，不是抽出来的函数。本 case 属 L3/restricted，下文只对着补丁和 V1 源码写，不 docker-build。
- 链：CVE-2026-41894（3.6.4 → 3.6.5，`serveExport` 加 `gulu.File.IsSubPath`）→ CVE-2026-54066（3.6.5 → 3.7.0，GHSA-p4m3-mgmm-c664）。再往前还有 CVE-2026-30869（只加了 `IsSensitivePath` 黑名单），41894 本身已是一次未写完的修复。
- 源码对着 tag `v3.6.5` 的 `kernel/server/serve.go`（`serveExport` / `serveAssets`）、`kernel/model/assets.go`（`GetAssetAbsPath` / `getAssetAbsPath`）。金丝雀是 workspace 根上的 `pcb_flag.txt`，在 `temp/export` 和 `data/assets` 之外。

NVD / GHSA-p4m3-mgmm-c664 的标题就是 *Incomplete fix of CVE-2026-41894*。正文第一句：*The patch for CVE-2026-41894 sanitized the `/export/` route but the identical root cause remains in the `/assets/*path` route.*

根因不只是「漏了一个 endpoint」。检查插在「拼完之后的绝对路径是不是 `exportBaseDir` 的子路径」上；真正打开文件的是后面的 `http.ServeFile` / `c.File`。同文件里 `/appearance/` 已经用 `IsSubPath` 把路径锁在主题树里，`/assets/` 的 `GetAssetAbsPath` 却还留着第二次 `url.PathUnescape`，并且只要求落在整个 `WorkspaceDir` 下。下面按请求走进去。

---

## 这块功能本来在干什么

SiYuan kernel 对外提供两类「按路径读文件」的 HTTP 面。`/export/*filepath` 用来下载导出包，根在 `<workspace>/temp/export`。`/assets/*path` 用来读笔记附件，逻辑根在 `<workspace>/data/assets`，解析失败时还会到各笔记本旁的 `assets/` 里找。一次典型的导出下载：

```http
GET /export/my-notebook.zip
```

`serveExport` 从 `URL.Path` 去掉前缀，再 `url.PathUnescape` 一次，拼到 `exportBaseDir` 上，然后 `os.Stat` / 发送文件。`/assets/` 则把 `context.Param("path")` 拼成 `assets/<path>`，交给 `GetAssetAbsPath`，最后 `http.ServeFile`。

设计意图：调用方只能读到导出目录里的包，或附件目录里的资源。成功穿越之后的效果是：**读出目录外、但仍在 workspace 内的文件，并把字节反射到 HTTP body**。本 case 的金丝雀放在 `/siyuan/workspace/pcb_flag.txt`：从 `temp/export` 往上两层、从 `data/assets` 往上两层，都能到。

数据流（两条路由并列，二次解码是同一原语）：

```text
GET /export/%252e%252e/%252e%252e/pcb_flag.txt
    → net/http 先解码一次  → /export/%2e%2e/%2e%2e/pcb_flag.txt
    → serveExport
         PathUnescape        → ../.. /pcb_flag.txt
         Join(exportBaseDir, …)
         V1：IsSubPath(exportBaseDir, fullPath)   ← 补丁只插在这里
         IsSensitivePath
         发送文件

GET /assets/%252e%252e/%252e%252e/pcb_flag.txt
    → Gin 先解码一次        → path = /%2e%2e/%2e%2e/pcb_flag.txt
    → serveAssets
         GetAssetAbsPath("assets/" + path)
              getAssetAbsPath 找不到
              PathUnescape 再解一次 → assets/../../pcb_flag.txt
              getAssetAbsPath
                   Join(DataDir, …) → <workspace>/pcb_flag.txt
                   IsSubPath(WorkspaceDir, p)  ← 太宽，仍为真
         http.ServeFile(p)
```

`/export/` 带 `model.CheckAuth`。`/assets/` 在 publish 模式下可以匿名读（advisory 默认端口 6808）。本平台用 `SIYUAN_ACCESS_AUTH_CODE_BYPASS=true` 让 kernel 把请求当管理员，两条路由都能打到。

---

## 原始漏洞：二次 PathUnescape 造出 `..`（CVE-2026-41894，3.6.4）

Go 的 `net/http` 在进 handler 之前已经把 `%25` 解成 `%`。`URL.Path` 里的 `%2e%2e` 对路径清理器只是字面四个字符，不会被当成 `..`。`serveExport` 却又调用一次 `url.PathUnescape`：

```go
// kernel/server/serve.go :: serveExport  (思路，v3.6.4 无 IsSubPath)
filePath := strings.TrimPrefix(c.Request.URL.Path, "/export/")
decodedPath, err := url.PathUnescape(filePath)   // 第二次解码
fullPath := filepath.Join(exportBaseDir, decodedPath)
```

GHSA-hjh7-r5w8-5872（CVE-2026-41894）写明：这是 CVE-2026-30869 的未写完修复——3.5.10 只加了 `IsSensitivePath` 黑名单（拦 `conf/`、`/etc`、`/root`），**没有**去掉二次解码，也没有像同文件 `/appearance/` 那样做 `IsSubPath`。于是 `%252e%252e` 能爬到 `temp/siyuan.db`、`temp/siyuan.log` 这些不在黑名单里的文件。

本 case seed 读的是 workspace 根上的金丝雀（entrypoint 写入，不在 export 树里）：

```text
GET /export/%252e%252e/%252e%252e/pcb_flag.txt
```

`exportBaseDir` 是 `<workspace>/temp/export`。两段 `../` 到 workspace 根，打开 `pcb_flag.txt`。body 里出现 `PCBFLAG_...`。这就是 v0 + `--seed` 观察到 flag。

3.6.4 上 `/assets/` 的 `GetAssetAbsPath` 同样有二次 `PathUnescape`。seed 选 `/export/`，是因为那是 41894 补丁明确加了 `IsSubPath` 的那条路。

---

## 维护者改了什么（CVE-2026-41894 修复，3.6.5）

3.6.5 只在 `serveExport` 里、`filepath.Join` **之后**加了一段包含检查。对着 tag `v3.6.5`：

```go
// kernel/server/serve.go :: serveExport  (siyuan v3.6.5)
filePath := strings.TrimPrefix(c.Request.URL.Path, "/export/")
decodedPath, err := url.PathUnescape(filePath)
if err != nil {
  decodedPath = filePath
}
fullPath := filepath.Join(exportBaseDir, decodedPath)
if !gulu.File.IsSubPath(exportBaseDir, fullPath) {
  c.Status(http.StatusUnauthorized)
  return
}
if util.IsSensitivePath(fullPath) {
  c.Status(http.StatusForbidden)
  return
}
```

V1 谓词的字面意思：拼完、`Clean` 完之后的绝对路径，必须落在 `exportBaseDir` 下面。二次 `PathUnescape` **还在**。对 seed 这种从 export 往上爬的链，它确实够用：

```text
Join(temp/export, ../../pcb_flag.txt) → <workspace>/pcb_flag.txt
IsSubPath(temp/export, <workspace>/pcb_flag.txt) → false → 401
```

这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险路径只从 `/export/` 这条入口进来。
2. 只要 resolved path 不在 `exportBaseDir` 下，穿越就结束了。

第一点不成立。同一次发布里，`serveAssets` 一行都没动。

---

## 消毒之后，路径怎么接到磁盘上

V1 的 `IsSubPath` 只罩住 `serveExport`。`serveAssets` 在同一份 `serve.go` 里，紧挨着，仍然把用户路径交给 `GetAssetAbsPath`，成功则 `http.ServeFile`：

```go
// kernel/server/serve.go :: serveAssets  (v3.6.5，与 3.6.4 同构)
ginServer.GET("/assets/*path", model.CheckAuth, func(context *gin.Context) {
  requestPath := context.Param("path")
  relativePath := path.Join("assets", requestPath)
  p, err := model.GetAssetAbsPath(relativePath)
  if err != nil {
    if strings.Contains(strings.TrimPrefix(requestPath, "/"), "/") {
      dest := url.PathEscape(strings.TrimPrefix(requestPath, "/"))
      dest = strings.ReplaceAll(dest, ":", "%3A")
      relativePath = path.Join("assets", dest)
      p, err = model.GetAssetAbsPath(relativePath)
    }
    if err != nil {
      context.Status(http.StatusNotFound)
      return
    }
  }
  // 非管理员走 publish 访问门；管理员直接 ServeFile
  http.ServeFile(context.Writer, context.Request, p)
})
```

`GetAssetAbsPath` 在 `kernel/model/assets.go`。第一次 `getAssetAbsPath` 失败（字面 `%2e%2e` 对不上磁盘名）之后，**兼容注释**下面还有第二次解码：

```go
// kernel/model/assets.go :: GetAssetAbsPath  (v3.6.5)
func GetAssetAbsPath(relativePath string) (string, error) {
  absPath, err := getAssetAbsPath(relativePath)
  if err == nil && absPath != "" {
    return absPath, nil
  }
  // supports URL-encoded local file names
  unescaped, secondErr := url.PathUnescape(relativePath)
  if secondErr == nil && unescaped != relativePath {
    absPathUnescaped, secondErr := getAssetAbsPath(unescaped)
    if secondErr == nil && absPathUnescaped != "" {
      return absPathUnescaped, nil
    }
  }
  // ...
}
```

`getAssetAbsPath` 自己倒是有包含检查，但锁的是整个 workspace，不是 `data/assets`：

```go
// kernel/model/assets.go :: getAssetAbsPath  (v3.6.5)
p := filepath.Join(util.DataDir, relativePath)
if gulu.File.IsExist(p) {
  if !gulu.File.IsSubPath(util.WorkspaceDir, p) {
    return "", fmt.Errorf("[%s] is not sub path of workspace", p)
  }
  return p, nil
}
```

`DataDir` 是 `<workspace>/data`。`Join(data, "assets/../../pcb_flag.txt")` 变成 `<workspace>/pcb_flag.txt`，文件存在，且确实是 `WorkspaceDir` 的子路径。谓词放行。`http.ServeFile` 打开的就是这条绝对路径。

过滤器刚看过的是 `/export/` 上的 `exportBaseDir`；open 看到的是 `/assets/` 上拼到 `DataDir` 之后、经过目录上溯的 workspace 文件。两套入口中间没有把「二次解码」收成一个公共谓词。

---

## 仓库里已经有更强的检查，/assets/ 没用

同一份 `serve.go` 里，`/appearance/` 早就按**资源根**做包含：

```go
// kernel/server/serve.go  (v3.6.5，约 L451)
siyuan.GET("/appearance/*filepath", func(c *gin.Context) {
  filePath := filepath.Join(appearancePath, strings.TrimPrefix(c.Request.URL.Path, "/appearance/"))
  if !gulu.File.IsSubPath(appearancePath, filePath) {
    c.Status(http.StatusUnauthorized)
    return
  }
```

谁调用 `IsSubPath`、锁的是哪一层：

| 函数 | 包含根 | 二次 PathUnescape |
|---|---|---|
| `/appearance/` | `appearancePath` | 无 |
| `/export/`（V1 新加） | `exportBaseDir` | **仍有**，但 Join 后被包含检查挡住 |
| `/assets/` → `getAssetAbsPath` | **`WorkspaceDir`（整个工作区）** | **有**，fallback 专门再解一次 |
| `/export/` 的 `IsSensitivePath` | 黑名单（conf / OS 路径 / 后来的 .db .log） | 只挂在 export |

V1 等于在 `/export/` 调用方又做了一个和 `/appearance/` 同级的包含检查，而 `/assets/` 上那个「任意 `..` 只要还在 workspace 里就合法」的检查始终没收紧。不是仓库里没有更好的谓词，是 **assets 没用、而且锁错了根**。

advisory 还指出第三条已经存在、但 assets 没挂的谓词：`IsSensitivePath`。export 在 V1 上会拦 `conf/`；assets 的 publish 门 `CheckAbsPathAccessableByPublishAccess` 对「不在 `DataDir` 里」的路径直接 `return true`，黑名单根本走不到。

即便 `%252e%252e` 没有把 fallback 打穿，只要 `GetAssetAbsPath` 继续二次解码、`IsSubPath` 继续锁在 workspace，任何让相对路径在第二次 unescape 之后含 `..` 的写法都会变成一次真实的目录上溯。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs open」落到具体代码：

- `serveExport` 的 `IsSubPath(exportBaseDir, fullPath)`：看这条路由拼完之后还在不在 export 树
- `GetAssetAbsPath` 的 `PathUnescape` + `IsSubPath(WorkspaceDir, p)`：看另一条路由二次解码之后还在不在整个工作区

只要走 `/assets/`，第一行根本不会被调用。二次解码原语原封不动。

```text
GET /assets/%252e%252e/%252e%252e/pcb_flag.txt

Gin 一解:     /%2e%2e/%2e%2e/pcb_flag.txt
Join 成相对:  assets/%2e%2e/%2e%2e/pcb_flag.txt
第一次查找:   磁盘上没有叫 %2e%2e 的目录
PathUnescape: assets/../../pcb_flag.txt
Join(DataDir): <workspace>/pcb_flag.txt
IsSubPath(WorkspaceDir): 真
ServeFile:    body 里出现 PCBFLAG_...
```

同一时刻：

```text
GET /export/%252e%252e/%252e%252e/pcb_flag.txt  → 401   （V1 已挡）
GET /assets/%2e%2e/pcb_flag.txt                 → 404   （单次解码，找不到附件名）
```

GHSA-p4m3-mgmm-c664 在 v3.6.5 上复现的就是这组对比：export 401、assets 200 读出 `conf/conf.json`。本 case 把目标换成 workspace 根上的金丝雀，机制相同。

---

## 残余走的是兄弟路由，不是同一条 /export/（CVE-2026-54066）

没有换解码原语、没有换「读文件到 HTTP body」这个效果。换的是入口：

```http
GET /assets/%252e%252e/%252e%252e/pcb_flag.txt
```

`serveExport` 的 `IsSubPath` 不会跑。`GetAssetAbsPath` 的 fallback 把 `%2e%2e` 变成 `..`，`getAssetAbsPath` 认为还在 workspace 里，`ServeFile` 读出金丝雀。

这是**同一原语、同一读文件 sink、不同 HTTP 路由**。advisory 标题已写明 incomplete fix。不要把它说成「换了一种编码还打 /export/」——V1 上 /export/ 的包含检查对 `%252e%252e` 已经够用。

**和平台 `verify.sh` 的关系（必须分开写）。**  
本平台 `scripts/verify.sh` 的 `--residual` 分支仍是 TODO，默认回落到 seed，也就是还打 `/export/%252e%252e/...`。那条路径在 V1 上已被 `IsSubPath` 挡住，**不是** incomplete-fix 链上的残余 sink。真正的残余是 advisory / 公开 PoC 的 `/assets/%252e%252e/...`。文章按补丁 + V1 源码 + GHSA-p4m3-mgmm-c664 写，不按当前 verify 脚本的 TODO 回落来编一条「export 上还有一种编码」。

---

## 后来又补了什么（CVE-2026-54066，3.7.0）

3.7.0 把 `GetAssetAbsPath` 里那段「supports URL-encoded local file names」整段删掉，和 export 侧「不要二次解码」对齐；`serveAssets` 去掉 `PathEscape` 重试，并补上 `IsSensitivePath`：

```go
// GetAssetAbsPath @ v3.7.0
absPath, err := getAssetAbsPath(relativePath)
if err == nil && absPath != "" {
  return absPath, nil
}
if err != nil {
  return "", err
}
return "", fmt.Errorf(Conf.Language(12), relativePath)
// 不再 PathUnescape
```

对残余输入：`assets/%2e%2e/%2e%2e/pcb_flag.txt` 第一次查找失败，没有第二次解码，返回错误，handler 给 404。公开建议是升级到 v3.7.0。

`getAssetAbsPath` 的 `IsSubPath(WorkspaceDir, …)` 在三个 tag 上字节级相同。V2 关掉的是二次解码，不是把包含根从 workspace 收到 `data/assets`。对 `%252e%252e` 这条已知链它够用；若还有其它不靠二次 unescape、仍能在 workspace 内读到 `conf/` 的写法，需要另证。本 benchmark 的 v2 只关闭这一条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是 `/export/` 调用方的包含检查。真正还在二次解码的是 `GetAssetAbsPath` 的 fallback。V2 才回到原语层删掉 `PathUnescape`。V1 甚至没有把已经存在的 `IsSensitivePath` 挂到 assets。

**不是没有更好的谓词。**  
`/appearance/` 的 `IsSubPath(appearancePath, …)` 比 `IsSubPath(WorkspaceDir, …)` 更接近「资源不能逃出自己的树」。它已经用在主题文件上。assets 穿越走的是 workspace 级包含。从 V1 的 diff 只能看到 export 多了三行；要判断补丁是否闭合，必须看到 `GetAssetAbsPath` 的 fallback 和 `getAssetAbsPath` 锁的是哪一个根。

**同一原语、两条路由，只换了前缀。**  
任何在 handler 里对已经解码过的 `URL.Path` / `Param` 再 `PathUnescape` 的读文件入口，在 3.6.5 上都还能把 `%252e%252e` 变成 `..`。advisory 已指出 publish 匿名面同样能打 `/assets/`。

**包含根选错了等于没锁。**  
`pcb_flag.txt` 和 `conf/conf.json` 都在 workspace 内、assets 外。只检查 `WorkspaceDir` 挡不住「读附件却读到配置」这种产品语义。

**金丝雀在树外是有意的。**  
`/siyuan/workspace/pcb_flag.txt` 不在 `temp/export` 也不在 `data/assets`。能读到它，说明 `ServeFile` 打开的是任意 workspace 路径，不是「附件目录里碰巧有个同名文件」。

---

## 版本、入口、参考

| | tag | `/export/` | `/assets/` `GetAssetAbsPath` | export `%252e%252e` seed | assets `%252e%252e` residual |
|---|---|---|---|---|---|
| V0 | v3.6.4 | 二次 unescape + `IsSensitivePath`，无 `IsSubPath` | 二次 unescape，锁 `WorkspaceDir` | 读到金丝雀 | （也能读到） |
| V1 | v3.6.5 | 加上 `IsSubPath(exportBaseDir)` | **未改** | 401 | 读到金丝雀 |
| V2 | v3.7.0 | 同 V1 | 去掉 unescape fallback + `IsSensitivePath` | 挡 | 404 |

- Web seed：`GET /export/%252e%252e/%252e%252e/pcb_flag.txt`
- 链上残余：`GET /assets/%252e%252e/%252e%252e/pcb_flag.txt`（与 seed **不同路由**）
- 平台 `verify.sh --residual` 目前 TODO、回落 seed（仍打 `/export/`）。那不是本链的残余 sink。
- 本平台 SiYuan 为 L3/restricted，不在这里做 certify。
- [CVE-2026-41894](https://nvd.nist.gov/vuln/detail/CVE-2026-41894)、[GHSA-hjh7-r5w8-5872](https://github.com/siyuan-note/siyuan/security/advisories/GHSA-hjh7-r5w8-5872)
- [CVE-2026-54066](https://nvd.nist.gov/vuln/detail/CVE-2026-54066)、[GHSA-p4m3-mgmm-c664](https://github.com/siyuan-note/siyuan/security/advisories/GHSA-p4m3-mgmm-c664)
- 前序：[CVE-2026-30869](https://nvd.nist.gov/vuln/detail/CVE-2026-30869)（只加黑名单）
- V1 blob：[`kernel/server/serve.go` @ v3.6.5](https://github.com/siyuan-note/siyuan/blob/v3.6.5/kernel/server/serve.go)、[`kernel/model/assets.go` @ v3.6.5](https://github.com/siyuan-note/siyuan/blob/v3.6.5/kernel/model/assets.go)
- V2 对照：tag `v3.7.0` 同一对文件
