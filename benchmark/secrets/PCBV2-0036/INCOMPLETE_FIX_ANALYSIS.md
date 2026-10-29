# SiYuan /export/：敏感路径黑名单，没有问是不是还在导出目录里

- Case：`PCBV2-0036`
- 产品：SiYuan（思源笔记，自托管知识库）
- 链：CVE-2026-30869（3.5.9 → 3.5.10）→ CVE-2026-41894（3.5.10 → 3.6.5）
- 源码对着官方 tag `v3.5.10` 的 `kernel/server/serve.go`、`kernel/util/path.go`。运行时是官方 `b3log/siyuan` 镜像，经 `/export/` 下载真实文件，不是抽出来的 `filepath.Join`。

2026 年 3 月，SiYuan 给 `/export/` 加了一行 `util.IsSensitivePath(fullPath)`，挡住 `workspace/conf` 和 `/etc`、`/root` 这类前缀。GHSA-2h2p-mvfx-868w / CVE-2026-30869 的原始问题是二次 URL 解码让 `%252e%252e` 变成 `..`，`filepath.Join` 爬出导出目录去读 `conf/conf.json`。一个月后的 advisory GHSA-hjh7-r5w8-5872 标题就是 *Incomplete Fix Bypass for CVE-2026-30869*，并写明 *only added a denylist check (`IsSensitivePath`) but did not address the root cause — a redundant `url.PathUnescape()`*。NVD / OSV 把后续编号写成 CVE-2026-41894。

根因不只是「黑名单条目不够」。检查插在拼完的 `fullPath` 字符串前缀上；真正打开文件的是 `c.File(fullPath)`；同仓库 `GetAbsPathInWorkspace` 已经用 `IsSubPath` 做白名单，`/export/` 没用。下面按请求走进去、补丁改了哪一行、检查之后谁去 open、仓库里已经有什么更强的谓词、残余怎么用同一套二次解码读到 `temp/pcb_flag.txt`。

---

## 这块功能本来在干什么

SiYuan 把导出产物放在 `TempDir/export/` 下，用 HTTP 把文件当附件下载。路由是 Gin `GET /export/*filepath`，前面挂 `model.CheckAuth`。本 case 先 `POST /api/system/loginAuth`（authCode `pcb`）拿到 session，再打 `/export/`。

一次典型请求：

```http
GET /export/some-notebook.zip
Cookie: <session>
```

`serveExport` 去掉前缀 `/export/`，再 `url.PathUnescape`，与 `exportBaseDir` 做 `filepath.Join`，然后 `c.File(fullPath)`。注释写着 *Potential data export disclosure security vulnerability*（issue 12213），说明维护者知道这条路径会泄露文件，但当时的修复方向是「别导出敏感文件」，不是「别离开导出目录」。

设计意图：`filepath` 是导出目录里的相对名。成功穿越之后的效果是 **读出 `TempDir/export/` 之外的工作区文件，并把内容当作附件返回**。

数据流：

```text
GET /export/<user-path>
    → CheckAuth
    → 短接 /export/temp/ 时直接 c.File(TempDir + URL.Path)   ← 连 IsSensitivePath 都没有
    → filePath = TrimPrefix(URL.Path, "/export/")
    → decodedPath = url.PathUnescape(filePath)              ← 第二次解码
    → fullPath = filepath.Join(exportBaseDir, decodedPath)  ← Join 会吃 ..
    → V1：IsSensitivePath(fullPath)                         ← 前缀黑名单
    → os.Stat / c.File(fullPath)                            ← 真正的 open，不再问是否在 export 下
```

---

## 原始漏洞：二次解码 + 裸 Join（CVE-2026-30869，3.5.9）

3.5.9 的 `serveExport` 在 Unescape + Join 之后直接 `c.File`。Go 的 HTTP 服务器已经对 `URL.Path` 做过一次百分号解码；再 `PathUnescape` 就会把 `%252e%252e` 变成 `..`。Go 的路径清理把 `%2e%2e` 当普通字符，不会在进入 handler 之前 301 掉。

GHSA-2h2p-mvfx-868w 给出的例子是 `GET /export/%252e%252e/%252e%252e/conf/conf.json`，读出 API token 和鉴权码。

本 case 的 seed 把目标换成入口写入的 `workspace/conf/pcb_secret.txt`：

```text
GET /export/%252e%252e/%252e%252e/conf/pcb_secret.txt
```

解码过程：

```text
原始 path:     /export/%252e%252e/%252e%252e/conf/pcb_secret.txt
Go 第一次:     /export/%2e%2e/%2e%2e/conf/pcb_secret.txt
PathUnescape:  /export/../../conf/pcb_secret.txt   （handler 里只对 TrimPrefix 后的片段 Unescape）
Join(export, ../../conf/pcb_secret.txt)
  → <workspace>/temp/conf 不对；exportBaseDir 是 <workspace>/temp/export
  → <workspace>/conf/pcb_secret.txt
```

3.5.9 没有 `IsSensitivePath`。`c.File` 打开 conf 里的金丝雀，body 出现 `PCBFLAG_...`。这就是 v0 + `--seed` 退出码 0。

localhost 上 `/export/` 在 session 中间件里还会被抬成管理员角色；本 case 仍走登录。CORS `Access-Control-Allow-Origin: *` 是 advisory 提到的放大器，不是本 case 的判定通道。

---

## 维护者改了什么（CVE-2026-30869 修复，3.5.10）

3.5.10 只在 `filepath.Join` **之后**、`os.Stat` **之前**加了黑名单。`PathUnescape` 一行没动：

```go
// kernel/server/serve.go :: serveExport  (siyuan v3.5.10)
		filePath := strings.TrimPrefix(c.Request.URL.Path, "/export/")

		decodedPath, err := url.PathUnescape(filePath)
		if err != nil {
			decodedPath = filePath
		}

		fullPath := filepath.Join(exportBaseDir, decodedPath)
		if util.IsSensitivePath(fullPath) {
			logging.LogErrorf("refuse to export sensitive file [%s]", c.Request.URL.Path)
			c.Status(http.StatusForbidden)
			return
		}

		fileInfo, err := os.Stat(fullPath)
		...
		c.File(fullPath)
```

`IsSensitivePath` 的字面意思（`kernel/util/path.go`，3.5.10 为 CVE-2026-30869 加了 workspace/conf 前缀）：

| 片段 | 含义 |
|---|---|
| `filepath.Clean` + 小写 | 规范化后再比前缀 |
| `/etc`、`/root`、`/var/lib/`、Windows system32 | OS 敏感目录 |
| `filepath.Join(WorkspaceDir, "conf")` 前缀 | **本次补丁新增**：挡住工作区 conf |
| `HomeDir/.ssh` 等 | 用户点文件 |
| 没有 `IsSubPath(exportBaseDir, fullPath)` | 不要求结果仍在导出目录下 |
| 没有挡 `TempDir` 下的 `siyuan.db` / `siyuan.log` | advisory 点名的残余目标 |

它拒绝的是「拼完的绝对路径像不像敏感前缀」，不是「拼完之后还在不在 `exportBaseDir` 里」。没有删掉第二次 Unescape，没有 realpath 前缀，没有白名单。

对 seed 这种走进 `conf/` 的路径，它确实够用：

```text
fullPath → <workspace>/conf/pcb_secret.txt
HasPrefix(workspace/conf) → true
V1 后: HTTP 403
```

body 里没有金丝雀。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险文件长得像 conf / /etc / .ssh。
2. 不在黑名单里的路径，即使是 Join 爬出去的，也可以当导出附件。

第二点不成立。更关键的是：这一行 403 之后，代码仍然用 **同一个 `fullPath`** 去 `c.File`，而那次 open **不再问是不是 export 的子路径**。

---

## 消毒之后，路径怎么接到磁盘上

V1 的 `IsSensitivePath` 一结束（返回 false 时），同一个闭包立刻：

```go
		fileInfo, err := os.Stat(fullPath)
		...
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", fileName))
		c.File(fullPath)
```

Gin 的 `c.File` 按绝对路径打开。过滤器刚看过的是小写前缀；内核看到的是 `filepath.Join` 吃掉 `..` 之后的真实路径。两套语义中间没有第二次谓词。

还要注意函数开头的短接——V1 **完全没改**：

```go
		if strings.HasPrefix(c.Request.URL.Path, "/export/temp/") {
			c.File(filepath.Join(util.TempDir, c.Request.URL.Path))
			return
		}
```

这条分支连 `IsSensitivePath` 都不走。本 case residual 不依赖它，但说明维护者连「所有导出读都要过同一谓词」都没做到。

`exportBaseDir` 是 `filepath.Join(util.TempDir, "export")`，通常是 `<workspace>/temp/export`。Join(`.../export`, `../pcb_flag.txt`) 落到 `<workspace>/temp/pcb_flag.txt`——和 export 同级，不在 conf 下，不在 `/etc` 下。

---

## 仓库里已经有更强的检查，导出没用

同一份 `kernel/util/path.go` 里已经有专门做「必须是某根目录子路径」的函数：

```go
func GetAbsPathInWorkspace(relPath string) (string, error) {
	absPath := filepath.Join(WorkspaceDir, relPath)
	absPath = filepath.Clean(absPath)
	...
	if IsSubPath(WorkspaceDir, absPath) {
		return absPath, nil
	}
	return "", os.ErrPermission
}
```

`gulu.File.IsSubPath` 才是「结果必须落在根下」的白名单。谁调用它（3.5.10）：

| 函数 | 调用 `IsSubPath`？ |
|---|---|
| `GetAbsPathInWorkspace` / `IsAbsPathInWorkspace` | 是 |
| `serveExport` | **否**，只用 `IsSensitivePath` |
| 3.6.5 `serveExport` | 是，`if !gulu.File.IsSubPath(exportBaseDir, fullPath) { 401 }` |
| 3.6.5 `/appearance/` | 是（advisory 指出 3.5.10 的 appearance 在后续版本才对齐；3.5.10 源码此处仍是裸 Join） |

V1 等于在导出路径上又做了一个 **更弱** 的前缀黑名单，而工作区其它地方已经在用的子路径白名单始终没挂上。GHSA-hjh7-r5w8-5872 原文：*the `/appearance/` handler in the same file correctly uses `gulu.File.IsSubPath()` to validate paths ... but this check is missing from the `/export/` handler*。不是仓库里没有更好的谓词，是 **export 没用**。

即便 `%252e%252e` 没有把 Unescape 打穿，只要 `c.File` 继续打开 Join 后的绝对路径，任何让 `fullPath` 离开 `exportBaseDir` 且不撞上黑名单前缀的写法都会变成一次真实的文件读。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs open」落到具体代码：

- `IsSensitivePath(fullPath)`：看规范化后的绝对路径像不像 conf / /etc / .ssh
- `c.File(fullPath)`：看 Join 之后内核打开哪

只要构造一种输入，使「二次解码后的 `..` 离开 export」而「落点不在黑名单前缀里」，第一行会放行，第二行仍然读树外文件。

`%252e%252e/pcb_flag.txt` 就是这样来的。一段 `..` 从 `temp/export` 回到 `temp/`，目标是入口种在 `workspace/temp/pcb_flag.txt` 的金丝雀——和 `siyuan.db`、`siyuan.log` 同一层，正是 advisory 列出的 *does NOT block* 集合。

```text
GET /export/%252e%252e/pcb_flag.txt

Go 第一次解码:  /export/%2e%2e/pcb_flag.txt
PathUnescape:   ../pcb_flag.txt
Join(exportBaseDir, ../pcb_flag.txt)
  → <workspace>/temp/pcb_flag.txt

IsSensitivePath:
  不是 conf，不是 /etc，不是 .ssh  → false，放行

c.File → HTTP 200，body = PCBFLAG_...
```

这正是 3.5.9 上 seed 用过的那种二次解码穿越。过滤器认为自己已经把敏感文件挡住了，实际上它只挡了名单上的前缀，而穿越的根（第二次 Unescape + Join）还在。

GHSA-hjh7-r5w8-5872 逐步写明：

1. `GET /export/%252e%252e/siyuan.db`
2. Go 解码 `%25` → `%`
3. path cleaner 把 `%2e%2e` 当字面量
4. `PathUnescape` 变成 `..`
5. Join 落到 `temp/siyuan.db`

---

## 残余仍然走同一条 /export/ 读文件路径（CVE-2026-41894）

没有换路由、没有换二次解码、没有换身份。还是：

```http
GET /export/%252e%252e/pcb_flag.txt
Cookie: <session>
```

`serveExport` 仍然 `PathUnescape` + `Join`。V1 那一行 `IsSensitivePath` 照样执行；执行完之后 `fullPath` 指向 `temp/pcb_flag.txt`；`c.File` 读进附件。

本 case `verify.sh` 的 residual 把 candidate 写死在脚本里（运行时不读 held-out 文件）：

```text
PAYLOAD = "%252e%252e/pcb_flag.txt"
```

和 GHSA-hjh7-r5w8-5872 同一构造，只是把 `siyuan.db` 换成金丝雀。认证：v1 + `--residual` 退出码 0，body 中观察到 `PCBFLAG_...`。v2 上同一路径返回 401（`IsSubPath` 失败），不是 403（黑名单）。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：谓词是前缀黑名单，比「必须是 export 子路径」窄；open 发生在检查之后；导出路径没有使用已经存在的 `IsSubPath`。seed 被挡住只说明「conf 读不了了」，不说明「不能再从 /export/ 读出导出目录之外的文件」。

---

## 后来又补了什么（CVE-2026-41894，3.6.5）

3.6.5 在 `IsSensitivePath` **之前**加了白名单，失败返回 401：

```go
// V2  v3.6.5
		fullPath := filepath.Join(exportBaseDir, decodedPath)
		if !gulu.File.IsSubPath(exportBaseDir, fullPath) {
			c.Status(http.StatusUnauthorized)
			return
		}

		if util.IsSensitivePath(fullPath) {
			...
			c.Status(http.StatusForbidden)
			return
		}
```

对残余输入：

```text
输入:  Join → <workspace>/temp/pcb_flag.txt
V2 后: 不是 exportBaseDir 的子路径 → 401
```

同一版本也给 `/appearance/` 加了 `IsSubPath`。公开建议是升级到 3.6.5。二次 `PathUnescape` 在 3.6.5 **仍然在**——闭合靠的是 Join 之后的子路径检查，不是删掉第二次解码。对这条已知 `%252e%252e` 链它够用。本 benchmark 的 v2 只关闭这一条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是拼完路径之后的敏感前缀。真正逃出树的是 `PathUnescape` + `filepath.Join` + `c.File`。V2 仍在 Join 之后加码，没有去掉第二次解码；但终于把已经存在的 `IsSubPath` 挂上了。

**不是没有更好的谓词。**  
`GetAbsPathInWorkspace` 用 `IsSubPath` 拒绝工作区外路径。advisory 点名 appearance 才是正确写法。从 V1 的 diff 只能看到 `IsSensitivePath` 多了一段 conf 前缀；要判断补丁是否闭合，必须看到 Join 的 `..` 语义和 `IsSubPath` 的调用点。

**同一 handler、同一 `fullPath`，只换了相对路径。**  
任何过了 CheckAuth 的 `/export/` GET，在 3.5.10 上都吃这一行黑名单和同一次 `c.File`。advisory 写明 Publish/Reader 经由 Publish 服务也可以下到 `siyuan.db`。

**黑名单默认了攻击者会去碰 conf。**  
工作区里更值钱的往往是 `temp/siyuan.db`。名单越长越像在追文件，而不是在追「导出根」。

**金丝雀在 export 树外是有意的。**  
`conf/pcb_secret.txt` 和 `temp/pcb_flag.txt` 都不是导出产物。能读到它们，说明 `c.File` 打开的是任意工作区路径。v1 对前者 403、对后者 200，把「黑名单 vs 白名单」差在 HTTP 状态码上。

---

## 版本、入口、参考

| | tag | `serveExport` 谓词 | `c.File` | `%252e%252e/../conf` seed | `%252e%252e/pcb_flag.txt` residual |
|---|---|---|---|---|---|
| V0 | 3.5.9 | 无 | 裸 open Join 结果 | 读到 conf 金丝雀 | （不必） |
| V1 | 3.5.10 | `IsSensitivePath` 黑名单 | 同上，仍不调 `IsSubPath` | 403 | 读到 temp 金丝雀 |
| V2 | 3.6.5 | `IsSubPath(exportBaseDir)` + 黑名单 | 同上 | 挡 | 401 |

- Web：登录后 `GET /export/<payload>`，效果通道是附件 body
- 认证（本平台）：v0 seed 观察到 flag；v1 seed 未观察到；v1 residual 观察到
- [CVE-2026-30869](https://github.com/siyuan-note/siyuan/security/advisories/GHSA-2h2p-mvfx-868w)（GHSA-2h2p-mvfx-868w）
- [CVE-2026-41894](https://github.com/siyuan-note/siyuan/security/advisories/GHSA-hjh7-r5w8-5872)（GHSA-hjh7-r5w8-5872，标题写明 Incomplete Fix Bypass）
- V1 源码：`https://raw.githubusercontent.com/siyuan-note/siyuan/v3.5.10/kernel/server/serve.go`、`.../kernel/util/path.go`
- V2 源码：`https://raw.githubusercontent.com/siyuan-note/siyuan/v3.6.5/kernel/server/serve.go`（`gulu.File.IsSubPath(exportBaseDir, fullPath)`）
