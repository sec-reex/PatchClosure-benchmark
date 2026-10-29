# Gogs：IsSymlink 挂在新建/移动/上传上，API 纯更新路径没挂

- Case：`PCBV2-0121`
- 产品：Gogs（自托管 Git 服务）。运行时是官方镜像 `gogs/gogs:0.13.2` / `0.13.3` / `0.13.4`，整进程 HTTP，不是抽出来的函数。
- 链：CVE-2024-56731（0.13.2 → 0.13.3，commit `1cba9bc`）→ CVE-2025-64111（0.13.3 → 0.13.4，commit `c3eca1f`，GHSA-gg64-xxr9-qhjp）
- 源码对着 tag `v0.13.3` 的 `internal/db/repo_editor.go`（`UpdateRepoFile` / `UploadRepoFiles` / `DeleteRepoFile` / `GetDiffPreview`）、`internal/route/api/v1/repo/contents.go`（`PutContents`）、`internal/osutil/osutil.go`（`IsSymlink`）。金丝雀是 benign：`core.fsmonitor` 读入口写入的 `/data/pcb/flag.txt`，不是真 RCE payload。

NVD / GHSA-gg64-xxr9-qhjp 的原话：*due to the insufficient patch for CVE-2024-56731, it's still possible to update files in the `.git` directory and achieve remote command execution*。advisory 细节更具体：*`UpdateRepoFile` security check under some if conditions. While UpdateRepoFile call in API router will NOT match any of them.*

根因不只是「漏了一个 endpoint」。检查插在「这个路径字符串是不是 `.git`」以及「新建/移动时目标是不是 symlink」上；真正把字节写到磁盘的是后面的 `os.WriteFile`。同函数里已经有 `osutil.IsSymlink`，却只挂在 `IsNewFile` 和改名分支。下面按请求走进去。

---

## 这块功能本来在干什么

Gogs 给仓库提供 Web 上传和 GitHub 风格的 Contents API。两者最终都落到工作副本上的一次写文件，再 `git add` / `commit` / `push`。一次典型的 API 更新：

```http
PUT /api/v1/repos/<owner>/<repo>/contents/link
Authorization: token …
Content-Type: application/json

{"message":"update link","sha":"<blob sha>","content":"<base64>"}
```

`PutContents` 把 URL 里的 `*` 当树路径，base64 解码后交给 `UpdateRepoFile`。**不设 `IsNewFile`，且 `OldTreeName == NewTreeName`**，也就是「原地更新已有文件」：

```go
// internal/route/api/v1/repo/contents.go :: PutContents  (gogs v0.13.3)
func PutContents(c *context.APIContext, r PutContentsRequest) {
  content, err := base64.StdEncoding.DecodeString(r.Content)
  ...
  treePath := pathutil.Clean(c.Params("*"))

  err = c.Repo.Repository.UpdateRepoFile(
    c.User,
    db.UpdateRepoFileOptions{
      OldBranch:   c.Repo.Repository.DefaultBranch,
      NewBranch:   r.Branch,
      OldTreeName: treePath,
      NewTreeName: treePath,
      Message:     r.Message,
      Content:     string(content),
    },
  )
```

设计意图：调用者只能改仓库工作树里那个名字对应的普通文件。成功穿越之后的效果是：**写落到 symlink 指向的真实文件**（本 case 是 `.git/config`），随后 `git add` 触发 `core.fsmonitor`，脚本读出 `/data/pcb/flag.txt`。

数据流：

```text
PUT /api/v1/repos/.../contents/link   JSON content=base64(git config)
    → PutContents
         treePath = pathutil.Clean("link")     ← 只防路径穿越字符串，不看 inode
         UpdateRepoFile(IsNewFile=false, Old==New)
              isRepositoryGitPath("link")      ← 字面不是 .git，放行
              （V1 的 IsSymlink 只在 IsNewFile / 改名 分支）
              os.WriteFile(localPath+"/link", content)
                   内核跟随 symlink → .git/config
    → git add --all   → core.fsmonitor 跑 /data/pcb/fsmon.sh
    → /tmp/pcb_result.txt 出现 PCBFLAG_...
```

需要登录（或 API token）。仓库里事先有一条 `link -> .git/config` 的 symlink（git 允许提交 symlink）。没有「写 `.git/config`」这个显式权限位。

---

## 原始漏洞：上传跟着 symlink 走（CVE-2024-56731，0.13.2）

0.13.2 的 `UploadRepoFiles` 在 `com.Copy(tmpPath, targetPath)` 之前**没有** `IsSymlink`。CVE-2024-39931 已经加过 `isRepositoryGitPath`，拦的是路径**字符串**里出现 `.git`。advisory GHSA-wj44-9vcg-wjq7 写明：*there are no checks for symbolic links in the later steps. So, by creating a symbolic link that points to the `.git` directory, an attacker can still delete arbitrary files in the `.git` directory*。

本 case seed 走的是上传，不是删除。Web 流程：登录 → dropzone `POST .../upload-file` 得到 UUID → 再 commit 到仓库根。文件名是 `link`。`isRepositoryGitPath("link")` 为假。`com.Copy` 打开目标路径时内核跟随 symlink，覆盖 `.git/config`。

注入的 config 把 `core.fsmonitor` 指到预先放好的 `/data/pcb/fsmon.sh`。`git add` 时 Git 跑这个脚本，脚本读 flag 写到 `/tmp/pcb_result.txt`。这就是 v0 + `--seed` 观察到 `PCBFLAG_...`。

0.13.2 上 `UpdateRepoFile` 同样没有 symlink 检查；API PUT 在 V0 也能打。seed 选上传，是因为那是 56731 补丁明确加了 `IsSymlink` 的那条路。

---

## 维护者改了什么（CVE-2024-56731 修复，0.13.3）

commit `1cba9bc` 引入 `osutil.IsSymlink`（`Lstat` + `ModeSymlink`），并把它插进若干写路径。`v0.13.3` 的 `UpdateRepoFile` 入口仍是字符串检查：

```go
// internal/db/repo_editor.go :: UpdateRepoFile  (gogs v0.13.3)
func (repo *Repository) UpdateRepoFile(doer *User, opts UpdateRepoFileOptions) (err error) {
  // 🚨 SECURITY: Prevent uploading files into the ".git" directory.
  if isRepositoryGitPath(opts.NewTreeName) {
    return errors.Errorf("bad tree path %q", opts.NewTreeName)
  }
  ...
  oldFilePath := path.Join(localPath, opts.OldTreeName)
  filePath := path.Join(localPath, opts.NewTreeName)
  if err = os.MkdirAll(path.Dir(filePath), os.ModePerm); err != nil {
    return err
  }

  // If it's meant to be a new file, make sure it doesn't exist.
  if opts.IsNewFile {
    // 🚨 SECURITY: Prevent updating files in surprising place, check if the file is
    // a symlink.
    if osutil.IsSymlink(filePath) {
      return fmt.Errorf("cannot update symbolic link: %s", opts.NewTreeName)
    }
    if osutil.IsExist(filePath) {
      return ErrRepoFileAlreadyExist{filePath}
    }
  }

  if osutil.IsFile(oldFilePath) && opts.OldTreeName != opts.NewTreeName {
    if osutil.IsSymlink(oldFilePath) {
      return fmt.Errorf("cannot move symbolic link: %s", opts.OldTreeName)
    }
    ...
  }

  if err = os.WriteFile(filePath, []byte(opts.Content), 0600); err != nil {
    return fmt.Errorf("write file: %v", err)
  }
```

同一文件里，上传路径**每次**覆盖前都查：

```go
// internal/db/repo_editor.go :: UploadRepoFiles  (gogs v0.13.3)
    targetPath := path.Join(dirPath, upload.Name)

    // 🚨 SECURITY: Prevent updating files in surprising place, check if the target
    // is a symlink.
    if osutil.IsSymlink(targetPath) {
      return fmt.Errorf("cannot overwrite symbolic link: %s", upload.Name)
    }

    if err = com.Copy(tmpPath, targetPath); err != nil {
```

`DeleteRepoFile`、`GetDiffPreview` 同样无条件 `IsSymlink`。补丁默认了两件事：

1. 危险操作长得像「新建文件」或「改名/移动」或「dropzone 上传」。
2. 原地更新已有文件名时，目标不可能是 symlink；即使是，`os.WriteFile` 也只会改那个名字本身。

第二点不成立。Git 工作树里的 `link` 就是一条指向 `.git/config` 的 symlink。API 走的正是「不是新文件、名字没变」那条缝。

对 seed 这种上传：`UploadRepoFiles` 在 `com.Copy` 前看到 `IsSymlink(targetPath)==true`，返回 `cannot overwrite symbolic link`。这就是 v1 + `--seed` 退出码 10。

---

## 检查之后谁真正写那个路径

`IsSymlink` 一结束（或者根本没进那个 `if`），同一个 `UpdateRepoFile` 立刻：

```go
  if err = os.WriteFile(filePath, []byte(opts.Content), 0600); err != nil {
    return fmt.Errorf("write file: %v", err)
  }
```

`filePath` 是 `path.Join(localCopy, "link")`。Go 的 `os.WriteFile` 跟 POSIX `open` 一样，**默认跟随 symlink**。过滤器刚看过的是「`opts.IsNewFile` 是否为真」；open 看到的是 inode。中间没有第二次 `Lstat`。

`isRepositoryGitPath` 看的是 URL/树路径字符串，不是解析后的目标：

```go
func isRepositoryGitPath(path string) bool {
  path = strings.ToLower(path)
  return strings.HasSuffix(path, ".git") ||
    strings.Contains(path, ".git/") ||
    ...
}
```

`"link"` 不含 `.git`。真正被覆盖的 `.git/config` 从来不出现在这个谓词的输入里。

写完之后 `git.Add(..., All: true)` 会读这份被改过的 config。`core.fsmonitor` 是 Git 在 add 时执行的外部命令——这是效果通道，不是另一条漏洞面。

---

## 仓库里已经有更强的检查，纯更新没用

同一份 `osutil.go` 里的 `IsSymlink` 已经是对的谓词：`Lstat`，不跟随：

```go
// internal/osutil/osutil.go :: IsSymlink  (gogs v0.13.3)
func IsSymlink(path string) bool {
  if !IsExist(path) {
    return false
  }
  fileInfo, err := os.Lstat(path)
  if err != nil {
    return false
  }
  return fileInfo.Mode()&os.ModeSymlink != 0
}
```

谁调用它（0.13.3）：

| 函数 / 分支 | 调用 `IsSymlink`？ |
|---|---|
| `UploadRepoFiles` 覆盖前 | 是 |
| `DeleteRepoFile` | 是 |
| `GetDiffPreview` | 是 |
| `UpdateRepoFile` 且 `IsNewFile` | 是 |
| `UpdateRepoFile` 且改名（`OldTreeName != NewTreeName`） | 是 |
| `UpdateRepoFile` 纯更新（`IsNewFile=false` 且同名） | **否**，直接 `os.WriteFile` |
| `PutContents`（API） | **否**，自己也不查，把这条纯更新交下去 |

不是仓库里没有更好的谓词，是 **API 走的那条分支没用**。即便把 `IsSymlink(filePath)` 无条件挂上，也只检查最后一段；V2 才改成沿路径每一段 `Lstat` 的 `hasSymlinkInPath`。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「分支条件 vs open」落到具体调用：

- V1 过滤器：`IsNewFile` 或「旧名≠新名」时才 `Lstat`
- `os.WriteFile(localPath+"/link")`：内核按 symlink 打开 `.git/config`

只要构造一次 **同名、非新建** 的更新，第一道门放行，第二道门会跟着 link 走。

```text
seed（上传）:
  POST .../upload-file  file=link
  → UploadRepoFiles → IsSymlink(targetPath) == true → 拒绝

residual（API 纯更新）:
  PUT /api/v1/repos/.../contents/link
  → PutContents
       UpdateRepoFileOptions{IsNewFile: false, OldTreeName: "link", NewTreeName: "link"}
  → 跳过两个 IsSymlink 分支
  → os.WriteFile(.../link, malicious_config)
  → 实际写入 .git/config
```

GHSA-gg64-xxr9-qhjp 给的 PoC 就是这条 PUT，body 里是带 `sshCommand` 的 git config。本 case 把 `sshCommand` 换成 `core.fsmonitor` 读金丝雀，观察的是同一扇门有没有打开。

---

## 残余仍然走同一条工作树写文件路径（CVE-2025-64111）

没有换仓库、没有换身份模型、没有换观察通道。还是那条 `link -> .git/config`。换成 Contents API：

```http
GET  /api/v1/repos/<owner>/<repo>/contents/link     → 取 sha
PUT  /api/v1/repos/<owner>/<repo>/contents/link
     {"content":"<base64 of core.fsmonitor config>","message":"update link","sha":"..."}
```

`PutContents` 仍然调用同一个 `UpdateRepoFile`。V1 那两个 `IsSymlink` 分支照样不进；`os.WriteFile` 照样跟随；`git add` 照样跑 fsmonitor。API 可能返回 500（commit 阶段 fsmonitor 告警），但写已经发生——heldout 因此「不论 HTTP 状态都去读 `/tmp/pcb_result.txt`」。

本 case residual 和 advisory PoC 同一构造，只是把 `sshCommand` 换成金丝雀脚本。认证：v1 + `--residual` 观察到 `PCBFLAG_...`。

seed 被挡住只说明「dropzone 上传不再覆盖 symlink」，不说明「不能再通过 Contents API 把字节写进 `.git/config`」。

平台 `verify.sh` 的 residual 走的就是这条 API PUT，和源码链同一 sink（`UpdateRepoFile` → `os.WriteFile`）。不是另一条无关写路径。

---

## 后来又补了什么（CVE-2025-64111，0.13.4）

commit `c3eca1f`（*repository: reject any updates that has symlink in path hierarchy*）在 `UpdateRepoFile` 里、`os.WriteFile` **之前**无条件走路径每一段：

```go
// internal/db/repo_editor.go  (gogs v0.13.4，commit c3eca1f)
func hasSymlinkInPath(base, relPath string) bool {
  parts := strings.Split(filepath.ToSlash(relPath), "/")
  for i := range parts {
    filePath := path.Join(append([]string{base}, parts[:i+1]...)...)
    if osutil.IsSymlink(filePath) {
      return true
    }
  }
  return false
}

// UpdateRepoFile 在拿到 localPath 之后：
if hasSymlinkInPath(localPath, opts.OldTreeName) || hasSymlinkInPath(localPath, opts.NewTreeName) {
  return errors.New("cannot update file with symbolic link in path")
}
```

对残余输入：`relPath=="link"`，第一段就是 symlink，返回错误，写不到 `.git/config`，fsmonitor 不会被新 config 触发。公开建议升级到 0.13.4 / 0.14.0+dev。

即便如此，这仍然是「在 open 之前 Lstat 路径段」，没有改成 `O_NOFOLLOW`。对本条 `link -> .git/config` 够用。本 benchmark 的 v2 只关闭这一条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是若干「看起来像创建/移动」的分支。真正逃出工作树的是 `os.WriteFile` 跟随 symlink。V2 仍在同一函数加码，但终于把检查放到所有更新之前，并且沿路径每一段查，而不只是叶子。

**不是没有更好的谓词。**  
`IsSymlink` 已经用在上传、删除、diff preview 上。API 纯更新是同一份工作副本上的同一次 `WriteFile`。从 V1 的 diff 只能看到「新建时查一下」；要判断是否闭合，必须看到 `PutContents` 传下去的 `IsNewFile` 零值，以及 `WriteFile` 跟不跟随。

**同一 `UpdateRepoFile`、同一 `filePath`，只换了调用方。**  
Web 编辑器若走新建或改名，会被挡住；Contents API 固定走同名更新。advisory 原话就是 *the UpdateRepoFile call in the API router will NOT match any of them*。

**路径字符串检查和 inode 检查不是一层。**  
`isRepositoryGitPath` / `pathutil.Clean` 看 URL。symlink 让「看起来叫 `link` 的写」变成「写 `.git/config`」。只消毒字符串、不 `Lstat`，门是开的。

**金丝雀在 Git 配置里是有意的。**  
token 不在 HTTP 响应里。能在 `/tmp/pcb_result.txt` 读到它，说明工作副本上的 `.git/config` 已被写过，并且 `git add` 执行了里面的 fsmonitor——也就是过滤器放行了那次 `WriteFile`。

---

## 版本、入口、参考

| | 版本 | 上传 `UploadRepoFiles` | `UpdateRepoFile` 纯更新 | 明文上传 seed | API PUT residual |
|---|---|---|---|---|---|
| V0 | 0.13.2 | 无 `IsSymlink`，`com.Copy` 跟随 | 无 `IsSymlink` | 写到 `.git/config`，flag | （不必） |
| V1 | 0.13.3 | 覆盖前 `IsSymlink` | 只在 `IsNewFile`/改名 查 | `cannot overwrite symbolic link` | `WriteFile` 跟随，flag |
| V2 | 0.13.4 | 同上 | `hasSymlinkInPath` 无条件 | 挡 | `cannot update file with symbolic link in path` |

- Web seed：`POST /<user>/<repo>/upload-file` 再 commit
- API residual：`PUT /api/v1/repos/<user>/<repo>/contents/link`
- [CVE-2024-56731](https://nvd.nist.gov/vuln/detail/CVE-2024-56731)、[CVE-2025-64111](https://nvd.nist.gov/vuln/detail/CVE-2025-64111)
- [GHSA-wj44-9vcg-wjq7](https://github.com/gogs/gogs/security/advisories/GHSA-wj44-9vcg-wjq7)、[GHSA-gg64-xxr9-qhjp](https://github.com/gogs/gogs/security/advisories/GHSA-gg64-xxr9-qhjp)
- V1 commit `1cba9bc`；V2 commit [`c3eca1f`](https://github.com/gogs/gogs/commit/c3eca1fca3a4750e55dfa6d9935564a897232858)
- 源码：[`v0.13.3` `UpdateRepoFile`](https://github.com/gogs/gogs/blob/v0.13.3/internal/db/repo_editor.go)、[`PutContents`](https://github.com/gogs/gogs/blob/v0.13.3/internal/route/api/v1/repo/contents.go)
