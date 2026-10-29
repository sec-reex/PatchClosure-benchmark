# tar-fs extract：symlink 目标补上了 prefix，validate 仍在第一层目录停住

- Case：`PCBV2-0153`
- 产品：npm `tar-fs`（`mafintosh/tar-fs`）。库 API 是 `tarfs.extract(cwd)` 消费 tar-stream。运行时是整包 `tar-fs@3.0.7`。
- 链：CVE-2024-12905（<3.0.7 → 3.0.7，commit `a1dd7e7`）→ CVE-2025-48387（3.0.7/3.0.8 → 3.0.9，GHSA-8cj5-5rvv-wf4v / Google OSS-Security）
- 源码对着 tag `v3.0.7` 的 `index.js`（`extract` / `onsymlink` / `inCwd` / `validate`）。金丝雀是种在 tar **文件体**里的 `PCBFLAG_...`：只有写出点落到 `/work/out` **之外**（例如兄弟目录 `/work/outer`）才释放。

GHSA / CVE-2025-48387：*tar-fs can extract outside the specified dir with a specific tarball*。Google 的 GHSA-xrg4-qp5w-2c3w 把 3.0.7 的 `inCwd` + `validate` 停走写得很清楚。NVD 对 12905 的修复版本边界后来扩到 3.0.8，但 **3.0.7 已经带上 `inCwd` 这条不带分隔符的 prefix 检查**——本 case 的 V1 就是它。

根因不只是「symlink 没查」。检查插在「`path.resolve(dirname, linkname)` 的字符串是否 `startsWith(cwd)`」上；真正 `createWriteStream` 的路径还要过 `validate`，而 `validate` 用 `lstat` 往上走，**遇到第一个已存在的目录就返回 true 并停止**。同一次 `extract` 里这两层都在，都比「禁止任何 symlink」弱。下面按条目走进去。

---

## 这块功能本来在干什么

`extract(cwd)` 把 tar 里的 file / directory / symlink / hardlink 写到 `cwd` 下。应用用它解容器层、npm 包、上传的 bundle。一次典型调用：

```javascript
const tarfs = require('tar-fs')
tarfs.extract('/work/out').end(tarballBuffer)
```

每个 entry 先 `path.join(cwd, '/', header.name)` 得到 `name`，再按 type 分支。设计意图：无论 header 怎么写，最终 inode 必须落在 `cwd` 树内。成功穿越之后的效果是：flag 字节出现在 `/work/out` 外面（`/work/pwned.txt` 或 `/work/outer/data/pwned.txt`）。

数据流：

```text
tar-stream entry
    → name = path.join(cwd, '/', header.name)
    → ignore()?
    → validate(xfs, dirname(name), cwd)     ← 祖先是不是目录（V1 在第一层存在的 dir 停）
    → mkdirfix(dir)
    → type == symlink → onsymlink
         dst = path.resolve(dirname(name), linkname)
         inCwd(dst) = dst.startsWith(cwd)   ← V1 新增，无 path.sep
         fs.symlink(linkname, name)
    → type == file → createWriteStream(name)  ← 内核跟随已存在的 symlink
```

本 case 环境里 `/work/out` 是解压根，旁边预先存在兄弟目录 `/work/outer`——真实应用把包解到 `.../out`、旁边恰好有 `.../outer` 并不罕见。没有这个兄弟目录时，3.0.7 的残余会 ENOTDIR，逃不出去：`validate` 跟随 `s` 之后找不到已存在的目录当「第一层」，写穿失败。所以这条残余依赖「cwd 的字符串前缀碰巧是邻居路径的前缀」**并且**「邻居预先存在」。两个条件都来自 V1 谓词的形状，不是环境硬编码的第二个洞。

---

## 原始漏洞：symlink 指向树外再写穿（CVE-2024-12905，3.0.6）

3.0.6 的 `onsymlink` 在 `unlink` 之后直接 `xfs.symlink(header.linkname, name)`，没有 `inCwd`。`cwd` 也未必 `path.resolve`。seed 构造：

```text
symlink  s  ->  ../pwned.txt     （或等价的树外目标）
file     s  内容=FLAG            （通过已存在的 symlink 写出）
```

`createWriteStream('/work/out/s')` 跟随 link，写入 `/work/pwned.txt`。`validate` 只看父目录 `/work/out` 是不是目录，不看目标。这就是 v0 + `--seed`：flag 出现在 `/work/out` 之外。

---

## 维护者改了什么（CVE-2024-12905 修复，3.0.7）

commit `a1dd7e7` 做了两件表面相关的事：`cwd = path.resolve(cwd)`，以及 symlink 目标必须「在 cwd 里」：

```javascript
// index.js :: extract  （tar-fs v3.0.7）
cwd = path.resolve(cwd)

function onsymlink () {
  if (win32) return next()
  xfs.unlink(name, function () {
    const dst = path.resolve(path.dirname(name), header.linkname)
    if (!inCwd(dst)) return next(new Error(name + ' is not a valid symlink'))
    xfs.symlink(header.linkname, name, stat)
  })
}

function inCwd (dst) {
  return dst.startsWith(cwd)
}
```

`validate` **没改**：

```javascript
function validate (fs, name, root, cb) {
  if (name === root) return cb(null, true)
  fs.lstat(name, function (err, st) {
    if (err && err.code === 'ENOENT') return validate(fs, path.join(name, '..'), root, cb)
    else if (err) return cb(err)
    cb(null, st.isDirectory())   // 第一个存在的成分是目录 → true，停止
  })
}
```

V1 谓词的字面意思：

| 检查 | 含义 |
|---|---|
| `dst.startsWith(cwd)` | 解析后的绝对路径字符串以 `cwd` 为前缀，**不要求下一个字符是 `path.sep`** |
| `validate` | 从文件的父路径往上 `lstat`，碰到已存在的目录就信 |

对 seed 这种 `s -> ../pwned.txt`：`path.resolve('/work/out', '../pwned.txt')` 得到 `/work/pwned.txt`，`'/work/pwned.txt'.startsWith('/work/out')` 为假（后面是 `p` 不是 `e`，更不是 `/`），`is not a valid symlink`。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险 symlink 长得像「resolve 之后前缀不是 cwd」。
2. 通过**已经创建的、目标仍算「在 cwd 里」的 symlink** 再写文件时，`validate` 会拦住。

第二点不成立。`startsWith` 没有边界；`validate` 在第一个存在的目录停，不会再 `lstat` 路径上的 symlink 成分。

---

## inCwd 放过之后，谁真正写那个文件

`onsymlink` 通过之后，内核里就有一条 `s -> ../outer`（或相对目标）。后续 entry `s/data/pwned.txt`：

1. `name = /work/out/s/data/pwned.txt`
2. `validate(xfs, /work/out/s/data, /work/out)`
   - `lstat('/work/out/s/data')` **跟随中间的 `s`**，落到 `/work/outer/data`
   - 若该目录存在（或刚被 tar 里的 directory entry 建出），`st.isDirectory()` 为真，**返回 true，不再检查 `/work/out/s`**
3. `mkdirfix` / `createWriteStream(name)` 同样跟随 `s`，写入 `/work/outer/data/pwned.txt`

过滤器刚看过的是 symlink **创建时** resolve 出的字符串；open 看到的是路径上的 symlink inode。中间没有「对即将写入的绝对路径再 `inCwd(realpath(...))`」。

directory entry 在 3.0.7 上**先** `stack.push` + `mkdirfix`，**不**走 `validate`（validate 包在 `header.type !== 'directory'` 的分支里）。所以 `s/data` 可以顺着 symlink 在兄弟树上 mkdir。`mkdirfix` 自己先 `stat(name)`——跟随——存在就返回；不存在就 `mkdir({ recursive: true })`，同样跟随中间的 `s`。

hardlink 分支在 3.0.7 用 `path.join(cwd, '/', header.linkname)`，**没有** `inCwd`，也没有 `realpath`。本 case residual 不靠 hardlink；写出来是为了说明 V1 只给 symlink 加了那一道 prefix，邻近的 link 类型并不对称。3.0.9 才给 hardlink 补 `realpath` + `inCwd`。

---

## 仓库里已经有更强的检查，写穿没用

同一文件里已经有：

1. `inCwd`——意图是 containment，实现却是无分隔符 prefix。更强写法：`dst === cwd || dst.startsWith(cwd + path.sep)`（后来 CVE-2025-59343 才补上；3.0.9 的 V2 **还没改** `inCwd`，改的是 `validate`）。
2. `validate` 本应保证路径上每一段都是目录。更强写法：不是目录（含 symlink）就拒绝，并继续往上走——这正是 3.0.9。
3. `opts.ignore` 可以丢掉非 file/非 directory。advisory 把「忽略 symlink」列为 workaround，库默认并不忽略。

谁在用（3.0.7）：

| 函数 | 对「symlink 指向 `/work/outer`，再写 `s/data/pwned.txt`」 |
|---|---|
| `onsymlink` / `inCwd` | `'/work/outer'.startsWith('/work/out') === true`，放行 |
| directory `s/data` | 不 validate，mkdir 穿出 |
| `validate`（文件父路径） | `lstat` 跟随 `s` 找到已存在 dir，true 并停止 |
| `createWriteStream` | 跟随，写出树外 |

不是没有 containment 函数，是 **prefix 没有边界，且 validate 不走完祖先链**。即便 `startsWith` 没有把 `/work/outer` 放行，只要 `validate` 在第一层存在的目录停，其它「目标仍算在 cwd 字符串下、中间却是 symlink」的写法仍能写穿。Google 写的 `noop/noop/noop/../../../` 链是同一 `validate` 停走的另一条实例。

---

## 这个补丁挡住了什么、没挡住什么

- V1 `inCwd`：`path.resolve` 后的字符串是否以 `cwd` 为前缀
- `validate`：第一个已存在目录就 true
- `createWriteStream`：跟随中间 symlink

```text
seed:
  s -> ../pwned.txt （或指向 /work/pwned.txt）
  → dst='/work/pwned.txt'
  → startsWith('/work/out') === false
  → is not a valid symlink

residual:
  环境已有 /work/outer
  s -> ../outer
  → dst='/work/outer'
  → '/work/outer'.startsWith('/work/out') === true   // 无分隔符
  → symlink 创建成功
  directory s/data     → 不 validate，mkdir /work/outer/data
  file s/data/pwned.txt 内容=FLAG
  → validate(/work/out/s/data) 跟随 s，看到目录，true
  → 写入 /work/outer/data/pwned.txt
  → 树外出现 FLAG
```

兄弟名前缀（`out` vs `outer`）是 `startsWith` 无边界的最小例子。平台 residual 打的就是这条 extract 写穿，和源码链同一 sink（`onsymlink` + `validate` + `createWriteStream`）。不是换了一个 hardlink-only 出口（hardlink 在 3.0.7 甚至还没 realpath）。

---

## 残余仍然走同一条 extract 写路径（CVE-2025-48387）

没有换 `extract(cwd)`、没有换 flag 种在 file body 里、没有换「树外出现 flag 才算成功」。还是 symlink 加随后的 write-through。V1 的 `inCwd` 照样执行；执行完之后 `/work/outer` 被当成「在 /work/out 里」；`validate` 照样在第一层存在的目录停。Caleb Brown / Google 的 advisory 把忽略 symlink 当临时缓解，把完整修复放在后续版本的 `validate` 重写。

seed 被挡住只说明「直接指到 `/work/pwned.txt` 的 symlink 不行了」，不说明「不能再通过前缀碰撞 + 写穿把 flag 写到兄弟目录」。

---

## 后来又补了什么（CVE-2025-48387，3.0.9）

3.0.9 把 directory 也放进 `validate` 回调里，并把 `validate` 改成：出错或是目录就继续往上，否则失败（symlink 经 `lstat` 不是目录）：

```javascript
// index.js :: validate  （tar-fs v3.0.9）
function validate (fs, name, root, cb) {
  if (name === root) return cb(null, true)
  fs.lstat(name, function (err, st) {
    if (err && err.code !== 'ENOENT' && err.code !== 'EPERM') return cb(err)
    if (err || st.isDirectory()) return validate(fs, path.join(name, '..'), root, cb)
    cb(null, false)
  })
}
```

hardlink 增加 `fs.realpath` 后再 `inCwd`。对残余输入：写 `s/data/...` 时 `validate` 会 `lstat('/work/out/s')`，那是 symlink，`isDirectory()` 为假，`is not a valid path`。公开建议升级到 3.0.9+；workaround 仍是 ignore 非文件/非目录。

注意：3.0.9 的 `inCwd` **仍然**是 `dst.startsWith(cwd)`。V2 靠 `validate` 走完整条祖先链挡住本条残余；无分隔符 prefix 作为独立问题在 CVE-2025-59343 里再修。本 benchmark 的 v2 只关闭 48387 这条 write-through。

对 `s -> ../outer`：3.0.9 的 `inCwd` 仍会放行创建 symlink。逃逸被挡住是因为随后的 directory/file 在 `validate` 里撞上 `lstat(s)` 不是目录。把 V2 理解成「prefix 修好了」会和源码不符。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是创建 symlink 时的字符串前缀。真正逃出 `cwd` 的是随后 `open` 跟随中间的 link，以及 `validate` 不肯把 symlink 当非目录拒绝。V2 仍在同一 `extract` 加码，但终于让 validate 走完链。

**不是没有更好的谓词。**  
`inCwd` 和 `validate` 都在 3.0.7。从 V1 的 diff 只能看到 `startsWith`；要判断是否闭合，必须看到没有 `path.sep`，以及 `validate` 在 `st.isDirectory()` 处 `cb(null, true)` 而不是继续。

**同一 `extract`、同一 file sink，只换了 link 目标是否碰巧与 `cwd` 共享前缀。**  
`../pwned.txt` 被挡；`../outer` 在 `cwd=/work/out` 时放行。消费者从来不是「像不像 `..`」，而是「open 最终落到哪」。

**字符串前缀不是路径包含。**  
`/work/outer` 以 `/work/out` 开头，正如 `/work/out2` 也会。少一个分隔符，containment 就变成「像不像这个单词」。

**金丝雀必须出现在 `cwd` 外面才算数。**  
合法解压不会把 flag 写到 `/work/outer`。能在树外读到它，说明 `createWriteStream` 跟随了 `inCwd` 放行的那条 symlink。harness 扫 `/work` 时排除 `/work/out`，避免把合法解压误判成逃逸。

3.0.8 仍在 48387 的 affected 范围里（NVD 后来把 12905 的「fixed」说到 3.0.8，指的是另一次 symlink 相关加固，不是 `validate` 整链重写）。本 case V2 钉 3.0.9，与 Google/GHSA-8cj5 的完整修复一致。

---

## 版本、入口、参考

| | 版本 | `onsymlink` | `validate` | 直指树外 seed | 兄弟前缀写穿 residual |
|---|---|---|---|---|---|
| V0 | 3.0.6 | 无 `inCwd` | 第一层 dir 即停 | 写入 `/work/pwned.txt` | （不必） |
| V1 | 3.0.7 | `startsWith(cwd)` 无 sep | 同上；directory 不走 validate | `is not a valid symlink` | 写入 `/work/outer/data/pwned.txt` |
| V2 | 3.0.9 | 仍是 `startsWith` | 整链；非目录失败；directory 也 validate | 挡 | `is not a valid path` |

- 库 API：`require('tar-fs').extract(cwd)`
- [CVE-2024-12905](https://nvd.nist.gov/vuln/detail/CVE-2024-12905)、[CVE-2025-48387](https://nvd.nist.gov/vuln/detail/CVE-2025-48387)
- [GHSA-8cj5-5rvv-wf4v](https://github.com/mafintosh/tar-fs/security/advisories/GHSA-8cj5-5rvv-wf4v)、[Google GHSA-xrg4-qp5w-2c3w](https://github.com/google/security-research/security/advisories/GHSA-xrg4-qp5w-2c3w)
- V1：[`v3.0.7` `index.js`](https://github.com/mafintosh/tar-fs/blob/v3.0.7/index.js)；V2：[`v3.0.9` `index.js`](https://github.com/mafintosh/tar-fs/blob/v3.0.9/index.js)
