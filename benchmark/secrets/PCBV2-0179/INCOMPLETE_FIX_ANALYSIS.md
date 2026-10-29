# pyLoad：commonpath 加进了仓库，Tar 解压仍在用 commonprefix

- Case：`PCBV2-0179`
- 产品：pyLoad（下载管理器）。运行时是整仓 `pip install ".[plugins]"` 后的 `pyload` 进程（端口 8000），不是抽出来的 `UnTar.py`。
- 链：CVE-2026-32808（commit `e81028fe` → `5f4f0fa5`，GHSA-7g4m-8hx2-4qh3）→ CVE-2026-35592（`5f4f0fa5` → `0fc250c9`，GHSA-mvwx-582f-56r7）
- 源码对着 `5f4f0fa5fed3520e57f2cb5a1053e3654c082eea` 的 `src/pyload/core/utils/fs.py`（`is_within_directory` / `safejoin`）、`src/pyload/plugins/extractors/SevenZip.py`（`verify`）、`src/pyload/plugins/extractors/UnTar.py`（`_safe_extractall`）。金丝雀是写出：恶意 tar 成员把 `${PCB_FLAG}` 写到解压目录的**兄弟路径**。

GHSA-mvwx-582f-56r7 的原话：*The correct function `os.path.commonpath()` was added to the codebase in the GHSA-7g4m-8hx2-4qh3 fix (commit 5f4f0fa) but was never applied to `_safe_extractall()`, making this an incomplete fix.*

根因不只是「Tar 插件忘了改」。检查插在「拼出来的绝对路径字符串是不是以 dest 为前缀」上；真正写盘的是后面的 `tarfile.extractall`。同一次 32808 补丁已经在 `fs.py` 里放了按路径分量比较的 `is_within_directory`，却只挂到 `safejoin` 的调用点上。下面按产品路径走进去。

**平台 seed 和残余不是同一个 sink。** seed 打的是 `SevenZip.verify()` 里 join 之后的 `os.remove`（任意删除）；残余打的是 `UnTar._safe_extractall` 的 zip-slip 写出。二者同属「32808 引入了 `commonpath`，但没接到所有归档路径消费者」这条链。下文先写 32808 改了什么、Tar 为什么没吃到，再写残余成员名怎么骗过 `commonprefix`。

---

## 这块功能本来在干什么

pyLoad 下完带归档的包之后，ExtractArchive 插件会按类型选 extractor。Tar 走到 `UnTar.extract`；加密 7z 在真正解开之前会先 `SevenZip.verify` 试密码。

一次典型的 Tar 解压（用户添加下载 → 完成 → 插件解压）：

```text
ExtractArchive.package_finished
    → extract_queued
    → UnTar.extract(self.dest)
         tarfile.open(...)
         _safe_extractall(t, self.dest)
              对每个 member: join(dest, member.name) 再做「是否仍在 dest 内」
              tar.extractall(path, ...)
```

设计意图：归档成员必须落在该包的解压目录里。成功穿越之后的效果是：**成员名带 `../`，文件写到 dest 的兄弟目录**（本 case 是 `<dl>/pkg_evil/CANARY.txt`，内容为 `PCBFLAG_...`）。

7z 密码校验是另一条写/删路径：`SevenZip.verify` 从 `7z l` 输出取出条目名，拼到 `self.dest` 上再 `os.remove`。32808 修的就是这条删除。

---

## 原始漏洞：条目名直接 join 再删（CVE-2026-32808，`e81028fe`）

V0 的 `SevenZip.verify` 在加密文件、非加密头的 7z 上，找出最小文件，拼路径，先 `os.remove` 再试解：

```python
# SevenZip.verify  (pre-5f4f0fa)
extracted = os.path.join(self.dest, smallest if self.fullpath else os.path.basename(smallest))
os.remove(extracted)
```

`smallest` 来自 `7z l`，攻击者可做成 `../victim`。`os.path.join` 不拦 `..`。GHSA-7g4m-8hx2-4qh3：可删 pyLoad 进程写得动的任意文件；删掉 `~/.pyload/data/pyload.db` 后重启会回到默认口令。

同一 commit 之前，`UnTar._safe_extractall` 已经有一层「防 CVE-2007-4559」的检查，但用的是 `os.path.commonprefix`（字符串前缀），不是路径分量。V0 上这条 Tar 检查就已经能被兄弟目录名骗过；seed 选 7z 删除，是因为 32808 advisory 明确修的是那条 `os.remove`。

---

## 维护者改了什么（CVE-2026-32808 修复，`5f4f0fa5`）

`5f4f0fa5` 在 `fs.py` 增加按 **realpath + commonpath** 的谓词，并让 `safejoin` 调用它：

```python
# src/pyload/core/utils/fs.py  (5f4f0fa5)
def is_within_directory(base_dir, target_dir):
    real_base = os.path.realpath(base_dir)
    real_target = os.path.realpath(target_dir)
    return os.path.commonpath([real_base, real_target]) == real_base

def safejoin(*args):
    base = args[0]
    safe_joined = safepath(os.path.join(*args))
    if not is_within_directory(base, safe_joined):
        raise ValueError("Path traversal attempt detected")
    return safe_joined
```

`os.path.commonpath` 按路径分量取最长公共祖先，不是按字符前缀。`/downloads/pkg` 和 `/downloads/pkg_evil/x` 的 commonpath 是 `/downloads`，不等于 dest。

同一 diff 把 `os.path.join(self.dest, ...)` 换成 `safejoin` 的地方包括：

| 调用点 | 换成 safejoin？ |
|---|---|
| `SevenZip.verify` 里拼 `extracted` 再 `os.remove` | 是 |
| `SevenZip._find_smallest_file` / `chunks` / `UnRar` / `UnZip.list` / `HjSplit` | 是 |
| `UnTar.list`（`t.getnames()` 只用来填 `self.files`） | 是 |
| `UnTar._safe_extractall`（真正 `extractall` 之前的检查） | **否** |

V1 的 `SevenZip.verify`：

```python
# SevenZip.verify  (5f4f0fa5)
extracted = safejoin(self.dest, smallest if self.fullpath else os.path.basename(smallest))
try:
    os.remove(extracted)
```

seed 那种 `../` 条目名在 `is_within_directory` 处抛 `ValueError`，删不到树外文件。这就是 v1 + `--seed` 退出码 10。

补丁默认：凡是「归档条目 → 本地路径」都会经过 `safejoin`。`UnTar.extract` 并不经过 `safejoin`。

---

## 消毒之后，Tar 成员名怎么接到磁盘上

V1 的 `UnTar.py` 已经 `from pyload.core.utils.fs import safejoin`，但 `extract` 仍走模块级 `_safe_extractall`：

```python
# UnTar.py  (5f4f0fa5)
def _safe_extractall(tar, path=".", members=None, *, numeric_owner=False):
    def _is_within_directory(directory, target):
        abs_directory = os.path.abspath(directory)
        abs_target = os.path.abspath(target)
        prefix = os.path.commonprefix([abs_directory, abs_target])
        return prefix == abs_directory

    for member in tar.getmembers():
        member_path = os.path.join(path, member.name)
        if not _is_within_directory(path, member_path):
            raise ArchiveError("Attempted Path Traversal in Tar File (CVE-2007-4559)")

    tar.extractall(path, members, numeric_owner=numeric_owner)
```

过滤器看的是 **`commonprefix` 字符串**。`abspath("../pkg_evil/x")` 在 dest=`/data/dl/pkg` 时变成 `/data/dl/pkg_evil/x`。`' /data/dl/pkg' ` 是 `' /data/dl/pkg_evil/x' ` 的字符前缀，检查通过。随后 `tar.extractall` 按 POSIX 解析 `..`，把字节写到兄弟目录。

`list()` 用了 `safejoin`，只影响「列出将要解压的文件」；写出不经过 `list()`。

---

## 仓库里已经有更强的检查，解压没用

同一 commit 放进 `fs.py` 的 `is_within_directory` 禁止「realpath 后公共祖先不是 dest」。谁调用它：

| 函数 | 调用 `is_within_directory` / `safejoin`？ |
|---|---|
| `safejoin` 本身（进而 SevenZip.verify、UnZip.list、UnTar.list …） | 是 |
| `UnTar._safe_extractall` 内联的 `_is_within_directory` | **否**，继续 `commonprefix` |

V1 等于在 7z 删除路径上挂了路径分量谓词，而 Tar 写出路径上那个更弱的字符串前缀检查始终没换。不是仓库里没有更好的谓词，是 **extract 没用**。

`UnTar.py` 已经 import 了 `safejoin`，差的是 `_safe_extractall` 把内联函数换成 `fs.is_within_directory`。GHSA 推荐的修复就是这一行替换。

`list()` 用 `safejoin(self.dest, name)` 只为了填 `self.files` 给 UI/日志看。攻击者不需要这份列表为真：`extract()` 在 `verify()` 之后直接 `_safe_extractall`，成员名只经过内联 `commonprefix`。所以「UnTar 已经 import safejoin」从模块顶上看是真的，从写出路径上看是假的。

---

## 这个补丁挡住了什么、没挡住什么

- `safejoin` + `commonpath`：看 realpath 后是否仍是 dest 的子路径（7z 删除、多数 join）
- `_safe_extractall` 的 `commonprefix`：看两个绝对路径字符串是否共享字符前缀

只要构造一种成员名，使 `abspath(dest/name)` 以 dest 字符串开头、但路径分量已经走出 dest，第一套谓词用不上（根本没挂），第二套放行，`extractall` 仍然写出。

经典 zip-slip 前缀碰撞：

```text
dest:     /data/downloads/pkg
member:   ../pkg_evil/CANARY.txt

join:     /data/downloads/pkg/../pkg_evil/CANARY.txt
abspath:  /data/downloads/pkg_evil/CANARY.txt

commonprefix(['/data/downloads/pkg',
              '/data/downloads/pkg_evil/CANARY.txt'])
        = '/data/downloads/pkg'     ← 等于 dest，检查通过

commonpath(...) = '/data/downloads'  ← 不等于 dest，本该拒绝
```

`../pkg_evil` 利用的是 dest 最后一段 `pkg` 是目标目录名 `pkg_evil` 的前缀。明文 `../../../../etc/passwd` 那种「公共前缀已经对不上 dest」的穿越，旧检查也能挡住；32808 补丁没有把 Tar 从「挡经典 `../`」推进到「挡前缀碰撞」。

---

## 残余走 UnTar 写出，不是 SevenZip 删除（CVE-2026-35592）

没有换 pyLoad 进程、没有换 ExtractArchive 插件模型。换的是归档类型和 sink：

```text
恶意 .tar.gz，成员名 ../pkg_evil/CANARY.txt，内容 = PCBFLAG_...
    → UnTar.extract → _safe_extractall
         commonprefix 放行
         tar.extractall 写到 dest 的兄弟目录
```

平台 residual 观察到的是解压目录外那份 `CANARY.txt`，不是 7z 校验删掉的文件。这与 GHSA-mvwx-582f-56r7 的 PoC 同一构造（advisory 用 `/tmp/test_extraction_dir_pwned`）。

所以：seed 被挡住只说明「7z verify 的 join 换成了 safejoin」；不说明「归档解压不能再写出 dest 之外」。残余是 incomplete-fix 链上的 **sibling sink**（同一 `commonpath` 工具函数没挂到 Tar extract），不是另一条无关产品功能。

GHSA-mvwx-582f-56r7 的 PoC 用 dest=`/tmp/test_extraction_dir`、成员 `../test_extraction_dir_pwned/evil.txt`，打印 `Check passes (should be False): True`。这就是 `commonprefix` 的字符语义：dest  basename 是目标目录名的前缀时，abspath 之后字符串仍以 dest 开头。`commonpath` 会得到父目录 `/tmp`，检查失败。V1 的 `fs.py` 已经有后一种实现。

---

## 后来又补了什么（CVE-2026-35592，`0fc250c9`）

`0fc250c94270a43605e4197dcea5b44998190977` 只改 `UnTar.py`：删掉内联 `_is_within_directory`，改调 `fs.is_within_directory`：

```python
# UnTar.py  (0fc250c9)
from pyload.core.utils.fs import is_within_directory, safejoin

def _safe_extractall(tar, path=".", members=None, *, numeric_owner=False):
    for member in tar.getmembers():
        member_path = os.path.join(path, member.name)
        if not is_within_directory(path, member_path):
            raise ArchiveError("Attempted Path Traversal in Tar File (CVE-2007-4559)")
    tar.extractall(path, members, numeric_owner=numeric_owner)
```

对残余成员：`commonpath` 得到 dest 的父目录，不等于 dest，抛 ArchiveError，`extractall` 不会跑。公开建议升到 `pyload-ng 0.5.0b3.dev97`。

即便如此，`extractall` 之前仍是「先 join 再比 realpath」，没有 chroot / 独立临时目录。本 benchmark 的 v2 关闭这条 `../<dest前缀>_evil/` 写出。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是 `fs.safejoin` 和一批 `os.path.join` 调用点。Tar 真正逃出 dest 的是 `_safe_extractall` 里对 `tarfile.extractall` 的放行。V2 仍在同一函数换谓词，没有把解压丢进一次性沙箱目录。

**不是没有更好的谓词。**  
`is_within_directory` 在 32808 当天就进了 `fs.py`，而且 `UnTar.list` 已经 import `safejoin`。从 32808 的 diff 只能看到 UnTar 改了 `list()`；要判断补丁是否闭合，必须看到 `extract()` 仍调用带 `commonprefix` 的 `_safe_extractall`。

**同一插件、两种归档、两个 sink。**  
7z 校验删除和 Tar 解压写出都把「归档控制的路径」拼到 `self.dest` 上。只修 join 调用点、不修 extract 前的专用检查，就会留下 sibling。

**`commonprefix` 不是路径 API。**  
文档写明它是字符串操作。dest 名叫 `pkg` 时，`pkg_evil` 这种兄弟名是稳定的碰撞；换一个不以 dest 为前缀的目录名，旧检查反而会挡住。谓词强弱取决于目录怎么起名。

**平台 seed 不能拿来推断残余 sink。**  
v1 + `--seed` 退出码 10 只覆盖 SevenZip.verify。Tar zip-slip 在 V0/V1 上一直开着，只是 seed 没走它。

**`safepath` 也不是路径安全。**  
`safejoin` 先 `safepath(os.path.join(*args))` 再 `is_within_directory`。`safepath` 只剥 Windows 非法字符、截断超长名，不处理 `..`。真正挡住 7z 删除的是后面那次 `commonpath`。Tar extract 两条都没走。

**ExtractArchive 是产品入口，不是另一条洞。**  
HTTP/API 添加链接、下完包、插件解压，最后仍落到 `UnTar.extract(self.dest)` 或 `SevenZip.verify`。评测若用 `docker exec` 直接调 extractor，只是少了 Web 那几步，sink 仍是 site-packages 里的这两份插件。

---

## 版本、入口、参考

| | commit | SevenZip.verify | UnTar._safe_extractall | 7z `../` 删除 seed | Tar `../pkg_evil` 写出 |
|---|---|---|---|---|---|
| V0 | `e81028fe` | 裸 `os.path.join` + `os.remove` | `commonprefix` | 删到树外 | （开着，seed 未用） |
| V1 | `5f4f0fa5` | `safejoin` + `commonpath` | **仍 `commonprefix`** | ValueError | 写到兄弟目录 |
| V2 | `0fc250c9` | 同上 | `fs.is_within_directory` | 挡 | ArchiveError，挡 |

- 产品路径：pyLoad Web/API 添加下载 → ExtractArchive → `UnTar.extract` / `SevenZip.verify`
- [GHSA-7g4m-8hx2-4qh3](https://github.com/pyload/pyload/security/advisories/GHSA-7g4m-8hx2-4qh3)（CVE-2026-32808）
- [GHSA-mvwx-582f-56r7](https://github.com/pyload/pyload/security/advisories/GHSA-mvwx-582f-56r7)（CVE-2026-35592）
- V1 blob：[`fs.py@5f4f0fa5`](https://github.com/pyload/pyload/blob/5f4f0fa5fed3520e57f2cb5a1053e3654c082eea/src/pyload/core/utils/fs.py)、[`UnTar.py@5f4f0fa5`](https://github.com/pyload/pyload/blob/5f4f0fa5fed3520e57f2cb5a1053e3654c082eea/src/pyload/plugins/extractors/UnTar.py)、[`SevenZip.py@5f4f0fa5`](https://github.com/pyload/pyload/blob/5f4f0fa5fed3520e57f2cb5a1053e3654c082eea/src/pyload/plugins/extractors/SevenZip.py)
- V2：[`UnTar.py@0fc250c9`](https://github.com/pyload/pyload/blob/0fc250c94270a43605e4197dcea5b44998190977/src/pyload/plugins/extractors/UnTar.py)
