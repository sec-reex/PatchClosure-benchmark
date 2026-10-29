# plexus-archiver：canonical 拦了 `../`，悬空 symlink 的 getCanonicalPath 仍落在 dest 里

- Case：`PCBV2-0174`
- 产品：Codehaus Plexus Archiver（Maven `org.codehaus.plexus:plexus-archiver`）。运行时是 Maven Central 整包 `3.5` / `3.6.0` / `4.8.0`，薄 HTTP 入口只把上传的 tar 交给未改过的 `TarUnArchiver.extract()`。
- 链：CVE-2018-1002200（3.5 → 3.6.0，Zip-Slip，commit `f8f4233` / PR #87）→ CVE-2023-37460（≤4.7.1 → 4.8.0，GHSA-wh3p-fphp-9h2m，commit `5475983`）
- 源码对着 tag `plexus-archiver-3.6.0` 的 `src/main/java/org/codehaus/plexus/archiver/AbstractUnArchiver.java`（`extractFile`）。金丝雀是 benign：tar 条目内容是 `PCBFLAG_...`，写到 `/work/dest` 之外的 `/work/out/flag`。

GHSA-wh3p-fphp-9h2m：*Back in 2018, a ZipSlip vulnerability was discovered and fixed ... It turns out that even after the fix, plexus-archiver was still vulnerable to a similar attack.* 当目标目录里已有一条**指向不存在文件**的符号链接时，`resolveFile()` / `getCanonicalPath()` 返回的是链接自己的源路径（通过 containment），随后 `FileOutputStream` / `Files.newOutputStream` 默认跟随链接，内容写到链接目标。

根因不只是「漏了 symlink」。检查插在「规范化路径是不是 dest 前缀」上；真正写字节的是后面的 `new FileOutputStream(f)`。同函数注释已经写 *Hmm. Symlinks re-evaluate back to the original file here*，却没有 `isSymbolicLink` 谓词。下面按调用走进去。

---

## 这块功能本来在干什么

Plexus Archiver 给 Maven 插件和构建工具提供统一的解包 API。`TarUnArchiver` / `ZipUnArchiver` 最终都落到基类 `AbstractUnArchiver.extractFile`。一次典型调用：

```java
TarUnArchiver ua = new TarUnArchiver();
ua.setSourceFile(uploadedTar);
ua.setDestDirectory(new File("/work/dest"));
ua.extract();
```

本 case 的 HTTP 面是 `POST /extract`，body 是原始 tar。服务写临时文件后调用上面这段，再读见证 `/work/out/flag`。

设计意图：每个条目解析后必须落在 dest 目录内。成功穿越之后的效果是：**内容写到 dest 外的绝对路径**（本 case 是 `/work/out/flag`）。

数据流：

```text
POST /extract   body=tar
    → TarUnArchiver.extract()
         AbstractUnArchiver.extractFile
              f = FileUtils.resolveFile(dir, entryName)
              canonicalDest = f.getCanonicalPath()          ← V1 谓词
              if (!canonicalDest.startsWith(canonicalDir)) throw
              若 symlinkDestination 非空 → createSymbolicLink
              否则 new FileOutputStream(f)                  ← 跟随已有 symlink
                   IOUtil.copy(entryBytes, out)
    → 服务读 /work/out/flag → JSON witness
```

不需要登录。tar 由外部上传。dest 是 `/work/dest`；逃逸见证是 `/work/out/flag`。`overwrite` 默认为 true，所以第二条同名普通文件不会因为「已存在」而跳过写入——它会走进 `FileOutputStream`。

---

## 原始漏洞：`../` 直接 resolve 后写入（CVE-2018-1002200，3.5）

3.5 的 `extractFile` 在 `FileUtils.resolveFile(dir, entryName)` 之后**没有** containment 检查，直接 `new FileOutputStream(f)`。NVD：*plexus-archiver before 3.6.0 is vulnerable to directory traversal ... also known as 'Zip-Slip'*。Snyk 研究页和 PR #87 / commit `f8f4233` 是这次修复。

本 case seed 用单条普通文件：

```text
entry name:  ../out/flag
content:     ${PCB_FLAG}
dest:        /work/dest
resolve:     /work/out/flag
```

V0 照写。服务读见证，响应里出现 token。这就是 v0 + `--seed` 观察到 flag。明文 `../` 正是 1002200 补丁要挡的形态。

---

## 维护者改了什么（CVE-2018-1002200 修复，3.6.0）

3.6.0 在 `resolveFile` 之后、`mkdirs` / 写盘之前加上 canonical 前缀比较。对着 tag `plexus-archiver-3.6.0`：

```java
// AbstractUnArchiver.java :: extractFile  (plexus-archiver-3.6.0)
// Hmm. Symlinks re-evaluate back to the original file here. Unsure if this is a good thing...
final File f = FileUtils.resolveFile( dir, entryName );

// Make sure that the resolved path of the extracted file doesn't escape the destination directory
String canonicalDirPath = dir.getCanonicalPath();
String canonicalDestPath = f.getCanonicalPath();

if ( !canonicalDestPath.startsWith( canonicalDirPath ) )
{
    throw new ArchiverException( "Entry is outside of the target directory (" + entryName + ")" );
}

try
{
    ...
    if ( !StringUtils.isEmpty( symlinkDestination ) )
    {
        SymlinkUtils.createSymbolicLink( f, new File( symlinkDestination ) );
    }
    else if ( isDirectory )
    {
        f.mkdirs();
    }
    else
    {
        out = new FileOutputStream( f );   // 跟随已有 symlink
        IOUtil.copy( compressedInputStream, out );
    }
}
```

V1 谓词的字面意思：

| 片段 | 含义 |
|---|---|
| `FileUtils.resolveFile(dir, entryName)` | 拼路径并 `getCanonicalFile` |
| `canonicalDest.startsWith(canonicalDir)` | 规范化后必须在 dest 下 |
| 没有 `Files.isSymbolicLink` | 不区分「dest 里已有一条悬空链接」 |

对 seed 这种 `../out/flag`，`getCanonicalPath()` 得到 `/work/out/flag`，不以 `/work/dest` 开头，抛 `Entry is outside of the target directory`。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. `getCanonicalPath()` 总是反映「最终要写到的那个 inode」。
2. 通过 containment 之后，`FileOutputStream(f)` 不会写到树外。

两点在悬空 symlink 上都不成立。JDK `realpath`：目标存在时返回目标；目标不存在时退回链接自身的路径。`FileOutputStream` 默认跟随链接，把字节写到（尚不存在的）目标上，等于创建树外文件。

---

## 检查之后，谁真正写盘

V1 的 `startsWith` 一通过，同一个 `extractFile` 立刻进入写分支。普通文件走 `new FileOutputStream(f)`。`f` 此时若是一条指向 `/work/out/flag` 的悬空链接，canonical 比较看到的是 `/work/dest/entry1`（链接自己），`FileOutputStream` 看到的是链接目标。

过滤器刚看过的是「规范化字符串是不是 dest 前缀」；内核 open 看到的是 symlink follow。两套语义中间没有第二次谓词。函数开头那行注释已经承认 *Symlinks re-evaluate back to the original file here*，但比较和写入仍然用同一条 `f`。

GHSA 把后来 4.x 里的 `Files.newOutputStream(targetFileName.toPath())` 也标成默认 follow。3.6.0 用的是 `FileOutputStream`，跟随语义相同。

---

## 仓库里已经有更强的检查，没用上

同一次 `extractFile` 已经能区分「这条条目是不是在 *创建* symlink」（`symlinkDestination` 非空）和「这条条目是普通文件」。V2 用的谓词是：

```java
if (StringUtils.isEmpty(symlinkDestination) && Files.isSymbolicLink(canonicalDestPath))
    throw new ArchiverException("Entry is outside of the target directory (" + entryName + ")");
```

即：用普通文件去覆盖/跟随**已经存在的**符号链接时拒绝。3.6.0 没有 `Files.isSymbolicLink`。不是 2023 年才发明这个检查，是 **2018 年的 Zip-Slip 补丁只比了 canonical 字符串**。

`FileUtils.resolveFile` 内部的 `getCanonicalFile` 在目标不存在时返回源路径——这是 JDK 行为，不是 Plexus 独有。GHSA 把调用链写到 `JDK_Canonicalize`：先对整条路径 `realpath`；失败则从尾部剥名字重试，最终把「链接自己」当成 canonical。谓词若问的是 inode 类型而不是字符串前缀，悬空链接过不了。

`extract()` 本身只做 `validate` → `execute` → finalizer。路径决策全部在 `extractFile`。`TarUnArchiver` / `ZipUnArchiver` 没有自己的 containment；换归档格式不会换谓词。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs open」落到具体代码：

- `f.getCanonicalPath().startsWith(dir.getCanonicalPath())`：看规范化字符串
- `new FileOutputStream(f)`：看 open 是否跟随 symlink

只要构造一种输入，使「canonical 仍在 dest 内」但「写入跟随到 dest 外」，第一行会放行，第二行仍然写出树外文件。

GHSA 的 PoC：先放一条 `entry1 -> /tmp/target` 的 symlink，再放一条同名普通文件 `entry1`（或用两个归档、或改 zip 中央目录把第二条改名）。`resolveFile("entry1")` 在目标不存在时 canonical 为 dest 内的链接路径；随后 write 创建 `/tmp/target`。

本 case residual 同一构造，目标换成 `/work/out/flag`，内容是金丝雀：

```text
tar 条目 1:  entry1  类型=symlink  目标=/work/out/flag
tar 条目 2:  entry1  类型=regular  内容=PCBFLAG_...

V1 处理条目 1:
  createSymbolicLink(/work/dest/entry1 → /work/out/flag)
  canonical 在 dest 内，通过

V1 处理条目 2:
  f = resolveFile(dest, "entry1")  → 悬空链接
  getCanonicalPath() = /work/dest/entry1   （目标尚不存在）
  startsWith(/work/dest) → 通过
  FileOutputStream(f) 跟随 → 创建 /work/out/flag
```

这正是 3.5 上 seed 用过的那种逃逸（写出 `/work/out/flag`）。过滤器认为自己已经把 `../` 清干净了，实际上它刚允许「先种链接、再按同名写入」把字节送到链接目标。

advisory 也写明：不必在同一归档里重名，两个归档（先解链接、再解同名文件）同样能打。本 case 用单 tar 两条目，只是为了一次 `extract()` 走完。

重名在 zip 里有时要用中央目录改字节（GHSA 的 `sed -i 's/entry2/entry1/'`）；tar 可以直接写两条同名 `TarInfo`。平台 residual 用 tar，和 seed 同一 `TarUnArchiver`，不是换格式来躲检查。

---

## 残余仍然走同一个 extractFile（CVE-2023-37460）

没有换 UnArchiver、没有换 dest、没有换见证。还是：

```http
POST /extract
```

`TarUnArchiver.extract()` 仍然对每个条目调用 `extractFile`。V1 那两行 canonical 照样执行；对第二条普通 `entry1`，canonical 通过，`FileOutputStream` 跟随第一条留下的悬空链接，写出 `/work/out/flag`。

平台 residual 与不完整修复链是**同一 sink**（`AbstractUnArchiver.extractFile` → `FileOutputStream`），不是换到另一个归档格式的私有写路径。Zip 和 tar 都落到这个基类方法。

所以残余不是新洞面，而是同一写路径上三件事叠在一起：谓词问的是 canonical 字符串；open 发生在检查之后且跟随 symlink；注释里已经意识到 symlink 重求值，却没有 `isSymbolicLink`。seed 被挡住只说明「明文 `../` 没了」，不说明「不能再从 extract 写出 dest 外的文件」。

---

## 后来又补了什么（CVE-2023-37460，4.8.0）

commit `5475983` 在 containment 之后加上：若当前条目不是在创建 symlink，且目标路径已经是符号链接，则拒绝。4.8.0 同时把 `startsWith` 换成 `Path.startsWith`（避免 `/opt/dir` 误匹配 `/opt/directory` 这种字符串前缀假阴性）。

对残余输入：第二条 `entry1` 命中 `Files.isSymbolicLink`，抛 `Entry is outside of the target directory (entry1)`，`FileOutputStream` 不会执行。公开建议是升级到 4.8.0。

即便如此，这仍然是「在 open 之前多问一次 inode 类型」。两条归档分两次 `extract()`、中间有人在 dest 里放好链接，仍然依赖这次检查。本 benchmark 的 v2 关闭的是 reference residual 这条「同归档悬空链接 + 同名文件」。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是 `getCanonicalPath()` 字符串前缀。真正逃出 dest 的是 `FileOutputStream` 的 follow。V2 仍在 `extractFile` 里加码，但问的已经是 inode。

**不是没有更好的谓词。**  
函数开头的注释已经指向 symlink。`symlinkDestination` 分支说明作者知道链接和普通文件要分开处理。从 V1 的 diff 只能看到加了 `startsWith`；要判断补丁是否闭合，必须看到 `getCanonicalPath` 对悬空链接返回什么，以及 `FileOutputStream` 写到哪里。

**同一 `extractFile`、同一 `entryName`，只换了条目类型组合。**  
任何用 Plexus 解未信任归档的 Maven 插件，在 3.6.0–4.7.1 上都吃这次 canonical 和同一次 follow。advisory 影响面写的是 *whoever uses plexus archiver to extract an untrusted archive*。

**canonical 不是「最终写入路径」。**  
对悬空链接，它是链接自己；对已存在目标，它才是目标。谓词和 open 用了两种解析。

**金丝雀在 dest 外是有意的。**  
`/work/out/flag` 不是解压根下的普通条目。能读到它，说明 write 跟随到了 containment 之外。

**`overwrite` 默认 true。**  
第二条同名普通文件不会因为「dest 里已经有 entry1」而跳过；它会走进 `FileOutputStream`，这正是跟随发生的地方。
若调用方设了 `setOverwrite(false)` 且链接的 mtime 较新，残余可能写不进去——那是配置，不是 V1 谓词闭合。本 case 的 HTTP 服务不改 `overwrite`。

---

## 版本、入口、参考

| | 版本 | `extractFile` 谓词 | 写盘 | `../` seed | 悬空 symlink residual |
|---|---|---|---|---|---|
| V0 | 3.5 | 无 | `FileOutputStream(f)` | 写到 `/work/out/flag` | （不必） |
| V1 | 3.6.0 | canonical `startsWith` | 同上，跟随链接 | ArchiverException | canonical 通过，写出见证 |
| V2 | 4.8.0 | Path.startsWith + `isSymbolicLink` | 遇已有链接则拒 | 挡 | 挡 |

- 库 API：`TarUnArchiver.extract()` → `AbstractUnArchiver.extractFile`（本 case HTTP：`POST /extract`）
- 观察：响应 JSON `witness` 中的 `PCBFLAG_...`（`/work/out/flag`）
- [CVE-2018-1002200](https://nvd.nist.gov/vuln/detail/CVE-2018-1002200)、[CVE-2023-37460](https://nvd.nist.gov/vuln/detail/CVE-2023-37460)
- [GHSA-wh3p-fphp-9h2m](https://github.com/codehaus-plexus/plexus-archiver/security/advisories/GHSA-wh3p-fphp-9h2m)
- [Snyk Zip-Slip](https://snyk.io/research/zip-slip-vulnerability)、[SNYK-JAVA-ORGCODEHAUSPLEXUS-31680](https://snyk.io/vuln/SNYK-JAVA-ORGCODEHAUSPLEXUS-31680)
- V1 blob：[`AbstractUnArchiver.java@plexus-archiver-3.6.0`](https://github.com/codehaus-plexus/plexus-archiver/blob/plexus-archiver-3.6.0/src/main/java/org/codehaus/plexus/archiver/AbstractUnArchiver.java)
- V1 修复：[PR #87](https://github.com/codehaus-plexus/plexus-archiver/pull/87) / commit [`f8f4233`](https://github.com/codehaus-plexus/plexus-archiver/commit/f8f4233508193b70df33759ae9dc6154d69c2ea8)
- V2 commit：[`5475983`](https://github.com/codehaus-plexus/plexus-archiver/commit/54759839fbdf85caf8442076f001d5fd64e0dcb2) tag `plexus-archiver-4.8.0`
