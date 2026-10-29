# compressing：字符串说在 destDir 里，lstat 才知道 link 指向外面

- Case：`PCBV2-0069`
- 产品：npm `compressing`（Node 归档库；`compressing.tar.uncompress(source, destDir)` 解 tar/tgz/zip）
- 链：CVE-2026-24884（2.0.0 → 2.1.0，`isPathWithinParent` 字符串前缀）→ CVE-2026-40931 / GHSA-4c3q-x735-j3r5（→ 2.1.1 / 1.10.5，`isRealPathSafe` 逐段 `lstat`）
- 源码对着 GitHub tag `v2.1.0` 的 `lib/utils.js`：`isPathWithinParent`、`makeUncompressFn` 的 `'entry'` 处理。运行时是 npm 整包，HTTP `POST /extract` 把 tar 字节交给真实 `compressing.tar.uncompress`。

2.1.0 给解压加了 `path.resolve` 之后的前缀检查，并额外检查 **tar 里带的 symlink 条目** 的文本 target。这挡住了成员名 `../pcb_witness/flag.txt`，也挡住了「tar 自己带一条指向外面的 symlink」。GHSA-4c3q-x735-j3r5 标题就是 *Complete Bypass of CVE-2026-24884 Patch via Git-Delivered Symlink Poisoning*：destDir 里已经有一条 **磁盘上预先存在的** symlink（git clone 会原样留下），普通文件成员 `link/flag.txt` 的字符串路径仍在 destDir 内，但 `createWriteStream` 会顺着 symlink 写到外面。NVD CVE-2026-40931：*the patch for CVE-2026-24884 relies on a purely logical string validation within the isPathWithinParent utility*.

根因不只是「没调 lstat」。检查插在「resolve 后的字符串是不是以 destDir 开头」这一层；真正写文件的是 `fs.createWriteStream(destFilePath)`，内核会跟随已有 symlink。同一文件里已经会检查 tar 携带的 `header.linkname`，却从不 `lstat` 路径上已经存在的段。下面按请求走进去、2.1.0 改了哪几行、检查之后谁 open、磁盘谓词为什么没挂上，把这几层写完。

---

## 这块功能本来在干什么

`compressing.tar.uncompress(buf, destDir)` 把归档里的每个 entry 写到 `path.join(destDir, header.name)`。设计意图：无论成员名叫什么，文件必须落在 destDir 树内。

本 case 的服务对每个 `POST /extract` 建一份全新的临时 `destDir`，旁边是同级的 `pcb_witness/`（在 destDir **外面**）。tar 里那个文件的内容就是 `${PCB_FLAG}`。成功穿越之后的效果是：**`pcb_witness/flag.txt` 出现，body 的 `canary_value` 等于 flag**。解析后的归档从不回显，所以金丝雀只能来自一次逃出 destDir 的写入。

数据流：

```text
POST /extract  (raw tar bytes；residual 还带 x-pcb-poison: link)
    → 可选：destDir/link → ../pcb_witness     ← 模拟 git 留下的 symlink
    → compressing.tar.uncompress(buf, destDir)
         makeUncompressFn 'entry' handler
              destFilePath = join(destDir, stripFileName(name))
              resolvedDestPath = path.resolve(destFilePath)
              V1：isPathWithinParent(resolvedDestPath, destDir)   ← 只看字符串
                  symlink 条目再 resolve(linkname) 做同一检查
              通过则 mkdir + createWriteStream(destFilePath)     ← 真正的 open，跟随磁盘 symlink
    → 服务读 pcb_witness/，填 canary_value
```

没有登录。判断完全信任 `path.resolve` 的字符串前缀；不信任内核随后怎么走 already-present symlink。

`tgz.uncompress` 与 `tar.uncompress` 共用 `makeUncompressFn`，只是外面包 gzip。GHSA 回归测试明确 tgz 与 tar 同一缺口。zip 路径也走这份 utils，本 case 只打 tar，因为 advisory 的 git-poison 复现用 tar。

`stripFileName` 在检查之前会规范化名字：去掉绝对路径前导 `/`、把 `\` 换成 `/`、以及一段「看见 `..` 就抠掉 `../` 前缀」的处理。它对 `link/flag.txt` 原样返回——里面没有 `..`。所以 V1 的字符串检查面对的就是 `join(destDir, "link/flag.txt")`。

```javascript
// lib/utils.js :: stripFileName  (tag v2.1.0，节选)
  // fix relative path
  // foo/../bar/../../asdf/ => asdf/
  if (s.indexOf('..') !== -1) {
    fileName = fileName.replace(/(\.\.\/)+/, '');
    ...
  }
  strip = Math.min(strip, s.length - 1);
  return s.slice(strip).join('/') || '/';
```

这是另一层「只改字符串、不看磁盘」的消毒。seed 的 `../pcb_witness/flag.txt` 既可能被这里抠掉前缀、也会被后面的 `isPathWithinParent(resolve(...))` 挡住（resolve 后仍在 destDir 外）。residual 两层都过。

---

## 原始漏洞：join 完就写（CVE-2026-24884，2.0.0）

2.0.0 的 entry 处理没有 containment 检查。成员名 `../pcb_witness/flag.txt` 经 `path.join` / `path.resolve` 落到 destDir 的兄弟目录。seed 用 stdlib `tarfile` 打一份 GNU tar，单文件成员就是这条相对路径，内容是 flag。

V0 上 `createWriteStream` 写出 `pcb_witness/flag.txt`，HTTP `canary_value` 含 `PCBFLAG_...`。这是 case.json 记录的一次真实 Docker gate（**本分析未重新 compose**）。

`stripFileName` 在更早版本里就会抠掉一些 `../` 前缀，但不是完整的「解析后必须在 destDir 下」；CVE-2026-24884 才把 `isPathWithinParent` 接到 entry 路径上。

---

## 维护者改了什么（CVE-2026-24884 修复，2.1.0）

对着 GitHub tag `v2.1.0` 原文（这是 V1 不完整点；仓库里的 `patch.diff` 同步过 V1→V2 的 `isRealPathSafe`，分析以 tag 源码为准）：

```javascript
// lib/utils.js :: isPathWithinParent  (tag v2.1.0)
function isPathWithinParent(childPath, parentPath) {
  const normalizedChild = path.resolve(childPath);
  const normalizedParent = path.resolve(parentPath);
  const parentWithSep = normalizedParent.endsWith(path.sep)
    ? normalizedParent
    : normalizedParent + path.sep;
  return normalizedChild === normalizedParent ||
    normalizedChild.startsWith(parentWithSep);
}
```

挂到 `makeUncompressFn` 的 `'entry'` 回调：

```javascript
// lib/utils.js :: makeUncompressFn  'entry'  (tag v2.1.0)
            const destFilePath = path.join(resolvedDestDir, stripFileName(strip, header.name, header.type));
            const resolvedDestPath = path.resolve(destFilePath);

            // Security: Validate that the entry path doesn't escape the destination directory
            if (!isPathWithinParent(resolvedDestPath, resolvedDestDir)) {
              console.warn(`[compressing] Skipping entry with path traversal: "${header.name}" -> "${resolvedDestPath}"`);
              stream.resume();
              return;
            }

            if (header.type === 'file') {
              const dir = path.dirname(destFilePath);
              fs.mkdir(dir, { recursive: true }, err => {
                ...
                pump(stream, fs.createWriteStream(destFilePath, { mode: opts.mode || header.mode }), ...);
              });
            } else if (header.type === 'symlink') {
              const dir = path.dirname(destFilePath);
              const target = path.resolve(dir, header.linkname);
              if (!isPathWithinParent(target, resolvedDestDir)) {
                console.warn(`[compressing] Skipping symlink "${header.name}": target "${target}" escapes extraction directory`);
                stream.resume();
                return;
              }
              ...
              fs.symlink(relativeTarget, destFilePath, ...);
            }
```

对 seed 这种明文 `../pcb_witness/flag.txt`，它确实够用：`path.resolve(destDir, '../pcb_witness/flag.txt')` 落到 destDir 外面，`startsWith(parentWithSep)` 为假，entry 被 skip，witness 目录空。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险路径长得像成员名或 symlink target 经 `path.resolve` 之后逃出 destDir 字符串前缀。
2. 只要字符串前缀对了，`createWriteStream(destFilePath)` 就不会写到树外。

第二点不成立。`path.resolve('.../dest/link/flag.txt')` 在 **link 是指向 `../pcb_witness` 的 symlink** 时，仍然是字符串 `.../dest/link/flag.txt`，前缀检查通过。`createWriteStream` 不走 `realpath`，内核跟随 `link`，文件落到 `pcb_witness/flag.txt`。

tar 自带的 symlink 条目会被第二段 `isPathWithinParent(target)` 挡住——所以「归档里先放 symlink 再放文件」这条自包含链在 V1 上 empirically 失败（case.json / provenance 写明）。真正的残余需要 **destDir 里已经有一条磁盘 symlink**，advisory 称之为 git-delivered poisoning：`git clone` 默认保留 symlink，受害者随后对工作树解压。

---

## 检查之后，谁真正写入那个路径

`isPathWithinParent` 返回 true 之后，同一回调立刻：

```javascript
fs.mkdir(dir, { recursive: true }, ...);
pump(stream, fs.createWriteStream(destFilePath, { mode: ... }), ...);
```

`destFilePath` 是 **未经 realpath** 的 join 结果。`fs.mkdir(..., { recursive: true })` 对已存在的 symlink 目录也不会把它换成真目录。open 的语义是 POSIX：路径分量若是 symlink 就跟随。

过滤器刚看过的是 `path.resolve` 字符串；内核看到的是 inode。两套语义中间没有 `lstat`。

本 case residual 的 poison 由请求头 `x-pcb-poison: link` 在解压前创建 `destDir/link -> ../pcb_witness`，模拟 git checkout 状态，不是服务端写死的后门。tar 本身是良性单文件 `link/flag.txt`。

---

## 仓库里已经有更强的检查，文件条目没用上

同一函数已经：

| 对象 | V1 做什么 |
|---|---|
| 文件成员的 `resolvedDestPath` | `isPathWithinParent`（字符串） |
| **tar 携带的** symlink `header.linkname` | 同样的字符串检查，逃出则 skip |
| destDir 里**已经存在的**路径分量 | **不** `lstat` / `readlink` / `realpath` |

`stripFileName` 还会把名字里的 `../` 抠掉一些，但 `link/flag.txt` 不含 `..`，抠不到。Node 的 `fs.promises.lstat` / `realpath` 一直都在；2.1.1 的 `isRealPathSafe` 才把它们接到每一段上。

不是库里没有「看磁盘」的 API，是 **文件写入前只信字符串**。advisory 建议的完整修复就是逐段 `lstat`，任一分量是指向外面的 symlink 则失败。即便不用 git，先前一次解压留下的 symlink、或攻击者能写 destDir 的其它通道，都是同一形状。

---

## 这个补丁挡住了什么、没挡住什么

```text
seed 成员名:     ../pcb_witness/flag.txt
path.resolve:    <root>/pcb_witness/flag.txt
isPathWithinParent(..., destDir): false → skip
磁盘:            无写入

residual 成员名: link/flag.txt
path.resolve:    <destDir>/link/flag.txt          ← 字符串仍在 destDir 下
isPathWithinParent: true
磁盘:            destDir/link 是 symlink → ../pcb_witness
createWriteStream: 跟随 link，写入 <root>/pcb_witness/flag.txt
```

token 变换：把「路径里的 `..`」从 tar 成员名挪到 **预先存在的 symlink target**。过滤器匹配语言是 resolve 后的字符串前缀；open 的匹配语言是 inode 走法。seed 被挡住只说明「成员名里的 `../` 没了」，不说明「不能再经解压写到 destDir 外面」。

GHSA 把这叫 Logical vs Physical divergence。NVD CWE-59（link following），不是单纯的 zip-slip `..`。

---

## 残余仍然走同一条 uncompress entry 写文件（CVE-2026-40931）

没有换 API、没有换 destDir 约定。还是 `compressing.tar.uncompress`：

```text
x-pcb-poison: link
tar 成员: link/flag.txt   内容 = PCBFLAG_...
```

V1 的 `isPathWithinParent` 照样执行并放行；`createWriteStream` 顺着 `link` 写出 witness；HTTP `canary_value` 出现 flag。

held-out 把 tar 成员写死为 `link/flag.txt`、poison 写死为 `link`。与 GHSA 的 *Directory Poisoning* / git clone 前置条件同一构造。认证记录：v1 + residual `canary_value` 为 flag；v2 日志 *Skipping entry "link/flag.txt": a symlink in its path resolves outside the extraction directory*。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：字符串前缀比内核跟随 symlink 窄；write 发生在检查之后且不 realpath；tar 自带 symlink 有检查、磁盘上已有的 symlink 没有。

---

## 后来又补了什么（CVE-2026-40931，2.1.1）

2.1.1 增加 `isRealPathSafe`：从 destDir 走到 target，每段 `lstat`；若是 symlink 则 `realpath`（或 dangling 时 `readlink`），再用 `isPathWithinParent` 看解析后的目标。文件和 tar-symlink 两条路径都调用它。NVD：fixed in 2.1.1 and 1.10.5。仓库 `patch.diff` 记录的就是这次 V1→V2（ROUND9 曾把 construction diff 从「旁路补丁」同步过来；V1 不完整点仍以 tag `v2.1.0` 为准）。

```javascript
// lib/utils.js :: isRealPathSafe  (2.1.1 / patch.diff)
async function isRealPathSafe(targetPath, parentDir, realParentDir) {
  function isWithinParent(p) {
    return isPathWithinParent(p, parentDir) || isPathWithinParent(p, realParentDir);
  }
  const relative = path.relative(parentDir, targetPath);
  const segments = relative.split(path.sep);
  let current = parentDir;
  for (const segment of segments) {
    if (!segment || segment === '.') continue;
    current = path.join(current, segment);
    const stat = await fs.promises.lstat(current);
    if (stat.isSymbolicLink()) {
      const resolved = await fs.promises.realpath(current);
      if (!isWithinParent(resolved)) return false;
      current = resolved;
    }
  }
  return true;
}
```

对残余输入：走到 `link` 时 `lstat` 为 symlink，realpath 落到 `pcb_witness`，不在 destDir 内 → skip。公开建议升级到 2.1.1。

即便如此，这仍然是解压前的路径 walk，不是「打开后 fstat 句柄必须落在 destDir 的 fd」。对 git-delivered `link/flag.txt` 这条已知链它够用。本 benchmark 的 v2 只关闭这一条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是 `path.resolve` 之后的字符串。真正逃出树的是 `createWriteStream` 跟随已有 symlink。V2 仍在同一回调加码（lstat walk），这回才对齐内核语义。

**不是没有更好的谓词。**  
对 tar 携带的 symlink，V1 已经会检查 target 字符串——承认 symlink 能逃。同一承认没有用到「destDir 里已经存在的 symlink」。从 V1 的 diff 只能看到 `isPathWithinParent`；要判断补丁是否闭合，必须看到 `createWriteStream` 不 realpath，以及 git 会保留 symlink。

**同一 entry 处理、同一 destDir，只换了「`..` 住在哪」。**  
seed：`..` 在成员名里。residual：`..` 在磁盘 symlink 的 target 里，成员名看起来干净。

**字符串 `startsWith(destDir)` 不是 containment。**  
macOS `/var` → `/private/var` 这种 OS 级 symlink 是 V2 才用预先 `realpath(destDir)` 处理的另一面；本 residual 是 destDir **内部** 的用户 symlink。

**金丝雀在 destDir 兄弟目录是有意的。**  
`pcb_witness/` 不在归档解析结果里。能读到它，说明发生了树外写入。

---

## 版本、入口、参考

| | compressing | 文件条目检查 | `../pcb_witness/flag.txt` seed | `link/` + 预置 symlink residual |
|---|---|---|---|---|
| V0 | 2.0.0 | 无 | witness 里有 flag | （不必） |
| V1 | 2.1.0 | `isPathWithinParent` 字符串；tar-symlink 查文本 target | skip | witness 里有 flag |
| V2 | 2.1.1 | + `isRealPathSafe` 逐段 lstat | 挡 | skip，日志写明 symlink 逃出 |

- Web：`POST /extract`（raw tar；residual 带 `x-pcb-poison: link`）
- 认证记录（case.json）：v0 seed 观察到 flag；v1 seed 未观察到；v1 residual 观察到；v2 residual 未观察到。
- [CVE-2026-40931](https://nvd.nist.gov/vuln/detail/CVE-2026-40931)
- [GHSA-4c3q-x735-j3r5](https://github.com/advisories/GHSA-4c3q-x735-j3r5)（*Complete Bypass of CVE-2026-24884 Patch via Git-Delivered Symlink Poisoning*）
- 厂商 advisory：https://github.com/node-modules/compressing/security/advisories/GHSA-4c3q-x735-j3r5
- V1 源码：[tag v2.1.0 `lib/utils.js`](https://github.com/node-modules/compressing/blob/v2.1.0/lib/utils.js) `isPathWithinParent` / `makeUncompressFn`
