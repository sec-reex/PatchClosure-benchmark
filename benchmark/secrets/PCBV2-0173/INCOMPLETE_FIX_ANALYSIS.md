# spring-integration-zip：FILE 分支拦了 `..`，BYTE_ARRAY 把穿越名交还给调用方

- Case：`PCBV2-0173`
- 产品：Pivotal / Spring `spring-integration-zip`（Maven `org.springframework.integration:spring-integration-zip`）。运行时是 Maven Central 整包 `1.0.0.RELEASE` / `1.0.1.RELEASE` / `1.0.2.RELEASE`，薄 HTTP 入口只把上传的 zip 交给未改过的 `UnZipTransformer.transform()`。
- 链：CVE-2018-1261（1.0.0 → 1.0.1，commit `a5573eb`）→ CVE-2018-1263（1.0.1 → 1.0.2，commit `d10f537`）
- 源码对着 commit `a5573eb`（1.0.1.RELEASE 修复落点）的 `spring-integration-zip/src/main/java/org/springframework/integration/zip/transformer/UnZipTransformer.java`。金丝雀是 benign：zip 条目内容是 `PCBFLAG_...`，写到 `/work/dest` 之外的 `/work/out/flag`。

Spring 对 CVE-2018-1263 的原话：*The previous CVE-2018-1261 prevented the framework itself from writing the file. While the framework itself now does not write such files, it does present the errant path to the user application, which could inadvertently write the file using that path.* NVD 写 *Addresses partial fix in CVE-2018-1261*。

根因不只是「漏了一个 mode」。检查插在「框架自己 `copy` 到磁盘之前」；真正还能逃出目录的是后面 `uncompressedData.put(zipEntryName, data)` 交出去的那个名字。同一次 `ZipUtil.iterate` 里 FILE 和 BYTE_ARRAY 是并列分支，谓词只挂在前一个。下面按调用走进去。

---

## 这块功能本来在干什么

`UnZipTransformer` 把消息 payload（`File` / `byte[]` / `InputStream`）解成两种结果：`ZipResultType.FILE`（框架按条目名写到 `workDirectory/<messageId>/`）或 `ZipResultType.BYTE_ARRAY`（框架只返回 `name → bytes` 的 `SortedMap`，由调用方决定怎么落盘）。一次典型的 FILE 解压：

```java
UnZipTransformer t = new UnZipTransformer();
t.setWorkDirectory(new File("/work/dest"));
t.setZipResultType(ZipResultType.FILE);
Object out = t.transform(messageWithZipBytes);
```

本 case 的 HTTP 面：

```http
POST /unzip?mode=file     → ZipResultType.FILE
POST /unzip?mode=bytes    → ZipResultType.BYTE_ARRAY
```

设计意图：无论哪种结果类型，条目名不得爬出 `workDirectory`。成功穿越之后的效果是：**`../../out/flag` 被写成 `/work/out/flag`**，响应 `witness` 里出现金丝雀。

数据流：

```text
POST /unzip?mode=file|bytes   body=zip
    → UnZipTransformer.doZipTransform
         ZipUtil.iterate(entry)
              zipEntryName = zipEntry.getName()          ← 用户字符串
              FILE:
                   dest = new File(tempDir, zipEntryName)
                   if (name.contains("..") && !canonical.startsWith(workDir)) throw
                   SpringZipUtils.copy(..., dest)        ← 框架写盘
              BYTE_ARRAY:
                   data = IOUtils.toByteArray(...)
                   uncompressedData.put(zipEntryName, data)  ← V1 无检查
         return Map
    → 调用方若按 key 拼 File，写出 /work/out/flag
```

不需要登录。zip 由外部 POST 上传。`workDirectory` 是 `/work/dest`；逃逸见证是兄弟目录 `/work/out/flag`。

---

## 原始漏洞：条目名直接拼进 new File（CVE-2018-1261，1.0.0）

1.0.0 的 FILE 分支在 `new File(tempDir, zipEntryName)` 之后**没有** canonical 检查，直接 `SpringZipUtils.copy`。NVD / spring.io CVE-2018-1261：特制 zip（以及 bzip2/tar/xz/war/cpio/7z）里的穿越文件名拼到解压目录后落到目标文件夹外。修复版本是 1.0.1.RELEASE。Snyk Zip-Slip 表把这次记成 2018-05-03 的 `a5573eb`。

本 case seed 用单条普通文件：

```text
entry name:  ../../out/flag
content:     ${PCB_FLAG}
workDir:     /work/dest
tempDir:     /work/dest/<message-uuid>
destination: /work/dest/<uuid>/../../out/flag  →  /work/out/flag
```

V0 的 FILE 分支照写。服务读见证文件，JSON `witness` 里出现 token。这就是 v0 + `--seed` 观察到 flag。`mode=file` 对应「框架自己写盘」——正是 1261 补丁要挡的那条路。

BYTE_ARRAY 在 V0 同样不检查；seed 选 FILE，是因为那是 1261 明确加了谓词的分支。

---

## 维护者改了什么（CVE-2018-1261 修复，1.0.1）

commit `a5573eb`（*Disallow traversal entity in zip*）只在 FILE 分支、`copy` 之前插入：

```java
// UnZipTransformer.java :: process  (1.0.1.RELEASE / a5573eb)
if (ZipResultType.FILE.equals(zipResultType)) {
    final File tempDir = new File(workDirectory, message.getHeaders().getId().toString());
    tempDir.mkdirs();
    final File destinationFile = new File(tempDir, zipEntryName);

    /* If we see the relative traversal string of ".." we need to make sure
     * that the outputdir + name doesn't leave the outputdir.
     */
    if (zipEntryName.contains("..") &&
            !destinationFile.getCanonicalPath().startsWith(workDirectory.getCanonicalPath())) {
        throw new ZipException("The file " + zipEntryName +
                " is trying to leave the target output directory of " + workDirectory);
    }

    if (zipEntry.isDirectory()) {
        destinationFile.mkdirs();
    } else {
        SpringZipUtils.copy(zipEntryInputStream, destinationFile);
        uncompressedData.put(zipEntryName, destinationFile);
    }
}
else if (ZipResultType.BYTE_ARRAY.equals(zipResultType)) {
    if (!zipEntry.isDirectory()) {
        byte[] data = IOUtils.toByteArray(zipEntryInputStream);
        uncompressedData.put(zipEntryName, data);
    }
}
```

V1 谓词的字面意思：

| 片段 | 含义 |
|---|---|
| `zipEntryName.contains("..")` | 名字里没有 `..` 则整段跳过 |
| `destinationFile.getCanonicalPath().startsWith(workDirectory.getCanonicalPath())` | 规范化后必须落在 workDir 下 |
| 只在 `ZipResultType.FILE` | BYTE_ARRAY 不进入 |

对 seed 这种明文 `../../out/flag` + `mode=file`，`contains("..")` 为真，canonical 是 `/work/out/flag`，不以 `/work/dest` 开头，抛 ZipException。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险路径只在「框架自己 `copy`」时发生。
2. 把穿越名当作 Map 的 key 交还给应用是安全的。

第二点不成立。应用侧常见写法是 `new File(someRoot, mapKey)`，key 仍是 `../../out/flag`。

---

## 检查之后，谁真正写盘

FILE 分支里，检查通过（或根本不触发）之后，`SpringZipUtils.copy` 用已经算好的 `destinationFile` 写盘。BYTE_ARRAY 分支**没有** `destinationFile`，也就没有那次 canonical 比较；它只做：

```java
byte[] data = IOUtils.toByteArray(zipEntryInputStream);
uncompressedData.put(zipEntryName, data);
```

`doZipTransform` 最后把整张 `SortedMap` 当作 payload 返回。过滤器刚看过的是「FILE 分支会不会 `copy` 到树外」；调用方看到的是**未经检查的条目名**。两套语义中间没有第二次谓词。

本 case 的 HTTP 服务在 `mode=bytes` 时按 Spring 公告描述的「user application」来消费：用返回的 key 拼到消费根上写出。`new File("/work/dest/consume", "../../out/flag")` 仍然落到 `/work/out/flag`。金丝雀出现在 `witness` 里，依据就是这一步，而不是 FILE 分支又写了一次。

chybeta 2018-05 的分析写过同一观察：1.0.1 在 copy 前查了 `zipEntryName`，但 BYTE_ARRAY 仍把错误路径交给应用；1.0.2 才把检查提成 `checkPath` 并在两支都调用。

---

## 仓库里已经有更强的检查，另一支没用

V1 已经写出了「canonical 必须落在 workDir 下」这个更接近路径安全的谓词，只是：

| 位置 | 用了 canonical 谓词？ |
|---|---|
| FILE + `contains("..")` | 是 |
| FILE、名字里没有 `..` | **否**（前置条件把检查跳过） |
| BYTE_ARRAY | **否** |

`contains("..")` 本身比「永远比 canonical」弱：不带两点、却仍能规范化到树外的名字（若存在）不会进比较。V2 去掉了这个前置条件。不是仓库里没有更好的谓词，是 **BYTE_ARRAY 没用，FILE 还加了不必要的短路**。

即便应用自己再做一次 `contains("..")`，只要它信任框架返回的 key，1.0.1 等于把 1261 的问题从「框架写盘」挪到「框架交名」。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs 写盘」落到具体代码：

- FILE：`contains("..") && !canonical.startsWith(workDir)` → 框架拒绝 `copy`
- BYTE_ARRAY：无谓词 → `put(zipEntryName, bytes)` → 调用方按 key 写

只要走 BYTE_ARRAY，同一条 `../../out/flag` 不再经过那次 canonical 比较。Spring 公告把这称为 *present the errant path to the user application*。

```text
同一 zip 条目:  ../../out/flag  内容=PCBFLAG_...

mode=file  (seed):
  V1 FILE 谓词 → ZipException
  /work/out/flag 不出现

mode=bytes (residual):
  V1 BYTE_ARRAY 无谓词
  返回 key "../../out/flag"
  调用方 new File(consumeRoot, key) → /work/out/flag
```

这正是 1.0.0 上 seed 用过的那种逃逸路径。过滤器认为自己已经把框架写盘清干净了，实际上它刚把穿越名从另一扇门递了出去。

---

## 残余仍然走同一个 UnZipTransformer（CVE-2018-1263）

没有换库、没有换条目名、没有换见证文件。还是：

```http
POST /unzip?mode=bytes
```

`doZipTransform` 仍然 `ZipUtil.iterate` 同一条 `../../out/flag`。V1 的 FILE 谓词不在这条分支上；Map 的 key 仍是穿越名；消费端写出 `/work/out/flag`。

平台 residual 与不完整修复链是**同一 sink**（`UnZipTransformer.doZipTransform`），只是 `ZipResultType` 从 FILE 换成 BYTE_ARRAY——这正是 Spring 自己定义的 1261→1263 关系，不是另开的解压器或另开的路径 API。

所以残余不是新洞面，而是同一 transformer 上三件事叠在一起：谓词只挂在框架写盘分支；名字在检查之后（对 BYTE_ARRAY 是「没有检查」）被交给调用方；已经写好的 canonical 比较没有提升成两支共用的 `checkPath`。seed 被挡住只说明「FILE 不再自己写出树外文件」，不说明「不能再从解压结果里拿到树外路径」。

---

## 后来又补了什么（CVE-2018-1263，1.0.2）

commit `d10f537`（*Dissallow traversal entry even for byte[]*）把检查提成 `checkPath`，FILE 和 BYTE_ARRAY 都调用，并去掉 `contains("..")` 前置：

```java
// 1.0.2.RELEASE（patch.diff / 后来 master 上的形状）
if (ZipResultType.FILE.equals(zipResultType)) {
    final File destinationFile = checkPath(message, zipEntryName);
    ...
} else if (ZipResultType.BYTE_ARRAY.equals(zipResultType)) {
    if (!zipEntry.isDirectory()) {
        checkPath(message, zipEntryName);
        byte[] data = IOUtils.toByteArray(zipEntryInputStream);
        uncompressedData.put(zipEntryName, data);
    }
}
```

`checkPath` 对 `new File(tempDir, zipEntryName)` 做 canonical，不以 workDir 开头就抛同一句 ZipException。对残余输入：`mode=bytes` 在 `put` 之前抛，Map 里不会出现穿越 key，调用方无从写盘。公开建议是升级到 1.0.2.RELEASE。

即便如此，这仍然是「在返回/写盘之前比 canonical 前缀」。workDirectory 若配得过宽（例如某个家目录），目录内仍可能被任意写——这是配置面，不是本 residual。本 benchmark 的 v2 关闭的是 reference residual 这条 BYTE_ARRAY 交名。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是「框架会不会 `copy` 到树外」。真正还能逃逸的是返回值里的条目名。V2 才承认名字本身是危险值，必须在两支都验证。

**不是没有更好的谓词。**  
FILE 分支已经写出了 canonical `startsWith`。BYTE_ARRAY 就在下面几行。从 V1 的 diff 只能看到 FILE 多了一段 if；要判断补丁是否闭合，必须看到 `uncompressedData.put(zipEntryName, data)` 以及调用方如何消费 key。

**同一 `zipEntryName`，只换了结果类型。**  
任何把 `UnZipTransformer` 设成 `BYTE_ARRAY` 的集成流，在 1.0.1 上都吃未检查的 key。公告写明 preconditions：*using the unzip transformer and unpacking zip files from untrusted sources*。

**`contains("..")` 是多余的短路。**  
V2 删掉它，说明维护者后来也认为「先看子串再比路径」不够。

**金丝雀在 workDir 外是有意的。**  
`/work/out/flag` 不是解压根下的普通条目。能读到它，说明写落到了 containment 之外。

---

## 版本、入口、参考

| | 版本 | FILE 分支 | BYTE_ARRAY 分支 | `mode=file` seed | `mode=bytes` residual |
|---|---|---|---|---|---|
| V0 | 1.0.0.RELEASE | 无检查，框架 `copy` | 无检查，交名 | 写到 `/work/out/flag` | （不必） |
| V1 | 1.0.1.RELEASE | `contains("..")` + canonical | 仍无检查 | ZipException | 交名，调用方写到见证 |
| V2 | 1.0.2.RELEASE | `checkPath`（无 `contains` 前置） | 同样 `checkPath` | 挡 | 挡 |

- 库 API：`UnZipTransformer.transform()` / `doZipTransform`（本 case HTTP：`POST /unzip?mode=file|bytes`）
- 观察：响应 JSON `witness` 中的 `PCBFLAG_...`（`/work/out/flag`）
- [CVE-2018-1261](https://nvd.nist.gov/vuln/detail/CVE-2018-1261)、[CVE-2018-1263](https://nvd.nist.gov/vuln/detail/CVE-2018-1263)
- [spring.io CVE-2018-1261](https://spring.io/security/cve-2018-1261)、[spring.io CVE-2018-1263](https://spring.io/security/cve-2018-1263)
- [chybeta 分析](http://chybeta.github.io/2018/05/14/Unsafe-Unzip-with-spring-integration-zip-%E5%88%86%E6%9E%90-%E3%80%90CVE-2018-1261-%E4%B8%8E-CVE-2018-1263%E3%80%91/)
- V1 blob：commit [`a5573eb`](https://github.com/spring-projects/spring-integration-extensions/commit/a5573eb232ff85199ff9bb28993df715d9a19a25) `UnZipTransformer.java`
- V2 commit：[`d10f537`](https://github.com/spring-projects/spring-integration-extensions/commit/d10f537283d90eabd28af57ac97f860a3913bf9b)
