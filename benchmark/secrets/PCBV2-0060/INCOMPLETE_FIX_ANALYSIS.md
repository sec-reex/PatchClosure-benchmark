# FHIR TerminologyCache：normalize 之后仍用字符串前缀，兄弟目录算「在里面」

- Case：`PCBV2-0060`
- 产品：HL7 FHIR Core（`ca.uhn.hapi.fhir:org.hl7.fhir.r4b`，术语缓存 / 包解压）
- 链：CVE-2023-24057（5.6.90 → 5.6.92）→ CVE-2023-28465（5.6.92 → 5.6.106）
- 源码对着官方 tag `5.6.92` / `5.6.106` 的 `org.hl7.fhir.r4b.terminologies.TerminologyCacheManager`：`unzip`。运行时是 Maven Central 整包，经 HTTP `POST /unzip` 调用库自己的 `unzip`，不是抽出来的路径函数。

2023 年 1 月，GHSA-jqh6-9574-5x22 / CVE-2023-24057 指出 `Utilities.path` 只折叠**以 `../` 开头**的段，中间的 `..` 会留下；`path.startsWith(targetDir)` 因此挡不住 `child/../outside`。5.6.92 在比较前加了 `Path.normalize().toFile().getAbsolutePath()`。NVD CVE-2023-28465 写明 *NOTE: this issue exists because of an incomplete fix for CVE-2023-24057*。GHSA-9654-pr4f-gh6m 把绕过写成 *`"/usr/outnot".startsWith("/usr/out")`*——因为绝对路径字符串没有以斜杠结尾。

根因不只是「少写了一个斜杠」。检查插在「规范化后的绝对路径字符串是不是以 `targetDir` 为前缀」这一层；真正写盘的是那条路径。Java 已经有 `Path.startsWith(Path)` 按组件比较，V1 用的是 `String.startsWith`。下面按解压走进去、V1 改了哪一行、检查之后谁去 `streamToFile`、仓库里已经有什么更强的谓词、残余怎么用兄弟目录名把同一条 unzip 打出缓存根。

---

## 这块功能本来在干什么

FHIR 校验器会拉术语缓存 zip / npm 包，解到本地 `tx-cache` 目录。`TerminologyCacheManager` 打开输入流，按条目写出：

```java
unzip(new ByteArrayInputStream(res.getContent()), cacheFolder);
```

`cacheFolder` 一般是 `<base>/cache/tx-cache`。设计意图：zip 里的名字必须落在这个目录下。成功穿越之后的效果是 **条目被写到缓存根之外，内容是攻击者给的字节**。本 case 把 `${PCB_FLAG}` 只放在逃逸条目的**内容**里；文件名负责走出树。

数据流：

```text
HTTP POST /unzip  (zip 字节)
    → TerminologyCacheManager.unzip(is, targetDir)
         ze.getName()                         ← 用户控制的条目名
         Utilities.path(targetDir, name)      ← 拼接；V0 几乎不 normalize
         V1：Path.of(...).normalize()
              .toFile().getAbsolutePath()     ← 得到字符串 path
         V1：if (!path.startsWith(targetDir)) ← 字符串前缀
         TextFile.streamToFileNoClose(..., path)
    → 文件落在 targetDir 内或旁
```

没有登录。advisory 还提到缓存下载若不走 HTTPS，MITM 可以换 zip。本 case 只打上传解压这一条。

---

## 原始漏洞：中间的 `..` 过不了 Utilities.path（CVE-2023-24057，5.6.90）

5.6.90 的守卫是：

```java
String path = Utilities.path(targetDir, ze.getName());
if (!path.startsWith(targetDir)) {
    throw new RuntimeException("Entry with an illegal path: " + ze.getName());
}
```

GHSA-jqh6-9574-5x22 写明 `Utilities.path("/base", "/child/../test")` 得到 `"/base/child/../test"`——只有**段本身以遍历开头**才会被折叠。中间的 `..` 留在字符串里，而这个字符串仍以 `targetDir` 开头，于是守卫放行；内核 / `File` 再解析 `..` 时已经出树。本 case 的 seed：

```text
条目:  x/                              （先建中间目录）
       x/../../../pwned/escaped.txt    （内容 = PCB_FLAG）
```

`path` 仍以 `.../cache/tx-cache` 开头，守卫通过；解析后文件落到 `<root>/pwned/escaped.txt`。这就是 v0 + `--seed`。V1 加上 `normalize()` 之后，中间的 `..` 被收成 `<root>/cache/...`，不再以 `tx-cache` 为前缀，抛 `RuntimeException`。seed 在 V1 被挡住。

---

## 维护者改了什么（CVE-2023-24057 修复，5.6.92）

5.6.92 在 `startsWith` **之前**把拼接结果做成绝对路径并 `normalize`：

```java
// org.hl7.fhir.r4b/.../TerminologyCacheManager.java :: unzip
//   (tag 5.6.92, 约 L97–111)
  public static void unzip(InputStream is, String targetDir) throws IOException {
    try (ZipInputStream zipIn = new ZipInputStream(is)) {
      for (ZipEntry ze; (ze = zipIn.getNextEntry()) != null; ) {
        String path = Path.of(Utilities.path(targetDir, ze.getName()))
                          .normalize().toFile().getAbsolutePath();

        if (!path.startsWith(targetDir)) {
          // see: https://snyk.io/research/zip-slip-vulnerability
          throw new RuntimeException("Entry with an illegal path: " + ze.getName());
        }
        if (ze.isDirectory()) {
          Utilities.createDirectory(path);
        } else {
          Utilities.createDirectory(Utilities.getDirectoryForFile(path));
          TextFile.streamToFileNoClose(zipIn, path);
        }
      }
    }
  }
```

注释仍指向 Snyk Zip Slip。真正改的是：比较之前先把 `..` 收掉，让 seed 那种 `x/../../../pwned/...` 在字符串上就不再以 `targetDir` 开头。

对 seed：

```text
normalize 后:  <root>/pwned/escaped.txt
targetDir:     <root>/cache/tx-cache
startsWith:    false → throw
```

补丁默认了两件事：

1. 危险路径靠 `..` 组件逃出，normalize 之后前缀就会断。
2. 「规范化绝对路径字符串以 `targetDir` 开头」等于「落在目录树内」。

第二点不成立。`String.startsWith` 比较的是字符，不是路径组件。`targetDir` 由 `getAbsolutePath()` 一类 API 得到时，**通常没有尾斜杠**。于是任何「`targetDir` + 额外后缀」的兄弟路径，字符串上都算匹配。

---

## 检查之后，谁真正写那个文件

`startsWith` 一通过，同一个循环立刻 `Utilities.createDirectory` + `TextFile.streamToFileNoClose(zipIn, path)`。`path` 就是刚才那条绝对路径字符串。没有第二次 `canonicalFile.toPath().startsWith(base.toPath())`，也没有「写完再确认 realpath 前缀」。

内核按这条绝对路径创建文件。若它指向 `.../cache/tx-cache-esc/escaped.txt`，文件就出现在 `tx-cache` 的**兄弟**目录里。过滤器认为自己在看「是不是在 targetDir 下面」；`File` 实际打开的是另一棵树，只是名字共享一段字符前缀。

`unzip` 的调用方把 `cacheFolder` 传进来。本 case 里是 `<base>/cache/tx-cache`。兄弟目录 `<base>/cache/tx-cache-esc/` 不在缓存根下，也不在 zip 的「相对条目」语义里。

---

## 仓库里已经有按组件比较的 API，字符串前缀没用

V1 为了 normalize，已经 `import` / 使用了 `java.nio.file.Path`：

```java
Path.of(Utilities.path(targetDir, ze.getName())).normalize().toFile().getAbsolutePath();
```

它先得到 `Path`，立刻 `.toFile().getAbsolutePath()` 降回 `String`，再用 `String.startsWith`。`Path.startsWith(Path)` 比较的是组件：`tx-cache-esc` 不是 `tx-cache` 的子路径。GHSA-9654-pr4f-gh6m 写明：

> Comparing paths with the `java.nio.files.Path#startsWith` will adequately protect against this vulnerability.

不是仓库里没有更好的谓词，是 **刚构造出来的 `Path` 被折成字符串之后，用错了 `startsWith`**。Snyk 对 Zip Slip 的经典建议也包括「不要用字符串前缀」。V1 注释引了那篇文章，实现仍用字符串。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs 文件系统」落到具体代码：

- V1 的 `path.startsWith(targetDir)`：看绝对路径**字符串**是不是以 `targetDir` 开头
- `streamToFileNoClose(path)`：按这条路径写文件

只要构造一种输入，使 normalize 之后的绝对路径**字符串**仍以 `targetDir` 开头，但最后一个不同的组件已经在目录外，第一行会放行，第二行写到兄弟处。

GHSA 的最小例子：

```text
"/usr/outnot".startsWith("/usr/out")  → true
```

本 case 缓存根的 basename 是 `tx-cache`。残余条目：

```text
../tx-cache-esc/escaped.txt
```

`Utilities.path` 把开头的 `../` 收回到 `<base>/cache/`，再接上 `tx-cache-esc/escaped.txt`：

```text
path      = <base>/cache/tx-cache-esc/escaped.txt
targetDir = <base>/cache/tx-cache
startsWith → true   （"tx-cache-esc/..." 以 "tx-cache" 为前缀）
写出      → <base>/cache/tx-cache-esc/escaped.txt   （在 tx-cache 外面）
```

这不是 `..` 逃到任意位置——advisory 也写 *impact is limited to sibling directories*。但对「文件必须落在缓存根下」来说，兄弟目录已经是逃逸。seed 的中间 `..` 被 normalize 清掉了；残余不再需要 `..` 出现在 normalize **之后**的字符串里，只需要名字共享前缀。

字符变换：

```text
zip 名:     ../tx-cache-esc/escaped.txt
path 拼接:  Utilities.path(tx-cache, ../tx-cache-esc/escaped.txt)
normalize:  <base>/cache/tx-cache-esc/escaped.txt
守卫:       字符串前缀匹配 → 放行
```

---

## 残余仍然走同一条 unzip 写文件路径（CVE-2023-28465）

没有换函数、没有换 zip API、没有换身份。还是 `TerminologyCacheManager.unzip`。条目换成兄弟前缀：

```text
("../tx-cache-esc/escaped.txt", PCB_FLAG)
```

V1 那一行 `normalize` 照样执行；执行完之后字符串仍以 `.../tx-cache` 开头；`streamToFileNoClose` 写到 `tx-cache-esc/`。HTTP 响应里的 escaped_files 列出缓存根之外、内容含 `PCBFLAG_...` 的文件。

公开 advisory 与 Snyk SNYK-JAVA-CAUHNHAPIFHIR-3358778 同一构造。本文按 **5.6.92 源码 + GHSA** 推导；case.json 记录过外部 HTTP 上的门控，非本轮 compose。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：normalize 清掉了中间 `..`；比较仍是字符串前缀；`Path` 对象被降成 `String` 之后再也没用组件语义。seed 被挡住只说明「带 `../` 的绝对路径不再以 targetDir 开头」，不说明「不能写到名字以 targetDir 为前缀的兄弟目录」。

---

## 后来又补了什么（CVE-2023-28465，5.6.106）

5.6.106 把守卫换成 `Path.startsWith(Path)`：

```java
// tag 5.6.106, 约 L97–105
        Path path = Path.of(Utilities.path(targetDir, ze.getName())).normalize();
        String pathString = path.toFile().getAbsolutePath();
        if (!path.startsWith(Path.of(targetDir).normalize())) {
          throw new RuntimeException("Entry with an illegal path: " + ze.getName());
        }
```

写出仍用 `pathString`。比较用路径组件：`tx-cache-esc` 不是 `tx-cache` 的子路径，throw。公开建议是所有 `org.hl7.fhir.core` 升到 5.6.106。NVD 原话：*if an allowed directory name is a substring of the directory name chosen by the attacker*。

即便如此，这仍然是「在写盘之前比较路径」。对这条兄弟前缀链它够用。本 benchmark 的 v2 只关闭这一条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是比较之前要不要 `normalize`。真正逃出树的是「字符串前缀 ≠ 目录包含」。V2 仍在 `unzip` 里换比较函数，没有改成 canonical file + `Path.startsWith` 的双路径形式（advisory 给过后一种例子）。

**不是没有更好的谓词。**  
V1 已经拿到了 `Path`。`Path.startsWith(Path.of(targetDir).normalize())` 就是 V2 那一行。从 V1 的 diff 只能看到加了 `normalize`；要判断补丁是否闭合，必须看到随后仍是 `String.startsWith`，以及 `getAbsolutePath()` 不带尾斜杠。

**同一函数、同一 `ze.getName()`，只换了条目写法。**  
任何走到 `TerminologyCacheManager.unzip` 的缓存初始化 / 包解压，在 5.6.92 上都吃这一行字符串前缀。r5 模块有一份平行实现，advisory 写明两份都脆弱。

**前缀匹配和路径包含不是同一种语言。**  
`"/usr/outnot".startsWith("/usr/out")` 对字符串为真，对目录为假。Zip Slip 文献反复写过这件事；V1 注释引用了文献，比较仍用字符串。

**金丝雀在树外是有意的。**  
`tx-cache-esc/escaped.txt` 不在 extraction root。能读到 flag 内容，说明 `streamToFileNoClose` 打开的不是缓存目录里的文件。

---

## 版本、入口、参考

| | tag | `unzip` 守卫 | 中间 `../` seed | 兄弟前缀 residual |
|---|---|---|---|---|
| V0 | 5.6.90 | `Utilities.path` + `String.startsWith`，无 normalize | 写到树外 | （不必） |
| V1 | 5.6.92 | normalize 后仍 `String.startsWith(targetDir)` | throw | 写到 `tx-cache-esc/` |
| V2 | 5.6.106 | `Path.startsWith(Path.of(targetDir).normalize())` | 挡 | 组件不匹配，挡 |

- Web：`POST /unzip`
- 源码：GitHub `hapifhir/org.hl7.fhir.core` tag `5.6.92` 的 `org.hl7.fhir.r4b/.../TerminologyCacheManager.java`（`unzip` L97–111）
- [CVE-2023-24057](https://nvd.nist.gov/vuln/detail/CVE-2023-24057)、[CVE-2023-28465](https://nvd.nist.gov/vuln/detail/CVE-2023-28465)
- [GHSA-jqh6-9574-5x22](https://github.com/hapifhir/org.hl7.fhir.core/security/advisories/GHSA-jqh6-9574-5x22)
- [GHSA-9654-pr4f-gh6m](https://github.com/hapifhir/org.hl7.fhir.core/security/advisories/GHSA-9654-pr4f-gh6m)
- [Snyk SNYK-JAVA-CAUHNHAPIFHIR-3358778](https://security.snyk.io/vuln/SNYK-JAVA-CAUHNHAPIFHIR-3358778)
- advisory 点名的 V1 片段：[`TerminologyCacheManager.java#L99-L105`](https://github.com/hapifhir/org.hl7.fhir.core/blob/b0daf666725fa14476d147522155af1e81922aac/org.hl7.fhir.r4b/src/main/java/org/hl7/fhir/r4b/terminologies/TerminologyCacheManager.java#L99-L105)
