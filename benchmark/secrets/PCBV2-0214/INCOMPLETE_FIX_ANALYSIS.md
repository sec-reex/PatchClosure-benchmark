# XWiki：normalize 拒绝 `../`，前导 `/` 让 Paths 先缩到根再放行

- Case：`PCBV2-0214`
- 产品：XWiki Platform（Java wiki，Tomcat）。运行时是官方镜像 `xwiki:16.10.6` / `16.10.16` / `16.10.17` + MariaDB，走产品自己的未认证 `GET /bin/ssx/Main/WebHome?resource=`，不是抽出来的函数。
- 链：CVE-2025-55748（16.10.6 → 16.10.7，GHSA-m63c-3rmg-r2cf，commit `9e7b4c0`）→ CVE-2026-23734（GHSA-xq3r-2qv5-vqqm 列所有 &lt; 16.10.17，含 16.10.16；commit `a979caf` / XCOMMONS-3547）
- 源码对着 tag `xwiki-commons-16.10.16` 的 `ClassLoaderUtils.java` 和 `xwiki-platform-16.10.16` 的 `SxResourceSource.java`。金丝雀是 benign：`ROOT/WEB-INF/pcb_flag.txt`，在 classloader 根 `WEB-INF/classes/` 的上一层，只有穿越成功才进 ssx 响应。

GHSA-xq3r-2qv5-vqqm：*`resource=/../../WEB-INF/xwiki.cfg`*。NVD CVE-2026-23734：*The vulnerability can be exploited via resources parameter the ssx and jsx endpoints by using leading slashes.* 这是同一 sink 上对 55748 谓词的再打。

根因不只是「忘了前导斜杠」。检查插在「`Paths.get(原串).normalize()` 是否 `startsWith("../")`」上；真正 `getResourceAsStream` 的是**未经 normalize 的原串**，而 Tomcat 的 classloader 对前导 `/` 的语义和 `java.nio.file.Paths` 不是一套。下面按请求走进去。

---

## 这块功能本来在干什么

ssx / jsx 把皮肤扩展（CSS / JS）从 classpath 或文档对象拉出来，给浏览器当静态资源。`resource` 查询参数指名 classpath 上的文件。一次典型合法请求：

```http
GET /bin/ssx/Main/WebHome?resource=path/to/hello.js&minify=false
```

未认证即可。`SxResourceSource` 拿这个字符串，经 `ClassLoaderUtils.getResourceAsStream` 打开，内容进 HTTP body。设计意图：只能读 classloader 根（Tomcat 上是 `ROOT/WEB-INF/classes/`）之下的资源，不能爬到 `WEB-INF/xwiki.cfg`、`hibernate.cfg.xml`。成功穿越之后的效果是：**ssx 响应体里出现 `WEB-INF/pcb_flag.txt` 的金丝雀**（和 advisory 读 `xwiki.cfg` 同一扇门）。

数据流：

```text
GET /bin/ssx/Main/WebHome?resource=<name>&minify=false
    → Sx 动作（未认证）
    → new SxResourceSource(resourceName)
    → getContent()
         ClassLoaderUtils.getResourceAsStream(cl, resourceName)
              resolveResourceName(null, resourceName)     ← V1 谓词
                   Paths.get(fullPath).normalize()
                   startsWith("../") ? throw : return 原串
         classloader.getResourceAsStream(原串)            ← Tomcat 自己解析
    → IOUtils.toString → HTTP body
```

没有登录、没有「读 WEB-INF」权限位。`minify=false` 只影响是否压缩，不改变打开哪份资源。jsx 是同一套 `resource` 参数。

---

## 原始漏洞：resource 直接进 classloader（CVE-2025-55748，16.10.6）

16.10.6 的 `SxResourceSource.getContent` 把查询参数原样交给 context classloader：

```java
// SxResourceSource.java  (修复前，GHSA-m63c-3rmg-r2cf / commit 9e7b4c0 所改)
ClassLoader contextClassLoader = Thread.currentThread().getContextClassLoader();
try (InputStream in = contextClassLoader.getResourceAsStream(this.resourceName)) {
    return IOUtils.toString(in, StandardCharsets.UTF_8);
}
```

Tomcat 上 classloader 根是 `WEB-INF/classes/`。`resource=../../WEB-INF/pcb_flag.txt` 向上两层到 `ROOT/`，再进 `WEB-INF/pcb_flag.txt`。advisory 给的例子是 `../../WEB-INF/xwiki.cfg`。无认证。

本 case seed 就是这条明文相对穿越。v0（16.10.6）ssx body 里出现金丝雀。

---

## 维护者改了什么（CVE-2025-55748 修复，16.10.7 起，16.10.16 仍是这套谓词）

`9e7b4c0` 把打开改成 `ClassLoaderUtils.getResourceAsStream`。16.10.16 上 `resolveResourceName` 在 **prefix 为空**（ssx 这条路）时：

```java
// ClassLoaderUtils.java :: resolveResourceName  (xwiki-commons-16.10.16)
private static String resolveResourceName(String prefixPath, String resourcePath) {
    String fullPath;
    if (StringUtils.isEmpty(prefixPath)) {
        fullPath = resourcePath;

        Path normalizedResource = Paths.get(fullPath).normalize();
        if (normalizedResource.startsWith("../")) {
            throw new IllegalArgumentException(String.format(
                "The provided resource name [%s] is trying to navigate out of the mandatory root location",
                resourcePath));
        }
    } else {
        ...
    }

    // We cannot sent back the normalized version as it might produce a result
    // which is not compatible with the ClassLoader (for example, on Windows
    // Path#normalize() is replacing all "/" by "\", which is not a path
    // separator in ClassLoader)

    return fullPath;   // 原串，不是 normalizedResource
}
```

`SxResourceSource.getContent`（16.10.16）：

```java
try (InputStream in = ClassLoaderUtils.getResourceAsStream(contextClassLoader, this.resourceName)) {
    return IOUtils.toString(in, StandardCharsets.UTF_8);
}
```

`getResourceAsStream(cl, name)` 内部是 `cl.getResourceAsStream(resolveResourceName(null, name))`。检查用 normalize 后的 `Path`；打开用返回的原串。

补丁默认了两件事：

1. 危险名字 normalize 之后会以 `../` 开头。
2. 原串交给 Tomcat classloader 时，语义和 `Paths.normalize()` 一致。

第二点不成立。`Paths.get("/../../WEB-INF/pcb_flag.txt").normalize()` 把路径当成**文件系统绝对路径**，`..` 在 `/` 上消掉，得到 `/WEB-INF/pcb_flag.txt`，**不以 `../` 开头**。Tomcat 的 `getResourceAsStream` 则忽略前导 `/`，仍按 `../../WEB-INF/pcb_flag.txt` 相对 `WEB-INF/classes/` 解析。

注释已经写了不能返回 normalize 结果（Windows 反斜杠）。16.10.7 一度返回过 normalize 后的路径，前导斜杠变体碰巧被挡住；后来 XCOMMONS-3332 为了 Windows classpath 改回返回原串，16.10.8–16.10.16 整段再次受影响。GHSA 因此把 16.10.16 列进 affected。本 case V1 钉最新受影响发行版 16.10.16。

对 seed 这种明文 `../../WEB-INF/pcb_flag.txt`：

```text
Paths.get("../../WEB-INF/pcb_flag.txt").normalize()
    → ../../WEB-INF/pcb_flag.txt
    → startsWith("../") == true → IllegalArgumentException → ssx 404
```

这就是 v1 + `--seed` 退出码 10。

---

## 检查之后谁真正打开那份资源

`startsWith("../")` 为假之后，函数返回 `fullPath`（查询参数原样，含前导 `/`）。`ClassLoader.getResourceAsStream` 收到的就是它。过滤器刚看过的是 NIO `Path` 的 normalize；open 看到的是 servlet classloader 的资源名。中间没有「去掉所有前导 `/` 再 normalize 一次」，也没有「打开后的 URL 必须仍在 classes/ 下」。

`SxResourceSource` 把流读成字符串，ssx 动作写进响应。金丝雀在 `WEB-INF/` 而不在 `classes/` 里，能出现在 body 里，依据就是 classloader 跟着原串上的 `../` 爬出了根。

prefix 非空的另一分支用 `normalizedResource.startsWith(prefixPath)`，ssx 的 `resource` 走的是 prefix 为空的分支，用的是更弱的 `startsWith("../")`。

---

## 仓库里已经有更强的检查，打开没用

同一函数里已经有一份 `normalizedResource`。谁用它：

| 步骤 | 用 normalize 后的路径？ |
|---|---|
| `startsWith("../")` 拒绝 | 是，只当谓词输入 |
| `return` 给 classloader | **否**，返回原串 `fullPath` |
| 先剥前导 `/` 再 normalize（V2） | **否**，16.10.16 没有 |
| 16.10.7 返回 normalize 结果 | 后来为了 Windows 撤回 |

不是仓库里算不出「这是不是在往上爬」，是 **打开没用计算结果**。注释把「不能复用 normalize 结果」写成了设计约束，于是检查和 open 永远是两套字符串。更强的谓词——剥掉 Tomcat 会忽略的前导 `/` 再跑同一条 `startsWith("../")`——要到 XCOMMONS-3547 才挂上。

即便前导 `/` 没把 `Paths` 打穿，只要继续把原串交给 classloader，任何「normalize 后看起来安全、Tomcat 仍当相对穿越」的写法都会变成一次真实读。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「NIO normalize」和「Tomcat classloader」落到具体输入：

- V1 过滤器：`Paths.get(s).normalize().startsWith("../")`
- `getResourceAsStream(s)`：Tomcat 忽略前导 `/`，按相对 `WEB-INF/classes/` 解析 `../`

只要构造一种输入，使 NIO 把它当成绝对路径缩到根下、而 classloader 仍当相对穿越，第一道门放行，第二道门爬出 classes/。

```text
seed:
  resource=../../WEB-INF/pcb_flag.txt
  → normalize 仍以 ../ 开头 → throw → 404

residual:
  resource=/../../WEB-INF/pcb_flag.txt
  → Paths 当成绝对路径
  → normalize → /WEB-INF/pcb_flag.txt
  → startsWith("../") == false
  → return 原串 "/../../WEB-INF/pcb_flag.txt"
  → Tomcat 忽略开头的 /
  → 相对 classes/ 的 ../../WEB-INF/pcb_flag.txt
  → ROOT/WEB-INF/pcb_flag.txt → body 含 flag
```

GHSA-xq3r-2qv5-vqqm 给的 URL 就是 `/bin/ssx/Main/WebHome?resource=/../../WEB-INF/xwiki.cfg&minify=false`。本 case 把目标换成金丝雀文件，观察的是同一扇 classloader 门。

---

## 残余仍然走同一条 ssx resource 读路径（CVE-2026-23734）

没有换动作、没有换认证、没有换观察通道。还是未认证的 ssx：

```http
GET /bin/ssx/Main/WebHome?resource=/../../WEB-INF/pcb_flag.txt&minify=false
```

`SxResourceSource` 仍然调用同一个 `ClassLoaderUtils.getResourceAsStream`。V1 那行 `startsWith("../")` 照样执行；对前导斜杠它为假；返回的原串照样进 Tomcat classloader；body 里出现金丝雀。jsx 同一参数同一工具类。

本 case residual 和 advisory PoC 同一构造，只是把 `xwiki.cfg` 换成 `pcb_flag.txt`。认证意图：v1 + `--residual` 观察到 `PCBFLAG_...`。

seed 被挡住只说明「明文相对 `../` 不再打开」，不说明「不能再从 ssx 读出 classes/ 之外的 WEB-INF 文件」。

平台 residual 走的就是这条 ssx `resource` → classloader sink，和源码链同一 sink。不是另一条无关的皮肤文件读取。

---

## 后来又补了什么（CVE-2026-23734，16.10.17）

commit `a979caf`（*XWIKI-23898: Improve classpath resolution for Tomcat*）在 prefix 为空时，**先剥光前导 `/`，再 normalize**：

```java
// ClassLoaderUtils.java  (xwiki-commons 16.10.17 / a979caf)
// On Tomcat, all leading / have no effect, contrary to Paths#normalize()
int index = 0;
while (index < fullPath.length() && fullPath.charAt(index) == '/') {
    ++index;
}
String normalizedPath = fullPath.substring(index);
Path normalizedResource = Paths.get(normalizedPath).normalize();
if (normalizedResource.startsWith("../")) {
    throw new IllegalArgumentException(...);
}
```

对残余输入：`/../../WEB-INF/pcb_flag.txt` 变成 `../../WEB-INF/pcb_flag.txt`，normalize 后以 `../` 开头，抛错，ssx 404。明文相对穿越仍然被挡。公开建议升级到 16.10.17 / 17.4.9 / 17.10.3 / 18.1.0-rc-1。

即便如此，这仍然是「在 open 之前按 Tomcat 规则改写字符串」，没有改成返回 normalize 结果或 `O_NOFOLLOW` 式的打开。对本条前导斜杠链够用。本 benchmark 的 v2 只关闭这一条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是 NIO `Path.normalize()` 的谓词。真正爬出 classes/ 的是 servlet classloader 对原串的解析。V2 仍在同一函数加码，但终于按 Tomcat「前导 `/` 无效」先改写再检查。

**不是没有更好的谓词。**  
`normalizedResource` 已经算出来。16.10.7 还用它当返回值，碰巧挡住了本条残余。从 V1 的 diff 只能看到「加了 startsWith("../")」；要判断是否闭合，必须看到 `return fullPath` 和 Tomcat 对 `/../` 的语义差。

**同一 `resolveResourceName`、同一 `getResourceAsStream`，只换了前导 `/`。**  
advisory 原话就是 leading slashes。明文 `../` 被挡住，不等于 classloader 不再跟随 `../`。

**检查语言和打开语言不是一层。**  
`Paths` 把前导 `/` 当绝对路径根。Tomcat 把它当可忽略前缀。只消毒一种语言，门是开的。

**金丝雀在 classes/ 之上是有意的。**  
合法皮肤名到不了 `WEB-INF/pcb_flag.txt`。能在 ssx body 里读到它，说明 classloader 打开的是树外资源——也就是 `startsWith("../")` 放行了那次原串。

---

## 版本、入口、参考

| | 版本 | `resolveResourceName` | 明文 `../` seed | `/../` residual |
|---|---|---|---|---|
| V0 | 16.10.6 | 无，直接 `getResourceAsStream` | 读到金丝雀 | （不必） |
| 55748 修复当日 | 16.10.7 | normalize + 曾返回 normalize 结果 | 挡 | 碰巧挡 |
| V1 | 16.10.16 | normalize + **返回原串** | 挡 | Tomcat 跟随，flag |
| V2 | 16.10.17 | 先剥 `/` 再 normalize | 挡 | `../` 被看见，挡 |

- Web：`GET /bin/ssx/Main/WebHome?resource=…&minify=false`（jsx 同参）
- [CVE-2025-55748](https://nvd.nist.gov/vuln/detail/CVE-2025-55748)、[CVE-2026-23734](https://nvd.nist.gov/vuln/detail/CVE-2026-23734)
- [GHSA-m63c-3rmg-r2cf](https://github.com/xwiki/xwiki-platform/security/advisories/GHSA-m63c-3rmg-r2cf)、[GHSA-xq3r-2qv5-vqqm](https://github.com/xwiki/xwiki-commons/security/advisories/GHSA-xq3r-2qv5-vqqm)
- V1 引入：platform commit [`9e7b4c0`](https://github.com/xwiki/xwiki-platform/commit/9e7b4c03f2143978d891109a17159f73d4cdd318)；V2 commons commit [`a979caf`](https://github.com/xwiki/xwiki-commons/commit/a979cafd89f6a9c9c0b9ab19744d672df64429bf)
- 源码：[`xwiki-commons-16.10.16` `ClassLoaderUtils.java`](https://github.com/xwiki/xwiki-commons/blob/xwiki-commons-16.10.16/xwiki-commons-core/xwiki-commons-classloader/xwiki-commons-classloader-api/src/main/java/org/xwiki/classloader/internal/ClassLoaderUtils.java)、[`xwiki-platform-16.10.16` `SxResourceSource.java`](https://github.com/xwiki/xwiki-platform/blob/xwiki-platform-16.10.16/xwiki-platform-core/xwiki-platform-skin/xwiki-platform-skin-skinx/src/main/java/com/xpn/xwiki/web/sx/SxResourceSource.java)
