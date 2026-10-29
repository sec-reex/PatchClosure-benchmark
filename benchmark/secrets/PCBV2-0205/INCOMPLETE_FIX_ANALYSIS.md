# Tomcat FileStore：canonical 路径用字符串前缀比较，兄弟目录仍被当成「在仓库里」

- Case：`PCBV2-0205`
- 产品：Apache Tomcat（官方镜像 `tomcat:9.0.35-jdk8-openjdk`）。运行时是整进程 Servlet 容器 + `PersistentManager`/`FileStore`；不是抽出来的 `startsWith`。
- 链：CVE-2020-9484（9.0.34 → 9.0.35，commit `3aa8f28d`）→ CVE-2021-25329（9.0.35 → 9.0.43，commit `4785433a`）
- 源码对着 tag `9.0.35` 的 `org.apache.catalina.session.FileStore.file(String id)`。金丝雀是 benign：反序列化 gadget 的 `readObject` 把 `PCB_FLAG` 写到 `/tmp/pcb_marker.txt`，`/marker.jsp` 读出来。

Tomcat 9 安全页对 CVE-2021-25329 的标题就是 *Fix for CVE-2020-9484 was incomplete*。原文：*When using a highly unlikely configuration edge case, the Tomcat instance was still vulnerable to CVE-2020-9484.* 根因不只是「还漏了一种 `../`」。检查插在 canonical 路径的**字符串前缀**上；真正 `ObjectInputStream` 的是检查通过之后的那个 `File`。下面按 Cookie 走进去。

---

## 这块功能本来在干什么

`PersistentManager` + `FileStore` 把空闲会话序列化到目录里，文件名是 `<sessionId>.session`。下次请求带上 `JSESSIONID` 时，管理器按这个 id 找文件、反序列化成 `StandardSession`。设计意图：id 可以是客户端送来的，但文件必须落在配置的 store 目录内。

本 case 的 `context.xml`：

```xml
<Manager className="org.apache.catalina.session.PersistentManager" maxIdleBackup="1">
    <Store className="org.apache.catalina.session.FileStore"
           directory="/usr/local/tomcat/sessions"/>
</Manager>
```

一次典型请求：

```http
GET / HTTP/1.1
Cookie: JSESSIONID=../../../../tmp/payload
```

数据流：

```text
Cookie JSESSIONID
    → CoyoteAdapter / StandardSession
         id = cookie 值（可含 / 和 ..）
    → PersistentManager 在内存未命中时 Store.load(id)
         FileStore.file(id)
              filename = id + ".session"
              file = new File(storageDir, filename)
              V1：file.getCanonicalPath().startsWith(storageDir.getCanonicalPath())
              通过则 return file
         FileInputStream(file) + ObjectInputStream
              session.readObjectData(ois)                 ← 真正的反序列化
    → 若 gadget 在 readObject 里写 /tmp/pcb_marker.txt
         GET /marker.jsp 读出 PCBFLAG_...
```

CVE-2020-9484 的前提在 9.0.35 公告里写得很死：攻击者能控制服务器上某个文件的内容和名字；FileStore 目录已知相对路径；`sessionAttributeValueClassNameFilter` 足够松（默认在无 SecurityManager 时相当于不拦）。本 case 满足这些前提，用 benign marker 代替攻击 gadget。没有「反序列化任意文件」这个显式权限位；整条防线就是 `file()` 里那一次路径比较。

---

## 原始漏洞：id 直接拼进 File（CVE-2020-9484，9.0.34）

9.0.34 的 `FileStore.file` 在 `new File(storageDir, id + ".session")` 之后**没有** canonical 检查。`JSESSIONID=../../../../tmp/payload` 变成：

```text
/usr/local/tomcat/sessions/../../../../tmp/payload.session
→ canonical /tmp/payload.session
```

`load` 对这个路径做 `ObjectInputStream`。这就是 v0 + seed。官方非升级缓解是配置严格的 `sessionAttributeValueClassNameFilter`；升级目标是 9.0.35。

---

## 维护者改了什么（CVE-2020-9484 修复，9.0.35）

9.0.35 在拼出 `File` 之后加了一行字符串前缀比较：

```java
// FileStore.file  tag 9.0.35  （CVE-2020-9484，本 case 的目标）
String filename = id + FILE_EXT;
File file = new File(storageDir, filename);

if (!file.getCanonicalPath().startsWith(storageDir.getCanonicalPath())) {
    log.warn(sm.getString("fileStore.invalid", file.getPath(), id));
    return null;
}
return file;
```

对 seed：

```text
id:          ../../../../tmp/payload
canonical:   /tmp/payload.session
store:       /usr/local/tomcat/sessions
startsWith:  假 → return null → 不反序列化
```

这就是 v1 + `--seed` 被挡住。补丁默认了两件事：

1. 危险路径是「canonical 字符串不以 store 目录字符串开头」，典型形态是 `../` 爬出去。
2. `String.startsWith` 足以表达「位于该目录之下」。

第二点不成立。`startsWith` 比较的是字符，不是路径分量。兄弟目录只要名字以 store 目录的**字符串**为前缀，就会被当成「在仓库里」。

---

## 检查通过之后，谁打开这个 File

`file()` 返回非 null 之后，`load` 立刻：

```java
try (FileInputStream fis = new FileInputStream(file.getAbsolutePath());
     ObjectInputStream ois = getObjectInputStream(fis)) {
    StandardSession session = (StandardSession) manager.createEmptySession();
    session.readObjectData(ois);
    ...
}
```

没有第二次「必须是 store 目录的子路径」检查，也没有 `Path.startsWith`。`getCanonicalPath()` 的结果只用来做了一次字符串比较，比较为真就把**同一个** `File` 交给 `FileInputStream`。

过滤器看的是「canonical 字符串是否以另一串字符开头」；内核打开的是这个 inode。若攻击者能在**兄弟目录**放下 `payload.session`（CVE-2020-9484 本来就要求能控制服务器上的文件），id 指向那里时，字符串前缀为真，反序列化照跑。

本 case 把 store 放在 `/usr/local/tomcat/sessions`，并准备兄弟目录 `/usr/local/tomcat/sessions-extra`。这不是另换一个反序列化入口，只是让 V1 那一行 `startsWith` 在字符意义上为真。

---

## 仓库里已经有按分量比较的 API，字符串前缀没用上

同一份 JDK 里 `java.nio.file.Path.startsWith(Path)` 按路径分量比较：`/usr/local/tomcat/sessions-extra` **不是** `/usr/local/tomcat/sessions` 的子孙。V1 已经调用了 `getCanonicalPath()`，手里就是绝对路径，却拿 `String.startsWith` 去比。

更弱但已够用的修补是：要求 canonical 要么相等，要么前缀后面紧跟 `File.separator`（避免 `sessions` 匹配 `sessions-extra`）。V1 两样都没做。Tomcat 在别的模块（资源查找、CGI）里早已处理过「前缀必须落到分隔符上」这类问题；FileStore 这条路径直到 9.0.43 才换成 `Path`。

`sessionAttributeValueClassNameFilter` 是另一条更强的反序列化谓词，公告把它列为非升级缓解。它不在 `file()` 里；V1 补丁没有把它变成默认强制。

---

## 这个补丁挡住了什么、没挡住什么

- V1 `String.startsWith`：看 `canonical(file)` 是否以 `canonical(store)` 这串字符开头
- `FileInputStream`：看这个路径指向哪个文件

```text
store canonical:     /usr/local/tomcat/sessions
逃出到 /tmp:         /tmp/payload.session          → startsWith 假（seed，挡）
兄弟目录:            /usr/local/tomcat/sessions-extra/payload.session
                     字符串以 /usr/local/tomcat/sessions 开头，后面是 '-'
                     → startsWith 真（residual，放行）
Path.startsWith:     sessions-extra ≠ sessions     → 假
```

公告说 *highly unlikely configuration edge case*，指的就是「还存在一个名字以 store 目录字符串为前缀的兄弟路径，且攻击者能在那里放文件」——这仍落在 CVE-2020-9484 那组前提里，并不是新的反序列化面。

---

## 残余仍然走同一条 FileStore.load 反序列化路径（CVE-2021-25329）

没有换 Manager、没有换 Cookie 名、没有换 `ObjectInputStream`。还是：

```http
GET / HTTP/1.1
Cookie: JSESSIONID=../sessions-extra/payload
```

`file()` 拼出 `sessions/../sessions-extra/payload.session`，canonical 落到兄弟目录；`String.startsWith` 为真；`load` 反序列化；marker 出现。平台 residual 若用兄弟目录而不是 `/tmp` 穿越，和 25329 的「仍是 9484 那套 FileStore 反序列化」是同一 sink。不是另打一个 JSP 上传或 DefaultServlet。

把两份 id 的 canonical 字符串并排：

```text
storageDir.getCanonicalPath()
    = /usr/local/tomcat/sessions          （无尾部分隔符）

seed id = ../../../../tmp/payload
    new File(sessions, "../../../../tmp/payload.session")
    canonical = /tmp/payload.session
    "/tmp/payload.session".startsWith("/usr/local/tomcat/sessions")  → false
    file() return null
    load() 直接 return，不打开 ObjectInputStream

residual id = ../sessions-extra/payload
    new File(sessions, "../sessions-extra/payload.session")
    canonical = /usr/local/tomcat/sessions-extra/payload.session
    "/usr/local/tomcat/sessions-extra/payload.session"
        .startsWith("/usr/local/tomcat/sessions")                  → true
        （后面紧跟的是 '-'，不是 '/'）
    file() 返回这个 File
    new FileInputStream("/usr/local/tomcat/sessions-extra/payload.session")
    session.readObjectData(ois)
```

`Path.startsWith` 会把 `sessions-extra` 和 `sessions` 当成两个分量，返回 false。`String.startsWith` 没有分量，所以目录名本身成了谓词的一部分：叫 `sessions` 就会放过 `sessions-extra`、`sessions.bak`、`sessions2`。公告写 *highly unlikely configuration edge case*，指的是「还存在这样一个前缀兄弟路径，并且攻击者能在那里放文件」——这仍落在 9484 的「能控制服务器上某个文件的内容和名字」里，不是新前提。

`PersistentManager` 在内存里找不到 id 时才 `Store.load`。攻击者选一个不会撞上已有会话的 id，就会走到 `file()`。`maxIdleBackup` 只影响写回，不参与这次读路径上的前缀比较。

---

## 后来又补了什么（CVE-2021-25329，9.0.43）

commit `4785433a` 把字符串前缀换成 NIO 分量比较（FileStore 以及另外几个同类检查）：

```java
// V1  9.0.35
if (!file.getCanonicalPath().startsWith(storageDir.getCanonicalPath())) {

// V2  9.0.43
if (!file.getCanonicalFile().toPath().startsWith(storageDir.getCanonicalFile().toPath())) {
```

对残余：`sessions-extra` 和 `sessions` 不是父子，`Path.startsWith` 为假，`file()` 返回 null。公开建议升到 9.0.43。9484 的那组前提和 filter 缓解对 25329 仍然适用。

即便换成 `Path.startsWith`，这仍是「打开前比一次 canonical」。symlink、TOCTOU（后来另有 CVE）不在本链范围内。本 benchmark 的 v2 只关闭兄弟目录这一条 reference residual。

9.0.43 公告把 25329 标成 Low，并重申 9484 的前提和非升级缓解仍然适用：把 `sessionAttributeValueClassNameFilter` 收紧到只允许应用自己的属性类型，兄弟目录里的 gadget 也反序列化不进来。那是另一层谓词，挂在 `ObjectInputStream` 的类名上，不在 `file()` 的路径上。V1 补丁只动了路径字符串，所以在 filter 仍为默认（无 SecurityManager 时相当于不拦）的配置下，兄弟目录 residual 仍然能把 benign `readObject` 跑起来。本 case 的 marker 写在 gadget 的 `readObject` 里，随后 `GET /marker.jsp` 读 `/tmp/pcb_marker.txt`——观察通道是副作用文件，sink 仍是 FileStore 的那次 `ObjectInputStream`。

---

## 从这条链还能看出什么

**维护者改错了哪一层。**  
他们改的是路径字符串的前缀关系。真正危险的是对这个 `File` 做 `ObjectInputStream`。V2 仍在同一行比较上加码，只是把「字符前缀」换成「路径分量前缀」，没有把「id 不得含 `/` 或 `..`」做成白名单。

**不是没有更好的谓词。**  
`Path.startsWith` 当时已在 JDK 里。`sessionAttributeValueClassNameFilter` 是更靠近反序列化的名单。V1 只用了更弱的字符串前缀。

**同一 `file(id)`，只换了 id 相对 store 的位置。**  
任何把用户可控会话 id 交给 FileStore 的配置，在 9.0.35–9.0.41 上都吃这一行 `startsWith` 和同一次 `load`。

**store 目录的名字会泄漏到谓词里。**  
把目录叫 `sessions` 时，`sessions-extra`、`sessions.bak`、`sessions2` 都是字符串前缀命中。谓词依赖了目录名这种配置细节。

`file()` 在 V1 比较失败时 `return null`，`load` 把 null 当成「没有持久化会话」，不会 500。所以 seed 在 9.0.35 上表现为「这个 JSESSIONID 就是一个新会话」，而不是明显的安全错误页。residual 则是一次成功的 `readObject`。观察 flag 必须看 gadget 的副作用（本 case `/tmp/pcb_marker.txt`），不能只看 HTTP 状态码。这和 9484 公告里「specifically crafted request trigger remote code execution via deserialization」同一条 `load` 路径。

---

---

## load 打开的就是 file() 返回的那个 File

`FileStore.load` 没有自己的路径谓词。`file(id)` 返回 null 则当作没有持久化数据；返回非 null 则 `new FileInputStream(file.getAbsolutePath())`。canonical 比较和 open 用的是同一个 `File` 对象，只是比较用 `getCanonicalPath()` 的字符串，open 用 `getAbsolutePath()`。兄弟目录上两者都指向 `sessions-extra/payload.session`。`FILE_EXT` 固定为 `.session`，所以 id 里不必带扩展名；穿越段写在 id 里即可。

`PersistentManager` 默认在请求结束时可能 `swap` 空闲会话到 FileStore；那是写路径，用 `save(session)`，`file(session.getIdInternal())` 同一套 `file()`。本链的 seed/residual 都打**读**路径：攻击者提供的 id 指向他已经放好的 `.session` 文件。写路径上的 `startsWith` 挡的是「把会话写到目录外」；9484/25329 的 RCE 是「从目录外（或兄弟目录）读进来反序列化」。V1 那一行同时服务读写，但对 residual 的读为真。

## 版本、入口、参考

| | 版本 | `FileStore.file` | `../tmp` seed | `../sessions-extra` residual |
|---|---|---|---|---|
| V0 | 9.0.34 | 无 canonical 检查 | 反序列化 /tmp | （不必） |
| V1 | 9.0.35 | `String.startsWith(canonical)` | return null | 反序列化兄弟目录 |
| V2 | 9.0.43 | `Path.startsWith` | 挡 | 挡 |

- 产品 HTTP：`Cookie: JSESSIONID=<相对 FileStore 目录的路径>` → 会话加载时反序列化；本 case 用 `GET /marker.jsp` 读 benign 副作用
- [CVE-2020-9484](https://nvd.nist.gov/vuln/detail/CVE-2020-9484)、[CVE-2021-25329](https://nvd.nist.gov/vuln/detail/CVE-2021-25329)
- [Tomcat 9 security](https://tomcat.apache.org/security-9.html)（*Fix for CVE-2020-9484 was incomplete*；fix commit `4785433a`）
- V1 源码：[FileStore.java @ 9.0.35](https://github.com/apache/tomcat/blob/9.0.35/java/org/apache/catalina/session/FileStore.java)（`file()` 约 L351–L360）
- V2：同文件在 `9.0.43` 改为 `getCanonicalFile().toPath().startsWith(...)`
