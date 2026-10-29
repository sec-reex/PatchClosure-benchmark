# Jetty：鉴权看的是解码前的点，DefaultServlet 看的是解码后的点

- Case：`PCBV2-0001`
- 产品：Eclipse Jetty（Servlet 容器；本 case 跑官方 `jetty:9.4.39-jre8` 镜像，ROOT webapp + `WEB-INF/pcb-secret.txt` 金丝雀）
- 链：CVE-2021-28164（9.4.37–9.4.38 → 9.4.39）→ CVE-2021-34429（9.4.39–9.4.42 → 9.4.43）
- 源码对着 `jetty-9.4.39.v20210325` 的 `Request.setMetaData`、`HttpURI`、`URIUtil.decodePath` / `canonicalPath`、`ContextHandler.isProtectedTarget`。运行时是整份 Jetty，不是抽出来的函数。

9.4.37 把 URI 解析改成 RFC 3986：先规范化、再解码。鉴权看到的路径里 `%2e` 还是三个字符，`WEB-INF` 检查放行；DefaultServlet 随后把 `%2e` 解成 `.` 再压成 `/WEB-INF/...`，受保护资源被读出来。9.4.39 给「含糊段」补了一刀 `canonicalPath`，挡住了字面 `%2e`。GHSA-vjv5-gp2w-65vm 写明 CVE-2021-34429 *is a variation of the vulnerability reported in CVE-2021-28164*：同一条鉴权-在-规范化-之前的缝，只是换了一种编码。

根因不只是「忘了 `%u002e`」。检查插在「这段像不像 `%2e`」上；真正打开文件的是另一套 decode + 文件系统规范化。`URIUtil.decodePath` 里已经有 `%uXXXX` 解码，且注释写着 *TODO remove %u support in jetty-10*，V1 的含糊段表却根本没把它算进去。下面按请求走进去。

---

## 这块功能本来在干什么

Jetty 把每个 webapp 的 `WEB-INF/`（以及 `META-INF/`）标成受保护目标。明文 `GET /WEB-INF/web.xml` 必须 404，不能把部署描述符、class、内嵌密钥交出去。本 case 的金丝雀是 compose entrypoint 写进 ROOT 的 `WEB-INF/pcb-secret.txt`；三条版本上明文 GET 都是 404。

一次典型请求：

```http
GET /%2e/WEB-INF/pcb-secret.txt HTTP/1.1
Host: localhost:8080
```

数据流（9.4.39，本 case 的 V1）：

```text
HTTP request-target
    → HttpParser → HttpURI.parse
         checkSegment() 查 __ambiguousSegments  trie
         若 path 含 % 或 .：
           canonicalPath(_path)     ← 在**仍编码**的字符串上做 RFC 去点
           decodePath(canonical)    ← 这时才 %2e / %uXXXX → 字符
    → Request.setMetaData
         if (uri.isAmbiguous())
             path = URIUtil.canonicalPath(decoded)   ← V1 补丁插在这里
         setPathInfo(path)
    → ContextHandler.doHandle
         isProtectedTarget(target)  ← 只看 pathInfo 是否以 /WEB-INF 开头
         命中则 404，不再往下
    → DefaultServlet / ResourceHandler
         ContextHandler.getResource(path)
         文件系统再规范化一次，打开 WEB-INF 里的文件
    → 响应 body
```

设计意图：`isProtectedTarget` 看到的 `target` 必须已经是「应用语义上的路径」。成功穿越之后的效果是**读出 WEB-INF 里的文件，并把内容反射到 HTTP body**。

---

## 原始漏洞：`%2e` 段在鉴权之后才变成点（CVE-2021-28164，9.4.38）

9.4.37 引入 RFC 合规解析：规范化发生在解码之前。`HttpURI` 结束解析时（9.4.39 源码，逻辑与 9.4.38 同序）：

```java
// jetty-http/.../HttpURI.java :: parse  (jetty-9.4.39.v20210325)
        if (!encoded && !dot)
        {
            ...
            _decodedPath = _path;
        }
        else if (_path != null)
        {
            String canonical = URIUtil.canonicalPath(_path);
            if (canonical == null)
                throw new BadMessageException("Bad URI");
            _decodedPath = URIUtil.decodePath(canonical);
        }
```

`canonicalPath` 的输入是**仍带百分号**的 `_path`。`/%2e/WEB-INF/...` 里没有字面 `.` / `..` 段，去点是空操作。随后 `decodePath` 把 `%2e` 变成 `.`，`_decodedPath` 变成 `/./WEB-INF/pcb-secret.txt`。

`ContextHandler.doHandle` 用这份 pathInfo 做保护检查：

```java
// jetty-server/.../ContextHandler.java :: doHandle / isProtectedTarget
        if (dispatch == DispatcherType.REQUEST && isProtectedTarget(target))
        {
            baseRequest.setHandled(true);
            response.sendError(HttpServletResponse.SC_NOT_FOUND);
            return;
        }

    public boolean isProtectedTarget(String target)
    {
        ...
        if (StringUtil.startsWithIgnoreCase(target, t))  // t = "/WEB-INF"
        {
            char c = target.charAt(t.length());
            if (c == '/' || c == '?' || c == '#' || c == ';')
                return true;
        }
        return false;
    }
```

`/./WEB-INF/...` 并不以 `/WEB-INF` 开头。检查放行。DefaultServlet 再按文件系统语义把 `/./` 压掉，打开 `WEB-INF/pcb-secret.txt`，body 里出现 `PCBFLAG_...`。

GHSA-v7ff-8wcx-gmc5 的例子是 `/context/%2e/WEB-INF/web.xml`。本 case seed：

```text
GET /%2e/WEB-INF/pcb-secret.txt
```

9.4.38 上 HTTP 200，金丝雀在 body 里。明文 `/WEB-INF/pcb-secret.txt` 三条版本都是 404，所以这不是「WEB-INF 本来就能读」，是编码绕过了鉴权。

---

## 维护者改了什么（CVE-2021-28164 修复，9.4.39）

GHSA-v7ff 对应的补丁（`Request.java`，tag `jetty-9.4.39.v20210325`，commit 主题 *Always normalize ambiguous URIs*）在 `setMetaData` 里：若 URI 被标成含糊，就对**已经解码**的 path 再跑一次 `canonicalPath`。

```java
// jetty-server/.../Request.java :: setMetaData  (9.4.39)
        HttpURI uri = request.getURI();

        boolean ambiguous = uri.isAmbiguous();
        if (ambiguous)
        {
            ...
            if (uri.hasAmbiguousSegment() && (... NO_AMBIGUOUS_PATH_SEGMENTS ...))
                throw new BadMessageException("Ambiguous segment in URI");
            ...
        }
        ...
        else if (encoded.startsWith("/"))
        {
            path = (encoded.length() == 1) ? "/" : uri.getDecodedPath();

            // Strictly speaking if a URI is legal and encodes ambiguous segments, then they
            // should be reflected in the decoded string version. However, previous behaviour
            // was to always normalize so we will continue to do so.
            if (ambiguous)
                path = URIUtil.canonicalPath(path);
        }
```

「含糊」由 `HttpURI.checkSegment` 查一张静态表：

```java
// jetty-http/.../HttpURI.java  (9.4.39)
    private static final Trie<Boolean> __ambiguousSegments = new ArrayTrie<>();
    static
    {
        __ambiguousSegments.put("%2e", Boolean.TRUE);
        __ambiguousSegments.put("%2e%2e", Boolean.TRUE);
        __ambiguousSegments.put(".%2e", Boolean.TRUE);
        __ambiguousSegments.put("%2e.", Boolean.TRUE);
        __ambiguousSegments.put("..", Boolean.FALSE);
        __ambiguousSegments.put(".", Boolean.FALSE);
    }
```

对 seed `/%2e/WEB-INF/...`：段 `%2e` 命中 TRUE → `isAmbiguous()` → `canonicalPath("/./WEB-INF/...")` → `/WEB-INF/...` → `isProtectedTarget` 命中 → 404。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险的点段长得像表里那四个百分号写法（`%2e` / `%2e%2e` / `.%2e` / `%2e.`）。
2. 不在这张表里的编码，解码之后不会再变成 `.` / `..`，因此不必再规范化。

第二点不成立。`getDecodedPath` 用的 `URIUtil.decodePath` 比这张表认得的编码多。

---

## 消毒之后，谁真正打开那个文件

V1 的 `canonicalPath` 只在 `ambiguous == true` 时跑。`ambiguous == false` 时，`setPathInfo` 拿到的就是 `getDecodedPath()` 的原样，例如 `/./WEB-INF/pcb-secret.txt`。

`isProtectedTarget` 仍然只做前缀匹配，不自己去点。随后 `nextHandle` 把请求交给 DefaultServlet。资源查找走 `ContextHandler.getResource`：9.4.39 的 `PathResource` **不再**把「请求路径 vs 规范路径不一致」当成 alias（9.4.37 之前的 `FileResource` 会）。文件系统把 `/./WEB-INF/...` 收成 `/WEB-INF/...`，文件被打开。

过滤器刚看过的是「这段是不是表里的 `%2e`」；open 看到的是 decode 之后、再经目录上溯的绝对路径。两套语义中间，V1 只在表命中时桥接了一次。

---

## 仓库里已经有更强的检查，含糊表没用上

同一份 `URIUtil.java` 里，`decodePath` 不但解 `%2e`，还解微软风格的 `%uXXXX`，注释写明这东西不该继续存在：

```java
// jetty-util/.../URIUtil.java :: decodePath  (9.4.39, 约 L473–487)
                if (u == 'u')
                {
                    // TODO remove %u support in jetty-10
                    // this is wrong. This is a codepoint not a char
                    builder.append((char)(0xffff & TypeUtil.parseInt(path, i + 2, 4, 16)));
                    i += 5;
                }
                else
                {
                    builder.append((byte)(0xff & (TypeUtil.convertHexDigit(u) * 16
                        + TypeUtil.convertHexDigit(path.charAt(i + 2)))));
                    i += 2;
                }
```

`%u002e` 四个十六进制是 U+002E，也就是 `.`。`__ambiguousSegments` 没有 `%u002e`。`checkSegment` 查不到 → 不标含糊 → `setMetaData` 不跑第二趟 `canonicalPath`。

不是仓库里没有「把编码点变成真点再规范化」的能力：`decodePath` + `canonicalPath` 都在。V1 把第二趟规范化挂在一张**穷举出来的含糊段表**上，而真正解码的函数比这张表宽。

更早的防线是 `FileResource` 的 alias 检查（请求名和 canonical 名不一致就不送）。9.4.37 换成 `PathResource` 时丢掉了。V2 才把它找回来，并让 `getResource` 拒绝未规范化路径。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「含糊表 vs decode」落到具体字符串：

- `HttpURI.checkSegment`：段是不是 `%2e` / `%2e%2e` / `.%2e` / `%2e.`
- `URIUtil.decodePath`：`%2e` **以及** `%uXXXX` 都变成字符；`%00` 变成 NUL
- `canonicalPath`：只认已经是 `.` / `..` 的段
- `isProtectedTarget`：解码后的 pathInfo 是否以 `/WEB-INF` 开头

只要构造一种输入，使「不在含糊表里」但 `decodePath` 仍能造出 `.`，第一张表放行，pathInfo 仍是 `/./WEB-INF/...`，Servlet 仍然打开受保护文件。

`%u002e` 就是这样来的。六个字符 `% u 0 0 2 e`。trie 键是 `%2e`，对不上。decode 却按 `%u` 分支读四位 hex：

```text
输入:   /%u002e/WEB-INF/pcb-secret.txt

HttpURI.checkSegment("%u002e")  →  不在表里，ambiguous=false
canonicalPath(编码串)           →  无字面点段，不变
decodePath                      →  /./WEB-INF/pcb-secret.txt
setMetaData                     →  不跑第二趟 canonicalPath
isProtectedTarget("/./WEB-INF/...")  →  不以 /WEB-INF 开头，放行
DefaultServlet / 文件系统       →  /WEB-INF/pcb-secret.txt
```

编码 NUL 是另一条：`/.%00/WEB-INF/pcb-secret.txt`。NUL 截断规范化，点段收不干净，保护检查同样对不上 `/WEB-INF`。GHSA-vjv5 两条都写了。

---

## 残余仍然走同一条 WEB-INF 读文件路径（CVE-2021-34429）

没有换 handler、没有换鉴权函数、没有换金丝雀位置。还是：

```http
GET /%u002e/WEB-INF/pcb-secret.txt HTTP/1.1
```

`HttpURI` 照样 parse；V1 那张含糊表照样查；查完 `ambiguous=false`；`decodePath` 把 `%u002e` 变成 `.`；`isProtectedTarget` 放行；DefaultServlet 读 `WEB-INF/pcb-secret.txt`；body 里出现 `PCBFLAG_...`。

本 case 的 residual candidate（运行时写死在 verify，分析引用 held-out）：

```text
path = "/%u002e/WEB-INF/pcb-secret.txt"
备选: "/.%00/WEB-INF/pcb-secret.txt"
```

和 GHSA-vjv5 的 PoC 同一构造，只是把 `web.xml` 换成金丝雀。认证：v1 + `--residual` 退出码 0，body 中观察到 flag。9.4.43 上 `%u002e` 变 404，`.%00` 变 400。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：含糊段表比 decode 语言窄；第二趟规范化挂在表命中之后；读路径上的 alias 检查已经被 9.4.37 拿掉。seed 被挡住只说明「字面 `%2e` 没了」，不说明「不能再从 WEB-INF 读出文件」。

---

## 后来又补了什么（CVE-2021-34429，9.4.43）

GHSA-vjv5 列了几道防线，不是再往表里加一行 `%u002e`：

1. **先解码、再规范化**（退回 9.4.37 之前的顺序）。`%u002e` 先变成 `.`，再被 `canonicalPath` 压掉，鉴权看到 `/WEB-INF/...`。
2. **解析期拒绝含糊**：编码点段、编码分隔符、空段、带参数的点段、NUL → 默认 400，除非显式打开 compliance。
3. **资源层不再二次 decode**。
4. **`ContextHandler.getResource` 要求路径已经规范化**，否则必须过 AliasChecker。
5. **`PathResource` 把请求名 vs canonical 名不一致重新当成 alias**。

9.4.43 上 `%u002e` 被压成受保护路径 → 404；`.%00` 被当成含糊 → 400。公开建议升级到 9.4.43 / 10.0.6 / 11.0.6。

即便如此，默认模式仍可能留下其它「decode 比含糊检测宽」的写法；本 benchmark 的 v2 只关闭这一条 reference residual。

---

## 从这条链还能看出什么

**维护者改错了哪一层。**  
他们改的是 `setMetaData` 里「若表说含糊，则再规范化」。真正逃出 WEB-INF 的是 `decodePath` 造出的 `.` 加上 DefaultServlet 的文件系统规范化。V2 把顺序改回 decode-then-normalize，并把 alias 检查挂回 `getResource`，才碰到 open 那一层。

**不是没有更好的谓词。**  
`URIUtil.decodePath` 已经认识 `%u`。`canonicalPath` 已经能压 `/./`。`FileResource` 曾经拒绝 alias。V1 只把第二趟规范化接到一张穷举表上。从 V1 的 diff 只能看到 `if (ambiguous) canonicalPath`；要判断是否闭合，必须看到 `__ambiguousSegments` 的键和 `decodePath` 的 `%u` 分支。

**同一函数、同一 `target`，只换了点段的写法。**  
`isProtectedTarget` 不区分 `%2e` 还是 `%u002e`。任何让解码后的 pathInfo 变成 `/./WEB-INF/...` 的编码都走同一 404 门。

**金丝雀在 WEB-INF 里是有意的。**  
明文 GET 三条版本都 404。能读到它，说明 DefaultServlet 打开的是受保护目标，而不是「webapp 根下碰巧有个同名文件」。

---

## 版本、入口、参考

| | 版本 | `HttpURI` 含糊表 | `setMetaData` | `decodePath` 的 `%u` | 明文 `%2e` seed | `%u002e` residual |
|---|---|---|---|---|---|---|
| V0 | 9.4.38 | 无第二趟 decoded canonical | RFC：先规范再解码 | 解成 `.` | 读到金丝雀 | （不必） |
| V1 | 9.4.39 | `%2e` 等四键 | 仅 ambiguous 时对 decoded 再规范 | 仍解 `%u002e` | 404 | 读到金丝雀 |
| V2 | 9.4.43 | 解析期拒绝含糊 / NUL | 先解码再规范化；`getResource` 要求已规范 | 默认拒绝 `%u` 作点段 | 挡 | 404 / 400 |

- Web：`GET /%2e/WEB-INF/pcb-secret.txt`（seed）；`GET /%u002e/WEB-INF/pcb-secret.txt`（residual）
- 认证（本平台）：v0 seed 观察到 flag；v1 seed 未观察到；v1 residual 观察到。
- [CVE-2021-28164](https://nvd.nist.gov/vuln/detail/CVE-2021-28164)、[CVE-2021-34429](https://nvd.nist.gov/vuln/detail/CVE-2021-34429)
- [GHSA-v7ff-8wcx-gmc5](https://github.com/jetty/jetty.project/security/advisories/GHSA-v7ff-8wcx-gmc5)（V1）
- [GHSA-vjv5-gp2w-65vm](https://github.com/jetty/jetty.project/security/advisories/GHSA-vjv5-gp2w-65vm)（V2；*variation of CVE-2021-28164*）
- V1 源码：[`Request.java` @ jetty-9.4.39.v20210325](https://github.com/jetty/jetty.project/blob/jetty-9.4.39.v20210325/jetty-server/src/main/java/org/eclipse/jetty/server/Request.java)、[`HttpURI.java`](https://github.com/jetty/jetty.project/blob/jetty-9.4.39.v20210325/jetty-http/src/main/java/org/eclipse/jetty/http/HttpURI.java)、[`URIUtil.java`](https://github.com/jetty/jetty.project/blob/jetty-9.4.39.v20210325/jetty-util/src/main/java/org/eclipse/jetty/util/URIUtil.java)
- V1 发布说明：[9.4.39.v20210325](https://github.com/eclipse/jetty.project/releases/tag/jetty-9.4.39.v20210325)（#6101 Normalize ambiguous URIs）
