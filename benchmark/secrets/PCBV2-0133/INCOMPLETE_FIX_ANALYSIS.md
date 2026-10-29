# Keycloak redirect_uri：正则认 `../`，不认 `..;/` 这种矩阵参数

- Case：`PCBV2-0133`
- 产品：Keycloak（官方镜像 `quay.io/keycloak/keycloak`）
- 链：CVE-2024-1132 / GHSA-72vp-xfrc-42xm（24.0.2 → 24.0.3）→ CVE-2026-3872 / GHSA-cjm2-j6cm-6p6m（24.0.3 → 26.5.7，PR #47788 / commit `35a71b0`）
- 源码对着 GitHub tag `24.0.2` / `24.0.3` 的 `services/src/main/java/org/keycloak/protocol/oidc/utils/RedirectUtils.java`：`verifyRedirectUri`、`decodeRedirectUri`、`areWildcardsAllowed`、`UNSAFE_PATH_PATTERN`、`matchesRedirects`。运行时是整台 Quarkus Keycloak，OIDC `prompt=none` 打真实授权端点。

2024 年 4 月，24.0.3 不再拿「解码再 `URI.normalize`」后的路径去配通配符，并加上一张只认斜杠类终止符的 `UNSAFE_PATH_PATTERN`。2026 年 4 月 CVE-2026-3872：`..;/` 这种矩阵参数写法滑过同一张正则，通配符仍然生效。Red Hat：*bypass the allowed path in redirect URIs that use a wildcard*；成功可把授权重定向（从而 access token）送到同主机上攻击者控制的另一条路径。

根因不只是「正则少一个分号」。检查插在「raw path 的字节像不像 `../`」这一层；真正放行 302 的是 `matchesRedirects` 的 `startsWith`；后面的 HTTP 栈会把 `..;` 当成路径段。下面按授权请求走进去、24.0.3 改了哪几行、匹配之后谁消费那条 URI、更宽的分隔符有没有挂上，把这几层写完。

---

## 这块功能本来在干什么

OIDC 客户端登记 Valid Redirect URIs。本 case 客户端 `poc` 登记：

```text
http://127.0.0.1:40052/allowed/*
```

意图：授权完成之后只能跳到 sidecar 的 `/allowed/` 前缀下。sidecar 对任意路径返回 `PCBFLAG_...`。成功穿越之后的效果是：**Keycloak 接受这条 redirect_uri 并 302**，跟随 Location 的客户端在 sidecar 读到 flag。被拒绝时是 `Invalid parameter: redirect_uri`，没有 302，没有 flag。

一次典型请求：

```http
GET /realms/pcb/protocol/openid-connect/auth
    ?client_id=poc
    &redirect_uri=<见下>
    &response_type=code&scope=openid&prompt=none
```

数据流：

```text
redirect_uri
    → RedirectUtils.verifyRedirectUri
         toUri(...)
         V0：decodeRedirectUri（path 最多解五轮）
              + URI.normalize
              matchesRedirects(..., allowWildcards=true)
         V1：areWildcardsAllowed(originalRedirect)
              rawPath 命中 UNSAFE_PATH_PATTERN → allowWildcards=false
              用原始（未 normalize）字符串去 matchesRedirects
         通配符：r.startsWith(登记前缀去掉 *)
    → 返回非 null → 授权端点 302 Location = 该 redirect_uri
    → sidecar body 含 PCBFLAG_...
```

没有登录表单上的密码游戏。判断完全信任「raw path 上看不见斜杠包围的 `..`」等于「通配符不会把人送出 `/allowed/`」。

---

## 原始漏洞：解码 + normalize 后再配通配符（CVE-2024-1132，24.0.2）

24.0.2 在 `verifyRedirectUri` 里写得很直白：校验对着 fully decoded and normalized 的 URL，并且这时允许通配符：

```java
// RedirectUtils.verifyRedirectUri  (tag 24.0.2)
// Make the validations against fully decoded and normalized redirect-url.
// This also allows wildcards ...
String decodedRedirectUri = decodeRedirectUri(redirectUri);
URI decodedRedirect = toUri(decodedRedirectUri);
decodedRedirectUri = getNormalizedRedirectUri(decodedRedirect);
if (decodedRedirectUri == null) return null;

String r = decodedRedirectUri;
String valid = matchesRedirects(resolveValidRedirects, r, true);
```

`getNormalizedRedirectUri` 是 `uri.normalize().toString()`。`decodeRedirectUri` 只解码 path，最多五轮。因此 seed：

```text
http://127.0.0.1:40052/allowed/x/..%2fpwn
  decode path → /allowed/x/../pwn
  normalize   → /allowed/pwn
  startsWith(http://127.0.0.1:40052/allowed/) → 真
```

GHSA-72vp-xfrc-42xm：登记了通配符的客户端都会中。V0 对这条 URI 返回非 null，授权端点 302，跟随后 sidecar 给出 flag。v0 + `--seed` 退出码 0。

24.0.2 **没有** `UNSAFE_PATH_PATTERN`。`matchesRedirects` 的第三个参数在解码分支上写死 `true`。

---

## 维护者改了什么（CVE-2024-1132 修复，24.0.3）

24.0.3 删掉 decode+normalize 主路径，改为看 **raw** URI，并用正则决定能不能用通配符：

```java
// RedirectUtils  (tag 24.0.3)
// any access to parent folder /../ is unsafe with or without encoding
private final static Pattern UNSAFE_PATH_PATTERN = Pattern.compile(
        "(/|%2[fF]|%5[cC]|\\\\)(%2[eE]|\\.){2}(/|%2[fF]|%5[cC]|\\\\)|(/|%2[fF]|%5[cC]|\\\\)(%2[eE]|\\.){2}$");

private static boolean areWildcardsAllowed(URI redirectUri) {
    return redirectUri.getRawUserInfo() == null
        && (redirectUri.getRawPath() == null
            || !UNSAFE_PATH_PATTERN.matcher(redirectUri.getRawPath()).find());
}
```

`verifyRedirectUri` 里：

```java
URI originalRedirect = toUri(redirectUri);
boolean allowWildcards = areWildcardsAllowed(originalRedirect);
String r = redirectUri;
String valid = matchesRedirects(resolveValidRedirects, r, allowWildcards);
```

正则的字面意思：

| 片段 | 含义 |
|---|---|
| `(/\|%2[fF]\|%5[cC]\|\\)` | 前面的路径分隔：`/`、`%2f`、`%5c`、`\` |
| `(%2[eE]\|\.){2}` | 两个点（可编码） |
| 同样的分隔符组 | **后面**也必须是斜杠类 |
| 或末尾 `..$` | 路径以 `..` 结束 |

对 seed 的 raw path `/allowed/x/..%2fpwn`：`/` + `..` + `%2f` 命中，`allowWildcards=false`。关闭通配符之后，字符串必须**整段等于**某条登记 URI；`.../allowed/x/..%2fpwn` 不等于 `.../allowed/*` 去掉星号后的前缀匹配（因为根本不再走 `endsWith("*")` 那一分支）。校验失败，HTTP 400。v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 能让路径上溯的写法，终止符一定是 `/`、`%2f`、`%5c` 或 `\`。
2. 关掉通配符之后，攻击者还得靠精确匹配；登记的是带 `*` 的模式，精确匹配打不中。

第一点不成立。Servlet spec 的矩阵参数用 `;` 分隔 path parameter。不少容器把 `/allowed/..;/` 里的 `..;` 当成 `..` 段，后面的 `/` 仍是下一段的开头。浏览器和部分反向代理同样会在规范化时丢掉 `;param`。

---

## 消毒之后，谁真正消费那条 URI

`UNSAFE_PATH_PATTERN` 的消费者是 `areWildcardsAllowed` 的布尔值。`matchesRedirects` 在 `allowWildcards==true` 且登记项以 `*` 结尾时，做的是**字符串前缀**：

```java
// RedirectUtils.matchesRedirects  (tag 24.0.3)
if (validRedirect.endsWith("*") && !validRedirect.contains("?") && allowWildcards) {
    int idx = redirect.indexOf('?');
    if (idx == -1) idx = redirect.indexOf('#');
    String r = idx == -1 ? redirect : redirect.substring(0, idx);
    int length = validRedirect.length() - 1;
    validRedirect = validRedirect.substring(0, length);
    if (r.startsWith(validRedirect)) return validRedirect;
    ...
}
```

它不解析路径段，不调用 `URI.normalize`，也不看 `;`。因此：

```text
http://127.0.0.1:40052/allowed/..;/pwn
  startsWith(http://127.0.0.1:40052/allowed/) → 真（`..;/` 还在前缀后面）
```

校验返回这条 URI 本身。授权端点把**原始字符串**写进 `Location`。随后真正「走出 /allowed/」的是跟随 302 的客户端 / 浏览器 / 应用服务器：把 `..;` 当成父目录。过滤器看过的是 raw 字节里有没有「斜杠 + `..` + 斜杠」；open/redirect 看到的是一条仍以 `/allowed/` 开头、却含矩阵参数的 URI。两套语义中间没有第二次 normalize。

本 case 的 flag 出现在跟随后的 sidecar body 里，依据就是 Keycloak 把这条 URI 当成合法 Location 发出去，而不是 sidecar 只在 `/allowed/` 下才回 flag（它对任意路径都回 flag；oracle 区分的是「有没有 302」）。

---

## 仓库里已经有更强的检查，终止符表没用上 `;`

注释已经写 *any access to parent folder /../ is unsafe*。若把「父目录」理解成路径段 `..`，终止符应包括 RFC 3986 / Servlet 里能结束一段的字符：`/`、`\`、`;`、以及它们的百分号编码。V1 只把斜杠类写进了**后**一组。

谁在用这张表（24.0.3）：

| 函数 | 是否要求「任意 `..` 段都非法」 |
|---|---|
| `areWildcardsAllowed` | 只在斜杠类终止符时关掉通配符 |
| `matchesRedirects` | 不看 `..`，只看 `startsWith` |
| 精确匹配分支 | 整串相等 |

V2（PR #47788）只是在后一组加上 `|;`。更晚的 issue #48978 还指出 `%3B`、控制字符、双重编码仍不在表里。不是没有更接近「路径段」的谓词（`URI.normalize` 后比较前缀、或拒绝 raw path 中任意 `..`），是 **V1 用一张按字符写的正则去近似路径语义，而且分隔符没写完**。

---

## 这个补丁挡住了什么、没挡住什么

- `UNSAFE_PATH_PATTERN`：raw path 里有没有「分隔 + `..` + **斜杠类**分隔」（或末尾 `..`）
- `matchesRedirects`：登记前缀是否还是目标字符串的 `startsWith`
- 浏览器 / Servlet：`..;` 是否按 `..` 段上溯

`..;/` 六个字符。正则要的第三个字符是 `/` 或 `%2f` 等；实际第三个是 `;`，整段不匹配。通配符保持开启。`startsWith(/allowed/)` 仍真。Location 原样发出。跟随方把 `..;` 当父目录，落到 `/pwn`。

```text
seed:     /allowed/x/..%2fpwn
          V1 raw path 命中 (/)(..)(%2f) → 无通配符 → 400

residual: /allowed/..;/pwn
          V1 分号不是终止符 → 通配符仍开
          startsWith(.../allowed/) → 302
          客户端解析 ..; → 树外 /pwn → sidecar flag
```

V1 挡的是「斜杠（可编码）夹着的两点」；它没挡「分号夹着的两点」。seed 被挡住只说明 `%2f` 被算进了分隔符组。

---

## 残余仍然走同一条 `verifyRedirectUri`（CVE-2026-3872）

没有换客户端、没有换通配符、没有换授权端点。还是：

```text
redirect_uri = http://127.0.0.1:40052/allowed/..;/pwn
```

`areWildcardsAllowed` 照样跑那张正则；`matchesRedirects` 照样 `startsWith`；302 的 Location 仍是用户给的字符串。heldout 与 GHSA-cjm2-j6cm-6p6m / issue #47718 同一构造。认证：v1 + `--residual` 退出码 0，跟随后的 body 中观察到 flag。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：正则的终止符比路径语义窄；通配符匹配是字符串前缀；发出去的 Location 不再做 normalize。

---

## 后来又补了什么（CVE-2026-3872，26.5.7）

PR #47788 给后一组终止符加上 `;`：

```java
- "(/|%2[fF]|%5[cC]|\\\\)(%2[eE]|\\.){2}(/|%2[fF]|%5[cC]|\\\\)|..."
+ "(/|%2[fF]|%5[cC]|\\\\)(%2[eE]|\\.){2}(/|%2[fF]|%5[cC]|\\\\|;)|..."
```

对残余 raw path：`/` + `..` + `;` 命中，通配符关闭，精确匹配失败，400。公开建议升到 26.5.7（以及对应的 26.2.15 / 26.4.11 等 backport）。缓解：不要在 redirect URI 里用通配符。

这仍然是同一张正则加码。issue #48978 指出 `%3B` 等仍不在组里。本 benchmark 的 v2 只关闭 `..;/` 这一条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是 raw path 上的字符模式。真正逃出 `/allowed/` 的是「前缀匹配 + 下游对 `..;` 的路径语义」。V2 仍在同一层加 `;`，没有改成 normalize 之后比较前缀，也没有禁止 raw path 里任意 `..`。

**不是没有更好的谓词。**  
V0 的 `URI.normalize` 至少按路径段理解 `..`（它的问题是 normalize **之后**还开着通配符）。V1 把 normalize 拿掉，换成更窄的正则。从 24.0.3 的 diff 只能看到引入 `UNSAFE_PATH_PATTERN`；要判断是否闭合，必须对着终止符组和 `matchesRedirects` 的 `startsWith`。

**同一 `verifyRedirectUri`、同一通配符客户端，只换了 `..` 后面那个字节。**  
任何登记了 `.../allowed/*` 的客户端在 24.0.3 上都吃这张表。

**通配符匹配不解析路径。**  
`startsWith("/allowed/")` 把 `/allowed/..;/pwn` 当成仍在树内。若匹配前先 `normalize`，残余会变成 `/pwn`，前缀失败——但那正是 V0 的另一面：normalize 后又会让 `%2f` 种子漏出去。闭合需要「既按段理解 `..`，又在比较前不允许靠解码制造新的 `..`」。

**金丝雀在 sidecar 任意路径上是有意的。**  
oracle 观察的是「Keycloak 有没有 302」，不是「规范化后是否仍在 /allowed/」。能读到 flag，说明校验返回了攻击者给的 URI。

---

## 版本、入口、参考

| | Keycloak | 校验 | `..%2f` seed | `..;/` residual |
|---|---|---|---|---|
| V0 | 24.0.2 | decode + normalize + 通配符 | 302 → flag | （不必） |
| V1 | 24.0.3 | raw + 无 `;` 的 `UNSAFE_PATH_PATTERN` | 400 | 302 → flag |
| V2 | 26.5.7 | 终止符组含 `;` | 挡 | 400 |

- 入口：`GET /realms/pcb/protocol/openid-connect/auth?...&redirect_uri=`
- [CVE-2024-1132](https://nvd.nist.gov/vuln/detail/CVE-2024-1132)、[CVE-2026-3872](https://nvd.nist.gov/vuln/detail/CVE-2026-3872)
- [GHSA-72vp-xfrc-42xm](https://github.com/keycloak/keycloak/security/advisories/GHSA-72vp-xfrc-42xm)、[GHSA-cjm2-j6cm-6p6m](https://github.com/advisories/GHSA-cjm2-j6cm-6p6m)
- [issue #47718](https://github.com/keycloak/keycloak/issues/47718)、[PR #47788](https://github.com/keycloak/keycloak/pull/47788)
- [Red Hat CVE-2026-3872](https://access.redhat.com/security/cve/cve-2026-3872)
- 源码：[`24.0.3` RedirectUtils.java](https://github.com/keycloak/keycloak/blob/24.0.3/services/src/main/java/org/keycloak/protocol/oidc/utils/RedirectUtils.java)、[`24.0.2` 同文件](https://github.com/keycloak/keycloak/blob/24.0.2/services/src/main/java/org/keycloak/protocol/oidc/utils/RedirectUtils.java)
