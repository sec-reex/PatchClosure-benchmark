# Jenkins CSRF crumb：session 字段加了，没 session 时却写成常数

- Case：`PCBV2-0129`
- 产品：Jenkins core（CI/CD 控制器；官方镜像 `jenkins/jenkins`）
- 链：CVE-2019-10353 / SECURITY-626（LTS 2.176.1 → 2.176.2）→ CVE-2019-10384 / SECURITY-1491（2.176.2 → 2.176.3）
- 源码对着 GitHub tag `jenkins-2.176.2` / `jenkins-2.176.3` 的 `core/src/main/java/hudson/security/csrf/DefaultCrumbIssuer.java`：`issueCrumb`、`getSessionId`、`validateCrumb`。运行时是整台官方 Jenkins，CSRF 由真实 `CrumbFilter` 校验，不是抽出来的哈希函数。

2019 年 7 月 17 日，Jenkins 给 CSRF crumb 的 MD5 输入补上 web session id，想让「从一个会话拿到的 crumb 不能拿到另一个会话里用」。六周后同一条 advisory 链写明：这是 SECURITY-626 的不完整修复——`getSession(false)` 在没有会话时返回 `null`，补丁把这个空值写成字面量 `"NO_SESSION"`。所有没带 `JSESSIONID` 的请求因此共享同一个 session 分量。NVD CVE-2019-10384 写的是 *allowed users to obtain CSRF tokens without an associated web session ID*；2019-08-28 advisory 原话是 *This is the result of an incomplete fix for SECURITY-626*。

根因不只是「少创建了会话」。检查插在「哈希输入里有没有第三段」这一层；真正放行 POST 的是 `validateCrumb` 对两次 `issueCrumb` 的字节比较；同一次哈希已经会读 session，却用「不创建」语义把空会话折叠成常数。下面按请求走进去、2.176.2 改了哪几行、哈希之后谁消费那个字符串、创建会话的 API 有没有挂上，把这几层写完。

---

## 这块功能本来在干什么

Jenkins 对会改状态的 HTTP 动作走 CSRF 防护：客户端先向 crumb issuer 要一枚 token，再把它放进 `Jenkins-Crumb` 头（或表单字段）一起 POST。`CrumbFilter` 拦截 POST，调用当前 `CrumbIssuer` 的 `validateCrumb`。默认实现是 `DefaultCrumbIssuer`：把「当前身份 + 客户端 IP +（后来加上的）会话」拼成字符串，MD5 后再和 salt 做一次 digest，得到 hex crumb。

一次典型的状态写：

```http
POST /pcbReveal/reveal HTTP/1.1
Jenkins-Crumb: <hex>
Cookie: JSESSIONID=...
```

本 case 用 `init.groovy.d` 装上库存 `DefaultCrumbIssuer`（含 IP），再注册一个 `UnprotectedRootAction`：只有真实 `CrumbFilter` 收下这枚 crumb，才把环境里的 `PCBFLAG_...` 写进响应。成功穿越之后的效果是：**一枚在另一个客户端上下文里发出来的 crumb 被当成当前请求的合法 token，状态写发生，flag 出现在 body**。没有换 endpoint、没有绕过 filter。

数据流：

```text
GET  /crumbIssuer/api/json          ← 发行：issueCrumb(reqA, salt)
         buffer = name ; clientIP [ ; sessionComponent ]
         MD5(buffer) ⊕ salt → hex crumb
POST /pcbReveal/reveal
         CrumbFilter
         validateCrumb(reqB, salt, submitted)
              再跑一遍 issueCrumb(reqB, salt)
              MessageDigest.isEqual(新 hex, 提交的 hex)
         通过 → 状态写，body 里出现 PCBFLAG_...
```

设计意图：crumb 必须绑在「同一个人、同一 IP、**同一次 web session**」上。过期或换会话之后旧 crumb 失效。V0 缺第三段；V1 加了第三段但空会话折叠成常数；真正比较的永远是两次 `issueCrumb` 的输出，不是「有没有 JSESSIONID 这张 cookie」。

---

## 原始漏洞：crumb 不绑 session（CVE-2019-10353，LTS 2.176.1）

2.176.1 的 `issueCrumb` 只拼身份和 IP：

```java
// DefaultCrumbIssuer.issueCrumb  (jenkins-2.176.1)
HttpServletRequest req = (HttpServletRequest) request;
StringBuilder buffer = new StringBuilder();
Authentication a = Jenkins.getAuthentication();
if (a != null) {
    buffer.append(a.getName());
}
buffer.append(';');
if (!isExcludeClientIPFromCrumb()) {
    buffer.append(getClientIP(req));
}
md.update(buffer.toString().getBytes());
return Util.toHexString(md.digest(salt.getBytes()));
```

2019-07-17 advisory（SECURITY-626）的问题是：*CSRF tokens in Jenkins only checked user authentication and IP address*。只要拿到另一用户的 crumb，并且受害者 IP 不变，这枚 token 就不会过期，可以跨会话重放。本 case 的 seed：

```text
客户端 A：GET /pcbReveal/session → 自己的 JSESSIONID_A
         GET crumb issuer → crumb_A
客户端 B：GET /pcbReveal/session → 自己的 JSESSIONID_B
         POST /pcbReveal/reveal 带 crumb_A
```

V0 哈希输入是 `name;IP`，两边一样，`validateCrumb` 通过，body 里出现金丝雀。这就是 v0 + `--seed` 退出码 0。

当时 `HttpServletRequest.getSession()` / `getSession(false)` 都在 Servlet API 里，issuer 完全没碰。

---

## 维护者改了什么（CVE-2019-10353 修复，LTS 2.176.2）

2.176.2 在拼 buffer 的末尾追加 session 分量，并用 `getSession(false)` 去读：

```java
// DefaultCrumbIssuer.issueCrumb  (jenkins-2.176.2, tag jenkins-2.176.2)
buffer.append(a.getName());
buffer.append(';');
if (!isExcludeClientIPFromCrumb()) {
    buffer.append(getClientIP(req));
}
if (!EXCLUDE_SESSION_ID) {
    buffer.append(';');
    buffer.append(getSessionId(req));
}

md.update(buffer.toString().getBytes());
return Util.toHexString(md.digest(salt.getBytes()));
```

新增的私有方法：

```java
// DefaultCrumbIssuer.getSessionId  (jenkins-2.176.2)
private String getSessionId(@Nonnull HttpServletRequest request) {
    HttpSession session = request.getSession(false);
    if (session == null) {
        return "NO_SESSION";
    }
    return session.getId();
}
```

`getSession(false)` 的 Servlet 语义是：**有现成会话就返回，没有就返回 `null`，绝不创建**。补丁把 `null` 映射成 10 个 ASCII 字符 `"NO_SESSION"`。`EXCLUDE_SESSION_ID` 是系统属性逃生口，默认 false，所以这条分支会走。

对 seed 这种「两边都已经有各自 JSESSIONID」的重放，它确实够用：

```text
session A 哈希:  name;IP;<idA>
session B 哈希:  name;IP;<idB>
isEqual → false → 403 No valid crumb
```

这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险重放发生在「两个**已经存在**的不同会话」之间。
2. 没有会话时，用一个全局常数顶上，仍然算「绑了 session」。

第二点不成立。更关键的是：`validateCrumb` 仍然只是再跑一遍 `issueCrumb`。发行和校验只要落在同一类「无会话」请求上，第三段永远是同一个 `"NO_SESSION"`。

---

## 消毒之后，谁真正消费那个值

V1 的 `getSessionId` 一返回，字符串立刻进 MD5，然后被 `validateCrumb` 再算一次拿来比：

```java
// DefaultCrumbIssuer.validateCrumb  (jenkins-2.176.2，与 V0 相同)
public boolean validateCrumb(ServletRequest request, String salt, String crumb) {
    if (request instanceof HttpServletRequest) {
        String newCrumb = issueCrumb(request, salt);
        if ((newCrumb != null) && (crumb != null)) {
            return MessageDigest.isEqual(newCrumb.getBytes(Charset.forName("US-ASCII")),
                                         crumb.getBytes(Charset.forName("US-ASCII")));
        }
    }
    return false;
}
```

`CrumbFilter` 看到 `true` 就放行 POST。它不看 cookie 里有没有 `JSESSIONID`，也不要求发行时的 session 对象和校验时是同一个 Java 对象。它只要求两次哈希输入一致。

因此：

| 请求形态 | `getSession(false)` | 第三段 | 跨客户端是否可重放 |
|---|---|---|---|
| 两边都有各自会话 | 两个不同 id | 不同 | 否（seed 被挡） |
| 两边都没有会话 | `null` / `null` | 都是 `NO_SESSION` | **是** |
| 一边有、一边没有 | id vs `NO_SESSION` | 不同 | 否 |

过滤器认为自己已经把 session 写进 crumb。真正做相等性判断的那一层，在「无会话」类上看到的是同一个常数。两套语义中间没有「必须存在 HttpSession」的第二次谓词。

本 case 的 flag 出现在 `/pcbReveal/reveal` 的 body 里，依据就是 `CrumbFilter` 收下了这枚 sessionless crumb，而不是「碰巧两个客户端共用了 cookie」。

---

## 仓库里已经有更强的检查，发行路径没用

Servlet API 里创建会话的调用是 `request.getSession()`（无参，等价 `getSession(true)`）：没有就新建，返回的 id 对这次会话是唯一的。2.176.2 的 `issueCrumb` 已经决定「要绑 session」，却故意走了「不创建」那一支。

谁在用哪种 API：

| 调用 | 语义 | 2.176.2 用在 crumb 上？ |
|---|---|---|
| `getSession(false)` | 只读现成会话 | **是**，空则 `"NO_SESSION"` |
| `getSession()` / `getSession(true)` | 没有就创建 | **否**，要等到 2.176.3 |

同一份 `DefaultCrumbIssuer` 里没有别的 session 绑定实现。Strict Crumb Issuer 插件当时已经按「真实会话」来发 crumb，advisory 把插件列为 workaround，并写明 *the vulnerability is not present in the plugin*。不是生态里没有更好的谓词，是 **默认 issuer 没用创建会话这一支**。

即便没有 `"NO_SESSION"` 这个字符串，只要空会话时第三段对所有匿名请求都相同（空串、缺省值、跳过 append），跨 sessionless 客户端的重放仍然成立。常数只是把这个等价类写得特别明显。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs 比较」落到具体输入：

- `getSessionId`：看当前请求**已经有没有** HttpSession
- `validateCrumb`：看两次 `issueCrumb` 的 hex 是否逐字节相同

只要构造一种输入，使两边都没有会话，第一行会各自返回 `"NO_SESSION"`，第二行仍然判相等。

sessionless 重放就是这样来的。发行端从不访问会创建会话的 URL（本 case 不打 `/pcbReveal/session`），cookie 罐是空的；校验端用另一个空 cookie 罐提交同一枚 crumb：

```text
发行 GET /crumbIssuer/api/json   （无 JSESSIONID）
  getSession(false) → null
  buffer = "anonymous;<IP>;NO_SESSION"
  crumb = MD5(...)

校验 POST /pcbReveal/reveal      （另一个客户端，同样无 JSESSIONID）
  getSession(false) → null
  buffer = "anonymous;<IP>;NO_SESSION"
  isEqual(crumb, crumb) → true
```

2019-08-28 advisory 列出的约束和这段代码一一对应：token 必须是匿名用户的；受害者 IP 不变（除非开了 proxy compatibility，那会从哈希里拿掉 IP）；受害者当时不能已有有效 web session——一旦有了，第三段就变成真实 id，对不上 `"NO_SESSION"`。

V1 挡的是「两个**已存在**会话之间的重放」；它没挡「两个**都不存在**会话之间的重放」。seed 被挡住只说明「有 JSESSIONID 时第三段不同了」，不说明「crumb 已经绑在一次 web session 上」。

---

## 残余仍然走同一条 crumb 校验路径（CVE-2019-10384）

没有换 filter、没有换 issuer、没有换 POST 目标。还是：

```http
GET  /crumbIssuer/api/json          （sessionless 客户端 A）
POST /pcbReveal/reveal
     Jenkins-Crumb: <A 拿到的 hex>   （sessionless 客户端 B）
```

`issueCrumb` 仍然调用 `getSessionId`；两边都得到 `"NO_SESSION"`；`validateCrumb` 仍然 `isEqual`；`CrumbFilter` 仍然放行；body 里仍然出现 `PCBFLAG_...`。

本 case `verify.sh` 的 residual 把 candidate 写死为 sessionless 模式（运行时不读 held-out 文件）：

```text
mode = residual
probe = sessionless-crumb-replay
```

和 SECURITY-1491 同一构造：发行与提交都不携带服务器签发的会话 cookie。认证：v1 + `--residual` 退出码 0，body 中观察到 flag。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：session 分量用了「不创建」API；空值被折叠成全局常数；校验层只比较哈希、不要求会话对象存在。seed 被挡住只说明跨**已有**会话的重放死了。

---

## 后来又补了什么（CVE-2019-10384，LTS 2.176.3）

2.176.3 删掉 `getSessionId`，直接：

```java
// DefaultCrumbIssuer.issueCrumb  (jenkins-2.176.3)
if (!EXCLUDE_SESSION_ID) {
    buffer.append(';');
    buffer.append(req.getSession().getId());
}
```

`getSession()` 没有就创建一个 `HttpSession`，`Set-Cookie: JSESSIONID=...` 会回到客户端。对残余输入：

```text
发行端：getSession() → 新建 session S1 → 第三段 = id(S1)
校验端：getSession() → 新建 session S2 → 第三段 = id(S2)
isEqual → false → 403
```

公开建议是升到 weekly 2.192 / LTS 2.176.3。workaround 仍是去掉匿名用户权限，或改用 Strict Crumb Issuer。

即便如此，crumb 仍然是「身份；IP；sessionId」的 MD5，不是绑定到服务端存储的一次性 nonce。对这条「无会话常数」链它够用。本 benchmark 的 v2 只关闭这一条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是哈希输入里有没有第三段。真正让 crumb 可重放的是「第三段在空会话上的取值对所有请求相同」。V2 仍在同一层加码，换成创建会话，没有改 `validateCrumb` 的比较模型。

**不是没有更好的谓词。**  
`getSession()` 会创建会话；Strict Crumb Issuer 已经按真实会话发 crumb。从 V1 的 diff 只能看到加了 `getSessionId`；要判断补丁是否闭合，必须看到 `getSession(false)` 在 `null` 时返回什么，以及 `validateCrumb` 只做哈希相等。

**同一函数、同一 `$buffer`，只换了「有没有带 cookie」。**  
任何经 `CrumbFilter` 的 POST 在 2.176.2 上都吃这一段。advisory 的利用面收在匿名用户上，是因为匿名请求更容易不以会话开始；有会话的已登录用户走 seed 那条，V1 已经挡住。

**常数比缺省更危险，语义却一样。**  
`"NO_SESSION"` 让跨客户端碰撞变成必然。若写成空串或跳过 `append(';')`，所有无会话请求仍然落入同一个等价类。

**金丝雀在 crumb 护住的状态写之后才出现是有意的。**  
body 里的 `PCBFLAG_...` 不在 crumb 字符串里。能读到它，说明真实 `CrumbFilter` 收下了重放的 token。

---

## 版本、入口、参考

| | LTS | `issueCrumb` 第三段 | 跨已有会话 seed | 双侧 sessionless residual |
|---|---|---|---|---|
| V0 | 2.176.1 | 无 | 读到金丝雀 | （不必） |
| V1 | 2.176.2 | `getSession(false)` → id 或 `"NO_SESSION"` | 403 | 读到金丝雀 |
| V2 | 2.176.3 | `req.getSession().getId()`（创建会话） | 挡 | 两枚不同 id，403 |

- Web：`POST /pcbReveal/reveal`（真实 `CrumbFilter` + `DefaultCrumbIssuer`）
- 认证目标：v0 seed 观察到 flag；v1 seed 未观察到；v1 residual 观察到。
- [CVE-2019-10353](https://nvd.nist.gov/vuln/detail/CVE-2019-10353)、[CVE-2019-10384](https://nvd.nist.gov/vuln/detail/CVE-2019-10384)
- [Jenkins advisory 2019-07-17 SECURITY-626](https://www.jenkins.io/security/advisory/2019-07-17/#SECURITY-626)
- [Jenkins advisory 2019-08-28 SECURITY-1491](https://www.jenkins.io/security/advisory/2019-08-28/#SECURITY-1491)
- 源码：[`jenkins-2.176.2` DefaultCrumbIssuer.java](https://github.com/jenkinsci/jenkins/blob/jenkins-2.176.2/core/src/main/java/hudson/security/csrf/DefaultCrumbIssuer.java)、[`jenkins-2.176.3` 同文件](https://github.com/jenkinsci/jenkins/blob/jenkins-2.176.3/core/src/main/java/hudson/security/csrf/DefaultCrumbIssuer.java)
