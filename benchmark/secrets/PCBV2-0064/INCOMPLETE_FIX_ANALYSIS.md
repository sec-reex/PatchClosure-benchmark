# OFBiz：XML-RPC 入口拆了，checkLogin 仍把 requirePasswordChange 当成非 error

- Case：`PCBV2-0064`
- 产品：Apache OFBiz（ERP / 电商套件，Java）
- 链：CVE-2023-49070（release18.12 `7935a146` → `c59336f6`「Remove xml rpc」）→ CVE-2023-51467（`c59336f6` → `1dcfa071`，OFBIZ-12873）
- 源码对着 `ofbiz-framework` commit `c59336f604f503df5b2f7c424fd5e392d5923a27`（V1）和 `1dcfa071804a`（V2）的 `framework/webapp/.../LoginWorker.java`：`checkLogin`、`login`。运行时是完整 OFBiz + ControlServlet，经 HTTPS 打真实 `<security auth="true"/>` 的请求。官方 git tag `18.12.06`–`18.12.11` 从未发布，版本号按发行说明对应到这些 commit。

2023 年 12 月 4 日，Apache 用删掉 webtools `xmlrpc` request-map 的方式修 CVE-2023-49070（预认证 XML-RPC 反序列化）。SonicWall 在验证补丁时发现：带 `requirePasswordChange=Y` 的请求仍能绕过 `LoginWorker.checkLogin`。NVD CVE-2023-51467 最初写成 SSRF，后来改成认证绕过导致 RCE。Zscaler / Qualys / 0daylabs 都写明 **49070 的修复没有动登录谓词**。

根因不只是「少改了一个返回值」。检查（V1）插在「xmlrpc 这条路由还在不在」上；真正放行受保护视图的是 `checkLogin == "success"`。`login()` 在 userLogin 失败时仍可返回 `"requirePasswordChange"`，而 `checkLogin` 只把 `"error"` 当失败。下面按一次受保护请求走进去、V1 删了什么、检查之后谁去读那个返回值、仓库里已经有什么更严的失败路径、残余怎么用同一套参数打到 auth=true 的页面。

---

## 这块功能本来在干什么

OFBiz 每个 webapp 的 `controller.xml` 把 URI 映射到事件。`<security auth="true"/>` 的请求在跑业务事件之前先走 `LoginWorker.checkLogin`。成功才继续；否则进登录页。本 case 的残余入口是：

```http
GET /pcbcanary/control/flag?USERNAME=Y&PASSWORD=Y&requirePasswordChange=Y
```

`pcbcanary` 是平台加的金丝雀组件：只有 `checkLogin` 返回 `"success"` 时 Groovy 事件才写出 `${PCB_FLAG}`。设计意图：没有合法会话就不能看这个视图。成功穿越之后的效果是 **未认证调用者拿到本应登录后才有的响应体**。

seed 走的是另一条 URI：`/webtools/control/xmlrpc`。V0 上这条 request-map 还在，ControlServlet 会把它交给 XML-RPC 处理器（本 case **不**做反序列化，只看路由是否还在）。V1 删掉 map 之后，任何方法都会得到 `Unknown request [xmlrpc]`。

数据流（残余，登录谓词）：

```text
HTTP(S) GET /pcbcanary/control/flag?...
    → RequestHandler 找到 auth=true 的 request-map
    → LoginWorker.checkLogin
         取 USERNAME / PASSWORD / TOKEN（参数或 session）
         若 username==null 或 (password==null 且 token==null)
            或 login() 返回 "error"
            → return "error"          ← 唯一的失败门
         否则 return "success"
    → login()
         requirePasswordChange = "Y".equals(request.getParameter(...))
         userLogin 服务失败
         V1：return requirePasswordChange ? "requirePasswordChange" : "error"
    → checkLogin 看见的不是 "error" → "success"
    → 金丝雀事件写出 PCBFLAG_...
```

没有事先登录。`requirePasswordChange` 是**请求参数**，不是库里用户行上的标志。

---

## 原始漏洞：预认证 XML-RPC（CVE-2023-49070，V0 = 7935a146）

V0 是「Remove xml rpc」的父提交。webtools 的 `controller.xml` 里仍有 `xmlrpc` request-map，指向 XML-RPC 事件。历史上这条通道可以在未登录时打到不安全的反序列化。本 case 的 seed 只观测通道是否还活着：

```text
GET /webtools/control/xmlrpc?USERNAME=Y&PASSWORD=Y&requirePasswordChange=Y
```

- V0：不是 `Unknown request` → 路由仍在（seed 打穿的是「端点活着」这一效果）
- V1：`Unknown request [xmlrpc]` → 路由没了

同时，V0 上 `LoginWorker.login` 的失败返回已经是 `requirePasswordChange ? "requirePasswordChange" : "error"`。认证绕过**早于** 49070 就存在；49070 只是当时被拿来打 XML-RPC 的那条交付面。Qualys 写：*eliminating the XML RPC code proved to be an ineffective patch*。

---

## 维护者改了什么（CVE-2023-49070 修复，V1 = c59336f6）

commit `c59336f604` 标题是 `Remove xml rpc (#630)`。它从 webtools 的 controller 里删掉 xmlrpc request-map 及相关库，**不修改** `LoginWorker.java`。V1 上 `checkLogin` / `login` 与 V0 同构。

`checkLogin`（约 L323–381）里，未登录时的门是：

```java
// LoginWorker.java :: checkLogin
//   (commit c59336f6, 约 L342–366)
            if (username == null
                    || (password == null && token == null)
                    || "error".equals(login(request, response))) {

                request.removeAttribute("_LOGIN_PASSED_");
                session.setAttribute("_PREVIOUS_REQUEST_", request.getPathInfo());
                ...
                return "error";
            }
        }
        ...
        return "success";
```

三端或：用户名为 null、口令与 token 都为 null、**或者** `login()` 的返回值字符串等于 `"error"`。其它任何返回值——包括 `"requirePasswordChange"`、包括 `"success"`——都让整段 if 为假，函数落到 `"success"`。

`login()` 在 userLogin 服务失败时（约 L601–605）：

```java
        } else {
            Map<String, String> messageMap = UtilMisc.toMap("errorMessage", (String) result.get(ModelService.ERROR_MESSAGE));
            String errMsg = UtilProperties.getMessage(resourceWebapp, "loginevents.following_error_occurred_during_login", messageMap, UtilHttp.getLocale(request));
            request.setAttribute("_ERROR_MESSAGE_", errMsg);
            return requirePasswordChange ? "requirePasswordChange" : "error";
        }
```

`requirePasswordChange` 来自（约 L444）：

```java
        boolean requirePasswordChange = "Y".equals(request.getParameter("requirePasswordChange"));
```

空用户名/空口令的早退（约 L445–447）同样是 `return requirePasswordChange ? "requirePasswordChange" : "error"`。0daylabs 分析过空凭据向量；本 case residual 用**非空但非法**凭据，好走进 userLogin 失败分支而不是早退——V2 修的正是这条失败返回。

对 seed：xmlrpc map 已删除，`RequestHandler` 在安全检查**之前**就因未知请求失败，与 login 返回值无关。这就是 v1 + `--seed` 被挡住（在 xmlrpc 通道上）。

补丁默认了两件事：

1. 预认证危险只存在于 XML-RPC 那条 request-map。
2. 删掉 map 之后，`checkLogin` 对受保护视图仍然够用。

第二点不成立。`checkLogin` 从来不只为 XML-RPC 服务；所有 `auth=true` 的请求都走它。

---

## 检查之后，谁真正放行那个视图

V1「检查」的是 controller 里还有没有 `xmlrpc`。`RequestHandler` 对未知 URI 直接错误页。对**仍然存在**的 `auth=true` map，它接着调用 `checkLogin`。`checkLogin` 只问 `login()` 是不是返回了字面 `"error"`。

`login()` 在失败路径上问的是请求参数 `requirePasswordChange`，不是「这次认证是否成功」。userLogin 服务已经返回 ERROR、`_ERROR_MESSAGE_` 已经写上，函数却可以把 `"requirePasswordChange"` 交回去。`checkLogin` 把这个字符串当成「不是 error」，于是 `"success"`。ControlServlet 接着跑业务事件。金丝雀 Groovy 看见的是一次成功的安全检查，不是一次改密流程。

空字符串的 USERNAME/PASSWORD 也值得单独说：`request.getParameter` 对 `USERNAME=` 返回 `""` 而不是 `null`。`username == null` 为假。这就是 Qualys 测试用例 1（空凭据 + `requirePasswordChange=Y`）能绕过的原因。本 case 用非空非法凭据（`USERNAME=Y&PASSWORD=Y`），走的是失败返回那一行，不依赖 null vs empty 的区别。两条向量在 V1 上都让 `login()` 返回非 `"error"`。

0daylabs 把 `checkLogin` 读成：只要用户名、口令、token「不是 null」，并且 `login()` 返回值不是 `"error"`，就当认证成功。V1 同时满足这两个口：参数有值（哪怕是 `Y` / 空串），返回值被三元表达式改成了 `"requirePasswordChange"`。Apache 在 18.12.11 发行说明里把这件事记成 OFBIZ-12873；oss-security 2023-12-26 线程同步了升级到 18.12.11 的公告。公开利用后来把绕过接到 `ProgramExport` 等 Groovy 端点做成 RCE——那是效果放大，不是另一套登录谓词。本 case 停在金丝雀视图，只证明 `checkLogin` 已经返回 `"success"`。

---

## 仓库里已经有更严的失败返回，checkLogin 没用上

`login()` 里大量其它错误已经 `return "error"`：租户 delegator 失败、默认 delegator 失败、等等（V1 源码 L483、L504 附近）。失败时「一律 error」这条习惯已经在同一函数里。唯独 `requirePasswordChange` 参数能把失败改写成另一种字符串。

`checkLogin` 的门是 `"error".equals(...)`，不是「必须是 success」的白名单，也不是「requirePasswordChange 视为未登录」。OFBiz 本来就有改密视图；把「需要改密」和「认证失败」合成同一个非 error 返回值，检查方无法区分。

V2 没有改 `checkLogin` 的三端或（仍只认 `"error"`），而是把 `login()` 失败路径改成永远 `"error"`。更强的谓词——失败就是 error——早就写在相邻分支里，V1 的 xmlrpc 删除根本没碰到它。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs 放行」落到具体代码：

- V1 的 49070 修复：webtools controller 里没有 `xmlrpc` 这个名字
- `checkLogin`：`login()` 返回值是不是字面 `"error"`

seed 用的是第一个。残余用的是第二个。参数变换：

```text
USERNAME=Y
PASSWORD=Y
requirePasswordChange=Y
```

`getParameter("USERNAME")` → `"Y"`（非 null）  
`getParameter("PASSWORD")` → `"Y"`（非 null）  
`login()` → userLogin 失败 → `"requirePasswordChange"`  
`"error".equals("requirePasswordChange")` → false  
`checkLogin` → `"success"`

没有编码层的变换。V1 **不改写**这些参数，只是 xmlrpc 路由不再消费它们。其它 `auth=true` 的 URI 照样消费。

公开 PoC（0daylabs / Indusface / SonicWall）还演示过空凭据：`USERNAME=&PASSWORD=&requirePasswordChange=Y`。那是早退分支。本 case 选非空非法凭据，对应 V2 实际改掉的那一行（L605）。两条都是同一谓词：`requirePasswordChange` 把失败变成非 error。

---

## 残余仍然让 checkLogin 返回 success（CVE-2023-51467）

没有换 `LoginWorker`、没有换 `auth=true` 语义。URI 从 `/webtools/control/xmlrpc` 换成任意仍存在的受保护请求。本 case：

```http
GET /pcbcanary/control/flag?USERNAME=Y&PASSWORD=Y&requirePasswordChange=Y
```

xmlrpc 删除看不见这条 URI。`checkLogin` 调用 `login()`；V1 那一行三元表达式返回 `"requirePasswordChange"`；门落到 `"success"`；金丝雀事件写出 `PCBFLAG_...`。

这与 seed **不是**同一条 request-map。seed 的效果是「xmlrpc 端点还在」；残余的效果是「受保护视图当已登录」。49070 修的是前者，从未声称修过后者。公开分析把 51467 称为 49070 的不完整修复，依据是：**当时用来打 RCE 的认证弱点还在**，只是交付面从 XML-RPC 换成了任意 auth=true 端点（再结合 ProgramExport 等）。本 case 把效果收到金丝雀视图，不演示 RCE。

SonicWall / Zscaler：验证 49070 补丁时发现仍可绕过认证。Apache 发行说明 18.12.11 / OFBIZ-12873。本文按 **c59336f6 的 LoginWorker 源码 + 公开 writeup** 推导。case.json 记录过真实 OFBiz 上的门控，非本轮 compose。

所以残余不是「xmlrpc 删得不干净」，而是检查插错了层：删通道，没有改「什么算登录失败」。

---

## 后来又补了什么（CVE-2023-51467，V2 = 1dcfa071）

OFBIZ-12873 把失败返回改成 `"error"`（并伴随若干 `null` 检查改成 `UtilValidate.isEmpty` 的 commit，`d8b097f` / `f10b42fa`）：

```java
// LoginWorker.java :: login  失败分支
//   (commit 1dcfa071, 约 L605)
            return "error";
```

不再读 `requirePasswordChange` 来决定返回值。`checkLogin` 的 `"error".equals(login(...))` 为真，返回 `"error"`，金丝雀视图不跑。公开建议是升级到 18.12.11。

即便如此，`checkLogin` 仍只把 `"error"` 当失败。后续还有 CVE-2026-45434 一类「改密流程 / 请求参数再绕过」的分析，说明这条返回值协议还会被追问。本 benchmark 的 v2 只关闭「失败时因 requirePasswordChange=Y 返回非 error」这一条。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是 xmlrpc 还在不在。真正放行受保护视图的是 `checkLogin` 对 `login()` 返回值的解释。V2 仍在 `login()` 里把失败统一成 `"error"`，没有把 `checkLogin` 改成白名单 `"success"`，也没有停止从请求里读 `requirePasswordChange`。

**不是没有更好的谓词。**  
同一 `login()` 里其它错误已经 `return "error"`。从 49070 的 diff 只能看到 controller.xml 删行；要判断补丁是否闭合，必须看到 `login()` L605 的三元表达式和 `checkLogin` 只认 `"error"`。

**同一谓词、两条 URI。**  
XML-RPC 只是当时的交付面。`requirePasswordChange=Y` 对所有走 `checkLogin` 的 `auth=true` 请求有效。删掉一个 map 不会让谓词消失。

**null 检查不是 empty 检查。**  
`USERNAME=` 得到 `""`。`== null` 为假。V2 的 `UtilValidate.isEmpty` 同时收掉这条空凭据向量。本 case residual 用非空非法凭据，专门打失败返回，不依赖这次 null/empty 差异。

**seed 的效果通道和残余不同，登录谓词在 V0/V1 上相同。**  
xmlrpc 在 V1 上死了，绕过在 V1 上还活着。要理解「不完整」，必须同时看被删的 map 和没改的 `LoginWorker`，不能只看 seed 在 V1 上失败。

**发行 tag 对不上 commit 时，以分支为准。**  
`release18.12.06` 到 `release18.12.11` 这些 git tag 从未推到 GitHub。NVD / 发行说明仍写 18.12.10 / 18.12.11。本 case 把 V1 钉在 `c59336f6`（Remove xml rpc）、V2 钉在 `1dcfa071`（OFBIZ-12873），并在 `case.yaml` 里写明这一点。分析登录谓词时读的是这些 commit 上的 `LoginWorker.java`，不是某个缺失的 tag 名字。

**返回值协议比路由表更稳。**  
request-map 可以删。`checkLogin` 对所有 `auth=true` 的 URI 仍是同一份字节。把「认证失败」编码成多种字符串、再只拒绝其中一种，等于把失败策略交给每一个 `login()` 分支去记。V1 删 xmlrpc 时一个分支都没改；V2 改的也只是把那个分支收回 `"error"`，而不是把 `checkLogin` 改成只接受 `"success"`。

---

## 版本、入口、参考

| | commit（release18.12） | xmlrpc map | `login()` 失败返回 | seed `/xmlrpc` | residual `requirePasswordChange=Y` |
|---|---|---|---|---|---|
| V0 | `7935a146` | 在 | `requirePasswordChange ? ... : "error"` | 路由活着 | 同样绕过（不必） |
| V1 | `c59336f6` | **删除** | **同上** | `Unknown request` | `checkLogin=success`，金丝雀出现 |
| V2 | `1dcfa071` | 仍无 | `"error"` | 挡 | `checkLogin=error`，无 flag |

- Web：seed `GET /webtools/control/xmlrpc`；residual `GET /pcbcanary/control/flag?USERNAME=Y&PASSWORD=Y&requirePasswordChange=Y`（OFBiz 会跳 HTTPS :8443）
- 源码：GitHub `apache/ofbiz-framework` commit `c59336f6` 的 `LoginWorker.java`（`checkLogin` L342、`login` L444 / L605）
- [CVE-2023-49070](https://nvd.nist.gov/vuln/detail/CVE-2023-49070)、[CVE-2023-51467](https://nvd.nist.gov/vuln/detail/CVE-2023-51467)
- [OFBIZ-12873](https://issues.apache.org/jira/browse/OFBIZ-12873)
- [18.12.11 release notes](https://ofbiz.apache.org/release-notes-18.12.11.html)
- [Zscaler ThreatLabz](https://www.zscaler.com/blogs/security-research/apache-ofbiz-authentication-bypass-vulnerability-cve-2023-51467)
- [Qualys](https://threatprotect.qualys.com/2023/12/27/apache-ofbiz-authentication-bypass-vulnerability-cve-2023-51467/)
- [0daylabs 分析](https://blog.0daylabs.com/2024/02/26/apache-ofbiz-authbypass-rce/)
- [oss-security 2023-12-26](https://www.openwall.com/lists/oss-security/2023/12/26/3)
