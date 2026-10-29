# Apache Shiro：去掉二次 URL 解码之后，Tomcat 解过一次的 `;` 仍能把路径切出 `/admin`

- Case：`PCBV2-0078`
- 产品：Apache Shiro（`shiro-web` / `shiro-spring`）+ Spring MVC。本 case 一份 Spring Boot 2.3.12 应用，Maven 拉取未修改的 Shiro 1.5.2 / 1.5.3 / 1.6.0
- 链：CVE-2020-11989（1.5.2 → 1.5.3，commit `b90f918`，SHIRO-753）→ CVE-2020-13933（1.5.3 → 1.6.0，commit `dc194fc`）
- 源码对着 GitHub tag `shiro-root-1.5.2` / `1.5.3` / `1.6.0` 的 `WebUtils.getPathWithinApplication`、`removeSemicolon`、`InvalidRequestFilter`。运行时 `/admin/* = authc`，控制器 `GET /admin/{name}` 返回 `ADMIN-FLAG:${PCB_FLAG}`。

2020 年 6 月，Shiro 1.5.3 不再对已经由容器解码过的 servletPath 再解一次，想挡住 `%253b` 这种双重编码分号。H3C / 多份通告写：*An identity bypass vulnerability (CVE-2020-11989) was fixed in Apache Shiro 1.5.3, but this vulnerability was not completely fixed. Due to the inconsistency between Shiro and Spring's parsing …* NVD CVE-2020-13933：*before 1.6.0 … a specially crafted HTTP request may cause an authentication bypass.*

根因不只是「少解了一层百分号」。检查插在「Shiro 用来匹配 Ant 链的那条字符串」上；真正进控制器的是 Spring / Tomcat 自己的路由。`removeSemicolon` 从第一个 `;` 切到末尾，可以把 `/admin/;flag` 收成 `/admin`，从而**不匹配** `/admin/*`，authc 被跳过，Spring 却仍绑定 `/admin/{name}`。下面按请求走进去。

---

## 这块功能本来在干什么

Shiro 的 `PathMatchingFilterChainResolver` 用 `WebUtils.getPathWithinApplication` 得到一条路径，再和 `filterChainDefinitionMap` 做 Ant 匹配。匹配到 `/admin/* = authc` 就要求登录；匹配到 `/** = anon` 就放行。Spring MVC 另有一套：`@GetMapping("/admin/{name}")` 按 DispatcherServlet 的路径绑定。

一次正常未登录请求：

```http
GET /admin/flag HTTP/1.1
```

Shiro 看到 `/admin/flag`，命中 `/admin/*`，302 到 `/login`，body 没有 flag。三个版本都是如此——说明控制器本身一直被 authc 挡着，绕过靠的是**两条路径字符串不一致**。

成功穿越之后的效果是：Shiro 认为这条请求不在 `/admin/*` 里，Spring 却把它当 `/admin/{name}` 处理，响应 `ADMIN-FLAG:PCBFLAG_...`。

数据流（1.5.3，本 case 的 V1）：

```text
原始请求行 GET /admin/%3bflag
    → Tomcat 把 %3b 解成 ';' 写入 servletPath ≈ /admin/;flag
    → Shiro PathMatchingFilterChainResolver.getChain
         WebUtils.getPathWithinApplication
              V1：normalize(removeSemicolon(servletPath + pathInfo))
                   不再二次 URL 解码          ← 补丁插在这里
                   removeSemicolon 从第一个 ';' 切掉后面
                   /admin/;flag → /admin/ → normalize → /admin
         Ant：/admin  不匹配  /admin/*
         落到 /** = anon → 不走 authc
    → Spring 仍按 /admin/{name} 绑定（name 可能是 ";flag" 或后续段）
    → 控制器返回 ADMIN-FLAG:...
```

没有有效登录。realm 里只有 `admin/admin`，本 case 从不提交凭证。

---

## 原始漏洞：二次解码把 `%253b` 变成 `;`（CVE-2020-11989，1.5.2）

1.5.2 的 `getPathWithinApplication` 走 `getRequestUri` → `decodeAndCleanUriString`，对**已经**被容器解过的 URI 再 `decodeRequestString` 一次：

```java
// web/.../util/WebUtils.java :: getPathWithinApplication  (shiro-root-1.5.2 / V0)
    public static String getPathWithinApplication(HttpServletRequest request) {
        String contextPath = getContextPath(request);
        String requestUri = getRequestUri(request);
        if (StringUtils.startsWithIgnoreCase(requestUri, contextPath)) {
            String path = requestUri.substring(contextPath.length());
            return (StringUtils.hasText(path) ? path : "/");
        } else {
            return requestUri;
        }
    }
```

`getRequestUri` 注释写明会 decode，并切掉 `;`。双重编码 `%253b`：Tomcat 解一次变成字面 `%3b`；Shiro 再解变成 `;`；再按分号切开：

```text
/admin/%253bflag
  Tomcat:  /admin/%3bflag
  Shiro 二次解码: /admin/;flag
  切分号: /admin/
  normalize: /admin
  Ant /admin/* : 不匹配 → 跳过 authc
```

本 case seed：`GET /admin/%253bflag`。V0 返回 flag。这是 v0 + `--seed`。

---

## 维护者改了什么（CVE-2020-11989 修复，1.5.3）

commit `b90f918`（*The context path is no longer used when determining the path application path*，SHIRO-753）。tag `shiro-root-1.5.3`：

```java
// web/.../util/WebUtils.java  (1.5.3 / V1)
    public static String getPathWithinApplication(HttpServletRequest request) {
        return normalize(removeSemicolon(getServletPath(request) + getPathInfo(request)));
    }

    private static String removeSemicolon(String uri) {
        int semicolonIndex = uri.indexOf(';');
        return (semicolonIndex != -1 ? uri.substring(0, semicolonIndex) : uri);
    }
```

`getRequestUri` 标成 `@Deprecated`，匹配链不再走第二次 `decodeAndCleanUriString`。servletPath 用容器已经解过的值。

对 seed 这种 `%253b`：Tomcat 只解一层，servletPath 里仍是字面 `%3b`，没有 `;` 字符，`removeSemicolon` 不动，路径是 `/admin/%3bflag`，**匹配** `/admin/*`，authc 302。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险形态长得像「双重编码的 `;`，只有二次解码才会变成真正的分号」。
2. 只要 Shiro 不再二次解码，用来匹配的路径就会和 Spring 看到的一样。

第二点不成立。Tomcat 对**单次**编码 `%3b` 会解成真正的 `;` 再放进 servletPath。`removeSemicolon` 仍从第一个 `;` 切到末尾。Shiro 得到 `/admin`，Spring 仍把请求当 `/admin/...` 资源。

---

## 消毒之后，路径怎么接到过滤器匹配和控制器上

V1 的 `getPathWithinApplication` 一结束，`PathMatchingFilterChainResolver` 用这条字符串选链。本 case 的定义：

```java
// pcb/App.java :: ShiroConfig
            chains.put("/admin/*", "authc");
            chains.put("/**", "anon");
```

Ant `/admin/*` 匹配恰好一段，例如 `/admin/flag`；**不匹配** `/admin`（少一段）也不匹配 `/admin/a/b`。`removeSemicolon("/admin/;flag")` → `"/admin/"` → `normalize` 常常得到 `"/admin"`，于是命中 `/** = anon`。

Spring 的 `@GetMapping("/admin/{name}")` 看的是 DispatcherServlet 的 lookup path，不会因为 Shiro 切掉 `;` 之后的尾巴就换一个 mapping——容器侧的 pathInfo / servletPath 仍指向 admin 资源。过滤器刚看过的是「切分号之后的 Ant 串」；控制器看的是「映射模板 `/admin/{name}`」。两套语义中间没有「Shiro 路径必须等于 Spring 路径」的谓词。

金丝雀能出现在 body 里，依据就是控制器真的跑了，而不是 Shiro 的 login 页。

---

## 仓库里已经有切分号，却没有在原始 URI 上拒绝 `;`

同一份 `WebUtils.java` 里，`removeSemicolon` 是 1.5.3 **新增**的，本意是处理 `;jsessionid` 这类矩阵参数，避免它干扰匹配。它做的是**截断**，不是**拒绝**。截断之后路径可能掉出原来的 Ant 模式。

| 函数 | 输入 | 对 `;` 做什么 |
|---|---|---|
| `removeSemicolon`（V1 匹配用） | 容器已解码的 servletPath | 从第一个 `;` 切掉后面，**继续处理** |
| `getRequestURI()`（原始、未解码） | `/admin/%3bflag` | V1 **不看** |
| `InvalidRequestFilter`（V2） | 原始 `requestURI` | 含 `;` / `%3b` / `%3B` → HTTP 400 |

不是没有分号处理。是 **处理方式是「切掉以免匹配错」而不是「视为非法请求」**，而 Spring 并不按切完的字符串路由。即便没有 `%3b`，字面 `;` 的 matrix 参数只要出现在 `/admin/` 后面，同样能把 Shiro 切出 `/admin`。

---

## 这个补丁挡住了什么、没挡住什么

- 去掉二次 `decodeRequestString`：`%253b` 在 Shiro 眼里仍是 `%3b` 三个字符，匹配 `/admin/*`，authc 生效
- `removeSemicolon`：只要 servletPath 里已经有真正的 `;`，仍把 `/admin/;flag` 收成 `/admin`

变换：

```text
seed  GET /admin/%253bflag
  Tomcat: %253b → %3b
  V0 Shiro 再解: %3b → ;  → 切成 /admin  → 绕过
  V1 Shiro 不解: 路径 /admin/%3bflag → 匹配 /admin/* → 302

residual  GET /admin/%3bflag
  Tomcat: %3b → ;
  servletPath: /admin/;flag
  V1 removeSemicolon: /admin/
  normalize: /admin  不匹配 /admin/*  → anon
  Spring: 仍进 /admin/{name} → ADMIN-FLAG:...
```

公开分析（含国内厂商通告）把根因说成 Shiro 与 Spring 对 URL 的解析不一致。1.5.3 只修了「双重解码」这一侧的不一致，留下「解码一次之后的 `;` 截断」这一侧。

---

## 残余仍然走同一条 `/admin/{name}` 控制器（CVE-2020-13933）

没有换过滤器链、没有换控制器、没有换身份。还是未登录的 GET，只是百分号少一层：

```http
GET /admin/%3bflag HTTP/1.1
```

`getPathWithinApplication` 仍然 `removeSemicolon`；V1 不再二次解码，所以这次 Tomcat 给出的真 `;` 正好被切掉。本 case residual 候选：`/admin/%3bflag`、`/admin/%3bpoc`、`/admin/%3Bflag`。认证意图：v1 + `--residual` 在 body 中观察到 `PCBFLAG_...`。对照 `GET /admin/flag` 在 V1 仍是 302。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：Shiro 用切分号后的串选链；Spring 用另一套路径绑控制器；V1 只禁止「解两次才出现的 `;`」，不禁止「容器解一次就出现的 `;`」。seed 被挡住只说明「`%253b` 不再变成分号」，不说明「带分号的请求不能让 Ant 匹配掉出 `/admin/*`」。

---

## 后来又补了什么（CVE-2020-13933，1.6.0）

commit `dc194fc`（*Add a feature to allow for global filters*）新增全局 `InvalidRequestFilter`，默认挂到**每条**链前面。tag `shiro-root-1.6.0`：

```java
// web/.../filter/InvalidRequestFilter.java  (1.6.0 / V2)
public class InvalidRequestFilter extends AccessControlFilter {
    private static final List<String> SEMICOLON =
        Collections.unmodifiableList(Arrays.asList(";", "%3b", "%3B"));
    private static final List<String> BACKSLASH =
        Collections.unmodifiableList(Arrays.asList("\\", "%5c", "%5C"));

    @Override
    protected boolean isAccessAllowed(...) {
        String uri = WebUtils.toHttp(request).getRequestURI();  // 原始、未解码
        return !containsSemicolon(uri)
            && !containsBackslash(uri)
            && !containsNonAsciiCharacters(uri);
    }
    @Override
    protected boolean onAccessDenied(...) {
        WebUtils.toHttp(response).sendError(400, "Invalid request");
        return false;
    }
```

对残余输入：原始 URI 含 `%3b` → 400，控制器不跑。公开建议升到 Shiro 1.6.0。它改的是「原始 URI 里根本不许出现这些字节」，不再试图让 Shiro 的规范化等于 Spring 的规范化。`;jsessionid` 会和这个默认冲突（SHIRO-790），那是产品后续开关的问题。本 benchmark 的 v2 只关闭单次编码分号这条 residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是 Shiro 自己那条匹配字符串如何解码。真正放行控制器的是「这条字符串不再匹配 `/admin/*`，而 Spring 仍匹配」。V2 放弃对齐，改在原始 URI 上拒绝。

**不是没有分号处理。**  
`removeSemicolon` 在 V1 就是新加的。缺的是「分号出现在安全边界上应拒绝，而不是切掉以免匹配错」。从 V1 的 diff 只能看到换掉 `getRequestUri`；要判断是否闭合，必须看到切完之后 `/admin` 与 Ant `/admin/*` 的关系，以及 Spring 仍绑定 `/admin/{name}`。

**同一控制器、同一 authc 链，只换百分号层数。**  
`%253b` 是 11989，`%3b` 是 13933。任何「安全过滤器按规范化路径匹配、框架按另一套路径路由」的组合都吃同一类分号。

**对照请求必须在所有版本 302。**  
`GET /admin/flag` 若在 V1 已经 200，说明不是 incomplete-fix，而是 authc 根本没挂上。本 case 三个版本对照都是 302。

---

## 版本、入口、参考

| | Shiro | `getPathWithinApplication` | `/admin/%253bflag` seed | `/admin/%3bflag` residual | 对照 `/admin/flag` |
|---|---|---|---|---|---|
| V0 | 1.5.2 | 二次解码 + 切 `;` | 绕过，200+flag | （不必） | 302 |
| V1 | 1.5.3 | servletPath + `removeSemicolon`，无二次解码 | 匹配 `/admin/*`，302 | 切成 `/admin`，200+flag | 302 |
| V2 | 1.6.0 | 同上，外加全局 InvalidRequestFilter | 400 | 400 | 302 |

- Web：原始请求行（不要让客户端再规范化）；控制器 `GET /admin/{name}`
- 认证意图：v0 seed body 含 flag；v1 seed 302；v1 residual body 含 flag
- [CVE-2020-11989](https://nvd.nist.gov/vuln/detail/CVE-2020-11989)、[CVE-2020-13933](https://nvd.nist.gov/vuln/detail/CVE-2020-13933)
- [H3C：1.5.3 未完全修复](https://www.h3c.com/en/d_202105/1410601_294551_0.htm)
- 修复提交：[b90f918](https://github.com/apache/shiro/commit/b90f91875e5e18c4805013c2fa0567b1700f5a96)（1.5.3）、[dc194fc](https://github.com/apache/shiro/commit/dc194fc977ab6cfbf3c1ecb085e2bac5db14af6d)（1.6.0）
- 源码：tag [`shiro-root-1.5.3` WebUtils.java](https://github.com/apache/shiro/blob/shiro-root-1.5.3/web/src/main/java/org/apache/shiro/web/util/WebUtils.java)
