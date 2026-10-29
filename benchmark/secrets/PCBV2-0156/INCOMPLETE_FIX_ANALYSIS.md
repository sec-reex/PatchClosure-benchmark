# oauth2-proxy：GetRequestPath 去掉了 query，却仍从 X-Forwarded-Uri 取路径

- Case：`PCBV2-0156`
- 产品：oauth2-proxy（反向代理上的 OAuth2 / OIDC 门）。运行时是官方镜像 `quay.io/oauth2-proxy/oauth2-proxy:v7.11.0`，`--reverse-proxy` + `--skip-auth-route=^/foo/.*/bar$`，上游是内部 sidecar。不是抽出来的函数。
- 链：CVE-2025-54576 / GHSA-7rh7-c77v-6434（7.10.0 → 7.11.0）→ CVE-2026-40575 / GHSA-7x63-xv5r-3p2x（7.11.0 → 7.15.2，须配置 `--trusted-proxy-ip`）
- GHSA-7x63-xv5r-3p2x 原话：*OAuth2 Proxy may trust a client-supplied `X-Forwarded-Uri` header when `--reverse-proxy` is enabled … An attacker can spoof this header so OAuth2 Proxy evaluates authentication and skip-auth rules against a different path than the one actually sent to the upstream application.*

根因不只是「漏了一个 header」。检查插在「skip-auth 正则匹配哪一段 URI 字符串」上；真正转给上游的是 Go `http.Request` 自己的 path。V1 换了 `GetRequestPath` 想丢掉 query，但 `GetRequestPath` **先调用** `GetRequestURI`，而后者在 `ReverseProxy==true` 时优先返回客户端的 `X-Forwarded-Uri`。下面按请求走进去。

---

## 这块功能本来在干什么

oauth2-proxy 坐在上游前面：没 session 的请求被拉去登录；命中 `--skip-auth-route` 的路径直接放行。一次典型的「本该保护」的请求：

```http
GET /foo/critical_endpoint HTTP/1.1
Host: oauth2-proxy:4180
```

配置里有一条 skip：

```text
--skip-auth-route=^/foo/.*/bar$
```

意图是放行 `/foo/<任意一段>/bar` 这种健康检查，**不要**放行 `/foo/critical_endpoint`。`IsAllowedRequest` → `isAllowedRoute` → `isAllowedPath`：正则匹配成功就跳过鉴权，把请求原样转到 `--upstream`。

本 case 上游只在 `/foo/critical_endpoint` 返回 `${PCB_FLAG}`，其余路径返回 `public-ok`。成功穿越之后的效果是：**未登录请求打到受保护的上游路径，body 里出现金丝雀**。oauth2-proxy 是唯一的门；上游自己没有鉴权。

数据流：

```text
GET /foo/critical_endpoint[?... 或 X-Forwarded-Uri: ...]
    → OAuthProxy.IsAllowedRequest
         isAllowedRoute → isAllowedPath
              V0：GetRequestURI(req)     ← path + query；若 ReverseProxy 则可能是 X-Forwarded-Uri
              V1：GetRequestPath(req)    ← 对 GetRequestURI 的结果剥 query
              regex ^/foo/.*/bar$
         匹配 → 不查 session → ReverseProxy 到 upstream
              upstream 看的是 req.URL.Path = /foo/critical_endpoint
    → 200 + PCBFLAG_...
```

`IsAllowedRequest` 的完整短路是：

```go
func (p *OAuthProxy) IsAllowedRequest(req *http.Request) bool {
  isPreflightRequestAllowed := p.skipAuthPreflight && req.Method == "OPTIONS"
  return isPreflightRequestAllowed || p.isAllowedRoute(req) || p.isTrustedIP(req)
}
```

本 case 没有开 skip-preflight，也没有把 oracle IP 放进 `--trusted-ip`。唯一能让未登录请求到上游的，就是 `isAllowedRoute` → `isAllowedPath`。所以 residual 必须让那条 `^/foo/.*/bar$` 在 **GetRequestPath 的返回值**上为真，同时又让 upstream 看到 `/foo/critical_endpoint`。query seed 用 URI 后缀做到这一点；X-Forwarded-Uri residual 用另一份字符串做到这一点。

---

## 原始漏洞：正则打在「path + query」上（CVE-2025-54576，7.10.0）

7.10.0 的 `isAllowedPath`（tag `v7.10.0` `oauthproxy.go`）：

```go
func isAllowedPath(req *http.Request, route allowedRoute) bool {
  matches := route.pathRegex.MatchString(requestutil.GetRequestURI(req))
  ...
}
```

`GetRequestURI`（`pkg/requests/util/util.go`）在 `IsProxied` 时：

```go
func GetRequestURI(req *http.Request) string {
  uri := req.Header.Get("X-Forwarded-Uri")
  if !IsProxied(req) || uri == "" {
    uri = req.URL.RequestURI() // 保留 ?query
  }
  return uri
}
```

advisory GHSA-7rh7-c77v-6434 的例子和本 case seed 相同：

```text
配置：^/foo/.*/bar$
意图：只放行 /foo/something/bar
实际：GET /foo/critical_endpoint?param=/bar
      GetRequestURI = "/foo/critical_endpoint?param=/bar"
      正则 $ 锚在整段 URI 末尾，query 里的 /bar 让它匹配
```

上游忽略未知 query，仍按 path `/foo/critical_endpoint` 返回 flag。这就是 v0 + `--seed`。V0 上 `X-Forwarded-Uri` 同样能打，但 seed 只演示「query 被拿去匹配」这一条，因为那是 7.11.0 补丁明确改掉的调用。

---

## 维护者改了什么（CVE-2025-54576 修复，7.11.0）

7.11.0 只换了 `isAllowedPath` 调用的辅助函数，并**新增** `GetRequestPath`：

```go
# V0  7.10.0
matches := route.pathRegex.MatchString(requestutil.GetRequestURI(req))

# V1  7.11.0   （本 case 的目标）
matches := route.pathRegex.MatchString(requestutil.GetRequestPath(req))

# GetRequestPath（v7.11.0 pkg/requests/util/util.go）
func GetRequestPath(req *http.Request) string {
  uri := GetRequestURI(req)           // ← 仍然可能是 X-Forwarded-Uri
  if parsedURL, err := url.Parse(uri); err == nil {
    return parsedURL.Path             // 丢掉 query
  }
  if idx := strings.Index(uri, "?"); idx != -1 {
    return uri[:idx]
  }
  return uri
}
```

对 seed `GET /foo/critical_endpoint?param=/bar`、不带转发头：

```text
GetRequestURI  = /foo/critical_endpoint?param=/bar
GetRequestPath = /foo/critical_endpoint
regex ^/foo/.*/bar$  → 不匹配 → 要登录 → 403
```

这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. skip-auth 应该匹配的是「路径」，所以剥掉 `?` 就够了。
2. `GetRequestURI` 返回的那串已经是「这次请求的 URI」。

第二点在 `--reverse-proxy` 下不成立：那串优先是客户端可设的 `X-Forwarded-Uri`。更关键的是：匹配用的字符串和转给上游的 `req.URL.Path` **不是同一个值**；匹配通过之后，上游仍按真实 path 处理。

`isAPIPath` 在 V1 **继续**用 `GetRequestURI`。skip-auth 这条路换了 Path，API 前缀那条路没换——说明仓库里对「要不要带 query / 要不要信转发头」没有统一谓词。

`GetRequestPath` 的注释自己就写了两件互相打架的事：*returns the request URI or X-Forwarded-Uri if present and the request is proxied* **but always strips the query**。CVE-2025-54576 要修的是后半句；CVE-2026-40575 打的是前半句。7.11.0 把「剥 query」做成了 `GetRequestURI` 的包装，于是转发头信任被原样继承。

`IsProxied` 只看 request scope 里的 `ReverseProxy` 布尔——也就是启动参数 `--reverse-proxy`，**不是**「对端 IP 在代理网段」。本 case 三个版本都带这个 flag，因为 oauth2-proxy 作为独立反向代理的推荐部署就是这样。V1 没有任何「这个 X-Forwarded-Uri 是不是前置 nginx 写的」的判断。

---

## 消毒之后，这个路径怎么接到上游上

V1 `isAllowedPath` 为真之后，oauth2-proxy 做 reverse proxy：把**原始** `http.Request` 转到 upstream，**不会**改成 `X-Forwarded-Uri` 里的路径。过滤器刚看过的是转发头（或剥了 query 的 URI）；上游看到的是：

```text
GET /foo/critical_endpoint
```

没有第二次「匹配用的 path 必须等于 `req.URL.Path`」。匹配用的字符串来自转发头时，代理仍按 Go 的 `req.URL` 去 upstream——这正是 GHSA 说的 *evaluates authentication and skip-auth rules against a different path than the one actually sent to the upstream application*。

`isTrustedIP` 是另一条 skip（`--trusted-ip`，按源 IP 整段放行），和 skip-auth 正则无关，也不校验 `X-Forwarded-Uri` 的来源。V1 已经能解析 CIDR 集合，却只用来「这些 IP 可以免登录」，不用来「这些 IP 才可以设转发头」。7.15.2 的 `--trusted-proxy-ip` 才是后一种。

金丝雀只在受保护 path 上出现。body 里有 `PCBFLAG_...`，依据是这次 **skip 决策和上游 path 分家**，而不是 sidecar 把 flag 挂在了 `/foo/x/bar`。

---

## 仓库里已经有更强的检查，skip-auth 没用

同一份 `net/http` 请求上已经有不带 query、也不读转发头的路径：

| 表达式 | 含 query？ | 信 `X-Forwarded-Uri`？ |
|---|---|---|
| `req.URL.Path` | 否 | 否 |
| `req.URL.RequestURI()` | 是 | 否 |
| `GetRequestURI` | 若头存在则原样 | `--reverse-proxy` 下是 |
| `GetRequestPath`（V1） | 剥掉 | **是**（因为它调用 GetRequestURI） |

V1 等于在 skip-auth 上又做了一个**更弱**的「先信转发头、再剥 query」，而 `req.URL.Path` 始终没挂上。不是标准库里没有更好的谓词，是 **isAllowedPath 没用**。

`--trusted-ip` 已经按 CIDR 判断对端；7.15.2 才把类似集合用到「谁可以设 X-Forwarded-*」。V1 有 IP 集合基础设施，没接到转发头信任上。

---

## 这个补丁挡住了什么、没挡住什么

- `GetRequestPath`：看 `GetRequestURI()` 剥 query 之后像不像 `^/foo/.*/bar$`
- 上游：看 `req.URL.Path` 是哪条路由

只要构造一种输入，使「剥完 query 的那串」命中 skip，而真实 path 仍是受保护资源，第一行会放行，第二行仍返回 flag。

`X-Forwarded-Uri: /foo/anything/bar` 就是这样来的。`--reverse-proxy=true` 时 `IsProxied` 为真：

```text
请求行：     GET /foo/critical_endpoint
转发头：     X-Forwarded-Uri: /foo/anything/bar

GetRequestURI  = /foo/anything/bar          （来自头，不是请求行）
GetRequestPath = /foo/anything/bar          （没有 query 可剥）
regex          = 匹配 → skip auth
upstream       = /foo/critical_endpoint     → flag
```

GHSA-7x63-xv5r-3p2x 把影响范围写成：`--reverse-proxy` **并且** 配置了 skip-auth。两者本 case 都具备。直接打 7.11.0 的 4180、不经过前置 nginx 时，客户端就是「代理」，头被全信。

---

## 残余仍然走同一条 isAllowedPath（CVE-2026-40575）

没有换 skip 正则、没有换上游、没有换身份。还是：

```http
GET /foo/critical_endpoint HTTP/1.1
X-Forwarded-Uri: /foo/anything/bar
```

`isAllowedPath` 仍然调用 `GetRequestPath`；`GetRequestPath` 仍然先 `GetRequestURI`；头里的 `/foo/anything/bar` 满足 `^/foo/.*/bar$`；session 被跳过；upstream 按请求行返回 flag。

平台 residual 打的是 **同一个 skip-auth 谓词**，不是另一条 oauth2-proxy 路由（例如 `isAPIPath`）。seed 挡的是 query 拼接，residual 换的是 URI 字符串的来源。

---

## 后来又补了什么（CVE-2026-40575，7.15.2）

7.15.2 增加 `--trusted-proxy-ip`。`ReverseProxy` 为真但列表为空时，默认仍是 `0.0.0.0/0` + `::/0`（兼容），日志打 WARNING。只有显式写成前置代理网段时，非该网段来源的 `X-Forwarded-*` 才被忽略，`GetRequestURI` 回落到 `req.URL.RequestURI()`。

对本 case：compose 里 V2 设了 `--trusted-proxy-ip=10.99.99.0/24`，oracle 不在这个网段，伪造头被丢掉，`GetRequestPath` 变成 `/foo/critical_endpoint`，skip 失败，403。公开建议是升级到 v7.15.2 **并且** 配置该 flag；只升级不配等于没修。

`buildTrustedProxyNetSet`（7.15.2+）在 `ReverseProxy && len(TrustedProxyIPs)==0` 时填 `0.0.0.0/0` 和 `::/0`，并打 WARNING。GetRequestURI 是否信头，变成「对端 IP 是否落在这个 NetSet」。本 case 把 V2 配成一个**攻击者不会落在其中**的网段，才让负对照闭合。

即便如此，skip-auth 仍匹配 `GetRequestPath` 而不是强制 `req.URL.Path`。对「客户端直连 + 伪造头」这条已知链，配上 trusted CIDR 够用。

---

## 从这条链还能看出什么

**维护者改错了哪一层。**  
他们改的是「URI 里要不要包含 query」。真正分家的是「匹配用的字符串」和「upstream 的 path」。V2 仍在转发头信任层加码，没有让 skip-auth 只看 `req.URL.Path`。

**不是没有更好的谓词。**  
`req.URL.Path` 既无 query 也不读 `X-Forwarded-Uri`，正好是 CVE-2025-54576 advisory 自己建议的 *Path-only matching*。V1 实现成了「GetRequestURI 再剥 query」，把转发头信任一起带过来了。从 7.11.0 的 diff 只能看到 `GetRequestURI` → `GetRequestPath`；要判断是否闭合，必须打开 `GetRequestPath` 的函数体。

**同一 `isAllowedPath`、同一条 skip 正则，只换了 URI 的来源。**  
query 和 `X-Forwarded-Uri` 都是让「匹配字符串」变成 `/foo/.../bar`，而请求行仍是受保护 path。

**默认信任所有代理 IP 是有意的兼容。**  
V2 不配 `--trusted-proxy-ip` 时 residual 仍然通。闭合这条链需要代码 **和** 部署。

---

## 版本、入口、参考

| | 镜像 | `isAllowedPath` 读什么 | query seed | `X-Forwarded-Uri` residual |
|---|---|---|---|---|
| V0 | v7.10.0 | `GetRequestURI`（path+query，可被转发头替换） | 读到金丝雀 | （不必） |
| V1 | v7.11.0 | `GetRequestPath` = 剥 query 的 `GetRequestURI` | 403 | 读到金丝雀 |
| V2 | v7.15.2 + `--trusted-proxy-ip` | 非可信 IP 忽略转发头 | 403 | 403 |

- Web：`GET /foo/critical_endpoint`（seed 带 `?param=/bar`；residual 带 `X-Forwarded-Uri`）
- 源码：tag [`v7.11.0`](https://github.com/oauth2-proxy/oauth2-proxy/blob/v7.11.0/pkg/requests/util/util.go) `GetRequestPath` / `GetRequestURI`；[`oauthproxy.go`](https://github.com/oauth2-proxy/oauth2-proxy/blob/v7.11.0/oauthproxy.go) `isAllowedPath`；对比 [`v7.10.0`](https://github.com/oauth2-proxy/oauth2-proxy/blob/v7.10.0/oauthproxy.go)
- [GHSA-7rh7-c77v-6434](https://github.com/oauth2-proxy/oauth2-proxy/security/advisories/GHSA-7rh7-c77v-6434) / [CVE-2025-54576](https://nvd.nist.gov/vuln/detail/CVE-2025-54576)
- [GHSA-7x63-xv5r-3p2x](https://github.com/oauth2-proxy/oauth2-proxy/security/advisories/GHSA-7x63-xv5r-3p2x) / [CVE-2026-40575](https://nvd.nist.gov/vuln/detail/CVE-2026-40575)
- [ZeroPath 分析](https://zeropath.com/blog/cve-2025-54576-oauth2-proxy-auth-bypass)
