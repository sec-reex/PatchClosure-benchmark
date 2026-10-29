# Traefik：Connection 保护加了，比较却是大小写敏感的

- Case：`PCBV2-0010`
- 产品：Traefik（Go 反向代理）。入口中间件 `pkg/middlewares/forwardedheaders` 在把请求交给上游之前，自己写入 `X-Real-Ip` / `X-Forwarded-*`。
- 链：CVE-2024-45410（2.11.8 → 2.11.9）→ CVE-2026-29054（2.11.9…2.11.37 → 2.11.38；v3 线是 3.1.3…3.6.8 → 3.6.9）
- 源码对着 GitHub tag `v2.11.9` / `v2.11.38` 的 `pkg/middlewares/forwardedheaders/forwarded_header.go`：`ServeHTTP`、`rewrite`、`removeConnectionHeaders`。运行时是官方 `traefik:v2.11.x` 镜像，不是抽出来的函数。

2024 年 9 月，Traefik 给 forwarded-headers 中间件加了 `removeConnectionHeaders`：客户端若在 `Connection` 里点名 `X-Real-Ip`，代理不得按 hop-by-hop 把它删掉。GHSA-92mv-8f8w-wq52 在 2026 年 3 月写明：*The Connection tokens are compared case-sensitively against the protected header names, but the actual header deletion operates case-insensitively. ... This is a bypass of the fix for CVE-2024-45410.* NVD CVE-2026-29054 把受影响窗口钉在 2.11.9–2.11.37。

根因不只是「忘了 EqualFold」。检查插在「token 字符串是否出现在 `xHeaders` 切片里」；真正删头的是 `net/http` 的 `Header.Del`，按规范名大小写不敏感。同文件里 `xHeaders` 存的已经是规范名 `X-Real-Ip`。下面按请求走进去、2.11.9 加了哪一段、删头之前谁消费那个 token、规范名谓词有没有挂上，把这几层写完。

---

## 这块功能本来在干什么

Traefik 作为边缘代理，要告诉上游「真实客户端是谁」。默认 `insecure=false`、trustedIPs 为空时，它不信任客户端自带的 `X-Forwarded-*` / `X-Real-Ip`，先清掉再按 `RemoteAddr` 重写。一次典型请求：

```http
GET /admin/secret HTTP/1.1
Host: ...
```

`XForwarded.ServeHTTP` 的顺序是：对不信任的对端清空受管头 → `rewrite` 写入 `X-Real-Ip` 等 →（V1 起）`removeConnectionHeaders` → `next.ServeHTTP`。上游若用「没有 `X-Real-Ip` = 来自内网」做 IP 白名单，缺头就会当成可信调用。本 case 的上游只在**没有** `X-Real-Ip` 时返回金丝雀，有头则 `forbidden`。

数据流：

```text
HTTP/1.1 请求（含 Connection）
    → XForwarded.ServeHTTP
         清空客户端带来的 X-Real-Ip / X-Forwarded-*
         rewrite: Set("X-Real-Ip", clientIP)     ← Traefik 自己写入
         V1：removeConnectionHeaders(req)        ← 补丁插在这里
              拆 Connection token
              slices.Contains(xHeaders, sf) ? 跳过 : Header.Del(sf)
         ReverseProxy 再按 hop-by-hop 语义转发
    → 上游看 X-Real-Ip 在不在
```

没有登录。攻击者不能伪造 `X-Real-Ip` 的值（中间件会先删再写），只能设法让**已经写好的头**在转发前消失。成功穿越之后的效果是：上游以为这是内部来源，把 `/admin/secret` 的 `PCBFLAG_...` 返回给未认证客户端。

---

## 原始漏洞：Connection 可以点名删掉 Traefik 刚写的头（CVE-2024-45410，2.11.8）

2.11.8 的 `ServeHTTP` 在 `rewrite` 之后直接 `next.ServeHTTP`。HTTP/1.1 的 `Connection` 列出 hop-by-hop 头；Go 的 `httputil.ReverseProxy` 会按 RFC 7230 §6.1 把这些头从转发请求里拿掉。客户端发送：

```http
GET /admin/secret HTTP/1.1
Connection: close, X-Real-Ip
```

Traefik 刚把 `X-Real-Ip` 设成真实客户端 IP，ReverseProxy 看到 Connection 里的 token，把这颗头删掉。上游收到的请求没有 `X-Real-Ip`，放行金丝雀。这是 CVE-2024-45410 / GHSA-62c8-mh53-4cqv。

本 case 的 seed 用规范大小写：

```text
Connection: close, X-Real-Ip
```

---

## 维护者改了什么（CVE-2024-45410 修复，2.11.9）

2.11.9 在 `rewrite` 之后、交给下一跳之前，插入 `removeConnectionHeaders`。和 2.11.8 并排，关键差就是这一段。`xHeaders` 是中间件自己的受管名单，字面量已经是规范名：

```go
// pkg/middlewares/forwardedheaders/forwarded_header.go  (v2.11.9)
const (
    xForwardedProto = "X-Forwarded-Proto"
    ...
    xRealIP         = "X-Real-Ip"
    connection      = "Connection"
)

var xHeaders = []string{
    xForwardedProto, xForwardedFor, xForwardedHost, xForwardedPort,
    xForwardedServer, xForwardedURI, xForwardedMethod,
    xForwardedTLSClientCert, xForwardedTLSClientCertInfo,
    xRealIP,
}

func (x *XForwarded) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    if !x.insecure && !x.isTrustedIP(r.RemoteAddr) {
        for _, h := range xHeaders {
            unsafeHeader(r.Header).Del(h)
        }
    }
    x.rewrite(r)
    x.removeConnectionHeaders(r)   // V0 没有这一行
    x.next.ServeHTTP(w, r)
}
```

新函数的字面意思：拆 `Connection`，若 token 在 `xHeaders` 里就**不要**删对应头、也不要把该 token 留给下游；否则 `req.Header.Del(sf)`。

```go
// removeConnectionHeaders  (v2.11.9，约 L194–L248)
func (x *XForwarded) removeConnectionHeaders(req *http.Request) {
    ...
    for _, f := range req.Header[connection] {
        for _, sf := range strings.Split(f, ",") {
            if sf = textproto.TrimString(sf); sf != "" {
                // Connection header cannot dictate to remove X- headers managed by Traefik
                if slices.Contains(xHeaders, sf) {
                    continue
                }
                if slices.Contains(x.connectionHeaders, sf) {
                    connectionHopByHopHeaders = append(connectionHopByHopHeaders, sf)
                    continue
                }
                req.Header.Del(sf)
            }
        }
    }
    ...
}
```

对 seed 这种规范大小写，它确实够用：

```text
sf = "X-Real-Ip"
slices.Contains(xHeaders, "X-Real-Ip") == true  → continue，不 Del
Connection 里的 X-Real-Ip token 被丢掉
下游仍带着 Traefik 写入的 X-Real-Ip → forbidden
```

这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 客户端写出的 token 会和 `xHeaders` 里的规范名**同一个字节序列**。
2. `Header.Del(sf)` 只有在「不是受管头」时才会碰到受管头——也就是保护比较和删除用同一套相等关系。

第二点不成立。Go 的 header map 按 `CanonicalHeaderKey` 存；`Del` 会先规范化再删。`slices.Contains` 对 `string` 是精确相等。

---

## 消毒之后，token 怎么接到真正的删除上

V1 的 `slices.Contains` 一结束，同一循环立刻：

```go
req.Header.Del(sf)
```

`net/http.Header.Del` 的语义是：把 key 做成规范名，再从 map 里删。`sf = "x-real-ip"` 时：

```text
CanonicalHeaderKey("x-real-ip") == "X-Real-Ip"
delete(header, "X-Real-Ip")
```

`rewrite` 刚刚用规范名写进去的那颗头被删掉。过滤器刚看过的是原始 token 字符串；open（这里是 header map 删除）看到的是规范化后的键。两套相等关系中间没有第二次谓词。

`unsafeHeader` 注释写着 *Must be used only when the header name is already a canonical key*。`removeConnectionHeaders` 却把**未规范化**的 `sf` 交给 `Header.Del`。删除路径会规范化；保护路径不会。

Go 自己的 `httputil.ReverseProxy` 删 hop-by-hop 头时用的是 `httpguts.HeaderValuesContainsToken` / 规范名。Traefik 加的保护本应比 ReverseProxy 更严，结果保护比较比删除更窄。

---

## 仓库里已经有规范名，比较没用上

同一份文件里：

- `xHeaders` 的每个元素都是规范名常量（`X-Real-Ip`，不是 `X-Real-IP` 也不是 `x-real-ip`）。
- `unsafeHeader` 要求调用方已经规范化。
- `isWebsocketRequest` 里的 `containsHeader` **已经**用 `strings.EqualFold` 比较 Connection token。

谁用了大小写不敏感比较：

| 代码 | 比较 Connection / 头名的方式 |
|---|---|
| `isWebsocketRequest` | `strings.EqualFold` |
| `removeConnectionHeaders` 保护分支 | `slices.Contains(xHeaders, sf)` 精确匹配 |
| `req.Header.Del(sf)` | 内部 `CanonicalHeaderKey` |

不是仓库里没有「忽略大小写」的写法。是 **保护名单那一行没用**。即便没有小写 token，只要客户端写出 `X-Real-IP`、`X-REAL-IP` 这类 RFC 允许的变体，精确匹配同样 miss，`Del` 同样能删掉规范名那一颗。advisory 举的是 `Connection: x-real-ip`。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「保护比较 vs 删除」落到具体变换：

- `slices.Contains(xHeaders, sf)`：看 token 是否**等于** `"X-Real-Ip"` 等字面量
- `Header.Del(sf)`：看规范化后的键是否存在

只要 token 规范化之后等于某颗受管头、规范化之前不等于，第一行放行，第二行仍删。

```text
Connection: close, x-real-ip

sf = "x-real-ip"
slices.Contains(xHeaders, "x-real-ip") == false     // 保护 miss
slices.Contains(x.connectionHeaders, "x-real-ip")   // 默认也不在允许名单
req.Header.Del("x-real-ip")                         // 删掉 X-Real-Ip
上游：没有 X-Real-Ip → 当成内部来源 → 金丝雀
```

带上完整顺序：

```text
1. 清空客户端自带 X-Real-Ip
2. rewrite 写入 X-Real-Ip = 真实客户端 IP
3. removeConnectionHeaders：小写 token 躲过名单，Del 掉刚写入的头
4. ReverseProxy 转发一份没有身份头的请求
```

这正是 2.11.8 上 seed 用过的那种效果。过滤器认为自己已经把 `X-Real-Ip` 从 Connection 语义里摘出来了，实际上它只摘了规范大小写那一种写法。GHSA 原话：*a remote unauthenticated client can use lowercase Connection tokens (e.g. Connection: x-real-ip) to bypass the protection and trigger the removal of Traefik-managed forwarded identity headers.*

V1 保护的是「token 字节等于名单」；HTTP/1.1 头名是大小写不敏感的。`x-real-ip` 三个词都不是两个点那种编码变体，它就是同一个头的另一种合法写法。

---

## 残余仍然走同一条 forwarded-headers 路径（CVE-2026-29054）

没有换入口、没有换中间件、没有换身份。还是：

```http
GET /admin/secret HTTP/1.1
Connection: close, x-real-ip
```

`ServeHTTP` 仍然 `rewrite` 再 `removeConnectionHeaders`。V1 那一行 `slices.Contains(xHeaders, sf)` 照样执行；执行完之后因为 miss 而 `Del`；上游再次看不到 `X-Real-Ip`。

本 case residual 写死为：

```text
Connection: close, x-real-ip
```

和 GHSA PoC 同一构造，只是把下游「admin bypass」换成金丝雀。认证意图：v1 + `--residual` 响应体中观察到 `PCBFLAG_...`。规范大小写的 seed 在同一 V1 上是 `forbidden`。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：保护比较用精确字符串；删除用规范名；`xHeaders` 里已经是规范名却没有在比较前先 `CanonicalHeaderKey`。seed 被挡住只说明「照着常量抄的 token 不再能删头」，不说明「不能再通过 Connection 拿掉 Traefik 管理的身份头」。

---

## 后来又补了什么（CVE-2026-29054，2.11.38）

2.11.38 在比较和删除之前先规范化 token：

```go
// removeConnectionHeaders  (v2.11.38，约 L207–L248)
for sf := range strings.SplitSeq(f, ",") {
    if sf = textproto.TrimString(sf); sf != "" {
        key := http.CanonicalHeaderKey(sf)
        if slices.Contains(xHeaders, key) {
            continue
        }
        if slices.Contains(x.connectionHeaders, key) {
            connectionHopByHopHeaders = append(connectionHopByHopHeaders, key)
            continue
        }
        delete(req.Header, key)
    }
}
```

对残余输入：

```text
sf  = "x-real-ip"
key = "X-Real-Ip"
slices.Contains(xHeaders, "X-Real-Ip") == true → continue
X-Real-Ip 保留 → forbidden
```

`NewXForwarded` 同时把 `connectionHeaders` 允许名单也做成规范名。公开建议是升级到 Traefik `v2.11.38` 或 `v3.6.9`。advisory 写 *No workaround available*。

即便如此，这仍然是「在 Connection token 层做名单」。若还有其它能让 ReverseProxy 或后续中间件拿掉 `X-Real-Ip` 的写法，需要另证。本 benchmark 的 v2 只关闭这一条小写 token residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是「要不要把 Connection token 交给 `Del`」。真正让头消失的是 `Header.Del` / ReverseProxy 的 hop-by-hop 语义。保护比较没有用删除那一层已经在用的规范名。V2 仍在同一函数里加 `CanonicalHeaderKey`，没有改成「转发前强制再写一遍 `X-Real-Ip`」或「禁止客户端 Connection 携带任何 X- 头」。

**不是没有更好的谓词。**  
同文件 `isWebsocketRequest` 已经 `EqualFold`。`http.CanonicalHeaderKey` 是标准库。从 V1 的 diff 只能看到加了一个 `slices.Contains(xHeaders, sf)`；要判断补丁是否闭合，必须看到 `Header.Del` 的大小写行为，以及 `xHeaders` 里存的是哪一种写法。

**同一函数、同一 `Connection` 头，只换了 token 的大小写。**  
`X-Forwarded-For`、`X-Forwarded-Host`、`X-Forwarded-Proto` 都在 `xHeaders` 里，同样吃这一行精确匹配。advisory 写 *and similarly named headers in the managed list*。

**上游信任「头不在」和「头在且为某 IP」是两种不同的授权。**  
本 case 把「缺头」当成内部来源，是为了把 advisory 里的 IP 白名单绕过变成可观察的金丝雀。真实部署里缺 `X-Real-Ip` 也可能让 scheme / Host 判断走错。

---

## 版本、入口、参考

| | Traefik | `removeConnectionHeaders` | `Connection: X-Real-Ip` seed | `Connection: x-real-ip` residual |
|---|---|---|---|---|
| V0 | 2.11.8 | 无，ReverseProxy 直接 hop-by-hop 删除 | 上游无头，金丝雀 | （不必） |
| V1 | 2.11.9 | `slices.Contains(xHeaders, sf)` 精确匹配 | 保护命中，forbidden | 保护 miss，`Del` 仍删，金丝雀 |
| V2 | 2.11.38 | 先 `CanonicalHeaderKey(sf)` 再比较 | 挡 | 挡 |

- Web：`GET /admin/secret`，HTTP/1.1，`Connection` 携带受管头名
- 认证意图：v0 seed 观察到 flag；v1 seed forbidden；v1 residual 观察到 flag。
- [CVE-2024-45410](https://nvd.nist.gov/vuln/detail/CVE-2024-45410)、[CVE-2026-29054](https://nvd.nist.gov/vuln/detail/CVE-2026-29054)
- [GHSA-92mv-8f8w-wq52](https://github.com/traefik/traefik/security/advisories/GHSA-92mv-8f8w-wq52)（写明 bypass of CVE-2024-45410）
- 源码：[`forwarded_header.go` @ v2.11.9](https://github.com/traefik/traefik/blob/v2.11.9/pkg/middlewares/forwardedheaders/forwarded_header.go)、[v2.11.38](https://github.com/traefik/traefik/blob/v2.11.38/pkg/middlewares/forwardedheaders/forwarded_header.go)
