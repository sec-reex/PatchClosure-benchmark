# new-api SSRF：第一跳 URL 补上了，302 的 Location 没再跑同一谓词

- Case：`PCBV2-0151`
- 产品：New API（QuantumNous/new-api，LLM 网关）。运行时是官方镜像 `calciumion/new-api:v0.9.0.5`，整进程 HTTP，不是抽出来的 `ValidateURL`。
- 链：CVE-2025-59146（<0.9.0.5 → v0.9.0.5，GHSA-xxv6-m6fx-vfhh）→ CVE-2025-62155（≤v0.9.5 → v0.9.6，GHSA-9f46-w24h-69w4）
- 源码对着 tag `v0.9.0.5` 的 `common/ssrf_protection.go`（`ValidateURL` / `isPrivateIP`）和 `service/download.go`（`DoDownloadRequest` → `http.Get`）、`service/http_client.go`（**没有** `CheckRedirect`）。金丝雀是内网 sidecar `172.31.9.9` 上的 `PCBFLAG_...`，由 `POST /v1/chat/completions` 的 `image_url` 触发服务端 GET。

GHSA-9f46-w24h-69w4 的原话：*Because the existing fix only applies security restrictions to the first URL request, a 302 redirect can bypass existing security measures and successfully access the intranet.* 公开 PoC 把 302 服务开在 8080——默认允许端口——再跳到 `127.0.0.1`。

根因不只是「忘了重定向」。检查插在「用户给的那一串 URL 像不像私网」上；真正发 GET 的是后面的 `http.Get` / `http.Client`，默认跟随 302，**不会**再调用 `ValidateURL`。同一次下载路径里已经有完整的 `isPrivateIP` + 端口白名单，却只挂在第一跳。下面按请求走进去。

---

## 这块功能本来在干什么

多模态补全会按 `image_url` 去拉图，给 tokenizer / 上游模型用。一次典型请求（需用户 token，注册默认开）：

```http
POST /v1/chat/completions
Authorization: Bearer sk-…
Content-Type: application/json

{
  "model": "gpt-4o-mini",
  "stream": true,
  "messages": [{
    "role": "user",
    "content": [
      {"type": "text", "text": "describe"},
      {"type": "image_url", "image_url": {"url": "http://172.31.9.9/internal-secret.png"}}
    ]
  }]
}
```

`GET_MEDIA_TOKEN=true` 时，token 计数会把 URL 当文件源拉下来。调用链（后续 advisory GHSA-v5c3-6wvc-pc2q 对着更新代码写的，v0.9.0.5 已经是同一出口）：

```text
POST /v1/chat/completions
    → GetTokenCountMeta 收集 image_url.url
    → LoadFileSource / loadFromURL
    → service.DoDownloadRequest(originUrl)
         ValidateURLWithFetchSetting(originUrl)     ← V1 只在这里
         http.Get(originUrl)                        ← 标准库默认跟随重定向
    → 内网响应进入 token / 模型路径
```

未开 worker 时 V1 走的就是 `net/http` 默认客户端，不是自定义 `CheckRedirect`。设计意图：用户 URL 不能指向 RFC1918 / loopback / 链路本地。成功穿越之后的效果是内网 canary 被 GET 到，hit 日志里出现 `PCBFLAG_...`。

数据流里和「私网」相关的谓词全部在 `ValidateURL`：协议、端口、`isPrivateIP`、域名/IP 名单。`http.Get` 不再问一次。

---

## 原始漏洞：image_url 无目的地校验（CVE-2025-59146，0.9.0.4）

v0.9.0.4 没有 `common/ssrf_protection.go`。`DoDownloadRequest` 在非 worker 模式下直接 `http.Get(originUrl)`（issue #1636 指向更早的 `cf_worker.go` 同名函数）。任意已登录用户都能让网关去拉 `http://172.31.9.9/...` 或 `http://169.254.169.254/`。这就是 v0 + `--seed`：直连内网 IP，canary 记一笔。

GHSA-xxv6-m6fx-vfhh：*The application fails to properly validate this user-supplied URL before making a server-side request. This vulnerability is not limited to image URLs.*

---

## 维护者改了什么（CVE-2025-59146 修复，v0.9.0.5）

v0.9.0.5 引入可配置 SSRF 模块，默认开启。`DoDownloadRequest` 在 GET 之前调用：

```go
// service/download.go  （v0.9.0.5）
func DoDownloadRequest(originUrl string, reason ...string) (resp *http.Response, err error) {
    if system_setting.EnableWorker() {
        ...
        return DoWorkerRequest(req)
    }
    fetchSetting := system_setting.GetFetchSetting()
    if err := common.ValidateURLWithFetchSetting(originUrl, fetchSetting.EnableSSRFProtection,
        fetchSetting.AllowPrivateIp, fetchSetting.DomainFilterMode, fetchSetting.IpFilterMode,
        fetchSetting.DomainList, fetchSetting.IpList, fetchSetting.AllowedPorts,
        fetchSetting.ApplyIPFilterForDomain); err != nil {
        return nil, fmt.Errorf("request reject: %v", err)
    }
    return http.Get(originUrl)
}
```

`ValidateURL` 解析 URL，只许 http/https，查端口白名单（默认含 80/443/8080/8443），host 是 IP 则 `IsIPAccessAllowed`：

```go
// common/ssrf_protection.go :: isPrivateIP  （v0.9.0.5）
func isPrivateIP(ip net.IP) bool {
    if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
        return true
    }
    private := []net.IPNet{
        {IP: net.IPv4(10, 0, 0, 0), Mask: net.CIDRMask(8, 32)},
        {IP: net.IPv4(172, 16, 0, 0), Mask: net.CIDRMask(12, 32)},
        {IP: net.IPv4(192, 168, 0, 0), Mask: net.CIDRMask(16, 32)},
        {IP: net.IPv4(127, 0, 0, 0), Mask: net.CIDRMask(8, 32)},
        {IP: net.IPv4(169, 254, 0, 0), Mask: net.CIDRMask(16, 32)},
        ...
    }
    ...
}
```

对 seed 这种 `http://172.31.9.9/internal-secret.png`，`172.16.0.0/12` 命中，返回 `private IP address not allowed`。这就是 v1 + `--seed` 退出码 10。

同一文件里的 `InitHttpClient` **没有** `CheckRedirect`：

```go
// service/http_client.go  （v0.9.0.5）
func InitHttpClient() {
    if common.RelayTimeout == 0 {
        httpClient = &http.Client{}
    } else {
        httpClient = &http.Client{
            Timeout: time.Duration(common.RelayTimeout) * time.Second,
        }
    }
}
```

而 `DoDownloadRequest` 用的还是 `http.Get`，连这个 `httpClient` 都不是——直接 `DefaultClient`，默认最多跟 10 次重定向，回调是「只限制次数」。

补丁默认了两件事：

1. 危险目的地长得像「用户提交的那一串 URL 的 host」。
2. 标准库跟 302 时，新 Location 仍然安全（或根本不会跟到私网）。

第二点不成立。`DefaultClient` 把 302 的 `Location` 当成新请求，不再经过 `ValidateURL`。

---

## 校验之后，谁真正拨号

`ValidateURL` 返回 nil 之后，同一函数立刻：

```go
return http.Get(originUrl)
```

`http.Get` → `DefaultClient.Do`。遇到 302，用 `Location` 组新 URL，**没有** `CheckRedirect` 钩子里的业务校验。第一跳可以是公网 IP `11.11.11.10:8080`（不在私网表、端口在默认允许列表）。第二跳可以是 `http://172.31.9.9:80/internal-secret.png`。拨号发生在第二跳，谓词只看过第一跳。

worker 模式同样只在把 URL 交给 worker **之前**验一次；worker 若自己跟重定向，是另一条实现。本 case 默认未开 worker，走 `http.Get`。

过滤器刚看过的是字符串 `originUrl`；内核看到的是重定向之后的五元组。中间没有第二次 `isPrivateIP`。

---

## 仓库里已经有更强的检查，重定向没用

`ValidateURLWithFetchSetting` 已经是完整的目的地谓词：协议、端口、私网、名单。Go 标准库从第一天就提供 `http.Client.CheckRedirect`。更强、当时就能挂上的用法：

```go
client := &http.Client{
    CheckRedirect: func(req *http.Request, via []*http.Request) error {
        return ValidateURLWithFetchSetting(req.URL.String(), ...)
    },
}
```

这正是 v0.9.6 写进 `service/http_client.go` 的 `checkRedirect`。v0.9.0.5 里函数已经存在，**调用点只有第一跳**。

谁在用（v0.9.0.5）：

| 位置 | 调用 `ValidateURL`？ |
|---|---|
| `DoDownloadRequest` 第一跳 | 是 |
| `DoWorkerRequest` 第一跳 | 是 |
| `http.Get` / `DefaultClient` 跟随 302 | **否** |
| `GetHttpClient()` 的 `http.Client` | 无 `CheckRedirect` |

不是没有「对每个 URL 跑一遍」的函数，是 **Client 没挂**。即便 302 没有把第一跳打穿，只要 `http.Get` 继续自动跟随，任何「第一跳看起来像公网」的 Location 都会变成一次真实的内网 GET。

（之后的 CVE-2026-42339 还指出 `isPrivateIP` 漏了 `0.0.0.0/8`。那是同一谓词的另一缺口，不是本 case 的 302 residual。）

---

## 这个补丁挡住了什么、没挡住什么

- V1 过滤器：用户提交的 URL 是否私网 / 非法端口
- `http.Get`：跟随 `Location`，不再问过滤器

```text
seed:
  image_url = http://172.31.9.9/internal-secret.png
  → isPrivateIP(172.31.9.9) → reject

residual:
  image_url = http://11.11.11.10:8080/redirect     （公网、允许端口）
  → ValidateURL 放行
  → http.Get
  → 302 Location: http://172.31.9.9:80/internal-secret.png
  → DefaultClient 直接 GET 内网
  → canary 记 flag
```

和 GHSA 给的 Flask 302 脚本同一构造，只是把 `127.0.0.1:8003` 换成 case 里的 `172.31.9.9:80`。平台 residual 打的就是这条 `DoDownloadRequest` → `http.Get` 跟随，和源码链同一 sink。不是换了一个 webhook 出口。

---

## 残余仍然走同一条 image_url 下载路径（CVE-2025-62155）

没有换 `/v1/chat/completions`、没有换 token 计数拉图、没有换 canary。还是 `image_url.url`，只是第一跳改成攻击者控制的公网 302。`ValidateURL` 照样执行；执行完之后 `http.Get` 照样跟到内网。advisory 写 *only applies security restrictions to the first URL request*。

seed 被挡住只说明「直连私网 IP 不行了」，不说明「服务端 GET 的最终目的地一定经过 `isPrivateIP`」。

---

## 后来又补了什么（CVE-2025-62155，v0.9.6）

v0.9.6 给包级客户端挂上 `checkRedirect`，并让 `DoDownloadRequest` 改走 `GetHttpClient().Get`（不再是裸 `http.Get`）：

```go
// service/http_client.go  （v0.9.6）
func checkRedirect(req *http.Request, via []*http.Request) error {
    fetchSetting := system_setting.GetFetchSetting()
    urlStr := req.URL.String()
    if err := common.ValidateURLWithFetchSetting(urlStr, ...); err != nil {
        return fmt.Errorf("redirect to %s blocked: %v", urlStr, err)
    }
    if len(via) >= 10 {
        return fmt.Errorf("stopped after 10 redirects")
    }
    return nil
}
```

对残余输入：第一跳仍通过；302 的 Location 再进 `ValidateURL`，`172.31.9.9` 被 `isPrivateIP` 拒绝，`redirect to ... blocked`。公开建议升级到 v0.9.6。

即便如此，这仍然是「每个 Location 再跑同一字符串谓词」，不是拨号时对解析出的 IP 再查一次（那是更晚的 `GetSSRFProtectedHTTPClient`）。对本条 302→内网 IP 够用。本 benchmark 的 v2 只关闭这一条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是 GET 之前的 URL 字符串。真正连到内网的是 `http.Client` 跟随重定向之后的那次拨号。V2 仍用同一个 `ValidateURL`，但终于挂到 `CheckRedirect`。

**不是没有更好的谓词。**  
`ValidateURL` 在 v0.9.0.5 已经完整。从 V1 的 diff 只能看到 download 入口多了一次调用；要判断是否闭合，必须看到 `return http.Get(originUrl)` 和 `http.Client{}` 没有 `CheckRedirect`。

**同一 `DoDownloadRequest`、同一 `image_url`，只换了第一跳是否 302。**  
`/v1/responses`、`/v1/messages` 只要汇到 `loadFromURL`，都吃这一次跟随。

**字符串校验的对象必须是「即将拨号的 URL」。**  
只校验用户输入、把后续 Location 当可信，等于把 SSRF 决策交给攻击者的 HTTP 服务。

**金丝雀在无宿主机端口的内网 sidecar 上是有意的。**  
`172.31.9.9:80` 从外面打不到。能在 hit 日志里读到 flag，说明 new-api 进程自己发出了第二跳 GET。

---

## 版本、入口、参考

| | 版本 | 第一跳 | 跟随 302 | 直连私网 seed | 公网 302 residual |
|---|---|---|---|---|---|
| V0 | v0.9.0.4 | 无 `ValidateURL` | `http.Get` 跟随 | canary 被 GET | （不必） |
| V1 | v0.9.0.5 | `ValidateURL` | `http.Get` 仍跟随、不复核 | `private IP not allowed` | Location 直达内网，flag |
| V2 | v0.9.6 | 同上 | `GetHttpClient` + `checkRedirect` 再验 | 挡 | `redirect ... blocked` |

- 产品入口：`POST /v1/chat/completions`（`image_url.url`）；同 sink 还有 responses/messages
- [CVE-2025-59146](https://nvd.nist.gov/vuln/detail/CVE-2025-59146)、[CVE-2025-62155](https://nvd.nist.gov/vuln/detail/CVE-2025-62155)
- [GHSA-xxv6-m6fx-vfhh](https://github.com/QuantumNous/new-api/security/advisories/GHSA-xxv6-m6fx-vfhh)、[GHSA-9f46-w24h-69w4](https://github.com/QuantumNous/new-api/security/advisories/GHSA-9f46-w24h-69w4)
- 源码：[`v0.9.0.5` `ssrf_protection.go`](https://github.com/QuantumNous/new-api/blob/v0.9.0.5/common/ssrf_protection.go)、[`download.go`](https://github.com/QuantumNous/new-api/blob/v0.9.0.5/service/download.go)、[`http_client.go`](https://github.com/QuantumNous/new-api/blob/v0.9.0.5/service/http_client.go)
- V2：[`v0.9.6` `http_client.go`](https://github.com/QuantumNous/new-api/blob/v0.9.6/service/http_client.go)
