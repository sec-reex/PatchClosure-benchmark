# Gogs webhook：投递前只看了第一跳主机名

- Case：`PCBV2-0033`
- 产品：Gogs（自托管 Git 服务）
- 链：CVE-2022-1285（0.12.7 → 0.12.8 / 本 case 的 V1 是 0.14.2）→ CVE-2026-47267（0.14.2 → 0.14.3）
- 源码对着官方 tag `v0.14.2` 的 `internal/database/webhook.go`、`internal/httplib/httplib.go`、`internal/netutil/netutil.go`。运行时是官方 `gogs/gogs` 镜像 + 仓库 webhook，不是抽出来的函数。

2022 年 5 月 31 日，Gogs 给 webhook 投递加了一行：每次真正发出 HTTP 请求之前，用 `netutil.IsBlockedLocalHostname` 再查一次 payload URL 的主机名，挡住解析到本地网段的地址。NVD 把这件事记成 CVE-2022-1285，advisory GHSA-w689-557m-2cvq 写明 *Webhook payload URLs are revalidated before each delivery*。四年后的 0.14.3 才补上第二件事：HTTP 客户端默认会跟随 3xx，而那一行检查从来没看到过 `Location`。NVD 把这件事记成 CVE-2026-47267，并写明 *the fix for CVE-2022-1285 prevents ... URLs with a hostname that resolves in localCIDRs. However, webhooks still follow redirects*。

根因不只是「白名单漏了一个地址」。检查插在字符串 URL 的 Hostname 上；真正发请求的是另一套 `http.Client`，默认跟随重定向；标准库里已经有 `CheckRedirect`，0.14.2 的 httplib 根本没有这个字段。下面按请求走进去、补丁改了哪一行、检查之后谁去发 HTTP、仓库里已经有什么更强的钩子、残余怎么把同一条投递改到内部金丝雀。

---

## 这块功能本来在干什么

Gogs 给仓库管理员提供 webhook：push、issue、或者「Test Delivery」时，服务端把一份签名过的 JSON 投到用户填的 URL，再把对方的 HTTP 响应记进投递历史。Web 入口是仓库设置页；本 case 走 API，因为 UI 创建时会做 localCIDR 校验，而 API 创建在 0.12.7 上没有同等检查。

一次典型请求：

```http
POST /api/v1/repos/<user>/<repo>/hooks
Authorization: token <admin>
{"type":"gogs","config":{"url":"http://canary:8000/flag","content_type":"json"},"events":["push"],"active":true}
```

随后 `POST .../hooks/<id>/tests` 触发一次投递。`HookTask.deliver` 取出 `t.URL`，发出 POST，把响应 body 写进 `t.ResponseInfo.Body`。仓库设置页的 delivery history 会把这份 body 原样渲染出来。

设计意图：`url` 是管理员显式配置的通知地址（CI、聊天机器人、SaaS）。成功穿越之后的效果是 **Gogs 进程替用户向内部网络发 HTTP 请求，并把内部服务的响应反射到投递记录页**。

数据流：

```text
API config.url  （或 UI 表单）
    → Webhook 行写入数据库
    → Test Delivery / 事件触发
    → HookTask.deliver
         payloadURL := url.Parse(t.URL)
         V1：IsBlockedLocalHostname(payloadURL.Hostname(), allowlist)
              ← 只看这一次解析出的主机名
         httplib.Post(t.URL)          ← 仍是用户字符串
         http.Client.Do               ← 默认跟随 3xx，不再查 Hostname
         io.ReadAll(resp.Body)
    → ResponseInfo.Body
    → 投递历史页
```

---

## 原始漏洞：创建时不查、投递时也不查（CVE-2022-1285，0.12.7）

0.12.7 的 `deliver` 取出 `t.URL` 之后直接 `httplib.Post`。UI 创建 webhook 时有一份 localCIDR 校验，API 创建没有。Huntr bounty da1fbd6e 和 GHSA-w689-557m-2cvq 指出：恶意用户可以把 payload URL 指到内网，用 webhook 当 SSRF 探针。

本 case 的 seed 把 URL 设成内部金丝雀（compose 里 `canary` 服务，不对外暴露端口）：

```text
url = "http://canary:8000/flag"
```

0.12.7 投递时没有任何主机名再检查。Gogs 向 `canary:8000` 发 POST，金丝雀把 `PCBFLAG_...` 写进响应，投递记录页出现 flag。这就是 v0 + `--seed` 退出码 0。

没有换仓库、没有换身份。邮件或其它事件同样会走 `deliver`；本 case 只打 Test Delivery。

---

## 维护者改了什么（CVE-2022-1285 修复，commit 7885f454 / #6988）

0.12.8 在 `deliver` 入口、真正 `httplib.Post` **之前**加了一段。0.14.2（本 case 的 V1）里这段还在，路径从 `internal/db` 改到了 `internal/database`：

```go
// internal/database/webhook.go :: HookTask.deliver  (gogs v0.14.2)
func (t *HookTask) deliver() {
	payloadURL, err := url.Parse(t.URL)
	if err != nil {
		t.ResponseContent = fmt.Sprintf(`{"body": "Cannot parse payload URL: %v"}`, err)
		return
	}
	if netutil.IsBlockedLocalHostname(payloadURL.Hostname(), conf.Security.LocalNetworkAllowlist) {
		t.ResponseContent = `{"body": "Payload URL resolved to a local network address that is implicitly blocked."}`
		return
	}

	t.IsDelivered = true
	...
	req := httplib.Post(t.URL).SetTimeout(timeout, timeout).
		...
		SetTLSClientConfig(&tls.Config{InsecureSkipVerify: conf.Webhook.SkipTLSVerify})
```

`IsBlockedLocalHostname` 的字面意思（`internal/netutil/netutil.go`）：

| 步骤 | 含义 |
|---|---|
| `hostname == allow` 或 `allow == "*"` | 白名单命中则放行 |
| `net.LookupIP(hostname)` | 解析失败当作 blocked |
| `cidr.Contains(ip)` | 命中硬编码的 RFC1918 / loopback / link-local 等则 blocked |

它检查的是 **这一次 `t.URL` 解析出来的主机名**，不是随后 HTTP 客户端实际连上的地址。没有 `CheckRedirect`，没有对 `Location` 再跑一遍同一谓词，没有「最终 URL 必须等于配置 URL」。

对 seed 这种明文内网主机名，它确实够用：

```text
输入:  http://canary:8000/flag
LookupIP("canary") → 容器内网地址（10/8 或 172.16/12）
V1 后: 直接 return，ResponseContent = "Payload URL resolved to a local network address..."
```

投递记录里没有金丝雀 body。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险目标长得像「payload URL 自己的 Hostname 解析进 localCIDR」。
2. 只要这一跳被放行，后面的 HTTP 客户端不会再换一个主机。

第二点不成立。更关键的是：这一段 `return` 之后，代码仍然把原始 `t.URL` 交给 `httplib.Post`，而那次 POST **不再做 Hostname 检查**。

---

## 检查之后，请求怎么接到对端

V1 的 `IsBlockedLocalHostname` 一结束，同一个函数立刻用原来的 `t.URL` 建请求：

```go
	req := httplib.Post(t.URL).SetTimeout(timeout, timeout).
		Header("X-Gogs-Delivery", t.UUID).
		Header("X-Gogs-Signature", t.Signature).
		...
		SetTLSClientConfig(&tls.Config{InsecureSkipVerify: conf.Webhook.SkipTLSVerify})

	resp, err := req.Response()
	...
	p, err := io.ReadAll(resp.Body)
	t.ResponseInfo.Body = string(p)
```

`httplib.Post` 最终走到 `internal/httplib/httplib.go` 的 `getResponse`。0.14.2 组出来的客户端是：

```go
// internal/httplib/httplib.go :: getResponse  (gogs v0.14.2)
	client := &http.Client{
		Transport: trans,
		Jar:       jar,
	}

	resp, err := client.Do(r.req)
```

`http.Client` 的 `CheckRedirect` 是零值。Go 文档写明：未设置时默认跟随最多 10 次重定向。`Settings` 结构体里有 Timeout、TLS、Proxy、Transport，**没有 CheckRedirect 字段**。`SetTLSClientConfig` 能改 TLS，没有对应的 `SetCheckRedirect`。

过滤器刚看过的是 `url.Parse(t.URL).Hostname()`；`client.Do` 看到的是第一跳 302 之后的 `Location`。两套语义中间没有第二次谓词。

投递历史拿到的 `ResponseInfo.Body` 已经是 **最后一跳** 的响应。金丝雀在内网能出现在 history 里，依据就是这一步，而不是「attacker 自己的响应里碰巧写了 flag」。

---

## 仓库里已经有更强的钩子，投递没用

Go 标准库 `net/http.Client` 本来就有专门拦重定向的字段：

```go
// net/http.Client
type Client struct {
	...
	CheckRedirect func(req *Request, via []*Request) error
}
```

谁调用它：

| 位置 | 设置 `CheckRedirect`？ |
|---|---|
| 0.14.2 `httplib.getResponse` | **否**，`&http.Client{Transport, Jar}` |
| 0.14.3 `HookTask.deliver` | 是，一律 `errors.Newf("refusing to follow webhook redirect...")` |

V1 等于在调用方 `deliver` 做了一个 **只覆盖第一跳 Hostname** 的检查，而真正换主机的是 `http.Client` 默认策略。不是标准库里没有更好的谓词，是 **httplib 没用**。

即便 attacker 的 Hostname 没有打穿 `IsBlockedLocalHostname`，只要 `client.Do` 继续跟随 302，任何「第一跳在白名单、第二跳在 localCIDR」的写法都会变成一次真实的内网请求。

同一份 `netutil.go` 里的 `IsBlockedLocalHostname` 本来也可以对 `req.URL.Hostname()` 再跑一遍——那会是「跟随，但每跳都查」。0.14.2 两样都没做。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs HTTP 客户端」落到具体代码：

- `IsBlockedLocalHostname(payloadURL.Hostname(), allowlist)`：看配置 URL 的主机名这次解析到哪
- `http.Client.Do`：看 3xx 的 `Location`，默认最多跟 10 次，不再回调上面那一行

只要构造一种输入，使「第一跳 Hostname 不在 localCIDR（或在 allowlist 里）」而「第二跳落到金丝雀」，第一行会放行，第二行仍然打进内网。

`LOCAL_NETWORK_ALLOWLIST = attacker` 就是这样来的。attacker 是 compose 里一个对每次投递回 302 的接收端，Location 指向 `http://canary:8000/flag`。第一跳的 Hostname 是 `attacker`，白名单命中，`IsBlockedLocalHostname` 返回 false。`httplib` 发出 POST，收到 302，默认跟随到 `canary`。`canary` 的响应 body 被读进 `ResponseInfo.Body`。

带上 Test Delivery：

```text
API config.url:  http://attacker:8000/cb

deliver 看到的 Hostname:
  attacker     → allowlist 命中，检查通过

httplib / http.Client 实际请求:
  POST http://attacker:8000/cb
  ← 302 Location: http://canary:8000/flag
  GET/POST http://canary:8000/flag     ← 不再查 IsBlockedLocalHostname

ResponseInfo.Body:
  PCBFLAG_...
```

这正是 0.12.7 上 seed 用过的那种内网读取。过滤器认为自己已经把 localCIDR 挡干净了，实际上它只挡了配置字符串，而客户端会按真实 `Location` 再发一次。

CVE-2026-47267 的 NVD 原文就是：*`the fix for CVE-2022-1285 prevents adding webooks or running webhooks with URLs with a hostname that resolves in localCIDRs. However, webhooks still follow redirects allowing to access hostname inside localCIDRs`*。

---

## 残余仍然走同一条 webhook 投递路径（CVE-2026-47267）

没有换 API、没有换 Test Delivery、没有换身份。还是：

```http
POST /api/v1/repos/<user>/<repo>/hooks
{"config":{"url":"http://attacker:8000/cb",...}}
POST .../hooks/<id>/tests
```

`deliver` 仍然调用同一个 `IsBlockedLocalHostname`。V1 那一行照样执行；执行完之后 `httplib.Post(t.URL)` 跟随 302；`io.ReadAll` 读到金丝雀；history 页出现 flag。

本 case `verify.sh` 的 residual 把 candidate 写死在脚本里（运行时不读 held-out 文件）：

```text
HOOK_URL = "http://attacker:8000/cb"     # LOCAL_NETWORK_ALLOWLIST=attacker
attacker 对每次投递 302 → http://canary:8000/flag
```

和 GHSA-c4v7-xg93-qf8g 同一构造，只是把 169.254.169.254 换成内部金丝雀。认证：v1 + `--residual` 退出码 0，delivery body 中观察到 `PCBFLAG_...`。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：谓词匹配的是配置 URL 的 Hostname，比 HTTP 客户端实际连接的地址窄；发请求发生在检查之后；httplib 没有使用已经存在的 `CheckRedirect`。seed 被挡住只说明「明文内网 Hostname 没了」，不说明「不能再让 Gogs 把内网响应写进投递记录」。

---

## 后来又补了什么（CVE-2026-47267，0.14.3，commit 199cf4fd / #8263）

0.14.3 给 `httplib` 加了 `SetCheckRedirect`，并在 `deliver` 里安装一个一律拒绝的策略：

```go
// V2  0.14.3
	req := httplib.Post(t.URL).SetTimeout(timeout, timeout).
		...
		SetTLSClientConfig(&tls.Config{InsecureSkipVerify: conf.Webhook.SkipTLSVerify}).
		SetCheckRedirect(func(req *http.Request, _ []*http.Request) error {
			// The webhook target is explicitly configured by the user, so any
			// redirect would silently retarget the signed payload. Refuse all
			// redirects rather than chase them.
			return errors.Newf("refusing to follow webhook redirect to %q", req.URL.Redacted())
		})
```

对残余输入：

```text
第一跳: attacker:8000  → 302 Location: http://canary:8000/flag
V2 后: CheckRedirect 返回 error
ResponseInfo.Body ≈ Delivery: Post "http://canary:8000/flag": refusing to follow webhook redirect ...
```

公开建议是升级到 0.14.3。PR #8263 的说明写明：目标 URL 是用户显式配置的，任何重定向都会悄悄改写已签名 payload 的目的地——这才是 SSRF 向量的根，不论第二跳是本地还是公网。

即便如此，`IsBlockedLocalHostname` 仍然只跑第一跳。V2 选择的是「根本不跟随」，而不是「每跳都再查一遍」。对这条已知 302 链它够用。本 benchmark 的 v2 只关闭这一条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是 `deliver` 入口对 `t.URL` Hostname 的解析。真正换主机的是 `http.Client` 默认跟随 `Location`。V2 才把钩子插到客户端层。

**不是没有更好的谓词。**  
`http.Client.CheckRedirect` 从 Go 1 就在。`IsBlockedLocalHostname` 也可以对 `req.URL.Hostname()` 再跑。0.14.2 的 httplib `Settings` 连这个字段都没有。从 V1 的 diff 只能看到加了一段 Hostname 检查；要判断补丁是否闭合，必须看到 `getResponse` 里组出来的 `http.Client`。

**同一函数、同一 `t.URL`，只换了第一跳的写法。**  
任何把用户 URL 传进 `HookTask.deliver` 的事件（push、issue、Test Delivery）在 0.14.2 上都吃这一行检查和同一次 `client.Do`。advisory 已指出跟随重定向即可进入 localCIDR。

**API 创建和 UI 创建的谓词不一致。**  
UI 在保存时就会拦 localCIDR；API 创建在 CVE-2022-1285 之前完全没有。V1 把检查下移到投递时，对两种入口都生效——但只对第一跳生效。本 case seed 走 API 直连 canary，residual 走 API 直连 attacker。

**金丝雀在 webhook 配置树之外是有意的。**  
`canary:8000` 没有宿主机端口。能在 delivery history 里读到它，说明 Gogs 进程自己向内网发了请求，而不是页面上碰巧有一份静态文本。

---

## 版本、入口、参考

| | tag | `deliver` 谓词 | `httplib` 客户端 | 直连 canary seed | attacker 302 residual |
|---|---|---|---|---|---|
| V0 | 0.12.7 | 无 | 默认跟随 3xx | 读到金丝雀 | （不必） |
| V1 | 0.14.2 | `IsBlockedLocalHostname(t.URL.Hostname)` | 同上，仍无 `CheckRedirect` | 被拒，无 body | 跟随 302，读到金丝雀 |
| V2 | 0.14.3 | 同上 | `SetCheckRedirect` 一律拒绝 | 挡 | `refusing to follow webhook redirect` |

- Web：`POST /api/v1/repos/<user>/<repo>/hooks` + `POST .../hooks/<id>/tests`，效果通道是投递记录页 body
- 认证（本平台）：v0 seed 观察到 flag；v1 seed 未观察到；v1 residual 观察到
- [CVE-2022-1285](https://nvd.nist.gov/vuln/detail/CVE-2022-1285)、[GHSA-w689-557m-2cvq](https://github.com/gogs/gogs/security/advisories/GHSA-w689-557m-2cvq)
- [CVE-2026-47267](https://nvd.nist.gov/vuln/detail/CVE-2026-47267)、[GHSA-c4v7-xg93-qf8g](https://github.com/gogs/gogs/security/advisories/GHSA-c4v7-xg93-qf8g)
- 修复提交：[7885f454](https://github.com/gogs/gogs/commit/7885f454a4946c4bbec1b4f8c603b5eea7429c7f)（#6988）、[199cf4fd](https://github.com/gogs/gogs/commit/199cf4fd5bbe40b92f6dc8d649e241fd7a8d0018)（#8263）
- Huntr：[da1fbd6e-7a02-458e-9c2e-6d226c47046d](https://huntr.dev/bounties/da1fbd6e-7a02-458e-9c2e-6d226c47046d)
