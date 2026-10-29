# Docker Engine AuthZ：chunked 补上了，超大 body 仍然 fail-open

- Case：`PCBV2-0146`
- 产品：Moby / Docker Engine（容器守护进程）。AuthZ 插件挂在 Engine API 前面，插件看过 body 才决定是否把请求交给 daemon。
- 链：CVE-2024-41110（commit `fc274cd`，随 v23.0.15 / v26.1.5 / v27.1.1 发布）→ CVE-2026-34040（commit `e89edb19`，v29.3.1）
- 源码对着 tag `v27.1.1` 的 `pkg/authorization/authz.go`（`AuthZRequest` / `drainBody` / `isChunked` / `sendBody`）。真正的 sink 是 daemon 对 `POST /v1.xx/containers/create` 的处理：插件没看到 `Privileged:true`，daemon 却按完整 JSON 建了特权容器。

GHSA-x744-4wpc-v9h2 的原话：*This is an incomplete fix for CVE-2024-41110. Using a specially-crafted API request, an attacker could make the Docker daemon forward the request to an authorization plugin without the body.* Cyera 的技术说明更具体：2024 年那次只补了「零长度 / chunked 不同步」，`maxBodySize` 上那道「超了就静默丢掉 body、请求照样往下走」从 AuthZ 框架引入起就在。

根因不只是「少判了一种 Transfer-Encoding」。检查插在「要不要把 body 拷一份给插件」上；真正建容器的是后面的 daemon，它读的是**另一份** `r.Body`。同函数里 `drainBody` 已经能用 `Peek(maxBodySize)` 发现「body 太大」，发现之后却返回 `nil` body 而不是拒绝。下面按请求走进去。

---

## 这块功能本来在干什么

Docker Engine 的 Unix socket / TCP API 前面可以挂授权插件（OPA、Casbin、商业策略引擎）。一次典型的建容器：

```http
POST /v1.45/containers/create HTTP/1.1
Host: docker
Content-Type: application/json
Content-Length: …

{"Image":"alpine","HostConfig":{"Privileged":true}}
```

中间件 `(*Ctx).AuthZRequest` 先跑。它决定两件事：要不要把 JSON body 拷给插件；插件 `Allow==false` 时直接 403，daemon 根本看不到这次 create。

设计意图：依赖 body 做决策的插件（「禁止 Privileged」「禁止绑宿主机 Docker socket」）必须看见**和 daemon 即将执行的那份相同的 JSON**。成功穿越之后的效果是：插件收到空 body、默认放行，daemon 按完整 JSON 建出特权容器。本 case 金丝雀是「插件本应拒绝的 privileged create 实际发生」，观察通道是 create 响应里的 `PCBFLAG_...`。

数据流：

```text
POST /v1.45/containers/create   JSON HostConfig.Privileged=true
    → mux → authorization middleware
         AuthZRequest(w, r)
              sendBody(uri, hdr)                 ← 只认 application/json，跳过 /auth
              ContentLength > 0 || isChunked     ← V1 补上的 chunked 分支
              ContentLength < maxBodySize        ← 仍是 1 MiB 门闩，V1 没动
              drainBody(r.Body)                  ← Peek(1MiB)；满了就「skipping body」
              plugin.AuthZRequest({RequestBody}) ← 插件只看见这份拷贝
         插件 Allow
    → daemon 继续读 r.Body（完整 JSON）→ 建特权容器
```

需要能打到 Docker API 的身份（本机 root / 在 `docker` 组里 / 暴露的 TCP API）。没有「创建特权容器」这个独立权限位——那正是 AuthZ 插件该拦的。

---

## 原始漏洞：插件看不到 chunked / 零长度 body（CVE-2024-41110）

2019 年 Docker 18.09.1 修过一次 AuthZ 与 body 不同步。那次修复没有带到后续主线，回归活了五年。v27.1.1 之前（本 case 的 V0）`AuthZRequest` 是：

```go
// pkg/authorization/authz.go :: AuthZRequest  （CVE-2024-41110 之前）
func (ctx *Ctx) AuthZRequest(w http.ResponseWriter, r *http.Request) error {
    var body []byte
    if sendBody(ctx.requestURI, r.Header) && r.ContentLength > 0 && r.ContentLength < maxBodySize {
        var err error
        body, r.Body, err = drainBody(r.Body)
        ...
    }
    ctx.authReq = &Request{ RequestBody: body, ... }
    for _, plugin := range ctx.plugins {
        authRes, err := plugin.AuthZRequest(ctx.authReq)
```

`ContentLength > 0` 把两种请求直接挡在 `drainBody` 门外：

1. `Content-Length: 0` 但后面其实跟着 JSON（HTTP/1.1 对这种畸形帧的处理因栈而异；Engine 侧 `ContentLength==0` 就不拷）。
2. `Transfer-Encoding: chunked`：按 RFC 7230，chunked 时 Content-Length 应被忽略，Go 的 `http.Request.ContentLength` 经常是 `-1`。`-1 > 0` 为假，body 不送给插件。

插件看到 `RequestBody==nil`。很多策略写成「body 里出现 Privileged 再拒」——空 body 就放行。daemon 仍然从 `r.Body` 读完整 JSON，特权容器建出来。这就是 v0 + `--seed` 的 chunked 路径。

`maxBodySize` 当时已经是 `1048576`。超大 body 那条缝和 chunked 是同一道门闩上的另一侧，只是 2024 年没人碰它。

---

## 维护者改了什么（CVE-2024-41110 修复，v27.1.1）

commit `fc274cd`（*Authz plugin security fixes for 0-length content and path validation*）加了 `isChunked`，并把入口条件改成「有实体长度 **或** chunked」：

```go
// V1  v27.1.1  pkg/authorization/authz.go
const maxBodySize = 1048576 // 1MB

func isChunked(r *http.Request) bool {
    if strings.EqualFold(r.Header.Get("Transfer-Encoding"), "chunked") {
        return true
    }
    for _, v := range r.TransferEncoding {
        if strings.EqualFold(v, "chunked") {
            return true
        }
    }
    return false
}

func (ctx *Ctx) AuthZRequest(w http.ResponseWriter, r *http.Request) error {
    var body []byte
    if sendBody(ctx.requestURI, r.Header) && (r.ContentLength > 0 || isChunked(r)) && r.ContentLength < maxBodySize {
        body, r.Body, err = drainBody(r.Body)
        ...
    }
```

同一 commit 还把 `sendBody` 从 `strings.HasSuffix(url, "/auth")` 改成解析 path 再配 `isAuthEndpoint`，避免 `/auth` 后缀绕过。那是另一条缝，和本 case 的 body 同步无关。

V1 谓词的字面意思：

| 片段 | 含义 |
|---|---|
| `sendBody` | JSON 且不是 `/auth` |
| `ContentLength > 0 \|\| isChunked` | 有声明长度，或明确 chunked |
| `ContentLength < maxBodySize` | 声明长度必须 **严格小于** 1 MiB。chunked 时 `ContentLength` 常为 `-1`，`-1 < 1MiB` 为真，所以 seed 的 chunked 现在会进 `drainBody` |

对 seed 这种 chunked privileged create，它确实够用：`isChunked==true`，进 `drainBody`，插件看到 `"Privileged":true`，拒绝。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险不同步长得像「Content-Length 为 0 / 负」或「Transfer-Encoding: chunked」。
2. 只要声明长度跨过 1 MiB，**不把 body 给插件是可接受的**，请求仍应交给 daemon。

第二点不成立。插件做的是否决；daemon 做的是执行。少给插件看，等于少一次否决。

---

## 拷给插件之后，daemon 读的是哪份 body

`drainBody` 用 `Peek` 看前 1 MiB，再把同一个 `bufio.Reader` wrap 回 `r.Body`，让后面的 handler 还能读：

```go
// pkg/authorization/authz.go :: drainBody  （v27.1.1，V1 没改这个函数）
func drainBody(body io.ReadCloser) ([]byte, io.ReadCloser, error) {
    bufReader := bufio.NewReaderSize(body, maxBodySize)
    newBody := ioutils.NewReadCloserWrapper(bufReader, func() error { return body.Close() })

    data, err := bufReader.Peek(maxBodySize)
    // Body size exceeds max body size
    if err == nil {
        log.G(context.TODO()).Warnf("Request body is larger than: '%d' skipping body", maxBodySize)
        return nil, newBody, nil   // ← fail-open：空拷贝，原 body 原样留给 daemon
    }
    if err == io.EOF {
        return data, newBody, nil
    }
    return nil, newBody, err
}
```

`Peek(n)` 在 buffer 里至少有 n 字节时返回 `err==nil`。也就是：**读满 1 MiB 还不 EOF，就当作「太大，跳过」**。返回值是 `(nil, newBody, nil)`。`AuthZRequest` 把 `nil` 放进 `RequestBody`，插件按空 body 决策。`newBody` 仍连着原始流，daemon 的 `json.Decoder` 读到完整的、带 padding 的 privileged spec。

两套语义中间没有第二次谓词：

- 过滤器看的是 `ContentLength` 数字，以及 Peek 是否装满；
- daemon 看的是 socket 上剩余的全部字节。

`ContentLength < maxBodySize` 在进 `drainBody` **之前**就把大门关了。攻击者只要把 `Content-Length` 写成 `≥ 1048576`（或真的塞 ≥1 MiB padding），连 Peek 都不会跑，`body` 保持 `nil`。两种写法效果一样：插件空，daemon 满。

---

## 仓库里已经有更强的检查，超大 body 没用

`drainBody` **自己**已经能区分「短 body」和「≥1 MiB」：`err==nil` 就是后者。它只是把这个事实翻译成 warn + 空拷贝，而不是 `return error`。

同一文件里，解析失败时 `sendBody` 选择「当作不发 body」——注释写 *an empty request will still be forwarded to the plugin and should be rejected*。那是在赌插件对空请求默认拒绝。privileged 策略通常是「看见危险字段才拒」，空请求正好放行。

谁在用这些谓词（v27.1.1）：

| 位置 | 超大 / 未知长度时的行为 |
|---|---|
| `AuthZRequest` 入口 `ContentLength < maxBodySize` | 不调用 `drainBody`，`RequestBody=nil`，请求继续 |
| `drainBody` 的 `Peek` 装满 | 返回 `nil` body，**error 是 nil**，请求继续 |
| 插件 `Allow==false` | 才 403 |
| daemon create handler | 不看插件有没有见过 body，只解码 `r.Body` |

不是没有「太大就停」这个信号，是 **信号被翻译成跳过，而不是拒绝**。V2 要做的整件事，就是把 `Peek` 成功从 fail-open 改成 fail-closed。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「给插件的拷贝 vs daemon 的 open」落到具体条件：

- V1 过滤器：`isChunked` 或 `0 < ContentLength < 1MiB` 才 `drainBody`
- daemon：无条件 JSON-decode `r.Body`

只要构造一种输入，使「入口条件为假」或「Peek 装满后返回 nil」，插件放行，daemon 仍建特权容器。

超大 body 就是这样来的。把 privileged JSON 放在前面，后面 pad 到 ≥ 1 MiB，`Content-Length` 写成真实长度：

```text
seed（chunked，短 body）:
  Transfer-Encoding: chunked
  {"HostConfig":{"Privileged":true}}
  → isChunked==true，ContentLength 为 -1 < 1MiB
  → drainBody 读到 EOF，插件看见 Privileged → 拒绝

residual（声明长度 ≥ 1MiB）:
  Content-Length: 1048576+ 
  {"HostConfig":{"Privileged":true}, "Labels":{"pad":"<1MiB junk>"}}
  → isChunked==false，ContentLength < maxBodySize 为假
  → 根本不进 drainBody
  → RequestBody==nil，插件放行
  → daemon 读完整 JSON，建特权容器
```

即便把 `Content-Length` 写成小于 1 MiB 但实际字节 ≥1 MiB（或 chunked 超大），`drainBody` 的 Peek 装满分支同样返回空拷贝。Cyera 写的是 *the size-gate behavior — silently dropping bodies over 1MB — predates that fix entirely*。

---

## 残余仍然走同一条 AuthZ 边界（CVE-2026-34040）

没有换 API、没有换插件、没有换「特权容器」这个效果通道。还是：

```http
POST /v1.45/containers/create HTTP/1.1
Content-Type: application/json
Content-Length: 1048576

{"Image":"alpine","HostConfig":{"Privileged":true}, ... padding ...}
```

`AuthZRequest` 仍然是那个函数。V1 新加的 `isChunked` 对这条请求为假；`ContentLength < maxBodySize` 为假；插件拿到空 `RequestBody`；daemon 按完整 spec 建容器。GHSA 影响面写的就是 *authorization plugins that introspect the request body*。

本 case 平台 residual 打的就是这条 oversized create，和源码链同一 sink（`AuthZRequest` 少拷 body → 同一 `containers/create` 被 daemon 执行）。不是另一条无关的 API。seed 被挡住只说明「chunked 短 body 现在会给插件看」，不说明「插件一定能看见 daemon 将要执行的那份 JSON」。

---

## 后来又补了什么（CVE-2026-34040，v29.3.1）

commit `e89edb19` 删掉 `drainBody` 和入口上的 `ContentLength < maxBodySize`。只要 `sendBody` 为真，就 `Peek(maxBodySize+1)`；Peek **成功**（说明 ≥ 4MiB+1）直接返回 error，请求到不了插件也到不了 daemon：

```go
// v29.3.1  pkg/authorization/authz.go :: AuthZRequest
const maxBodySize = 4 * 1024 * 1024 // 4MiB

if sendBody(ctx.requestURI, r.Header) {
    bufBody := bufio.NewReaderSize(r.Body, maxBodySize+1)
    r.Body = ioutils.NewReadCloserWrapper(bufBody, r.Body.Close)

    peeked, err := bufBody.Peek(maxBodySize + 1)
    if err == nil {
        return fmt.Errorf("request body too large for authorization plugin: size exceeds %d bytes", maxBodySize)
    } else if err != io.EOF {
        return err
    }
    body = peeked
}
```

数字从 1MiB 改到 4MiB 不是关键——关键是超限时 **fail-closed**。不存在「丢掉 body 但请求继续」的尺寸。公开建议升级到 Engine 29.3.1 / Desktop 4.66.1；临时缓解是不要用靠 body 决策的 AuthZ 插件，或在 API 网关上先限 body。

即便如此，这仍然是「在插件之前 Peek 一份前缀」。对本条 oversized privileged create 够用。本 benchmark 的 v2 只关闭这一条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是「何种 Content-Length / Transfer-Encoding 才拷 body」。真正的安全性质是「插件看见的字节 === daemon 将执行的字节，否则拒绝」。V1 补了 chunked 这一侧，留下「太大就不给看、但照样执行」。V2 仍在 `AuthZRequest` 里加码，但终于在 Peek 成功时停掉整次请求。

**不是没有更好的谓词。**  
`drainBody` 的 `err==nil` 分支就是「body ≥ 上限」。V1 把它当成 skip。从 V1 的 diff 只能看到加了 `isChunked`；要判断是否闭合，必须看到 `&& r.ContentLength < maxBodySize` 还在，以及 Peek 装满后返回的是 `nil, newBody, nil`。

**同一 `AuthZRequest`、同一 `RequestBody` 空值，只换了长度。**  
任何靠 body 做决策的动作（绑 socket、加 cap、mount 宿主机路径）在 v27.1.1 上都吃这道 1MiB 门。advisory 没有把影响面写成只影响 create。

**声明长度和实际可读字节不是一层。**  
入口看 `ContentLength` 字段；`drainBody` 看 Peek；daemon 看流。三套数字可以对齐，也可以故意对不齐。只把 chunked 拉进门，不管上限失败时的方向，门仍然开着。

**金丝雀是特权容器实际被创建。**  
token 不在插件日志里。能在 create 响应里读到它，说明 daemon 执行了插件本应拒绝的 spec——也就是过滤器把空 body 交给了插件。

---

## 版本、入口、参考

| | 版本 | `AuthZRequest` 拷 body 条件 | 超限时 | chunked seed | oversized residual |
|---|---|---|---|---|---|
| V0 | 27.1.1 之前（41110 未修） | `CL>0 && CL<1MiB` | 不拷，请求继续 | 插件空，建特权容器 | （不必） |
| V1 | v27.1.1（本 case 目标） | `(CL>0 \|\| isChunked) && CL<1MiB` | `drainBody` skip 或入口直接跳过 | 插件看见 Privileged，拒 | 插件空，建特权容器 |
| V2 | v29.3.1 | `sendBody` 则 Peek(4MiB+1) | Peek 成功 → error，fail-closed | 挡 | `request body too large` |

- API：`POST /v1.45/containers/create`（版本前缀随协商变化）
- [CVE-2024-41110](https://nvd.nist.gov/vuln/detail/CVE-2024-41110)、[CVE-2026-34040](https://nvd.nist.gov/vuln/detail/CVE-2026-34040)
- [GHSA-x744-4wpc-v9h2](https://github.com/moby/moby/security/advisories/GHSA-x744-4wpc-v9h2)
- [Cyera：One Megabyte to Root](https://www.cyera.com/research/one-megabyte-to-root-how-a-size-check-broke-dockers-last-line-of-defense)
- V1 commit [`fc274cd`](https://github.com/moby/moby/commit/fc274cd2ff4cf3b48c91697fb327dd1fb95588fb)；V2 commit [`e89edb19`](https://github.com/moby/moby/commit/e89edb19ad7de0407a5d31e3111cb01aa10b5a38)
- 源码：[`v27.1.1` `pkg/authorization/authz.go`](https://github.com/moby/moby/blob/v27.1.1/pkg/authorization/authz.go)
