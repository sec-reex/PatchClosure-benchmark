# activitypub-federation-rust：解析出的 IP 表里没有 0.0.0.0

- Case：`PCBV2-0065`
- 产品：`activitypub_federation`（Rust crate；Lemmy / hatsu / gill 等 Fediverse 软件用来拉远程 ActivityPub 对象）
- 链：CVE-2025-25194（0.6.1 → 0.6.2 / 本 case 的 V1 钉在最后仍带缺口的发布 `0.7.0-beta.8`，commit `4ad668cc10` #134）→ CVE-2026-33693（→ `0.7.0-beta.9`，commit `4ae8532b17` #162）
- 源码对着 GitHub tag `0.6.1` / `0.7.0-beta.8` / `0.7.0-beta.9` 的 `src/config.rs::verify_url_valid`、`src/utils.rs::v4_is_invalid`。运行时是 crates.io 整包 + 真实 `fetch_object_http`，不是抽出来的谓词。

2025 年 1 月，activitypub-federation 给联邦抓取加了「先 `lookup_host`，再按 RFC1918 / loopback / link-local / multicast 拒绝」。这挡住了把域名指到 `127.0.0.1` 的 SSRF。一年后 GHSA-q537-8fr5-cw35 / NVD CVE-2026-33693 写明：同一套解析后的 IPv4 谓词**没有** `is_unspecified()`。操作系统把连到 `0.0.0.0` 的 TCP 接到本机，于是「解析结果看起来不是 loopback」的域名仍然打到 localhost。NVD 原文是 *bypass the SSRF protection introduced by the fix for CVE-2025-25194*。

根因不只是「漏了一个 IP」。检查插在「解析出来的 `IpAddr` 像不像内网」这一层；真正发 GET 的是 reqwest，它按同一主机名再连一次。标准库里 `Ipv4Addr::is_unspecified()` 一直在，同文件注释还写着等 `is_global()` 稳定再换，却谁都没挂上。下面按请求走进去、#134 改了哪几行、解析之后谁消费那个地址、更宽的谓词有没有挂上，把这几层写完。

---

## 这块功能本来在干什么

ActivityPub 联邦要拉远程对象：对方实例给一个 `https://remote.example/u/alice`，本机必须 HTTP GET 这份 JSON。crate 的公共入口是 `fetch_object_http`。规范 [B.3](https://www.w3.org/TR/activitypub/#security-considerations) 要求生产环境不要去碰 localhost。

本 case 的服务是一个真实 axum 进程，依赖 crates.io 上钉死版本的 `activitypub_federation`。外部触发：

```http
POST /fetch
Content-Type: application/json

{"url":"http://original-target.pcb/flag"}
```

handler 把 URL 交给 crate 自己的 fetch，**不**自己做 IP 检查：

```rust
// service/src/main.rs :: fetch_handler
match fetch_object_http::<(), RemoteObject>(&url, &data).await {
    Ok(res) => /* flag_body = res.object.content */,
    Err(e)  => /* blocked:true, error = crate UrlVerificationError */,
}
```

`FederationConfig` 配成 `debug=false`（生产 denylist 真跑）+ `allow_http_urls=true`（允许 http 对象 id，guard 仍执行）。实例域名是 `svc.pcb`，和攻击域名不同，所以 `is_local_url` 为假，会走进 IP 解析。

设计意图：远程对象 id 必须是公网可达的 ActivityPub 文档。成功穿越之后的效果是 **crate 对解析后的地址发了 GET，loopback sidecar 把 `${PCB_FLAG}` 当 Note.content 送回来**。flag 只活在 sidecar 进程里，服务启动时 `env -u PCB_FLAG`，所以 body 里出现金丝雀只能说明真实 SSRF，不是环境变量泄漏。

数据流：

```text
POST /fetch {url}
    → fetch_object_http
         verify_url_valid(url)          ← 补丁插在这里
              scheme http/https
              domain 正则
              非 debug：lookup_host(domain, 80)
                   V1：IPv4 is_private|link_local|loopback|multicast
                   （没有 is_unspecified / is_broadcast）
              命中则 UrlVerificationError，GET 不发
         reqwest GET 同一 url            ← 真正的 connect，内核再解析一次
    → 解析 ActivityPub JSON
    → flag_body = object.content
```

没有登录。判断完全信任「解析结果不像内网 ⇒ 可以抓」；不信任操作系统稍后怎么路由 `0.0.0.0`。

---

## 原始漏洞：域名解析成 loopback 也不查（CVE-2025-25194，0.6.1）

0.6.1 的 `verify_url_valid` 只看 scheme、本地域名、显式端口。**没有** `lookup_host`。GHSA-7723-35v7-qcxw 写的是：Webfinger / 对象抓取把用户控制的 domain 拼进 URL，再进 `fetch_object_http`；localhost 检查只认主机名字符串像不像 `localhost`，域名 `localh.st` 这种解析到 `127.0.0.1` 的写法直接穿过。

本 case 的 seed 更直：`/etc/hosts` 把 `original-target.pcb` 指到 `127.0.0.1`。V0 不解析 IP，reqwest 连 127.0.0.1:80，sidecar 返回带 flag 的 Note。这是观察到的：v0 + `--seed` 响应 `flag_body` 含 `PCBFLAG_...`。

NVD CVE-2025-25194 当时写 *a fix has not been made available*；crate 侧实际修复是 2025-01-23 的 #134，进 0.6.2。本 case 的 V1 不钉 0.6.2，而钉 **最后一份仍漏 `is_unspecified` 的已发布 crate**：`0.7.0-beta.8`。中间 #161 把内联谓词重构成 `v4_is_invalid` 并加了 `is_documentation()`，但没有单独的 crate tag；功能上和 beta.8 的内联四谓词等价——都没有 `is_unspecified()`。

---

## 维护者改了什么（CVE-2025-25194 修复，0.7.0-beta.8）

tag `0.7.0-beta.8` 的检查仍写在 `verify_url_valid` 里，在拼请求**之前**、`lookup_host` **之后**。对着 GitHub blob 原文：

```rust
// src/config.rs :: FederationConfig::verify_url_valid  (tag 0.7.0-beta.8)
        // Extra checks only for production mode
        if !self.debug {
            if url.port().is_some() {
                return Err(Error::UrlVerificationError("Explicit port is not allowed"));
            }

            // Resolve domain and see if it points to private IP
            // TODO: Use is_global() once stabilized
            // https://doc.rust-lang.org/std/net/enum.IpAddr.html#method.is_global
            let invalid_ip =
                lookup_host((domain.to_owned(), 80))
                    .await?
                    .any(|addr| match addr.ip() {
                        IpAddr::V4(addr) => {
                            addr.is_private()
                                || addr.is_link_local()
                                || addr.is_loopback()
                                || addr.is_multicast()
                        }
                        IpAddr::V6(addr) => {
                            addr.is_loopback()
                                || addr.is_multicast()
                                || ((addr.segments()[0] & 0xfe00) == 0xfc00)
                                || ((addr.segments()[0] & 0xffc0) == 0xfe80)
                        }
                    });
            if invalid_ip {
                return Err(Error::UrlVerificationError(
                    "Localhost is only allowed in debug mode",
                ));
            }
        }
```

对 seed 这种 A 记录 = `127.0.0.1` 的域名，它确实够用：`is_loopback()` 为真，crate 返回 `UrlVerificationError`，GET 不发，body 没有金丝雀。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险地址长得像 private / link-local / loopback / multicast。
2. 解析结果「不是这四类」⇒ 操作系统连过去也不会落到本机。

第二点不成立。`0.0.0.0`（`Ipv4Addr::UNSPECIFIED`）对这四个方法全是 `false`。Linux / macOS / Windows 上，对 `0.0.0.0:80` 的 TCP connect 会落到 `127.0.0.1:80`。

IPv6 分支同样窄：只认 loopback / multicast / unique-local / link-local，**没有** `to_ipv4_mapped()`。所以 `::ffff:0.0.0.0` 在 beta.8 上也过关——这是 advisory 写的次要向量，held-out 里叫 `residual6-target.pcb`。

---

## 检查之后，谁真正连那个地址

`verify_url_valid` 返回 `Ok` 之后，`fetch_object_http` 用**原来的 URL**（主机名，不是钉死的 IP）交给 reqwest。crate 的默认 client 关了自动 redirect、设了 10s timeout，但 **getaddrinfo 会再跑一遍**。

对 residual：

```text
residual-target.pcb  →  /etc/hosts  →  0.0.0.0

verify_url_valid:
  lookup_host("residual-target.pcb", 80) → 0.0.0.0
  is_private=false  is_link_local=false
  is_loopback=false is_multicast=false
  → invalid_ip = false  → Ok(())

reqwest GET http://residual-target.pcb/flag
  → 再解析到 0.0.0.0:80
  → 内核路由到 127.0.0.1:80
  → sidecar 返回 Note { content: PCBFLAG_... }
```

过滤器看的是「这四个谓词」；内核看的是「unspecified 地址怎么路由」。两套语义中间没有第二次谓词，也没有把连接钉到检查时的 IP（没有 `CURLOPT_RESOLVE` 那种 pin）。

sidecar 绑在同一容器的 loopback `:80`，以 `application/activity+json` 回答，`id` 按 Host+path 重建，好过 crate 的 `extract_id == res.url` 校验。所以 flag 出现在 `flag_body` 里，依据就是这次真实 GET，而不是 handler 自己读文件。

GHSA-q537-8fr5-cw35 还顺带写了 DNS rebinding TOCTOU（检查时公网、connect 时 loopback）。本 case **不**打那条：hosts 文件两次解析都是 `0.0.0.0`，残余只证明「unspecified 不在 denylist」。rebinding 是同一 guard 上另一缺口，advisory 单独给了较低分。

---

## 仓库里已经有更强的检查，IPv4 谓词没用

同一段注释已经点名了更宽的 API：

```rust
// TODO: Use is_global() once stabilized
```

`IpAddr::is_global()` 会把 unspecified、broadcast、documentation 和各类不可路由范围算进去。它当时还没稳定，所以维护者手写了四个方法。但 **`Ipv4Addr::is_unspecified()` 和 `is_broadcast()` 从 Rust 1.0 就稳定存在**，不需要等 `is_global`。

谁调用了它们：

| 谓词 | 在 V1 `verify_url_valid` 里？ |
|---|---|
| `is_private` / `is_loopback` / `is_link_local` / `is_multicast` | 是 |
| `is_unspecified`（0.0.0.0） | **否** |
| `is_broadcast`（255.255.255.255） | **否** |
| `is_documentation` | 否（#161 才加进 `v4_is_invalid`，仍无 unspecified） |
| IPv6 `to_ipv4_mapped()` 再走 v4 谓词 | **否**（V2 的 `v6_is_invalid` 才有） |
| IPv6 原生 `is_unspecified`（`::`） | **否**（V2 才有；V1 的 v6 分支手写 bitmask） |

不是标准库没有更好的谓词，是 **解析后的 match 没用**。advisory 还指出不对称：V2 重构后 `v6_is_invalid` 对原生 `::` 已经 `is_unspecified()`，却把 `::ffff:0.0.0.0` 交给 `v4_is_invalid`——而 v4 当时仍漏 unspecified。缺口从 v4 表漏到 mapped-v6。

即便 `0.0.0.0` 没有把这四个方法打穿，只要 reqwest 继续用主机名重解析，任何「检查时看起来公网、连接时落到本机」的写法都还可能过。本 residual 不需要 TOCTOU：两次解析都是 unspecified。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs connect」落到具体值：

- `verify_url_valid` 的 IPv4 分支：看 `is_private|link_local|loopback|multicast`
- 内核 / reqwest：看 `connect(0.0.0.0:80)` 实际落到哪

```text
地址            is_loopback  is_private  is_unspecified  V1 放行？  connect 落到
127.0.0.1       true         false       false           否        （seed，挡住）
10.0.0.1        false        true        false           否
169.254.0.1     false        false*      false           否（link_local）
0.0.0.0         false        false       true            是        127.0.0.1
255.255.255.255 false        false       false           是        （broadcast，advisory 一并补）
::ffff:0.0.0.0  （走 V1 v6 分支，四条 bitmask 全否）     是        同 0.0.0.0
```

`* 169.254.0.0/16` 在 Rust 里 `is_link_local()` 为真，不靠 `is_private()`。

seed 的 token 是字面 loopback，被 `is_loopback` 吃掉。residual 的 token 是 unspecified：四个方法全否，字符串形态也不像 `127.0.0.1`，但路由语义与 loopback 相同。过滤器认为自己已经按 ActivityPub B.3 清干净了本机，实际上它刚放行了一种操作系统会当成本机的写法。

---

## 残余仍然走同一条联邦抓取路径（CVE-2026-33693）

没有换 API、没有换身份、没有换 sidecar。还是：

```http
POST /fetch
{"url":"http://residual-target.pcb/flag"}
```

`fetch_object_http` 仍然先 `verify_url_valid`。V1 那四个谓词照样执行；执行完之后 `invalid_ip=false`；reqwest 连 `0.0.0.0:80`；sidecar 把 flag 写进 Note.content；handler 放进 `flag_body`。

held-out 把 candidate 写死为：

```text
TARGET_URL    = http://residual-target.pcb/flag      → hosts 0.0.0.0
TARGET_URL_V6 = http://residual6-target.pcb/flag     → hosts ::ffff:0.0.0.0
```

和 GHSA-q537-8fr5-cw35 的攻击步骤同一构造（evil.com A → 0.0.0.0），只是域名换成 hosts 固定解析，避免对外部 DNS 的依赖。认证合同（dossier / case.json 记录的一次真实 Docker gate，**本分析未重新 compose**）：v1 + residual 观察到 `PCBFLAG_...`。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：denylist 比「会落到本机的地址」窄；真正 connect 发生在检查之后且不钉 IP；标准库里已经有 `is_unspecified` 却没挂上。seed 被挡住只说明「字面 127.0.0.1 没了」，不说明「不能再经联邦 fetch 读到 loopback 服务」。

---

## 后来又补了什么（CVE-2026-33693，0.7.0-beta.9）

#161 先把内联 match 抽成 `src/utils.rs` 的 `v4_is_invalid` / `v6_is_invalid`（仍无 unspecified）。#162 / commit `4ae8532b17bc35755240b7f55d4a5b7665351599` 在 v4 上补了两行，进 0.7.0-beta.9：

```rust
// src/utils.rs :: v4_is_invalid  (tag 0.7.0-beta.9)
fn v4_is_invalid(v4: Ipv4Addr) -> bool {
    v4.is_private()
        || v4.is_loopback()
        || v4.is_link_local()
        || v4.is_multicast()
        || v4.is_documentation()
        || v4.is_unspecified()
        || v4.is_broadcast()
}

fn v6_is_invalid(v6: Ipv6Addr) -> bool {
    v6.is_loopback()
        || v6.is_multicast()
        || v6.is_unique_local()
        || v6.is_unicast_link_local()
        || v6.is_unspecified()
        || v6_is_documentation(v6)
        || v6.to_ipv4_mapped().is_some_and(v4_is_invalid)
}
```

对残余输入：`0.0.0.0` 现在 `is_unspecified()==true` → `UrlVerificationError`（crate 原文仍说 *points to local IP address* / `DANGER_FEDERATION_ALLOW_LOCAL_IP`）。mapped-v6 经 `to_ipv4_mapped()` 继承同一拒绝。公开建议是升级 `activitypub_federation` 到 `0.7.0-beta.9`。

即便如此，这仍然是「解析后的地址表」，reqwest 仍用主机名重解析。`is_global()` 的 TODO 还在。advisory 里那条 TTL=0 rebinding 需要另证。本 benchmark 的 v2 只关闭 `0.0.0.0` / `::ffff:0.0.0.0` 这一条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是 `verify_url_valid` 里对 `lookup_host` 结果的分类。真正打到 sidecar 的是 reqwest 对同一主机名的 connect，以及内核把 unspecified 当成本机。V2 仍在同一层加码（多两个谓词），没有把连接钉到检查时的 IP。

**不是没有更好的谓词。**  
`Ipv4Addr::is_unspecified()` 一直稳定。注释里的 `is_global()` 更接近「不可路由就拒绝」。从 V1 的 diff 只能看到加了 private/loopback/link-local/multicast；要判断补丁是否闭合，必须看到 `0.0.0.0` 在这四个方法上的返回值，以及 connect 时内核怎么路由。

**同一函数、同一 `url`，只换了 A 记录。**  
任何把用户 URL 传进 `fetch_object_http` 的路径（对象抓取、Webfinger）在 beta.8 上都吃这一段 match。advisory 的攻击面是未认证联邦流量。

**检查用的 IP 和连接用的 IP 不是同一个 socket 地址。**  
`lookup_host` 的结果只用来 `any(|addr| ...)`，通过之后丢掉。reqwest 再解析。hosts 文件两次给出同一 unspecified 就已经够 residual；若 DNS 两次答案不同，还是 TOCTOU。

**金丝雀在 loopback 且不在服务环境变量里是有意的。**  
`PCBFLAG_...` 只由 sidecar 写进 ActivityPub JSON。能读到它，说明 crate 真的对 0.0.0.0 发了 GET。

---

## 版本、入口、参考

| | crate | `verify_url_valid` IPv4 | 明文 `127.0.0.1` seed | `0.0.0.0` residual |
|---|---|---|---|---|
| V0 | 0.6.1 | 无 `lookup_host` | 读到金丝雀 | （不必；同样能读） |
| V1 | 0.7.0-beta.8 | `private\|link_local\|loopback\|multicast`，无 unspecified | `UrlVerificationError` | 读到金丝雀 |
| V2 | 0.7.0-beta.9 | `v4_is_invalid` 加 `is_unspecified`/`is_broadcast`；v6 走 `to_ipv4_mapped` | 挡 | 挡 |

- Web：`POST /fetch {"url":"http://<domain>/flag"}`
- 认证记录（dossier，非本次运行）：v0 seed 观察到 flag；v1 seed 未观察到；v1 residual 观察到；v2 residual 被 crate 自己的 local-IP 错误挡住。
- [CVE-2025-25194](https://nvd.nist.gov/vuln/detail/CVE-2025-25194)、[CVE-2026-33693](https://nvd.nist.gov/vuln/detail/CVE-2026-33693)
- [GHSA-7723-35v7-qcxw](https://github.com/LemmyNet/lemmy/security/advisories/GHSA-7723-35v7-qcxw)（seed）
- [GHSA-q537-8fr5-cw35](https://github.com/advisories/GHSA-q537-8fr5-cw35)（residual；写明 *does not check for Ipv4Addr::UNSPECIFIED*）
- V1 源码：[tag 0.7.0-beta.8 `src/config.rs`](https://github.com/LemmyNet/activitypub-federation-rust/blob/0.7.0-beta.8/src/config.rs) `verify_url_valid`
- V1 引入：[commit `4ad668cc10`](https://github.com/LemmyNet/activitypub-federation-rust/commit/4ad668cc1074a691e77dd9dc8fae3835262c9cbd) #134
- V2：[commit `4ae8532b17`](https://github.com/LemmyNet/activitypub-federation-rust/commit/4ae8532b17bc35755240b7f55d4a5b7665351599) #162；[tag 0.7.0-beta.9 `src/utils.rs`](https://github.com/LemmyNet/activitypub-federation-rust/blob/0.7.0-beta.9/src/utils.rs)
