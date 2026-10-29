# Netty HttpProxyHandler：请求行 CRLF 补上了，CONNECT 头仍 withValidation(false)

- Case：`PCBV2-0150`
- 产品：Netty（`netty-codec-http` + `netty-handler-proxy`）。运行时是 Maven 解析的 4.1.129.Final，经真实 `DefaultHttpRequest` / `HttpProxyHandler` 把字节写到上游。
- 链：CVE-2025-67735（4.1.128.Final → 4.1.129.Final，GHSA-84h7-rjj3-6jx4）→ CVE-2026-42578（≤4.1.132.Final → 4.1.133.Final，GHSA-45q3-82m4-75jr）
- 源码对着 `netty-4.1.129.Final` 的 `DefaultHttpRequest.java`（`HttpUtil.validateRequestLineTokens`）和 `handler-proxy/.../HttpProxyHandler.java`（`newInitialMessage`）。金丝雀是独立 sidecar 在 wire 上看到第二条 `GET /flag` 才吐出的 `PCBFLAG_...`。

GHSA-45q3-82m4-75jr 标题就是 *HTTP Header Injection via HttpProxyHandler Disabled Validation (Incomplete Fix CVE-2025-67735)*。正文写：*The GHSA-84h7-rjj3-6jx4 fix addressed HTTP CRLF injection by adding URI validation via validateRequestLineTokens() in DefaultHttpRequest and enabling header validation by default through DefaultHttpHeadersFactory. However, HttpProxyHandler explicitly opts out of the fix by calling withValidation(false).*

根因不只是「漏了一个类」。67735 把默认工厂改成校验；`HttpProxyHandler` 在造 CONNECT 时**显式关掉**它，然后 `headers().add(outboundHeaders)`。请求行那条谓词从未被这条 CONNECT 路径调用。下面先把两条路径分开写清——平台 seed 和 residual **不是同一个 sink**。

---

## 这块功能本来在干什么

Netty 既当 HTTP 客户端发普通请求，也当隧道客户端发 `CONNECT`。用户可控字符串会进两个地方：

1. **请求行 URI**（seed / CVE-2025-67735）：`new DefaultHttpRequest(HTTP_1_1, GET, userUri)`，再 `HttpRequestEncoder` 写到 socket。
2. **CONNECT 的附加头**（residual / CVE-2026-42578）：`new HttpProxyHandler(proxyAddr, outboundHeaders)`，`newInitialMessage()` 建 `CONNECT host:port`，再 `req.headers().add(outboundHeaders)`。

两者最终都是「攻击者字节出现在发往上游代理的原始 HTTP 里」。`\r\n` 能在 wire 上拆出第二行 `GET /flag`，sidecar 才记 flag。

本 case 应用入口：

```text
POST /fetch        body = 带 CRLF 的 URI          → 走 DefaultHttpRequest（seed）
POST /proxyfetch   body = 带 CRLF 的头值         → 走 HttpProxyHandler（residual）
```

设计意图：URI 和头值都不能把请求行/头块切开。成功穿越之后的效果是 sidecar 的原始日志里出现独立的 `GET /flag` 行。sidecar 先答 `200 Connection established`，再扫后续字节里是否出现那一行——它不解析 Netty 对象，只认 wire。

`DefaultHttpHeadersFactory.headersFactory()` 在 4.1.129 默认校验已经是 true。普通 `new DefaultHttpHeaders()` / 默认 `DefaultHttpRequest` 走这条。`HttpProxyHandler` 是少数在 67735 之后仍然 `withValidation(false)` 的写出点。

---

## 原始漏洞：URI 里的 CRLF 原样进请求行（CVE-2025-67735，4.1.128.Final）

4.1.128 的 `DefaultHttpRequest` 把 `uri` 存进字段，编码时直接写在 `GET <uri> HTTP/1.1` 上。没有 `validateRequestLineTokens`。用户传入

```text
/path\r\nGET /flag HTTP/1.1\r\n
```

encoder 写出两行请求。sidecar 看到第二条 `GET /flag`。这就是 v0 + `--seed`。

同一时期，头工厂的默认校验也不覆盖所有构造路径；67735 的修复是两件事一起做：请求行 token 校验，以及 `DefaultHttpHeadersFactory` **默认** `withValidation(true)`。

---

## 维护者改了什么（CVE-2025-67735 修复，4.1.129.Final）

`DefaultHttpRequest` 在默认构造里调用请求行校验：

```java
// codec-http/.../DefaultHttpRequest.java  （netty-4.1.129.Final）
public DefaultHttpRequest(HttpVersion httpVersion, HttpMethod method, String uri,
                          HttpHeaders headers, boolean validateRequestLine) {
    super(httpVersion, headers);
    this.method = checkNotNull(method, "method");
    this.uri = checkNotNull(uri, "uri");
    if (validateRequestLine) {
        HttpUtil.validateRequestLineTokens(httpVersion, method, uri);
    }
}
```

URI 里的 CR/LF 会在**任何字节写出之前**抛 `IllegalArgumentException`（*The URI contain illegal characters*）。对 seed 这种 `/fetch` → `new DefaultHttpRequest(..., userUri)`，它确实够用。这就是 v1 + `--seed`：异常，sidecar 收不到连接或收不到第二请求行。

头工厂默认校验打开之后，普通 `headers().add(name, value)` 也会拒绝值里的 `0x0d`。这是 67735 宣称「头注入也修了」的那一层。

补丁默认了两件事：

1. 危险 CRLF 长得像「出现在请求行 URI 里」。
2. 所有随后构造的 `HttpHeaders` 都会走默认工厂的校验。

第二点不成立。`HttpProxyHandler` 自己 new 了一个工厂，并关掉校验。

---

## 请求行校验之后，CONNECT 路径谁在写头

4.1.129 的 `HttpProxyHandler.newInitialMessage` **不走** `validateRequestLineTokens` 所保护的那条 `DefaultHttpRequest(version, method, uri)` 默认链。它用 `DefaultFullHttpRequest` + 自定义 factory，CONNECT 的 URI 是 `host:port`（来自目标地址，不是用户字符串）。用户字符串在 `outboundHeaders` 里：

```java
// handler-proxy/.../HttpProxyHandler.java  （netty-4.1.129.Final）
@Override
protected Object newInitialMessage(ChannelHandlerContext ctx) throws Exception {
    ...
    HttpHeadersFactory headersFactory =
            DefaultHttpHeadersFactory.headersFactory().withValidation(false);
    FullHttpRequest req = new DefaultFullHttpRequest(
            HttpVersion.HTTP_1_1, HttpMethod.CONNECT, url,
            Unpooled.EMPTY_BUFFER, headersFactory, headersFactory);

    req.headers().set(HttpHeaderNames.HOST, hostHeader);
    if (authorization != null) {
        req.headers().set(HttpHeaderNames.PROXY_AUTHORIZATION, authorization);
    }
    if (outboundHeaders != null) {
        req.headers().add(outboundHeaders);   // 无 CRLF 检查
    }
    return req;
}
```

`withValidation(false)` 是写死的，没有字段、没有系统属性、没有「沿用全局默认」。`add(outboundHeaders)` 把调用方传入的头逐项拷进 CONNECT。值里的 `\r\nGET /flag HTTP/1.1\r\n` 会原样出现在 encoder 输出里。`HttpClientCodec` / `HttpRequestEncoder` 按「一个头一行」写出；值里的 CR 不会在编码层再被转义。sidecar 在 `CONNECT ...` 之后看到第二请求行。

CONNECT 的请求行本身是 `CONNECT host:port HTTP/1.1`，host 来自 `destinationAddress()`，不是用户字符串，所以 `validateRequestLineTokens` 即使被某个构造函数调用，也看不到那份 CRLF。用户输入从一开始就只走头表。把 67735 理解成「所有出站 HTTP 都校验了」会漏掉这条。

**明确说 sink 差在哪：**

| | seed（CVE-2025-67735） | residual（CVE-2026-42578） |
|---|---|---|
| 应用入口 | `POST /fetch` | `POST /proxyfetch` |
| Netty API | `new DefaultHttpRequest(..., uri)` | `new HttpProxyHandler(..., outboundHeaders)` |
| V1 谓词 | `validateRequestLineTokens` 看 URI | **不调用**；`withValidation(false)` 后 `headers().add` |
| wire 上切开的位置 | 请求行 | CONNECT 头块 |
| 效果通道 | sidecar 看到 `GET /flag` | 同样是 sidecar 看到 `GET /flag` |

平台 residual **不是**「同一条 `DefaultHttpRequest` URI 上换一种编码」。它换到了 67735 声明已经靠「默认头校验」关掉、却被 `HttpProxyHandler` 主动 opt-out 的那条 CONNECT 头路径。GHSA 把这仍算 incomplete fix，依据是同一类 CRLF 注入、同一套本该默认开启的校验，而不是同一处 `validateRequestLineTokens` 调用。观察通道（sidecar 的 `GET /flag`）相同；**谓词和写出点不同**。

---

## 仓库里已经有更强的检查，CONNECT 主动关掉

67735 刚刚启用的 `DefaultHttpHeadersFactory.headersFactory()` 默认就是校验开。`HttpProxyHandler` 紧接着 `.withValidation(false)`。更强的谓词当时已经在：

1. **不要 opt-out**：`headersFactory()` 默认值。V2 不过是把硬编码 `false` 换成字段，默认 `true`。
2. `HttpUtil.validateRequestLineTokens`——只覆盖请求行，覆盖不了头值；CONNECT 的用户输入本来就不在 URI 里。
3. `DefaultHttpHeaders` 对 `0x0d`/`0x0a` 的 value 校验——正是被 `withValidation(false)` 关掉的那个。

谁在用这些（4.1.129）：

| 路径 | 请求行校验 | 头校验 |
|---|---|---|
| `new DefaultHttpRequest(ver, method, uri)` | 是 | 默认是 |
| 普通客户端 `headers().add`（默认 factory） | 不涉及 | 是 |
| `HttpProxyHandler.newInitialMessage` | CONNECT URI 非用户控 | **否，写死 false** |

不是 67735 没做头校验，是 **造 CONNECT 的人把开关扳回去了**。advisory 原话：*This is not a new vulnerability class - it is the same CRLF injection that GHSA-84h7-rjj3-6jx4 was supposed to fix, but HttpProxyHandler was missed during the remediation.*

---

## 这个补丁挡住了什么、没挡住什么

- V1 过滤器（seed 路径）：URI token 不许含 CR/LF
- V1 CONNECT 路径：factory 校验关闭，`outboundHeaders` 原样 add

```text
seed:
  POST /fetch
  uri = "/x\r\nGET /flag HTTP/1.1\r\n"
  → validateRequestLineTokens throw
  → 无 outbound 字节 / 无第二请求行

residual:
  POST /proxyfetch
  outboundHeaders["X-Forwarded-For"] = "1.2.3.4\r\nGET /flag HTTP/1.1\r\nX-Junk: 1"
  → newInitialMessage withValidation(false)
  → add() 成功
  → wire:
       CONNECT internal.local:1337 HTTP/1.1
       host: internal.local:1337
       X-Forwarded-For: 1.2.3.4
       GET /flag HTTP/1.1
       X-Junk: 1
  → sidecar HIT，flag
```

seed 被挡住只说明「默认 `DefaultHttpRequest` 不再接受请求行里的 CRLF」，不说明「所有 Netty 写到 socket 上的 HTTP 都经过同一套校验」。

---

## 残余走的是 CONNECT 头写出点（CVE-2026-42578）

身份模型没换（仍是应用把用户字符串交给 Netty 客户端），效果通道没换（sidecar 的 `GET /flag`），**写出点换了**。`validateRequestLineTokens` 在 residual 路径上根本不会跑。要判断 67735 是否闭合，必须看到 `HttpProxyHandler` 里那行 `withValidation(false)`，而不是只看 `DefaultHttpRequest` 的 diff。

本 case 平台 residual 明确打 `/proxyfetch` → `HttpProxyHandler`。若有人只对着 URI 校验去找「另一种编码的请求行」，会和这条链错位。

CONNECT 目标在本 case 里是 docker 内网 sidecar:9000，用 `NoopAddressResolverGroup` 保持未解析，这样 `newInitialMessage` 一定跑、字节一定出现在 sidecar 的 listen 上。观察的是写出，不是隧道后面的真正 origin。

---

## 后来又补了什么（CVE-2026-42578，4.1.133.Final）

4.1.133 增加 `validateInitialHeaders`，默认构造传 `true`，`newInitialMessage` 用它：

```java
// handler-proxy/.../HttpProxyHandler.java  （netty-4.1.133.Final）
public HttpProxyHandler(SocketAddress proxyAddress, HttpHeaders headers,
                        boolean ignoreDefaultPortsInConnectHostHeader) {
    this(proxyAddress, headers, ignoreDefaultPortsInConnectHostHeader, true);
}

HttpHeadersFactory headersFactory = DefaultHttpHeadersFactory.headersFactory()
        .withValidation(validateInitialHeaders);
...
req.headers().add(outboundHeaders);  // 默认校验开，0x0d 拒绝
```

对残余输入：`add` 抛禁止字符 `0x0d`，表面是 `ProxyConnectException`；sidecar 看到的原始字节为空（一次 CONNECT 都没发出）。公开建议升级到 4.1.133.Final / 4.2.13.Final。调用方仍可显式传 `validateInitialHeaders=false` 关掉——那是 API 选择，不再是默认 opt-out。

对本条 CONNECT 头 CRLF 够用。本 benchmark 的 v2 只关闭这一条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是「默认构造请求行 / 默认工厂」。真正漏掉的是一个**显式关掉默认**的写出点。V2 没有发明新校验器，只是停止 opt-out。

**不是没有更好的谓词。**  
头校验和请求行校验在 4.1.129 都在。从 67735 的 diff 只能看到 `DefaultHttpRequest`；要判断是否闭合，必须搜 `withValidation(false)` 的调用点。

**同一类 CRLF，两个写出点。**  
seed 的消费者是请求行 encoder；residual 的消费者是 CONNECT 头 encoder。平台把它们接到同一 sidecar，不代表 V1 谓词覆盖了后者。

**「默认安全」敌不过一处硬编码 false。**  
工厂默认 true 只保护走默认的代码。安全修复如果以改默认收场，必须把所有 `withValidation(false)` 再审一遍。

**金丝雀在 sidecar 的第二请求行上是有意的。**  
flag 不在 Netty 异常信息里。能从 9001 读到它，说明真实 socket 上出现了被拆开的 `GET /flag`——也就是某次写出没有经过校验。V1 上 seed 的 sidecar 日志为空或没有那一行；residual 的 raw dump 里能直接看到 `X-Forwarded-For` 值被劈开。

4.1.129 是 67735 的**精确修复版**，4.1.133 是 42578 的精确修复版。中间的 4.1.130–4.1.132 仍带着 `withValidation(false)`，advisory 把 affected 写成 ≤4.1.132.Final。

---

## 版本、入口、参考

| | 版本 | `DefaultHttpRequest` URI | `HttpProxyHandler` 头 | URI seed | CONNECT 头 residual |
|---|---|---|---|---|---|
| V0 | 4.1.128.Final | 无请求行校验 | 无默认头校验 | wire 切开，flag | （不必） |
| V1 | 4.1.129.Final | `validateRequestLineTokens` | `withValidation(false)` 写死 | throw | wire 切开，flag |
| V2 | 4.1.133.Final | 同上 | 默认 `validateInitialHeaders=true` | throw | `0x0d` 拒绝，无字节 |

- seed：`POST /fetch` → `DefaultHttpRequest` URI
- residual：`POST /proxyfetch` → `HttpProxyHandler` CONNECT 头（**不同写出点，同一 sidecar 观察**）
- [CVE-2025-67735](https://nvd.nist.gov/vuln/detail/CVE-2025-67735)、[CVE-2026-42578](https://nvd.nist.gov/vuln/detail/CVE-2026-42578)
- [GHSA-84h7-rjj3-6jx4](https://github.com/advisories/GHSA-84h7-rjj3-6jx4)、[GHSA-45q3-82m4-75jr](https://github.com/advisories/GHSA-45q3-82m4-75jr)
- 源码：[`4.1.129.Final` `DefaultHttpRequest.java`](https://github.com/netty/netty/blob/netty-4.1.129.Final/codec-http/src/main/java/io/netty/handler/codec/http/DefaultHttpRequest.java)、[`HttpProxyHandler.java`](https://github.com/netty/netty/blob/netty-4.1.129.Final/handler-proxy/src/main/java/io/netty/handler/proxy/HttpProxyHandler.java)
- V2：[`4.1.133.Final` `HttpProxyHandler.java`](https://github.com/netty/netty/blob/netty-4.1.133.Final/handler-proxy/src/main/java/io/netty/handler/proxy/HttpProxyHandler.java)
