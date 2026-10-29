# Netty HttpObjectDecoder：colon 前空白补上了，CL+TE 仍然静默选 chunked

- Case：`PCBV2-0149`
- 产品：Netty `io.netty:netty-codec-http`。运行时是 Maven 解析的 4.1.43.Final，经 `HttpServerCodec` 解码原始字节。不是抽出来的 `splitHeader`。
- 链：CVE-2019-16869（4.1.41.Final → 4.1.42.Final，PR #9585，commit `39cafcb`）→ CVE-2020-7238（4.1.43.Final 仍受影响，4.1.44.Final，PR #9865，commit `8494b04`）
- 源码对着 tag `netty-4.1.43.Final` 的 `codec-http/.../HttpObjectDecoder.java`（`splitHeader` / `readHeaders`）。金丝雀是源站 `GET /flag` 返回的 `PCBFLAG_...`：只有当前序请求被当成 chunked（或其它会把后续字节当成下一请求的帧）时，pipeline 里的第二请求才会被解码。

NVD 对 CVE-2020-7238 的原话：*Netty 4.1.43.Final allows HTTP Request Smuggling because it mishandles Transfer-Encoding whitespace (such as a [space]Transfer-Encoding : chunked line) ... NOTE: this issue exists because of an incomplete fix for CVE-2019-16869.* 公开描述仍在说空白，但 4.1.44 真正合进去的是 `readHeaders` 对 **Content-Length + Transfer-Encoding: chunked** 的拒绝——也就是 RFC 7230 §3.3.3 那条「应当当错误处理」的冲突。whitespace 那条在 4.1.42 已经挂上了。

根因不只是「正则/空白没写完」。检查插在「header **名字**里能不能夹空格」上；真正决定「这段 body 有多长、后面的字节算不算下一个请求」的是 `readHeaders` 选的 state。同一次解码里已经能看到 `Content-Length` 和 `Transfer-Encoding` 两份头，却仍让 chunked 静默覆盖 CL。下面按字节走进去。

---

## 这块功能本来在干什么

`HttpObjectDecoder` 把 TCP 流切成 HTTP/1.1 消息。反向代理 / 前面的客户端按自己的规则切；Netty 源站再切一次。两边对「body 在哪结束」不一致，就会把 pipeline 里的下一请求当成上一请求的 body，或反过来。

一次意图中的请求：

```http
GET / HTTP/1.1
Host: origin
Content-Length: 0

```

本 case 源站还有：

```http
GET /flag HTTP/1.1
```

只有当前序请求被解码器 **接受** 并且按某种 framing 把 `/flag` 当成**第二个**请求，router 才会把金丝雀写进响应流。前序若进 `BAD_MESSAGE`，连接关掉，后面的字节被吞掉。

数据流：

```text
原始套接字字节
    → HttpServerCodec / HttpObjectDecoder
         splitHeader(line)              ← V1 改的：请求里空白不再结束 name
         headers.add(name, value)       ← DefaultHttpHeaders 校验非法名
         readHeaders()
              isTransferEncodingChunked? → READ_CHUNK_SIZE
              else contentLength()>=0   → READ_FIXED_LENGTH_CONTENT
         （V1：CL 和 TE:chunked 可以同时存在，chunked 赢）
    → 切出的 HttpRequest 进 router
    → GET /flag → body 里 PCBFLAG_...
```

没有鉴权。效果通道是「第二请求是否被当成独立 GET」。源站 router 本身不解析 Transfer-Encoding；它只看见 decoder 交出来的 `HttpRequest`。所以 residual 不需要换 path、换方法，只需要让 decoder 把 pipeline 切两次。

---

## 原始漏洞：名字和冒号之间的空白（CVE-2019-16869，4.1.41.Final）

4.1.41 的 `splitHeader` 在扫 name 时，遇到空白就停：

```java
// HttpObjectDecoder.splitHeader  （4.1.41.Final）
for (nameEnd = nameStart; nameEnd < length; nameEnd ++) {
    char ch = sb.charAtUnsafe(nameEnd);
    if (ch == ':' || Character.isWhitespace(ch)) {
        break;
    }
}
```

`Transfer-Encoding : chunked`（colon 前一个空格）会把 name 停在 `Transfer-Encoding`，后面的空白被跳过，值仍是 `chunked`。解码器认为这是合法的 TE:chunked。前置代理若按 Content-Length 切、或不认带空格的 TE，两边 framing 分裂。seed 把 smuggled `GET /flag` 放在这种前序后面，Netty 按 chunked 读完（或把后续当新请求），flag 出现在响应流。这就是 v0 + `--seed`。

RFC 7230 §3.2.4 写得很清楚：请求里 field-name 和 colon 之间不许有空白，服务器必须 400。

---

## 维护者改了什么（CVE-2019-16869 修复，4.1.42 / 本 case V1=4.1.43）

PR #9585 / commit `39cafcb` 让**请求**路径上空白不再结束 name，把空格留在 name 里，交给 `DefaultHttpHeaders` 去拒绝非法名。响应路径仍跳过空白（代理转发）：

```java
// HttpObjectDecoder.splitHeader  （netty-4.1.43.Final）
nameStart = findNonWhitespace(sb, 0);
for (nameEnd = nameStart; nameEnd < length; nameEnd ++) {
    char ch = sb.charAtUnsafe(nameEnd);
    // RFC 7230 §3.2.4
    if (ch == ':' ||
            (!isDecodingRequest() && Character.isWhitespace(ch))) {
        break;
    }
}
name = sb.subStringUnsafe(nameStart, nameEnd);
```

请求里 `Transfer-Encoding : chunked` 的 name 变成 `"Transfer-Encoding "`（带空格）。`headers.add` 时 `DefaultHttpHeaders` 的 name 校验拒绝，消息进失败路径，连接关掉。对 seed 这种 colon 前空白，它确实够用。这就是 v1 + `--seed`：400，body 里没有金丝雀。

补丁默认了两件事：

1. 走私长得像「TE 名字和冒号之间夹空白」。
2. 合法、干净的 `Transfer-Encoding: chunked` 配上 `Content-Length` 时，选 chunked 是安全的。

第二点正是 RFC 7230 §3.3.3 警告过的：同时出现 TE 和 CL「可能表示 request smuggling，应当当错误处理」。V1 的 `readHeaders` 没碰这条。

---

## 名字合法之后，谁决定 body 有多长

`splitHeader` 一结束，`readHeaders` 把 name/value 加进 `message.headers()`，然后选下一个 state。4.1.43 仍是：

```java
// HttpObjectDecoder.readHeaders  （netty-4.1.43.Final）
if (isContentAlwaysEmpty(message)) {
    HttpUtil.setTransferEncodingChunked(message, false);
    nextState = State.SKIP_CONTROL_CHARS;
} else if (HttpUtil.isTransferEncodingChunked(message)) {
    nextState = State.READ_CHUNK_SIZE;          // ← 有 TE:chunked 就走 chunked
} else if (contentLength() >= 0) {
    nextState = State.READ_FIXED_LENGTH_CONTENT;
} else {
    nextState = State.READ_VARIABLE_LENGTH_CONTENT;
}
return nextState;
```

`HttpUtil.isTransferEncodingChunked` 看的是已经通过 name 校验、进了 `HttpHeaders` 的值，大小写不敏感，认 `chunked` 这个 token。`Content-Length` 即使也在，只要 TE 是 chunked，就**不会**走 `READ_FIXED_LENGTH_CONTENT`。没有 throw，没有 400。`contentLength()` 只在「不是 chunked」的分支里参与选 state；冲突时它被跳过，不是被交叉检查。

前置代理若按 CL 把 smuggled 请求当成 body 的一部分转过来，Netty 按 chunked 解析：chunk 结束之后的字节成为连接上的下一消息。`GET /flag` 被独立解码。过滤器刚看过的是「name 里有没有空白」；framing 看的是「TE 和 CL 能不能共存」。中间没有第二次 RFC 谓词。

`DefaultHttpHeaders` 对合法名字 `Transfer-Encoding`、合法值 `chunked` 没有任何意见——它不负责「这两个合法头的组合」。V1 把安全性质完全压在 name 校验上，合法组合必然漏。

---

## 仓库里已经有更强的检查，冲突头没用

同一解码器里已经有：

1. `DefaultHttpHeaders` 的 name/value 校验（V1 正是靠它拒绝带空格的 name）。
2. RFC 7230 原文就在 `splitHeader` 的注释里——维护者读过 §3.2.4，但没把 §3.3.3 的「CL+TE 当错误」写进 `readHeaders`。
3. `contentLength()` / `HttpUtil.getContentLength` 已经能取出 CL。V2 要做的只是：在 `isTransferEncodingChunked` 为真且 `contentLengthValuesCount > 0` 时 throw。

谁在用这些（4.1.43）：

| 位置 | CL+TE:chunked |
|---|---|
| `splitHeader`（请求） | 不关心，只扫空白 |
| `DefaultHttpHeaders.add` | 名字合法就收 |
| `readHeaders` 选 state | **chunked 覆盖 CL，不报错** |
| 后续 `READ_CHUNK_SIZE` | 按 chunk 读 body |

不是 RFC 里没有这条规则，是 **选 state 的那一层没用**。即便空白没有把 `splitHeader` 打穿，只要 `readHeaders` 继续让 chunked 静默赢，干净的 CL.TE 仍然能走私。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「name 空白 vs framing 冲突」落到具体字节：

- V1 过滤器：请求 header name 不能在 colon 前被空白截断（空格留在 name 里 → 校验失败）
- `readHeaders`：合法 `Transfer-Encoding: chunked` 存在则 `READ_CHUNK_SIZE`，不管有没有 CL

```text
seed:
  Transfer-Encoding : chunked     （colon 前空格）
  → name="Transfer-Encoding " → DefaultHttpHeaders 拒绝 → 400
  后续 GET /flag 被吞

residual:
  Content-Length: <某长度>
  Transfer-Encoding: chunked      （干净，无空白）
  → splitHeader 两行都合法
  → isTransferEncodingChunked==true → READ_CHUNK_SIZE
  → 按 chunked 切，pipeline 里的 GET /flag 成为第二请求
  → flag 出现在响应流
```

NVD 文案仍举 `[space]Transfer-Encoding : chunked`，容易让人以为 4.1.43 的残余还是空白变体。对着 V1 源码，空白路径已经死了；4.1.44 合入的测试和 throw 信息是 *Both 'Content-Length: …' and 'Transfer-Encoding: chunked' found*。平台 residual 走的是这条 CL.TE，**同一 `HttpObjectDecoder` 帧边界 sink**，不是另一个 handler。谓词从 `splitHeader` 换成了 `readHeaders` 里没写的那条 RFC 条款。

---

## 残余仍然走同一条解码器帧边界（CVE-2020-7238）

没有换端口、没有换 `/flag`、没有换「第二请求被解码」这个效果通道。还是同一条 TCP 连接上的 pipelined 字节。前序改成干净的 CL+TE:chunked；`splitHeader` 的 V1 改动照样执行且放行；`readHeaders` 仍选 `READ_CHUNK_SIZE`；`GET /flag` 仍被当成独立请求。

本 case residual 和 PR #9865 要关的那条链一致。seed 被挡住只说明「colon 前空白不再把 TE 认成合法」，不说明「解码器不会在 CL 和 TE 之间站队」。

HTTP/1.0 在 V2 里仍可能走旧逻辑（throw 有 `HTTP_1_1` 守卫）。本 benchmark 的前序是 HTTP/1.1，和 RFC 7230 的 MUST 对齐。平台 residual 用 raw socket 送字节，不经任何 HTTP 客户端库规范化，所以 CL 和 TE 会同时到达 `readHeaders`。

---

## 后来又补了什么（CVE-2020-7238，4.1.44.Final）

PR #9865 / commit `8494b04` 在 `readHeaders` 里先数 `Content-Length`，HTTP/1.1 下多 CL 直接 throw；若 TE:chunked 且已经有 CL，再 throw：

```java
// HttpObjectDecoder.readHeaders  （4.1.44.Final）
List<String> values = headers.getAll(HttpHeaderNames.CONTENT_LENGTH);
int contentLengthValuesCount = values.size();
if (contentLengthValuesCount > 1 && message.protocolVersion() == HttpVersion.HTTP_1_1) {
    throw new IllegalArgumentException("Multiple Content-Length headers found");
}
...
} else if (HttpUtil.isTransferEncodingChunked(message)) {
    if (contentLengthValuesCount > 0 && message.protocolVersion() == HttpVersion.HTTP_1_1) {
        throw new IllegalArgumentException(
            "Both 'Content-Length: " + contentLength + "' and 'Transfer-Encoding: chunked' found");
    }
    return State.READ_CHUNK_SIZE;
}
```

对残余输入：两行头都合法，但选 state 之前就进 BAD_MESSAGE，400 + 关连接，`GET /flag` 不会被解码。公开建议升级到 4.1.44.Final。whitespace 拒绝仍然保留。

即便如此，这仍然是「在选 framing 之前 throw」，没有改成「只认一种长度来源并忽略另一种」。对本条 CL.TE 够用。本 benchmark 的 v2 只关闭这一条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是 header **名字**的切分。真正决定走私能不能成的是 **body 长度状态机**。V2 仍在同一类里加码，但终于在 `readHeaders` 选 state 之前处理冲突。

**不是没有更好的谓词。**  
§3.3.3 和 `getAll(CONTENT_LENGTH)` 在 4.1.43 都在。从 V1 的 diff 只能看到 `splitHeader` 的 `isDecodingRequest` 分支；要判断是否闭合，必须看到 `readHeaders` 里 `isTransferEncodingChunked` 仍无条件赢。

**同一解码器、同一 `/flag` sink，只换了前序头的写法。**  
空白 TE 和干净 CL.TE 都是为了让「第二请求」被 Netty 单独解码。NVD 把后者算作前者的 incomplete fix，依据是同一 smuggling 面，不是同一行正则。

**name 校验不是 framing 校验。**  
`DefaultHttpHeaders` 能拒绝非法 token，不能表达「这两个合法头不能一起出现」。把安全性质完全交给 name 校验，CL.TE 这种全是合法 token 的冲突会漏。

**金丝雀在第二请求的响应里是有意的。**  
`/flag` 不是第一请求的 path。能在原始响应流里读到 flag，说明解码器把 pipeline 切成了两次 HTTP 消息——也就是 `readHeaders` 选的 framing 让后续字节成为了新请求。若前序进 BAD_MESSAGE，Netty 关连接，router 根本看不到第二次 `channelRead`。

4.1.43 作为 V1 而不是 4.1.42，是因为 4.1.42 已经带上 whitespace 修复，4.1.43 仍未带 CL+TE 拒绝——和 NVD「4.1.43.Final allows smuggling / incomplete fix」的版本钉一致。

---

## 版本、入口、参考

| | 版本 | `splitHeader`（请求） | `readHeaders` CL+TE | 空白 TE seed | 干净 CL.TE residual |
|---|---|---|---|---|---|
| V0 | 4.1.41.Final | 空白结束 name，TE 合法 | chunked 覆盖 CL | 第二请求被解码，flag | （不必） |
| V1 | 4.1.43.Final | 空白留在 name，校验拒绝 | 仍覆盖，不报错 | 400 | 第二请求被解码，flag |
| V2 | 4.1.44.Final | 同上 | HTTP/1.1 throw | 400 | 400 |

- 库：`HttpServerCodec` / `HttpObjectDecoder` 对原始 HTTP/1.1 字节
- [CVE-2019-16869](https://nvd.nist.gov/vuln/detail/CVE-2019-16869)、[CVE-2020-7238](https://nvd.nist.gov/vuln/detail/CVE-2020-7238)
- PR [#9585](https://github.com/netty/netty/pull/9585)、[#9865](https://github.com/netty/netty/pull/9865)
- 源码：[`netty-4.1.43.Final` `HttpObjectDecoder.java`](https://github.com/netty/netty/blob/netty-4.1.43.Final/codec-http/src/main/java/io/netty/handler/codec/http/HttpObjectDecoder.java)
