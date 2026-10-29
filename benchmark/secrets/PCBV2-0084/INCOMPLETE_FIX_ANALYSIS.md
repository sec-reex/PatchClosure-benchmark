# axios：协议相对 URL 会抛错，绝对 URL 仍覆盖 baseURL

- Case：`PCBV2-0084`
- 产品：npm `axios`（github.com/axios/axios）。应用侧是一个把 `baseURL` 钉在允许上游、只让用户填 path 的出站代理。
- 链：CVE-2024-39338（1.7.3 → 1.7.4，GHSA-8hc4-vh64-cxmj，commit `6b6b605`）→ CVE-2025-27152（1.7.4 → 1.8.2，GHSA-jr5f-v2jv-69x6，commit `fb8eec2` / PR #6810；`buildFullPath` 三参在 1.8.0 的 #6192）
- 源码对着 GitHub tag `v1.7.4` 的 `lib/adapters/http.js`、`lib/core/buildFullPath.js`、`lib/helpers/isAbsoluteURL.js`、`lib/helpers/combineURLs.js`。运行时装的是发布包本身，不是抽出来的函数。

2024 年 8 月，axios 1.7.4 把 Node http adapter 里 `new URL(fullPath, 'http://localhost')` 改成非浏览器环境下 base 为 `undefined`，想挡住 `//internal/flag` 这种协议相对 URL 把请求打到内部主机。2025 年 3 月 GHSA-jr5f-v2jv-69x6 写明：*A previously reported issue (protocol-relative URL SSRF) ... A similar problem that occurs when passing ABSOLUTE URLs*。NVD CVE-2025-27152：*Even if baseURL is set, axios sends the request to the specified absolute URL*。

根因不只是「少拦了一种 URL 写法」。检查插在「`new URL` 的第二参数在 Node 里是不是 localhost」这一层；真正决定出站目的地的是更早的 `buildFullPath` / `isAbsoluteURL`；同文件里已经有 `combineURLs(baseURL, path)`，却只在「相对 URL」时调用。下面按请求走进去、1.7.4 改了哪一行、解析之后谁消费那个 URL、更强的「禁止绝对覆盖」谓词为什么没用上，把这几层写完。

---

## 这块功能本来在干什么

axios 给 Node 提供带 `baseURL` 的 HTTP 客户端。很多应用把允许的上游写进 `baseURL`，只让用户填 path：webhook 中继、图片代理、链接预览。一份典型调用：

```javascript
axios.get(userPath, { baseURL: 'http://public-app', allowAbsoluteUrls: false })
```

本 case 的 harness 把 `public-app` 当唯一允许主机，内部 sidecar `internal-sidecar` 无宿主端口，只在服务端网络里。用户通过 HTTP 把 `path` 交给服务，服务用真实 axios 发请求，把上游 body 回给调用方。

设计意图：`path` 必须是相对路径，最终 host 永远是 `public-app`。成功穿越之后的效果是：**库认为可以出站，实际请求打到内部 sidecar**，响应 body 里出现 `PCBFLAG_...`。

数据流：

```text
HTTP ?path=
    → axios.get(path, { baseURL: 'http://public-app', allowAbsoluteUrls: false })
         buildFullPath(baseURL, url)          ← isAbsoluteURL 为真则原样返回 url
         V1：new URL(fullPath, undefined)     ← 补丁插在这里（仅 Node）
         http.request({ hostname: parsed.hostname, ... })
    → 内部 sidecar body → 代理响应
```

没有登录。判断完全信任「用户字段是 path」，不信任 axios 会不会把绝对 URL 当成完整目的地。

---

## 原始漏洞：协议相对 `//host`（CVE-2024-39338，1.7.3）

1.7.3 的 http adapter 用固定 base 解析：

```javascript
// lib/adapters/http.js  (axios@1.7.3)
    const fullPath = buildFullPath(config.baseURL, config.url);
    const parsed = new URL(fullPath, 'http://localhost');
```

`isAbsoluteURL` 把 `//host` 也当成绝对（正则允许可选 scheme）：

```javascript
// lib/helpers/isAbsoluteURL.js  (v1.7.3 与 v1.7.4 字节相同)
export default function isAbsoluteURL(url) {
  return /^([a-z][a-z\d+\-.]*:)?\/\//i.test(url);
}
```

因此 `buildFullPath('http://public-app', '//internal-sidecar/flag')` **不**调用 `combineURLs`，直接返回 `//internal-sidecar/flag`。`new URL('//internal-sidecar/flag', 'http://localhost')` 继承 http scheme，host 变成 `internal-sidecar`，`baseURL` 被丢掉。

本 case 的 seed：

```text
path = //internal-sidecar/flag
```

1.7.3 请求打到 sidecar，body 里出现 `PCBFLAG_...`。`allowAbsoluteUrls: false` 在 1.7.3 的 `buildFullPath` 里还不存在，被忽略。

---

## 维护者改了什么（CVE-2024-39338 修复，1.7.4）

1.7.4（commit `6b6b605`）只改 http adapter 里 `new URL` 的第二参数。`buildFullPath.js` / `isAbsoluteURL.js` / `combineURLs.js` 与 1.7.3 **字节相同**。对着官方 tag `v1.7.4`：

```javascript
// lib/adapters/http.js :: httpAdapter / dispatchHttpRequest
// (axios@v1.7.4, 约 L229–232)
    // Parse url
    const fullPath = buildFullPath(config.baseURL, config.url);
    const parsed = new URL(fullPath, utils.hasBrowserEnv ? platform.origin : undefined);
    const protocol = parsed.protocol || supportedProtocols[0];
```

Node 里 `hasBrowserEnv` 为假，base 是 `undefined`。WHATWG：`new URL('//internal-sidecar/flag', undefined)` 抛 `TypeError: Invalid URL`。请求发不出去。

对 seed 这种协议相对 path，它确实够用：代理返回错误，body 没有金丝雀。这就是 v1 + `--seed` 退出码 10。

`buildFullPath` 在 1.7.4 仍是两参数：

```javascript
// lib/core/buildFullPath.js  (axios@v1.7.4)
export default function buildFullPath(baseURL, requestedURL) {
  if (baseURL && !isAbsoluteURL(requestedURL)) {
    return combineURLs(baseURL, requestedURL);
  }
  return requestedURL;
}
```

补丁默认了两件事：

1. 危险形态长得像「没有 scheme 的 `//host`」，在 Node 里不能单独构成 URL。
2. 只要 `new URL` 不再用 `http://localhost` 当 base，用户就不能覆盖 `baseURL`。

第二点不成立。`http://internal-sidecar/flag` 本身就是合法绝对 URL，`new URL` 不需要第二参数；`isAbsoluteURL` 为真，`buildFullPath` 原样返回，host 仍然不是 `public-app`。

---

## 消毒之后，谁真正发出那次 HTTP

V1 的 `new URL` 一成功，同一个 `dispatchHttpRequest` 立刻用 `parsed.hostname` / `parsed.port` / `parsed.protocol` 填 `http.request` 的 options。`setProxy`、`follow-redirects` 看到的都是这个 parsed URL，不是 `config.baseURL`。

```javascript
// lib/adapters/http.js  (v1.7.4, parsed 之后)
      options.hostname = parsed.hostname;
      options.port = parsed.port;
      setProxy(options, config.proxy, protocol + '//' + parsed.hostname + ...);
```

过滤器刚看过的是「协议相对 URL 在 Node 里能不能构造」；socket 看到的是 `parsed.hostname`。两套语义中间没有「最终 URL 必须以 baseURL 为前缀」的检查。GHSA-jr5f 建议的正是这一条，1.7.4 没做。

金丝雀在 `public-app` 之外、无宿主端口。body 里出现 FLAG，依据就是 axios 真的对 `internal-sidecar` 发了 HTTP。

---

## 仓库里已经有更强的检查，绝对 URL 没用上

同一份 `buildFullPath.js` 里已经有「把用户 path 拼回 baseURL」的函数：

```javascript
// lib/helpers/combineURLs.js  (axios@v1.7.4)
export default function combineURLs(baseURL, relativeURL) {
  return relativeURL
    ? baseURL.replace(/\/+$/, '') + '/' + relativeURL.replace(/^\/+/, '')
    : baseURL;
}
```

谁调用它：

| 条件 | 调用 `combineURLs`？ |
|---|---|
| `baseURL` 有值且 `isAbsoluteURL(requestedURL)` 为假 | 是，目的地钉在 base |
| `isAbsoluteURL` 为真（含 `//host` 和 `http://host`） | **否**，原样返回 `requestedURL` |

V1 等于在 adapter 层对 `//host` 加了一个**更窄**的「Node 里 new URL 会抛」副作用，而 `buildFullPath` 里那个「相对才拼接」的分支对绝对 URL 始终跳过。不是仓库里没有「钉在 baseURL 上」的原语，是 **绝对 URL 不走 combine**。

应用已经传了 `allowAbsoluteUrls: false`。1.7.4 的 `buildFullPath` 只有两个参数，这个选项被忽略。直到 1.8.x 才变成第三参。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs 出站」落到具体代码：

- `new URL(fullPath, undefined)`（Node）：协议相对 URL 非法，抛错
- `isAbsoluteURL` + `buildFullPath`：以 `://` 或 `//` 开头的字符串不拼接 baseURL
- `http.request({ hostname: parsed.hostname })`：按解析结果连主机

只要构造一种输入，使「`new URL` 在没有 base 时仍合法」且「`isAbsoluteURL` 为真」，第一行会放行，第三行仍然打到用户选的 host。

完全绝对 URL 就是这样来的：

```text
path:  http://internal-sidecar/flag

isAbsoluteURL：/^([a-z][a-z\d+\-.]*:)?\/\//i 匹配 http://  → true
buildFullPath：不 combine，返回 http://internal-sidecar/flag
new URL('http://internal-sidecar/flag')：合法，hostname=internal-sidecar
http.request：连 internal-sidecar:80
body：PCBFLAG_...
```

协议相对 seed 在 V1 变成 Invalid URL；同样的 sidecar、同样的 `baseURL`，只是多写了 `http:`。过滤器认为自己已经把「覆盖目的地」堵住了，实际上它只堵住了需要第二参数才能补 scheme 的那一种写法。

GHSA-jr5f-v2jv-69x6 的 PoC 就是 `axios.create({ baseURL: "http://localhost:10001/" }).get("http://localhost:10002/")`，请求打到 10002，连带着把 `X-API-KEY` 头带到攻击者主机。

---

## 残余仍然走同一条 axios.get 出站路径（CVE-2025-27152）

没有换 adapter、没有换 `baseURL`、没有换 harness。还是：

```text
GET /?path=http://internal-sidecar/flag
```

`buildFullPath` 仍然两参数；`isAbsoluteURL` 仍然为真；`new URL` 仍然成功；`http.request` 仍然连 sidecar；body 仍然是 FLAG。

本 case `verify.sh` 的 residual 把 candidate 写死在脚本里：

```text
path = http://internal-sidecar/flag
```

和 GHSA-jr5f 同一构造。认证：v1 + `--residual` 退出码 0，body 中观察到 `RUN_FLAG`。相对 path `/data` 在所有版本都留在 `public-app`（对照：baseURL 不是被随便绕过的）。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：adapter 补丁只针对「缺 scheme 的 `//`」；真正覆盖目的地的是 `buildFullPath` 对绝对 URL 的短路；`combineURLs` 和后来的 `allowAbsoluteUrls` 在 1.7.4 都没挂上。seed 被挡住只说明「`//host` 在 Node 里会抛」，不说明「用户不能指定出站主机」。

---

## 后来又补了什么（CVE-2025-27152，1.8.2）

1.8.0（#6192 / commit `32c7bcc`）给 `buildFullPath` 加第三参 `allowAbsoluteUrls`。1.8.1 的 http adapter **没把**该参数传进去（issue #6806）。1.8.2（PR #6810 / commit `fb8eec2`）才在 http adapter 里传入。对着 `v1.8.2`：

```javascript
// lib/core/buildFullPath.js  (axios@v1.8.2)
export default function buildFullPath(baseURL, requestedURL, allowAbsoluteUrls) {
  let isRelativeUrl = !isAbsoluteURL(requestedURL);
  if (baseURL && isRelativeUrl || allowAbsoluteUrls == false) {
    return combineURLs(baseURL, requestedURL);
  }
  return requestedURL;
}
```

本 case 的 harness 设 `allowAbsoluteUrls: false`。对残余输入：

```text
combineURLs('http://public-app', 'http://internal-sidecar/flag')
→ http://public-app/http://internal-sidecar/flag
```

host 留在 `public-app`，sidecar 收不到请求，body 没有 FLAG。公开建议是升级到 axios 1.8.2（或更高；1.8.3 还修了 xhr/fetch adapter 漏传第三参）。

即便如此，默认 `allowAbsoluteUrls` 仍是 true：应用必须显式关掉。本 benchmark 的 v2 在 harness 里关掉它，只关闭这一条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
CVE-2024-39338 改的是 `new URL` 的 base。真正丢掉 `baseURL` 的是 `buildFullPath` 的绝对短路。V2 才在这一层加 `allowAbsoluteUrls`，而且第一次加的时候 http adapter 还漏传。

**不是没有更好的谓词。**  
`combineURLs` 已经能把任意 path 钉回 base。`isAbsoluteURL` 为真时故意不调用它。从 V1 的 diff 只能看到 `http://localhost` → `undefined`；要判断补丁是否闭合，必须看到 `buildFullPath` 在绝对 URL 时返回什么。

**同一 `config.url`，只换了有没有 scheme。**  
任何把用户字符串传进 `axios.get(url)` 且依赖 `baseURL` 钉死目的地的应用，在 1.7.4 上都吃两参数 `buildFullPath` 和同一次 `http.request`。

**`allowAbsoluteUrls: false` 在 V1 是死选项。**  
harness 已经传了，1.7.4 签名里没有第三参。看起来像防御的配置，运行时不生效。

**金丝雀在另一台内部主机上是有意的。**  
body 能读到它，说明出站 socket 的 hostname 被用户字符串改掉了，而不是 `public-app` 碰巧回了 FLAG。

---

## 版本、入口、参考

| | npm | `buildFullPath` | http `new URL` base | `//sidecar` seed | `http://sidecar` residual |
|---|---|---|---|---|---|
| V0 | 1.7.3 | 两参，绝对则原样 | `'http://localhost'` | 打到 sidecar | （不必） |
| V1 | 1.7.4 | 同上 | Node：`undefined` | Invalid URL | 打到 sidecar |
| V2 | 1.8.2 | 三参，`allowAbsoluteUrls==false` 则 combine | 同 V1 | 挡 | combine 回 public-app，挡 |

- Web：harness `GET ?path=...` → `axios.get(path, { baseURL: 'http://public-app', allowAbsoluteUrls: false })`
- 认证（本平台）：v0 seed 观察到 flag；v1 seed 未观察到；v1 residual 观察到。
- [CVE-2024-39338](https://nvd.nist.gov/vuln/detail/CVE-2024-39338)、[CVE-2025-27152](https://nvd.nist.gov/vuln/detail/CVE-2025-27152)
- [GHSA-8hc4-vh64-cxmj](https://github.com/advisories/GHSA-8hc4-vh64-cxmj)、[GHSA-jr5f-v2jv-69x6](https://github.com/axios/axios/security/advisories/GHSA-jr5f-v2jv-69x6)
- V1 commit：[`6b6b605`](https://github.com/axios/axios/commit/6b6b605eaf73852fb2dae033f1e786155959de3a)
- V1 源码：[`http.js` @ `v1.7.4`](https://github.com/axios/axios/blob/v1.7.4/lib/adapters/http.js)、[`buildFullPath.js` @ `v1.7.4`](https://github.com/axios/axios/blob/v1.7.4/lib/core/buildFullPath.js)
- V2：[`fb8eec2`](https://github.com/axios/axios/commit/fb8eec214ce7744b5ca787f2c3b8339b2f54b00f)（PR #6810）；`buildFullPath` 三参见 #6192 / `32c7bcc`
