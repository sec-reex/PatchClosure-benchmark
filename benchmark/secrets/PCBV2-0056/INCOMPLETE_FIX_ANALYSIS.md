# Astro：`isRemotePath` 认 `//host`，不认 WHATWG 会当成 `//` 的 `\\host`

- Case：`PCBV2-0056`
- 产品：Astro（`output: 'server'` + `@astrojs/node`）。本 case npm 安装整包 `astro@5.13.1` / `5.13.4` / `5.13.10`，打内置 `GET /_image`。守卫在传递依赖 `@astrojs/internal-helpers` 的 `isRemotePath`。
- 链：CVE-2025-55303（5.13.1 / ih 0.7.1 → 5.13.4 / ih 0.7.2，commit `4d16de7` 量级，正则加上裸 `//`）→ CVE-2025-59837（5.13.10 / ih 0.7.3，commit `1e2499e`，解码 `%5C` 并把前导 `\` 当 remote）。GHSA-qcpr-679q-rhm2 把 59837 写成 CVE-2025-58179 的 patch bypass；本 case 配对的是 55303 的 `//` 修复与 59837 的反斜杠残余。
- 源码对着 GitHub tag `astro@5.13.4` 的 `packages/internal-helpers/src/path.ts`（`isRemotePath`）和 `packages/astro/src/assets/endpoint/generic.ts`（`GET`）。V2 对着 `astro@5.13.10` 同文件。运行时是真实 `astro build` + standalone Node，不是抽出来的函数。

`/_image` 用 `isRemotePath` 决定要不要强制 `image.domains` 白名单。本地路径跳过白名单，再 `new URL(src, origin)` + `fetch`。5.13.4 让协议相对 URL `//host` 被当成 remote，于是未在名单里的 sidecar 得 403。GHSA-qcpr 原文：*The fix blocks `http://`, `https://` and `//`, but can be bypassed using backslashes (`\`) - the endpoint still issues a server-side fetch.*

根因不只是「正则漏了反斜杠」。检查问的是 **字符串是不是以 `//` 开头**；真正发请求的是 **WHATWG `URL`，它会把 `\\` 归一成 `/`**。下面按 GET 走进去、0.7.2 改了哪段正则、`new URL` 之后谁去 `fetch`、仓库里已有的 `slash()` 有没有挂上分类器，把这几层写完。

---

## 这块功能本来在干什么

SSR Astro 站点把图片优化入口暴露为 `/_image`。配置：

```js
image: {
  domains: ['public-app'],
  service: { entrypoint: 'astro/assets/services/noop' },
  endpoint: { entrypoint: 'astro/assets/endpoint/generic' },
}
```

`generic` 而不是 node adapter 自带的 `node` endpoint：后者在 production 对本地路径还有一层 `dist/assets` 前缀检查，会在 SSRF 之前返回 500，把这个洞挡住（case.json `endpoint_faithfulness_note`，**observed**）。CVE 的真实表面是所有 SSR/serverless 用的 generic 入口。

一次典型请求：

```http
GET /_image?href=http://public-app/img.png
```

`parseURL` 取出 `src`，`isRemotePath(src)` 为真则 `isRemoteAllowed`；不在 `image.domains` 就 403。为假则跳过白名单，仍 `new URL(src, origin)` 再 `fetch`。成功穿越之后的效果是：**服务端向未公开的 sidecar `internal-sidecar` 发请求，noop service 把上游 body（flag）原样还给客户端**。没有登录。判断完全信任「看起来不像 `http(s)://` 或 `//` 的 src 就是站内路径」，不信任 URL 解析器会把反斜杠当成斜杠。

数据流：

```text
GET /_image?href=<src>
    → generic GET
         isRemotePath(transform.src)
              V0：/^(?:http|ftp|https|ws):?\/\//  或 data:
              V1：再加上 |\/\/
         若 remote 且 !isRemoteAllowed → 403
         sourceUrl = new URL(src, url.origin)     ← WHATWG：\\ → /
         fetch(sourceUrl)
    → noop 把上游字节写进 200 body
```

sidecar 没有宿主机端口，不在 `image.domains`。能读到它的 flag，说明 `fetch` 的 host 是 `internal-sidecar`，不是 origin 自己。

---

## 原始漏洞：协议相对 URL 不当 remote（CVE-2025-55303，ih 0.7.1）

0.7.1 的 `isRemotePath`（case.json，**observed** 于容器内依赖）：

```js
// @astrojs/internal-helpers@0.7.1  path.js
isRemotePath = /^(?:http|ftp|https|ws):?\/\//.test(src) || src.startsWith('data:')
```

`//internal-sidecar/flag` 没有 scheme，正则不匹配，也不是 `data:`，于是 `isRemotePath === false`，白名单跳过。`new URL('//internal-sidecar/flag', origin)` 的 host 是 `internal-sidecar`，`fetch` 打到 sidecar，body 里是 flag。这就是 v0 + `--seed` 退出码 0。

合法 `http://public-app/img.png` 在三个版本上都落到 public-app、没有 flag（**observed**），说明 403 是白名单在工作，不是入口坏了。

---

## 维护者改了什么（CVE-2025-55303 修复，ih 0.7.2 / astro 5.13.4）

tag `astro@5.13.4` 的 `packages/internal-helpers/src/path.ts`：

```ts
/**
 * Regex that matches the following URLs like:
 * - http://example.com
 * - https://example.com
 * - ftp://example.com
 * - ws://example.com
 * - //example.com (protocol-relative URLs)
 */
const URL_PROTOCOL_REGEX = /^(?:(?:http|ftp|https|ws):?\/\/|\/\/)/;

/**
 * Checks whether the path is considered a remote path. Paths need to start with:
 * - `http://` `https://` `ftp://` `ws://`
 * - `//` (protocol-relative URLs)
 * - `data:` (base64 images)
 */
export function isRemotePath(src: string) {
    return URL_PROTOCOL_REGEX.test(src) || src.startsWith('data:');
}
```

对 seed 这种明文 `//internal-sidecar/flag`，它确实够用：正则的 `|\/\/` 分支匹配，`isRemotePath === true`，`isRemoteAllowed` 查 `image.domains`，sidecar 不在名单里，generic endpoint 返回 403。这就是 v1 + `--seed` 退出码 10。

同一请求路径上的消费者没变。tag `astro@5.13.4` 的 `packages/astro/src/assets/endpoint/generic.ts` 函数 `GET`：

```ts
const isRemoteImage = isRemotePath(transform.src);

if (isRemoteImage && isRemoteAllowed(transform.src, imageConfig) === false) {
    return new Response('Forbidden', { status: 403 });
}

const sourceUrl = new URL(transform.src, url.origin);
inputBuffer = await loadRemoteImage(sourceUrl, isRemoteImage ? new Headers() : request.headers);
```

`loadRemoteImage` 就是 `fetch(src)`。注意：`isRemotePath === false` 时**仍然** `new URL` + `fetch`，只是把浏览器的 `request.headers` 转发出去，并跳过 allowlist。

补丁默认了两件事：

1. 会变成「别的 host」的 src，都长得像 `scheme://` 或开头两个**正斜杠**。
2. 分类器用的字符串，就是 `new URL` 看见的那种斜杠。

第二点不成立。查询串里的 `%5C%5C` 解码成 `\\`；WHATWG 对 http(s) 把 `\` 当 `/`。`\\internal-sidecar\flag` 在分类器里不像 `//`，在 `URL` 里却是 `http://internal-sidecar/flag`。

---

## 消毒之后，谁真正用那个 src 去 fetch

V1 的正则只看 `transform.src` 的原始字符。`generic.ts` 紧接着：

```ts
const sourceUrl = new URL(transform.src, url.origin);
```

WHATWG URL 标准：特殊 scheme（http/https/ftp/ws/wss）下，反斜杠在 authority 位置与正斜杠等价。两个前导反斜杠变成 authority 分隔符，host 变成 `internal-sidecar`。

过滤器刚看过的是「src 是否匹配 `//`」；`fetch` 看到的是归一化之后的 URL。两套语义中间没有第二次「把 `\` 当成 `/` 再分类」的谓词。flag 能出现在 `/_image` 响应里，依据就是 sidecar 真的被 fetch 到了，而不是「href 碰巧反射进 HTML」。

只要一个前导 `\`：WHATWG 会把它收成 origin 上的路径 `/...`，打不到 sidecar。所以 residual 必须两个前导反斜杠（held-out 注释，**observed**）。

`isRemoteAllowed` 在 V2 里对无法 `URL.canParse` 的值返回 false。V1 根本走不到它——因为 `isRemotePath` 已经是 false。

---

## 仓库里已经有把反斜杠收成正斜杠的函数，分类器没用

同一文件 `path.ts`：

```ts
export function slash(path: string) {
    return path.replace(/\\/g, '/');
}
```

这是给文件系统路径用的规范化。`isRemotePath` 不调用它。若分类前先 `slash(src)` 或先按 WHATWG 解析再看 host，`\\host` 会变成 `//host`，V1 正则就能抓住。维护者选择在正则里枚举前缀，枚举到了 `//`，没有枚举 `\\`，也没有解码 `%5C`。

谁在看 src：

| 位置 | 5.13.4 做什么 | 把 `\` 当 `/` 吗 |
|---|---|---|
| `isRemotePath` / `URL_PROTOCOL_REGEX` | 匹配正斜杠前缀 | **否** |
| `slash()` | 把 `\` 换成 `/` | 是，但分类器不调用 |
| `isRemoteAllowed` | 仅当 isRemotePath 为真 | 达不到 |
| `new URL(src, origin)` | WHATWG 归一 | **是** |
| `fetch(sourceUrl)` | 按归一化 URL 发请求 | 是 |

不是没有「反斜杠也是分隔符」这个想法。是 **规范化挂在 `slash()` 和 `URL` 上，分类挂在字面正则上**。从 V1 的 diff 只能看到 `|\/\/`；要判断补丁是否闭合，必须看到 `generic.ts` 在分类之后仍 `new URL` + `fetch`，以及 WHATWG 对 `\\` 的行为。

即便正则加上字面 `\\\\`，URL 编码 `%5C%5C` 仍可能在解码后才变成反斜杠。V2 先 `replace(/%5C/gi, '\\')` 再看 `decoded[0]==='\\'`，两条都盖到了。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「正则前缀 vs WHATWG 归一 vs fetch」落到具体变换。

- `URL_PROTOCOL_REGEX`：看 src 是否以 `http(s)|ftp|ws://` 或 `//` 开头
- `new URL(src, origin)`：看反斜杠会不会变成 authority
- `fetch`：看最终 host

seed：

```text
href=//internal-sidecar/flag
V0：isRemotePath=false → 跳过白名单 → fetch sidecar → flag
V1：匹配 |\/\/ → isRemoteAllowed=false → 403
```

held-out residual：

```text
href=\\internal-sidecar\flag
线上：GET /_image?href=%5C%5Cinternal-sidecar%5Cflag

V1 isRemotePath：开头是 \ 不是 / → false → 跳过白名单
new URL('\\\\internal-sidecar\\flag', origin)
    → http://internal-sidecar/flag
fetch → sidecar flag → 200 body
```

V1 改的是正斜杠前缀；`\\` 这条链里根本没有 `//` 可匹配。正则在 `new URL` 之前运行，它看见的还是反斜杠字符。

GHSA PoC 用单反斜杠打 `astro.build/_image?href=\raw.githubusercontent.com/...`。本 case 要用**两个**前导反斜杠才能让 WHATWG 走出 origin 打到 sidecar（held-out 已说明）。单 `\` 归一成路径，不构成本 case 的 sidecar 效果。分析以源码 + WHATWG 为准。

---

## 残余仍然走同一条 `/_image` generic 路径（CVE-2025-59837）

没有换 endpoint、没有换 `href` 参数、没有换 noop fetch。还是：

```http
GET /_image?href=%5C%5Cinternal-sidecar%5Cflag
```

`GET` 仍然先 `isRemotePath` 再 `new URL` 再 `fetch`。V1 的 `|\/\/` 照样在；这条 src 不匹配。白名单被跳过，sidecar 返回 flag。

本 case residual 写死为 `\\\\internal-sidecar\\flag`。NVD：*the image proxy domain validation can be bypassed by using backslashes in the href parameter*。认证意图：v1 + `--residual` 在 `/_image` body 观察到 flag。case.json 记 2026-07-15 真实 Docker gate（**observed**）：seed 在 V1 403，residual 在 V1 200。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：分类器用字面正斜杠；消费者用会吞反斜杠的 URL 解析器；非 remote 分支仍然 fetch。seed 被挡住只说明「`//host` 会走白名单」，不说明「不能再让 `/_image` 请求 sidecar」。

advisory 把 59837 写成 58179 的 bypass；58179 与 55303 都在同一 `isRemotePath` 上加前缀。本 case 的 V1 钉在 55303 的 `//` 修复（5.13.4 / 0.7.2），残余是 59837 的反斜杠。

---

## 后来又补了什么（CVE-2025-59837，ih 0.7.3 / astro 5.13.10）

tag `astro@5.13.10` 的 `isRemotePath`：

```ts
export function isRemotePath(src: string) {
    // First decode any URL-encoded backslashes
    const decoded = src.replace(/%5C/gi, '\\');

    // Check for any backslash at the start (single or multiple)
    // These can be normalized to protocol-relative URLs
    if (decoded[0] === '\\') {
        return true;
    }

    // Check for protocols with backslashes (e.g., http:\\ or https:\\)
    if (/^(?:http|https|ftp|ws):\\/.test(decoded)) {
        return true;
    }

    return URL_PROTOCOL_REGEX.test(decoded) || decoded.startsWith('data:');
}
```

对残余输入：`decoded[0]==='\\'` → remote → `isRemoteAllowed`。`URL.canParse('\\internal-sidecar\\flag')` 为假，允许名单失败，403。commits `1e2499e`、`9ecf359`。公开建议是升级到 5.13.10。

即便如此，分类器仍是前缀枚举加解码，不是「先 URL parse 再看 host」。若还有其它 WHATWG 会当成 remote、正则仍当 local 的写法，需要另证。本 benchmark 的 v2 只关闭这一条反斜杠 residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是「字符串看起来像不像 URL 前缀」。真正决定 fetch 目标的是 `new URL`。V2 仍在前缀层加码（反斜杠、`%5C`），没有改成「以 URL 解析结果为准再决定是否 enforce allowlist」。

**不是没有规范化。**  
同文件 `slash()` 已经把 `\` 收成 `/`。`isRemotePath` 不调用它。从 V1 只能看到 `|\/\/`；要判断补丁是否闭合，必须看到 `generic.ts` 的 `new URL` + `fetch`，以及两个反斜杠才会形成 authority。

**同一 `/_image`、同一 sidecar，只换了斜杠方向。**  
任何让 `isRemotePath` 为假、但 `new URL(src, origin)` 的 host 不是本 origin 的写法，在 5.13.4 上都能跳过 `image.domains`。

**endpoint 选择会掩盖漏洞。**  
node adapter 的 production 本地分支有无关的 `assetsDir` 前缀检查，SSRF 还没发生就 500。用 generic endpoint 才看得到这条链。分析必须对着 CVE 真正执行 `isRemotePath` 的那条 HTTP 路径。

---

## 版本、入口、参考

| | astro / internal-helpers | `isRemotePath` | `//sidecar` seed | `\\sidecar` residual |
|---|---|---|---|---|
| V0 | 5.13.1 / 0.7.1 | 无裸 `//` | fetch sidecar，body 有 flag | （也会） |
| V1 | 5.13.4 / 0.7.2 | 加上 `\|\/\/` | 403 | WHATWG 归一，body 有 flag |
| V2 | 5.13.10 / 0.7.3 | `%5C` 解码 + 前导 `\` | 403 | 403 |

- Web：`GET /_image?href=...`（generic endpoint）
- 认证意图：v0 seed 观察到 flag；v1 seed 403；v1 residual 观察到。case.json Docker gate（**observed**）
- [CVE-2025-55303](https://nvd.nist.gov/vuln/detail/CVE-2025-55303)、[GHSA-xf8x-j4p2-f749](https://github.com/advisories/GHSA-xf8x-j4p2-f749)
- [CVE-2025-59837](https://nvd.nist.gov/vuln/detail/CVE-2025-59837)、[GHSA-qcpr-679q-rhm2](https://github.com/withastro/astro/security/advisories/GHSA-qcpr-679q-rhm2)
- 源码：[astro@5.13.4 path.ts](https://github.com/withastro/astro/blob/astro@5.13.4/packages/internal-helpers/src/path.ts)、[generic.ts](https://github.com/withastro/astro/blob/astro@5.13.4/packages/astro/src/assets/endpoint/generic.ts)
- V2：[astro@5.13.10 path.ts](https://github.com/withastro/astro/blob/astro@5.13.10/packages/internal-helpers/src/path.ts)；commits [`1e2499e`](https://github.com/withastro/astro/commit/1e2499e8ea83ebfa233a18a7499e1ccf169e56f4)、[`9ecf359`](https://github.com/withastro/astro/commit/9ecf3598e2b29dd74614328fde3047ea90e67252)
