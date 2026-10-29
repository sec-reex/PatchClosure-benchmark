# Angular SSR：拦了两个斜杠，没拦一个反斜杠，join 之后浏览器仍当成 `//`

- Case：`PCBV2-0074`
- 产品：npm `@angular/ssr`（Angular CLI 的服务端渲染引擎）
- 链：CVE-2026-27738（20.3.16 → 20.3.17，commit `f086ecc` / `8700e18`）→ CVE-2026-33397（20.3.17…20.3.20 → 20.3.21，PR `#32771` / commit `1dc6992`）
- 源码对着 GitHub tag `v20.3.17` / `v20.3.21` 的 `packages/angular/ssr/src/utils/validation.ts`、`url.ts`：`validateHeaders`、`INVALID_PREFIX_REGEX`、`joinUrlParts`、`addLeadingSlash`。运行时是整份 `@angular/ssr`，`GET /old` 的 Location 由引擎用 `X-Forwarded-Prefix` 拼出来。

2026 年 2 月，Angular SSR 让 `joinUrlParts` 剥掉**全部**前导 `/`，并给 `X-Forwarded-Prefix` 加正则，想挡住 `///evil.com` 这种协议相对跳转。GHSA-vfx2-hv2g-xj5f 写明：*an incomplete fix for CVE-2026-27738. While the original fix successfully blocked multiple leading slashes (e.g. `///`), the internal validation logic fails to account for a single backslash (`\`) bypass.* 浏览器把 Location 里的 `/\evil` 当成 `//evil`。

根因不只是「正则少写了一个字符」。检查插在「前缀是不是以两个 `/` 或 `\` 开头」上；真正发给浏览器的是 `joinUrlParts` 剥完正斜杠、再 `addLeadingSlash` 之后的字符串。下面按请求走进去。

---

## 这块功能本来在干什么

部署在反代后面的 Angular SSR 会读 `X-Forwarded-Prefix`，当作应用的公共路径前缀，再拼到内部 redirect 的 `Location` 上。典型形状和官方生成的 `server.ts` 一样：引擎校验头，路由 `/old` → `/new`。

一次典型请求：

```http
GET /old HTTP/1.1
X-Forwarded-Prefix: /app
```

期望 Location 是 `/app/new`，仍在本源。本 case 的 host（`server.mjs`）把每个请求交给真实的 `AngularNodeAppEngine`。

数据流（20.3.17，本 case 的 V1）：

```text
HTTP GET /old
    + Header X-Forwarded-Prefix
    → AngularNodeAppEngine.handle
         validateHeaders / validateRequest
              V1：INVALID_PREFIX_REGEX.test(prefix)  ← 补丁插在这里
              匹配则抛错 → 本 case 看到 HTTP 400，没有 Location
         路由决定 302 /new
         Location = joinUrlParts(prefix, '/new')
              只剥正斜杠 '/'，不剥 '\'
              最后 addLeadingSlash → 保证以 '/' 开头
    → 响应 Location 交给浏览器
```

设计意图：前缀是本站路径（`/app`、`/shop`），拼完之后仍是源内绝对路径。成功穿越之后的效果是：**Location 变成协议相对 URL，浏览器导航到攻击者选的 host**。本 case 把 per-run flag 写进 host 标签 `<FLAG>.evil.invalid`，所以 flag 出现在 Location 头里。

没有登录。判断完全信任「校验过的前缀 + joinUrlParts」会得到本站路径，不信任浏览器稍后怎么读 `/\`。

---

## 原始漏洞：三个斜杠塌成 `//`（CVE-2026-27738，20.3.16）

20.3.16 的 `joinUrlParts` 每个 part 只剥**一个**前导 `/` 和一个尾斜杠。NVD CVE-2026-27738：*The logic normalizes URL segments by stripping leading slashes; however, it only removes a single leading slash. … an attacker can provide a value starting with three slashes.*

```text
prefix = ///<FLAG>.evil.invalid
剥一个前导 / → //<FLAG>.evil.invalid
join('/new') + addLeadingSlash → 仍以 // 开头
Location: //<FLAG>.evil.invalid/new
```

浏览器把 `//host/...` 当协议相对 URL，跟当前页面的 scheme 走，离开本源。本 case seed：

```text
X-Forwarded-Prefix: ///<flag>.evil.invalid
GET /old
```

V0 发出 302，Location 里出现 `PCBFLAG_...`。当时还没有 `INVALID_PREFIX_REGEX`。

---

## 维护者改了什么（CVE-2026-27738 修复，20.3.17）

commit `f086ecc`（20.x 线上对应 `8700e18`）做了两件事：join 剥光正斜杠；`validateHeaders` 拒绝「看起来像 `//` 或含 `.` / `..`」的前缀。tag `v20.3.17`：

```ts
// packages/angular/ssr/src/utils/validation.ts  (v20.3.17)
const INVALID_PREFIX_REGEX = /^[/\\]{2}|(?:^|[/\\])\.\.?(?:[/\\]|$)/;

function validateHeaders(request: Request): void {
  ...
  const xForwardedPrefix = getFirstHeaderValue(headers.get('x-forwarded-prefix'));
  if (xForwardedPrefix && INVALID_PREFIX_REGEX.test(xForwardedPrefix)) {
    throw new Error(
      'Header "x-forwarded-prefix" must not start with multiple "/" or "\\" or contain ".", ".." path segments.',
    );
  }
}
```

`joinUrlParts` 改成指针扫掉**全部**前导/尾部 `'/'`（注意：比较的是字符 `'/'`，不是 `'\\'`）：

```ts
// packages/angular/ssr/src/utils/url.ts :: joinUrlParts  (v20.3.17)
export function joinUrlParts(...parts: string[]): string {
  const normalizedParts: string[] = [];
  for (const part of parts) {
    if (part === '') continue;
    let start = 0;
    let end = part.length;
    while (start < end && part[start] === '/') {
      start++;
    }
    while (end > start && part[end - 1] === '/') {
      end--;
    }
    if (start < end) {
      normalizedParts.push(part.slice(start, end));
    }
  }
  return addLeadingSlash(normalizedParts.join('/'));
}
```

`addLeadingSlash`：若第一个字符不是 `/`，就在前面加一个 `/`。

对 seed 这种明文 `///host`，它确实够用：`^[/\\]{2}` 吃掉开头两个 `/`，校验抛错，引擎不发 Location。这就是 v1 + `--seed` 退出码 10（本 case 观察到 HTTP 400）。

补丁默认了两件事：

1. 危险前缀长得像「开头至少两个斜杠或反斜杠」或含 `.` / `..` 段。
2. 只要校验过了，`joinUrlParts` 再剥光 `/`、补一个 `/`，浏览器看到的一定是源内路径。

第二点不成立。正则要的是**两个** `[/\\]`；单个 `\` 过关。join 又不剥反斜杠。`addLeadingSlash` 还会在 `\` 前面再补一个 `/`，正好造出浏览器认得的 `/\`。

---

## 消毒之后，前缀怎么接到 Location 上

校验一过，引擎把**原始前缀字符串**（不是正则替换后的版本）交给 `joinUrlParts`，再写成 `Location`。`joinUrlParts` 只认 `'/'`：

| 输入 part | 剥前导 `/` 之后 | `addLeadingSlash` 之后 |
|---|---|---|
| `/app` | `app` | `/app` |
| `///evil` | 校验阶段已拒绝 | — |
| `\evil` | `\evil`（第一个字符不是 `/`） | `/\evil` |

过滤器刚看过的是「开头有没有两个 `[/\\]`」；浏览器看的是 RFC / WHATWG 对 `Location: /\host` 的读法。现代浏览器把 `/\` 和 `//` 同等对待，当成协议相对 URL。GHSA-vfx2 原话：*The application prepends a leading forward slash, resulting in a Location header containing `/\evil.com`. Modern browsers interpret the `/\` sequence as `//`.*

金丝雀能出现在 Location 里，依据就是这一步：应用发出去的是 join 之后的字节，浏览器按协议相对 URL 解析。

---

## 仓库里已经有校验，字符类却比 join / 浏览器窄

同一份 `validation.ts` 里，host 头有 `VALID_HOST_REGEX`，port / proto 各有一张表。前缀这张表只拒绝「两个 slash-like 字符」和点段：

| 调用点 | 谓词 | 单个前导 `\` |
|---|---|---|
| `INVALID_PREFIX_REGEX` | `^[/\\]{2}` 或 `.` / `..` 段 | 不匹配，放行 |
| `joinUrlParts` | `part[start] === '/'` | 不剥 |
| `addLeadingSlash` | 若不是 `/` 就前置 `/` | 变成 `/\...` |
| 浏览器 | `/\` ≈ `//` | 离站 |

不是没有校验。是 **校验的「多个 slash」比后面 join 实际剥的字符、也比浏览器当成 authority 的字符，都更窄**。错误信息写 *must not start with multiple "/" or "\\"*，等于自己承认目标是「多个」，单个反斜杠不在范围内。

即便没有 `\host`，只要任何 join 不剥、浏览器却当分隔符的字符还能留在开头，`addLeadingSlash` 仍可能拼出协议相对 URL。V2 只把「单个 `\`」补进正则。

---

## 这个补丁挡住了什么、没挡住什么

- `INVALID_PREFIX_REGEX`：看前缀是不是以两个 `/` 或 `\` 开头，或含 `.` / `..`
- `joinUrlParts`：看字符是不是 `'/'`
- 浏览器：看 Location 是不是 `//host` 或等价的 `/\host`

只要构造一种输入，使校验看不到两个 slash-like 字符，但 join + 前置 `/` 之后浏览器仍读出 authority。

huntr / GHSA 的 PoC 用单个反斜杠：

```text
X-Forwarded-Prefix: \<FLAG>.evil.invalid

validateHeaders(20.3.17):
  INVALID_PREFIX_REGEX = /^[/\\]{2}|...
  第一个字符 '\'，第二个是 FLAG 的 'P'，不是 [/\\]
  → test 为 false，放行

joinUrlParts('\<FLAG>.evil.invalid', '/new'):
  不剥 '\'
  addLeadingSlash → '/\<FLAG>.evil.invalid/new'

浏览器: /\\ → //  →  https://<FLAG>.evil.invalid/new
```

V1 改的是「多个斜杠」和「剥光 `/`」；`\host` 里既没有两个 slash，也没有需要剥的 `/`。新规则无事可做，`addLeadingSlash` 反而补上缺失的那一杠。

---

## 残余仍然走同一条 SSR 跳转路径（CVE-2026-33397）

没有换路由、没有换头、没有换身份。还是：

```http
GET /old
X-Forwarded-Prefix: \<flag>.evil.invalid
```

`validateHeaders` 仍然跑 V1 那张正则；跑完之后因为不够两个 `[/\\]`，join 把反斜杠留下，Location 变成 `/\<flag>.evil.invalid/new`。本 case residual 写死为：

```text
prefix = "\\" + flag + ".evil.invalid"
```

和 GHSA-vfx2 的 `\evil.com` 同一构造，只是 host 换成金丝雀标签。认证意图：v1 + `--residual` 在 Location 里观察到 `PCBFLAG_...`。公开 advisory 还提到缺少 `Vary: X-Forwarded-Prefix` 时的缓存投毒；本 case 只看 Location 是否离站。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：正则按「两个 slash-like」写；join 只剥正斜杠；发出去之前又强制加一个 `/`。seed 被挡住只说明「三个 `/` 不再能塌成 `//`」，不说明「任意 slash-like 字符都不能在剥完之后变成协议相对 URL」。

---

## 后来又补了什么（CVE-2026-33397，20.3.21）

PR `#32771`（20.3.x 上 `1dc6992`，*disallow x-forwarded-prefix starting with a backslash*）把正则改成**单个前导反斜杠也非法**。tag `v20.3.21`：

```ts
// packages/angular/ssr/src/utils/validation.ts  (v20.3.21)
const INVALID_PREFIX_REGEX = /^(?:\\|\/[/\\])|(?:^|[/\\])\.\.?(?:[/\\]|$)/;
```

拆开看：

| 分支 | 含义 |
|---|---|
| `^\\` | 以单个 `\` 开头 |
| `^\/[/\\]` | 以 `/` 再跟 `/` 或 `\` 开头（`//`、`/\`） |
| `(?:^|[/\\])\.\.?(?:[/\\]|$)` | `.` / `..` 段（和 V1 一样） |

对残余输入 `\host`：第一条就匹配，校验抛错，错误信息改成 *must not start with "\\" or multiple "/"*。公开建议升级到 `@angular/ssr@20.3.21`（以及 21.2.3 / 22.0.0-next.2）。即便如此，应用若在引擎之前把未消毒的前缀写进别的跳转，需要另证。本 benchmark 的 v2 只关闭这一条 single-backslash residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是「前缀开头有几个 slash-like 字符」以及 join 对 `'/'` 的剥除。真正让浏览器离站的是 **join 之后强制加 `/` 得到的 Location 字节**。V2 仍在同一张正则上加码，没有让 join 把 `\` 也剥掉，也没有在写出 Location 之前断言「不是协议相对 URL」。

**不是没有校验。**  
`validateHeaders` 在 V1 就存在，host / port / proto / prefix 都查。缺的是「浏览器会当成 `//` 的那种两个字符组合」，包括 `/\` 这种由补丁自己拼出来的。从 V1 的 diff 只能看到 `{2}` 和剥光 `/`；要判断是否闭合，必须看到 `addLeadingSlash` 和浏览器对 `/\` 的读法。

**同一头、同一 `/old`，只换了前缀第一个字节。**  
任何把 `X-Forwarded-Prefix` 拼进 redirect Location 的 SSR 部署，在 20.3.17 上都吃同一张正则。advisory 还指出缓存若不 Vary 该头，一次投毒会留给后续用户。

**join 和校验的字符表不一致。**  
校验把 `\` 算进「slash-like」，join 却只剥 `/`。这种不一致让「校验放行 + join 规范化」本身变成攻击者的变换。

---

## 版本、入口、参考

| | npm | `INVALID_PREFIX_REGEX` | `joinUrlParts` | `///host` seed | `\host` residual |
|---|---|---|---|---|---|
| V0 | 20.3.16 | 无 | 只剥一个 `/` | Location `//host/new` | （不必；同样离站） |
| V1 | 20.3.17 | `^[/\\]{2}` + 点段 | 剥光 `/`，不剥 `\` | 400，无 Location | Location `/\host/new` |
| V2 | 20.3.21 | `^\\` 或 `^\/[/\\]` + 点段 | 同上 | 挡 | 400，无 Location |

- Web：`GET /old` + `X-Forwarded-Prefix`
- 认证意图：v0 seed Location 含 flag；v1 seed 400；v1 residual Location 含 flag
- [CVE-2026-27738](https://nvd.nist.gov/vuln/detail/CVE-2026-27738)、[GHSA-xh43-g2fq-wjrj](https://github.com/advisories/GHSA-xh43-g2fq-wjrj)
- [CVE-2026-33397](https://www.cve.org/CVERecord?id=CVE-2026-33397)、[GHSA-vfx2-hv2g-xj5f](https://github.com/angular/angular-cli/security/advisories/GHSA-vfx2-hv2g-xj5f)
- 修复提交：[f086ecc](https://github.com/angular/angular-cli/commit/f086eccc36d10cf01c426e35864bc32e1e292323)（20.3.17）、[1dc6992](https://github.com/angular/angular-cli/commit/1dc6992a5ae6c5a1f16f22f6c94690d5cf218c38) / [PR #32771](https://github.com/angular/angular-cli/pull/32771)（20.3.21）
- 源码：tag [`v20.3.17` validation.ts](https://github.com/angular/angular-cli/blob/v20.3.17/packages/angular/ssr/src/utils/validation.ts)、[`url.ts`](https://github.com/angular/angular-cli/blob/v20.3.17/packages/angular/ssr/src/utils/url.ts)
