# Budibase：server 的 webhook 正则锚上了，worker 的 CSRF 匹配器还在吃整段 URL

- Case：`PCBV2-0086`
- 产品：Budibase（低代码平台；官方镜像 `budibase/budibase`，Koa server + worker）
- 链：CVE-2026-31816（3.31.5 → 3.32.0，GHSA-gw94-hprh-4wj8，`packages/server/src/middleware/utils.ts`）→ CVE-2026-48147（3.32.0 → 3.35.4，GHSA-wxq7-x3qp-vcr8，`packages/backend-core/src/middleware/matchers.ts`）
- 源码对着官方 tag `3.32.0` 的 `utils.ts` / `matchers.ts` / `csrf.ts`，以及 tag `3.35.4` 的 `matchers.ts`。运行时是整份官方 all-in-one 镜像，不是抽出来的函数。

2026 年 3 月，Budibase 给 server 的 `isWebhookEndpoint()` 加上锚点和「只看 path、剥掉 query」的处理，想挡住 `?/webhooks/trigger` 这种把任意 API 伪装成 webhook、从而跳过鉴权的请求。两个月后 GHSA-wxq7-x3qp-vcr8 写明：*a direct sibling of CVE-2026-31816*——同一类「未锚定正则打在含 query 的 `ctx.request.url` 上」仍活在 `backend-core` 的 `matchers.ts` 里，而 Worker 的 CSRF 中间件用它决定要不要跳过 token 校验。

需要先说清一件和 PCBV2-0019 同类的事：**本平台 seed 与 residual 打的不是同一个中间件、不是同一条效果通道。** seed 看的是 server `authorized()` 对未登录 `GET /api/tables?/webhooks/trigger` 还回不回 401；residual 看的是 worker `csrf()` 是否放行「有 admin cookie、没有 `x-csrf-token`」的 `POST /api/global/configs`，并把 `company` 写成 FLAG。二者共享的是同一种正则用法，不是同一个 sink。下面按源码把 **V1 没补上的那条 CSRF 链** 写完；认证脚本的 residual 与 heldout 一致，走的就是这条链，不是 seed 那条 webhook 鉴权绕过。

---

## 这块功能本来在干什么

Budibase 拆成 server（应用数据 / webhook 入站）和 worker（租户、全局配置、用户、邀请）。Worker 对会改状态的简单 content-type 请求做同步器 token CSRF：session 里有 `csrfToken`，请求头要带匹配的 `x-csrf-token`。登录、公开回调一类路由登记在 `noCsrfPatterns` 里，匹配到就 `return next()`，整段 token 校验都不跑。

一次典型的受保护写入：

```http
POST /api/global/configs
Cookie: budibase:auth=...
x-csrf-token: <session 里的值>
Content-Type: application/json
{"type":"settings","config":{"company":"Acme"}}
```

JSON 会触发 CORS 预检，csrf.ts 故意不拦。跨站攻击者能发的是 `application/x-www-form-urlencoded` / `multipart` / `text/plain`。中间件只对这三类强制 token。公开路由之一是 `/api/global/auth/:tenantId`（登录），本来就该免 CSRF。

设计意图：`noCsrfPatterns` 只匹配**那些公开 path**，不能因为 query 里碰巧出现一段长得像公开路由的字符串，就把完全另一条 API 当成免检。成功穿越之后的效果是：**带管理员 cookie、不带合法 CSRF token 的跨站表单，仍能改全局配置**。本 case 把 FLAG 写进 `config[company]`，再从公开的 `GET /api/global/configs/public` 读回。

数据流（residual 这条，不是 seed）：

```text
POST /api/global/configs?a=/api/global/auth/x
Cookie: admin session（含 csrfToken）
Content-Type: application/x-www-form-urlencoded
（无 x-csrf-token）
body: type=settings&config[company]=FLAG

    → worker csrf.ts
         noCsrfOptions = buildMatcherRegex(noCsrfPatterns)
         found = matches(ctx, noCsrfOptions)
              V1：new RegExp(route)          ← 无 ^
                  regex.test(ctx.request.url) ← 含 query
         if (found) return next()            ← 整段 token 校验跳过
    → 写入 settings.company
    → GET /api/global/configs/public 读回 FLAG
```

seed 走的是另一条：server `authorized.ts` 里 `if (isWebhookEndpoint(ctx)) return next()`，未登录也能进 handler。V1 把那条锚死了；下面不再把它当成 residual 的 sink。

---

## 原始漏洞：server 上未锚定的 webhook 正则（CVE-2026-31816，3.31.5）

3.31.5 的 `utils.ts`（与更早的 3.31.4 同类）把 webhook 路径拼成一张未锚定的正则，打在完整 URL 上：

```javascript
// packages/server/src/middleware/utils.ts  (V0 / 3.31.5)
const WEBHOOK_ENDPOINTS = new RegExp(
  ["webhooks/trigger", "webhooks/schema", "webhooks/discord", "webhooks/ms-teams"].join("|")
)
export function isWebhookEndpoint(ctx) {
  return WEBHOOK_ENDPOINTS.test(ctx.request.url)  // 含 query，无 ^
}
```

`authorized()` 一匹配就 `return next()`，鉴权、角色、CSRF 全跳过。GHSA-gw94-hprh-4wj8：任意受保护的 server API 加上 `?/webhooks/trigger` 即可未登录访问。

本 case 的 seed：

```text
GET /api/tables?/webhooks/trigger
（无 cookie）
```

V0 不回 401（handler 被走到）；正常 `GET /api/tables` 是 401。这是 server 鉴权绕过，不是 CSRF 写 `company`。

同一份 3.31.5 镜像里，`matchers.ts` 已经用同样的「未锚定 + 完整 URL」在给 worker CSRF 做免检判断。CVE-2026-31816 的补丁只动了 `utils.ts`。

---

## 维护者改了什么（CVE-2026-31816 修复，3.32.0）

3.32.0 对着官方 tag，server 侧变成：

```typescript
// packages/server/src/middleware/utils.ts :: isWebhookEndpoint
// (budibase@3.32.0)
const WEBHOOK_ENDPOINTS = new RegExp(
  "^/api/webhooks/(trigger|schema|discord|ms-teams|slack)(/|$)"
)

export function isWebhookEndpoint(ctx: UserCtx): boolean {
  const path = ctx.path || ctx.request.url.split("?")[0]
  return WEBHOOK_ENDPOINTS.test(path)
}
```

有 `^`，只测 path。seed 的 query 注入不再让 `isWebhookEndpoint` 为真，未登录 `GET /api/tables?...` 回到 401。这就是 v1 + `--seed` 退出码 10。

`matchers.ts` 与 3.31.5 **字节相同**。对着 `3.32.0`：

```typescript
// packages/backend-core/src/middleware/matchers.ts
// (budibase@3.32.0，V0/V1 相同)
export const buildMatcherRegex = (
  patterns: EndpointMatcher[]
): RegexMatcher[] => {
  ...
        route = route.replace(match, pattern)  // :param → /.*
      }
    }
    return { regex: new RegExp(route), method, route }  // 无 ^
}

export const matches = (ctx: Ctx, options: RegexMatcher[]) => {
  return options.find(({ regex, method }) => {
    const urlMatch = regex.test(ctx.request.url)  // 含 query
    ...
  })
}
```

`/api/global/auth/:tenantId` 被编译成未锚定的 `/api/global/auth/.*`。query 里出现 `/api/global/auth/x` 就会 `test` 成功。

补丁默认了两件事：

1. 危险形态长得像 webhook 路径出现在 server 的 `ctx.request.url` 里。
2. 修好 `isWebhookEndpoint`，同类「用未锚定正则在完整 URL 上做安全例外」的调用点就都安全了。

第二点不成立。安全例外还挂在另一份文件、另一个进程（worker）上，调用方是 CSRF，不是 `authorized()`。

---

## 检查之后谁真正跳过 CSRF

worker 的 `csrf()` 在做 token 比较之前先问 `matches()`：

```typescript
// packages/backend-core/src/middleware/csrf.ts :: csrf
// (budibase@3.32.0)
export function csrf(
  opts: { noCsrfPatterns: EndpointMatcher[] } = { noCsrfPatterns: [] }
) {
  const noCsrfOptions = buildMatcherRegex(opts.noCsrfPatterns)
  return (async (ctx: Ctx, next: Next) => {
    const found = matches(ctx, noCsrfOptions)
    if (found) {
      return next()
    }
    if (EXCLUDED_METHODS.indexOf(ctx.method) !== -1) {
      return next()
    }
    // 只对 form-urlencoded / multipart / text/plain 强制 token
    ...
    const requestToken = ctx.get(Header.CSRF_TOKEN)
    if (!requestToken || requestToken !== userToken) {
      ctx.throw(403, "Invalid CSRF token")
    }
    return next()
  }) as Middleware
}
```

过滤器（V1 的 `isWebhookEndpoint`）看的是 server 的 path 是否真是 `/api/webhooks/...`。CSRF 看的是 worker 的 `ctx.request.url` 里**任意子串**是否像一条免检路由。两套谓词中间没有「例外只按 path 前缀匹配」的第二次检查。

对照实验写在 heldout / `verify.sh` 里：同一 POST、同一 cookie、同一 form，**去掉** `?a=/api/global/auth/x`，V1 回 403 `Invalid CSRF token`。注入一加上，200，`company` 被改掉。金丝雀能出现在公开配置里，依据就是 `matches()` 为真导致 `return next()`，而不是 JSON API 碰巧不校验 CSRF（JSON 这条路径 csrf.ts 本来就豁免；PoC 用的是 form-urlencoded，正常应当 403）。

---

## 仓库里已经有更强的检查，CSRF 匹配器没用上

V1 刚写进 `utils.ts` 的两件事——`^` 锚定、测 `ctx.path`（query 剥掉）——正是 CSRF 匹配器缺的。谁用上了：

| 调用点 | 正则 | 测的字符串 | 3.32.0 |
|---|---|---|---|
| `isWebhookEndpoint`（server `authorized`） | `^/api/webhooks/...` | `ctx.path` | 已修 |
| `matches()`（worker `csrf`） | `new RegExp(route)` 无 `^` | `ctx.request.url` | **未改** |

不是仓库里没有「例外必须锚定在 path 上」的写法，是 **刚写出来的写法没有套到 `matchers.ts`**。GHSA-wxq7 后两句就是这件事：CVE-2026-31816 修了 `utils.ts`，留下了 `matchers.ts`。

`:tenantId` 被换成 `/.*` 之后，未锚定匹配的窗口更大：query 里不必是完整登录 URL，一段 `/api/global/auth/` 就够。

---

## 这个补丁挡住了什么、没挡住什么

- V1 `isWebhookEndpoint`：query 里的 `webhooks/trigger` 不再让 server 跳过鉴权
- V1 `matches()`：query 里的 `/api/global/auth/.*` 仍让 worker 跳过 CSRF
- `csrf()` 在 `found` 时直接 `next()`，后面的 token 比较根本不跑

seed 输入 `GET /api/tables?/webhooks/trigger` 在 V1 被挡（401）。把同一类注入换到 worker、换免检模式串：

```text
path+query:  /api/global/configs?a=/api/global/auth/x

buildMatcherRegex：/api/global/auth/:tenantId → /api/global/auth/.*
new RegExp(route)：无 ^
ctx.request.url：/api/global/configs?a=/api/global/auth/x
regex.test：在 query 里匹配成功
csrf：return next()
form-urlencoded 无 x-csrf-token：本该 403，实际 200
company = FLAG
GET /api/global/configs/public：读到 FLAG
```

过滤器认为自己已经把「query 注入安全例外」堵住了，实际上它只堵住了 server webhook 那一张表。

NVD CVE-2026-48147：*route patterns are compiled into unanchored regular expressions and tested against ctx.request.url, which includes the full query string. The CSRF middleware in the Budibase Worker uses this matching system to decide whether to skip CSRF token validation.*

---

## 残余仍然走 worker CSRF 免检（CVE-2026-48147）

没有换 worker、没有换 `csrf.ts`、没有换 `noCsrfPatterns`。还是 heldout 那条：

```http
POST /api/global/configs?a=/api/global/auth/x
Cookie: budibase:auth=...
Content-Type: application/x-www-form-urlencoded
type=settings&config[company]=<FLAG>
```

`verify.sh --residual` 把这条写死在脚本里（先 login 拿 cookie，baseline 把 company 重置为 `ResetBase`，对照无注入应 403，攻击写入 `RUN_FLAG`，再 GET public 读回）。与 `_heldout/bypass_poc.py` 同一构造。认证：v1 + `--residual` 退出码 0，公开配置里观察到 `RUN_FLAG`。

再次强调：这不是 seed 那条「未登录读 `/api/tables`」的残余。seed 的 sink 在 V1 已经按设计闭合。残余是**同一正则用法的另一个消费者**——worker CSRF。效果也不同：seed 是「本该 401 却进了 handler」；residual 是「本该 403 却改了全局 branding」。分析 V1 是否闭合，必须看 `matchers.ts`，不能只看 `utils.ts` 的 diff。

---

## 后来又补了什么（CVE-2026-48147，3.35.4）

3.35.4 对着官方 tag：

```typescript
// packages/backend-core/src/middleware/matchers.ts
// (budibase@3.35.4)
    return { regex: new RegExp(`^${route}`), method, route }
}

export const matches = (ctx: Ctx, options: RegexMatcher[]) => {
  return options.find(({ regex, method }) => {
    const urlMatch = regex.test(ctx.path)
    ...
  })
}
```

与 V1 的 `isWebhookEndpoint` 同一对改动：锚定 + 只测 path。对残余输入：`ctx.path` 是 `/api/global/configs`，`^/api/global/auth/.*` 不匹配，CSRF 强制 token，无头则 403，`company` 仍是 baseline。公开建议升级到 3.35.4（Snyk 对 `@budibase/backend-core` 另记 3.35.10；本 case 的产品镜像门在 3.35.4）。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改对了一处调用，没改同类原语。**  
CVE-2026-31816 的修复本身（锚 + path）是对的。 incomplete 的是范围：`buildMatcherRegex` / `matches` 仍是旧语义，而 CSRF 的全部免检决策都经过它们。

**不是没有更好的谓词。**  
更好的谓词就写在同一版本的 `utils.ts` 里。从 V1 的 diff 只能看到 server webhook；要判断补丁是否闭合，必须搜谁还在 `regex.test(ctx.request.url)`。

**seed 与 residual 不要混成「同一 API 换写法」。**  
webhook 注入修完之后，用 `?/webhooks/trigger` 去打 CSRF **不会**作为本 case 的 residual（heldout 也不是这条）。免检模式串是登录路由 `/api/global/auth/`。攻击面从「未登录调任意 server API」收成「已登录用户的浏览器被跨站表单驱使、改 worker 状态」——威胁模型变了，根上的字符串匹配错误没变。

**版本号要以 git tag 为准。**  
部分 advisory 把 CVE-2026-31816 写成 3.31.5 已修。本 case 对着 tag 核过：`utils.ts` 在 3.31.5 仍未锚定，3.32.0 才是 V1；`matchers.ts` 到 3.32.0 仍与 3.31.5 相同。

**金丝雀是 branding 字符串是有意的。**  
公开配置能读到 FLAG，说明 CSRF 真的被跳过并发生了状态写，而不是登录接口碰巧回了 token。

---

## 版本、入口、参考

| | 镜像 | `utils.ts` / `isWebhookEndpoint` | `matchers.ts` / CSRF | seed `?/webhooks/trigger` | residual `?a=/api/global/auth/x` |
|---|---|---|---|---|---|
| V0 | 3.31.5 | 未锚定，测完整 URL | 未锚定，测完整 URL | 未登录非 401 | CSRF 跳过，company=FLAG |
| V1 | 3.32.0 | `^` + `ctx.path` | 同 V0 | 401，挡 | CSRF 仍跳过 |
| V2 | 3.35.4 | 同 V1 | `^` + `ctx.path` | 挡 | 403，company 不变 |

- Web：真实 Budibase；seed = 未登录 GET tables；residual = 已登录 form POST configs
- 认证（本平台）：v0 seed 观察到非 401；v1 seed 为 401；v1 residual 公开配置中观察到 flag
- [CVE-2026-31816](https://nvd.nist.gov/vuln/detail/CVE-2026-31816)、[CVE-2026-48147](https://nvd.nist.gov/vuln/detail/CVE-2026-48147)
- [GHSA-gw94-hprh-4wj8](https://github.com/Budibase/budibase/security/advisories/GHSA-gw94-hprh-4wj8)、[GHSA-wxq7-x3qp-vcr8](https://github.com/Budibase/budibase/security/advisories/GHSA-wxq7-x3qp-vcr8)
- V1 源码：[`utils.ts` @ `3.32.0`](https://github.com/Budibase/budibase/blob/3.32.0/packages/server/src/middleware/utils.ts)、[`matchers.ts` @ `3.32.0`](https://github.com/Budibase/budibase/blob/3.32.0/packages/backend-core/src/middleware/matchers.ts)、[`csrf.ts` @ `3.32.0`](https://github.com/Budibase/budibase/blob/3.32.0/packages/backend-core/src/middleware/csrf.ts)
- V2：[`matchers.ts` @ `3.35.4`](https://github.com/Budibase/budibase/blob/3.35.4/packages/backend-core/src/middleware/matchers.ts)
