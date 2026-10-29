# Next.js middleware matcher：webpack 补上了 `.rsc`，Turbopack 仍在用旧后缀

- Case：`PCBV2-0152`
- 产品：Next.js（App Router + `middleware.ts`）。运行时是整包 `next@15.5.16`，`next build` / `next build --turbopack` 后再 `next start`。
- 链：CVE-2026-44575（≥15.2.0 <15.5.16，GHSA-267c-6grr-h53f，webpack 管线补 `.rsc` / `.segment.rsc`）→ CVE-2026-45109（15.5.16 的 Turbopack 仍漏，15.5.18 / 16.2.6，GHSA-26hh-7cqf-hhc6）
- 源码对着 tag `v15.5.16` 的 `packages/next/src/build/analysis/get-page-static-info.ts`（`getMiddlewareMatchers`）和 `crates/next-api/src/middleware.rs`（Turbopack 自己拼 matcher）。运行时消费的是 `.next/server/middleware-manifest.json` 里的 `regexp`。金丝雀是 `middleware.ts` 本应 401 的 `/admin` 页体里的 `PCBFLAG_...`。

NVD / GHSA-26hh-7cqf-hhc6 的原话：*It was found that the fix addressing CVE-2026-44575 did not apply to middleware.ts with Turbopack.* commit `c06d94b` 标题是 *Turbopack: Match proxy matchers with webpack implementation*。

根因不只是「漏了一种 URL」。检查插在「编译期 matcher 正则是否覆盖传输变体」上；真正决定「这次请求跑不跑 middleware」的是运行时拿 **已经写进 manifest 的那条 regexp** 去测 `req.path`。同一份 `config.matcher = ['/admin']`，webpack 和 Turbopack 各编一次。V1 只改了 TypeScript 那份。下面按请求走进去。

---

## 这块功能本来在干什么

App Router 用 `middleware.ts` 做登录门。开发者写：

```ts
// middleware.ts
export function middleware(req: NextRequest) {
  if (!req.cookies.get('auth')) {
    return NextResponse.json({ error: 'unauthorized' }, { status: 401 })
  }
  return NextResponse.next()
}
export const config = { matcher: ['/admin'] }
```

`/admin` 在 App Router 上还有传输变体：`/admin.rsc`（整页 RSC payload）、`/admin.segments/.../__PAGE__.segment.rsc`（segment prefetch）。这些路径解析到**同一页**，但 middleware 匹配的是**进来时的 path**，发生在 rewrite 之前。

一次未登录请求：

```http
GET /admin.rsc
```

若 compiled regexp 匹配 `/admin.rsc`，middleware 跑，401。若不匹配，middleware 整段跳过，页面数据进 body。

设计意图：`matcher: ['/admin']` 保护所有会渲染 `/admin` 的 URL。成功穿越之后的效果是未登录拿到 admin 页里的 flag。本 case `next.config.js` 用 `beforeFiles` rewrite 把变体指回页面——自托管没有 Vercel 适配器时，没有这层 rewrite 会 404；**matcher 仍然只看见原始 path**。

数据流：

```text
GET /admin.rsc   （无 cookie）
    → next start 读 middleware-manifest.json
         matchers[0].regexp.test(pathname)
              命中 → 跑 middleware.ts → 401
              不命中 → 跳过鉴权 → rewrite 到 /admin → 200 + flag
```

webpack 构建和 Turbopack 构建各写一份 manifest。运行时不再回源 `getMiddlewareMatchers`。`next start` 读的是磁盘上那份 JSON；换 bundler 等于换过滤器，即使 `middleware.ts` 字节完全相同。

middleware 跑在 routing/rewrite **之前**。`beforeFiles` 把 `/admin.rsc` 指到 `app/admin/page.tsx` 发生在 matcher 判定之后：matcher 不命中时，rewrite 仍然发生，页面照常渲染。这就是为什么自托管必须补 rewrite 才能 200，而 200 本身不代表鉴权过了——鉴权在更前面，已经跳过。

---

## 原始漏洞：matcher 只覆盖页面 path 和 `.json`（CVE-2026-44575，15.2.0）

15.2.0 编出来的 regexp 是：

```text
^(?:\/(_next\/data\/[^/]{1,}))?\/admin(\.json)?[\/#\?]?$
```

`/admin` 命中，`/admin.json` 命中，`/admin.rsc` 不命中。prefetch 变体直接到页面。这就是 v0 + `--seed`：未登录 `GET /admin.rsc` 拿到 flag。人话路径 `GET /admin` 在所有版本都是 401——门本身是真的，只是没挂到变体上。

GHSA-267c-6grr-h53f：*specially crafted `.rsc` and segment-prefetch URLs can resolve to the same page without being matched by the intended middleware rule*。

---

## 维护者改了什么（CVE-2026-44575 修复，15.5.16 webpack）

`getMiddlewareMatchers` 加上 App Router 传输后缀：

```ts
// packages/next/src/build/analysis/get-page-static-info.ts  （v15.5.16）
const APP_ROUTE_RSC_SUFFIX_MATCHER = escapeStringRegexp(RSC_SUFFIX) // .rsc
const APP_ROUTE_SEGMENT_PREFETCH_SUFFIX_MATCHER =
  `${escapeStringRegexp(RSC_SEGMENTS_DIR_SUFFIX)}/.+${escapeStringRegexp(RSC_SEGMENT_SUFFIX)}`
const APP_ROUTE_TRANSPORT_SUFFIX_MATCHER =
  `${APP_ROUTE_RSC_SUFFIX_MATCHER}|${APP_ROUTE_SEGMENT_PREFETCH_SUFFIX_MATCHER}`
const MIDDLEWARE_DATA_SUFFIX_MATCHER = `\\.json|${APP_ROUTE_TRANSPORT_SUFFIX_MATCHER}`

// Match transport-specific route forms that resolve to the same page.
const sourceSuffix = isRoot
  ? `(...?|${ROOT_APP_ROUTE_TRANSPORT_MATCHER})?`
  : `{(${MIDDLEWARE_DATA_SUFFIX_MATCHER})}?`
source = `${OPTIONAL_MIDDLEWARE_NEXT_DATA_PREFIX}${source}${sourceSuffix}`
```

webpack 构建走这条函数，15.5.16 的 manifest 变成：

```text
^(?:\/(_next\/data\/[^/]{1,}))?\/admin(\.json|\.rsc|\.segments\/.+\.segment\.rsc)?[\/#\?]?$
```

对 seed 这种 webpack 产物上的 `GET /admin.rsc`，regexp 命中，middleware 401。这就是 v1 + `--seed`（webpack profile）退出码 10。

**同一 tag 的 Turbopack 没有调用这个函数。** `crates/next-api/src/middleware.rs` 自己拼 source，注释写 *Mirrors implementation in get-page-static-info.ts getMiddlewareMatchers*，实际仍是旧后缀：

```rust
// crates/next-api/src/middleware.rs  （v15.5.16）
if is_root {
    source.push('(');
    if has_i18n {
        source.push_str("|\\\\.json|");
    }
    source.push_str("/?index|/?index\\\\.json)?")
} else {
    source.push_str("{(\\\\.json)}?")   // ← 只有 .json，没有 .rsc
}
source.insert_str(0, "/:nextData(_next/data/[^/]{1,})?");
```

`next build --turbopack` 写进 manifest 的仍是 15.2.0 那种 `(\.json)?`。

补丁默认了两件事：

1. 危险变体长得像「webpack 编出来的 matcher 没覆盖 `.rsc`」。
2. 另一种 bundler 会复用同一份 `getMiddlewareMatchers`。

第二点不成立。Turbopack 复制了一份更弱的实现。

---

## 编译期正则之后，谁在运行时做匹配

middleware 是否执行，看的不是 `middleware.ts` 里的 `config.matcher` 源字符串，而是 manifest 里的 `regexp`。`next-server` 用 `getMiddlewareRouteMatcher(info.matchers)` 缓存成函数，对每个请求的 pathname 求值。**求值器本身没有「这是 RSC 变体就强制跑 middleware」的第二谓词。**

webpack 和 Turbopack 的差别在编译期已经写死。15.5.16 + Turbopack 的运行时行为和 15.2.0 一样：`/admin.rsc` 对 `(\.json)?` 为假，跳过 `middleware.ts`，rewrite 到页面，flag 进 body。

过滤器（开发者以为的）是 `matcher: ['/admin']`；真正的过滤器是 bundler 选中的那份编译器输出。中间没有「两种 bundler 必须字节级一致」的检查——直到 V2 的 e2e（`regex.test('/dashboard.rsc')`）才补上。`c06d94b` 的测试断言写得很直白：webpack 实现里已经为真的 pathname，Turbopack 编出的 regexp 在 15.5.16 上为假。

生产路径上 `next build --turbopack` 在 15.5 已经是一等公民，不是实验开关。升级到「patched」15.5.16 却用 Turbopack 出包，等于没打 44575。

---

## 仓库里已经有更强的检查，Turbopack 没用

15.5.16 的 TypeScript `getMiddlewareMatchers` **就是**更强的谓词：`.json|.rsc|.segments/.+.segment.rsc`。Rust 文件顶部还写了 mirror。更强、当时就能做的：

1. 让 Turbopack 调用同一套后缀常量（V2 的 `c06d94b`）。
2. 运行时：凡是以 `.rsc` 结尾、canonicalize 之后等于受保护页面的 path，强制跑 middleware——不依赖编译期 regexp。
3. 开发者文档要求手写 `/admin.rsc`（advisory 的 workaround）——那是把框架责任推回应用。

谁在用（15.5.16）：

| 构建 | matcher 来源 | `/admin.rsc` |
|---|---|---|
| `next build`（webpack） | `getMiddlewareMatchers` | 命中，401 |
| `next build --turbopack` | `middleware.rs` 手搓 `{(\.json)}?` | **不命中，跳过鉴权** |
| 运行时 matcher 引擎 | 只消费 manifest | 不补偿 |

不是 44575 没写出正确正则，是 **只写进了一条编译管线**。即便 `.rsc` 没有把 webpack matcher 打穿，只要 Turbopack 继续写旧 regexp，同一条 `GET /admin.rsc` 在另一种 `next build` 下仍是未鉴权页面。

---

## 这个补丁挡住了什么、没挡住什么

- V1 webpack：编译期后缀含 `.rsc`
- V1 Turbopack：编译期后缀仍只有 `.json`
- 运行时：对 pathname 测 regexp，不二次判断「是不是同一页」

```text
控制：GET /admin          → 四种 profile 都 401

seed（15.2.0 webpack / 任何未打 44575 的构建）：
  GET /admin.rsc 无 cookie
  → regexp 无 .rsc → 跳过 middleware → 200 + flag

v1 webpack（15.5.16）：
  GET /admin.rsc
  → regexp 含 .rsc → middleware 401

residual（15.5.16 turbopack）：
  GET /admin.rsc          ← 同一 URL，同一 middleware.ts
  → manifest 仍是 (\.json)? → 跳过 middleware → 200 + flag
```

平台 residual 打的就是这条 **同一 `GET /admin.rsc`、换 bundler**。不是另一个 path、不是另一个 cookie 头。和 GHSA-26hh 的 *did not apply to middleware.ts with Turbopack* 一致。sink 仍是「middleware matcher 是否在鉴权前命中」；变的是哪一份编译器给 matcher 填空。

---

## 残余仍然走同一条 middleware 门（CVE-2026-45109）

没有换 `/admin`、没有换 `middleware.ts`、没有换 flag 所在的页面。还是未登录的 RSC 变体。webpack 那份 V1 正则照样能挡住；Turbopack 那份从未被 44575 改过。NVD：*the fix addressing CVE-2026-44575 did not apply to middleware.ts with Turbopack*。

seed 被挡住只说明「webpack 产物上的 `.rsc` 现在会进 middleware」，不说明「所有官方 bundler 编出的 matcher 都覆盖传输变体」。

`segment.rsc` 是同一条后缀常量里的另一项。本 case residual 用 `/admin.rsc` 就够打穿 15.5.16 Turbopack；prefetch 路径 `/admin.segments/.../__PAGE__.segment.rsc` 在同一份旧 regexp 上同样不命中，只是平台没把它当第二套 seed。

---

## 后来又补了什么（CVE-2026-45109，15.5.18）

commit `c06d94b`（#93594）把 webpack 那份后缀搬进 `middleware.rs`，并给 `get-page-static-info` 的测试补上 `/dashboard.rsc` 与 `.segment.rsc` 断言。15.5.18 / 16.2.6 的 Turbopack manifest 与 webpack 对齐：

```text
^(?:\/(_next\/data\/[^/]{1,}))?\/admin(\.json|\.rsc|\.segments\/.+\.segment\.rsc)?[\/#\?]?$
```

对残余输入：Turbopack 产物上 `/admin.rsc` 命中，401。公开建议升级到 15.5.18 或 16.2.6；停在 15.5.16 / 16.2.5 的 Turbopack 用户仍受影响。

即便如此，这仍然是「编译期把变体写进 regexp」，运行时没有独立的「RSC 变体必须鉴权」。对本条 `/admin.rsc` 够用。本 benchmark 的 v2 只关闭这一条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是 webpack 的 matcher 编译。真正跳过鉴权的是运行时对 **另一份** manifest regexp 的 `test`。V2 没有改运行时引擎，只是让第二份编译器抄对。

**不是没有更好的谓词。**  
`MIDDLEWARE_DATA_SUFFIX_MATCHER` 在 15.5.16 已经在 TypeScript 里。从 44575 的 diff 只能看到 `get-page-static-info.ts`；要判断是否闭合，必须打开 `crates/next-api/src/middleware.rs` 里那行 `{(\.json)}?`。

**同一 `middleware.ts`、同一 `/admin.rsc`，只换了 `next build` 是否带 `--turbopack`。**  
GHSA-26hh 是 incomplete-fix follow-up，不是新的页面、不是新的 cookie 绕过。

**源码 matcher 和 compiled matcher 不是一层。**  
开发者看见的是 `['/admin']`。框架承诺会补上 data/RSC 变体。承诺必须对每个官方 bundler 成立，否则「我升级到了 patched version」在 Turbopack 上为假。

**金丝雀在受保护页面的 RSC body 里是有意的。**  
`GET /admin` 控制组始终 401。能在 `/admin.rsc` 里读到 flag，说明 middleware 没跑，而不是页面自己忘了鉴权。RSC payload 带的是服务端渲染数据原文，所以这条绕过的是鉴权门，不是「只漏了一个静态文件」。

15.5.16 / 16.2.5 修了 5 月 6 日那批 advisory 里的 webpack 侧；5 月 7 日的 follow-up 才把 Turbopack 拉齐。停在「我已经升到 15.5.16」对 `--turbopack` 部署不成立。

---

## 版本、入口、参考

| | 版本 / 构建 | compiled matcher 后缀 | `GET /admin` | `GET /admin.rsc` 无 cookie |
|---|---|---|---|---|
| V0 | 15.2.0 webpack | `(\.json)?` | 401 | 200 + flag |
| V1 | 15.5.16 webpack | `.json\|.rsc\|.segments/...` | 401 | 401 |
| V1 residual | 15.5.16 turbopack | 仍是 `(\.json)?` | 401 | 200 + flag |
| V2 | 15.5.18 turbopack | 与 webpack 对齐 | 401 | 401 |

- 产品入口：`GET /admin.rsc`（App Router 传输变体）；控制 `GET /admin`
- [CVE-2026-44575](https://nvd.nist.gov/vuln/detail/CVE-2026-44575)、[CVE-2026-45109](https://nvd.nist.gov/vuln/detail/CVE-2026-45109)
- [GHSA-267c-6grr-h53f](https://github.com/vercel/next.js/security/advisories/GHSA-267c-6grr-h53f)、[GHSA-26hh-7cqf-hhc6](https://github.com/vercel/next.js/security/advisories/GHSA-26hh-7cqf-hhc6)
- V1：[`v15.5.16` `get-page-static-info.ts`](https://github.com/vercel/next.js/blob/v15.5.16/packages/next/src/build/analysis/get-page-static-info.ts)、[`middleware.rs`](https://github.com/vercel/next.js/blob/v15.5.16/crates/next-api/src/middleware.rs)
- V2 commit [`c06d94b`](https://github.com/vercel/next.js/commit/c06d94ba22d0156e8bff28c81f7874b73d80ed03)
