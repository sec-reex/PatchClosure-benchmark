# @astrojs/cloudflare：allowlist 只看了第一次 href，fetch 还在 follow 302

- Case：`PCBV2-0081`
- 产品：`@astrojs/cloudflare`（Astro 的 Cloudflare SSR adapter；npm `@astrojs/cloudflare`，源码在 withastro/astro 的 `packages/integrations/cloudflare`）
- 链：CVE-2025-58179（12.6.5 → 12.6.6，GHSA-qpr4-c339-7vq8，commit `9ecf359`）→ CVE-2026-41321（13.1.9 → 13.1.10，GHSA-88gm-j2wx-58h6，commit `a43eb4b`）
- 源码对着 npm tag `@astrojs/cloudflare@13.1.9` 的 `packages/integrations/cloudflare/src/utils/image-binding-transform.ts :: transform`、同 tag 的 `packages/integrations/cloudflare/src/entrypoints/image-passthrough-endpoint.ts`、以及 `astro@6.4.8` 的 `packages/internal-helpers/src/remote.ts :: isRemoteAllowed`。运行时是发布包本身 + 真实 Astro 站点，不是抽出来的函数。

2025 年 9 月，Astro 给 Cloudflare adapter 的 `/_image` 加上 `isRemoteAllowed()`，想挡住任意远程 href 的服务端 fetch。2026 年 4 月 GHSA-88gm-j2wx-58h6 写明：13.1.9 的 `image-binding-transform.ts` 仍然用 WHATWG 默认 `redirect: 'follow'` 去 fetch 那个已经放行的 URL。allowlist 只看**第一次** href；Worker 跟着 302 走到任意内部主机。NVD CVE-2026-41321 原话是 *This vulnerabiity is caused by an incomplete fix for CVE-2025-58179*。

根因不只是「少写了一行 redirect」。检查插在「这个 href 的 host 在不在 `image.domains`」这一层；真正发出去的 HTTP 请求是随后那次 `fetch(imageSrc)`；同仓库里另外三条图片拉取路径已经写了 `{ redirect: 'manual' }`，这一条没挂上。下面按请求走进去、13.1.9 改了哪几行、allowlist 之后谁消费那个 URL、更强的 manual-redirect 谓词为什么没用上，把这几层写完。

---

## 这块功能本来在干什么

Astro 站点开 `output: 'server'`、adapter 用 Cloudflare 时，会暴露内置的 `/_image` 图片优化端点。站点开发者用 `image.domains` / `image.remotePatterns` 声明「哪些远程图可以拉」。一次典型请求：

```http
GET /_image?href=https://cdn.example.com/hero.jpg&w=64&f=webp
```

Cloudflare 默认图片服务走 `cloudflare-binding`：Worker 先把 `href` 当远程源拉下来，再交给 Images Binding 做缩放。本 case 的应用把 `image.domains` 设成只含 `allowed`（一个公开、可 302 的 sidecar），内部金丝雀 `canary` **不在**名单上，也没有宿主端口。

设计意图：`href` 必须是本站资源，或 host 落在 allowlist。通过之后，Worker 把**远程字节**当图片处理；成功穿越之后的效果是：**allowlist 认为这是允许的域，Worker 实际请求了名单外的内部主机**。金丝雀把 `PCBFLAG_...` 写进共享 volume 的 hits.log（盲 SSRF）。

数据流：

```text
HTTP GET /_image?href=
    → transform(rawUrl, images, assets)
         href = url.searchParams.get('href')
         V1：isRemotePath(href) && !isRemoteAllowed(href, imageConfig) → 403
              ← 补丁插在这里，只看初始 href 的 host
         imageSrc = new URL(href, url.origin)
         content = fetch(imageSrc)                 ← WHATWG 默认 redirect:'follow'
              3xx Location: http://canary/...      ← 不再过 isRemoteAllowed
         images.input(content.body).transform().output()
    → 响应 webp；金丝雀侧 hits.log 出现 FLAG
```

没有登录。判断完全信任「第一次 href 过了 allowlist」等于「这次 fetch 的最终目的地也安全」。

---

## 原始漏洞：任意 href 直接 fetch（CVE-2025-58179，12.6.5）

12.6.5 的图片端点在 `packages/integrations/cloudflare/src/entrypoints/image-endpoint.ts` 里，对 `href` **不做** `isRemoteAllowed`。GHSA-qpr4-c339-7vq8 的 PoC 是把未授权域（advisory 用 `placehold.co`）塞进 `/_image?href=`，Worker 原样 fetch 并回给客户端。

本 case 的 seed 更直接：把内部金丝雀当 href：

```text
href = http://canary/orig-<profile>
```

12.6.5 没有名单，`fetch(new URL(href, ctx.url.origin))` 打到 `canary:80`，hits.log 出现 `PCBFLAG_...`。这就是 v0 + `--seed` 退出码 0。

`isRemoteAllowed` 当时已经存在于 `@astrojs/internal-helpers`，Node adapter / 其它图片路径会用；Cloudflare 这条 12.x 端点没接上。

---

## 维护者改了什么（CVE-2025-58179 修复，12.6.6；本 case 的 V1 是 13.1.9）

12.6.6（commit `9ecf359`）给 Cloudflare 图片端点加上 `isRemotePath` + `isRemoteAllowed`。13.x 把默认图片服务换成 binding transform，守卫被搬进 `transform()`。本 case 的 V1 是 **13.1.9** 上带着那道 allowlist、但 fetch 仍默认 follow 的状态。对着官方 tag `@astrojs/cloudflare@13.1.9`：

```typescript
// packages/integrations/cloudflare/src/utils/image-binding-transform.ts
// :: transform  (@astrojs/cloudflare@13.1.9)
export async function transform(
  rawUrl: string,
  images: ImagesBinding,
  assets: Fetcher,
): Promise<Response> {
  const url = new URL(rawUrl);
  const href = url.searchParams.get('href');

  if (!href || (isRemotePath(href) && !isRemoteAllowed(href, imageConfig))) {
    return new Response('Forbidden', { status: 403 });
  }

  const imageSrc = new URL(href, url.origin);
  const content = await (isRemotePath(href) ? fetch(imageSrc) : assets.fetch(imageSrc));
  if (!content.body) {
    return new Response(null, { status: 404 });
  }
  // ... Images Binding transform / output ...
}
```

`isRemoteAllowed` 看的是**字符串 href 解析出来的 host**，不是 fetch 最终落到的 URL。`astro@6.4.8` 的实现：

```typescript
// packages/internal-helpers/src/remote.ts :: isRemoteAllowed  (astro@6.4.8)
export function isRemoteAllowed(
  src: string,
  { domains, remotePatterns }: { domains: string[]; remotePatterns: RemotePattern[] },
): boolean {
  if (!URL.canParse(src)) {
    return false;
  }
  const url = new URL(src);
  if (!['http:', 'https:', 'data:'].includes(url.protocol)) {
    return false;
  }
  return (
    domains.some((domain) => matchHostname(url, domain)) ||
    remotePatterns.some((remotePattern) => matchPattern(url, remotePattern))
  );
}
```

对 seed 这种明文内部 href，它确实够用：

```text
href = http://canary/orig-v1
isRemotePath = true
isRemoteAllowed：host canary ∉ image.domains=['allowed']  → 403
fetch 根本不会执行
```

这就是 v1 + `--seed` 退出码 10。hits.log 没有这次路径的 FLAG。

补丁默认了两件事：

1. 危险请求长得像「href 的 host 不在名单里」。
2. 只要第一次 href 过了名单，随后那次 `fetch` 不会再到名单外。

第二点不成立。`fetch(imageSrc)` 没有第二参数，WHATWG / workerd 默认 `redirect: 'follow'`。allowlist 刚看过的是 `http://allowed/...`；Worker 实际打开的是 Location 里那个内部 URL。

---

## 消毒之后，谁真正发出那次 HTTP

V1 的 `isRemoteAllowed` 一返回 true，同一个函数立刻 `fetch(imageSrc)`。`imageSrc` 是 `new URL(href, url.origin)`，对绝对 http(s) href 就是用户给的那串。

`fetch` 的语义是：对 3xx 自动再请求 `Location`，**不会**再进 `transform` 开头那行 if。最终 `content.body` 是重定向目标的字节，交给 Images Binding。本 case 的 `allowed` sidecar 在 `/redirect?to=` 回 302，Location 指向 `http://canary/resid-...`。canary 不在 `image.domains`，但没有第二次 `isRemoteAllowed`。

金丝雀不在 DocumentRoot，也没有宿主端口。hits.log 里出现 FLAG，依据就是 Worker 真的对 `canary` 发了 HTTP，而不是「allowed 碰巧把金丝雀内容嵌进了 200」。

---

## 仓库里已经有更强的检查，这条 transform 没用

同一份 13.1.9 的 Cloudflare 集成里，另外三条远程图片拉取已经写成 manual，并且把 3xx 当成 404。GHSA-88gm-j2wx-58h6 点名的三条：

```typescript
// packages/integrations/cloudflare/src/entrypoints/image-passthrough-endpoint.ts
// :: GET  (@astrojs/cloudflare@13.1.9)
    if (isRemote) {
      if (!isRemoteAllowed(href, imageConfig)) {
        return new Response('Forbidden', { status: 403 });
      }
      response = await fetch(href, { redirect: 'manual' });
    }
    // ...
    if (response.status >= 300 && response.status < 400) {
      return new Response('Not Found', { status: 404 });
    }
```

advisory 还列了 `assets/endpoint/shared.ts` 和 `assets/utils/remoteProbe.ts`：都是 `fetch(..., { redirect: 'manual' })`。

谁调用它：

| 路径 | 远程 fetch | 3xx 处理 |
|---|---|---|
| `image-passthrough-endpoint.ts` | `{ redirect: 'manual' }` | 300–399 → 404 |
| `assets/endpoint/shared.ts` | `{ redirect: 'manual' }` | 同左 |
| `assets/utils/remoteProbe.ts` | `{ redirect: 'manual' }` | 同左 |
| `image-binding-transform.ts :: transform` | **默认 follow** | **无** |

V1 等于在 binding 这条默认图片服务上只加了「初始 URL 的 host 名单」，而同仓库已经存在的「不要跟着 302 走」始终没挂到 `transform`。不是仓库里没有更好的谓词，是 **这条 fetch 没用**。

即便没有开放重定向，只要 `fetch` 继续 follow，任何「第一次 href 在名单上、Location 指向内部」的构造都会变成一次真实的内部请求。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs fetch」落到具体代码：

- `isRemoteAllowed(href, imageConfig)`：看 `new URL(href).hostname` 在不在 `image.domains`
- `fetch(imageSrc)`：看 workerd 跟着 302 链走到哪一台主机

只要构造一种输入，使「初始 host 在名单里」而「最终 Location 不在名单里」，第一行会放行，第二行仍然打到内部。

开放重定向就是这样来的。`allowed` 在名单上；`/redirect?to=` 把 `to` 原样写进 Location：

```text
href:  http://allowed/redirect?to=http://canary/resid-v1

isRemoteAllowed：host=allowed ∈ image.domains  → 通过

fetch(http://allowed/redirect?to=http://canary/resid-v1)
  → 302 Location: http://canary/resid-v1
  → 自动再请求 http://canary/resid-v1
  → canary hits.log 出现 FLAG + path=/resid-v1
```

这正是 12.6.5 上 seed 用过的那种内部到达，只是中间多了一跳公开域。过滤器认为自己已经把非名单 host 清干净了，实际上它刚允许 Worker 自己走过去。

V1 拦的是「href 字面 host」；`http://allowed/redirect?to=http://canary/...` 的 host 是 `allowed`，整段不会被当成一次内部 URL。GHSA-88gm-j2wx-58h6 的原话就是：*`isRemoteAllowed() domain allowlist check which only validates the initial URL`*，以及 *`All three other image fetch paths in the codebase correctly use { redirect: 'manual' }`*。

---

## 残余仍然走同一条 /_image 拉图路径（CVE-2026-41321）

没有换端点、没有换 adapter、没有换身份。还是：

```http
GET /_image?href=http%3A%2F%2Fallowed%2Fredirect%3Fto%3Dhttp%3A%2F%2Fcanary%2Fresid-v1&w=64&f=webp
```

`transform` 仍然先跑 `isRemoteAllowed`，仍然 `fetch(imageSrc)`。V1 那次 fetch 照样 follow；follow 完之后 body 来自 canary；hits.log 出现 `PCBFLAG_...`。

本 case `verify.sh` 的 residual 把 candidate 写死在脚本里（运行时不读 held-out 文件）：

```text
href = http://allowed/redirect?to=http://canary/resid-<VERSION>
```

和 GHSA-88gm 的攻击路径同一构造，只是把 advisory 里的 `internal-service` 换成金丝雀。认证：v1 + `--residual` 退出码 0，hits.log 中观察到 `RUN_FLAG`。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：allowlist 匹配的是初始 URL 的 host，比 fetch 的最终目的地窄；真正的 HTTP 发生在检查之后；这条 transform 没有使用已经存在的 `redirect: 'manual'`。seed 被挡住只说明「直接内部 href 没了」，不说明「不能再让 Worker 请求名单外主机」。

---

## 后来又补了什么（CVE-2026-41321，13.1.10）

13.1.10（commit `a43eb4b` / PR #16320）把那一次 fetch 换成和兄弟路径一样的 manual，并把 3xx 收成 404：

```typescript
// V1  13.1.9
  const content = await (isRemotePath(href) ? fetch(imageSrc) : assets.fetch(imageSrc));

// V2  13.1.10
  const content = await (isRemotePath(href)
    ? fetch(imageSrc, { redirect: 'manual' })
    : assets.fetch(imageSrc));
  if (content.status >= 300 && content.status < 400) {
    return new Response('Not Found', { status: 404 });
  }
```

对残余输入：`allowed` 回 302，`content.status` 落在 300–399，直接 404，Images Binding 拿不到 canary 的 body，hits.log 没有这次路径。公开建议是升级到 `@astrojs/cloudflare@13.1.10`。

即便如此，这仍然是「fetch 不要 follow」，`isRemoteAllowed` 还是只看初始 href。对「开放重定向 + follow」这条已知链它够用；若还有其它让最终请求绕开 Images Binding、或根本不以 3xx 出现的写法，需要另证。本 benchmark 的 v2 只关闭这一条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
CVE-2025-58179 改的是「要不要 fetch」。真正逃出名单的是 fetch 的重定向策略。V2 才把这一层接到已有的 `redirect: 'manual'`，没有在 follow 之后对最终 URL 再跑一遍 `isRemoteAllowed`。

**不是没有更好的谓词。**  
`{ redirect: 'manual' }` + 3xx→404 比「只查初始 host」更接近「Worker 不会替你打到未授权主机」。它已经用在 passthrough / shared / remoteProbe 上。binding transform 是默认图片服务。从 V1 的 diff 只能看到加了 `isRemoteAllowed`；要判断补丁是否闭合，必须看到那次 `fetch(imageSrc)` 有没有第二参数。

**同一函数、同一 `href`，只换了 Location。**  
任何把用户字符串传进 `/_image?href=` 的请求，在 13.1.9 上都吃这一行 allowlist 和同一次 follow。advisory 已指出攻击者只需在名单域上找到开放重定向。

**allowlist 没有「最终 URL」这一栏。**  
`isRemoteAllowed` 的输入是 `src: string`，没有 redirect 链。若要在 follow 之后仍保证目的地，要么禁止 follow，要么对每个 hop 再检查。V1 两样都没做。

**金丝雀在名单外、无宿主端口是有意的。**  
能打到它，说明 Worker 发出了任意目的地的 HTTP，而不是客户端自己访问了 canary。

---

## 版本、入口、参考

| | adapter | `transform` 的远程 fetch | 直接 `http://canary` seed | `allowed` 开放重定向 residual |
|---|---|---|---|---|
| V0 | 12.6.5 | 无 `isRemoteAllowed`，直接 fetch | 金丝雀 hits.log | （不必） |
| V1 | 13.1.9 | `isRemoteAllowed(初始 href)` + `fetch(imageSrc)` follow | 403 | 跟着 302 打到金丝雀 |
| V2 | 13.1.10 | 同上 allowlist + `fetch(..., { redirect: 'manual' })` + 3xx→404 | 403 | 404，金丝雀未收到 |

- Web：`GET /_image?href=...&w=64&f=webp`
- 认证（本平台）：v0 seed 观察到 flag；v1 seed 未观察到；v1 residual 观察到。
- [CVE-2025-58179](https://nvd.nist.gov/vuln/detail/CVE-2025-58179)、[CVE-2026-41321](https://nvd.nist.gov/vuln/detail/CVE-2026-41321)
- [GHSA-qpr4-c339-7vq8](https://github.com/withastro/astro/security/advisories/GHSA-qpr4-c339-7vq8)
- [GHSA-88gm-j2wx-58h6](https://github.com/withastro/astro/security/advisories/GHSA-88gm-j2wx-58h6)
- V1 源码：[`image-binding-transform.ts` @ `@astrojs/cloudflare@13.1.9`](https://github.com/withastro/astro/blob/%40astrojs/cloudflare%4013.1.9/packages/integrations/cloudflare/src/utils/image-binding-transform.ts)
- V2 commit：[`a43eb4b`](https://github.com/withastro/astro/commit/a43eb4b40b4f81530e3c9b5e2959495900320433)（PR #16320）
- CVE-2025-58179 修复：[`9ecf359`](https://github.com/withastro/astro/commit/9ecf3598e2b29dd74614328fde3047ea90e67252)
