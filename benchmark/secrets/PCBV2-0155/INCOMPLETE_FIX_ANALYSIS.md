# nuxt-og-image：isBlockedUrl 认了 `::1` 和点分 mapped-v4，没把 hex 映射回 127.0.0.1

- Case：`PCBV2-0155`
- 产品：npm `nuxt-og-image`（Nuxt 模块，服务端渲染 Open Graph 图）。运行时是整包 `nuxt-og-image@6.2.5` 装进 Nuxt 4 应用，走模块自己的 `/_og/` 图片路由，不是抽出来的函数。
- 链：GHSA-pqhr-mp3f-hrpp（6.2.4 → 6.2.5，commit `9902a897`，**无 CVE 别名**）→ CVE-2026-44589 / GHSA-c2rm-g55x-8hr5（6.2.5…6.4.8 → 6.4.9，commit `79db60f1`）
- CVE-2026-44589 原话：*The isBlockedUrl() denylist introduced in nuxt-og-image@6.2.5 to remediate GHSA-pqhr-mp3f-hrpp … is incomplete. It has an incomplete IPv6 prefix list and is missing redirect re-validation.*

根因不只是「IPv6 黑名单少写了几行」。检查插在「这个 URL 字符串像不像内网」上；真正发请求的是后面的 `$fetch(src)`。同一次检查已经能把点分的 `::ffff:127.0.0.1` 映射回 IPv4 再走 `isPrivateIPv4`，却要求 mapped-v4 **必须是点分**；hex 压缩的 `::ffff:7f00:1` 掉进「四条 IPv6 前缀」那个更弱的分支。下面按请求走进去。

---

## 这块功能本来在干什么

页面用 `defineOgImageComponent` 把一张远程图（头像、封面）嵌进 OG 模板。爬虫或调试请求去拉生成的 `/_og/...` 时，模块在 **服务端** 把 `<img src>` / `background-image: url(...)` 拉下来，转成 data URI 再交给 Satori。一次典型触发：

```http
GET /ssrf?avatar=http://[::1]:9111/
```

页面把 `avatar` 原样塞进组件的 `src`。nuxt-og-image 把它编进 og:image URL（路径段 `src_~<b64url>`）。再请求那张 OG 图：

```http
GET /_og/d/c_Ssrf,src_~<b64>,...png
```

生产环境（`import.meta.dev === false`）里，`imageSrc` 插件对非相对、非 `data:` 的绝对 URL 先跑 `isBlockedUrl`，再 `$fetch`。设计意图：远程图可以是公网 `https://cdn.example/avatar.png`，不能是环回 / 私网 / 云 metadata。成功穿越之后的效果是：**进程对容器自己的环回发 HTTP，把只绑在 unpublished `:9111` 上的金丝雀 SVG 拉回来，base64 嵌进 OG 输出**。

数据流：

```text
GET /ssrf?avatar=<url>
    → defineOgImageComponent('Ssrf', { src: avatar })
    → 生成 /_og/d/c_Ssrf,src_~...
GET 该 og:image
    → imageSrc transformer
         src = decodeHtml(src)
         V1：isBlockedUrl(src)          ← 只看 URL 字符串
         $fetch(src, { responseType: 'arrayBuffer' })
              ofetch 默认 redirect: follow   ← 真正的出站，不再查
         toBase64Image(buffer) → <img src="data:...">
    → OG SVG body 里出现 PCBFLAG_...
```

不需要登录。`debug:true` 只让渲染结果可见，**不放松** `isBlockedUrl`。相对路径走本地 storage / origin fetch，不进这条绝对 URL 分支。

---

## 原始漏洞：绝对 URL 直接 `$fetch`（GHSA-pqhr-mp3f-hrpp，6.2.4）

6.2.4 的 `imageSrc` 在非相对分支里 `decodeHtml` 之后立刻 `$fetch`，**没有** denylist。advisory 给出三条向量，都是用户能影响的参数最终变成一张要拉的图：

```http
GET /_og/d/og.png?style=background-image:+url('http://127.0.0.1:8888/secret')
GET /_og/d/og.png?html=<img src="http://127.0.0.1:8888/secret">
```

本 case seed 走页面 `avatar` → 组件 `src`，等价于第三条里的 `<img src>`。V0 对 `http://[::1]:9111/` 没有任何 host 分类，`$fetch` 打到 sidecar。这就是 v0 + `--seed` 观察到 `PCBFLAG_...`。

GHSA-pqhr-mp3f-hrpp 的缓解说明写了：*Decimal/hexadecimal IP encoding bypasses are also handled*——那是他们以为 WHATWG `URL` 解析器加上即将加入的 denylist 已经覆盖的部分。6.2.5 对十进制/十六进制 **IPv4 整型**（`2130706433`、`0x7f000001`）确实有 `RE_INT_IP` 分支；对 IPv6 映射地址只覆盖了点分形态。

---

## 维护者改了什么（GHSA-pqhr-mp3f-hrpp 修复，6.2.5）

commit `9902a897`（tag `v6.2.5`）在 `src/runtime/server/og-image/core/plugins/imageSrc.ts` 加入 `isBlockedUrl`，并在 `$fetch` **之前**短路：

```ts
# V0  6.2.4
src = decodeHtml(src)
imageBuffer = await $fetch(src, { responseType: 'arrayBuffer' })

# V1  6.2.5   （本 case 的目标；npm 包 dist/.../imageSrc.js 同逻辑）
src = decodeHtml(src)
if (!import.meta.dev && isBlockedUrl(src)) {
  logger.warn(`Blocked internal image fetch: ${src}`)
  delete node.props.src
} else {
  imageBuffer = await $fetch(src, { responseType: 'arrayBuffer' })
}

# V2  6.4.9
# isBlockedUrl 搬到 util/ssrf.ts：expandIPv6 + isPrivateIPv6
# 出站改 fetchWithRedirectValidation（redirect: 'manual'，每跳再查）
```

V1 `isBlockedUrl` 的分层（tag `v6.2.5` 源文件原文）：

```ts
function isBlockedUrl(url: string): boolean {
  const parsed = new URL(url)                       // 非 http(s) → 拦
  const bare = hostname.replace(RE_IPV6_BRACKETS, '')
  if (bare === 'localhost' || bare.endsWith('.localhost')) return true

  const mappedV4 = bare.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/)
  const ip = mappedV4 ? mappedV4[1]! : bare         // 只认点分 mapped-v4

  // 点分 IPv4 → isPrivateIPv4(a, b)   含 127/8、10/8、172.16/12、192.168/16、169.254、0/8
  // RE_INT_IP → 把 2130706433 / 0x7f000001 拆成高两 octet 再 isPrivateIPv4

  if (bare === '::1' || bare.startsWith('fc') || bare.startsWith('fd') || bare.startsWith('fe80'))
    return true
  return false                                      // 其余当公网
}
```

对 seed `http://[::1]:9111/`：`bare === '::1'` 为真，删 `src`，不 `$fetch`。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 环回 IPv6 只会长得像 `::1`；mapped-v4 只会长得像 `::ffff:127.0.0.1`。
2. 对**初始** URL 拦一次就够，`$fetch` 不会再走到别的 IP。

两点都不成立。更关键的是：这一行之后，代码仍然把**用户给的那串 URL**交给 ofetch，而且那次连接**不再跑分类器**。

---

## 消毒之后，这个 URL 怎么接到出站请求上

V1 的 `isBlockedUrl` 返回 false 之后，同一个 transformer 立刻：

```ts
imageBuffer = (await $fetch(src, {
  responseType: 'arrayBuffer',
}).catch(() => {})) as BufferSource | undefined
if (imageBuffer) {
  node.props.src = toBase64Image(buffer)
}
```

`$fetch` 是 ofetch，默认 `redirect: 'follow'`，内核 / undici 按 URL 的 host 建连。过滤器刚看过的是字符串 `bare` 的几条 `startsWith`；TCP 看到的是解析后的地址。WHATWG `URL` 会把 `[::ffff:7f00:1]` 收成 hostname `::ffff:7f00:1`，**不会**先展开成 `::ffff:127.0.0.1` 再交给这段 JS。

`background-image` 那条 transformer 用同一份 `isBlockedUrl`，然后同样 `$fetch(decodedSrc)`。两条路共用谓词、共用出站。

金丝雀 sidecar 绑在 `::` 的 9111、不发布到宿主机。OG 响应里出现 `PCBFLAG_...`，依据是这次 `$fetch` 真的打到了环回，而不是「模板里碰巧写死了 flag」。

---

## 仓库里已经有更强的检查，hex mapped-v4 没用上

同一函数里已经有「把地址当成 IPv4 再判私网」的路径：

| 形态 | 走哪条 |
|---|---|
| `127.0.0.1` / `10.0.0.1` | 点分 → `isPrivateIPv4` |
| `2130706433` / `0x7f000001` | `RE_INT_IP` → `isPrivateIPv4` |
| `::ffff:127.0.0.1` | `RE_MAPPED_V4` 抽出点分 → `isPrivateIPv4` |
| `::ffff:7f00:1` | **四条 IPv6 前缀**，配不上就 `return false` |
| `::1` | `bare === '::1'` |

`isPrivateIPv4` 在同文件里写得很直白：

```ts
function isPrivateIPv4(a: number, b: number): boolean {
  if (a === 127) return true
  if (a === 10) return true
  if (a === 172 && b >= 16 && b <= 31) return true
  if (a === 192 && b === 168) return true
  if (a === 169 && b === 254) return true
  if (a === 0) return true
  return false
}
```

`isPrivateIPv4(127, 0)` 会拦环回。`::ffff:7f00:1` 的后 32 bit 就是 `127.0.0.1`（`7f00:0001`），但 V1 只有在 **点分** 时才抽出那 32 bit。不是没有「这是不是 127/8」的谓词，是 **hex mapped-v4 没接到那条谓词上**。

同一份 6.2.5 还加了 `restrictRuntimeImagesToOrigin`（按 `Host` / `X-Forwarded-Host` 限制谁能打 `/_og`）。它默认 **false**，本 case 也没打开。就算打开，它管的是「哪台主机允许渲染 OG」，不管 `<img src>` 指向哪里。advisory 写的 *Decimal/hexadecimal IP encoding bypasses are also handled* 指的是 `RE_INT_IP` 那条 IPv4 整型分支，不是 IPv6 组。

advisory 还指出：`$fetch` 跟随 30x 时没有第二次 `isBlockedUrl`。即便 hex 映射被补上，一个公网 Origin 302 到 `http://127.0.0.1:9111/` 仍然能完成 SSRF。V1 源码里没有 `redirect: 'manual'`，也没有 hop 循环。本 case residual 不依赖 302，因为 hex mapped-v4 已经能直接打环回；redirect 是同一谓词上的第二条缝，V2 一起补。

---

## 这个补丁挡住了什么、没挡住什么

- `isBlockedUrl`：看 hostname 字符串是不是 `localhost` / 点分私网 / 整型 IPv4 / `::1` / `fc`/`fd`/`fe80` 前缀
- `$fetch`：看 Node 把这串 URL 解析成哪个地址、以及 30x 之后去哪

把 residual 的 hostname 按 V1 分支走一遍：

```text
avatar = http://[::ffff:7f00:1]:9111/
new URL(...).hostname = ::ffff:7f00:1     （WHATWG 去掉方括号，不展开）
bare = ::ffff:7f00:1

localhost？否
RE_MAPPED_V4 /^::ffff:(\d+\.\d+\.\d+\.\d+)$/ ？
    7f00:1 不是点分 → 不抽 IPv4，ip 仍是 ::ffff:7f00:1
点分四段？ split('.') 得不到 4 个纯数字 → 跳过 isPrivateIPv4
RE_INT_IP？ 含冒号 → 否
bare === '::1'？否
startsWith fc/fd/fe80？否
return false  → 放行
$fetch → TCP 落到 127.0.0.1:9111（v4-mapped）
sidecar SVG <desc> 里的 PCBFLAG_... 被 toBase64Image 嵌进 OG
```

GHSA-c2rm-g55x-8hr5 把这条列为 *IPv6-mapped IPv4 loopback in pure-hex form (RE_MAPPED_V4 regex requires dotted-quad). Reaches 127.0.0.1 on a single-stack-IPv4 host with no other primitive needed*。对比：`http://[::ffff:127.0.0.1]:9111/` 会走 `RE_MAPPED_V4`，在 V1 上就被拦——所以残余不是「任意 IPv6」，而是「同一 mapped-v4、换了书写」。

同一条谓词还放过 `fec0::/10`、`5f00::/16`、`3fff::/20`、`64:ff9b:1::7f00:1` 等；本 case 的 residual 只打 hex mapped-v4 这一条，因为它和 seed 一样打环回 sidecar，不依赖外网 302。

---

## 残余仍然走同一条 imageSrc `$fetch`（CVE-2026-44589）

没有换路由、没有换插件、没有换身份。还是：

```http
GET /ssrf?avatar=http://[::ffff:7f00:1]:9111/
```

再拉生成的 og:image。`isBlockedUrl` 照样执行；执行完认为这是公网；`$fetch` 打到 sidecar；SVG `<desc>` 里的 flag 被 base64 嵌进 OG。公开 residual 与 seed 是同一 sink（绝对 `<img src>` 的服务端 fetch），只换了 host 的写法。

平台 `poc/residual_poc.py` 的 candidate 就是这串 URL。它打的是 incomplete-fix 链上的 **同一个 `$fetch`**，不是另一条 Nitro 路由。

---

## 后来又补了什么（CVE-2026-44589，6.4.9）

commit `79db60f1` 把分类器搬到 `src/runtime/server/util/ssrf.ts`：`expandIPv6` 展开 8 组 16-bit，`isPrivateIPv6` 在 `g5 === 0xFFFF` 时把 `g6` 拆回 IPv4 再走 `isPrivateIPv4`。`::ffff:7f00:1` → groups `[0,0,0,0,0,65535,32512,1]` → `a=127,b=0` → 拦。

出站改成 `fetchWithRedirectValidation`：`redirect: 'manual'`，每个 `Location` 再跑一遍 `isBlockedUrl`。对这条 hex mapped-v4 residual，展开后即拦，不必走到 redirect。把 `::ffff:7f00:1` 按 V2 `expandIPv6` / `isPrivateIPv6` 走一遍：

```text
bare = ::ffff:7f00:1
expandIPv6 → 8 组 [0, 0, 0, 0, 0, 0xFFFF, 0x7f00, 0x0001]
g5 === 0xFFFF → 抽嵌入 IPv4
a = (0x7f00 >> 8) & 0xFF = 127
b = 0x7f00 & 0xFF = 0
isPrivateIPv4(127, 0) → true → 拦
```

`fetchWithRedirectValidation` 对每个 hop 先 `isBlockedUrl` 再 `fetch(..., redirect:'manual')`，最多 5 跳。公开建议是升级到 `nuxt-og-image@6.4.9`。

即便如此，分类器仍是 denylist + 字符串解析，没有把「解析一次 IP、connect 钉死」做成强制。对本 benchmark 的 reference residual 它够用。

---

## 从这条链还能看出什么

**维护者改错了哪一层。**  
他们改的是 fetch 前的 hostname 字符串。真正出网的是 `$fetch`。V2 仍在同一层加码（展开 IPv6 + 每跳再查），没有把校验过的 IP pin 到 socket。

**不是没有更好的谓词。**  
`isPrivateIPv4` 已经认识 127/8。`RE_MAPPED_V4` 已经会把 mapped-v4 **抽成 IPv4**。hex 形态只是没进那条抽取。从 6.2.5 的 diff 只能看到「加了 denylist」；要判断是否闭合，必须看到 `RE_MAPPED_V4` 的点和 `$fetch` 的 redirect 默认值。

**同一 transformer、同一 `$fetch`，只换了 avatar 的写法。**  
任何进入绝对 `<img src>` / `background-image` 分支的用户字符串，在 6.2.5 上都吃同一份 `isBlockedUrl`。advisory 的 html/style 参数和本 case 的 `avatar` query 是同一插件。

**金丝雀在 unpublished 环回是有意的。**  
`:9111` 不映射到宿主机。能读到它，说明模块侧 fetch 打的是容器自己的 loopback，而不是页面把 flag 写进了 HTML。

---

## 版本、入口、参考

| | npm | `isBlockedUrl` | 出站 | `http://[::1]:9111/` | `http://[::ffff:7f00:1]:9111/` |
|---|---|---|---|---|---|
| V0 | 6.2.4 | 无 | 直接 `$fetch` | 读到金丝雀 | （不必） |
| V1 | 6.2.5 | 点分 mapped-v4 + `::1`/`fc`/`fd`/`fe80` | `$fetch` follow 30x | 拦 | 读到金丝雀 |
| V2 | 6.4.9 | `expandIPv6` / `isPrivateIPv6` | `fetchWithRedirectValidation` | 拦 | 展开成 127/8，拦 |

- Web：`GET /ssrf?avatar=...` → 再 `GET` 生成的 `/_og/...`
- 源码：tag [`v6.2.5`](https://github.com/nuxt-modules/og-image/blob/v6.2.5/src/runtime/server/og-image/core/plugins/imageSrc.ts) 的 `isBlockedUrl`；V2 [`v6.4.9`](https://github.com/nuxt-modules/og-image/blob/v6.4.9/src/runtime/server/util/ssrf.ts)
- [GHSA-pqhr-mp3f-hrpp](https://github.com/nuxt-modules/og-image/security/advisories/GHSA-pqhr-mp3f-hrpp)（无 CVE）
- [CVE-2026-44589](https://www.cve.org/CVERecord?id=CVE-2026-44589) / [GHSA-c2rm-g55x-8hr5](https://github.com/nuxt-modules/og-image/security/advisories/GHSA-c2rm-g55x-8hr5)
- [GitLab GLAD](https://advisories.gitlab.com/npm/nuxt-og-image/CVE-2026-44589/)
- 修复提交：[9902a897](https://github.com/nuxt-modules/og-image/commit/9902a897ba907110721368c830fc8d5ff1916d73)、[79db60f1](https://github.com/nuxt-modules/og-image/commit/79db60f12a54deee883b73890391d720c98533dd)
