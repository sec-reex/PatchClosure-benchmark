# @fastify/static：挡住了 `%2F`，没挡住路径里的 `..`

- Case：`PCBV2-0021`
- 产品：`@fastify/static`（Fastify 静态文件插件）
- 链：CVE-2026-6414 / GHSA-x428-ghpx-8j92（9.1.0 → 10.1.0）→ CVE-2026-15074 / GHSA-83w8-p2f5-377r（10.1.0 → 10.1.1）
- 源码对着官方 tag `v10.1.0` 的 `index.js :: getPathnameForSend`、`pumpSendToReply`。运行时是整包 npm 包 + 本 case 的 Fastify 应用（`/static/secret/*` 守卫 + 静态根），不是抽出来的 `decodeURI`。

10.1.0 引入 `getPathnameForSend`：先按路由前缀切路径，再 `decodeURI`，避免 find-my-way 把 `%2F` 当普通字符匹配进静态 catch-all、随后 `@fastify/send` 再解码成真正的 `/`。GHSA-83w8-p2f5-377r 写明：这个 helper **只**挡住了 `%2F`；`..` 和 `%2E%2E` 能活过 `decodeURI`（没有需要再编码的字符），find-my-way 匹配时**不**折叠 `..`，于是请求打在静态插件上而不是守卫路由 `/static/secret/*`；send 在自己的穿越检查之前先 `path.normalize`，把 `foo/../secret` 收成 `secret`。NVD 把这件事记成 CVE-2026-15074。

根因不是「decodeURI 写错了」。V1 的 decode 对 `%2F` 是对的。检查插在「前缀匹配之后的 pathname 字符串」上；真正打开文件的是 `@fastify/send` 对**另一套**已经 normalize 过的路径。下面按请求走进去、补丁改了哪一段、消毒后谁还在 normalize、send 自带的穿越谓词为什么管不住守卫绕过，把这三层写完。

---

## 这块功能本来在干什么

应用把 `@fastify/static` 挂在 `/static`（wildcard `prefix + '*'`），同时用一条更具体的路由 `fastify.all('/static/secret/*', 403)` 保护金丝雀。设计意图：直接访问 `/static/secret/canary.txt` 应命中守卫、403；静态插件只服务「守卫覆盖范围之外」的 URL。find-my-way 按路径模板匹配，**不会**在匹配前做 `path.normalize`。

一次典型请求：

```http
GET /static/secret%2Fcanary.txt HTTP/1.1
GET /static/foo/../secret/canary.txt HTTP/1.1
```

wildcard handler 取出 `req.raw.url`，交给 `getPathnameForSend`，再 `pumpSendToReply` → `send(request.raw, encodeURI(pathnameForSend), options)`。成功穿越之后的效果是**读出守卫前缀下的文件内容**（`/data` 静态根里的 `secret/canary.txt`，含 `PCBFLAG_...`）。这不是逃出 `root`，是绕过「这个 URL 前缀不许静态插件碰」的路由守卫。

数据流：

```text
HTTP URL
    → find-my-way 匹配（不折叠 ..，%2F 不当 /）
         /static/secret/* 守卫  vs  /static/* 静态
    → getPathnameForSend(raw.url)
         V1：decodeURI(pathname)     ← 只处理编码
    → pumpSendToReply
         allowedPath?(pathname)      ← 仍是未 normalize 的字符串
         send(..., encodeURI(pathname), {root})
              send 内部 path.normalize 后再做「不得逃出 root」
    → 文件内容 → HTTP body
```

---

## 原始漏洞：编码斜杠绕过守卫（CVE-2026-6414，9.1.0）

9.1.0 的 wildcard handler 用 `'/' + req.params['*']` 当 pathname。find-my-way 把 `%2F` 留在 params 里当普通字符，所以 `/static/secret%2Fcanary.txt` **不**匹配 `/static/secret/*`（守卫要的是路径段 `secret` 后面的 `/`），而匹配 `/static/*`。静态插件随后 `decodeURI`，`secret%2Fcanary.txt` 变成 `secret/canary.txt`，send 在 root 下打开该文件。seed：

```text
GET /static/secret%2Fcanary.txt
```

9.1.0 返回 200 和金丝雀。守卫形同虚设。

---

## 维护者改了什么（CVE-2026-6414 修复，10.1.0）

10.1.0 不再信任 `req.params['*']`，改为从 `req.raw.url` 按路由前缀切片，再 decode：

```js
# index.js :: wildcard handler  (v10.1.0)
          const pathname = getPathnameForSend(req.raw.url, matchRoutePrefix)
          if (!pathname) {
            return reply.callNotFound()
          }
          pumpSendToReply(req, reply, pathname, sendOptions.root)

# index.js :: getPathnameForSend
function getPathnameForSend (url, matchRoutePrefix) {
  const questionMark = url.indexOf('?')
  const pathnameEnd = questionMark === -1 ? url.length : questionMark
  const prefixLength = matchRoutePrefix(url, pathnameEnd)
  if (prefixLength === undefined) return
  let pathname = url.slice(prefixLength, pathnameEnd)
  if (pathname === '') pathname = '/'
  else if (!pathname.startsWith('/')) pathname = '/' + pathname
  try {
    return decodeURI(pathname)
  } catch {}
}
```

对 seed 的 `%2F`：若实现还会把含编码分隔符的 URL 判为「前缀对不上 / 非法」，守卫或 `callNotFound` 会挡住（本 case v1 上 seed 为 404）。10.1.0 的意图是：送进 send 的 pathname 必须是 decode 之后、与路由所见一致的路径。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 绕过守卫的办法是「匹配时的路径」和「打开时的路径」因**编码**而不一致。
2. `decodeURI` 之后，剩下的字符串就是 send 将要打开的路径，中间不会再被折叠。

第二点不成立。`decodeURI` 不折叠 `.` / `..`；`%2E%2E` decode 成 `..` 后原样留下。send 在穿越检查**之前**会 `path.normalize`。

---

## 消毒之后，路径怎么接到磁盘上

`getPathnameForSend` 一返回，`pumpSendToReply` 用这份 pathname：

```js
# index.js :: pumpSendToReply  (v10.1.0)
    if (allowedPath && !allowedPath(pathname, options.root, request)) {
      return reply.callNotFound()
    }
    ...
    const { statusCode, headers, stream, type, metadata } =
      await send(request.raw, encodeURI(pathnameForSend), options)
```

`allowedPath` 看到的是仍含 `foo/../secret` 的字符串（如果应用提供了这个回调）。本 case 的守卫**不是** `allowedPath`，是另一条 Fastify 路由。匹配已经结束：find-my-way 选中了 `/static/*`，不会再去跑 `/static/secret/*`。

`@fastify/send` / pillarjs send 在 root 模式下会规范化相对路径，再检查规范化结果是否仍在 root 下。`foo/../secret/canary.txt` 规范化成 `secret/canary.txt`，仍在 root 内，穿越检查通过，文件被读出。过滤器刚看过的是「decode 后的 URL 后缀」；open 看到的是 normalize 后的相对路径。两套语义中间没有「pathname 不得含 `..` 段」的谓词。

wildcard 注册的是 `path: prefix + '*'`。find-my-way 把 `*` 当成剩余后缀，**按斜杠分段**，不把 `..` 当成「回到上一模板段」。因此 `/static/foo/../secret/canary.txt` 的第一段是 `foo`，不是 `secret`，更具体的 `/static/secret/*` 根本不会当候选。匹配在插件 handler 跑起来之前就已经选错了；`getPathnameForSend` 无法回头改路由决策，它只能决定送进 send 的字符串。守卫若写成 `preHandler` 挂在 `/static/secret/*` 上，同样不会跑。

10.1.0 的 `getPathnameForSend` **没有** `dotDotSegmentRegex`。那是 10.1.1 才加的。`pumpSendToReply` 里对 send 的调用是 `encodeURI(pathnameForSend)`：`..` 不含 encodeURI 会转义的字符，来回一趟原样留下，正好送进 send 的 normalize。

---

## 仓库里已经有更强的检查，守卫路由没用上

send 自带「不得用 `..` 逃出 root」。这比 V1 的 decode 更接近「路径安全」，但它回答的是另一个问题：文件是否在 `root` 外面。本 case 的金丝雀**在 root 里面**，只是 URL 前缀被另一条路由声明为禁区。send 的谓词对「守卫绕过」永远返回安全。

谁在 10.1.0 看路径：

| 层 | 是否折叠 `..` | 是否拒绝 `..` |
|---|---|---|
| find-my-way 匹配 | 否 | 否，所以打到静态 catch-all |
| `getPathnameForSend` | 否，只 decodeURI | **否** |
| `allowedPath` | 否（收到未折叠串） | 仅当应用自己写 |
| `@fastify/send` | **是**，normalize | 只拦逃出 root |

V1 等于在调用方加了一个**更弱**的编码还原，而真正 open 的那一层会把 V1 故意留下来的 `..` 自己折叠掉。不是仓库里没有「路径」概念，是 **getPathnameForSend 没用 send 之前的段检查**。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs open」落到具体代码：

- `getPathnameForSend` 的 `decodeURI`：看有没有编码斜杠这类「匹配 ≠ 打开」的编码差
- send 的 `path.normalize` + root 前缀检查：看折叠之后是否仍在静态根下

只要构造一种输入，使 find-my-way 看到的前缀**不是** `/static/secret`，而 normalize 之后打开的是 `secret/canary.txt`，第一层会放行（它只在乎 decode），第二层仍然读到金丝雀。

```text
GET /static/foo/../secret/canary.txt

find-my-way:
  不是 /static/secret/*   （当前段是 foo，下一段是 ..）
  是   /static/*
getPathnameForSend:
  pathname = /foo/../secret/canary.txt
  decodeURI 不变
send:
  normalize → /secret/canary.txt
  位于 root 内 → 200 + FLAG
```

`%2E%2E` 同样：decode 成 `..`，之后与明文 `..` 同一条路。GHSA 原话：*`getPathnameForSend` helper introduced by the fix for GHSA-x428-ghpx-8j92 only guards against the `%2F` variant; `..` and `%2E%2E` survive the `decodeURI`+`encodeURI` round-trip*。

---

## 残余仍然走同一条静态 catch-all（CVE-2026-15074）

没有换插件、没有换 root。还是：

```http
GET /static/foo/../secret/canary.txt
```

wildcard handler 仍然调用同一个 `getPathnameForSend`。V1 的 `decodeURI` 照样执行；执行完之后 pathname 仍含 `..`；`pumpSendToReply` 把它交给 send；normalize 后打开金丝雀；body 里出现 `PCBFLAG_...`。

本 case `verify.sh` 的 residual 把 path 写死为 `/static/foo/../secret/canary.txt`（语义来自 held-out，运行时不读 hidden 文件）。认证：v1 + `--residual` 退出码 0，body 中观察到 flag。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：匹配语言不折叠 `..`；检查只还原编码；open 在检查之后折叠 `..` 且只拦逃出 root。seed 被挡住只说明「`%2F` 不能再拆段」，不说明「不能再从静态根里读出守卫前缀下的文件」。

---

## 后来又补了什么（CVE-2026-15074，10.1.1）

10.1.1 在 `getPathnameForSend` 和 `pumpSendToReply` 里显式拒绝非前导的 `..` 段（`dotDotSegmentRegex` / `leadingDotDotSegmentRegex`），decode 之后若 URL 含 `..` 而送进 send 的后缀不是「仅前导 `..`」（send 自己会拒前导穿越），返回 403 Forbidden。测试覆盖 `/foo/../deep/...`、`/%2e%2e/`、以及路由参数吃掉 `..` 的 `prefix: '/app/:version'` 形态。

10.1.1 加的两段正则把「段」说清楚了：

```js
const dotDotSegmentRegex = /(?:^|[\\/])\.\.(?:[\\/]|$)/u
const leadingDotDotSegmentRegex = /^\/?\.\.(?:[\\/]|$)/u
```

非前导 `foo/../secret` 命中前者、不命中后者，403。前导 `../etc/passwd` 仍交给 send 自己的 root 穿越检查。V1 两段都没有。`getPathnameForSend` 在 10.1.1 还会对 **decode 后的完整 URL path**（`url.slice(0, pathnameEnd)`）测第一段正则，因为路由参数可能在 suffix 被切走之前就把 `..` 吃掉。

`encodeURI(pathnameForSend)` 在 10.1.0 的注释里写着 send 会再 URI-decode，所以这里先编回去。`..` 和 `%2E%2E`（若已经 decode 成 `..`）都不含 encodeURI 会改写的字符，来回一趟等于 noop。V1 用这场 round-trip 处理 `%2F` 一类分隔符；它对 `..` 是恒等变换，随后 send 的 normalize 才是第一次「改变路径含义」的步骤。

对残余输入：`getPathnameForSend` 返回 `null`，handler `forbiddenPathError()`，status 403，body 无 flag。公开建议是升级到 `@fastify/static` 10.1.1；workaround 是不要用路由中间件保护静态文件，改用插件自己的 `allowedPath`（且应对**规范化后**的路径调用）。

即便如此，这仍然是「在 send 之前删/拒 `..` 子串」，send 仍不负责路由守卫。对这条已知链它够用。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是「params 和 raw URL 因 `%2F` 不一致」。真正绕过守卫的是「匹配用未折叠路径、打开用折叠路径」。V2 把 `..` 拒绝提前到 send 之前，这才让匹配和打开看到同一套「不许有 `..`」的规则。

**不是没有更好的谓词。**  
send 已经会 normalize。从 V1 的 diff 只能看到换了 `getPathnameForSend`；要判断补丁是否闭合，必须看到 find-my-way 不折叠 `..`，以及 send 折叠之后仍在 root 内。

**同一 wildcard handler，只换了路径写法。**  
`%2F` 和 `..` 都是「匹配所见 ≠ 打开所达」。V1 只修了第一种表示。

**守卫挂在路由器上，文件在插件里开。**  
Fastify 路由守卫跑在静态 handler 之前、针对原始 URL。把授权放在 `allowedPath(normalized)` 才能和 open 对齐。

**金丝雀在守卫前缀下、静态根内是有意的。**  
读到它不证明任意文件读取，只证明路由守卫被绕过。advisory 也把影响范围写成 route-guard bypass。

**路由参数会吃掉一段 `..`。**  
10.1.1 的测试 `/app/:version` + `/app/../deep/...` 表明：前缀 matcher 按 `:` 段跳过一个路径段，`..` 可能在「前缀之内」被消费，suffix 里看不到 leading `..`，send 的「前导穿越」检查也不触发。所以 V2 必须在 **decode 后的完整 URL path** 上测 `dotDotSegmentRegex`，而不是只看切下来的 suffix。V1 的 `getPathnameForSend` 只 decode suffix，连这个完整 URL 都没看。

V1 切前缀之后只做：

```js
    try {
      return decodeURI(pathname)
    } catch {}
```

10.1.1 在 decode 全 URL path 和 decode suffix 之后各做一次「非前导 `..` → null/403」。本 case 的 residual `/static/foo/../secret/canary.txt` 不涉及 `:param`，完整 path 和 suffix 都含 `foo/../`，两处检查任意一处就能挡；V1 两处都没有。

`pumpSendToReply` 把 `pathnameForSend` 交给 `@fastify/send`。send 内部 `path.normalize` 会把 `foo/../secret/canary.txt` 收成 `secret/canary.txt`，再与 `root` join。规范化后的绝对路径仍以静态 root 为前缀，send 自己的「逃出 root」检查因此返回允许。V1 的不完整在于：路由守卫看的是未折叠的 `foo/../secret`，send 看的是折叠后的 `secret`。两者中间没有把「折叠后是否仍落在被守卫的前缀上」再问一遍路由器。

---

## 版本、入口、参考

| | tag | `%2F` seed | `foo/../secret` residual | `getPathnameForSend` |
|---|---|---|---|---|
| V0 | 9.1.0 | 200 + FLAG | （亦可，非本 seed） | 无，用 params['*'] |
| V1 | 10.1.0 | 404 | 200 + FLAG | decodeURI only |
| V2 | 10.1.1 | 挡 | 403 | 拒非前导 `..` |

- Web：`GET /static/secret%2Fcanary.txt`（seed）/ `GET /static/foo/../secret/canary.txt`（residual），端口 3000
- 认证（本平台）：v0 seed 观察到 flag；v1 seed 未观察到；v1 residual 观察到。
- 应用侧守卫：`/static/secret/*` → 403；静态 root 内含 `secret/canary.txt`。
- 残余 path 写死为 `/static/foo/../secret/canary.txt`（与 GHSA 示例同一形态）。
- [CVE-2026-15074](https://nvd.nist.gov/vuln/detail/CVE-2026-15074) / [GHSA-83w8-p2f5-377r](https://github.com/fastify/fastify-static/security/advisories/GHSA-83w8-p2f5-377r)
- 前置：CVE-2026-6414 / GHSA-x428-ghpx-8j92
- 官方 tag：`https://github.com/fastify/fastify-static/tree/v10.1.0` 与 `v10.1.1`
- 源码函数：`index.js` 的 `getPathnameForSend`、`pumpSendToReply`、wildcard `handler`
