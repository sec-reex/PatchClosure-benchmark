# @fastify/static `allowedPath`：`..` 拦住了，`/.` 还在规范化前面

- Case：`PCBV2-0109`（legacy `fastify-static-cve-2026-7120`）
- 产品：npm `@fastify/static`。本 case 用真实 Fastify + 发布包，`allowedPath` 对以 `/private/` 开头的 pathname 返回 404；金丝雀在 `/data/root/private/canary.txt`。
- 链：CVE-2026-15074 / GHSA-83w8-p2f5-377r（10.1.0 → 10.1.1，非前导 `..` 当 403）→ CVE-2026-7120 / GHSA-8pvw-jcv7-9cmj（10.1.1 → 10.1.2，先 `path.posix.normalize` 再调 `allowedPath`）
- 源码对着 GitHub tag `v10.1.1` 的 `index.js`：`pumpSendToReply`、`getPathnameForSend`、`dotDotSegmentRegex`。运行时装的是发布包本身。

2026 年 7 月，10.1.1 修了「`/foo/../private/...` 匹配到静态 catch-all，send 再把 `..` 塌掉」的路由守卫绕过。同一天 GHSA-8pvw-jcv7-9cmj 写明：*`@fastify/static` evaluates the `allowedPath` callback before normalizing dot segments and duplicate slashes*。NVD CVE-2026-7120 映射 CWE-180（先验证后规范化）。

根因不只是「少处理一种点段」。检查插在「用户字符串长什么样」这一层；真正打开文件的是 `@fastify/send` 的 `path.normalize`。V1 只把非前导 `..` 收成 403，没有把 `allowedPath` 看到的串变成磁盘将看到的串。下面按请求走进去、10.1.1 改了哪几行、send 怎么塌路径、normalize 谓词挂在哪，把这几层写完。

---

## 这块功能本来在干什么

插件把 URL 前缀下的文件从 `root` 目录送出去。应用用 `allowedPath(pathname, root, request)` 当安全边界：某些子树对静态通道不可见，必须 404。本 case：

```javascript
allowedPath: (pathname) => !pathname.startsWith('/private/')
```

一次典型合法请求：

```http
GET /static/public/readme.txt
```

`getPathnameForSend` 去掉前缀，得到 `/public/readme.txt`，`pumpSendToReply` 把它交给 `send(request.raw, encodeURI(pathname), { root })`。设计意图：`pathname` 就是将要读的相对路径，`allowedPath` 看到的和磁盘看到的是同一条。成功穿越之后的效果是：**过滤器认为路径不在 `/private/` 下，send 规范化之后读到了 `private/canary.txt`**，body 里出现 `PCBFLAG_...`。

数据流：

```text
HTTP GET /static/<rest>
    → find-my-way 匹配静态 catch-all（不规范化 .. 和 .）
    → getPathnameForSend(req.raw.url, prefix)     # 去掉 /static
    → pumpSendToReply(..., pathname, root)
         V1：若 pathname 含非前导 `..` → 403          ← CVE-2026-15074 插在这里
         allowedPath(pathname, root, request)         ← 仍看原始串
         send(..., pathname)                          ← path.normalize 后再读盘
    → 文件内容进 HTTP body
```

没有登录。判断完全信任 `allowedPath` 对原始 pathname 的前缀比较。

---

## 原始漏洞：非前导 `..`（CVE-2026-15074，@fastify/static 10.1.0）

10.1.0 的 `pumpSendToReply` 把用户 pathname 直接交给 `allowedPath` 再交给 send。`find-my-way` 匹配时不折叠 `..`，所以：

```text
GET /static/foo/../private/canary.txt
```

不会命中「只保护 `/private/*`」的路由中间件（如果应用是那样挂的），而是命中静态 `*`。pathname = `/foo/../private/canary.txt`。`allowedPath` 的 `startsWith('/private/')` 为假。`@fastify/send` 在自己的穿越守卫之前做 `path.normalize`，`/foo/../private/canary.txt` 变成 `/private/canary.txt`，文件被读出。

Snyk / GHSA-83w8-p2f5-377r：非前导 `..` 和 `%2E%2E` 活过 decodeURI 往返，再被 send 塌掉。本 case 的 seed 用明文 `..`：

```text
path = /static/foo/../private/canary.txt
```

10.1.0 返回 200 + flag。注意：更早的 CVE-2026-6414 / `getPathnameForSend` 管的是 `%2F` 编码斜杠；15074 是它没覆盖的 `..` 形态。本 case V0 钉在 10.1.0，seed 是 `..` 而不是 `%2F`。

---

## 维护者改了什么（CVE-2026-15074 修复，10.1.1）

tag `v10.1.1` 在 `allowedPath` **之前**加了对非前导 `..` 的拒绝：

```javascript
// index.js :: pumpSendToReply  (github.com/fastify/fastify-static tag v10.1.1)
async function pumpSendToReply (request, reply, pathname, rootPath, ...) {
  const pathnameOrig = pathname
  const options = Object.assign({}, sendOptions, pumpOptions)
  // ... root ...

  // @fastify/send rejects leading ".." segments, but it normalizes
  // non-leading ones away before its guard runs.
  if (dotDotSegmentRegex.test(pathname) && !leadingDotDotSegmentRegex.test(pathname)) {
    return reply.send(forbiddenPathError())
  }

  if (allowedPath && !allowedPath(pathname, options.root, request)) {
    return reply.callNotFound()
  }

  let pathnameForSend = pathname
  // ...
  } = await send(request.raw, encodeURI(pathnameForSend), options)
```

注释已经承认：send 会把非前导 `..` 在自己的守卫之前规范化掉。V1 的对策是：**看见这种 `..` 就 403**，不要交给 send。

对 seed：

```text
pathname = /foo/../private/canary.txt
dotDotSegmentRegex 命中，且不是 leading `..`
→ forbiddenPathError() → 403
```

这就是 v1 + `--seed` 退出码 10。`allowedPath` 根本没被问到。

补丁默认了两件事：

1. 危险路径长得像「中间有 `..` 段」。
2. 没有 `..` 的 pathname 就是磁盘路径，`allowedPath` 拿原始串做前缀判断是安全的。

第二点不成立。`.` 段、重复斜杠同样会被 `path.normalize` / `path.posix.normalize` 吃掉，且 **V1 的正则不认它们**。

---

## 检查之后，谁真正消费那个 pathname

`allowedPath` 一通过，`pathnameForSend` 仍是用户串，交给 `send(..., encodeURI(pathnameForSend), { root })`。`@fastify/send` 内部 `path.normalize`：

```text
/./private/canary.txt  →  /private/canary.txt
//private/canary.txt   →  /private/canary.txt
```

然后按 root + 规范化路径 `createReadStream`。过滤器刚看过的是「原始字符串是否以 `/private/` 开头」；open 看到的是规范化后的绝对路径。两套语义中间没有第二次谓词。

`getPathnameForSend` 只做前缀剥离和 decodeURI，不做 dot-segment 折叠。V1 没有 `normalizeRequestPathname`。

---

## 仓库里已经有更强的检查，allowedPath 没用

V1 自己写了注释：send 会 normalize。它选择「禁止一种会被 normalize 改变的写法（`..`）」，而不是「先 normalize 再判断」。Node 的 `path.posix.normalize` 已经能同时处理 `.`、`..`、`//`。

同一函数稍后把**未规范化**的串传给 send——send 才是真正的消费者。把 `allowedPath` 接到 `path.posix.normalize(pathname)` 上，是 10.1.2 才做的事。不是仓库里没有规范化原语，是 **allowedPath 的入参没用上**。

即便没有 `/./`，`//private/canary.txt` 同样 `startsWith('/private/') === false`，normalize 后仍落在 private 下。GHSA-8pvw-jcv7-9cmj 把 `//file`、`/./file`、`/public/../private/file` 并列。V1 只挡住了第三种里带 `..` 的那支。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs open」落到具体代码：

- `dotDotSegmentRegex.test(pathname)`：看有没有 `..` 段
- `allowedPath(pathname)`：看原始串是否以 `/private/` 开头
- `send` 的 `path.normalize`：看点段和重复斜杠塌完之后是哪条路径

只要构造一种输入，使「没有 `..`」且「原始串不以 `/private/` 开头」，但规范化后是 `/private/canary.txt`，前两行放行，第三行读到金丝雀。

`/static/./private/canary.txt` 就是这样来的：

```text
getPathnameForSend → pathname = /./private/canary.txt
dotDotSegmentRegex 不命中（没有 ..）
allowedPath('/./private/canary.txt')
  startsWith('/private/') = false  → 放行
send normalize → /private/canary.txt
root + 该路径 → /data/root/private/canary.txt
body = PCBFLAG_...
```

字符串变换：用户多写了一段 `/.`。`allowedPath` 做的是字面前缀，不是路径前缀。token `/private/canary.txt` 还在；它前面多了 `/.`，刚好让 `startsWith` 失败。

平台 `verify.sh --residual` 写死 `path=/static/./private/canary.txt`，与 heldout 一致，仍是同一 `pumpSendToReply` → `send` sink。

---

## 残余仍然走同一条静态文件路径（CVE-2026-7120）

没有换插件、没有换 `allowedPath` 回调、没有换金丝雀文件。还是：

```http
GET /static/./private/canary.txt
```

（客户端必须 `--path-as-is`，否则 HTTP 库会先把 `/.` 清掉。）

`pumpSendToReply` 仍然先跑 V1 的 `..` 检查（这次不触发），再跑 `allowedPath`（这次放行），再 `send`（这次读到 private）。认证：v1 + `--residual` 200，body 中观察到 flag。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：V1 只封了 `..` 这一种会被 normalize 改变的写法；`allowedPath` 看的是规范化前的串；真正 open 发生在检查之后。seed 被挡住只说明「非前导 `..` 没了」，不说明「不能再让 allowedPath 与磁盘路径说的不是同一句话」。

---

## 后来又补了什么（CVE-2026-7120，10.1.2）

10.1.2（本 case `patch.diff`）在 `allowedPath` 前引入：

```javascript
function normalizeRequestPathname (pathname) {
  if (!pathname.startsWith('/')) {
    return pathname
  }
  return path.posix.normalize(pathname)
}

const normalizedPathname = normalizeRequestPathname(pathname)
if (allowedPath && !allowedPath(normalizedPathname, options.root, request)) {
  return reply.callNotFound()
}
```

对残余：`/./private/canary.txt` → `/private/canary.txt` → `startsWith('/private/')` 为真 → 404。`..` 种子同样先变成 `/private/...` 再被拒；V1 的 403 特判不再是唯一闸。公开建议升级到 10.1.2。NVD：绕过本身不让你逃出 `root`，只打败基于路径的过滤。

即便如此，若 `allowedPath` 自己再做一次不规范的字符串比较，或 send 与 `path.posix.normalize` 对 Windows 分隔符不一致，需要另证。本 benchmark 的 v2 只关闭 `/./` 这条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是「禁止一种 send 会塌掉的写法」。真正读盘的是 send 规范化后的路径。V2 才把 `allowedPath` 的入参改成规范化结果，让两层说同一种语言。

**不是没有更好的谓词。**  
注释已经指向 send 的 normalize。`path.posix.normalize` 在 Node 里现成。V1 选择枚举 `..`，而不是接到 normalize 上。从 V1 的 diff 只能看到多了一个 regex；要判断补丁是否闭合，必须看到 `allowedPath` 的实参和 send 的实参是不是同一条串。

**同一函数、同一 `pathname`，只换了点段种类。**  
`/.`、`//`、`/foo/../` 在 POSIX 规范化下是一家。只修 `..` 会留下 `.` 和重复斜杠。

**先验证后规范化。**  
`allowedPath` 若被当成 ACL，就必须看 canonical 路径。V1 把 ACL 放在 canonicalize 前面，CWE-180 的字面意思。

**金丝雀在 denied 子树里是有意的。**  
文件仍在 `root` 下，所以 send 的穿越守卫不会拦。能读到它，说明失败的是应用自己的 `allowedPath` 前缀策略，不是「逃出了静态根」。

---

## 版本、入口、参考

| | npm | `pumpSendToReply` | `allowedPath` 入参 | `foo/../private` seed | `./private` residual |
|---|---|---|---|---|---|
| V0 | 10.1.0 | 无 `..` 特判 | 原始串 | send 塌 `..`，200 flag | 同样 200 |
| V1 | 10.1.1 | 非前导 `..` → 403 | 仍是原始串 | 403 | `/.` 放行，200 flag |
| V2 | 10.1.2 | `normalizeRequestPathname` 后再 `allowedPath` | 规范化串 | 404 | 404 |

- Web：`GET /static/foo/../private/canary.txt`、`GET /static/./private/canary.txt`（`--path-as-is`）
- 认证（本平台）：v0 seed 观察到 flag；v1 seed 未观察到；v1 residual 观察到。
- [CVE-2026-15074](https://github.com/advisories/GHSA-83w8-p2f5-377r)、[GHSA-83w8-p2f5-377r](https://github.com/advisories/GHSA-83w8-p2f5-377r)
- [CVE-2026-7120](https://nvd.nist.gov/vuln/detail/CVE-2026-7120)、[GHSA-8pvw-jcv7-9cmj](https://github.com/fastify/fastify-static/security/advisories/GHSA-8pvw-jcv7-9cmj)
- 源码：`https://github.com/fastify/fastify-static/blob/v10.1.1/index.js`、compare `v10.1.1...v10.1.2`
