# Vite：`rawRE` 只认 `raw` 在 query 末尾，`?raw?import` 从旁边走过去

- Case：`PCBV2-0003`
- 产品：Vite 开发服务器（本 case `npm i vite@5.4.14/5.4.15/5.4.16`，`vite --host`，金丝雀在项目根外的 `/canary.txt`）
- 链：CVE-2025-30208（≤5.4.14 → 5.4.15）→ CVE-2025-31125（≤5.4.15 → 5.4.16）
- 源码对着 `v5.4.15` / `v5.4.16` 的 `packages/vite/src/node/server/middlewares/transform.ts`、`utils.ts` 的 `rawRE` / `urlRE` / `importQueryRE`、`static.ts` 的 `ensureServingAccess`。运行时是整份 Vite dev server，不是抽出来的函数。

`/@fs/` 本来拒绝 allow list 以外的文件。CVE-2025-30208 发现 `?import&raw??` 这种拖尾分隔符让 `rawRE` 配不上，fs 检查被跳过，raw 插件照样读盘。5.4.15 先剥掉末尾的 `?`/`&` 再测正则。GHSA-4r4m-qw57-chr8 一周后写明：*content of non-allowed files is exposed using `?raw?import`*。同一条 transform 中间件，只是 `raw` 后面换成了另一个 query。

根因不只是「忘了 `?import`」。检查插在「URL 像不像 `(?|&)raw(?:&|$)`」上；真正 `fs.readFile` 的是后面的 `transformRequest` + raw 插件。`ensureServingAccess` 已经存在，V1 只在正则命中时才调用。下面按请求走进去。

---

## 这块功能本来在干什么

Vite dev server 把源文件变成浏览器能 import 的模块。`/@fs/<绝对路径>` 是「从文件系统根读文件」的内部 URL。`server.fs.strict`（默认开）用 allow / deny 限制能读的目录；项目根以外默认 403。

`?raw` 让 Vite 把文件当字符串模块返回：

```js
export default "<file contents>\n"
```

一次典型请求：

```http
GET /@fs/canary.txt?import&raw?? HTTP/1.1
```

数据流（5.4.15，本 case 的 V1）：

```text
GET /@fs/canary.txt?...
    → viteTransformMiddleware
         url = decodeURI(removeTimestampQuery(req.url))
         urlWithoutTrailingQuerySeparators = url.replace(/[?&]+$/, '')
         if (rawRE.test(stripped) || urlRE.test(stripped))
             && !ensureServingAccess(stripped, ...)
                 return 403          ← V1 补丁插在这里
         if (isJSRequest || isImportRequest || ...)
             url = removeImportQuery(url)
             transformRequest(url)   ← raw 插件 fs.readFile，不再做 fs.allow
             send(result.code)
    → 若 transform 没接手：
         serveRawFsMiddleware
             对 /@fs/ 调 ensureServingAccess 后 sirv 读盘
```

设计意图：只要这次响应会把文件内容交出去（raw / url），就必须先过 `ensureServingAccess`。成功穿越之后的效果是**读出项目根以外的文件，并以 `export default "..."` 出现在 body 里**。本 case 金丝雀在 `/canary.txt`；明文 `GET /@fs/canary.txt` 三条版本都是 403。

---

## 原始漏洞：拖尾 `?` 让 `rawRE` 配不上（CVE-2025-30208，5.4.14）

5.4.14 的 `rawRE` / `urlRE` 定义在 `utils.ts`，5.4.15 没改这两行：

```ts
// packages/vite/src/node/utils.ts  (v5.4.15，与 5.4.14 相同)
export const urlRE = /(\?|&)url(?:&|$)/
export const rawRE = /(\?|&)raw(?:&|$)/

const importQueryRE = /(\?|&)import=?(?:&|$)/
export const isImportRequest = (url: string): boolean => importQueryRE.test(url)
```

`rawRE` 要求 `raw` 后面立刻是 `&` 或结尾。`?import&raw??` 里 `raw` 后面是 `?`，配不上。5.4.14 的 transform 中间件**不剥拖尾分隔符**，直接 `rawRE.test(url)`：条件为假，`ensureServingAccess` 根本不跑。

但后面 `isImportRequest(url)` 为真（有 `?import`），于是走进 `transformRequest`。raw 插件按 query 把文件读出来，包成 `export default`。GHSA-x574-m823-4x7w 的例子是 `/@fs/tmp/secret.txt?import&raw??`。

本 case seed：

```text
GET /@fs/canary.txt?import&raw??
```

5.4.14 上 HTTP 200，body 里是 `export default "PCBFLAG_...\n"`。明文 `/@fs/canary.txt` 是 403，所以这不是「/@fs 本来就能读根外」，是 query 让 fs 检查没挂上。

---

## 维护者改了什么（CVE-2025-30208 修复，5.4.15）

5.4.15 只在调用 `rawRE` **之前**剥掉末尾的 `?`/`&`，然后把剥完的字符串交给原来的正则和 `ensureServingAccess`：

```ts
// packages/vite/src/node/server/middlewares/transform.ts
// transformMiddleware / viteTransformMiddleware  (v5.4.15)
const trailingQuerySeparatorsRE = /[?&]+$/
...
      const urlWithoutTrailingQuerySeparators = url.replace(
        trailingQuerySeparatorsRE,
        '',
      )
      if (
        (rawRE.test(urlWithoutTrailingQuerySeparators) ||
          urlRE.test(urlWithoutTrailingQuerySeparators)) &&
        !ensureServingAccess(
          urlWithoutTrailingQuerySeparators,
          server,
          res,
          next,
        )
      ) {
        return
      }
```

对 seed `?import&raw??`：

```text
剥拖尾后: /@fs/canary.txt?import&raw
rawRE /(\?|&)raw(?:&|$)/  →  命中（raw 在末尾）
ensureServingAccess('/@fs/canary.txt?import&raw')
  → isFileServingAllowed 对 /canary.txt 不在 allow list → 403
```

这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 让 `rawRE` 配不上的，只有末尾多余的 `?`/`&`。
2. 只要 `rawRE`/`urlRE` 配不上，这次请求就不会以 raw/url 方式把文件内容交出去，因此不必调 `ensureServingAccess`。

第二点不成立。raw 插件认的 query 形状比 `rawRE` 宽：`raw` 后面再跟 `?import` 仍然是 raw 转换。

---

## 消毒之后，谁真正读那个文件

`ensureServingAccess` 返回 true 或根本没被调用时，中间件继续：

```ts
      if (
        isJSRequest(url) ||
        isImportRequest(url) ||
        isCSSRequest(url) ||
        isHTMLProxy(url)
      ) {
        url = removeImportQuery(url)
        url = unwrapId(url)
        const result = await transformRequest(url, server, { ... })
        if (result) {
          return send(req, res, result.code, type, { ... })
        }
      }
```

`isImportRequest` 用的是另一张正则 `(\?|&)import=?(?:&|$)`。`?raw?import` 末尾是 `import`，这张正则命中。`transformRequest` 走插件管道；`?raw` 让 raw 插件 `fs.readFile` 目标文件，**不再问** `server.fs.allow`。

`serveRawFsMiddleware` 里对 `/@fs/` **每次**都调 `ensureServingAccess`。残余不走这条：transform 中间件先把它当模块转换吃掉了。

过滤器刚看过的是「剥拖尾之后像不像 `(?|&)raw(?:&|$)`」；open 看到的是 raw 插件的绝对路径。两套 query 语言中间没有第二次 fs 谓词。

---

## 仓库里已经有更强的检查，transform 没用上

`static.ts` 的 `ensureServingAccess` / `isFileServingAllowed` 是完整的 allow/deny 实现，`serveRawFsMiddleware` 对所有 `/@fs/` 都调用。transform 中间件却加了一道**门闩**：只有 `rawRE`/`urlRE` 说「这是 raw/url」才检查。

V1 没有改 `rawRE`。它仍然是：

```ts
export const rawRE = /(\?|&)raw(?:&|$)/
```

`(?:&|$)` 不承认 `raw` 后面是 `?`。同一文件里 `trailingSeparatorRE = /[?&]$/` 只剥**一个**末尾字符，给 `removeImportQuery` 用；V1 新增的 `trailingQuerySeparatorsRE = /[?&]+$/` 也只剥末尾，不改中间的 `?raw?import`。

更强的谓词已经有了两种写法：

- 对 `/@fs/` **总是** `ensureServingAccess`（`serveRawFsMiddleware` 就是这么干的）；
- 把 `rawRE` 改成 `/[?&]raw\b/`，不要求 `raw` 在 query 末尾。

V2 用的是第二种，并补上 `inlineRE`。不是仓库里没有 fs 检查，是 transform 入口的正则比 raw 插件窄。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「门闩正则 vs raw 插件」落到具体 query：

| URL 后缀 | 剥拖尾后 | `rawRE` `(?|&)raw(?:&|$)` | `isImportRequest` | V1 是否 403 |
|---|---|---|---|---|
| `?import&raw??` | `?import&raw` | 命中 | 命中 | 是（seed 被挡） |
| `?raw??` | `?raw` | 命中 | 否 | 是 |
| `?raw?import` | `?raw?import`（末尾不是 `?`/`&`） | **不命中**（`raw` 后是 `?`） | **命中** | 否 |

`?raw?import` 六个字符的关系：`raw` 和 `import` 之间是 `?`，不是 `&`。V1 当它不是 raw 请求，跳过 `ensureServingAccess`；`isImportRequest` 当它是 import，送进 `transformRequest`；raw 插件看到 `raw` 参数，读文件。

```text
输入:  /@fs/canary.txt?raw?import

剥 [?]&]+$ :  不变（结尾是 t）
rawRE:        失败
ensureServingAccess:  不调用
isImportRequest:      成功
transformRequest + raw 插件:
  export default "PCBFLAG_...\n"
```

GHSA-4r4m 还写了 `?inline&import`（双 base64）。本 case residual 用 `?raw?import`，token 直接出现在 body 里，不必解码。

---

## 残余仍然走同一条 `/@fs/` + raw 读文件路径（CVE-2025-31125）

没有换中间件、没有换金丝雀、没有换 `/@fs/`。还是：

```http
GET /@fs/canary.txt?raw?import HTTP/1.1
```

`viteTransformMiddleware` 照样跑；V1 那两行 `rawRE`/`urlRE` 照样测；测完认为不是 raw；`transformRequest` 仍然用 raw 插件读 `/canary.txt`；`send` 把 `export default "PCBFLAG_..."` 写进 body。

本 case residual candidate：

```text
PATH = "/@fs/canary.txt?raw?import"
```

和 GHSA-4r4m 的 *content of non-allowed files is exposed using `?raw?import`* 同一构造。认证：v1 + `--residual` 退出码 0；5.4.16 上 403。

seed 被挡住只说明「末尾多余 `?` 没了」，不说明「带 `raw` 的 `/@fs/` 都会先过 fs.allow」。

---

## 后来又补了什么（CVE-2025-31125，5.4.16）

5.4.16 不再从 `utils.ts` 进口那对「必须在末尾或 `&` 前」的正则，在 transform 中间件里换成词边界，并补上 `inline`：

```ts
// packages/vite/src/node/server/middlewares/transform.ts  (v5.4.16)
const trailingQuerySeparatorsRE = /[?&]+$/

// TODO: consolidate this regex pattern with the url, raw, and inline checks in plugins
const urlRE = /[?&]url\b/
const rawRE = /[?&]raw\b/
const inlineRE = /[?&]inline\b/
...
      if (
        (rawRE.test(urlWithoutTrailingQuerySeparators) ||
          urlRE.test(urlWithoutTrailingQuerySeparators) ||
          inlineRE.test(urlWithoutTrailingQuerySeparators)) &&
        !ensureServingAccess(
          urlWithoutTrailingQuerySeparators,
          server,
          res,
          next,
        )
      ) {
        return
      }
```

`?raw?import` 里 `[?&]raw\b` 命中 → `ensureServingAccess` → 403。`?inline&import` 同样被 `inlineRE` 拦住。

公开建议：升级到 5.4.16 / 6.0.13 / 6.1.3 / 6.2.4 / 4.5.11。且不要把 dev server `--host` 暴露到网上（两条 advisory 的前提）。

---

## 从这条链还能看出什么

**维护者改错了哪一层。**  
他们改的是「测 `rawRE` 之前先剥拖尾」。真正读盘的是 `transformRequest` 的 raw 插件。V2 仍在同一层加码（放宽正则），没有把 `/@fs/` 无条件接到已经存在的 `ensureServingAccess`。

**不是没有更好的谓词。**  
`ensureServingAccess` 完整可用。`serveRawFsMiddleware` 对 `/@fs/` 每次都调。transform 用正则当门闩，正则比插件认的 query 窄。从 V1 的 diff 只能看到 `trailingQuerySeparatorsRE`；要判断是否闭合，必须看到 `rawRE` 的 `(?:&|$)` 和 `isImportRequest` 的 `?import`。

**同一中间件、同一 `/@fs/`，只换了 query 里 `raw` 的邻居。**  
`raw` 后面是 `??` 被 V1 挡住；后面是 `?import` 就不是。

**金丝雀在项目根外是有意的。**  
明文 `/@fs/canary.txt` 三条版本 403。能读到它，说明 raw 插件打开的是 allow list 以外的路径。

---

## 版本、入口、参考

| | 版本 | transform 门闩 | `rawRE` | `?import&raw??` seed | `?raw?import` residual |
|---|---|---|---|---|---|
| V0 | 5.4.14 | 不剥拖尾，直接测 | `(\?|&)raw(?:&|$)` | 读到金丝雀 | （不必） |
| V1 | 5.4.15 | 先剥 `[?&]+$` 再测 | 同上 | 403 | 读到金丝雀 |
| V2 | 5.4.16 | 同上 + `inlineRE` | `/[?&]raw\b/` | 挡 | 403 |

- Web：`GET /@fs/canary.txt?import&raw??`（seed）；`GET /@fs/canary.txt?raw?import`（residual）
- 认证（本平台）：v0 seed 观察到 flag；v1 seed 403；v1 residual 观察到。
- [CVE-2025-30208](https://nvd.nist.gov/vuln/detail/CVE-2025-30208)、[CVE-2025-31125](https://nvd.nist.gov/vuln/detail/CVE-2025-31125)
- [GHSA-x574-m823-4x7w](https://github.com/advisories/GHSA-x574-m823-4x7w)（V1，`?raw??`）
- [GHSA-4r4m-qw57-chr8](https://github.com/vitejs/vite/security/advisories/GHSA-4r4m-qw57-chr8)（V2，`?raw?import` / `?inline&import`）
- V1 源码：[`transform.ts` @ v5.4.15](https://github.com/vitejs/vite/blob/v5.4.15/packages/vite/src/node/server/middlewares/transform.ts)、[`utils.ts` `rawRE`](https://github.com/vitejs/vite/blob/v5.4.15/packages/vite/src/node/utils.ts)
- V2 源码：[`transform.ts` @ v5.4.16](https://github.com/vitejs/vite/blob/v5.4.16/packages/vite/src/node/server/middlewares/transform.ts)
