# follow-redirects：scheme 会剥 Authorization，正则仍不认识 Proxy-Authorization

- Case：`PCBV2-0070`
- 产品：npm `follow-redirects`（Node `http`/`https` 的 redirect 封装；axios 的传输层）
- 链：CVE-2022-0536（1.14.7 → 1.14.8，commit `62e546a` *Drop confidential headers across schemes*）→ CVE-2024-28849 / GHSA-cxjh-pqwp-8mfp（→ 1.15.6，正则扩到 `(?:proxy-)?authorization`）
- 源码对着 npm / GitHub tag `v1.14.8` 的 `index.js`：`RedirectableRequest._processResponse`、`removeMatchingHeaders`。运行时是发布包本身，client 对真实 HTTP 302 链发请求。

2022 年 2 月 8 日，1.14.8 把「剥机密头」的触发从「换了 host」扩成「换了 scheme **或** 换了 host」。这挡住了 `https://victim` → `http://victim` 时仍转发 `Authorization` 的明文泄漏。两年后 GHSA-cxjh-pqwp-8mfp 原文：*follow-redirects only clears authorization header during cross-domain redirect, but keep the proxy-authentication header which contains credentials too*。NVD CVE-2024-28849 固定版本 1.15.6。

根因不只是「正则少写了一个名字」。检查插在「这次 302 算不算跨源」这一层；真正发出第二跳的是同一份 `this._options.headers`。同一次 `removeMatchingHeaders` 已经会删 `authorization` 和 `cookie`，RFC 7235 里同属凭证的 `Proxy-Authorization` 却不在正则里。下面按 302 走进去、1.14.8 改了哪几行、剥完之后谁把剩下的头发走、更宽的头表有没有挂上，把这几层写完。

---

## 这块功能本来在干什么

`follow-redirects` 对 3xx + `Location` 自动再请求。浏览器对跨源 redirect 会丢掉 `Authorization`；这个库给 Node 用，自己实现那份剥离。

设计意图：换到另一个 origin 时，不要把登录凭证带到新主机。本 case 的 seed 是 **同 host、降 scheme**（https→http）；residual 是 **同 scheme、换 host**。金丝雀是客户端在敏感头里放的 `Basic ${PCB_FLAG}`。collector sidecar 回显它**实际收到的**请求头；flag 出现 ⇒ 头没被剥。

数据流：

```text
client follow-redirects.get(url, { headers: { Authorization 或 Proxy-Authorization: Basic FLAG } })
    → 第一跳 200/302
    → _processResponse
         解析 Location
         V0：仅当 host 不同才 removeMatchingHeaders(/^(?:authorization|cookie)$/i)
         V1：scheme 不同 或 host 不同 才跑同一正则     ← 补丁只改了 if
         V2：if 再整理；正则变成 /^(?:(?:proxy-)?authorization|cookie)$/i
         用（可能已剥过的）headers 发第二跳
    → collector echo 收到的头
```

没有登录。判断完全信任「触发条件 + 正则 ⇒ 凭证不会过网」；不信任下一跳服务器看到的原始头名字。

本 case 的 client 是 `docker compose run` 起来的 Node 进程，对 compose 网上的真实 `victim` / `redirector` / `attacker` HTTP 服务发请求（`run_mode` 是库客户端，不是入站 HTTP）。flag 从不进库源码，只在 probe 时写入请求头。collector 的 echo 是唯一观察通道。

`isSameOrSubdomain`（V1 用来判断 host 维）只做字符串后缀：

```javascript
// index.js  (tag v1.14.8)
function isSameOrSubdomain(subdomain, domain) {
  if (subdomain === domain) {
    return true;
  }
  const dot = subdomain.length - domain.length - 1;
  return dot > 0 && subdomain[dot] === "." && subdomain.endsWith(domain);
}
```

`victim` → `victim` 为真，所以 seed 全靠 **protocol !==** 那一维开火。`redirector` → `attacker` 为假，residual 靠 host 维开火。两条都能进 `removeMatchingHeaders`，之后只剩正则决定删谁。

---

## 原始漏洞：同 host 降 scheme 不剥头（CVE-2022-0536，1.14.7）

1.14.7 只在 **host 不同**（且不是子域）时剥头，不管 scheme：

```javascript
// index.js :: _processResponse  (v1.14.7，patch.diff 记录)
    // Drop the confidential headers when redirecting to another domain
    if (!(redirectUrlParts.host === currentHost || isSubdomainOf(redirectUrlParts.host, currentHost))) {
      removeMatchingHeaders(/^(?:authorization|cookie)$/i, this._options.headers);
    }
```

huntr / GHSA-pw2r-vq6v-hr8c / NVD CVE-2022-0536：*Improper Removal of Sensitive Information*，修复 1.14.8。https 页 302 到 `http://<同一 host>/...` 时 host 字符串相同，if 为假，`Authorization: Basic FLAG` 明文落到 http collector。

本 case seed：`https://victim/redir` → `302 Location: http://victim/collect`，头是 `Authorization: Basic <PCB_FLAG>`。V0 上 collector 回显含 flag。这是 dossier 记录的一次真实 compose gate（**本分析未重新 compose**）。

（1.14.7 相对更早版本已经把 Cookie 加进正则，并在跨 host 时剥 Authorization；CVE-2022-0536 补的是 **scheme 维**，不是第一次发明剥离。）

---

## 维护者改了什么（CVE-2022-0536 修复，1.14.8）

commit `62e546a99c07c3ee5e4e0718c84a6ca127c5c445`。对着 GitHub tag `v1.14.8` 原文：

```javascript
// index.js :: RedirectableRequest.prototype._processResponse  (tag v1.14.8)
    // Drop confidential headers when redirecting to another scheme:domain
    if (redirectUrlParts.protocol !== currentUrlParts.protocol ||
       !isSameOrSubdomain(redirectUrlParts.host, currentHost)) {
      removeMatchingHeaders(/^(?:authorization|cookie)$/i, this._options.headers);
    }
```

`removeMatchingHeaders` 按**头名字**测正则，命中则 `delete headers[header]`：

```javascript
function removeMatchingHeaders(regex, headers) {
  var lastValue;
  for (var header in headers) {
    if (regex.test(header)) {
      lastValue = headers[header];
      delete headers[header];
    }
  }
  ...
}
```

对 seed 这种 https→http、host 仍是 `victim` 的 302，它确实够用：`protocol !==` 为真，正则吃掉 `Authorization`，第二跳 collector 看不到 Basic FLAG。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险泄漏长得像「换 scheme（或换 host）时还带着 Authorization/Cookie」。
2. 只要 if 在跨 scheme / 跨 host 时开火，机密头就会被剥光。

第二点不成立。if 开火之后，正则仍是 `authorization|cookie`。`Proxy-Authorization` 不匹配（`proxy-authorization` 以 `proxy-` 开头）。跨 **host** 的 302 会进这个 if，但 `Proxy-Authorization: Basic FLAG` 原样留在 `this._options.headers` 里，随第二跳发到另一个域。

RFC 7235 把 `Proxy-Authorization` 和 `Authorization` 都定义为携带凭证。axios 用户经常两套头一起设。GHSA 报告者的最小例子就是同时带 `Authorization` 和 `Proxy-Authorization`，跨域后前者没了、后者还在。

Node 的 `http.request` 把头名写成 `proxy-authorization`（小写）发出去；collector 回显也是这个名字。正则带 `/i`，所以大小写不是缺口。`removeMatchingHeaders` 返回被删掉的最后一个值（给内部用），删不中时 `Proxy-Authorization` 仍是 `this._options.headers` 上的一个键。第二跳 `_performRequest` 把整个 headers 对象交给 `http.request`，没有再过一遍名字表。

huntr / Snyk 对 CVE-2022-0536 的描述停在「http 降级时 Authorization 泄漏」。读 1.14.8 的 commit message（*Drop confidential headers across schemes*）会以为 confidential 集合已经闭合。真正的集合字节在 `removeMatchingHeaders` 的第一个参数里，那次 commit 没动它。CVE-2024-28849 的 GHSA-cxjh-pqwp-8mfp 才第一次把 `proxy-authentication header which contains credentials too` 写进咨询。

---

## 检查之后，谁真正发出第二跳

if 块一结束（无论删没删头），`_processResponse` 立刻 `_performRequest()`，用**同一份** `this._options`（含 headers）建下一跳 native `http.request` / `https.request`。没有第二份「机密头表」。collector 看到的就是 Node 实际写出的请求头。

过滤器刚看过的是「scheme/host 变了没有」；正则看的是头名字字符串。`Proxy-Authorization` 在触发条件已经为真时仍然过网。flag 出现在 collector echo 里，依据就是这次真实跨容器 HTTP，而不是库在日志里打印了 FLAG。

---

## 仓库里已经有更强的检查，正则没用上

同一函数已经：

- 知道有一类头叫 confidential，要用 `removeMatchingHeaders` 删
- 已经列出 `authorization` 和 `cookie`
- **没有**列出 RFC 里另一个凭证头 `Proxy-Authorization`

`removeMatchingHeaders` 对大小写不敏感（`/i`），所以 `ProXy-AuthoriZation` 只要进了正则就会删。缺口不是大小写，是 **名字根本不在交替支里**。

谁在跨源时被剥（V1）：

| 头 | `/^(?:authorization|cookie)$/i` |
|---|---|
| Authorization | 是 |
| Cookie | 是 |
| Proxy-Authorization | **否** |
| 自定义 `X-API-Key` 等 | 否（那是后来 GHSA-r4q5-vmmm-2653 / 1.16.0 的另一条链） |

不是没有「按名字删头」的原语，是 **1.14.8 只改了 if，没改正则**。从 `v1.14.7...v1.14.8` 的 compare 可以看见：`removeMatchingHeaders(...)` 那一行的正则字节级不变，只改了上面的条件。

---

## 这个补丁挡住了什么、没挡住什么

```text
seed:
  Authorization: Basic FLAG
  https://victim/redir → 302 http://victim/collect     同 host，换 scheme
  V0: if 为假（只看 host）→ 头留下 → http collector 有 FLAG
  V1: protocol !== 为真 → 正则删 Authorization → collector 无 FLAG

residual:
  Proxy-Authorization: Basic FLAG
  http://redirector/redir → 302 http://attacker/collect  换 host，同 scheme
  V1: host 不同 → if 为真 → 正则不认 proxy-authorization → attacker collector 有 FLAG
```

token 变换：把凭证从 `Authorization` 换到 `Proxy-Authorization`，把 302 从「同 host 降 scheme」换成「跨 host」。触发条件在 V1 上对两条都会开火（residual 靠跨 host）；只有正则决定删谁。seed 被挡住只说明「Authorization 在跨 scheme 时没了」，不说明「凭证头都不会过跨源 302」。

---

## 残余仍然走同一条 _processResponse 剥离（CVE-2024-28849）

没有换库、没有换 302 处理函数。还是 axios/follow-redirects 的自动跟随：

```text
GET http://redirector/redir
Proxy-Authorization: Basic PCBFLAG_...
→ 302 Location: http://attacker/collect
→ 第二跳把同一头带到 attacker
```

held-out 把 candidate 写死为这条。GHSA-cxjh-pqwp-8mfp 的推荐补丁就是把正则改成显式包含 `proxy-authorization`（发布时写成 `(?:proxy-)?authorization`）。认证记录：v1 + residual collector 回显 `proxy-authorization: Basic PCBFLAG_...`。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：if 扩了、正则没扩；第二跳使用剥完之后仍留下的 headers；RFC 里另一个凭证头从未进表。

---

## 后来又补了什么（CVE-2024-28849，1.15.6）

1.15.6 把正则扩成 `/^(?:(?:proxy-)?authorization|cookie)$/i`，并顺带整理了「降到非 https / 换域」的 if。GHSA 建议升级到 1.15.6。报告者给的推荐补丁是显式 `|proxy-authorization`；发布版写成 `(?:proxy-)?authorization`，对 `Proxy-Authorization` 等价。

```javascript
// index.js :: _processResponse  (v1.15.6，patch.diff / GHSA-r4q5 后续引用)
    if (redirectUrl.protocol !== currentUrlParts.protocol &&
       redirectUrl.protocol !== "https:" ||
       redirectUrl.host !== currentHost &&
       !isSubdomain(redirectUrl.host, currentHost)) {
      removeMatchingHeaders(/^(?:(?:proxy-)?authorization|cookie)$/i, this._options.headers);
    }
```

（V2 的 if 还把「升到 https」从剥头条件里拿掉，避免 1.14.8 那种同域 http→https 误伤 Authorization 的兼容问题，见 issue #192。residual 是跨 host 的 http→http，不依赖这一维。）

对残余输入：跨 host 时 if 为真，正则现在匹配 `proxy-authorization`，头被 delete，attacker collector 没有 FLAG。

即便如此，这仍然是「名字白名单式的删头」。自定义 `X-API-Key` 在 1.15.6 仍会过跨域 302（GHSA-r4q5-vmmm-2653，1.16.0）。本 benchmark 的 v2 只关闭 Proxy-Authorization 这一条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是「什么时候剥」。真正泄漏的是「剥哪些名字」。V2 才动正则。从 1.14.7→1.14.8 的 diff 只能看到 if；要判断补丁是否闭合，必须看到 `removeMatchingHeaders` 的正则字节没变。

**不是没有更好的谓词。**  
同一函数已经剥 `authorization`。RFC 7235 的 `Proxy-Authorization` 是对称的。把它加进交替支是一行。

**同一 `_processResponse`、同一 `removeMatchingHeaders`，只换了头名字和 302 的哪一维。**  
seed 打 scheme 维 + Authorization；residual 打 host 维 + Proxy-Authorization。V1 的 if 两条都会进，正则只覆盖第一条的头。

**触发条件和头集合是两个独立的开关。**  
只拧其中一个，另一个缺口仍在。1.14.8 拧了前者。

**金丝雀在请求头里、由对端 echo 是有意的。**  
collector 看到 FLAG 说明第二跳真的带上了凭证，不是客户端本地变量。V1 上 seed 的 Authorization 已被 delete，所以同一 collector 对 seed 看不到 FLAG、对 residual 看得到——差别只在头名字是否匹配那条 2017 年起就几乎没动过的正则。

---

## 版本、入口、参考

| | follow-redirects | 触发 if | 剥离正则 | https→http Authorization seed | 跨 host Proxy-Authorization residual |
|---|---|---|---|---|---|
| V0 | 1.14.7 | 仅跨 host | `authorization\|cookie` | collector 有 flag | （不必；同样泄漏） |
| V1 | 1.14.8 | 跨 scheme **或** 跨 host | 同上，未改 | 头被剥 | collector 有 flag |
| V2 | 1.15.6 | 再整理 | `(?:proxy-)?authorization\|cookie` | 挡 | 头被剥 |

- 触发：Node client 跟随真实 302（victim/redirector → collector）
- 认证记录（dossier）：v0 seed 泄漏；v1 seed 不泄漏；v1 residual 泄漏；v2 residual 不泄漏。本分析未重新 compose。
- axios 用户往往间接依赖 follow-redirects；咨询要求把传递依赖升到 ≥1.15.6。1.15.4/1.15.5 仍带旧正则（**推断自 changelog / GHSA 固定版本**，未逐 tag 再 clone）。
- [CVE-2022-0536](https://nvd.nist.gov/vuln/detail/CVE-2022-0536) / [GHSA-pw2r-vq6v-hr8c](https://github.com/advisories/GHSA-pw2r-vq6v-hr8c)
- [CVE-2024-28849](https://nvd.nist.gov/vuln/detail/CVE-2024-28849) / [GHSA-cxjh-pqwp-8mfp](https://github.com/follow-redirects/follow-redirects/security/advisories/GHSA-cxjh-pqwp-8mfp)
- V1 源码：[tag v1.14.8 `index.js`](https://github.com/follow-redirects/follow-redirects/blob/v1.14.8/index.js) `_processResponse`
- V1 commit：[62e546a](https://github.com/follow-redirects/follow-redirects/commit/62e546a99c07c3ee5e4e0718c84a6ca127c5c445)
- compare：[v1.14.7...v1.14.8](https://github.com/follow-redirects/follow-redirects/compare/v1.14.7...v1.14.8)（正则那一行未改）
- V2 源码：[tag v1.15.6 `index.js`](https://github.com/follow-redirects/follow-redirects/blob/v1.15.6/index.js)
- issue [#192](https://github.com/follow-redirects/follow-redirects/issues/192)（V2 调整「升 https 是否剥头」）
- huntr CVE-2022-0536 披露页（scheme 维；不含 Proxy-Authorization）
- 后续另一条链：[GHSA-r4q5-vmmm-2653](https://github.com/advisories/GHSA-r4q5-vmmm-2653)（自定义头，1.16.0；不是本 residual）
- 本 case 未改 case.yaml / compose / verify；gate 数字来自 dossier，标为 observed。
