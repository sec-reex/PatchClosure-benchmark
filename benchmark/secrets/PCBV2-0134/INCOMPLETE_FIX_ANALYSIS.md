# Koa `back()`：把 `startsWith('/')` 当成相对路径，`//host` 也算

- Case：`PCBV2-0134`
- 产品：npm `koa`（koajs）
- 链：CVE-2025-54420 / GHSA-jgmv-j7ww-jx2x（3.0.0 → 3.0.1）→ CVE-2025-62595 / GHSA-g8mr-fgfg-5qpc（3.0.1 → 3.0.3，commit `769fd75` / PR #1908）
- 源码对着 npm `koa@3.0.1` 的 `lib/response.js`：`back`、`redirect`（unpkg / GitHub tag `v3.0.1`）。运行时装的是发布包本身，应用只把 `ctx.response.back('/')` 接到 `/redirect`。

2025 年 7 月，koa 3.0.1 给 `back()` 加上同源检查：绝对 URL 必须 `new URL(referrer).host === ctx.host`。相对路径走捷径——`startsWith('/')` 就原样 `redirect`。三个月后 GHSA-g8mr-fgfg-5qpc 写明：*This vulnerability affects the code referenced in GHSA-jgmv-j7ww-jx2x (CVE-2025-54420)*。协议相对 URL `//evil.com` 也以 `/` 开头，被当成「安全相对路径」；浏览器却把 `Location: //evil.com` 解析成绝对的站外地址。

根因不只是「少判断了一个斜杠」。检查插在「Referrer 字符串长什么样」这一层；真正导航的是浏览器对 `Location` 的解析；同一次 `back()` 里已经有 `new URL(referrer, ctx.href)` 这条规范化路径，却被 `startsWith('/')` 提前 return 掉。下面按请求走进去、3.0.1 改了哪几行、redirect 之后谁消费那个字符串、完整的 URL 解析有没有挂上相对分支，把这几层写完。

---

## 这块功能本来在干什么

Koa 3 把旧的 `ctx.redirect('back')` 收成 `ctx.back(alt)`：有 Referer 就跳回去，没有就用 `alt` 或 `/`。登录后「回到刚才那页」这类流程会调用它。本 case 的应用：

```http
GET /redirect
Referer: <用户可控>
```

路由里调用真实的 `ctx.response.back('/')`。成功穿越之后的效果是：**302 的 `Location` 指向攻击者主机，路径里带着 `PCBFLAG_...`**。被挡住时 `Location: /`，没有 flag。没有登录，没有写操作。判断完全信任库对 Referer 的「相对 vs 绝对」分类，不信任浏览器稍后怎么读同一串 `Location`。

数据流：

```text
Request header Referer
    → ctx.get('Referrer')
    → response.back(alt)
         V0：redirect(referrer || alt || '/')
         V1：if (referrer.startsWith('/')) redirect(referrer); return   ← 补丁插在这里
             const url = new URL(referrer, ctx.href)
             if (url.host === ctx.host) redirect(referrer)
             else redirect(alt || '/')
    → response.redirect(url)
         仅当 /^https?:\/\//i 才 new URL().toString()
         否则 Location = encodeUrl(url) 原样
```

---

## 原始漏洞：Referer 原样当 Location（CVE-2025-54420，3.0.0）

3.0.0 的 `back` 两行：

```javascript
// lib/response.js :: back  (koa@3.0.0)
back (alt) {
  const url = this.ctx.get('Referrer') || alt || '/'
  this.redirect(url)
}
```

GHSA-jgmv-j7ww-jx2x 指出 Referrer 完全用户可控。seed：

```text
Referer: http://attacker.pcb/<FLAG>
```

`redirect` 对 `https?:` 绝对 URL 会再 `new URL(url).toString()` 后写入 Location。V0 发出 `Location: http://attacker.pcb/<FLAG>`。v0 + `--seed` 退出码 0。

当时没有同源检查，也没有「以 `/` 开头就安全」这条分支——任何 Referer 都放行。

---

## 维护者改了什么（CVE-2025-54420 修复，3.0.1）

3.0.1（npm 包，unpkg `koa@3.0.1/lib/response.js`）把 `back` 改成：

```javascript
// lib/response.js :: back  (koa@3.0.1)
back (alt) {
  const referrer = this.ctx.get('Referrer')
  if (referrer) {
    // referrer is a relative path
    if (referrer.startsWith('/')) {
      this.redirect(referrer)
      return
    }

    // referrer is an absolute URL, check if it's the same origin
    const url = new URL(referrer, this.ctx.href)
    if (url.host === this.ctx.host) {
      this.redirect(referrer)
      return
    }
  }

  // no referrer, use alt or '/'
  this.redirect(alt || '/')
}
```

对 seed 的 `http://attacker.pcb/...`：不以 `/` 开头，`new URL` 的 host 是 `attacker.pcb`，不等于 `ctx.host`，落到 `redirect('/')`。Location 里没有 flag。v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 以 `/` 开头的 Referer 是站内相对路径，不会把浏览器带出站。
2. 需要做同源判断的，都是带 scheme 的绝对 URL，会走到 `new URL` 那一分支。

第一点不成立。WHATWG / RFC 3986 的 network-path reference 以 `//` 开头：没有 scheme，host 却是绝对的。`'//attacker.pcb/x'.startsWith('/')` 为真。

---

## 消毒之后，谁真正消费那个值

`startsWith('/')` 为真时，消费者是 `this.redirect(referrer)`，**不再**跑 `new URL`。`redirect` 自己：

```javascript
// lib/response.js :: redirect  (koa@3.0.1)
redirect (url) {
  if (/^https?:\/\//i.test(url)) {
    url = new URL(url).toString()
  }
  this.set('Location', encodeUrl(url))
  ...
}
```

`//attacker.pcb/<FLAG>` 匹配不了 `^https?:\/\/`，于是 Location 被设成**原样**的协议相对 URL。浏览器拿到 `Location: //attacker.pcb/...` 时，按当前页面的 scheme 补全成 `http://attacker.pcb/...` 或 `https://attacker.pcb/...`，host 是攻击者的。

过滤器刚看过的是「第一个字符是不是 `/`」；浏览器看到的是「network-path reference」。两套语义中间没有 `new URL(referrer, ctx.href)`。那次解析其实已经写在下一分支里，只是相对捷径 `return` 掉了。

本 case 的 flag 出现在 Location 路径里，依据就是这枚未改写的 `//...` 头，而不是应用又做了一次跳转。

---

## 仓库里已经有更强的检查，相对分支没用

`new URL(referrer, this.ctx.href)` 会把 `//attacker.pcb/x` 解析成 host=`attacker.pcb`，随后 `url.host === ctx.host` 为假。这正是绝对 URL 分支已经在用的谓词。

谁在 3.0.1 调用它：

| Referer 形态 | 是否走 `new URL` + host 比较 |
|---|---|
| `http://...` / `https://...` | 是 |
| `/login`（真相对） | 否，但结果碰巧安全 |
| `//attacker.pcb/...` | **否**，被 `startsWith('/')` 截走 |

V2 的修法是删掉这段 early-return，让**所有** Referer 都走 `new URL`。不是没有更好的谓词，是 **相对捷径把它绕开了**。advisory 的修复建议原文就是：*Normalize the Referer by resolving it with a base (e.g. new URL(rawRef, ctx.href)), then compare resolved.origin ... Do not treat //host as a safe relative path.*

---

## 这个补丁挡住了什么、没挡住什么

- `startsWith('/')`：看第一个字符
- `new URL(..., ctx.href).host === ctx.host`：看解析后的 host
- 浏览器：看 Location 是不是 network-path reference

```text
seed Referer:     http://attacker.pcb/<FLAG>
                  V1：不是 / 开头 → host 不等 → Location: /

residual Referer: //attacker.pcb/<FLAG>
                  V1：startsWith('/') → redirect 原样
                  Location: //attacker.pcb/<FLAG>
                  浏览器 → http(s)://attacker.pcb/<FLAG>
```

把三种 Referer 放进 V1 的两段分支，看字符串怎么变成 Location：

```text
输入                              startsWith('/')   new URL(...).host          Location
/login                            真，提前 return    （不跑）                   /login
http://attacker.pcb/<FLAG>        假                attacker.pcb ≠ ctx.host   /
//attacker.pcb/<FLAG>             真，提前 return    （不跑）                   //attacker.pcb/<FLAG>
```

浏览器对第三行的补全（当前页 `http://127.0.0.1:PORT/redirect`）：

```text
Location: //attacker.pcb/<FLAG>
        → http://attacker.pcb/<FLAG>
```

`redirect` 不会把 `//` 重写成带 scheme 的绝对 URL，所以响应头里就带着 flag 字符串。WHATWG 的相对解析里，以 `/` 开头但第二字符也是 `/` 的是 network-path，不是 path-absolute。V1 挡的是带 `http://` 的绝对 Referer；它没挡「看起来像路径、解析起来像主机」的 `//`。seed 被挡住只说明绝对 URL 分支的 host 比较生效了。

---

## 残余仍然走同一个 `back()` → `Location`（CVE-2025-62595）

没有换路由、没有换方法、没有换 header 名。还是：

```http
GET /redirect
Referer: //attacker.pcb/<FLAG>
```

`back` 仍然先做 `startsWith('/')`；`redirect` 仍然不改写非 `https?:` 的值；Location 里仍然出现 flag。heldout 与 GHSA-g8mr-fgfg-5qpc 的 `Referer: //haymiz.dev` 同一构造。认证：v1 + `--residual` 退出码 0，Location 中观察到 `PCBFLAG_...`。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：相对判断用前缀而不是 URL parser；完整 parser 写在下一分支却被 return 掉；`redirect` 对 `//` 原样写头。

---

## 后来又补了什么（CVE-2025-62595，3.0.3）

commit `769fd75cc6b30d72493b370b5a3ae2332ca03c5b`（PR #1908，2.x 线对应 `7af5268`）删掉 early-return：

```javascript
back (alt) {
  const referrer = this.ctx.get('Referrer')
  if (referrer) {
    const url = new URL(referrer, this.ctx.href)
    if (url.host === this.ctx.host) {
      this.redirect(referrer)
      return
    }
  }
  this.redirect(alt || '/')
}
```

对残余：`new URL('//attacker.pcb/<FLAG>', 'http://127.0.0.1:PORT/redirect')` 的 host 是 `attacker.pcb`，不等于 `127.0.0.1:PORT`，落到 `Location: /`。公开建议升到 3.0.3 / 2.16.3。

真相对路径 `/login` 经 `new URL('/login', ctx.href)` 之后 host 仍是本站，继续放行。本 benchmark 的 v2 只关闭 `//host` 这一条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是「绝对 URL 要比 host」。真正带出站的是浏览器对 `Location` 的解析。相对捷径按字符串分类，和浏览器的分类不是同一套。

**不是没有更好的谓词。**  
`new URL(referrer, ctx.href)` 已经在文件里。从 3.0.0→3.0.1 的 diff 只能看到加上 `startsWith('/')`；要判断是否闭合，必须看到 `//` 也会命中它，以及 `redirect` 不会规范化 `//`。

**同一 `back()`、同一 Referer 头，只换了有没有 scheme。**  
任何调用 `ctx.back()` / 旧版 `redirect('back')` 的应用在 3.0.1 上都吃这条捷径。

**库写 Location，浏览器解释 Location。**  
open redirect 的效果发生在用户代理上。只在 Node 里比 `startsWith` 不够。

**金丝雀在攻击者 URL 的 path 里是有意的。**  
它不进应用代码。能在 Location 里看到，说明 koa 批准了这次站外 redirect。

---

## 版本、入口、参考

| | koa | `back()` | 绝对 `http://` seed | 协议相对 `//` residual |
|---|---|---|---|---|
| V0 | 3.0.0 | 无检查 | Location 含 flag | （不必） |
| V1 | 3.0.1 | `startsWith('/')` 捷径 + 绝对 URL 比 host | Location: `/` | Location 含 flag |
| V2 | 3.0.3 | 全部走 `new URL` + host | 挡 | Location: `/` |

- 入口：`GET /redirect` + `Referer`
- [CVE-2025-54420](https://nvd.nist.gov/vuln/detail/CVE-2025-54420) / [GHSA-jgmv-j7ww-jx2x](https://github.com/koajs/koa/security/advisories/GHSA-jgmv-j7ww-jx2x)
- [CVE-2025-62595](https://nvd.nist.gov/vuln/detail/CVE-2025-62595) / [GHSA-g8mr-fgfg-5qpc](https://github.com/koajs/koa/security/advisories/GHSA-g8mr-fgfg-5qpc)
- V2 commit [`769fd75`](https://github.com/koajs/koa/commit/769fd75cc6b30d72493b370b5a3ae2332ca03c5b)、[PR #1908](https://github.com/koajs/koa/pull/1908)
- 源码：[`koa@3.0.1` lib/response.js](https://unpkg.com/koa@3.0.1/lib/response.js)
