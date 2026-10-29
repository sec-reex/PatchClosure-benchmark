# Gitea：前两个字节的 `/\` 挡住了，path.Clean 还会造出一个来

- Case：`PCBV2-0118`
- 产品：Gitea（登录后 `redirect_to` 跳转）
- 链：CVE-2022-1058 / GHSA-4rqq-rxvc-v2rc（1.16.4 → 1.16.5，commit `e3d8e92` / `bab7d88`）→ CVE-2026-25779 / GHSA-j5r2-4c8j-xc3m（≤1.25.4 → 1.25.5 / 1.26.0，PR #36660 / #36716，commit `f913d90`）
- 源码对着 GitHub tag `v1.16.5` 的 `modules/context/context.go`（`RedirectToFirst`、`Redirect`）和 tag `v1.26.0` 的 `modules/httplib/url.go`（`urlIsRelative`）。运行时是官方 `gitea/gitea` 镜像，不是抽出来的函数。1.26.0 源码注释写明 *http.Redirect calls path.Clean and changes the meaning of a path. For example, `/a/../\b` will be changed to `/\b`*。

2022 年 3 月，Gitea 在 `RedirectToFirst` 里拒绝以 `//` 或 `/\` 开头的 Location。这挡住了 seed 那种 `/\<host>`。四年后 advisory 指出：同一条登录 `redirect_to` 上，守卫只看前两个字节；通过检查之后，`ctx.Redirect` 调用 Go 标准库 `http.Redirect`，后者对相对 Location 做 `path.Clean`，把 `/x/../\<host>` 收成 `/\<host>`。浏览器把前导 `/\` 当成 scheme-relative。NVD 把这件事记成 CVE-2026-25779。

根因不只是「少写了一种前缀」。检查插在「字符串头两个字节」这一层；真正写出 `Location` 的是 `http.Redirect` 的 `path.Clean`；同函数里已经有 `url.Parse`，却用 Go 的「`\` 是路径字节」语义，和浏览器的「`/\` 等于 `//`」对不上。下面按登录走进去、1.16.5 改了哪几行、放行之后谁改写那个字符串、更宽的谓词有没有挂上，把这几层写完。

---

## 这块功能本来在干什么

Gitea 登录成功后，按 `redirect_to`（查询参数或表单字段）发 302。`RedirectToFirst` 从候选 URL 里挑第一个「看起来像站内」的。

一次典型登录：

```http
POST /user/login
user_name=pcbuser&password=...&redirect_to=/dashboard
```

设计意图：`redirect_to` 必须是本站相对路径，或 host 等于 `setting.AppURL`。成功穿越之后的效果是：**应用认为这是相对路径，浏览器却导航到站外**——本 case 用 `PCBFLAG_...` 当 Location 里的 host 标签。

数据流：

```text
POST /user/login  redirect_to=
    → RedirectToFirst(loc, ...)
         V1：if loc[0]=='/' && (loc[1]=='/' || loc[1]=='\\') { continue }  ← 补丁插在这里
         url.Parse(loc)：Go 把 \ 当路径字节，Host==""
         若 Scheme/Host 非空且不是 AppURL → continue
         ctx.Redirect(loc)
             http.Redirect → 对相对 Location 做 path.Clean     ← 真正改写
    → 响应 Location: ...
    → 浏览器把 /\host 当成 //host
```

登录本身是身份建立；开放重定向的判定不看密码对不对，看 Location。本 case 先 seed 好 pcbuser。1.16.x 还要带 `_csrf`；守卫失败时 Location 是 `/`，不是 4xx——所以「blocked」看的是 Location 里还有没有 flag host，不是看登录成不成功。

---

## 原始漏洞：前导 `/\`（CVE-2022-1058，1.16.4）

1.16.4 的 `RedirectToFirst` 用 `url.Parse` 判断是否站外。Go 的 `url.Parse` 把 `\` 当成普通路径字符，所以 `/\evil.example` 的 Host 是空的，守卫认为这是相对路径，原样 `ctx.Redirect`。Andrew Thornton / huntr 的问题是：浏览器把 `/\` 和 `//` 都当成 scheme-relative。NVD CVE-2022-1058 写的是 *Open Redirect on login in go-gitea/gitea prior to 1.16.5*。

本 case 的 seed：

```text
redirect_to = /\<FLAG>.evil.example
```

1.16.4 发出 `Location: /\PCBFLAG_....evil.example`。这就是 v0 + `--seed` 退出码 0。

`/x/../\` 这种「先相对、再被 Clean 成 `/\`」当时还不在检查范围内。当时没人拿 `path.Clean` 当 `/\` 问题的一部分。huntr bounty `4fb42144` 给的也是前导 `/\` / `//`，和 seed 同一形态。

---

## 维护者改了什么（CVE-2022-1058 修复，1.16.5）

1.16.5 只在 `url.Parse` **之前**加了四行。本 case `patch.diff` 就是这次：

```go
// modules/context/context.go :: RedirectToFirst  (tag v1.16.5, 约 L178–200)
func (ctx *Context) RedirectToFirst(location ...string) {
    for _, loc := range location {
        if len(loc) == 0 {
            continue
        }

        // Unfortunately browsers consider a redirect Location with preceding "//" and "/\" as meaning redirect to "http(s)://REST_OF_PATH"
        // Therefore we should ignore these redirect locations to prevent open redirects
        if len(loc) > 1 && loc[0] == '/' && (loc[1] == '/' || loc[1] == '\\') {
            continue
        }

        u, err := url.Parse(loc)
        if err != nil || ((u.Scheme != "" || u.Host != "") && !strings.HasPrefix(strings.ToLower(loc), strings.ToLower(setting.AppURL))) {
            continue
        }

        ctx.Redirect(loc)
        return
    }
    ctx.Redirect(setting.AppSubURL + "/")
}
```

对 seed 这种头两个字节就是 `/\` 的值，它确实够用：`continue`，最后落到 `/`。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险 Location 长得像以 `//` 或 `/\` **开头**。
2. 通过检查的字符串，写进 `Location` 时不会再变成这两种前缀。

第二点不成立。更关键的是：这四行之后，代码仍然把**原始** `loc` 交给 `ctx.Redirect`，而 `Redirect` 会再改写一次。

---

## 放行之后，谁真正改写那个值

V1 的头两字节检查一通过，`ctx.Redirect` 调用标准库：

```go
// modules/context/context.go :: Redirect  (tag v1.16.5, 约 L396–403)
func (ctx *Context) Redirect(location string, status ...int) {
    code := http.StatusFound
    if len(status) == 1 {
        code = status[0]
    }
    http.Redirect(ctx.Resp, ctx.Req, location, code)
}
```

Go 的 `net/http.Redirect` 对**相对** URL 做 `path.Clean`。`/x/../\FLAG.evil.example` 的 `/x/../` 被收成 `/`，剩下 `/\FLAG.evil.example`。过滤器刚看过的是「第 0、1 个字节是不是 `/` 加 `/` 或 `\`」；客户端看到的是 Clean 之后的 Location。两套语义中间没有第二次谓词。

`url.Parse` 在 V1 已经跑过，但它用的是 Go 语义：`\` 不是分隔符，Host 仍为空，所以过了「必须是相对或本站」那一关。浏览器稍后用的是另一种语义。

---

## 仓库里当时没有「Clean 之后再查一遍」

1.16.5 没有在 `http.Redirect` 之前自己 `path.Clean`，也没有拒绝路径里任意位置的 `\`。这些是 1.25.5 / 1.26.0 才写进 `urlIsRelative` 的：

```go
// modules/httplib/url.go :: urlIsRelative  (tag v1.26.0)
func urlIsRelative(s string, u *url.URL) bool {
    if len(s) > 1 && (s[0] == '/' || s[0] == '\\') && (s[1] == '/' || s[1] == '\\') {
        return false
    }
    if u == nil {
        return false
    }
    if u.Scheme != "" || u.Host != "" {
        return false
    }
    // HINT: GOLANG-HTTP-REDIRECT-BUG: ... `/a/../\b` will be changed to `/\b`
    // So if the "path" contains `\`, it is not a valid relative URL
    return !strings.Contains(u.Path, "\\")
}
```

V1 等于只做了这个函数的前半段（头两字节），后半段「解析后的 Path 里不能有 `\`」当时还不存在。不是「有更好的谓词却没挂上」那么简单——1.16.5 **还没写出**那个谓词。要判断补丁是否闭合，必须看到 `ctx.Redirect` → `http.Redirect` → `path.Clean`。

即便 `/x/../\` 没有把头两字节检查打穿，只要 `http.Redirect` 继续 Clean 相对 Location，任何「检查时无害、Clean 后变成 `/\`」的写法都会变成一次真实的开放重定向。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「头两字节 vs Clean」落到具体代码：

- `loc[0]=='/' && (loc[1]=='/' || loc[1]=='\\')`：看开头是不是 scheme-relative
- `path.Clean`：看相对路径段怎么折叠

只要构造一种输入，使「头两字节是 `/` + 普通字符」而「Clean 之后变成 `/\`」，第一行会放行，第二行仍然写出危险 Location。

`/x/../\<FLAG>.evil.example` 就是这样来的：

```text
检查时:  loc[0]='/'  loc[1]='x'  → 不 continue
url.Parse: Host=="" → 当作相对，放行
path.Clean("/x/../\\FLAG.evil.example") → "/\\FLAG.evil.example"
Location: /\PCBFLAG_....evil.example
浏览器:  等同 //PCBFLAG_....evil.example
```

GHSA-j5r2-4c8j-xc3m 的 PoC 是 `/a/../\example.com`。本 case 只是把 host 换成 flag 标签。

---

## 残余仍然走同一条登录 Location（CVE-2026-25779）

没有换路由、没有换守卫函数。还是：

```http
POST /user/login
redirect_to=/x/../\<FLAG>.evil.example
```

`RedirectToFirst` 仍然跑 V1 那四行；头两字节不是 `/\`，放行；`http.Redirect` 收成 `/\<FLAG>.evil.example`。认证：v1 + `--residual` 退出码 0，Location 里观察到 `PCBFLAG_...`。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：检查看的是原始前缀；写出 Location 的是另一套规范化；浏览器和 `url.Parse` 对 `\` 的读法不同。seed 被挡住只说明「字面开头 `/\` 没了」，不说明「Location 里不能再出现 scheme-relative 的站外 host」。

---

## 后来又补了什么（CVE-2026-25779，1.25.5 / 1.26.0）

跳转判定收到 `httplib.IsCurrentGiteaSiteURL` / `urlIsRelative`：头两字节检查保留，并拒绝解析后 Path 里任意 `\`（含百分号解码后的）。对残余输入，`u.Path` 含 `\`，判定为非相对，落到 `/`。公开建议是升级到 1.25.5 或 1.26.0。源码把根因写成 `GOLANG-HTTP-REDIRECT-BUG`。

即便如此，这仍然依赖「在交给 `http.Redirect` 之前按浏览器语义拒绝」。本 benchmark 的 v2（1.26.0）关闭这一条 reference residual。

Go 标准库这边没有改 `http.Redirect` 对 `\` 的处理。Gitea 只能在应用层先按浏览器语义拒掉。1.16.5 只拒了「已经长成 `/\`」的字面量；1.26.0 才拒「解析后 Path 里任何 `\`」，把 `/x/../\` 也盖住。百分号解码后的 `%5c` 同一谓词也会挡。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是 `RedirectToFirst` 入口的前两个字节。真正把相对路径收成 `/\` 的是 `http.Redirect` 的 `path.Clean`。V2 才在解析后的 Path 上禁 `\`。

**检查和写出用了两套规范化。**  
`url.Parse` 不把 `\` 当分隔符；`path.Clean` 会折叠 `..` 但保留 `\`；浏览器把 `/\` 当 `//`。从 V1 的 diff 只能看到加了四行；要判断补丁是否闭合，必须看到 `Redirect` 的实现。

**同一函数、同一 `loc`，只换了前缀后面的写法。**  
seed 和 residual 都是登录 `redirect_to`。advisory 的 `/a/../\example.com` 和本 case 的 `/x/../\...` 是同一种变换。

**金丝雀在 Location host 上是有意的。**  
flag 不在 HTML body 里。能在 302 的 Location 里看到它，说明浏览器会跟到站外，而不是「应用碰巧回了首页」。

---

## 版本、入口、参考

| | tag | `RedirectToFirst` | 写出 Location | `/\host` seed | `/x/../\host` residual |
|---|---|---|---|---|---|
| V0 | 1.16.4 | 无头两字节检查 | `http.Redirect` + Clean | Location 带 flag | （也可） |
| V1 | 1.16.5 | 拒绝开头 `//` `/\` | 同上 | 落到 `/` | Clean 成 `/\host`，带 flag |
| V2 | 1.26.0 | `urlIsRelative`：开头 + Path 禁 `\` | 仍走 Redirect，但先拒绝 | 挡 | Path 含 `\`，挡 |

- Web：`POST /user/login`（或带 `redirect_to` 的登录 GET）
- 认证（本平台）：v0 seed 观察到 flag；v1 seed 未观察到；v1 residual 观察到
- [CVE-2022-1058](https://nvd.nist.gov/vuln/detail/CVE-2022-1058)、[CVE-2026-25779](https://nvd.nist.gov/vuln/detail/CVE-2026-25779)
- [GHSA-4rqq-rxvc-v2rc](https://github.com/advisories/GHSA-4rqq-rxvc-v2rc)
- [GHSA-j5r2-4c8j-xc3m](https://github.com/advisories/GHSA-j5r2-4c8j-xc3m)
- huntr：[4fb42144](https://huntr.dev/bounties/4fb42144-ac70-4f76-a5e1-ef6b5e55dc0d)
- V1 commit：[`e3d8e92`](https://github.com/go-gitea/gitea/commit/e3d8e92bdc67562783de9a76b5b7842b68daeb48)；V2 PRs [#36660](https://github.com/go-gitea/gitea/pull/36660)、[#36716](https://github.com/go-gitea/gitea/pull/36716)
