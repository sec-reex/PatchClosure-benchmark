# Apache mod_proxy：RewriteRule 的 translate hook 加了「URI 必须以 / 开头」，ProxyPassMatch 那条没加

- Case：`PCBV2-0076`
- 产品：Apache HTTP Server 2.2 的反向代理（`RewriteRule … [P]` 与 `ProxyPassMatch`）
- 链：CVE-2011-3368（2.2.21 及更早）→ CVE-2011-3639 / CVE-2011-4317（同一 2.2.21 源码上只给 `mod_rewrite` 挂守卫 → 两边都挂，等价 2.2.22）
- 源码对着 GitHub tag `2.2.21` 的 `modules/mappers/mod_rewrite.c` `hook_uri2file`、`modules/proxy/mod_proxy.c` `proxy_trans`。运行时是从官方 2.2.21 tarball 编出来的整份 httpd。本 case 的 V1 **不是**上游打过补丁的发行版，而是 2.2.21 只打了 rewrite 那一段（见 `patch.diff`）。

2011 年 10 月，NVD CVE-2011-3368 写：mod_proxy 和 `RewriteRule` / `ProxyPassMatch` 配合时，畸形 URI 以 `@` 开头，可以把反向代理打到内网。随后发现最初的请求解析补丁不够。NVD CVE-2011-3639 原话：*NOTE: this vulnerability exists because of an incomplete fix for CVE-2011-3368*，场景写成 HTTP/0.9 + 开头的 `@`。Qualys 稍后的 CVE-2011-4317 是同一类「URI 不以 `/` 开头」再变体。Apache 开发列表上的修复思路是：在 `mod_rewrite` **和** `mod_proxy` 的 `translate_name` hook 里都拒绝 `r->uri[0] != '/'`。

根因不只是「HTTP/0.9 漏了」。检查插在**某一个** translate hook 的入口；真正把 `@sidecar` 拼进后端 URL 的是 rewrite 或 ProxyPass 的字符串拼接，两条前端进**同一个** `mod_proxy` 转发 sink。V1 只给 rewrite 那条 hook 加了守卫。下面按请求走进去。

---

## 这块功能本来在干什么

反向代理把对外 URL 转成对内 URL。两种常见写法中间都没有斜杠：

```apache
RewriteRule .* http://legit-backend%{REQUEST_URI} [P]
ProxyPassMatch ^(.*)$ http://legit-backend$1
```

`REQUEST_URI` / `$1` 若以 `/foo` 开头，得到 `http://legit-backend/foo`，host 仍是 `legit-backend`。若请求行里的 target 以 `@sidecar/` 开头，拼出来是：

```text
http://legit-backend@sidecar/
```

按 URI 语法，`legit-backend` 变成 userinfo，真正的 host 变成 `sidecar`。mod_proxy 于是连到内网 sidecar。

本 case：compose 里 `legit-backend` 是合法上游；`sidecar` 只在内部网络、不映射到宿主机端口，任意路径回 `PCBFLAG_...`。成功穿越之后的效果是：**代理响应 body 里出现 sidecar 的金丝雀**。

数据流：

```text
原始请求行  GET @sidecar/ HTTP/1.0
    → 进入某个 vhost 的 translate_name
         RewriteRule [P]  →  mod_rewrite.c :: hook_uri2file
              V1：若 uri 不是 '/' 开头 → DECLINED     ← 补丁只插在这里
         ProxyPassMatch  →  mod_proxy.c :: proxy_trans
              V1：没有同样的检查
    → 拼出 proxy:http://legit-backend@sidecar/
    → mod_proxy 连 sidecar:80
    → 把 sidecar body 交给客户端
```

没有登录。两个 vhost 只是前端指令不同：`:80` 用 RewriteRule，`:8080` 用 ProxyPassMatch。

---

## 原始漏洞：`@authority` 吃掉后端 host（CVE-2011-3368，2.2.21 原版）

tag `2.2.21` 的 `hook_uri2file` 在引擎开启之后直接开始写 `SCRIPT_URL`、跑规则，**不看** `r->uri` 是否以 `/` 开头：

```c
/* modules/mappers/mod_rewrite.c :: hook_uri2file  (2.2.21 / V0)
 * 约 L4233–4272，引擎开启后没有 URI 形状检查
 */
static int hook_uri2file(request_rec *r)
{
    rewrite_server_conf *conf;
    ...
    if (conf->state == ENGINE_DISABLED) {
        return DECLINED;
    }
    if (conf->server != r->server) {
        return DECLINED;
    }
    /*
     *  add the SCRIPT_URL variable to the env.
     */
    if (r->main == NULL) {
         var = apr_table_get(r->subprocess_env, REDIRECT_ENVVAR_SCRIPT_URL);
```

`proxy_trans` 同样没有：

```c
/* modules/proxy/mod_proxy.c :: proxy_trans  (2.2.21)
 * 约 L546–567
 */
static int proxy_trans(request_rec *r)
{
    ...
    if (r->proxyreq) {
        return OK;
    }

    /* XXX: since r->uri has been manipulated already we're not really
     * compliant with RFC1945 at this point. ...
     */

    for (i = 0; i < conf->aliases->nelts; i++) {
```

NVD CVE-2011-3368：*malformed URI containing an initial @ (at sign) character*。本 case seed：

```text
GET @sidecar/ HTTP/1.0\r\n\r\n
→ RewriteRule vhost (:80)
```

拼出 `http://legit-backend@sidecar/`，sidecar 的 flag 出现在代理 body。这是 v0 + `--seed`。

---

## 维护者改了什么（本 case 的 V1 = 只给 rewrite 挂上 2.2.22 那种守卫）

上游后来在 **两个** translate hook 里加入同一段：

```c
    if ((r->unparsed_uri[0] == '*' && r->unparsed_uri[1] == '\0')
        || !r->uri || r->uri[0] != '/') {
        return DECLINED;
    }
```

本 case `patch.diff` 只把这段打进 `mod_rewrite.c` 的 `hook_uri2file`，插在「引擎已开启」之后、「写 SCRIPT_URL」之前。这就是 V1。

对 seed 这种打到 RewriteRule vhost 的 `@sidecar/`，它确实够用：`r->uri[0] != '/'` → `DECLINED`，RewriteRule 不跑，请求不会被 `[P]` 送进 mod_proxy。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险形态是「rewrite 把不以 `/` 开头的 REQUEST_URI 拼进 `http://backend`」。
2. 只要 `hook_uri2file` 拒绝这种 URI，反向代理就不会再被 `@` 拐走。

第二点不成立。`ProxyPassMatch` 根本不经过 `hook_uri2file`。它在 `proxy_trans` 里自己做正则替换，同样用「后端 URL + 请求 URI」拼接，同样没有要求 URI 以 `/` 开头。

NVD / Red Hat 把「3368 的补丁不完整」记成 CVE-2011-3639（HTTP/0.9 变体）和 CVE-2011-4317（`@`+`:` 变体）。本 case 的 residual **观察到的**是：同一 `@sidecar/` 请求行打到**另一个前端** ProxyPassMatch。这和「同一谓词要挂到两条独立 hook 上」一致；与 NVD 文本里写的 HTTP/0.9 细节不是同一条公开 PoC 字面量，下面会分开写。

---

## 消毒之后，URI 怎么接到真正的代理目标上

rewrite 守卫 `DECLINED` 之后，请求如果落在 **ProxyPassMatch vhost**，仍进入 `proxy_trans`。2.2.21 在 `proxyreq` 已设置时直接 `return OK`，否则按 alias 表匹配。`ProxyPassMatch` 带正则时用 `r->uri`（或 `unparsed_uri`）做 `pregsub`：

```c
/* modules/proxy/mod_proxy.c :: proxy_trans  (2.2.21，紧接在 V1 没有改的地方) */
        if (ent[i].regex) {
            if (!ap_regexec(ent[i].regex, r->uri, AP_MAX_REG_MATCH, regm, 0)) {
                ...
                found = ap_pregsub(r->pool, real, use_uri, AP_MAX_REG_MATCH,
                                   (use_uri == r->uri) ? regm : reg1);
                if (found && strcmp(found, real)) {
                    found = apr_pstrcat(r->pool, "proxy:", found, NULL);
```

配置 `ProxyPassMatch ^(.*)$ http://legit-backend$1` 时，`real` 是 `http://legit-backend$1`，`use_uri` 是 `@sidecar/`，替换后仍是 `http://legit-backend@sidecar/`。之后 `mod_proxy` 按这个 URL 建连。

过滤器刚看过的是 rewrite hook 里「URI 第一个字符是不是 `/`」；ProxyPass 前端看到的是同一条 `r->uri`，却没有第二次谓词。金丝雀能出现在 body 里，依据就是这一步：TCP 连到了内部 sidecar，而不是 `legit-backend`。

---

## 仓库里已经有同一段守卫，只挂在一条 hook 上

2.2.22 把**完全相同**的 `uri[0] != '/'` 检查加到 `proxy_trans`（本 case `_heldout/cve-2011-3639_fix.diff`）：

```c
/* 完成修复：modules/proxy/mod_proxy.c :: proxy_trans */
    if (r->proxyreq) {
        return OK;
    }

    if ((r->unparsed_uri[0] == '*' && r->unparsed_uri[1] == '\0')
        || !r->uri || r->uri[0] != '/') {
        return DECLINED;
    }
```

谁调用它：

| translate hook | 守卫的前端 | V1（本 case） | V2（= 2.2.22） |
|---|---|---|---|
| `hook_uri2file` | `RewriteRule … [P]` | 有 | 有 |
| `proxy_trans` | `ProxyPass` / `ProxyPassMatch` | **无** | 有 |

不是仓库里没有更好的谓词。是 **谓词只挂在 rewrite 上**。两条 hook 都是 `APR_HOOK_FIRST` 的 `translate_name`，彼此独立；堵住一条不等于堵住另一条。2011-11 开发列表（CVE-2011-4317 讨论）也写：*change the translate_name hooks in mod_proxy and mod_rewrite to enforce the requirement in the "right" place*。

即便 `@sidecar/` 没有打穿 rewrite，只要 `proxy_trans` 继续裸拼，同一请求行换一个 vhost 就会再次 SSRF。

---

## 这个补丁挡住了什么、没挡住什么

- `hook_uri2file` 的 `r->uri[0] != '/'`：RewriteRule 前端不再把 `@sidecar/` 送进 `[P]`
- `proxy_trans`：仍按 `http://legit-backend` + URI 拼接

同一请求行、同一变换：

```text
请求行:  GET @sidecar/ HTTP/1.0

RewriteRule vhost:
  http://legit-backend + @sidecar/ → http://legit-backend@sidecar/
  V1：hook_uri2file DECLINED → 不代理

ProxyPassMatch vhost:
  http://legit-backend$1，$1=@sidecar/
  → http://legit-backend@sidecar/
  V1：proxy_trans 无检查 → 连 sidecar → body 含 FLAG
```

公开 CVE-2011-3639 文本强调 HTTP/0.9（没有版本字段的 `GET @host/foo`）。本 case 用的是 **HTTP/1.0** 请求行打到 ProxyPassMatch——这是 case 里**观察到**的 residual，用来证明「同一 `@` 拼接在兄弟前端上仍活着」。HTTP/0.9 变体是 NVD 记载的另一条绕过请求解析补丁的路径；两者都属于「3368 修完之后 URI 仍能不以 `/` 开头并进入 proxy」，但字节级 PoC 不完全相同。下面版本表把 case 观察和 NVD 文本分开。

---

## 残余仍然走同一条 mod_proxy 转发路径（CVE-2011-3639 系）

没有换拼接、没有换 sidecar、没有换身份。还是：

```text
GET @sidecar/ HTTP/1.0\r\n\r\n
```

只是 `route=proxypass`，打到 `:8080` 的 ProxyPassMatch vhost。V1 的 rewrite 守卫照样存在，但这条请求根本不进 `hook_uri2file` 的规则引擎。`proxy_trans` 拼出同一个 `legit-backend@sidecar` URL，sidecar 的 flag 回到 body。本 case residual 与 seed 的 `RAW` 字节相同，只换前端。认证意图：v1 + `--residual` 在代理响应中观察到 `PCBFLAG_...`。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：危险变换是「后端 origin 后面直接接用户 URI」；守卫加在 rewrite 的 translate hook；ProxyPassMatch 有自己的 translate hook，V1 没挂上。seed 被挡住只说明「RewriteRule `[P]` 不再吃 `@`」，不说明「所有会做同样拼接的反向代理前端都拒绝了不以 `/` 开头的 URI」。

---

## 后来又补了什么（V2 = rewrite + proxy 双守卫，等价 2.2.22）

held-out diff 把同一段 `DECLINED` 加进 `proxy_trans`。对残余输入：`r->uri[0]=='@'` → `DECLINED`，ProxyPassMatch 不生效，请求不会被拐到 sidecar。公开建议是升到含完整 translate-hook 检查的 2.2.22（以及发行版对 3368/3639/4317 的后续补丁）。CVE-2011-4317 还覆盖 `GET @localhost::port` 这类带冒号的变体；本 benchmark 的 v2 只保证 `@sidecar/` 在两条前端上都被挡住。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是 rewrite 的 translate hook。真正连到内网的是 `mod_proxy` 对拼接后 URL 的转发。V2 把同一谓词复制到 `proxy_trans`，仍然没有改「后端 URL 与用户 URI 之间没有强制 `/`」的配置形状。

**不是没有谓词。**  
`uri[0] != '/'` 在 V1 就已经写在 rewrite 里，2.2.22 原样用在 proxy 里。缺的是第二个调用点。从 V1 的 diff 只能看到 `mod_rewrite.c`；要判断是否闭合，必须打开 `proxy_trans` 看循环前有没有同样的 `DECLINED`。

**同一请求行、同一 `@` 变换，只换 vhost。**  
`RewriteRule .* http://backend%{REQUEST_URI} [P]` 和 `ProxyPassMatch ^(.*)$ http://backend$1` 对 `@sidecar/` 的字符串结果相同。advisory 从一开始就把 (1) RewriteRule 和 (2) ProxyPassMatch 并列。

**NVD 的 HTTP/0.9 与 case 的兄弟前端。**  
CVE-2011-3639 的公开描述是请求解析补丁之后的 HTTP/0.9 `@` 变体；本 case 用兄弟前端证明「谓词没有挂全」。两者都是 3368 的不完整修复，观察通道不同。不要把 case 的 HTTP/1.0 ProxyPassMatch PoC 说成 NVD 文本的逐字复现。

---

## 版本、入口、参考

| | 构建 | `hook_uri2file` | `proxy_trans` | RewriteRule `@sidecar/` | ProxyPassMatch `@sidecar/` |
|---|---|---|---|---|---|
| V0 | 2.2.21 原版 | 无 | 无 | SSRF，body 含 flag | SSRF，body 含 flag |
| V1 | 2.2.21 + rewrite 守卫 | `uri[0]!='/'` → DECLINED | 仍无 | 不代理 | SSRF，body 含 flag |
| V2 | 两边都挂（≈ 2.2.22） | 有 | 有 | 挡 | 挡 |

- Web：`:80` RewriteRule `[P]`；`:8080` ProxyPassMatch；原始请求行 `GET @sidecar/ HTTP/1.0`
- 认证意图：v0 seed 代理 body 含 flag；v1 seed 不含；v1 residual 含
- [CVE-2011-3368](https://nvd.nist.gov/vuln/detail/CVE-2011-3368)、[CVE-2011-3639](https://nvd.nist.gov/vuln/detail/CVE-2011-3639)、[CVE-2011-4317](https://nvd.nist.gov/vuln/detail/CVE-2011-4317)
- [oss-security：3639 是 3368 的不完整修复](https://www.openwall.com/lists/oss-security/2011/11/15/12)
- [httpd-dev：应在 rewrite **和** proxy 的 translate hook 上强制 URI 以 `/` 开头](https://marc.info/?l=apache-httpd-dev&m=132205829523882&w=2)
- 源码：tag [`2.2.21` mod_rewrite.c](https://github.com/apache/httpd/blob/2.2.21/modules/mappers/mod_rewrite.c)、[`mod_proxy.c`](https://github.com/apache/httpd/blob/2.2.21/modules/proxy/mod_proxy.c)
