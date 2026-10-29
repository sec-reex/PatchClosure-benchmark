# Apache httpd：trusted 标志在 DirectoryIndex 上抄对了，fast-redirect 仍抄主请求

- Case：`PCBV2-0075`
- 产品：Apache HTTP Server（本 case 跑官方 `httpd:2.4.60` / `2.4.61` / `2.4.62`；`AddType application/x-httpd-cgi .cgi`，金丝雀只活在 `secret.cgi` 的源码注释里）
- 链：CVE-2024-39884（仅 2.4.60 → 2.4.61，svn `r1918839`）→ CVE-2024-40725（2.4.60–2.4.61 → 2.4.62，svn `r1919249`）
- 源码对着 GitHub tag `2.4.61` / `2.4.62` 的 `modules/http/http_request.c` `ap_internal_fast_redirect`、`include/httpd.h` 的 `AP_REQUEST_IS_TRUSTED_CT`、`server/core.c` 的 `core_override_type` / `default_handler`。运行时是整份 httpd，不是抽出来的函数。

2.4.60 给内容类型加了「trusted」标志：只有受信任的 Content-Type 才会按遗留规则选出 handler（例如 `application/x-httpd-cgi` → mod_cgi）。间接请求上这个标志丢了，core `default_handler` 就把脚本当静态文件吐出去。2.4.61 在大量「字面设置 Content-Type」的路径上维持该标志，DirectoryIndex 这条间接请求被堵住。Apache 自己的 2.4 安全页把 CVE-2024-40725 标成 *A partial fix for CVE-2024-39884*：同一套 `AddType` 配置，只是间接请求换成了 MultiViews / `ap_internal_fast_redirect`。NVD 原话同样是 *A partial fix for CVE-2024-39884 in the core of Apache HTTP Server 2.4.61*。

根因不只是「漏了一个模块」。检查插在「当前 `request_rec` 的 Content-Type 带不带 trusted 位」上；真正决定执不执行 CGI 的是**合并之后那条主请求**上的标志。V1 的 fast-redirect 把子请求的 `content_type` 抄过来，trusted 位却仍问主请求 `r`。下面按请求走进去。

---

## 这块功能本来在干什么

httpd 可以用两种方式给文件绑 handler：显式 `SetHandler` / `AddHandler`，或遗留的「用 MIME 类型当 handler 名」。`AddType application/x-httpd-cgi .cgi` 属于后者：mod_cgi 认这个魔数类型，trusted 时执行脚本，不 trusted 时当普通文件。2.4.60 引入 trusted 位，是为了避免**客户端声称的** Content-Type 选中危险 handler；副作用是：服务器自己用 `AddType` 标出来的类型，一旦在间接请求上丢了那一位，脚本也不再执行。

一次直接请求（对照，所有版本都应执行）：

```http
GET /idx/secret.cgi HTTP/1.1
```

脚本 STDOUT 只有 `CGI-EXECUTED-OK-NO-SOURCE`。flag 写在源码注释 `# PCB-CANARY-SOURCE-ONLY PCB_FLAG=...` 里，执行路径永远打不印出来。成功穿越之后的效果是：**handler 被跳过，`default_handler` 把文件原文写进响应 body**，注释里的金丝雀可见。

数据流（2.4.61，本 case 的 V1）：

```text
HTTP request-target
    → 映射到文件系统（mod_dir / mod_negotiation / rewrite …）
         间接请求会生成子请求 rr，再 ap_internal_fast_redirect(rr, r)
              把 rr 的 uri / filename / handler / content_type 抄到 r
              V1：ap_set_content_type_ex(r, rr->content_type,
                       AP_REQUEST_IS_TRUSTED_CT(r))   ← 问的是主请求 r
    → 按 r 上的 handler / 受信任的 content-type 选模块
         trusted + application/x-httpd-cgi → mod_cgi 执行
         否则 core default_handler 打开文件，body = 源码
```

本 case 配置（`conf/vuln.conf`）：`AddType application/x-httpd-cgi .cgi`，`/idx/` 的 `DirectoryIndex secret.cgi`，htdocs 开了 `MultiViews`。

---

## 原始漏洞：间接请求丢掉 trusted（CVE-2024-39884，2.4.60）

2.4.60 开始，`ap_set_content_type()` 会把 trusted 位清掉；只有 `ap_set_content_type_ex(..., trusted=1)` 才置位。宏在 `include/httpd.h`：

```c
/* include/httpd.h  (2.4.61，与 2.4.60 同类)
 * Returns true if the content-type field is from a trusted source
 */
#define AP_REQUEST_TRUSTED_CT 1 << 1
#define AP_REQUEST_IS_TRUSTED_CT(r) \
    (!!AP_REQUEST_GET_BNOTE((r), AP_REQUEST_TRUSTED_CT))
```

字面配置路径会置位。例如 `ForceType` 走 `core_override_type`：

```c
/* server/core.c :: core_override_type  (2.4.61)
 * 字面 mime_type 以 trusted=1 写入
 */
    if (conf->mime_type && strcmp(conf->mime_type, "none"))
        ap_set_content_type_ex(r, (char*) conf->mime_type, 1);
```

2.4.60 的回归是：`AddType` 标出来的 CGI 类型，在**间接**取出文件时没有把这一位置到最终要输出的那条 `request_rec` 上。handler 选不中，落到 `default_handler`，源码泄露。Apache advisory：*"AddType" and similar configuration, under some circumstances where files are requested indirectly, result in source code disclosure*。

本 case seed 用 DirectoryIndex 这条间接请求：

```text
GET /idx/
```

mod_dir 把目录请求解析成 `secret.cgi` 再内部转。V0（2.4.60）body 里出现源码注释中的 `PCBFLAG_...`。直接 `GET /idx/secret.cgi` 在所有版本都执行、没有 flag——对照用。

---

## 维护者改了什么（CVE-2024-39884 修复，2.4.61）

`r1918839`（GitHub 合并记录 `fe171ff`，*maintain trusted flag / Always trust content types that we set literally*）把大量「服务器自己设置 Content-Type」的调用改成 `ap_set_content_type_ex(..., 1)` 或拷贝**当前**请求的 trusted 位。DirectoryIndex 那条间接请求在 2.4.61 上会执行 CGI，seed 再也看不到源码。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险形态是「间接请求用了 AddType，trusted 位没跟着走」。
2. 把「字面设置」的调用点都改成 trusted 之后，所有间接取出文件的路径都会带着这一位。

第二点不成立。还有一条内部跳转 **`ap_internal_fast_redirect`**，它把子请求 `rr` 的 `content_type` 抄到主请求 `r` 上，trusted 位问的却是 **`r` 自己**——跳转前主请求常常还没有 trusted 的 CGI 类型（例如 URL 没有 `.cgi` 后缀）。2.4.61 的这个函数：

```c
/* modules/http/http_request.c :: ap_internal_fast_redirect  (2.4.61 / V1) */
AP_DECLARE(void) ap_internal_fast_redirect(request_rec *rr, request_rec *r)
{
    apr_pool_join(r->pool, rr->pool);
    r->proxyreq = rr->proxyreq;
    ...
    r->filename = rr->filename;
    r->handler = rr->handler;
    ap_set_content_type_ex(r, rr->content_type, AP_REQUEST_IS_TRUSTED_CT(r));
    r->content_encoding = rr->content_encoding;
    ...
}
```

`rr->content_type` 可能已经是 `application/x-httpd-cgi` 且 `rr` 上 trusted；`r` 上那一位仍是 0。`ap_set_content_type_ex` 按第三个参数置位，于是主请求带着 CGI 类型、却标成 untrusted。

---

## 消毒之后，类型怎么接到真正的 handler 选择上

fast-redirect 一结束，后续模块看的是**主请求 `r`**：

- `r->handler` 若已被子请求填好，有机会直接走 CGI
- 遗留路径则看 `r->content_type` 是否为魔数类型 **且** `AP_REQUEST_IS_TRUSTED_CT(r)`
- 两者都不满足时，`server/core.c` 的 `default_handler`（`APR_HOOK_REALLY_LAST`）按静态文件打开 `r->filename`

```c
/* server/core.c :: default_handler  (2.4.61) */
static int default_handler(request_rec *r)
{
    conn_rec *c = r->connection;
    ...
    if (r->method_number == M_GET || r->method_number == M_POST) {
        if (r->finfo.filetype == APR_NOFILE) {
            ...
```

过滤器刚看过的是「字面 `AddType` / `ForceType` 当时那条请求的 trusted 位」；输出阶段看的是 fast-redirect **合并之后**主请求上的那一位。两套 `request_rec` 中间没有「子请求 trusted 则主请求也 trusted」的谓词。金丝雀能出现在 body 里，依据就是 `default_handler` 读了磁盘上的 `.cgi` 原文，而不是 CGI 的 STDOUT。

mod_negotiation 的 MultiViews 正是走 `ap_internal_fast_redirect` 的那类间接请求：URL `/idx/secret` 没有后缀，协商选中 `secret.cgi`，再把子请求合并进 `r`。

---

## 仓库里已经有「抄子请求 trusted」的写法，fast-redirect 抄反了

同一份 2.4.61 里，`core_override_type` 对字面类型用 `trusted=1`；其它模块在 `r1918839` 里也改成 `AP_REQUEST_IS_TRUSTED_CT` 拷贝**源**请求。fast-redirect 的源是 `rr`，目标是 `r`。正确的问法是 `AP_REQUEST_IS_TRUSTED_CT(rr)`。V1 问了 `r`。

| 位置 | 拷贝的 content_type | trusted 位问谁 |
|---|---|---|
| `core_override_type` | 配置字面量 | 恒 1 |
| `r1918839` 里多数模块 | 当前正在设置的那条请求 | 那条请求自己 |
| `ap_internal_fast_redirect`（V1） | `rr->content_type` | **`r`（主请求）** |
| 同上（V2 / `r1919249`） | `rr->content_type` | **`rr`（子请求）** |

不是没有 trusted 谓词。是 **合并两条请求时问错了对象**。DirectoryIndex 在 2.4.61 上能修好，说明那条路径碰巧让主请求也带上了 trusted，或根本不经过这个抄反的参数；MultiViews 仍走抄反的那一行。

即便没有 MultiViews，任何调用 `ap_internal_fast_redirect`、且主请求尚未 trusted 的间接取出，都会把子请求上已经正确的 CGI 类型变成 untrusted。

---

## 这个补丁挡住了什么、没挡住什么

- 2.4.61 的「字面 Content-Type 一律 trusted」：挡住 DirectoryIndex 这类会让最终请求自己带上 trusted CGI 类型的间接路径
- `ap_internal_fast_redirect(..., AP_REQUEST_IS_TRUSTED_CT(r))`：子请求的类型抄过来，trusted 仍跟主请求

只要构造一种间接请求：子请求已经是 trusted 的 `application/x-httpd-cgi`，主请求在合并前不是。MultiViews 的无后缀 URL 就是这样：

```text
GET /idx/secret

mod_negotiation:
  变体 secret.cgi，content_type = application/x-httpd-cgi，rr trusted

ap_internal_fast_redirect(rr, r)  在 2.4.61:
  r->content_type ← rr->content_type     （CGI 类型）
  trusted         ← AP_REQUEST_IS_TRUSTED_CT(r)  （主请求仍是 0）

handler 选择:
  遗留 CGI handler 因 untrusted 被跳过
  default_handler 打开 secret.cgi 原文
  body 含 # PCB-CANARY-SOURCE-ONLY PCB_FLAG=...
```

V1 改的是「谁在设置类型时要不要标 trusted」；fast-redirect **不是设置类型的人**，它是在抄别人已经设好的类型，却用自己的标志去覆盖。oss-security 2024-07-17（Eric Covener）把 2.4.61 叫 *partial fix*，建议升 2.4.62。

---

## 残余仍然走同一条「间接取出 CGI 却当静态文件」路径（CVE-2024-40725）

没有换 handler 配置、没有换文件、没有换身份。还是 `AddType application/x-httpd-cgi .cgi` 和同一份 `secret.cgi`。只是间接方式从 DirectoryIndex 换成协商：

```http
GET /idx/secret HTTP/1.1
```

`ap_internal_fast_redirect` 仍然执行；V1 那一行仍然问 `r`；`default_handler` 仍然吐源码。本 case residual 写死为 `GET /idx/secret`。和 advisory 说的 *files are requested indirectly* 同一类，只是具体前端是 MultiViews。认证意图：v1 + `--residual` 在 body 中观察到 `PCBFLAG_...`；直接 `/idx/secret.cgi` 仍只有 `CGI-EXECUTED-OK-NO-SOURCE`。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：handler 是否执行取决于合并后主请求的 trusted 位；V1 把「字面设置」标对了，却在 fast-redirect 里问错了 `request_rec`；`default_handler` 对 untrusted 的 CGI 类型按文件原文输出。seed 被挡住只说明「DirectoryIndex 这条间接请求现在会执行」，不说明「所有把子请求合并进主请求的路径都会带上子请求的 trusted 位」。

---

## 后来又补了什么（CVE-2024-40725，2.4.62）

`r1919249` 把那一个参数从 `r` 改成 `rr`。tag `2.4.62`：

```c
/* modules/http/http_request.c :: ap_internal_fast_redirect  (2.4.62 / V2) */
    r->handler = rr->handler;
    ap_set_content_type_ex(r, rr->content_type, AP_REQUEST_IS_TRUSTED_CT(rr));
    r->content_encoding = rr->content_encoding;
```

对残余输入：主请求继承子请求的 trusted 位，遗留 CGI handler 生效，脚本执行，body 没有源码注释。公开建议升级到 2.4.62。即便如此，其它「间接取出但既不经过 DirectoryIndex、也不经过这条 fast-redirect」的路径需要另证。本 benchmark 的 v2 只关闭 MultiViews 这一条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是「谁在 *set* Content-Type 时要标 trusted」。真正让源码泄露的是合并之后主请求上那一位是否仍为真。V2 只把 fast-redirect 的问对象从 `r` 换成 `rr`，没有取消「用 MIME 类型当 handler」这套遗留语义。

**不是没有 trusted 谓词。**  
`AP_REQUEST_IS_TRUSTED_CT` 和 `ap_set_content_type_ex` 在 V1 就存在，而且 `core_override_type` 已经用 trusted=1。缺的是 fast-redirect 问子请求。从 V1 的 diff 只能看到各模块的 `ap_set_content_type_ex(..., 1)`；要判断是否闭合，必须打开 `ap_internal_fast_redirect` 看第三个参数是 `r` 还是 `rr`。

**同一文件、同一 AddType，只换了 URL 有没有后缀。**  
`/idx/secret.cgi` 直接执行；`/idx/` 走 DirectoryIndex；`/idx/secret` 走协商。三种 URL 最终都想打开同一份脚本，trusted 位却按「怎么间接」分叉。

**金丝雀在源码注释里是有意的。**  
执行路径打印的字符串里没有 flag。能读到它，说明响应是文件原文，不是 CGI STDOUT。

---

## 版本、入口、参考

| | httpd | trusted 在 fast-redirect | `GET /idx/` seed | `GET /idx/secret` residual | 直接 `/idx/secret.cgi` |
|---|---|---|---|---|---|
| V0 | 2.4.60 | 间接请求普遍丢标志 | 源码泄露 | 源码泄露 | 执行，无 flag |
| V1 | 2.4.61 | `AP_REQUEST_IS_TRUSTED_CT(r)` | 执行，无 flag | 源码泄露 | 执行，无 flag |
| V2 | 2.4.62 | `AP_REQUEST_IS_TRUSTED_CT(rr)` | 挡 | 执行，无 flag | 执行，无 flag |

- Web：`GET /idx/`（DirectoryIndex）、`GET /idx/secret`（MultiViews）
- 认证意图：v0 seed body 含 flag；v1 seed 执行无 flag；v1 residual body 含 flag
- [CVE-2024-39884](https://nvd.nist.gov/vuln/detail/CVE-2024-39884)、[CVE-2024-40725](https://nvd.nist.gov/vuln/detail/CVE-2024-40725)
- 厂商页：[httpd 2.4 vulnerabilities](https://httpd.apache.org/security/vulnerabilities_24.html)
- [oss-security 2024-07-17](https://www.openwall.com/lists/oss-security/2024/07/17/6)（Covener：partial fix，升 2.4.62）
- svn：`r1918839`（2.4.61）、`r1919249`（2.4.62）；GitHub [`2.4.61` http_request.c](https://github.com/apache/httpd/blob/2.4.61/modules/http/http_request.c)
