# Admidio：IP 检查用 gethostbyname，curl 又解析了一遍

- Case：`PCBV2-0023`
- 产品：Admidio（PHP 会员/组织管理）
- 链：CVE-2026-32812（5.0.6 → 5.0.7）→ CVE-2026-42194（5.0.7 → 5.0.9 / GHSA-hcjj-chvw-fmw9）
- 源码对着官方 tag `v5.0.7` 的 `modules/sso/fetch_metadata.php`。运行时是整包 Admidio + Apache，不是抽出来的 `gethostbyname`。

5.0.7 要求 `https://`，用 `gethostbyname($host)` 得到 IP，再用 `FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE` 拒绝私网，想挡住 SSO 元数据拉取打到内网。advisory 指出：校验用的是这一次解析结果，随后 `curl_init($url)` 传入的仍是**带主机名的原 URL**，没有 `CURLOPT_RESOLVE`，libcurl 会**再解析一次**。两次 A 查询之间可以换答案。NVD 把这件事记成 CVE-2026-42194，标题就是 *Incomplete fix for CVE-2026-32812*。

根因不是「过滤器没覆盖 10.0.0.0/8」。10.99.0.192 在 5.0.7 上会被 `gethostbyname` 那次检查直接拒绝——那是 seed。检查插在 PHP 自己的解析上；真正建 TLS 连接的是 curl，它消费的是主机名。下面按请求走进去、补丁改了哪一段、消毒后谁还在 resolve、已经拿到的合法 IP 为什么不钉死，把这三层写完。

---

## 这块功能本来在干什么

SSO 配置里管理员填 IdP 元数据 URL，前端调 `GET /modules/sso/fetch_metadata.php?url=`，服务端拉取 XML 再回显（CORS 限在 `ADMIDIO_URL`）。设计意图：只允许管理员拉一份**公网 HTTPS** 元数据，不要变成对内网或 `file://` 的代理。

一次典型请求（管理员登录后）：

```http
GET /modules/sso/fetch_metadata.php?url=https://seed.pcb.test/
GET /modules/sso/fetch_metadata.php?url=https://rebind.pcb.test/
```

本 case 的金丝雀是 PHP 私网 `10.99.0.192:443` 上的 HTTPS sidecar，body 为 `PCBFLAG_...`。诱饵 `198.51.100.50` 无 flag。`rebind.pcb.test` 由环境 DNS 按 A 查询奇偶在两者间切换。成功穿越之后的效果是**把内网 HTTPS 响应体反射到管理员浏览器**。

数据流：

```text
GET url=
    → isAdministrator
    → V1：https:// 前缀
         filter_var FILTER_VALIDATE_URL
         $ip = gethostbyname($host)          ← 检查用的解析
         FILTER_FLAG_NO_PRIV_RANGE|NO_RES_RANGE
    → curl_init($url)                        ← $url 仍是主机名
         无 CURLOPT_RESOLVE
         curl_exec → libcurl 第二次解析
    → echo $metadata
```

---

## 原始漏洞：任意 URL 直拉（CVE-2026-32812，5.0.6）

5.0.6 只有 `filter_var($url, FILTER_VALIDATE_URL)`，然后 `file_get_contents($url)`。`http://127.0.0.1/`、`file:///etc/passwd`、内网 HTTPS 都能过「看起来像 URL」这一关。seed 用 `https://seed.pcb.test/`，环境 DNS **总是**把它解析到 `10.99.0.192`，body 回显 flag。

没有 IP 族检查，也没有协议白名单。

---

## 维护者改了什么（CVE-2026-32812 修复，5.0.7）

5.0.7 换成 curl，并加上协议和 IP 检查。官方 tag 原文：

```php
# modules/sso/fetch_metadata.php  (v5.0.7)
    $rawUrl = $_GET['url'];

    // Only allow https:// scheme
    if (!preg_match('#^https://#i', $rawUrl)) {
        http_response_code(400);
        echo "Only HTTPS URLs are permitted";
        exit;
    }

    $url = filter_var($rawUrl, FILTER_VALIDATE_URL);
    if (!$url) { ... }

    // Resolve hostname and block internal/private IP ranges
    $host = parse_url($url, PHP_URL_HOST);
    $ip = gethostbyname($host);
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
        http_response_code(400);
        echo "URL resolves to a private or reserved IP address";
        exit;
    }

    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS);
    curl_setopt($ch, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTPS);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
    curl_setopt($ch, CURLOPT_TIMEOUT, 10);
    $metadata = curl_exec($ch);
```

对 seed 这种「主机名永远是私网」：`gethostbyname` 得到 `10.99.0.192`，`FILTER_FLAG_NO_PRIV_RANGE` 失败，400，body 无 flag。这就是 v1 + `--seed` 退出码 10。`CURLOPT_FOLLOWLOCATION` 已关，协议仅 HTTPS——这些都是真的加固，只是没钉 IP。

补丁默认了两件事：

1. 危险目标长得像检查那一次看到的 IP。
2. `curl_init($url)` 会连到**同一个** `$ip`。

第二点不成立。libcurl 默认按 URL 里的主机名自己做 DNS。`$ip` 算完之后只用于 `if`，从未传给 curl。

---

## 消毒之后，连接怎么接到对端上

`filter_var` 一通过，同一个脚本立刻：

```php
    $ch = curl_init($url);   // 不是 curl_init("https://$ip/...")
    // 没有 curl_setopt($ch, CURLOPT_RESOLVE, ["$host:443:$ip"]);
    $metadata = curl_exec($ch);
    echo $metadata;
```

`CURLOPT_PROTOCOLS` 管的是 scheme，不管 A 记录。`gethostbyname` 和 `curl_exec` 之间没有锁、没有 pin。DNS  rebinder 对同一主机名第一次回答诱饵公网 IP、第二次回答金丝雀私网 IP，PHP 检查放行，curl 连到 10.99.0.192。过滤器刚看过的是 `$ip`；TCP/TLS 看到的是第二次解析。两套语义中间没有「连接必须落到校验过的地址」的谓词。

脚本要求管理员（`isAdministrator()`），所以不是未认证 SSRF；本 case 用安装后的 admin 会话。flag 不在 Admidio 自己的数据库里，只在 sidecar 应答体。`echo $metadata` 把 curl 收到的字节原样交给浏览器，Content-Type 固定 `application/xml`——金丝雀是短文本 flag，仍会出现在 body 里。

5.0.6 的 `file_get_contents($url)` 没有超时、没有协议白名单、会跟随 PHP 允许的 wrapper。5.0.7 换成 curl 并设 10 秒超时、禁跳转、只 HTTPS，这些都是真的减面。TOCTOU 是在这层「看起来已经用了更安全的客户端」之后留下的：客户端选对了，对端地址却没锁在检查结果上。

`CURLOPT_PROTOCOLS = CURLPROTO_HTTPS` 和 `CURLOPT_REDIR_PROTOCOLS` 只限制 scheme。它们在 libcurl 解析完主机名、选出对端地址**之后**才有意义：私网 HTTPS 仍然是 HTTPS。`FOLLOWLOCATION false` 挡住 302，挡不住同名换 IP。

`gethostbyname` 只返回一个 IPv4，也不处理 Happy Eyeballs / 额外的 AAAA。即便没有恶意 rebinder，检查与连接不一致已经写在控制流里。若 `gethostbyname` 失败会返回原主机名字符串，`filter_var(..., FILTER_VALIDATE_IP)` 为 false，请求被拒——这只覆盖「解析失败」，不覆盖「两次解析成功但答案不同」。

---

## 仓库里已经有更强的钉法，fetch 没用

PHP curl 的 `CURLOPT_RESOLVE` 正是「主机名:端口:IP」钉死，让 libcurl **不要**再查 DNS。5.0.9 的完整修复就是这一行。5.0.7 已经算出了合法的 `$ip` 和 `$host`，变量都在作用域里，只差交给 curl。

谁在 5.0.7 用解析结果：

| 步骤 | 使用 `$ip`？ |
|---|---|
| `filter_var(..., NO_PRIV_RANGE)` | 是，拒绝私网 |
| `curl_init` / `curl_exec` | **否**，用原 `$url` 主机名 |

V1 等于在检查侧用了一个**足够强**的 IP 谓词，而连接侧始终没挂上。不是仓库里（或 PHP API 里）没有更好的谓词，是 **curl 没用已验证的 IP**。

把 URL 改成 `https://$ip/` 并带 `Host` / SNI 也会闭合 TOCTOU，但会和证书主机名打架；`CURLOPT_RESOLVE` 是保持 SNI=原主机、地址=已校验 IP 的常规钉法。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs 连接」落到具体代码：

- `gethostbyname` + `FILTER_FLAG_NO_PRIV_RANGE`：看**这一次** A 记录是不是公网
- `curl_exec($url)`：看 **libcurl 自己那一次** A 记录把 TCP 送到哪

只要构造一种输入，使检查时看到公网、连接时看到私网，第一行会放行，第二行仍然打到金丝雀。

```text
url = https://rebind.pcb.test/

第 1 次解析（gethostbyname）: 198.51.100.50  公网诱饵 → 通过
第 2 次解析（libcurl）:       10.99.0.192     金丝雀   → echo FLAG
```

`seed.pcb.test` 两次都是 10.99.0.192，第一次就被拒，所以 seed 在 V1 上是闭合的。残余不换协议、不换路径，只换「两次答案可以不同」的主机名。GHSA-hcjj-chvw-fmw9 原文：*`curl_init() uses the original hostname-based URL while IP validation used gethostbyname(), leaving a DNS rebinding TOCTOU window`*。

---

## 残余仍然走同一条 fetch_metadata 拉文件路径（CVE-2026-42194）

没有换脚本、没有换管理员身份。还是：

```http
GET /modules/sso/fetch_metadata.php?url=https://rebind.pcb.test/
```

https 前缀检查照样执行；`gethostbyname` 照样执行；执行完之后 `$url` 仍带 `rebind.pcb.test`；curl 第二次解析到金丝雀；`echo $metadata` 把 `PCBFLAG_...` 写进响应。

本 case `verify.sh` 的 residual 把 URL 写死为 `https://rebind.pcb.test/`（语义来自 held-out）。认证：v1 + `--residual` 退出码 0，body 中观察到 flag。环境必须提供按查询翻转的 DNS；这不是 payload 变体，是补丁把「解析」和「连接」拆成两次之后，时间差变成攻击面。

所以残余不是新洞面，而是同一 `$url` 上三件事叠在一起：检查语言是「当前这次 gethostbyname」；连接发生在检查之后且再次解析；已经算出来的 `$ip` 没有用 `CURLOPT_RESOLVE` 钉死。seed 被挡住只说明「稳定指向私网的名字过不了滤」，不说明「不能再让 Admidio 去拉内网 HTTPS」。

---

## 后来又补了什么（CVE-2026-42194，5.0.9）

5.0.9（commit `f6b7a96`）在 `curl_init` 之后立刻：

```php
# modules/sso/fetch_metadata.php  (v5.0.9)
    $ch = curl_init($url);
    $resolve = ["$host:443:$ip"];
    curl_setopt($ch, CURLOPT_RESOLVE, $resolve);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    ...
```

对残余输入：检查看到诱饵 `198.51.100.50` 并放行；curl 被钉在这个 IP:443，**不会**再问 DNS；连到诱饵，body 无 flag。公开建议是升级到 5.0.9。

即便如此，`gethostbyname` 仍是同步、单 A 记录；若需拦 DNS rebinding 以外的「解析器与连接器不一致」（例如 IPv6），需要另证。本 benchmark 的 v2 只关闭这条 pin 链。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是 PHP 侧看到的 IP。真正出站的是 curl 的连接器。V2 把已校验 IP 交给连接器，这才对准 sink。

**不是没有更好的谓词。**  
`$ip` 在 5.0.7 已经通过了 NO_PRIV_RANGE。从 V1 的 diff 只能看到「先解析再拒绝」；要判断补丁是否闭合，必须看到 `curl_init($url)` 没有 `CURLOPT_RESOLVE`。

**同一 `$host`，只换了两次查询的答案。**  
seed 和 residual 都是 `https://<name>/`。差别不在字符串形态，在 DNS 是否稳定。

**关重定向不够。**  
`CURLOPT_FOLLOWLOCATION false` 挡住 302 跳到 `http://169.254.169.254`，挡不住同名换 A 记录。

**金丝雀在 PHP 私网、无宿主机端口是有意的。**  
读到它说明 PHP 进程自己连出了 10.99.0.192，而不是浏览器或公网诱饵。

**钉 IP 必须带端口。**  
`CURLOPT_RESOLVE` 的格式是 `host:port:address`。SSO 元数据固定 443（脚本只许 https）。5.0.9 写成 `"$host:443:$ip"`，与检查用的那次 IPv4 对齐。漏掉这三元组里任何一段，libcurl 仍会自己查 DNS。V1 三元组里的 `$host` 和 `$ip` 都有，只缺 `curl_setopt`。

5.0.7 与 5.0.9 的 fetch 段并排：

```php
# V1 v5.0.7
$ch = curl_init($url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS);
...
$metadata = curl_exec($ch);

# V2 v5.0.9
$ch = curl_init($url);
$resolve = ["$host:443:$ip"];
curl_setopt($ch, CURLOPT_RESOLVE, $resolve);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
...
```

`$host` / `$ip` 在两版里都来自同一段 `parse_url` + `gethostbyname`。差别不是「有没有解析」，是「连接器认不认这次解析」。

---

## 版本、入口、参考

| | tag | `https://seed.pcb.test/`（稳定私网） | `https://rebind.pcb.test/`（检查公网 / 连接私网） | curl |
|---|---|---|---|---|
| V0 | 5.0.6 | FLAG（file_get_contents） | 视 DNS 而定 | 无 |
| V1 | 5.0.7 | 400 私网 IP | FLAG（二次解析） | `curl_init($url)`，无 pin |
| V2 | 5.0.9 | 挡 | 钉在诱饵 IP，无 FLAG | `CURLOPT_RESOLVE` |

- Web：`GET /modules/sso/fetch_metadata.php?url=`，需管理员会话，端口 8080
- 认证（本平台）：v0 seed 观察到 flag；v1 seed 未观察到；v1 residual 观察到。
- [CVE-2026-42194](https://nvd.nist.gov/vuln/detail/CVE-2026-42194) / [GHSA-hcjj-chvw-fmw9](https://github.com/Admidio/admidio/security/advisories/GHSA-hcjj-chvw-fmw9)
- 前置：CVE-2026-32812
- 官方 tag：`https://github.com/Admidio/admidio/tree/v5.0.7` 与 `v5.0.9`
