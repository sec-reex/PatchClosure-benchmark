# NukeSentinel：IP 正则只锚了开头，Client-IP 后面的 SQL 照样进 INSERT

- Case：`PCBV2-0154`
- 产品：NukeSentinel（PHP-Nuke 的入侵防护插件）。真实入口是 `includes/nukesentinel.php` 读 `Client-IP`，再把值插进 `_nsnst_tracked_ips`。本平台认证被 SourceForge Cloudflare 403 挡住，拿不到发行 tarball；下文对着本地 `patch.diff`（2.5.05→2.5.06）和公开 advisory / Bugtraq / VIM 写，没有去 docker-build PHP-Nuke。
- 链：CVE-2007-1172（2.5.05 → 2.5.06）→ CVE-2007-1493（2.5.06 → 2.5.07）
- NVD 对 CVE-2007-1493 的原话：*uses a permissive regular expression to validate an IP address … due to an incomplete patch for CVE-2007-1172*。MITRE VIM（2007-03-14）写得更具体：2.5.06 的 `ereg("^([0-9]{1,3}\\.){3}[0-9]{1,3}"` 只保证**开头**像 IP，新 exploit 于是「在 SQL 前面垫一段 dotted-quad」。

根因不只是「正则写松了」。检查插在字符串 `$nsnst_const['client_ip']` 上；真正进 MySQL 的是后面那条 14 列 `INSERT`，对同一个变量做裸拼接。同一次 2.5.06 补丁已经给 `abget_blocked()` 的四个八位加了 `intval()`，却没用在 INSERT 那条路上。下面按请求走进去。

NVD 的 [CVE-2005-1023](https://nvd.nist.gov/vuln/detail/CVE-2005-1023) 是 PHP-Nuke 6.x–7.6 的 XSS（Search 的 `min`、FAQ 的 `categories`、Encyclopedia 的 `ltr`），**不是**这条 Client-IP SQLi。NukeSentinel 要防的是 PHP-Nuke 长期信任 `Client-IP` / `X-Forwarded-For` 的那一类头；公开 incomplete-fix 配对是 1172 → 1493。

---

## 这块功能本来在干什么

NukeSentinel 挂在几乎每个 PHP-Nuke 页面前面。它从一组 HTTP 头里取出「客户端 IP」，用来：查黑名单、写访问跟踪表、按国家码分类。一次典型请求：

```http
GET /index.php HTTP/1.1
Client-IP: 203.0.113.10
```

`nukesentinel.php` 一进来就填 `$nsnst_const`：

```php
# includes/nukesentinel.php  （2.5.05 / 2.5.06 同一组取值函数）
$nsnst_const['server_ip']  = get_server_ip();
$nsnst_const['client_ip']  = get_client_ip();   // HTTP_CLIENT_IP
$nsnst_const['forward_ip'] = get_x_forwarded(); // HTTP_X_FORWARDED_FOR
$nsnst_const['remote_addr'] = get_remote_addr();
$nsnst_const['remote_ip']  = get_ip();          // 优先 client_ip，否则 forward_ip，否则 REMOTE_ADDR
```

`get_ip()` 还会按 `', '`（逗号+空格）拆代理链，取第一段非 reserved 的地址。设计意图：这些字段是点分十进制 IPv4，随后可以安全地写进 SQL。成功穿越之后的效果是：**把任意 SQL 拼进 `_nsnst_tracked_ips` 的 VALUES，用子查询把库里另一张表的行读出来**。本 case 的金丝雀在 `pcb_secret.secret`，反射到跟踪表的 `client_ip` 列，再被页面读回。

数据流：

```text
HTTP Client-IP
    → get_client_ip() / get_ip()
    → V1：ereg("^([0-9]{1,3}\\.){3}[0-9]{1,3}", $client_ip)
         失败则改写成 "none"
    → 14 列 INSERT INTO nuke_nsnst_tracked_ips
         ... VALUES (..., '$remote_ip', ...)     ← 裸拼接，不再查 IP
    → 页面 SELECT 刚插入的行 → HTTP body
```

没有登录。`track_active=1` 时跟踪 INSERT 必跑。没有「这个头只能是 IP」的类型层，只有那一行 `ereg`。

---

## 原始漏洞：子串里有点分数字就算 IP（CVE-2007-1172，2.5.05）

2.5.05 的检查在填完常量**之后**才做，而且**两端都不锚**：

```php
# nukesentinel.php  2.5.05（约 L70 附近，patch.diff 删除的那四行）
if(!ereg("([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3})", $nsnst_const['client_ip']))
  { $nsnst_const['client_ip'] = "none"; }
# forward_ip / remote_ip / remote_addr 同样四份
```

`ereg` 在 PHP 5 里是 POSIX 正则、默认**搜索**而不是整串匹配。任意位置出现 `1.2.3.4` 就过。2007-02-20 Bugtraq「NukeSentinel 2.5.05 File Disclosure Exploit」（NVD 记成 CVE-2007-1172）的 Client-IP 是：

```text
' UNION SELECT 1,2,3,...#255.255.255.255
```

引号先闭合 `ip_addr`，UNION 改写后面的查询；点分地址放在 `#` 注释里，专门喂给这行不锚的 `ereg`。同一条链还能打 `_nsnst_blocked_ips` / `_nsnst_blockers`（`abget_blocked` 把 IP 按 `.` 切开再拼进 SELECT）。

本 case 的 seed 对着跟踪表的 14 列 INSERT，不走文件披露那条 UNION。payload **不以 IP 开头**，把 `1.2.3.4` 放在 SQL 注释末尾，正好满足 V0 的子串匹配：

```text
Client-IP: ','0','/','x','x','x',(SELECT secret FROM pcb_secret LIMIT 1),'x','x','x','x')-- 1.2.3.4
```

（不能写成 `, `，因为 `get_ip()` 会按逗号空格拆代理链。）V0 看到注释里的 `1.2.3.4`，放行；INSERT 把子查询结果写进 `client_ip` 列。这就是 v0 + `--seed` 能读到 `PCBFLAG_...` 的原因。

---

## 维护者改了什么（CVE-2007-1172 修复，2.5.06）

2.5.06 把那四行检查**提前**到取值函数返回之后立刻执行，并加上 `^`：

```php
# V0  2.5.05                         （子串匹配，位置靠后）
$nsnst_const['client_ip'] = get_client_ip();
# … 中间还填别的常量 …
if(!ereg("([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3})", $nsnst_const['client_ip']))
  { $nsnst_const['client_ip'] = "none"; }

# V1  2.5.06                         （本 case 的目标）
$nsnst_const['client_ip'] = get_client_ip();
if(!ereg("^([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3})", $nsnst_const['client_ip']))
  { $nsnst_const['client_ip'] = "none"; }

# V2  2.5.07                         （CVE-2007-1493）
# 同一行，末尾多一个 $
if(!ereg("^([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3})$", ...))
```

V1 正则的字面意思：

| 片段 | 含义 |
|---|---|
| `^` | 必须从字符串开头配 |
| `([0-9]{1,3}\\.){3}[0-9]{1,3}` | 四段 1–3 位数字，中间三个点 |
| （没有 `$`） | **后面随便什么都可以** |
| 没有 `^...$`、没有 `ip2long`、没有预处理成四个 `intval` |

对 seed 这种「先引号、IP 在注释里」的写法，它确实够用：字符串不以数字开头，整段被改成 `"none"`，INSERT 写不进子查询。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险输入长得不像「从第一个字符开始的点分 IP」。
2. 只要开头像 IP，整段就可以当 IP 用。

第二点不成立。更关键的是：这一行之后，代码仍然把**原字符串**（不是四个 octet）拼进 SQL，而且那次拼接**不再做任何转义**。

---

## 消毒之后，这个值怎么接到 SQL 上

V1 的 `ereg` 一结束，同一个请求稍后进入跟踪写入（约 L458，三条版本的 INSERT **字节级相同**）：

```sql
INSERT INTO `nuke_nsnst_tracked_ips`
  (user_id, username, date, ip_addr, ip_long, page,
   user_agent, refered_from, x_forward_for, client_ip,
   remote_addr, remote_port, request_method, c2c)
VALUES (..., '$remote_ip', ...)
```

`$remote_ip` 来自 `$nsnst_const['remote_ip']`，而 `get_ip()` 在 `client_ip` 非空且不是 `none` 时直接返回它。过滤器刚看过的是「开头像不像 `d.d.d.d`」；MySQL 看到的是单引号字符串里的完整 header。两套语义中间没有第二次谓词。

`get_ip()` 的优先级是 `client_ip` → `forward_ip` → `remote_addr`。seed / residual 都打 `Client-IP`，所以 `remote_ip` 就是那段 header。代理链拆分（`strpos(..., ', ')`）在正则**之后**还会再跑一遍，并且 2.5.06 给拆出来的每一段又加了同样的 `^` 正则：

```php
if(strpos($nsnst_const['client_ip'], ', ') AND isset($nsnst_const['client_ip'])) {
  $client_ips = explode(', ', $nsnst_const['client_ip']);
  if(...) {
    if(!ereg("^([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3})", $client_ips[0]))
      { $client_ips[0] = "none"; }
    $nsnst_const['client_ip'] = $client_ips[0];
  }
}
```

它防的是 `X-Forwarded-For: a, b` 这种合法链，挡不住「一段里没有逗号空格、开头是 IP、后面是 SQL」的单段 payload。payload 里写成 `','` 而不是 `', '`，就是为了不走进这个 explode。

页面读回刚插入的行。金丝雀出现在 body 里，依据是这次 INSERT + SELECT，而不是「跟踪表里碰巧有个同名 IP」。

---

## 仓库里已经有更强的检查，写路径没用

同一份 2.5.06 补丁给 `abget_blocked()` 加了四个 `intval()`：

```php
# nukesentinel.php :: abget_blocked  （2.5.06 新增）
function abget_blocked($remoteip){
  global $prefix, $db;
  $ip = explode(".", $remoteip);
  $ip[0] = (isset($ip[0])) ? intval($ip[0]) : '';
  $ip[1] = (isset($ip[1])) ? intval($ip[1]) : '';
  $ip[2] = (isset($ip[2])) ? intval($ip[2]) : '';
  $ip[3] = (isset($ip[3])) ? intval($ip[3]) : '';
  $testip1 = "$ip[0].*.*.*";
  ...
  $blocked_result = $db->sql_query("SELECT * FROM `".$prefix."_nsnst_blocked_ips` WHERE `ip_addr` = '$testip1' OR ...");
```

谁用它：

| 函数 | 对用户 IP 做什么 |
|---|---|
| `abget_blocked` | `explode` + `intval` 四个 octet，再拼进 SELECT |
| `ip2long` → `remote_long` | 把「看起来像 IP」的字符串收成无符号整数列 |
| 跟踪 INSERT 的 `ip_addr` / `client_ip` 等字符串列 | **否**，把 `$remote_ip` 原样放进 VALUES |

`intval('4','0','/')` 会变成 `4`，后面的 SQL 被丢掉——若 INSERT 也走这条规范化，残余前缀写法活不成。它只服务于黑名单 SELECT。`sprintf("%u", ip2long($nsnst_const['remote_ip']))` 在 V1 仍然对整段脏字符串调用：`ip2long('1.2.3.4\'...')` 在 PHP 里往往只吃前缀 IP，返回一个整数写进 `ip_long`，**并不**把字符串列清干净。所以「我们已经用了 ip2long」不能当成 INSERT 的卫士。

V1 等于在调用方又做了一个**更弱**的字符串前缀检查（只认开头的 `d.d.d.d`，不要求整串），而写路径上那个「只留下数字 octet」的转换始终没挂上。不是仓库里没有更好的谓词，是 **INSERT 没用**。PHP 自己还有 `ip2long()`（同文件已经用来填 `remote_long`），失败即非合法 IPv4；它也没有被当成放行条件。

即便不谈 `intval`，只要 INSERT 继续裸拼，任何让 `ereg("^d.d.d.d")` 为真、但后半段含引号的写法都会变成一次真实的 SQL 注入。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs INSERT」落到具体代码：

- V1 的 `ereg("^([0-9]{1,3}\\.){3}[0-9]{1,3}")`：看字符串**是不是以**点分四段开头
- INSERT 的 `'$remote_ip'`：看单引号字符串里**整段**是什么

只要构造一种输入，使「从左边配到四段数字」之后**还剩** SQL 元字符，第一行会放行，第二行仍然断句。

`1.2.3.4','0',...` 就是这样来的。POSIX `ereg` 没有 `$`，配完 `1.2.3.4` 就成功，后面的 `'` 不参与匹配：

```text
1.2.3.4','0','/','x','x','x',(SELECT secret FROM pcb_secret LIMIT 1),'x','x','x','x')-- -
     ↑ V1 看到这里已经匹配成功
            ↑ MySQL 看到这里闭合 ip_addr，开始注入其余列
```

VIM 2007-03-14 的原话就是：*they are checking to ensure the Client-IP HTTP Header contains a valid IP. Hence, the newer exploit code prepends a random dotted-quad IP address to the start of the SQL injection.* 2007-03-10 Bugtraq「NukeSentinel <= 2.5.06 SQL Injection」是这条残余的公开 PoC。

---

## 残余仍然走同一条跟踪 INSERT（CVE-2007-1493）

没有换 header、没有换表、没有换身份。还是：

```http
GET /index.php HTTP/1.1
Client-IP: 1.2.3.4','0','/','x','x','x',(SELECT secret FROM pcb_secret LIMIT 1),'x','x','x','x')-- -
```

`get_client_ip()` 仍然返回整段 header。V1 那一行 `^` 正则照样执行；执行完之后 `$client_ip` 仍是带引号的 SQL；`get_ip()` 把它当成 `remote_ip`；INSERT 拼进 VALUES；页面读回 `client_ip` 列里的金丝雀。

公开残余和 seed 是同一 sink。seed 被挡住只说明「不以 IP 开头的 payload 没了」，不说明「不能再从 Client-IP 往跟踪表里注入」。

本平台认证因 SourceForge 403 未跑通；上述差分来自 `patch.diff` 与 NVD/VIM，而不是 `verify.sh` 的字面量。

---

## 后来又补了什么（CVE-2007-1493，2.5.07）

2.5.07 把同一行换成**整串**匹配：

```php
- if(!ereg("^([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3})", $nsnst_const['client_ip']))
+ if(!ereg("^([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3})$", $nsnst_const['client_ip']))
```

对残余输入，末尾的 `','0',...` 让 `$` 失败，值被改成 `"none"`，子查询进不了 INSERT。公开建议是升级到 NukeSentinel 2.5.07。

即便如此，这仍然是「在拼 SQL 之前用正则近似 IP」，INSERT 还是不做 quoting / `intval`。对「IP 前缀 + 尾巴」这条已知链它够用；octet 溢出（`999.999.999.999`）或 IPv6 形态需要另证。本 benchmark 的 v2 只关闭这一条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是 `$nsnst_const['client_ip']` 入口的字符串形状。真正出数据的是跟踪 INSERT 的 `'$remote_ip'`。V2 仍在同一层加 `$`，没有把写路径接到已经存在的 `intval` octet 规范化，也没有 `mysql_real_escape_string`。

**不是没有更好的谓词。**  
`abget_blocked` 的 `intval` 四个 octet、以及同文件已经在用的 `ip2long`，都比「开头像 IP」更接近「这是一个 IPv4」。它们已经用在黑名单查询或整数列上。跟踪穿越走的是 INSERT。从 V1 的 diff 只能看到加了 `^`；要判断补丁是否闭合，必须看到 INSERT 的拼接和 `abget_blocked` 的调用点。

**同一函数、同一 `$remote_ip`，只换了 header 的写法。**  
任何把用户字符串放进 `$nsnst_const['client_ip']` 的头（`Client-IP`、`X-Forwarded-For`、`X-Forwarded`、`Remote-Addr` 在这份代码里都会进同一组 `ereg`），在 2.5.06 上都吃这一行正则和同一次 INSERT。advisory 已指出 2.5.06 及更早受影响。

**正则语言比 SQL 字符串语义窄。**  
`^d.d.d.d` 回答的是「前缀像地址」；MySQL 单引号字符串回答的是「哪里结束」。两者只在「整串恰好是地址」时重合。

---

## 版本、入口、参考

| | 版本 | IP 谓词 | 跟踪 INSERT | 注释里夹 IP 的 seed | IP 前缀 + SQL 的 residual |
|---|---|---|---|---|---|
| V0 | 2.5.05 | 不锚的子串 `ereg` | 裸拼 `$remote_ip` | 读到金丝雀 | （不必） |
| V1 | 2.5.06 | `^` 前缀，无 `$` | 同上，仍不 `intval` | 改写成 `none` | 读到金丝雀 |
| V2 | 2.5.07 | `^...$` 整串 | 同上 | 挡 | 尾巴让 `$` 失败，挡 |

- Web：`GET /index.php` + `Client-IP: ...`（PHP-Nuke 任意页 include `nukesentinel.php` 同样触发）
- 本平台认证：SourceForge Cloudflare 403，未 certify。分析来自 `patch.diff` + 公开 CVE 文本，不是运行时 `verify.sh`。
- [CVE-2007-1172](https://nvd.nist.gov/vuln/detail/CVE-2007-1172)、[CVE-2007-1493](https://nvd.nist.gov/vuln/detail/CVE-2007-1493)
- [CVE-2005-1023](https://nvd.nist.gov/vuln/detail/CVE-2005-1023)（PHP-Nuke XSS，与本链无关，已核对）
- [VIM 2007-03-14](https://attrition.org/pipermail/vim/2007-March/001429.html)（写明 2.5.06 弱 `^` 正则与「IP 前缀」bypass）
- [Bugtraq 2007-02-20](https://lists.openwall.net/bugtraq/2007/02/20/5)（CVE-2007-1172 File Disclosure）
- [Bugtraq 2007-03-10](http://www.securityfocus.com/archive/1/462453/100/0/threaded)（CVE-2007-1493，≤2.5.06）
- V1 源：本地 `patch.diff` 中的 `nukesentinel-2.5.06.php` 片段（发行包 `NukeSentinel_2506_70-80.tar.gz`）；无法从 SourceForge 再拉 blob
