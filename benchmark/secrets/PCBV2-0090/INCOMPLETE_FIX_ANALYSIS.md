# Craft CMS 5.8.22：`gethostbyname` 查过一遍，Guzzle 自己再解析一遍

- Case：`PCBV2-0090`（`craft-cms-cve-2026-27127`）
- 产品：Craft CMS。本 case 用 composer 安装的 `craftcms/cms` 5.8.20 / 5.8.22 / 5.8.23 + 真实 MariaDB，GraphQL `save_pcbvol_Asset(_file.url)` 走应用自己的 Guzzle 拉取。
- 链：CVE-2025-68437（≤5.8.20 → 5.8.21/5.8.22，commit `013db63`，GHSA-x27p-wfqw-hfcc）→ CVE-2026-27127（5.8.22 → 5.8.23，commit `a4cf3fb`，GHSA-gp2f-7wcm-5fhx）
- 源码对着 GitHub tag `5.8.22` 的 `src/gql/resolvers/mutations/Asset.php`：`handleUpload`、`validateHostname`、`createGuzzleClient`。V2 对着 commit `a4cf3fb` 的 `validateIp` + `RequestOptions::ON_STATS`。运行时是整包 CMS，不是抽出来的函数。

2025 年 12 月，Craft 给 GraphQL 资源上传的 `_file.url` 加了 `validateHostname`：解析 host、拒绝 IP 字面量、拒绝一组 metadata 主机名，再 `gethostbyname` 对照云 metadata IP 黑名单。这挡住了「URL 直接指向 `192.0.0.192` / `seed.pcb.test`（静态解析到该 IP）」这种拉取。两个月后 advisory 写明：检查时的 DNS 和真正发 HTTP 时的 DNS **不是同一次查找**。攻击者控制的域名可以第一次答 innocuous IP、第二次答 metadata IP。NVD CVE-2026-27127：*This is a bypass of the security fix for CVE-2025-68437 ... that allows access to all blocked IPs, not just IPv6 endpoints.*

根因不只是「黑名单漏了一个 IP」。检查插在「我自己 `gethostbyname` 一次」这一层；真正把字节写进临时文件的是随后 Guzzle/libcurl 的另一次解析。下面按 mutation 走进去、5.8.22 改了哪几行、检查之后谁发起 GET、仓库里有没有把「实际连上的 IP」钉死，把这几层写完。

---

## 这块功能本来在干什么

Craft 的 GraphQL 允许有 volume 写权限的 schema 用远端 URL 创建资源：服务端把文件拉下来，存进 volume，再能通过资源 URL 读回去。一次典型请求：

```graphql
mutation {
  save_pcbvol_Asset(_file: { url: "http://example.com/pic.png", filename: "pic.png" }) {
    id
    url
  }
}
```

入口是 `POST /index.php?p=actions/graphql/api`。`Asset::saveAsset` → `populateElementWithData` → `handleUpload`。`_file.url` 是用户字符串。

设计意图：URL 必须是「普通公网文件」，不能是云 metadata 或内网。成功穿越之后的效果是：**Craft 服务端对攻击者指定的地址发了 GET，响应体作为资源保存，随后可被读出**。本 case 的金丝雀在内部 sidecar `192.0.0.192`（Oracle metadata 风格地址）上，不在 Craft 进程里。

数据流：

```text
GraphQL _file.url
    → handleUpload
         V1：validateHostname($url)
              parse_url HOST
              hex 段规范化
              FILTER_VALIDATE_DOMAIN，拒绝 IP 字面量
              metadata 主机名列表
              gethostbyname($hostname)          ← 补丁的 CHECK
              in_array($ip, metadata IPv4 表)
         createGuzzleClient()->request('GET', $url, SINK)
              libcurl 再解析同一 host            ← 真正的 FETCH
         字节写入 tempFilePath，保存为 Asset
    → 再 GET 资源 URL，body 里出现 flag
```

需要 GraphQL schema 对该 volume 的 create/save。本 case 通过 Craft 自己的服务层把 public schema 打开到这条 mutation。

---

## 原始漏洞：URL 原样 GET（CVE-2025-68437，5.8.20）

5.8.20 的 `handleUpload` 在 `url` 分支里没有任何 host 检查：

```php
# src/gql/resolvers/mutations/Asset.php :: handleUpload  (5.8.20 语义)
} elseif (!empty($fileInformation['url'])) {
    $url = $fileInformation['url'];
    // ... 只准备 filename / extension ...
    $tempPath = AssetsHelper::tempFilePath($extension);
    $this->createGuzzleClient()->request('GET', $url, [
        'sink' => $tempPath,
    ]);
}
```

NVD：*`_file` input, specifically its `url` parameter, allows the server to fetch content from arbitrary remote locations without proper validation*。本 case 的 seed：

```text
url = http://seed.pcb.test/flag
```

环境 DNS 把 `seed.pcb.test` **始终** 解析到 canary `192.0.0.192`。5.8.20 直接 GET，资源内容就是 `PCBFLAG_...`。这就是 v0 + `--seed` 退出码 0。

---

## 维护者改了什么（CVE-2025-68437 修复，5.8.21 / 5.8.22）

5.8.21（commit `013db636fdb38f3ce5657fd196b6d952f98ebc52`）先加了「必须是域名、不能是 IP 字面量」。5.8.22 补上 metadata 主机名表和 `gethostbyname` + IPv4 黑名单。本 case 的 V1 是 5.8.22，tag 上的函数如下。

`handleUpload` 在发 GET **之前** 调用 `validateHostname`：

```php
# src/gql/resolvers/mutations/Asset.php :: handleUpload  (5.8.22)
        } elseif (!empty($fileInformation['url'])) {
            $url = $fileInformation['url'];

            if (!$this->validateHostname($url)) {
                throw new UserError("$url contains an invalid hostname.");
            }
            ...
            $this->createGuzzleClient()->request('GET', $url, [
                RequestOptions::ALLOW_REDIRECTS => false,
                RequestOptions::SINK => $tempPath,
            ]);
```

`validateHostname` 的后半段才是和 IP 黑名单有关的部分：

```php
# src/gql/resolvers/mutations/Asset.php :: validateHostname  (5.8.22)
        // make sure the hostname doesn’t resolve to a known cloud metadata IP
        $ip = gethostbyname($hostname);

        if (in_array($ip, [
            '169.254.169.254',
            '169.254.170.2',
            '169.254.169.254',
            '100.100.100.200',
            '192.0.0.192',
        ])) {
            return false;
        }

        return true;
```

前面还有：hex 形式的点分十进制、`FILTER_VALIDATE_DOMAIN`、`FILTER_VALIDATE_IP` 拒绝字面量、以及 `metadata` / `metadata.google.internal` 等主机名列表。这些都只看 **字符串形态的 host** 或 **这一次** `gethostbyname` 的返回值。

对 seed 这种「host 静态解析到 `192.0.0.192`」的写法，它确实够用：

```text
gethostbyname('seed.pcb.test') = 192.0.0.192
in_array → true → validateHostname false
UserError: contains an invalid hostname.
```

Guzzle 那一行根本不会执行。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险目标在检查时的 A 记录里就会露出来，而且和稍后连接用的地址相同。
2. `gethostbyname` 的返回值足以代表「即将连上的那台机器」。

两件事在攻击者控制 DNS 时都不成立。更关键的是：`request('GET', $url)` 拿到的仍是 **原始 URL 字符串**，不是检查时钉死的 IP。libcurl 会自己再查一次 DNS。

---

## 检查之后谁真正消费那个值

`validateHostname` 返回 true 之后，同一个 `$url` 原样进 Guzzle：

```php
# handleUpload  (5.8.22，紧接在 validateHostname 之后)
            $this->createGuzzleClient()->request('GET', $url, [
                RequestOptions::ALLOW_REDIRECTS => false,
                RequestOptions::SINK => $tempPath,
            ]);
```

`createGuzzleClient()` 是 `Craft::createGuzzleClient()`，没有 `CURLOPT_RESOLVE`，没有把 `$ip` 写进请求。Guzzle 把 host 交给 libcurl；libcurl 调用 `getaddrinfo`（或 c-ares），得到 **另一份** A/AAAA，再 TCP 连接、把 body 写进 `$tempPath`。

PHP 文档对 `gethostbyname` 的语义是「取 IPv4 地址」。Guzzle 的解析器是完整的 `getaddrinfo`。即便两次都只查 A，只要中间 TTL 到期或权威服务器按查询次数轮换答案，两次结果也可以不同。

过滤器刚看过的是「这一次 gethostbyname 的字符串」；open/fetch 看到的是「libcurl 解析出来的 primary_ip」。两套 DNS 中间没有第二次谓词，也没有把第一次的 IP pin 到第二次。

资源保存之后，攻击者再通过 Craft 的资源 URL 把 `$tempPath` 里的字节读回来。金丝雀出现在 body 里，依据是这次服务端 GET，而不是 GraphQL 响应碰巧包含了 URL 字符串。

---

## 仓库里已经能拿到「真正连上的 IP」，5.8.22 没用

Guzzle 的 `RequestOptions::ON_STATS` 在传输结束（或可在回调里看到 handler stat）时给出 `TransferStats`。`getHandlerStat('primary_ip')` 就是 libcurl 实际拨号的地址。5.8.23 的修复正是把黑名单挂在这个值上。

5.8.22 的 `handleUpload` **没有** `ON_STATS`，也没有 `validateIp`。`createGuzzleClient` 不接收已解析 IP。同一文件里已经有「不许连这些 IP」的表，却只拿去和 `gethostbyname` 的返回值比较。

GHSA-gp2f-7wcm-5fhx 甚至写了另一种钉死方式：`CURLOPT_RESOLVE => ["$hostname:80:$ip"]`，让检查和请求共用同一 IP。5.8.22 两样都没挂。不是仓库里没有「按实际连接地址判断」这条路，是 **CHECK 和 FETCH 各查一次 DNS**。

兄弟 CVE-2026-27129 会说明：即便不 rebind，`gethostbyname` 对 AAAA-only 主机还会返回主机名字符串本身。那是同一谓词的另一条盲区；本 case 的 residual 走的是两次 A 记录不同。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「检查时的 DNS vs 连接时的 DNS」落到具体字符串：

- `validateHostname`：`gethostbyname(host)` ∈ `{169.254.169.254, 169.254.170.2, 100.100.100.200, 192.0.0.192}` 则拒绝
- Guzzle `request('GET', $url)`：对 **同一个 host 字符串** 再解析，连上哪个 IP 由第二次查找决定

只要构造一种 DNS，使第一次查找落到黑名单之外、第二次落到 canary，第一行会放行，第二行仍然 GET 到 metadata。

本 case 环境里的 `rebind.pcb.test` 由 sidecar 按 A 查询次数翻转：

```text
奇数次（CHECK，validateHostname 的 gethostbyname）
    rebind.pcb.test → 192.0.0.50     （decoy，不在黑名单）

偶数次（FETCH，libcurl）
    rebind.pcb.test → 192.0.0.192    （canary，在黑名单，但此时已经过了检查）
```

URL 两边完全相同：

```text
url = http://rebind.pcb.test/flag
```

没有换 mutation、没有换 `_file.url` 字段、没有把 host 写成 IP 字面量（字面量会被 `FILTER_VALIDATE_IP` 挡掉）。变化的只是 **同一名字在两次查找中的 A 记录**。

V1 认为自己已经确认「这个 host 不是 metadata」。实际上它确认的是「几毫秒前的那一次 IPv4 查找不是 metadata」，而文件内容来自另一次查找。

---

## 残余仍然走同一条 Asset URL 拉取（CVE-2026-27127）

还是：

```http
POST /index.php?p=actions/graphql/api
mutation save_pcbvol_Asset(_file:{url:"http://rebind.pcb.test/flag", filename:"..."})
```

`handleUpload` 仍然先 `validateHostname` 再 Guzzle GET。V1 那一次 `gethostbyname` 看到 decoy，返回 true；Guzzle 看到 canary，把 flag 写进 temp 文件；随后读资源得到 `PCBFLAG_...`。

认证：v1 + `--residual` 退出码 0。repro 里 DNS sidecar 日志对得上：v1 每个请求两次 A 查询（CHECK→decoy，FETCH→canary）。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：检查用的解析器和连接用的解析器不是同一次；黑名单只套在检查结果上；真正写磁盘的 GET 不再看那张表。seed 被挡住只说明「静态解析到 192.0.0.192 的名字过不了 gethostbyname」，不说明「不能再让 Craft 去拉 metadata」。

平台 verify 的 residual 与 heldout 是同一 sink（GraphQL Asset `_file.url` → Guzzle SINK）。和 seed 的差别只在 DNS 行为。

---

## 后来又补了什么（CVE-2026-27127，5.8.23）

commit `a4cf3fb63bba3249cf1e2882b18a2d29e77a8575` 做了两件事：

1. `validateHostname` **不再** `gethostbyname`、不再比 IPv4 黑名单（仍拒绝 IP 字面量和 metadata 主机名），末尾直接 `return true`。
2. `handleUpload` 的 Guzzle 请求加上 `ON_STATS`，用 **实际 primary_ip** 调新的 `validateIp`。

```php
# 5.8.23 handleUpload
    $this->createGuzzleClient()->request('GET', $url, [
        RequestOptions::ALLOW_REDIRECTS => false,
        RequestOptions::SINK => $tempPath,
        RequestOptions::ON_STATS => function(TransferStats $stats) use ($url) {
            if (!$this->validateIp($stats->getHandlerStat('primary_ip'))) {
                throw new UserError("$url resolves to an invalid IP address.");
            }
        },
    ]);
```

```php
# 5.8.23 validateIp
    private function validateIp(string $ip): bool
    {
        if (in_array($ip, [
            '169.254.169.254',
            '169.254.170.2',
            '100.100.100.200',
            '192.0.0.192',
        ])) {
            return false;
        }
        return true;
    }
```

对残余：无论 CHECK 还是 FETCH，v2 的 `validateHostname` 不再查 DNS（所以每个请求只剩 libcurl 那一次查找）。那一次若连上 `192.0.0.192`，`validateIp` 拒绝，错误是 `resolves to an invalid IP address`。环境里 decoy `192.0.0.50` 不在表里——若 DNS 只答 decoy，连接会成功但读不到 flag。canary 被钉在实际连接 IP 上。

同一天的兄弟补丁 `2825388` 还给 `validateIp` 加了 IPv6 前缀表（见 PCBV2-0091）。本 case 的 v2 镜像是 5.8.23，两处都在。

---

## 从这条链还能看出什么

**维护者改错了哪一层。**  
他们改的是「发请求之前我自己查一次 A」。真正决定连谁的是 libcurl。V2 把谓词移到 `primary_ip`。

**不是没有更好的钉死方式。**  
`ON_STATS` / `CURLOPT_RESOLVE` 都能让「检查的 IP」和「连接的 IP」变成同一个值。5.8.22 只做了前一次查找。

**同一 `$url`，只换了 DNS 答案。**  
seed 和 residual 都是 `http://<name>/flag` + 同一 mutation。差别不在 payload 语法，在解析次数。

**黑名单是 IPv4 字面量表。**  
它既不覆盖 AAAA（27129），也不覆盖「检查时不是这些地址、连接时是」的时序。把表挂在错误的时间点上，表本身再完整也会被 rebind 翻过去。

**金丝雀在 Craft 之外是有意的。**  
`192.0.0.192` 没有对 host 暴露端口。能读到 flag，说明是 Craft 进程出站 GET 到了 sidecar，而不是应用本地文件。

---

## 版本、入口、参考

| | 版本 | `validateHostname` | 实际 GET | 静态 `seed.pcb.test`→192.0.0.192 | `rebind.pcb.test` CHECK decoy / FETCH canary |
|---|---|---|---|---|---|
| V0 | 5.8.20 | 无 | 裸 Guzzle | 拉到 flag | （不必） |
| V1 | 5.8.22 | `gethostbyname` + IPv4 表 | 再解析一次，无 `ON_STATS` | `invalid hostname` | 拉到 flag |
| V2 | 5.8.23 | 不再解析 | `ON_STATS` → `validateIp(primary_ip)` | `invalid IP`（若连上 canary） | `invalid IP` |

- Web：`POST /index.php?p=actions/graphql/api`，mutation `save_<Volume>_Asset(_file:{url})`
- 认证：v0 seed 观察到 flag；v1 seed 未观察到；v1 residual 观察到
- [CVE-2025-68437](https://nvd.nist.gov/vuln/detail/CVE-2025-68437)、[CVE-2026-27127](https://nvd.nist.gov/vuln/detail/CVE-2026-27127)
- [GHSA-x27p-wfqw-hfcc](https://github.com/craftcms/cms/security/advisories/GHSA-x27p-wfqw-hfcc)、[GHSA-gp2f-7wcm-5fhx](https://github.com/advisories/GHSA-gp2f-7wcm-5fhx)
- V1 源码：[Asset.php @ 5.8.22](https://github.com/craftcms/cms/blob/5.8.22/src/gql/resolvers/mutations/Asset.php)
- V2：[commit a4cf3fb](https://github.com/craftcms/cms/commit/a4cf3fb63bba3249cf1e2882b18a2d29e77a8575)
