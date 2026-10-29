# Craft CMS 5.8.22：`gethostbyname` 只认 A 记录，AAAA-only 的 host 变成「字符串过了黑名单」

- Case：`PCBV2-0091`（`craft-cms-cve-2026-27129`）
- 产品：Craft CMS。本 case 用 composer 安装的 `craftcms/cms` 5.8.20 / 5.8.22 / 5.8.23 + MariaDB，GraphQL `save_pcbvol_Asset(_file.url)` 走应用自己的 Guzzle。网络是双栈（`192.0.0.0/24` + `fd00:ec2::/64`）。
- 链：CVE-2025-68437（≤5.8.20 → 5.8.21/5.8.22，commit `013db63`，GHSA-x27p-wfqw-hfcc）→ CVE-2026-27129（5.8.22 → 5.8.23，commit `2825388`，GHSA-v2gc-rm6g-wrw9）
- 源码对着 GitHub tag `5.8.22` 的 `src/gql/resolvers/mutations/Asset.php`：`validateHostname`、`handleUpload`。V2 对着 `validateIp` 的 IPv6 前缀表。运行时是整包 CMS。与 PCBV2-0090 共用同一 V1 补丁、同一 GET sink，残余走的是解析器地址族而不是 DNS 时序。

CVE-2025-68437 的修复用 PHP `gethostbyname($hostname)` 把主机名变成 IPv4，再和 `{169.254.169.254, 169.254.170.2, 100.100.100.200, 192.0.0.192}` 比较。PHP 手册写得很清楚：*Get the IPv4 address corresponding to a given Internet host name*。主机只有 AAAA、没有 A 时，查找失败，函数返回 **未修改的主机名字符串**。字符串当然不在那张数字 IP 表里，检查放行；Guzzle/libcurl 用 `getaddrinfo` 看到 AAAA，连到 IPv6 metadata。GHSA-v2gc-rm6g-wrw9：*This is a bypass of the security fix for CVE-2025-68437*。

根因不只是「黑名单漏了 IPv6」。检查插在「IPv4 查找的返回值」上；真正拨号的是完整解析器。下面按 mutation 走进去、5.8.22 那一次 `gethostbyname` 对 AAAA-only 返回什么、谁拿这个返回值和表做 `in_array`、5.8.23 把谓词挂到 `primary_ip` 之后发生什么，把这几层写完。

---

## 这块功能本来在干什么

和 PCBV2-0090 同一条业务：GraphQL 用远端 URL 创建资源，服务端 GET，字节进 volume。

```graphql
mutation {
  save_pcbvol_Asset(_file: { url: "http://host6.pcb.test/flag", filename: "x.bin" }) {
    id
  }
}
```

`Asset::handleUpload` 读 `_file.url`。设计意图：不能拉取云 metadata。成功穿越之后的效果是 **Craft 出站连接到 metadata 风格地址，响应体作为资源可被读回**。本 case 的 canary 双栈：IPv4 `192.0.0.192`（在 5.8.22 黑名单里）和 IPv6 `fd00:ec2::254`（AWS IMDS 风格 ULA，要到 5.8.23 才进前缀表）。

数据流：

```text
GraphQL _file.url
    → handleUpload
         validateHostname($url)
              parse_url HOST
              拒绝 IP 字面量 / metadata 主机名
              $ip = gethostbyname($hostname)     ← 只查 A
              in_array($ip, IPv4 metadata 表)
         Guzzle GET $url
              getaddrinfo → A 和/或 AAAA
              双栈优先连 AAAA（本环境 host6 只有 AAAA）
         SINK → Asset → 再读 body
```

需要 volume 的 GraphQL create/save。本 case 打开了 public schema 上的该 mutation。

---

## 原始漏洞：URL 原样 GET（CVE-2025-68437，5.8.20）

5.8.20 没有 `validateHostname`。`handleUpload` 对 `$url` 直接 Guzzle GET。seed 用 `http://seed.pcb.test/flag`，DNS 的 A 记录是 `192.0.0.192`，flag 进资源。v0 + `--seed` 退出码 0。

这条 seed 和 0090 相同：静态 IPv4 metadata。V1 补丁要挡的就是它。

---

## 维护者改了什么（CVE-2025-68437 修复，5.8.22）

V1 与 0090 是同一份 `validateHostname`。关键行在 tag `5.8.22`：

```php
# src/gql/resolvers/mutations/Asset.php :: validateHostname  (5.8.22)
        // make sure the hostname is alphanumeric and not an IP address
        if (
            !filter_var($hostname, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) ||
            filter_var($hostname, FILTER_VALIDATE_IP)
        ) {
            return false;
        }

        // Check against well-known cloud metadata domains/IPs
        if (in_array($hostname, [
            'kubernetes.default',
            'kubernetes.default.svc',
            'kubernetes.default.svc.cluster.local',
            'metadata',
            'metadata.google.internal',
            'metadata.packet.net',
        ])) {
            return false;
        }

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

`handleUpload` 通过之后仍是：

```php
            $this->createGuzzleClient()->request('GET', $url, [
                RequestOptions::ALLOW_REDIRECTS => false,
                RequestOptions::SINK => $tempPath,
            ]);
```

没有 `ON_STATS`，没有 IPv6 表，没有 `dns_get_record`。

对 seed（`seed.pcb.test` 有 A=`192.0.0.192`）：

```text
gethostbyname('seed.pcb.test') = '192.0.0.192'
in_array → true → UserError: contains an invalid hostname.
```

v1 + `--seed` 退出码 10。

补丁默认了：

1. 危险目标一定有一张 A 记录，而且 `gethostbyname` 会返回那张 A。
2. 返回值要么是点分十进制 IP（能和表比），要么失败时……实际上失败时返回的是 **原字符串**，文档如此，代码没有把「返回值等于输入」当成失败。

PHP 手册：失败时 `gethostbyname` 返回传入的 hostname。`in_array('host6.pcb.test', ['192.0.0.192', ...])` 恒为 false。

---

## 检查之后谁真正消费那个值

`$ip` 只用在 `in_array` 里。通过之后没有任何代码再读它。Guzzle 拿到的是原始 URL：

```text
http://host6.pcb.test/flag
```

libcurl 调 `getaddrinfo("host6.pcb.test")`。本环境 DNS：

```text
host6.pcb.test  A    = NODATA
host6.pcb.test  AAAA = fd00:ec2::254
```

`getaddrinfo` 返回 AAAA，连接 `[fd00:ec2::254]:80`，canary 把 flag 写进响应。Craft 把 body 存成资源。

过滤器比较的是「`gethostbyname` 的返回字符串」；socket 连的是「`getaddrinfo` 的 AAAA」。地址族都对不上，更谈不上同一 IP。

`FILTER_VALIDATE_IP` 只拒绝 URL **字面量** 是 IP 的情况（例如 `http://[fd00:ec2::254]/`）。hostname 是名字时，这一支不会触发。`host6.pcb.test` 通过 `FILTER_VALIDATE_DOMAIN`。

---

## 仓库里已经有「按 IP 判断」的表，但表和解析器都是 IPv4

同一函数里那张 metadata 表全是 IPv4 字面量。AWS IMDS 的 IPv6 是 `fd00:ec2::254`，GCP 有 `fd20:ce::`，还有 `::1` / `fe80:` / `::ffff:` 映射。5.8.22 一张都没有。

即便把 IPv6 加进 `in_array`，`gethostbyname` 也 **永远不会** 返回 AAAA，比较仍然落空。缺的不是多几个字符串，是 **用会看 AAAA 的解析器，并对实际连接地址做前缀判断**。

5.8.23 的 `validateIp`（先由兄弟 CVE-2026-27127 的 `a4cf3fb` 挂上 `ON_STATS`，再由 `2825388` 加上 IPv6 前缀）才是这条链上「谁真正连上了」的谓词。5.8.22 没有 `validateIp`。GHSA 建议过用 `dns_get_record` 同时扫 A 和 AAAA；V1 没用。

兄弟 case 0090 说明：即使用对了 IPv4 解析，CHECK 和 FETCH 仍是两次查找。27129 不需要 rebind：一次 AAAA-only 就够把 `gethostbyname` 变成空转。

---

## 这个补丁挡住了什么、没挡住什么

- `gethostbyname`：只问 A。失败 → 返回 hostname 字符串。
- `in_array($ip, IPv4表)`：字符串对数字 IP，永不命中。
- Guzzle：完整 `getaddrinfo`，可以只靠 AAAA 连上。

本 case residual 的变换是地址族，不是编码花招：

```text
URL:     http://host6.pcb.test/flag

validateHostname:
  hostname = "host6.pcb.test"          （不是 IP 字面量，不在 metadata 主机名表）
  gethostbyname → "host6.pcb.test"     （无 A，原样返回）
  in_array("host6.pcb.test", [192.0.0.192, ...]) → false
  return true

Guzzle:
  getaddrinfo → fd00:ec2::254
  GET http://[fd00:ec2::254]/flag
  body = PCBFLAG_...
```

seed 的 `seed.pcb.test` 有 A，所以被同一张表挡住。residual 把 A 拿掉、只留 AAAA，检查侧「失败」成了「放行」。

advisory 还列出 `fd00-ec2--254.sslip.io` 这类把 IPv6 编码进主机名的公共服务。本环境用自己的 DNS sidecar 答 NODATA+AAAA，效果相同：`gethostbyname` 看不到数字 IP。

---

## 残余仍然走同一条 Asset URL 拉取（CVE-2026-27129）

还是 `save_pcbvol_Asset(_file:{url})`，还是 `handleUpload` → `validateHostname` → Guzzle SINK。只把 host 从 `seed.pcb.test` 换成 `host6.pcb.test`。

v1 + `--residual`：HTTP 200，资源 body 含 flag。容器内对照：`gethostbyname('host6.pcb.test')` 等于 `'host6.pcb.test'`；`curl http://[fd00:ec2::254]/` 返回同一 flag。`primary_ip` 为 `fd00:ec2::254`。

平台 verify 的 residual 与 heldout 同一 sink。和 seed 的差别是 DNS 记录类型（A vs AAAA-only），不是另一个 Craft API。

注意：0090 的 residual 是同一 host 两次 A 不同；0091 是一次查找就因地址族失败。两条都可以单独打穿 5.8.22 的 `validateHostname`。5.8.23 必须同时修 TOCTOU 和 IPv6，本 case 的 v2 镜像包含两处 commit。

---

## 后来又补了什么（CVE-2026-27129，5.8.23）

commit `2825388b4f32fb1c9bd709027a1a1fd192d709a3` 给已经由 `a4cf3fb` 引入的 `validateIp` 加上 IPv6 前缀：

```php
# src/gql/resolvers/mutations/Asset.php :: validateIp  (5.8.23)
        $v6Prefixes = [
            'fd00:ec2::', // AWS IMDS, DNS, NTP
            'fd20:ce::',  // GCP
            '::1',        // Loopback
            'fe80:',      // Link-local
            '::ffff:',    // IPv4-mapped IPv6
        ];
        foreach ($v6Prefixes as $prefix) {
            if (str_starts_with($ip, $prefix)) {
                return false;
            }
        }
```

`handleUpload` 里 `ON_STATS` 把 `primary_ip` 传进来。对 residual：libcurl 连上 `fd00:ec2::254`，`str_starts_with(..., 'fd00:ec2::')` 为真，抛 `resolves to an invalid IP address`。

这一步不再问 `gethostbyname` 有没有 A。它问的是 **已经连上的那张地址**。AAAA-only 不再能靠「检查失败返回字符串」蒙混。

`validateHostname` 在 5.8.23 里仍不做 AAAA 查找（27127 甚至去掉了 CHECK 时的 `gethostbyname`）。IPv6 闭合完全依赖 `validateIp`。若 `ON_STATS` 拿不到 `primary_ip`，这条前缀表不会跑——那是另一条需要另证的假设。本 benchmark 的 v2 关闭的是 `fd00:ec2::254` 这条 reference residual。

---

## 从这条链还能看出什么

**维护者改错了哪一层。**  
他们用 IPv4-only 的 libc 封装去代表「这个名字会连到哪」。真正连哪的是 `getaddrinfo`。返回值等于输入时，代码把它当成「一个不在表里的 IP」，而不是「查找失败」。

**不是没有更强的 API。**  
`dns_get_record($host, DNS_A + DNS_AAAA)`、`gethostbynamel` 做不到 AAAA，但 `socket_addrinfo_lookup` / Guzzle 自己的 stats 可以。V1 选了最窄的那一个。

**失败语义被当成成功。**  
`gethostbyname` 失败不抛、不返回 false，返回原字符串。`in_array` 对这种值永远是「不在黑名单」。安全检查把「解析失败」实现成了「放行」。

**同一 GET sink，seed 和 residual 只换记录类型。**  
IPv4 metadata 被挡住证明表在 A 记录上工作；AAAA-only 证明表从未见过连接地址。

**金丝雀双栈是有意的。**  
同一 sidecar 既服务 `192.0.0.192` 又服务 `fd00:ec2::254`。seed 打前者（被 V1 挡），residual 打后者（V1 放行）。能读到 flag 说明 Craft 真的出站到了 IPv6 canary。

---

## 版本、入口、参考

| | 版本 | 检查 | 连接 | `seed.pcb.test` A=192.0.0.192 | `host6.pcb.test` 仅 AAAA=fd00:ec2::254 |
|---|---|---|---|---|---|
| V0 | 5.8.20 | 无 | Guzzle | 拉到 flag | （不必） |
| V1 | 5.8.22 | `gethostbyname` + IPv4 表 | `getaddrinfo`，无 `validateIp` | `invalid hostname` | 拉到 flag |
| V2 | 5.8.23 | 不再用 gethostbyname 比 IP | `validateIp(primary_ip)` 含 IPv6 前缀 | `invalid IP` | `invalid IP`（fd00:ec2::） |

- Web：`POST /index.php?p=actions/graphql/api`，`save_<Volume>_Asset(_file:{url})`
- 认证：v0 seed 观察到 flag；v1 seed 未观察到；v1 residual 观察到
- [CVE-2025-68437](https://nvd.nist.gov/vuln/detail/CVE-2025-68437)、[CVE-2026-27129](https://nvd.nist.gov/vuln/detail/CVE-2026-27129)
- [GHSA-x27p-wfqw-hfcc](https://github.com/craftcms/cms/security/advisories/GHSA-x27p-wfqw-hfcc)、[GHSA-v2gc-rm6g-wrw9](https://github.com/craftcms/cms/security/advisories/GHSA-v2gc-rm6g-wrw9)
- V1 源码：[Asset.php @ 5.8.22](https://github.com/craftcms/cms/blob/5.8.22/src/gql/resolvers/mutations/Asset.php)
- V2：[commit 2825388](https://github.com/craftcms/cms/commit/2825388b4f32fb1c9bd709027a1a1fd192d709a3)（IPv6 前缀）；依赖 [a4cf3fb](https://github.com/craftcms/cms/commit/a4cf3fb63bba3249cf1e2882b18a2d29e77a8575) 的 `ON_STATS`
