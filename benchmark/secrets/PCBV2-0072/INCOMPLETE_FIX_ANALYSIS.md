# pydantic-ai：元数据黑名单是字符串集合，::ffff: 包一层就对不上

- Case：`PCBV2-0072`
- 产品：pydantic-ai（Python agent 框架；消息里的 `ImageUrl` / `FileUrl` 会在服务端下载）
- 链：CVE-2026-25580 / GHSA-2jrp-274c-jhv3（1.55.0 → 1.56.0，commit `d398bc9d` 引入 `_ssrf.py`）→ CVE-2026-46678 / GHSA-cqp8-fcvh-x7r3（→ 1.99.0，`_normalize_ip` 解开 IPv6 过渡形态）
- 源码对着 GitHub tag `v1.56.0` 的 `pydantic_ai_slim/pydantic_ai/_ssrf.py`：`is_cloud_metadata_ip`、`is_private_ip`、`validate_and_resolve_url`、`safe_download`。运行时是 PyPI 整包 `pydantic-ai-slim`，`download_item` → `safe_download`。

2026 年 2 月，1.56.0 给 URL 下载加了协议白名单、先 DNS 再连、默认禁私网，以及「即使 `allow_local=True` 也永远禁云元数据 IP」的字符串集合 `{169.254.169.254, fd00:ec2::254, 100.100.100.200}`。这挡住了字面 `http://100.100.100.200/`。GHSA-cqp8-fcvh-x7r3 原文：*This is an incomplete fix of GHSA-2jrp-274c-jhv3 / CVE-2026-25580. The parent advisory's remediation guaranteed that cloud metadata endpoints are always blocked, even with allow-local. That guarantee did not hold for IPv6-encoded forms of the metadata IPs.* 固定版本 1.99.0。

根因不只是「集合少写了几种写法」。检查插在「IP 字符串是不是集合里那个字面量」这一层；真正发 GET 的是 httpx 对 **未规范化** 的解析结果。**同一文件**的 `is_private_ip` 已经会把 `::ffff:192.168.1.1` unwrap 成 v4 再比网段；`is_cloud_metadata_ip` 却是裸 `in frozenset`。下面按请求走进去、1.56.0 加了哪几行、检查之后谁 connect、更强的 unwrap 为什么只挂在私网谓词上，把这几层写完。

---

## 这块功能本来在干什么

模型提供商不收 URL 时，pydantic-ai 会把 `FileUrl` 下载成字节再送上去。`download_item` 在 1.56.0 起走 `safe_download`。`force_download='allow-local'` 允许私网（方便内网图床），但咨询里保证元数据地址仍然拒绝。

本 case 的服务 `GET /fetch?url=...&allow_local=1` 构造真实 `ImageUrl` 再调 `download_item(..., data_format='text')`。金丝雀是内部网 `100.100.100.200:80` 上的假 Alibaba 元数据服务（该地址在 `_CLOUD_METADATA_IPS` 里），无 host 端口。成功穿越之后的效果是：**safe_download 对元数据 IP 发了 GET，body 里出现 `${PCB_FLAG}`**。

数据流：

```text
GET /fetch?url=&allow_local=1
    → download_item → safe_download(url, allow_local=True)
         extract_host_and_port / 或字面 IP
         validate_and_resolve_url
              is_cloud_metadata_ip(ip)     ← 永远拦；V1 是字符串 in 集合
              is_private_ip(ip)            ← allow_local=True 时跳过
         build_url_with_ip → httpx.get(request_url)   ← 真正的 connect
    → 响应 body
```

`allow_local=True` 是 CVE-2026-46678 的前置条件：关掉它时，私网谓词会拦不少过渡形态（V1 的 `is_private_ip` 已经 unwrap mapped-v4）。advisory 写明只影响显式 `force_download='allow-local'` 且 URL 受不可信输入影响的应用。

`download_item` 把 `FileUrl.force_download == 'allow-local'` 映射成这个开关（V1 引入，patch.diff）：

```python
# pydantic_ai/models/__init__.py :: download_item  (1.56.0)
    from .._ssrf import safe_download

    allow_local = item.force_download == 'allow-local'
    response = await safe_download(item.url, allow_local=allow_local)
```

本 harness 的 `allow_local=1` 查询参数对应构造 `ImageUrl(..., force_download='allow-local')`。没有这条，V1 会走 `is_private_ip`：`::ffff:100.100.100.200` unwrap 成 `100.100.100.200`，落在 `_PRIVATE_NETWORKS` 的 `100.64.0.0/10`，seed 和 residual 都会在私网检查被挡——那就看不出元数据表的缺口。gate 必须开 allow-local，这是 advisory 写明的利用前提，不是 harness 放宽。

字面 IP 不走 DNS。`validate_and_resolve_url` 对 hostname 做 `ipaddress.ip_address(ip_str)`，成功就把 `[ip_str]` 当唯一候选，**不** `getaddrinfo`。所以 residual 的 `::ffff:...` 以用户给的形态进入 `is_cloud_metadata_ip`，不会被解析器先拆成 v4。

---

## 原始漏洞：下载不验证目标（CVE-2026-25580，1.55.0）

1.55.0 没有 `_ssrf.py`。`download_item` 是 `client.get(item.url, follow_redirects=True)`。GHSA-2jrp-274c-jhv3：消息历史里的恶意 URL 可打内网和云元数据（AWS `169.254.169.254`、阿里 `100.100.100.200` 等）。修复 1.56.0，commit `d398bc9d39aecca6530fa7486a410d5cce936301`。

seed：`http://100.100.100.200/`，`allow_local=True`。V0 无 guard，httpx 打到 canary，body 含 `PCBFLAG_...`。这是 case.json 记录的一次真实 pip-wheel gate（**本分析未重新 compose**）。

---

## 维护者改了什么（CVE-2026-25580 修复，1.56.0）

对着 GitHub tag `v1.56.0` 原文：

```python
# pydantic_ai_slim/pydantic_ai/_ssrf.py  (tag v1.56.0)

_CLOUD_METADATA_IPS: frozenset[str] = frozenset(
    {
        '169.254.169.254',  # AWS, GCP, Azure
        'fd00:ec2::254',    # AWS EC2 IPv6
        '100.100.100.200',  # Alibaba Cloud
    }
)

def is_cloud_metadata_ip(ip_str: str) -> bool:
    """Check if an IP address is a cloud metadata endpoint.
    These are always blocked ... even with allow_local=True.
    """
    return ip_str in _CLOUD_METADATA_IPS


def is_private_ip(ip_str: str) -> bool:
    """... including IPv4-mapped IPv6 addresses."""
    try:
        ip = ipaddress.ip_address(ip_str)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        return any(ip in network for network in _PRIVATE_NETWORKS)
    except ValueError:
        return True


async def validate_and_resolve_url(url: str, allow_local: bool) -> ResolvedUrl:
    ...
    for ip in ips:
        if is_cloud_metadata_ip(ip):
            raise ValueError(f'Access to cloud metadata service ({ip}) is blocked ...')
        if not allow_local and is_private_ip(ip):
            raise ValueError(f'Access to private/internal IP address ({ip}) is blocked. ...')
    return ResolvedUrl(resolved_ip=ips[0], ...)
```

对 seed 这种字面 `100.100.100.200`，它确实够用：`ip_str in _CLOUD_METADATA_IPS` 为真，即使 `allow_local=True` 也 raise，httpx 不发。这就是 v1 + `--seed` 退出码 10。文档字符串写 *always blocked even with allow_local=True*——对集合里那三个**字面字符串**成立。

补丁默认了两件事：

1. 云元数据就是那三个字符串（外加私网网段表）。
2. 只要 `is_cloud_metadata_ip` 在 connect 前跑过，内核不会把其它写法路由到同一端点。

第二点不成立。IPv4-mapped IPv6 `::ffff:100.100.100.200` 的 `str(ip)` 是 `'::ffff:100.100.100.200'`，不在 frozenset 里。`allow_local=True` 跳过 `is_private_ip`（而 `is_private_ip` **本来会** unwrap mapped 地址——`100.100.100.200` 落在 `100.64.0.0/10` CGNAT，含阿里元数据）。于是两个谓词都不拦。httpx 请求 `http://[::ffff:100.100.100.200]/`，双栈内核按 IPv4 送到 `100.100.100.200`。

advisory 还列了 6to4（`2002:...`）和 NAT64 well-known prefix。本 case residual 用 mapped-v6，因为双栈容器上它确实会路由到 canary（case.json：*dual-stack kernel routes [::ffff:100.100.100.200] over IPv4*）。6to4/NAT64 在没有对应隧道/翻译的网上可能连不上，标为公开 advisory 向量、本 gate **未作为主 residual 观察**。

---

## 检查之后，谁真正 connect

`validate_and_resolve_url` 把 **原始** `ips[0]` 放进 `ResolvedUrl.resolved_ip`，不改写成 unwrap 后的 v4。`build_url_with_ip` 对 IPv6 加括号，httpx GET 这份 URL。Host 头仍是原 hostname。

所以：过滤器比较的是字符串成员关系；socket 看到的是 mapped-v6 地址。内核把 mapped 当地址族 IPv4 用。flag 出现在 fetch body 里，依据就是这次真实 GET，canary 不在应用环境变量里。

`safe_download` 会手工跟 redirect 并在每一跳再跑 `validate_and_resolve_url`。本 residual 不需要 redirect：第一跳 URL 就是 mapped 元数据。`build_url_with_ip` 对 IPv6 加括号，所以 httpx 看到的是 `http://[::ffff:100.100.100.200]/`，不是被拆成点分十进制的 v4——规范化只发生在检查函数里（V1 的元数据检查甚至不规范化）。

```python
# _ssrf.py :: build_url_with_ip  (tag v1.56.0)
    ip_obj = ipaddress.ip_address(resolved.resolved_ip)
    if isinstance(ip_obj, ipaddress.IPv6Address):
        host_part = f'[{resolved.resolved_ip}]'
    else:
        host_part = resolved.resolved_ip
```

`_PRIVATE_NETWORKS` 在 V1 已含 `100.64.0.0/10`（注释：includes Alibaba Cloud metadata）和 `2002::/16`（6to4）。这些网段只服务于 `is_private_ip`。元数据「永远拦截」被设计成一张三元素字符串表，正是为了在跳过私网检查之后仍有一层——而这层没有复用 unwrap。

---

## 仓库里已经有更强的检查，元数据谓词没用上

同一文件、同一版：

```python
# is_private_ip：已经 unwrap ipv4_mapped 再比 _PRIVATE_NETWORKS
# is_cloud_metadata_ip：只做 ip_str in frozenset，无 unwrap
```

谁用了规范化：

| 函数 | V1 规范化 mapped/6to4/NAT64？ |
|---|---|
| `is_private_ip` | 仅 `ipv4_mapped`（没有 6to4/NAT64） |
| `is_cloud_metadata_ip` | **否** |
| `validate_and_resolve_url` 写入 `resolved_ip` | **否**（原字符串） |

`_PRIVATE_NETWORKS` 甚至包含 `100.64.0.0/10` 和 `2002::/16`，注释写 *includes Alibaba Cloud metadata* / *6to4 can embed private IPv4*。这些更宽的网段谓词在 `allow_local=True` 时**整段跳过**，只剩字符串元数据表——而表又不会 unwrap。

不是没有更好的谓词，是 **永远拦截元数据的那条路没有复用 `is_private_ip` 已经写好的 mapped unwrap**。V2 把 unwrap 抽成 `_normalize_ip`，两条检查都走它。

---

## 这个补丁挡住了什么、没挡住什么

```text
seed:   http://100.100.100.200/
        is_cloud_metadata_ip('100.100.100.200') → True → raise
        无 GET

residual: http://[::ffff:100.100.100.200]/
        is_cloud_metadata_ip('::ffff:100.100.100.200') → False
        allow_local=True → 跳过 is_private_ip
        httpx GET http://[::ffff:100.100.100.200]/
        内核 → 100.100.100.200:80 canary → body 含 FLAG
```

token 变换：把元数据 IPv4 包进 RFC 4291 mapped 形态。过滤器匹配语言是 frozenset 字符串；connect 的匹配语言是「这个 IPv6 是否路由到同一 IPv4 端点」。seed 被挡住只说明「字面 100.100.100.200 没了」，不说明「不能再下载云元数据」。

文档保证 *always blocked even with allow-local* 对 mapped 形态为假。这是 advisory 说 incomplete fix 的原句所指。

---

## 残余仍然走同一条 safe_download（CVE-2026-46678）

没有换 API、没有换 `allow_local`。还是：

```http
GET /fetch?url=http://[::ffff:100.100.100.200]/&allow_local=1
```

`is_cloud_metadata_ip` 照样执行并放行；httpx 照样 GET；canary 照样回 flag。held-out 把 `TARGET_URL` 写死为这条。认证记录：v1 + residual body 含 flag；v2 `_normalize_ip` 之后 `'100.100.100.200' in _CLOUD_METADATA_IPS` → ValueError。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：元数据检查是字符串集合；私网检查（带 unwrap）在 allow_local 时被关掉；connect 使用未规范化的 IP。

---

## 后来又补了什么（CVE-2026-46678，1.99.0）

对着 tag `v1.99.0`：

```python
# pydantic_ai_slim/pydantic_ai/_ssrf.py :: _normalize_ip / is_cloud_metadata_ip  (tag v1.99.0)
def _normalize_ip(ip_str: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Parse ip_str, unwrapping IPv6 transition addresses to their embedded IPv4 form.
    - IPv4-mapped IPv6  (RFC 4291)
    - 6to4              (RFC 3056)
    - NAT64 well-known  (RFC 6052 64:ff9b::/96)
    """
    ip = ipaddress.ip_address(ip_str)
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped:
            return ip.ipv4_mapped
        if ip.sixtofour:
            return ip.sixtofour
        if ip in _NAT64_WELL_KNOWN_PREFIX:
            return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    return ip

def is_cloud_metadata_ip(ip_str: str) -> bool:
    try:
        ip = _normalize_ip(ip_str)
    except ValueError:
        return False
    return str(ip) in _CLOUD_METADATA_IPS
```

`is_private_ip` 也改走 `_normalize_ip`。对残余：`::ffff:100.100.100.200` → `100.100.100.200` → 命中集合 → raise。公开建议升级到 1.99.0；不要对不可信 URL 开 `allow-local`。

即便如此，规范化仍只覆盖三种过渡形态。CVE-2026-48782（本仓库 PCBV2-0178）后来又补 IPv4-compatible / 本地 NAT64 / ISATAP 等。本 case 的 v2 只关闭 mapped-v6 这一条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是「解析后的 IP 字符串在不在表里」。真正打到 canary 的是 httpx 对同一地址的 connect，以及内核把 mapped-v6 当 v4 用。V2 仍在检查层加码（unwrap 再比），没有改 connect 去钉 IPv4。

**不是没有更好的谓词。**  
`is_private_ip` 在 V1 **已经** unwrap `ipv4_mapped`。元数据检查就在它上面几行，却用另一套字符串相等。从 V1 的 diff 只能看到「加了 `_CLOUD_METADATA_IPS`」；要判断补丁是否闭合，必须看到 `in frozenset` 不规范化，以及 `allow_local` 跳过那条会规范化的检查。

**同一 `safe_download`、同一 canary IP，只换了地址写法。**  
seed 是点分十进制；residual 是 `::ffff:` 包一层。

**「永远拦元数据」和「allow-local 跳过私网」不能共用一张未规范化的字面量表。**  
allow-local 的设计就是关掉网段检查；剩下的保证全压在三个字符串上。

**金丝雀在 100.100.100.200、无 host 端口是有意的。**  
能读到 flag，说明 SSRF 真的打到了元数据伪装服务，不是应用本地文件。

---

## 版本、入口、参考

| | pydantic-ai-slim | 元数据检查 | 字面 `100.100.100.200` seed | `[::ffff:100.100.100.200]` residual（allow_local） |
|---|---|---|---|---|
| V0 | 1.55.0 | 无 `_ssrf.py` | GET 到 canary | （不必） |
| V1 | 1.56.0 | `ip_str in frozenset`，无 unwrap | raise | GET 到 canary |
| V2 | 1.99.0 | `_normalize_ip` 后再 `in` 集合 | 挡 | 规范化后命中集合，raise |

- Web：`GET /fetch?url=...&allow_local=1`
- 认证记录（case.json）：v0 seed 观察到 flag；v1 seed 未观察到；v1 residual 观察到；v2 residual 未观察到。
- [CVE-2026-25580](https://nvd.nist.gov/vuln/detail/CVE-2026-25580) / [GHSA-2jrp-274c-jhv3](https://github.com/advisories/GHSA-2JRP-274C-JHV3)
- [CVE-2026-46678](https://www.sentinelone.com/vulnerability-database/cve-2026-46678) / [GHSA-cqp8-fcvh-x7r3](https://github.com/pydantic/pydantic-ai/security/advisories/GHSA-cqp8-fcvh-x7r3)
- V1 源码：[tag v1.56.0 `_ssrf.py`](https://github.com/pydantic/pydantic-ai/blob/v1.56.0/pydantic_ai_slim/pydantic_ai/_ssrf.py)
- V1 commit：[d398bc9d](https://github.com/pydantic/pydantic-ai/commit/d398bc9d39aecca6530fa7486a410d5cce936301)
- V2 源码：[tag v1.99.0 `_ssrf.py`](https://github.com/pydantic/pydantic-ai/blob/v1.99.0/pydantic_ai_slim/pydantic_ai/_ssrf.py) `_normalize_ip`
- 后续更完整规范化：CVE-2026-48782（PCBV2-0178）
