# pydantic-ai：元数据黑名单只拆了三种 IPv6 过渡封装

- Case：`PCBV2-0178`
- 产品：Pydantic AI（Python LLM agent 框架）。运行时是 PyPI 整包 `pydantic-ai-slim` 1.56.0 / 1.99.0 / 1.102.0，经 `ImageUrl` → `models.download_item` → `_ssrf.safe_download` 发真实 HTTP，不是抽出来的函数。
- 链：CVE-2026-46678（1.56.0 → 1.99.0，GHSA-cqp8-fcvh-x7r3）→ CVE-2026-48782（1.99.0 → 1.102.0，GHSA-cg7w-rg45-pc59，commit `1add061`）
- 源码对着 tag `v1.99.0` 的 `pydantic_ai_slim/pydantic_ai/_ssrf.py`（`_normalize_ip` / `is_cloud_metadata_ip` / `safe_download`）和 `pydantic_ai_slim/pydantic_ai/models/__init__.py`（`download_item`）。金丝雀是内部 sidecar，冒充阿里云元数据 `100.100.100.200`，并在 NAT64 RFC 8215 本地前缀上绑 `64:ff9b:1::6464:64c8`。

GHSA-cg7w-rg45-pc59 的原话：*This is an incomplete fix of GHSA-cqp8-fcvh-x7r3 / CVE-2026-46678 ... The prior remediation decoded only IPv4-mapped IPv6, 6to4, and the NAT64 well-known prefix; the metadata guarantee did not hold for the remaining transition forms.*

根因不只是「黑名单少写了几个地址」。检查插在「把 IP 字符串拆成嵌入的 IPv4，再拿去对 `_CLOUD_METADATA_IPS` 做成员判断」上；真正发起连接的是后面的 `httpx.get(build_url_with_ip(resolved))`，用的仍是解析出来的原始字面量。`_normalize_ip` 只认三种封装，拆不开的 IPv6 包装会原样交给内核 / NAT64。下面按调用走进去。

---

## 这块功能本来在干什么

Pydantic AI 给 `ImageUrl` / `AudioUrl` / `VideoUrl` / `DocumentUrl` 提供本地下载。默认把 URL 交给模型供应商；`force_download=True` 时在本地拉，并挡住私网和云元数据。`force_download='allow-local'` 放开私网，但 advisory 写明 *Cloud metadata endpoints are always blocked, even with allow-local*。

一次典型调用（本 case 的 HTTP 包装把 URL 转成 `ImageUrl` 再调包内 API）：

```text
ImageUrl(url="http://[::ffff:100.100.100.200]/latest/meta-data/",
         force_download="allow-local")
```

`download_item` 把这个开关翻译成 `safe_download` 的 `allow_local`：

```python
# pydantic_ai/models/__init__.py :: download_item  (v1.99.0, 约 L1666–1669)
    from .._ssrf import safe_download

    allow_local = item.force_download == 'allow-local'
    response = await safe_download(item.url, allow_local=allow_local)
```

设计意图：`allow-local` 可以打内网文件服务，但不能打 `169.254.169.254` / `100.100.100.200` / `fd00:ec2::254`。成功穿越之后的效果是：**httpx 连上元数据 IP，响应体里出现 IAM 凭证（本 case 是 sidecar 上的 `PCBFLAG_...`）**。

数据流：

```text
ImageUrl.url + force_download='allow-local'
    → download_item
         allow_local = True
         safe_download(url, allow_local=True)
              extract_host_and_port          ← 字面 IP 不走 DNS
              validate_and_resolve_url
                   is_cloud_metadata_ip(ip)  ← V1：_normalize_ip 再 str 成员判断
                   is_private_ip             ← allow_local=True 时跳过
              build_url_with_ip(resolved)    ← 仍用原始 resolved_ip 发 GET
              httpx.get(request_url)
    → response.text 回到调用方
```

需要应用显式把用户可控 URL 设成 `allow-local`。捆绑的 `Agent.to_web` / `VercelAIAdapter` 不传播这个开关。

---

## 原始漏洞：字面 IPv4 才算元数据（CVE-2026-46678，1.56.0）

1.56.0 引入 `_ssrf.py`，用来闭合 CVE-2026-25580。`is_cloud_metadata_ip` 当时是**字符串成员判断**，没有过渡封装解码：

```python
# pydantic_ai/_ssrf.py  (v1.56.0)
def is_cloud_metadata_ip(ip_str: str) -> bool:
    return ip_str in _CLOUD_METADATA_IPS
```

`_CLOUD_METADATA_IPS` 里是 `'169.254.169.254'`、`'100.100.100.200'`、`'fd00:ec2::254'`。`::ffff:100.100.100.200` 对不上任何一项。`is_private_ip` 当时只额外拆 `ip.ipv4_mapped`；元数据检查连这一步都没有。

`allow_local=True` 跳过私网检查。内核把 IPv4-mapped 送到嵌入的 IPv4。seed 用：

```text
http://[::ffff:100.100.100.200]/...
```

`is_cloud_metadata_ip` 为假，httpx 打到 sidecar，body 里出现 `PCBFLAG_...`。这就是 v0 + `--seed`。GHSA-cqp8-fcvh-x7r3：父 advisory 保证「元数据永远拦」，对 IPv6 编码形式不成立。

---

## 维护者改了什么（CVE-2026-46678 修复，1.99.0）

1.99.0（PR #5528）加了 `_normalize_ip`，让元数据和私网检查都先拆一层：

```python
# pydantic_ai/_ssrf.py :: _normalize_ip  (v1.99.0)
_NAT64_WELL_KNOWN_PREFIX = ipaddress.IPv6Network('64:ff9b::/96')

def _normalize_ip(ip_str: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    ip = ipaddress.ip_address(ip_str)
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped:
            return ip.ipv4_mapped
        if ip.sixtofour:
            return ip.sixtofour
        if ip in _NAT64_WELL_KNOWN_PREFIX:
            return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    return ip
```

字面意思：

| 形态 | 依据 | V1 是否拆 |
|---|---|---|
| IPv4-mapped `::ffff:a.b.c.d` | RFC 4291 §2.5.5.2，`ip.ipv4_mapped` | 是 |
| 6to4 `2002:...` | RFC 3056，`ip.sixtofour` | 是 |
| NAT64 周知前缀 `64:ff9b::/96` | RFC 6052 | 是 |
| NAT64 本地前缀 `64:ff9b:1::/48` | RFC 8215 | **否** |
| IPv4-compatible `::a.b.c.d` | RFC 4291 已弃用 | **否** |
| ISATAP `...:5efe:a.b.c.d` | RFC 5214 | **否** |
| Teredo 客户端 IPv4（XOR） | RFC 4380；stdlib 有 `ip.teredo` | **否**（只把 `2001::/32` 整段列入私网） |

`is_cloud_metadata_ip` 变成：

```python
def is_cloud_metadata_ip(ip_str: str) -> bool:
    try:
        ip = _normalize_ip(ip_str)
    except ValueError:
        return False
    return str(ip) in _CLOUD_METADATA_IPS
```

对 seed `::ffff:100.100.100.200`：`ipv4_mapped` 给出 `100.100.100.200`，`str` 命中 frozenset，抛 `Access to cloud metadata service is blocked`。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 会把元数据 IPv4 藏起来的过渡形式，就是 stdlib 的 `ipv4_mapped` / `sixtofour`，再加上 RFC 6052 那一个 /96。
2. 拆完之后用 `str(ip)` 去对那三个字符串，语义上等于「只关心这三种拆法得到的点分十进制」。

第二点在 NAT64 配置的网上不成立：运营商还会用 RFC 8215 的 `64:ff9b:1::/48`。

---

## 消毒之后，谁拿这个值去连

V1 的 `_normalize_ip` 只服务于谓词。`validate_and_resolve_url` 通过之后，`ResolvedUrl.resolved_ip` 仍是**输入字面量**，不是拆出来的 IPv4：

```python
# pydantic_ai/_ssrf.py :: validate_and_resolve_url  (v1.99.0)
    for ip in ips:
        if is_cloud_metadata_ip(ip):
            raise ValueError(...)
        if not allow_local and is_private_ip(ip):
            raise ValueError(...)

    return ResolvedUrl(
        resolved_ip=ips[0],   # 原始字符串
        hostname=hostname,
        ...
    )
```

`safe_download` 紧接着：

```python
            request_url = build_url_with_ip(resolved)
            response = await client.get(request_url, headers=request_headers, ...)
```

`build_url_with_ip` 对 IPv6 加方括号，原样放进 URL。过滤器看的是「拆不拆得开、拆开后像不像那三个字符串」；httpx / 内核看的是「这个 IPv6 字面量路由到哪」。两套语义中间没有第二次谓词。

`allow_local=True` 时 `is_private_ip` 根本不跑。`64:ff9b:1::/48` 也不在 `_PRIVATE_NETWORKS` 里——V1 只把 `64:ff9b::/96` 当解码前缀，没有把它当禁网。元数据检查是唯一闸门。

---

## 标准库和后一版里已经有更强的拆法，V1 没用

同一份 CPython `ipaddress.IPv6Address` 上：

| 谓词 | V1 `_normalize_ip` |
|---|---|
| `ipv4_mapped` | 用了 |
| `sixtofour` | 用了 |
| `teredo`（低 32 位 XOR `0xFFFFFFFF`） | **没用**；只把 `2001::/32` 整段标成私网。`allow_local=True` 时这段私网检查被跳过 |
| IPv4-compatible（高 96 位为 0，且不是 mapped） | **没有**对应属性，V1 原样返回 IPv6 |
| ISATAP 接口 ID `0000:5efe` / `0200:5efe` | **没有** |

V2 的 `_embedded_ipv4s(..., exhaustive=True)` 按 RFC 6052 的多种前缀长度、RFC 8215 `/48`、ISATAP、Teredo XOR 把嵌入 IPv4 全部拆出来，再对 `_CLOUD_METADATA_IPV4` 做**地址对象**比较。这套逻辑 1.99.0 里不存在。不是「网上没有更完整的过渡形式表」，是 **V1 只接了 stdlib 两个属性和一个 /96**。

即便 RFC 8215 没把元数据检查打穿，只要连接仍用未规范化的字面量，任何「谓词拆不开、内核却会送到嵌入 IPv4」的写法都会变成一次真实的元数据 GET。

---

## 这个补丁挡住了什么、没挡住什么

- `_normalize_ip` + `str(ip) in _CLOUD_METADATA_IPS`：看三种封装拆完之后是不是那三个字符串
- `httpx.get(http://[原始 IPv6]/...)`：看双栈 / NAT64 怎么把这个包装送到 IPv4

只要构造一种输入，使「那三种拆法」都给不出 `100.100.100.200`，第一行放行，第二行仍然打到 sidecar。

RFC 8215 本地使用前缀就是这样。`64:ff9b:1::/48` 不是 `64:ff9b::/96` 的子集（`ff9b:1` 比周知前缀多了一段）。嵌入 IPv4 `100.100.100.200` = `6464:64c8`：

```text
输入 hostname:  64:ff9b:1::6464:64c8

_normalize_ip:
  ipv4_mapped = None
  sixtofour   = None
  ip in 64:ff9b::/96 ?  False
  → 返回原 IPv6

str(ip) = '64:ff9b:1::6464:64c8'  ∉  {169.254.169.254, 100.100.100.200, fd00:ec2::254}

build_url_with_ip → http://[64:ff9b:1::6464:64c8]/...
NAT64 / 本 case 双栈 sidecar → 100.100.100.200
```

IPv4-compatible `::100.100.100.200`、ISATAP `...:5efe:6464:64c8` 同样拆不开。advisory 把它们和运营商自选 NAT64 前缀列在一起。本 case 残余用 RFC 8215，因为容器网把这条前缀真的路由到了金丝雀。

---

## 残余仍然走同一条 download_item → safe_download（CVE-2026-48782）

没有换 API、没有换 `allow-local`、没有换 sidecar。还是：

```text
ImageUrl(url="http://[64:ff9b:1::6464:64c8]/...",
         force_download="allow-local")
    → download_item → safe_download(..., allow_local=True)
```

`is_cloud_metadata_ip` 照样跑 `_normalize_ip`；跑完仍是 IPv6 包装；`build_url_with_ip` 把包装交给 httpx；NAT64 语义下到达 `100.100.100.200`；响应体里出现 `PCBFLAG_...`。

平台残余和 NVD/GHSA 是同一 sink：`safe_download` 在 `allow_local=True` 时对元数据 IP 的过渡封装。不是换了一个下载入口。

---

## 后来又补了什么（CVE-2026-48782，1.102.0）

1.102.0（PR #5596，commit `1add06179ba4de259f7ab977620b697b7209f7e4`）用 `_embedded_ipv4s` 换掉 `_normalize_ip`。元数据检查走 `exhaustive=True`：

```python
# pydantic_ai/_ssrf.py  (v1.102.0)
_NAT64_PREFIXES = (
    (ipaddress.IPv6Network('64:ff9b::/96'),  (offsets_96,)),
    (ipaddress.IPv6Network('64:ff9b:1::/48'), offsets_48_56_64_96),
)

def is_cloud_metadata_ip(ip_str: str) -> bool:
    ...
    return any(candidate in _CLOUD_METADATA_IPV4
               for candidate in _embedded_ipv4s(ip, exhaustive=True))
```

对残余 `64:ff9b:1::6464:64c8`，按 /48 嵌入偏移拆出 `100.100.100.200`，命中 `_CLOUD_METADATA_IPV4`，再抛 ValueError。公开建议升到 `1.102.0`（或 2.0.0b3）。

即便如此，连接仍发往原始字面量；闭合靠的是「拆得够全就拒绝」。operator 自选、不在 RFC 表里的 NAT64 前缀，exhaustive 模式靠「所有标准嵌入位置都试一遍」覆盖。本 benchmark 的 v2 只关闭 RFC 8215 这条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是谓词里「IPv6 包装怎么还原成 IPv4」。真正打到元数据的是 `httpx.get` 对原始字面量的连接。V2 仍在同一层加码（拆得更全），没有改成「连接前把目标规范成嵌入 IPv4」或「对已建立连接的对端地址再查一次」。

**不是没有更好的谓词。**  
stdlib 已有 `teredo`；RFC 8215 / ISATAP / IPv4-compatible 的拆法在后续 commit 里写得很完整。V1 只接了 mapped、6to4、周知 NAT64。从 1.99.0 的 diff 只能看到加了 `_normalize_ip`；要判断是否闭合，必须对照过渡机制表，看哪些封装会在 `allow_local=True` 的网上被送到同一 IPv4。

**同一函数、同一 `resolved_ip`，只换了 hostname 的写法。**  
任何把用户 URL 送进 `download_item` 且 `force_download='allow-local'` 的路径，在 1.99.0 上都吃这一次规范化。

**黑名单用字符串而不是地址对象。**  
`str(ip) in _CLOUD_METADATA_IPS` 要求拆完之后恰好是那三个十进制写法。V2 改成 `IPv4Address` 集合，避免规范化字符串对不上。

**金丝雀绑在元数据 IP 和 RFC 8215 形态上是有意的。**  
普通双栈 VM 不路由 `64:ff9b:1::/48`。advisory 把攻击复杂度标成 High，就是这条前置条件。本 case 在 `metanet` 上显式路由，用来证明谓词拆不开时连接层会跟过去。

---

## 版本、入口、参考

| | 版本 | `_normalize_ip` / 嵌入拆解 | 明文 mapped seed | RFC 8215 residual |
|---|---|---|---|---|
| V0 | 1.56.0 | 无；`ip_str in frozenset` | 打到 sidecar | （不必） |
| V1 | 1.99.0 | mapped / 6to4 / `64:ff9b::/96` | ValueError | 打到 sidecar |
| V2 | 1.102.0 | `_embedded_ipv4s(exhaustive=True)` 含 RFC 8215 | 挡 | 拆出 100.100.100.200，挡 |

- 包 API：`pydantic_ai.models.download_item(ImageUrl(..., force_download='allow-local'))` → `_ssrf.safe_download`
- [CVE-2026-46678](https://nvd.nist.gov/vuln/detail/CVE-2026-46678)、[GHSA-cqp8-fcvh-x7r3](https://github.com/pydantic/pydantic-ai/security/advisories/GHSA-cqp8-fcvh-x7r3)
- [CVE-2026-48782](https://nvd.nist.gov/vuln/detail/CVE-2026-48782)、[GHSA-cg7w-rg45-pc59](https://github.com/pydantic/pydantic-ai/security/advisories/GHSA-cg7w-rg45-pc59)
- V1 blob：[`pydantic_ai/_ssrf.py@v1.99.0`](https://github.com/pydantic/pydantic-ai/blob/v1.99.0/pydantic_ai_slim/pydantic_ai/_ssrf.py)、[`models/__init__.py@v1.99.0`](https://github.com/pydantic/pydantic-ai/blob/v1.99.0/pydantic_ai_slim/pydantic_ai/models/__init__.py)
- V2：[`_ssrf.py@v1.102.0`](https://github.com/pydantic/pydantic-ai/blob/v1.102.0/pydantic_ai_slim/pydantic_ai/_ssrf.py)（`_embedded_ipv4s`）
