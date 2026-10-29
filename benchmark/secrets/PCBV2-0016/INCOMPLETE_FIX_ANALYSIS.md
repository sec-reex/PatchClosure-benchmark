# CPython http.client：路径不许带控制字符，Host 头仍按用户给的 netloc 写出去

- Case：`PCBV2-0016`
- 产品：CPython 标准库 `urllib.request` / `http.client`。应用把攻击者能影响的 URL 交给 `urlopen` / `HTTPConnection`。
- 链：CVE-2019-9740（3.7.3 → 3.7.4 起，`putrequest` 用 `_contains_disallowed_url_pchar_re` 拒路径里的 `\x00-\x20\x7f`；3.7.7 已含）→ CVE-2019-18348（3.7.7 → 3.7.8，在 `HTTPConnection.__init__` 对 `self.host` 跑**同一张**正则）
- 源码对着 GitHub tag `v3.7.7` / `v3.7.8` 的 `Lib/http/client.py`：`putrequest`、`_validate_path`、`_validate_host`、`putheader`。运行时是官方 `python:3.7.x-slim` 镜像里未改过的标准库。

2019 年 3 月，bpo-30458 修了「URL 路径 / 查询里嵌 `\r\n` 再跟一个 HTTP 头」：`putrequest` 在写出 `GET {url} HTTP/1.1` 之前搜控制字符。NVD CVE-2019-18348 原文：*CRLF injection is possible if the attacker controls a url parameter ... specifically in the host component of a URL ... This is similar to the CVE-2019-9740 query string issue and the CVE-2019-9947 path string issue.* 修复注释写在 `_validate_host` 上：`# Prevent CVE-2019-18348.`

根因不只是「host 漏了」。检查插在 **request-target**（`putrequest` 的 `url` 参数）上；真正把第二行送上线的还有 `Host:` 头，值来自构造时的 `self.host`；同文件里已经有 `_contains_disallowed_url_pchar_re`，3.7.7 的 `__init__` 没有调用它。下面按 urlopen 走进去、3.7.7 改了哪一层、校验之后谁把 host 写成头、同一谓词有没有挂到 host 上，把这几层写完。

---

## 这块功能本来在干什么

Python 应用用 `urllib.request.urlopen(user_url)` 去拉用户指定的地址。`urlopen` 把 URL 拆成 host / path，构造 `HTTPConnection(host)`，再 `putrequest(method, path)`。一次典型调用：

```python
urllib.request.urlopen("http://127.0.0.1/x")
```

写出的字节大致是：

```http
GET /x HTTP/1.1\r\n
Host: 127.0.0.1\r\n
...
```

设计意图：用户可以选 host 和 path，但不能在已经开始的 HTTP 报文里插入新的请求行或头。成功穿越之后的效果是：**对端（或中间的行协议服务）看见第二行 `GET flag`**。NVD 举的影响是「后面跟一个 HTTP header」；公开讨论里也包括把 CRLF 打进 Redis / memcached 这种按行解析的内部服务。本 case 在容器环回 127.0.0.1:9000 放了一个行协议金丝雀：看到（可带前导空白的）`GET flag` 就返回 `PCBFLAG_...`。

数据流：

```text
用户 URL
    → urllib 拆 netloc / path
    → HTTPConnection.__init__(host)     ← V1 不校验 host
         self.host = host
    → putrequest(method, url=path)
         V1：_validate_path(url)        ← 补丁只挂在这里
         写出 "GET {path} HTTP/1.1"
         自动 putheader("Host", self.host)
    → 套接字上的原始字节
    → 对端按行解析
```

`connect()` 把 TCP 指到哪和「报文里有没有额外一行」是两件事。本 case 把连接指到金丝雀监听器，只观察 request-building 这一层——正是两次 CVE 修的那一层。

---

## 原始漏洞：路径里的 CRLF 直接进请求行（CVE-2019-9740，3.7.3）

3.7.3 的 `putrequest` 把 `url` 拼进请求行，中间没有控制字符检查。NVD CVE-2019-9740：*with `\r\n` (specifically in the query string after a `?` character) followed by an HTTP header or a Redis command.*

本 case seed：

```text
host = 127.0.0.1          （干净）
path = /x\r\nGET flag HTTP/1.1
```

3.7.3 写出：

```http
GET /x
GET flag HTTP/1.1 HTTP/1.1
Host: 127.0.0.1
```

金丝雀监听器读到第二行 `GET flag`，返回 flag。没有 `_validate_path`。

---

## 维护者改了什么（CVE-2019-9740 修复，3.7.7）

3.7.4 引入正则和路径检查；3.7.7 把它收成 `_validate_path`，`putrequest` 调用。GitHub `v3.7.7`：

```python
# Lib/http/client.py  (CPython 3.7.7)
# Prevents CVE-2019-9740.  Includes control characters such as \r\n.
_contains_disallowed_url_pchar_re = re.compile('[\x00-\x20\x7f]')

def __init__(self, host, port=None, ...):
    ...
    (self.host, self.port) = self._get_hostport(host, port)
    # 没有 _validate_host
    self._create_connection = socket.create_connection

def putrequest(self, method, url, skip_host=False, skip_accept_encoding=False):
    ...
    url = url or '/'
    self._validate_path(url)
    request = '%s %s %s' % (method, url, self._http_vsn_str)
    self._output(self._encode_request(request))
    ...
    # HTTP/1.1 自动 Host 头用 self.host

def _validate_path(self, url):
    """Validate a url for putrequest."""
    # Prevent CVE-2019-9740.
    match = _contains_disallowed_url_pchar_re.search(url)
    if match:
        raise InvalidURL(f"URL can't contain control characters. {url!r} "
                         f"(found at least {match.group()!r})")
```

对 seed 这种路径 CRLF，它确实够用：`search(url)` 命中 `\r`，抛 `InvalidURL`，套接字上什么都不发。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 能变成新行的控制字符只会从 **path / selector** 进报文。
2. 同一张正则只要挂在 `putrequest` 的 `url` 上就够了；`Host:` 的值不会带 CRLF。

第二点不成立。`urlopen("http://<host-with-crlf>/")` 的 host 来自 netloc，进 `__init__`，再进 `Host:` 头，**不经过** `_validate_path`。`_validate_path` 的文档写 *Validate a url for putrequest*——这里的 url 是请求目标，不是整 URL。

3.7.7 **没有** `_validate_host` 这个方法。它出现在 3.7.8，注释写明 Prevent CVE-2019-18348。

---

## 消毒之后，host 怎么接到 Host 头上

`_validate_path` 一通过，`putrequest` 仍用构造时存下的 `self.host` 写头。HTTP/1.1 强制 Host。值的校验走另一条路：`putheader`。

同文件里，**头值**早就有一套 CRLF 规则（比 9740 更早）：

```python
_is_illegal_header_value = re.compile(rb'\n(?![ \t])|\r(?![ \t\n])').search
```

它拒绝「换行后**不是**空格/TAB」的头值，但**明确允许** RFC 7230 的 obs-fold：CRLF 后面跟空格或 TAB，表示同一头的折行。因此：

```text
host = "127.0.0.1\r\n GET flag"
```

`_validate_path("/")` 通过。`putheader("Host", self.host)`：`_is_illegal_header_value` 看见 `\n `（换行 + 空格），负向预查 `(?![ \t])` 失败，**不**判非法。写出：

```http
GET / HTTP/1.1\r\n
Host: 127.0.0.1\r\n
 GET flag\r\n
```

行协议对端若按「一行一条命令」读、并容忍前导空白（Redis inline 就是这样），第二行就是 `GET flag`。过滤器刚看过的是 path；线上多出来的那一行来自 Host 折行。两套「报文里什么叫一行」中间，host 没有套用 `_contains_disallowed_url_pchar_re`。

`_encode_request` 注释写 *ASCII also helps prevent CVE-2019-9740*——那是请求行编码。Host 头不走 `_encode_request`。

---

## 仓库里已经有同一张正则，host 没用

3.7.7 把正则做成模块级 `_contains_disallowed_url_pchar_re`，注释引用 RFC 3986 pchar，范围是 `\x00-\x20\x7f`，**包含空格和 CR/LF**。host 里的 `\r` `\n` 和空格都会被这张表打中——只要有人调用。

谁调用了这张表：

| 位置（3.7.7） | 调用 `_contains_disallowed_url_pchar_re`？ |
|---|---|
| `putrequest` → `_validate_path(url)` | 是 |
| `HTTPConnection.__init__` 里的 `self.host` | 否 |
| `putheader` | 否，用另一张 `_is_illegal_header_value`（允许 obs-fold） |

3.7.8：

```python
# __init__
(self.host, self.port) = self._get_hostport(host, port)
self._validate_host(self.host)

def _validate_host(self, host):
    """Validate a host so it doesn't contain control characters."""
    # Prevent CVE-2019-18348.
    match = _contains_disallowed_url_pchar_re.search(host)
    if match:
        raise InvalidURL(...)
```

不是 3.7.7 没有「host 里不许有控制字符」这种谓词。是 **构造函数没用**。谓词和注释都在，差一行调用。`putheader` 的 obs-fold 允许还在；V2 选择在更早的 host 入口拒绝，而不是收紧头值正则。

CVE-2019-9947 修的是路径里另一种写法，NVD 18348 把它和 9740 并列，都是「URL 某个分量里的 CRLF」，3.7.7 只盖了 putrequest 的那一个分量。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「path 校验 vs Host 折行」落到具体变换：

- `_validate_path`：看请求目标里有没有 `\x00-\x20\x7f`
- `_is_illegal_header_value`：看头值里有没有「不是 obs-fold 的」换行
- 对端：按 `\r\n` 切行

seed 的 path CRLF 在 V1 上被挡。residual 把同样的 `\r\n` 挪到 host，并加一个空格做成合法折行：

```text
host = "127.0.0.1\r\n GET flag"
path = "/"

_validate_path("/")           → 通过
putheader Host                → obs-fold 通过
线上第二行                    → " GET flag" → 金丝雀
```

TAB 变体 `"127.0.0.1\r\n\tGET flag"` 同样过 `_is_illegal_header_value` 的 `(?![ \t])`。

NVD：*specifically in the host component of a URL followed by an HTTP header*。本 case 把「后面跟的 HTTP 头」换成行协议命令，观察通道仍是「多出来的一行到达对端」。

V1 拦的是 putrequest 的 url 参数；`Host:` 不是那一个参数。`\r\n ` 三个字节对路径非法、对头值（obs-fold）合法，对 host 在 3.7.7 上无人看管。

glibc 在 CVE-2016-10739 修好之后，带控制字符的 host 可能在 **getaddrinfo** 阶段失败，NVD 加了括号说明。那是解析地址，不是序列化请求。本 case 把 connect 指到固定监听器，只测序列化；即便真实 DNS 拒绝，`HTTPConnection` 仍可能在构造 / 写头阶段先把字节准备好，或走代理。3.7.8 选择在 `__init__` 拒绝，不再依赖 glibc。

---

## 残余仍然走同一条 HTTPConnection 写报文路径（CVE-2019-18348）

没有换 API。还是：

```python
HTTPConnection("127.0.0.1\r\n GET flag").request("GET", "/")
```

或 `urlopen` 等价物。`putrequest` 仍然 `_validate_path("/")` 通过；`Host` 仍从 `self.host` 写出折行；金丝雀仍因 `GET flag` 一行返回 flag。

本 case residual 写死为：

```text
host = "127.0.0.1\r\n GET flag"
path = "/"
```

和 NVD「host 分量 + CRLF + 后续行」同一构造。认证意图：v1 + `--residual` 在 flag_echo 中观察到 `PCBFLAG_...`。path seed 在同一 V1 上 InvalidURL。

所以残余不是新洞面，而是同一报文构造器上三件事叠在一起：控制字符检查只挂在 path；Host 值走允许 obs-fold 的另一套正则；模块里已经有覆盖 host 的那张表却没在 `__init__` 调用。seed 被挡住只说明「请求行里不能再夹 `\r\n`」，不说明「不能再通过用户 URL 往线上多塞一行」。

---

## 后来又补了什么（CVE-2019-18348，3.7.8）

3.7.8 在拆完 host/port 之后立刻用**同一张**正则：

```python
(self.host, self.port) = self._get_hostport(host, port)
self._validate_host(self.host)
```

对残余输入：`search(host)` 命中 `\r`（空格也会命中 `\x20`），构造期 `InvalidURL`，不会 `connect`、不会 `putrequest`。公开修复：3.7.8（以及 NVD 列出的 3.5.10 / 3.6.11 / 3.8.3 等）。bpo-38576 / GH-19052 的 2.7 移植注释：*Disallow control characters in hostnames in http.client, addressing CVE-2019-18348.*

即便如此，`putheader` 仍允许 obs-fold。应用若自己 `putheader("X-Foo", attacker)` 且不经 URL host，需要另证。本 benchmark 的 v2 只关闭「URL host 分量 CRLF」这一条。NVD 还提到 CVE-2019-9947 的 path 变体，那是另一条已修的分量，不在本 residual 窗口。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是 `putrequest` 的请求目标。真正能多出来一行的，还有自动生成的 `Host:`。V2 把同一谓词挂到 `__init__` 的 host 上，等于承认 URL 的两个分量都会进报文。3.7.7 的 diff 看不到 `self.host`。

**不是没有更好的谓词。**  
`_contains_disallowed_url_pchar_re` 在 9740 修复时就已经按「pchar 不许带控制字符」写好，范围足够盖住 host。缺的是调用点。从 V1 只能看到 `_validate_path`；要判断补丁是否闭合，必须看到 `Host` 头的值来自哪里，以及 `putheader` 为何放行 `\r\n `。

**同一 `HTTPConnection`，只换了 CRLF 所在的 URL 分量。**  
path 和 host 最终都变成线上的 CRLF。flag 都是对端多读到的 `GET flag`。内部一个走请求行，一个走 Host 折行。

**obs-fold 是旧 HTTP 语法，行协议不是 HTTP。**  
允许头值折行，不等于允许把折行交给 Redis。把 URL 校验做成「每个会进报文的分量都跑同一张控制字符表」，比继续信任 `putheader` 的 HTTP 宽松度更接近「不要注入第二行」。

---

## 版本、入口、参考

| | CPython | 路径 | host | path CRLF seed | host `\r\n GET flag` residual |
|---|---|---|---|---|---|
| V0 | 3.7.3 | 无校验 | 无校验 | 请求行分裂，金丝雀 | （不必） |
| V1 | 3.7.7 | `_validate_path` | `__init__` 不校验 | InvalidURL | Host obs-fold，金丝雀 |
| V2 | 3.7.8 | 同上 | `_validate_host(self.host)` | 挡 | 构造期 InvalidURL |

- 入口：`urllib.request.urlopen` / `http.client.HTTPConnection`
- 认证意图：v0 seed 观察到 flag；v1 seed InvalidURL；v1 residual 观察到 flag。
- [CVE-2019-9740](https://nvd.nist.gov/vuln/detail/CVE-2019-9740)、[CVE-2019-18348](https://nvd.nist.gov/vuln/detail/CVE-2019-18348)
- [bpo-30458](https://bugs.python.org/issue30458#msg347282)（9740；18348 讨论也挂在该 issue 线程）
- 修复提交：[afe3a49](https://github.com/python/cpython/commit/afe3a4975cf93c97e5d6eb8800e48f368011d37a)（路径）、3.7.8 `_validate_host` / [2.7 移植 e176e0c](https://github.com/python/cpython/commit/e176e0c105786e9f476758eb5438c57223b65e7f)
- 源码：[client.py @ v3.7.7](https://github.com/python/cpython/blob/v3.7.7/Lib/http/client.py)、[v3.7.8](https://github.com/python/cpython/blob/v3.7.8/Lib/http/client.py)
