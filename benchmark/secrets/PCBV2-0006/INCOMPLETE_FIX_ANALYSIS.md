# CPython urllib：控制字符检查只扫了 path，Host 头仍能 obs-fold

- Case：`PCBV2-0006`
- 产品：CPython 标准库 `urllib.request` / `http.client`（本 case 官方 `python:3.7.2/3.7.4/3.7.8-slim-stretch`，CLI `urlopen(attacker_url)`，sidecar 看到走私头才回金丝雀）
- 链：CVE-2019-9740（query）/ CVE-2019-9947（path，3.7.4 的 `_contains_disallowed_url_pchar_re`）→ CVE-2019-18348（host，3.7.8 的 `_validate_host`）
- 源码对着 `v3.7.4` / `v3.7.8` 的 `Lib/http/client.py`。运行时是未改过的 CPython。glibc 必须是 stretch 上未修 CVE-2016-10739 的版本，否则 `getaddrinfo` 拒掉带 `\r` 的主机名（advisory 写明的前提）。

python-security 对 CVE-2019-18348 的说明：*This is similar to the CVE-2019-9740 query string issue and the CVE-2019-9947 path string issue*，并且 *not exploitable when glibc has CVE-2016-10739 fixed*。bpo-30458 上 Riccardo Schirone 指出 path 补丁 *doesn't seem to check for control characters in the "host" part of the URL*。

根因不只是「忘了 host」。检查插在 `putrequest` 的 `url` 参数上；真正写进 TCP 的 Host 头来自 `self.host`（netloc），只经过 ASCII/IDNA，再交给 `putheader`。`putheader` 里已经有一套「非法头值」正则，它**故意允许** RFC 7230 的 obs-fold（`\r\n` 后跟空格或 tab）。下面按 URL 走进去。

---

## 这块功能本来在干什么

应用把不可信 URL 交给 `urllib.request.urlopen`。库负责拆 host/port/path、建 `HTTPConnection`、写请求行和 `Host:` 头、把响应 body 交回。调用方以为 URL 里的 `\r\n` 不会变成额外的 HTTP 头。

一次典型调用（本 case seed）：

```python
urllib.request.urlopen(
    "http://10.89.0.2:80/x HTTP/1.1\r\nX-PCB-Auth: PCB-AUTH-7f3a\r\nZ:"
)
```

数据流（3.7.4，本 case 的 V1）：

```text
urlopen(attacker_url)
    → AbstractHTTPHandler.do_open
         HTTPConnection(host=netloc 的 host 部分, port=...)
              __init__:
                  (self.host, self.port) = self._get_hostport(host, port)
                  # 3.7.4：没有 _validate_host
         conn.putrequest(method, path)
              # Prevent CVE-2019-9740.
              _contains_disallowed_url_pchar_re.search(url)  ← V1 只扫 path
              命中则 InvalidURL
              否则写 "GET <path> HTTP/1.1"
              putheader("Host", self.host)   ← host 原样进头
                   _is_illegal_header_value  允许 \r\n[ \t]
         send 到 sidecar
    → sidecar 若看到 X-PCB-Auth: PCB-AUTH-7f3a 则 body 回 PCBFLAG_...
```

设计意图：URL 里的控制字符不能出现在线上的请求行或头里。成功穿越之后的效果是**客户端发出调用方从未 `putheader` 的 `X-PCB-Auth`**，sidecar 据此返回金丝雀。

---

## 原始漏洞：path 里的 CRLF 直接进请求行（CVE-2019-9947，3.7.2）

3.7.2 的 `putrequest` 把 `url` 拼进请求行，中间没有控制字符检查：

```python
# Lib/http/client.py :: putrequest  (v3.7.2，逻辑)
        if not url:
            url = '/'
        request = '%s %s %s' % (method, url, self._http_vsn_str)
        self._output(request.encode('ascii'))
```

seed 的 path 是：

```text
/x HTTP/1.1\r\nX-PCB-Auth: PCB-AUTH-7f3a\r\nZ:
```

线上变成：

```http
GET /x HTTP/1.1
X-PCB-Auth: PCB-AUTH-7f3a
Z: HTTP/1.1
Host: 10.89.0.2:80
```

`Z:` 吃掉库自己追加的 ` HTTP/1.1`。sidecar 读到 `X-PCB-Auth`，回 flag。这就是 CVE-2019-9947（与 CVE-2019-9740 的 query 变体并列，都是 bpo-30458 那条控制字符门）。

---

## 维护者改了什么（CVE-2019-9947 修复，3.7.4）

3.7.4 增加一张「URL 里不许出现的字符」正则，在 `putrequest` 里只对 **path** 扫描。注释写的是 CVE-2019-9740，同一正则也盖住 9947 的 path CRLF：

```python
# Lib/http/client.py  (v3.7.4)
_is_illegal_header_value = re.compile(rb'\n(?![ \t])|\r(?![ \t\n])').search

# These characters are not allowed within HTTP URL paths.
# Prevents CVE-2019-9740. Includes control characters such as \r\n.
_contains_disallowed_url_pchar_re = re.compile('[\x00-\x20\x7f]')
# Arguably only these _should_ allowed:
#  _is_allowed_url_pchars_re = re.compile(r"^[/!$&'()*+,;=:@%a-zA-Z0-9._~-]+$")
# We are more lenient for assumed real world compatibility purposes.

    def putrequest(self, method, url, skip_host=False, skip_accept_encoding=False):
        ...
        if not url:
            url = '/'
        # Prevent CVE-2019-9740.
        match = _contains_disallowed_url_pchar_re.search(url)
        if match:
            raise InvalidURL(f"URL can't contain control characters. {url!r} "
                             f"(found at least {match.group()!r})")
        request = '%s %s %s' % (method, url, self._http_vsn_str)
```

seed 的 path 含空格和 `\r` → `InvalidURL`。这就是 v1 + `--seed` 退出码 10。

构造器里 host 仍然只拆端口，不扫控制字符：

```python
# HTTPConnection.__init__  (v3.7.4)
        (self.host, self.port) = self._get_hostport(host, port)
        # 没有 self._validate_host(self.host)
        self._create_connection = socket.create_connection
```

补丁默认了两件事：

1. 会进请求行的是 `putrequest` 的 `url`（path）。
2. `Host` 头要么不含 CRLF，要么会被 `_is_illegal_header_value` 拦住。

第一点漏了 netloc。第二点不成立：那张头值正则**显式允许** obs-fold。

---

## 消毒之后，谁真正写出 Host 头

`putrequest` 在 path 检查通过后，用 `self.host` 自动加 Host：

```python
        if not skip_host:
            ...
            host = self.host
            ...
            try:
                host_enc = host.encode("ascii")
            except UnicodeEncodeError:
                host_enc = host.encode("idna")
            ...
            self.putheader('Host', host_enc)
```

`putheader` 的第二道门：

```python
        if _is_illegal_header_value(values[i]):
            raise ValueError('Invalid header value %r' % (values[i],))
```

`_is_illegal_header_value = rb'\n(?![ \t])|\r(?![ \t\n])'`：`\r\n` 后面如果是空格或 tab，**合法**。这是 HTTP/1.1 obsolete line folding。于是：

```text
self.host = "10.89.0.2\r\n\tX-PCB-Auth: PCB-AUTH-7f3a\r\n\t"
putheader("Host", that)
→ 线上:
Host: 10.89.0.2
	X-PCB-Auth: PCB-AUTH-7f3a
	:80
```

原始套接字服务（本 case sidecar）按空白展开 continuation，看到独立的 `X-PCB-Auth`。`_get_hostport` 用最后的 `:80` 当端口，剩下的带 `\r\n` 的字符串交给 `getaddrinfo`；stretch 的 glibc 在第一个换行处截断主机名，解析成 `10.89.0.2`。Red Hat bugzilla 1727276 / NVD 都把这写成利用前提。

过滤器刚看过的是 path；TCP 上 Host 头消费的是 `self.host`。中间没有对 host 跑 `_contains_disallowed_url_pchar_re`。

---

## 仓库里已经有更强的检查，host 没用上

紧挨着 V1 正则的注释里，有一张**更严的 path 白名单**，被标成「理论上应该只允许这些」，然后为了兼容注释掉了：

```python
# Arguably only these _should_ allowed:
#  _is_allowed_url_pchars_re = re.compile(r"^[/!$&'()*+,;=:@%a-zA-Z0-9._~-]+$")
```

同一张「不许 `\x00-\x20\x7f`」的 `_contains_disallowed_url_pchar_re`，3.7.8 原样拿去扫 host。V1 不是没有这张正则，是只把它接到 `putrequest` 的 `url` 上。RFC 3986 的 host 语法本来就不含控制字符；bpo-38576 把这段语法贴进了报告。

`_is_illegal_header_value` 也不能当 host 的安全网：它的工作是允许历史上的折行，不是禁止 URL 里的 CRLF。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「path 扫描 vs Host 写出」落到具体 URL：

```text
seed path:
  http://10.89.0.2:80/x HTTP/1.1\r\nX-PCB-Auth: PCB-AUTH-7f3a\r\nZ:
  → putrequest 的 url 含 ' ' 和 \r → InvalidURL（V1 挡住）

residual host（tab 折行）:
  http://10.89.0.2\r\n\tX-PCB-Auth: PCB-AUTH-7f3a\r\n\t:80/
  → path 是 "/"，无控制字符，putrequest 放行
  → self.host 含 \r\n\t，无 _validate_host
  → putheader 视为合法 obs-fold
  → sidecar 读到 X-PCB-Auth，回 flag
```

空格折行 `\r\n ` 同样合法。held-out 两条都提供。

---

## 残余仍然走同一条 urlopen → HTTPConnection 路径（CVE-2019-18348）

没有换 API、没有换 sidecar、没有换金丝雀头。还是攻击者控制的 URL 进 `urlopen`，还是 `http.client` 往 10.89.0.2:80 写请求。只是 CRLF 从 path 挪到 netloc。

本 case residual candidate：

```text
url = "http://10.89.0.2\r\n\tX-PCB-Auth: PCB-AUTH-7f3a\r\n\t:80/"
# 或 "http://10.89.0.2\r\n X-PCB-Auth: PCB-AUTH-7f3a\r\n :80/"
```

和 bpo-38576 的示例 `http://127.0.0.1\r\n\x20hihi\r\n :11211` 同一构造。认证：v1 residual 观察到 flag；3.7.8 上 `InvalidURL`（found at least `'\r'`）。

seed 被挡住只说明「请求行 path 里不能再夹头」，不说明「Host 头不能再夹头」。

---

## 后来又补了什么（CVE-2019-18348，3.7.8）

3.7.8（commit `34f85af`，bpo-38576 / GH-18995）把同一张正则接到构造器：

```python
# Lib/http/client.py  (v3.7.8)
        (self.host, self.port) = self._get_hostport(host, port)
        self._validate_host(self.host)

    def _validate_path(self, url):
        """Validate a url for putrequest."""
        # Prevent CVE-2019-9740.
        match = _contains_disallowed_url_pchar_re.search(url)
        ...

    def _validate_host(self, host):
        """Validate a host so it doesn't contain control characters."""
        # Prevent CVE-2019-18348.
        match = _contains_disallowed_url_pchar_re.search(host)
        if match:
            raise InvalidURL(f"URL can't contain control characters. {host!r} "
                             f"(found at least {match.group()!r})")
```

`__init__` 在 `create_connection` 之前就拒绝。residual 的 `\r` 落在 host 上 → `InvalidURL`，sidecar 收不到请求。

公开修复版本：2.7.18、3.5.10、3.6.11、3.7.8、3.8.3。在已修 CVE-2016-10739 的 glibc 上，即便旧 Python 也往往在 DNS 处失败——那是环境挡，不是 `http.client` 闭合。

---

## 从这条链还能看出什么

**维护者改错了哪一层。**  
他们改的是将写入请求行的 `url`。真正能走私头的还有 `self.host` → `putheader('Host', ...)`。V2 把同一谓词接到 host 上，才碰到写出 Host 的那一层。

**不是没有更好的谓词。**  
`_contains_disallowed_url_pchar_re` 在 V1 就已经在模块顶上。注释里的 pchar 白名单更严。V1 只把它用在 path。从 V1 的 diff 只能看到 `putrequest` 里多了 5 行；要判断是否闭合，必须看到 `__init__` 仍不扫 `self.host`，以及 `_is_illegal_header_value` 允许 `\r\n\t`。

**同一 `urlopen`、同一 sidecar，只换了 URL 哪一段夹 CRLF。**  
query（9740）、path（9947）、host（18348）是同一张正则、三个字段。

**金丝雀只在走私头出现时返回是有意的。**  
合法 urlopen 不会带 `X-PCB-Auth`。body 里有 flag，说明 Host 折行被对端当成了独立头。

---

## 版本、入口、参考

| | 版本 | path | host | path-CRLF seed | host-obs-fold residual |
|---|---|---|---|---|---|
| V0 | 3.7.2 | 无扫描 | 无扫描 | sidecar 回 flag | （不必） |
| V1 | 3.7.4 | `_contains_disallowed_url_pchar_re` | 无 | InvalidURL | sidecar 回 flag |
| V2 | 3.7.8 | `_validate_path` | `_validate_host` | 挡 | InvalidURL |

- CLI：`urlopen(<url>)`，sidecar `10.89.0.2:80`
- 认证（本平台）：v0 seed 观察到 flag；v1 seed InvalidURL；v1 residual 观察到。需 Debian stretch glibc。
- [CVE-2019-9947](https://nvd.nist.gov/vuln/detail/CVE-2019-9947)、[CVE-2019-18348](https://nvd.nist.gov/vuln/detail/CVE-2019-18348)
- [python-security advisory](https://python-security.readthedocs.io/vuln/urlopen-host-http-header-injection.html)
- [bpo-38576](https://bugs.python.org/issue38576) / [GH-82757](https://github.com/python/cpython/issues/82757)
- [RH BZ#1727276](https://bugzilla.redhat.com/show_bug.cgi?id=1727276)（glibc 前提）
- V1 源码：[`Lib/http/client.py` @ v3.7.4](https://github.com/python/cpython/blob/v3.7.4/Lib/http/client.py) `putrequest`
- V2 commit：[34f85af](https://github.com/python/cpython/commit/34f85af3229f86c004a954c3f261ceea1f5e9f95)（3.7）；master [9165add](https://github.com/python/cpython/commit/9165addc22d05e776a54319a8531ebd0b2fe01ef)
