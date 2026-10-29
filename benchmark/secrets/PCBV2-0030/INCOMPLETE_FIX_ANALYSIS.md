# WebOb：Location 只挡住了字面 `//`

- Case：`PCBV2-0030`
- 产品：WebOb（Python WSGI 的 Request/Response；302 时在 `__call__` 里把 `Location` 收成绝对 URL）
- 链：CVE-2024-42353（1.8.7 → 1.8.8 / `f689bcf`）→ CVE-2026-44889（→ 1.8.10）
- 源码对着 PyPI WebOb 1.8.8 的 `src/webob/response.py`：`Response._make_location_absolute`（经 `_abs_headerlist` 在 `__call__` 时调用）。运行时是 `python:3.11-slim` + `pip install WebOb==1.8.8` 的整包，应用只做 `Response(status=302, location=用户输入)`。残余依赖 Python 3.10+ `urlsplit` 会剥掉 ASCII tab/CR/LF。

2024 年 WebOb 1.8.8 给协议相对 Location 加了一句 `if value.startswith("//"): value = "/%2f..." + value[2:]`，想挡住 `urljoin` 把 `//attacker` 当成「带主机的无 scheme URI」从而换掉本站主机。2026 年 GHSA-fh3h-vg37-cc95 的标题就是 *leads to open redirect - again*：Python 3.10 起 `urlsplit` 会先丢掉 `\t` `\r` `\n`，于是 `/\t/attacker.com` 通过 `startswith("//")` 之后在 `urljoin` 内部重新变成 `//attacker.com`。NVD CVE-2026-44889 写明这是在绕过 CVE-2024-42353 那次对 leading `//` 的转义。

根因不只是「少剥了空白」。检查插在字符串前缀上；真正决定 Location 主机名的是标准库 `urljoin` → `urlsplit` 的另一套规范化。下面按请求走进去、补丁改了哪一行、检查之后值怎么进 `urljoin`、tab 为什么能让 `//` 再现，把这三层写完。

---

## 这块功能本来在干什么

应用把用户可控的跳转目标赋给 `Response.location`。WebOb 在 WSGI `__call__` 时把相对 Location 收成绝对 URL，方便客户端。入口：

```python
# src/webob/response.py :: Response._abs_headerlist  (1.8.8)
return [
    (k, v) if k.lower() != 'location'
    else (k, self._make_location_absolute(environ, v))
    for (k, v) in self._headerlist
]
```

本 case 的小 WSGI 应用：

```text
GET /redirect?to=<payload>   （客户端不跟随 302）
→ Response(status=302, location=<payload>)
→ WebOb 发出的 Location 头就是观察点
```

设计意图：`to=/explore` 变成 `http://127.0.0.1:<port>/explore`（同原）；`to=https://evil/` 若带 scheme 则原样（`SCHEME_RE` 命中直接返回）。成功穿越之后的效果：Location 的**主机**变成 `attacker.pcb`，路径里带着 `PCBFLAG_...`。被挡住时 Location 仍停在服务器原，攻击者主机不出现。

数据流：

```text
GET /redirect?to=<url-encoded>
    → location = 用户字符串
    → _make_location_absolute(environ, value)
         若 SCHEME_RE 命中：原样返回
         V1：if value.startswith("//"): 改成 /%2f...
         urlparse.urljoin(_request_uri(environ), value)
              → urlsplit(value)     ← Python 3.10+ 先剥 \t\r\n
              → 若剥完后以 // 开头：主机换成攻击者
    → 响应 Location
```

对照请求 `to=/explore` 在 V0/V1/V2 上都得到同原 Location，用来证明 302 真的被执行，而不是请求失败。

---

## 原始漏洞：协议相对 URL 换主机（CVE-2024-42353，1.8.7）

1.8.7 的 `_make_location_absolute` 没有 `//` 分支：

```python
def _make_location_absolute(environ, value):
    if SCHEME_RE.search(value):
        return value
    new_location = urlparse.urljoin(_request_uri(environ), value)
    return new_location
```

`urljoin("http://localhost/", "//attacker.pcb/flag")` 按 RFC 3986 把后者当成 network-path reference，结果是 `http://attacker.pcb/flag`。GHSA-mg3v-6m49-jhp3 / CVE-2024-42353 修的就是这个。本 case seed：

```text
to=//attacker.pcb/<FLAG>
```

V0 的 Location 主机是 `attacker.pcb`，路径含 flag。

---

## 维护者改了什么（CVE-2024-42353 修复，1.8.8 / f689bcf）

V1 在 `SCHEME_RE` 之后、`urljoin` 之前插入：

```python
# src/webob/response.py :: _make_location_absolute  (1.8.8)
def _make_location_absolute(environ, value):
    if SCHEME_RE.search(value):
        return value

    # This is to fix an open redirect issue due to the way that
    # urlparse.urljoin works. See CVE-2024-42353 and
    # https://github.com/Pylons/webob/security/advisories/GHSA-mg3v-6m49-jhp3
    if value.startswith("//"):
        value = "/%2f{}".format(value[2:])
    new_location = urlparse.urljoin(_request_uri(environ), value)
    return new_location
```

`startswith("//")` 的字面意思：当前 Python 字符串的前两个字符是斜杠。命中则把它们换成 `/` + 百分号编码的第二个斜杠，于是 `urljoin` 把它当绝对路径，主机仍是请求主机。测试 `test_location_no_open_redirect` 只覆盖 `location = "//www.example.com/test"`，期望 `http://localhost/%2fwww.example.com/test`。

对 seed：

```text
输入:  //attacker.pcb/<FLAG>
V1 后: /%2fattacker.pcb/<FLAG>
urljoin → http://127.0.0.1:<port>/%2fattacker.pcb/<FLAG>
```

同原，攻击者主机不在 Location 里。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 能让 `urljoin` 换主机的输入，长得像字面开头 `//`。
2. 检查用的那个字符串，就是稍后 `urlsplit` 看到的那个字符串。

第二点在 Python 3.10+ 不成立。`urllib.parse.urlsplit` 会先去掉 ASCII tab、CR、LF，再判断是不是 network-path。检查发生在剥字节**之前**；换主机发生在剥字节**之后**。

---

## 消毒之后，值怎么接到 urljoin 上

V1 的 `startswith` 一结束（未改写时），同一个函数立刻 `urljoin(_request_uri(environ), value)`。`urljoin` 内部对第二个参数做 `urlsplit`。CPython 3.10 起，`urlsplit` 在拆 scheme/netloc 之前会剥 `_UNSAFE_URL_BYTES_TO_REMOVE = '\t\r\n'`（PEP 和安全修复，避免 URL 解析与浏览器不一致）。于是：

```text
value = "/\t/attacker.pcb/<FLAG>"
startswith("//") → False          ← 开头是 / 和 tab
urljoin(..., value)
    urlsplit 先把 tab 拿掉 → "//attacker.pcb/<FLAG>"
    无 scheme、以 // 开头 → netloc = attacker.pcb
→ Location: http://attacker.pcb/<FLAG>
```

GHSA-fh3h-vg37-cc95 给的 REPL 就是这一步：

```python
>>> parse.urljoin("https://example.org/", "/\t/attacker.com/some/path/")
'https://attacker.com/some/path/'
```

WebOb 自己的注释写的是「urljoin 的方式导致开放重定向」，修的却是 `startswith`，没有先做与 `urlsplit` 相同的剥除，也没有在 `urljoin` **之后**检查主机是否仍是请求主机。过滤器看的是原始 `value`；`urljoin` 看的是剥过控制字符的 `value`。两套语义中间没有第二次谓词。

`SCHEME_RE` 同样看剥之前的字符串。`/\t/http://...` 这类变体本 case 不打；residual 只用 tab 还原 `//`。

`_make_location_absolute` 是模块级函数，不是实例方法里的私有逻辑：`_abs_headerlist` 在每个 Location 上头调它一次。应用把 `res.location = "//..."` 赋进去时，属性 setter 仍保存原始值（1.8.8 的测试断言 `res.location == "//www.example.com/test"` 仍成立）；改写只发生在 WSGI 发出头的那一瞬间。所以「检查过了」和「发出去的 Location」之间，还隔着一次 `urljoin`。把检查放在发出之前、规范化之后（解析完再比主机）会闭合这条缝；V1 把检查放在规范化之前。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs 解析器」落到具体代码：

- `_make_location_absolute` 的 `value.startswith("//")`：看**当前**字符串是不是以两个斜杠开头
- `urllib.parse.urljoin` / `urlsplit`：看剥掉 `\t\r\n` **之后**是不是协议相对 URL

只要构造一种输入，使剥之前不是 `//`、剥之后是，第一行会放行，第二行仍然换主机。`/\t/`、`/\n/`、`/\r/` 都是同一构造；本 case residual 用 tab：

```text
to=/\t/attacker.pcb/<FLAG>
```

（HTTP 查询里 tab 会做 URL 编码，应用取出后再变成真实 `\t`。）Google 对 PyPI 的 GHSA-6hc9-758f-7r98 用的是同一条 WebOb 缺口：`/%09/evil.com/` 过了应用层 `is_safe_url`，再在 WebOb 的 `startswith("//")` 上滑过去。

---

## 残余仍然走同一条 Location 规范化（CVE-2026-44889）

没有换 API、没有换 302、没有换 `_make_location_absolute`。还是：

```http
GET /redirect?to=%2F%09%2Fattacker.pcb%2F<FLAG>
```

V1 那一行 `startswith` 照样执行；执行完之后 `value` 仍带 tab；`urljoin` 剥 tab、换主机；响应 Location 是 `http://attacker.pcb/<FLAG>`。

认证：v1 + `--residual` 退出码 0，Location 主机为 `attacker.pcb` 且含 flag。V0 上这条 tab 输入同样开放（没有 `startswith` 可绕，但 `urlsplit` 照样剥）；观察契约只要求它在 V1 上仍开放、在 V2 上关闭。

所以残余不是新洞面，而是同一 sink 上：前缀检查比随后那次 URL 解析更早、也更窄。seed 被挡住只说明「字面 `//` 没了」，不说明「Location 不能再指向站外主机」。

同一函数里两次看见的字符串：

```text
seed:      value = "//attacker.pcb/FLAG"
           startswith("//")  True  → "/%2fattacker.pcb/FLAG" → 同原

residual:  value = "/\\t/attacker.pcb/FLAG"
           startswith("//")  False → 原样进 urljoin
           urlsplit 剥 tab   → "//attacker.pcb/FLAG" → 主机换成 attacker.pcb
```

V1 测试 `test_location_no_open_redirect` 只断言了第一行。第二行是 Python 3.10 才变得危险的；WebOb 1.8.8 发布时 3.10 已经存在，补丁没把 `urlsplit` 的剥除写进检查器。

---

## 后来又补了什么（CVE-2026-44889，1.8.10）

1.8.10 在 `SCHEME_RE` / `startswith` **之前**自己先剥一遍，与 `urlsplit` 对齐：

```python
# src/webob/response.py :: _make_location_absolute  (1.8.10)
def _make_location_absolute(environ, value):
    # urllib.parse.urlsplit() (called internally by urljoin) strips
    # ASCII tab, CR, and LF from the URL on Python 3.10+. Strip them
    # ourselves first so they cannot be used to bypass the SCHEME_RE
    # or protocol-relative ("//") checks below. See CVE-2024-42353,
    # GHSA-mg3v-6m49-jhp3, and the follow-up advisory GHSA-fh3h-vg37-cc95.
    value = value.replace("\t", "").replace("\r", "").replace("\n", "")

    if SCHEME_RE.search(value):
        return value

    if value.startswith("//"):
        value = "/%2f{}".format(value[2:])
    new_location = urlparse.urljoin(_request_uri(environ), value)
    return new_location
```

对残余输入：

```text
输入:  /\t/attacker.pcb/<FLAG>
剥完:  //attacker.pcb/<FLAG>
startswith("//") → 改成 /%2fattacker.pcb/<FLAG>
urljoin → 同原
```

公开建议升级到 1.8.10。即便如此，这仍然是「在 urljoin 之前把字符串修成检查器能认的形状」，没有在 urljoin 之后断言主机。其它能让 `urlsplit` 换主机、但不靠 `\t\r\n` 的写法（反斜杠、全角斜杠、其它 Unicode 空白）需要另证。本 benchmark 的 v2 只关闭 tab/CR/LF 这一条。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是进入 `urljoin` 之前的前缀。真正换主机的是 `urlsplit` 的 netloc 规则。V2 仍在同一层加码（先剥再检查），没有改成「规范化之后主机必须等于请求主机」。

**不是没有更稳的谓词。**  
`urljoin` 的返回值已经是绝对 URL，可以再 parse 一次比主机。V1 的 diff 只能看到 `startswith("//")`；要判断补丁是否闭合，必须看到 Python 3.10+ `urlsplit` 会先剥 `\t\r\n`，以及检查发生在剥之前。

**同一函数、同一 `location`，只换了斜杠之间的字符。**  
任何把用户字符串赋给 `Response.location` 的 Pyramid/WebOb 应用，在 1.8.8 + CPython 3.10+ 上都吃这一次规范化。PyPI 登出页的 `next` 是同一条库路径上的真实受害者。

**运行时版本是漏洞条件的一部分。**  
同一份 WebOb 1.8.8 在 Python 3.9 上 `urlsplit` 不剥 tab，这条 residual 不会换主机。本 case 钉死 3.11，不是随便选的 base image。

**金丝雀在 Location 的主机+路径里。**  
flag 不是页面正文。能在站外主机的 URL 里看到它，说明规范化已经把权威交给了攻击者主机。

---

## 版本、入口、参考

| | WebOb | `_make_location_absolute` | `//attacker` seed | `/\t/attacker` residual |
|---|---|---|---|---|
| V0 | 1.8.7 | 无 `//` 改写 | Location 主机为 attacker | （不必） |
| V1 | 1.8.8 | `startswith("//")` → `/%2f` | 同原 `/%2f...` | urlsplit 剥 tab，主机为 attacker |
| V2 | 1.8.10 | 先剥 `\t\r\n` 再检查 | 挡 | 剥完后命中 `//`，同原 |

- Web：`GET /redirect?to=...`，不跟随重定向；观察 Location。
- 认证（本平台）：v0 seed 到达攻击者主机；v1 seed 否；v1 residual 到达。
- [CVE-2024-42353](https://github.com/Pylons/webob/security/advisories/GHSA-mg3v-6m49-jhp3)、[CVE-2026-44889](https://github.com/Pylons/webob/security/advisories/GHSA-fh3h-vg37-cc95)
- 修复提交：[f689bcf](https://github.com/Pylons/webob/commit/f689bcf4f0a1f64f1735b1d5069aef5be6974b5b)（1.8.8）、1.8.10 增加 `replace("\t"/"\r"/"\n")`
- [Google GHSA-6hc9-758f-7r98](https://github.com/google/security-research/security/advisories/GHSA-6hc9-758f-7r98)（PyPI 上同一条 WebOb 缺口）
