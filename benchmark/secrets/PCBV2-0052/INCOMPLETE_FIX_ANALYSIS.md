# aiohttp：`isdecimal()` 挡住了 `+0`，没挡住 Unicode 十进制数字

- Case：`PCBV2-0052`
- 产品：aiohttp（asyncio HTTP 客户端/服务器）。本 case 用纯 Python 解析器（`AIOHTTP_NO_EXTENSIONS=1`），pip 安装整包 `aiohttp==3.8.5` / `3.8.6` / `3.9.2`，打 keep-alive 连接上的 pipelined 请求。
- 链：CVE-2023-47627（3.8.5 → 3.8.6，commit `d5c12ba`，`int(length_hdr)` 换成 `str.isdecimal()`）→ CVE-2024-23829（→ 3.9.2，commit `33ccdfb`，`DIGITS.fullmatch(..., re.ASCII)`）
- 源码对着 GitHub tag `v3.8.6` 的 `aiohttp/http_parser.py`：嵌套函数 `get_content_length`、模块级 `VERSRE`。运行时是 PyPI 整包，不是抽出来的函数。

aiohttp 的纯 Python HTTP 解析器要决定「这一帧的 body 有多长」，才能把后续字节切成下一请求。代理按 RFC 只认 ASCII `0-9`；服务器若更宽松，就会把代理当成 body 的那一段当成新请求。3.8.6 用 `str.isdecimal()` 拒绝 `+0` / `1_0`。NVD CVE-2024-23829 写明：*This vulnerability exists due to an incomplete fix for CVE-2023-47627.* GHSA-8qpw-xqxj-h4r2 把同一件事说成：安全相关的字符集仍比标准宽，例如 Unicode 数字。

根因不只是「忘了 ASCII」。检查问的是 Python 的「是不是十进制数字」；真正用来算 body 长度、从而决定下一帧边界的是 `int()`。`isdecimal()` 对阿拉伯数字 `٠`（U+0660）为真，`int("٠")` 也是 0。下面按原始套接字走进去、3.8.6 改了哪一行、`int()` 之后谁消费那个长度、更窄的 ASCII 谓词有没有挂上，把这几层写完。

---

## 这块功能本来在干什么

aiohttp 服务器（本 case 关掉 llhttp 扩展）用 `HttpParser` 从字节流切请求。`Content-Length` 决定第一帧 body 在哪结束。一次典型走私：

```http
POST / HTTP/1.1
Host: t
Content-Length: +0

GET /flag HTTP/1.1
Host: t
Connection: close
```

若解析器把 `+0` 当成长度 0，第一帧没有 body，管道里的 `GET /flag` 变成第二个请求。harness 的 `GET /flag` 返回 `${PCB_FLAG}`。成功穿越之后的效果是：**内部路由被当作独立请求执行，flag 出现在同一条 TCP 流的响应里**。没有登录。判断完全信任「长度字段是十进制数字」，不信任「十进制」在 Unicode 里比 `[0-9]` 宽。

数据流：

```text
原始套接字字节
    → HttpParser.parse_message
         头字段 utf-8 decode（surrogateescape）
    → get_content_length()
         V0：int(length_hdr)          ← 接受 +0、1_0、Unicode 数字
         V1：strip(" \t").isdecimal() ← 拒 +0；仍接受 ٠ / ０ / ०
              再 int(length_hdr)
    → 按 length 切 body
    → 剩余字节当下一请求
    → GET /flag → PCBFLAG_...
```

llhttp 扩展路径不走这段 Python。本 case 用 `AIOHTTP_NO_EXTENSIONS=1` 强制纯 Python 解析器，和 GHSA 的「the python one, not llhttp」一致。

---

## 原始漏洞：`int()` 当长度校验（CVE-2023-47627，aiohttp 3.8.5）

3.8.5 的 `get_content_length`（`http_parser.py`，case `patch.diff` 对照，**observed**）：

```python
# aiohttp/http_parser.py :: get_content_length  （v3.8.5）
try:
    length = int(length_hdr)
except ValueError:
    raise InvalidHeader(CONTENT_LENGTH)
if length < 0:
    raise InvalidHeader(CONTENT_LENGTH)
return length
```

Python `int("+0") == 0`，`int("1_0") == 10`。RFC 9110 §8.6 要求 Content-Length 是 ASCII 数字，不允许符号和下划线。前端代理若按 RFC 把 `Content-Length: +0` 判非法或不当 0，后端 aiohttp 却当 0，管道请求就被走私进来。

本 case seed：`Content-Length: +0` 再接 `GET /flag`。V0 上 `int("+0")==0`，第二请求打到 `/flag`，响应里有 `PCBFLAG_...`。这就是 v0 + `--seed` 退出码 0。

---

## 维护者改了什么（CVE-2023-47627 修复，3.8.6）

tag `v3.8.6` 同一嵌套函数（`aiohttp/http_parser.py`，`HttpParser` 解析路径里的 `get_content_length`，约 L335–346）：

```python
def get_content_length() -> Optional[int]:
    # payload length
    length_hdr = msg.headers.get(CONTENT_LENGTH)
    if length_hdr is None:
        return None

    # Shouldn't allow +/- or other number formats.
    # https://www.rfc-editor.org/rfc/rfc9110#section-8.6-2
    if not length_hdr.strip(" \t").isdecimal():
        raise InvalidHeader(CONTENT_LENGTH)

    return int(length_hdr)
```

对 seed 这种明文 `+0`，它确实够用：`"+0".isdecimal()` 为假（`+` 不是十进制数字），抛 `InvalidHeader`，连接常以 400 关掉，管道里的 `GET /flag` 不再被当成第二请求。这就是 v1 + `--seed` 退出码 10。

同一次提交还把 `VERSRE` 从 `HTTP/(\d+).(\d+)` 收成 `HTTP/(\d).(\d)`（点仍未转义），状态码改成 `status.isdecimal()`。注释引用了 RFC 9110，意图是「不要允许 +/- 或其它数字格式」。

补丁默认了两件事：

1. `str.isdecimal()` 的「十进制」等于 HTTP 的 DIGIT = `%x30-39`。
2. 只要过了 `isdecimal()`，`int()` 得到的长度就是代理也会认同的长度。

第一点不成立。Python 文档：`isdecimal()` 对任何 Unicode decimal 字符为真，包括 `٠` U+0660、`０` U+FF10、`०` U+0966。`int()` 同样认识这些字符。

---

## 消毒之后，谁真正用那个长度去切帧

V1 的 `isdecimal()` 一过，同一函数立刻 `return int(length_hdr)`。调用方用这个整数当 body 长度，从缓冲区切走那么多字节，剩下的交给下一轮 `parse_message`。

过滤器刚看过的是「每个字符是不是 Unicode 十进制数字」；帧边界看到的是「`int()` 解析出来的整数」。两套语义中间没有第二次「必须是 ASCII `[0-9]+`」的谓词。flag 能出现在响应流里，依据就是长度被当成 0，走私的 `GET /flag` 真的进了应用路由，而不是「header 碰巧没报错」。

头值在进入 `get_content_length` 之前已经 `bvalue.decode("utf-8", "surrogateescape")`。所以 residual 在线上是 UTF-8 字节 `d9 b0`（`٠`），解析器看到的 Python 字符串是那个 Unicode 数字。held-out 注释写明了这一层（**observed**）。

同一文件里，`VERSRE = re.compile(r"HTTP/(\d).(\d)")` 的 `\d` 默认也吃 Unicode；状态码 `status.isdecimal()` 同病。GHSA-8qpw 的 PoC 是 `HTTP/1.𝟙`。本 case 的效果通道选 Content-Length，因为长度 0 直接决定走私是否成立；版本行的 Unicode 数字是同一字符集漏洞的另一扇门。

---

## 仓库里已经有 ASCII 数字的写法，长度没用

同一份 `http_parser.py` 在 3.8.6 已经为 chunked 大小准备了字节级十六进制：

```python
HEXDIGIT = re.compile(rb"[0-9a-fA-F]+")
```

方法名用的 `METHRE` 也是显式 `0-9A-Za-z`。Content-Length 和状态码却走了 `str.isdecimal()`。RFC 9110 的 DIGIT 是 ASCII；`re.compile(r"\d+", re.ASCII)` 才是那张表。

谁在问「这是不是数字」：

| 位置 | 3.8.6 用什么 | 吃 Unicode 十进制吗 |
|---|---|---|
| `get_content_length` | `str.isdecimal()` | **是** |
| 状态码 | `status.isdecimal()` | 是 |
| `VERSRE` 的 `\d` | 无 `re.ASCII` | 是 |
| `HEXDIGIT`（chunk size） | `[0-9a-fA-F]` | 否 |
| `METHRE` | `[...0-9A-Za-z]+` | 否 |

不是没有「只许 ASCII 数字」这个想法。是 **长度和状态码挂了 Python 的十进制谓词，而 HTTP 要的是 ASCII DIGIT**。从 V1 的 diff 只能看到「换成 isdecimal 以拒绝 +/-」；要判断补丁是否闭合，必须看到 `isdecimal()` 与 `int()` 对 `٠` 都为真，以及代理按 `[0-9]` 切帧。

即便没有 Unicode 零，只要任何让 `isdecimal()` 为真、`int()` 得到与代理不同的长度的写法还能留下，走私窗口就还在。3.9.2 才把 DIGIT 收到 `re.ASCII`。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「isdecimal vs int vs 代理 DIGIT」落到具体变换。

- `length_hdr.strip(" \t").isdecimal()`：看每个字符是不是 Unicode Nd
- `int(length_hdr)`：把那些字符变成整数长度
- 代理 / RFC：只认 `0x30–0x39`

只要构造一种输入，使 Python 认为这是十进制、值为 0，而代理不把它当合法 Content-Length（或当非零），第一层会放行，第二层仍然按长度 0 切出下一请求。

seed：

```text
Content-Length: +0
V0: int("+0")==0 → 空 body → GET /flag 执行
V1: "+0".isdecimal()==False → InvalidHeader → 挡
```

held-out residual（三条等价向量，认证取第一条即可）：

```text
Content-Length: ٠     U+0660 Arabic-Indic digit zero
Content-Length: ０     U+FF10 Fullwidth digit zero
Content-Length: ०     U+0966 Devanagari digit zero

V1: "٠".isdecimal()==True
    int("٠")==0
    → 空 body → GET /flag → PCBFLAG_...
V2: DIGITS.fullmatch("٠") is None → InvalidHeader → 挡
```

V1 改的是「拒绝 +/- 和其它 Python int 格式」；`٠` 这条链里根本没有 `+` 可拒。`isdecimal()` 在 `int()` 之前运行，它放行的字符集恰好是 `int()` 会解析成 0 的那批。

---

## 残余仍然走同一条 Content-Length 切帧路径（CVE-2024-23829）

没有换头字段、没有换走私形状、没有换 `/flag` 路由。还是：

```http
POST / HTTP/1.1
Host: t
Content-Length: ٠

GET /flag HTTP/1.1
Host: t
Connection: close
```

`get_content_length` 仍然先 `isdecimal()` 再 `int()`。V1 的注释照样引用 RFC 9110；执行完之后因为 `٠` 是十进制数字，长度为 0，管道请求进应用。

本 case residual 写死为上述 Unicode 零（held-out `VECTORS`）。和 GHSA「Unicode digits, where only ASCII digits are standards-compliant」同一字符集问题，只是效果通道选了 Content-Length 而不是 `HTTP/1.𝟙`。认证意图：v1 + `--residual` 在原始响应流里观察到 `PCBFLAG_...`。case.json 记一次真实 Docker gate（**observed**）。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：补丁用了比 HTTP DIGIT 宽的 Python 谓词；`int()` 与 `isdecimal()` 对 Unicode 零意见一致；帧边界按这个 0 来切。seed 被挡住只说明「带号的十进制没了」，不说明「不能再让解析器把长度当成 0」。

NVD / OSV 原文：*This vulnerability exists due to an incomplete fix for CVE-2023-47627.*

---

## 后来又补了什么（CVE-2024-23829，aiohttp 3.9.2）

commit `33ccdfb` / tag 约 3.9.2 把数字谓词换成 ASCII 正则（`http_parser.py`）：

```python
VERSRE: Final[Pattern[str]] = re.compile(r"HTTP/(\d)\.(\d)", re.ASCII)
DIGITS: Final[Pattern[str]] = re.compile(r"\d+", re.ASCII)

# get_content_length
if not DIGITS.fullmatch(length_hdr):
    raise InvalidHeader(CONTENT_LENGTH)

# 状态码
if len(status) != 3 or not DIGITS.fullmatch(status):
    raise BadStatusLine(line)
```

`re.ASCII` 下 `\d` 只剩 `[0-9]`。`٠` 不再 fullmatch，走私帧在解析头时失败。同一次还把 `VERSRE` 的点转义、方法/头名收到 RFC 9110 `token`。公开建议是升级到 3.9.2。默认安装带 llhttp 时走的是另一套解析器；纯 Python 回退路径必须升到带 `DIGITS` 的版本。

即便如此，若还有其它让 Python 解析器与代理对帧边界意见不一致的写法（未处理异常、其它分隔符），需要另证。本 benchmark 的 v2 只关闭这一条 Unicode-digit Content-Length residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是「不要让 `int()` 吃 +/-」。真正决定走私的是「这个字符串对代理和对 aiohttp 是不是同一个长度」。V2 才回到 ASCII DIGIT。3.8.6 的 diff 里看不到 `re.ASCII`。

**不是没有 ASCII 字符表。**  
`HEXDIGIT`、`METHRE` 已经是字节/ASCII 白名单。长度却用了 `str` 的 Unicode 数字属性。从 V1 只能看到 `isdecimal()`；要判断补丁是否闭合，必须看到它对 `٠` 为真，以及 `int("٠")==0`。

**同一 `get_content_length`、同一管道 `/flag`，只换了「零」怎么写。**  
任何让 V1 接受且值为 0 的长度写法，都能让 `GET /flag` 变成第二请求。GHSA 的版本行 Unicode 数字是同一谓词在另一字段上的表现。

**语言标准不是协议标准。**  
`isdecimal()` 在 Unicode 里是对的；在 HTTP 里是错的。注释引了 RFC 9110，实现却没有按 RFC 的 DIGIT 来写。

---

## 版本、入口、参考

| | aiohttp | Content-Length 谓词 | `+0` seed | Unicode `٠` residual |
|---|---|---|---|---|
| V0 | 3.8.5 | `int(length_hdr)` | 走私成功，读到 flag | （不必） |
| V1 | 3.8.6 | `str.isdecimal()` + `int()` | 400，挡 | `int("٠")==0`，读到 flag |
| V2 | 3.9.2 | `DIGITS.fullmatch` + `re.ASCII` | 挡 | 挡 |

- 入口：原始 TCP，纯 Python 解析器；flag 在应用 `GET /flag`
- 认证意图：v0 seed 观察到 flag；v1 seed 无；v1 residual 观察到。case.json 记 Docker gate（**observed**）
- [CVE-2023-47627](https://nvd.nist.gov/vuln/detail/CVE-2023-47627)、[GHSA-gfw2-4jvh-wgfg](https://github.com/aio-libs/aiohttp/security/advisories/GHSA-gfw2-4jvh-wgfg)
- [CVE-2024-23829](https://nvd.nist.gov/vuln/detail/CVE-2024-23829)、[GHSA-8qpw-xqxj-h4r2](https://github.com/aio-libs/aiohttp/security/advisories/GHSA-8qpw-xqxj-h4r2)
- 源码：[v3.8.6 http_parser.py](https://github.com/aio-libs/aiohttp/blob/v3.8.6/aiohttp/http_parser.py)（`get_content_length` 约 L335）
- V1 commit [`d5c12ba`](https://github.com/aio-libs/aiohttp/commit/d5c12ba890557a575c313bb3017910d7616fce3d)；V2 commit [`33ccdfb`](https://github.com/aio-libs/aiohttp/commit/33ccdfb0a12690af5bb49bda2319ec0907fa7827) / [PR#8074](https://github.com/aio-libs/aiohttp/pull/8074)
