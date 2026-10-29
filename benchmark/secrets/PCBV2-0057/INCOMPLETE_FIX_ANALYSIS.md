# cpp-httplib：has_crlf 看见的是 C 字符串，写出的是 std::string

- Case：`PCBV2-0057`
- 产品：cpp-httplib（yhirose，C++11 header-only HTTP 库）
- 链：CVE-2020-11709（v0.5.8 → v0.5.9 / 本 case V1 钉在 v0.18.3）→ CVE-2025-0825（v0.17.3…v0.18.3 → v0.18.4，commit `9c36aae`）
- 源码对着 GitHub tag `v0.5.8` / `v0.18.3` / `v0.18.4` 的 `httplib.h`：`Response::set_header`、`detail::has_crlf`、`detail::fields::is_field_content`、`write_headers`。运行时是真实 `httplib.h` 编进一个把查询参数 `x` 反射进响应头的 HTTP 服务。

2020 年 4 月，issue #425 指出 `set_header` / `set_redirect` 把调用方给的字符串原样 `emplace` 进 `Headers`。维护者加了 `detail::has_crlf`，看见 `\r` 或 `\n` 就拒绝。NVD CVE-2020-11709 写的是 *does not filter \\r\\n in parameters passed into the set_redirect and set_header functions*。五年后 Checkmarx 报 CVE-2025-0825 / GHSA-65rj-829h-6g8x：*fails to filter CRLF characters ("\\r\\n") when those are prefixed with a null byte*。受影响范围写的是 v0.17.3 到 v0.18.3——`has_crlf` 一直在，只是它走的是 `c_str()`。

根因不只是「少拦了一个字符」。检查插在「C 字符串里有没有 CR/LF」这一层；真正写到 TCP 上的是 `std::string` 的 `data()` + `size()`，NUL 后面的字节都会出去。同文件里已经有按 `s.size()` 扫描的路径，`has_crlf` 没用。下面按请求走进去、V1 改了哪一行、检查之后谁消费那个值、仓库里已经有什么更长的扫描、残余怎么用 `%00` 把同一条响应头打穿。

---

## 这块功能本来在干什么

cpp-httplib 给应用一个 `Server` 和一份 `Response`。应用把用户输入写进响应头，是常见写法：回显、`Location`、自定义追踪头。本 case 的入口是：

```http
GET /echo?x=SAFE HTTP/1.1
```

处理函数把查询参数原样交给库：

```cpp
// server.cpp  （本 case 的应用侧，调用的是真实 httplib.h）
svr.Get("/echo", [](const httplib::Request &req, httplib::Response &res) {
    std::string echoed = req.get_param_value("x");
    res.set_header("X-Echo", echoed);   // 库的 sink
    res.set_content("ok\n", "text/plain");
});
```

`get_param_value` 做百分号解码，得到的是 `std::string`：`%00` 变成一个真正的 `'\0'`，`%0d%0a` 变成 `\r\n`，这些字节都还在 `size()` 里。设计意图：`x` 是一段头字段值，必须落在同一行 `X-Echo: ...` 里。成功穿越之后的效果是 **响应头被拆成多行，攻击者选的头名出现在 wire 上**（本 case 用 `X-Pcb-Inject: PCBFLAG_...` 当金丝雀）。

数据流：

```text
HTTP GET /echo?x=
    → Request::get_param_value("x")     ← 百分号解码，保留 NUL
    → Response::set_header("X-Echo", val)
         V1：detail::has_crlf(key/val)  ← 补丁插在这里，走 c_str()
         headers.emplace(key, val)      ← 整份 std::string 进 map
    → write_headers
         s = name + ": " + value + "\r\n"
         strm.write(s.data(), s.size()) ← 按长度写，不在 NUL 处停
    → TCP 上出现独立的 X-Pcb-Inject 行
```

没有登录。判断完全信任 `set_header` 对「这一串字节能不能当头值」的读法，不信任稍后 `write_headers` 会按长度把同一份字节写出去。

---

## 原始漏洞：明文 CRLF（CVE-2020-11709，v0.5.8）

v0.5.8 的 `Response::set_header` 没有过滤：

```cpp
// httplib.h  (cpp-httplib@v0.5.8, 约 L2764–2770)
inline void Response::set_header(const char *key, const char *val) {
  headers.emplace(key, val);
}

inline void Response::set_header(const char *key, const std::string &val) {
  headers.emplace(key, val);
}
```

`set_redirect` 同样直接 `set_header("Location", url)`。issue #425 / gist `shouc/a9330df817128bc4c4132abf3de09495` 的问题是：应用把用户串写进头，库不剥 CR/LF，客户端（或中间代理）会把后面的行当成新头。本 case 的 seed：

```text
x = SAFE%0d%0aX-Pcb-Inject:%20<PCB_FLAG>
```

解码后 `val` 里有 `\r\n`。v0.5.8 原样 `emplace`。`write_headers` 拼出：

```text
X-Echo: SAFE\r\n
X-Pcb-Inject: PCBFLAG_...\r\n
```

原始套接字读到独立的 `X-Pcb-Inject` 行。这就是 v0 + `--seed` 退出码 0。

没有鉴权。任何把外部字符串交给 `set_header` / `set_redirect` 的应用都走同一条路径；本 case 只打 `/echo?x=`。

---

## 维护者改了什么（CVE-2020-11709 修复，本 case 的 V1 = v0.18.3）

v0.5.9 起加了 `has_crlf`，并在 `set_header` / `set_redirect` 入口调用。v0.18.3 上这两处仍然是：

```cpp
// httplib.h  (cpp-httplib@v0.18.3)
// detail::has_crlf，约 L5304–5311
inline bool has_crlf(const std::string &s) {
  auto p = s.c_str();
  while (*p) {
    if (*p == '\r' || *p == '\n') { return true; }
    p++;
  }
  return false;
}

// Response::set_header，约 L5755–5759
inline void Response::set_header(const std::string &key,
                                 const std::string &val) {
  if (!detail::has_crlf(key) && !detail::has_crlf(val)) {
    headers.emplace(key, val);
  }
}
```

`set_redirect` 同样先 `if (!detail::has_crlf(url))`。字面意思：从 `c_str()` 开始，遇到第一个 `'\0'` 就结束；中间若看到 CR 或 LF 则拒绝。`emplace` 发生在这次扫描**之后**，放行的是**整份** `std::string`，不是 `c_str()` 截断后的前缀。

对 seed 这种明文 `\r\n`，它确实够用：

```text
输入:  SAFE\r\nX-Pcb-Inject: <FLAG>
has_crlf:  第一个非零字节扫到 \r → true → 不 emplace
wire:      没有 X-Pcb-Inject 行
```

这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险字节长得像出现在 C 字符串可见前缀里的 `\r` / `\n`。
2. `std::string` 的内容和 `c_str()` 看到的内容一样长——也就是中间没有 `'\0'`。

第二点不成立。更关键的是：这一行之后，代码仍然把完整的 `val` 交给 `write_headers`，而那次写出**按 `size()` 计长度**。

---

## 检查之后，头值怎么写到 TCP 上

V1 的 `has_crlf` 一返回 false，同一个 `set_header` 立刻 `headers.emplace(key, val)`。`Headers` 是 `multimap<string,string>`，存的是对象，不是 C 字符串。真正出站在 `write_headers`（约 L4425–4441）：

```cpp
// httplib.h :: write_headers  (v0.18.3)
inline ssize_t write_headers(Stream &strm, const Headers &headers) {
  ssize_t write_len = 0;
  for (const auto &x : headers) {
    std::string s;
    s = x.first;
    s += ": ";
    s += x.second;
    s += "\r\n";

    auto len = strm.write(s.data(), s.size());
    ...
  }
  auto len = strm.write("\r\n");
  ...
}
```

`s += x.second` 把 `val` 里**每一个**字节（含 NUL、含 NUL 后面的 `\r\n`）追加进去。`strm.write(s.data(), s.size())` 按长度写，不在 `'\0'` 处停。HTTP 客户端若用普通解析器，可能会把 NUL 当截断；原始套接字和不少代理会把后面的 `\r\nName: ...` 当成新头。过滤器刚看过的是 `c_str()`；socket 看到的是 `data()` + `size()`。两套语义中间没有第二次谓词。

金丝雀能作为独立头行出现在 body 之前，依据就是这一步，而不是「应用又写了一次头」。

---

## 仓库里已经有按长度扫描的路径，检查没用

同一份 `httplib.h` 里，别处已经知道 `std::string` 可能内嵌 NUL。Unix 抽象命名空间把 leading NUL 改成 `@` 时，用的是 `s.size()` 而不是 `c_str()`：

```cpp
// httplib.h :: escape_abstract_namespace_unix_domain  (v0.18.3, 约 L3368–3374)
inline std::string escape_abstract_namespace_unix_domain(const std::string &s) {
  if (s.size() > 1 && s[0] == '\0') {
    auto ret = s;
    ret[0] = '@';
    return ret;
  }
  return s;
}
```

`message_digest` 也是 `EVP_DigestUpdate(..., s.c_str(), s.size())`，指针和长度一起给。百分号解码循环是 `for (size_t i = 0; i < s.size(); i++)`。这些都是「按长度看每一个字节」。

`has_crlf` 却写成 `while (*p)`。不是仓库里没有更强的扫描，是 **CRLF 检查没用长度**。即便没有 RFC 7230 的 `field-content`，只要改成 `s.find('\r') != npos || s.find('\n') != npos`，或按 `s.size()` 走一遍，NUL 后面的 CRLF 也会被看见。V1 选了 C 字符串语义。

`has_crlf` 在 v0.18.4 里还在（约 L5369），只是 `set_header` 不再调用它。更强的谓词后来加在 `detail::fields` 里，而不是给 `has_crlf` 补上 `size()`。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs 写出」落到具体代码：

- `has_crlf`：从 `c_str()` 走到第一个 `'\0'`，看有没有 `\r` / `\n`
- `write_headers`：`s += x.second` 再 `write(data, size)`，看整份字节

只要构造一种输入，使「NUL 之前没有 CR/LF、NUL 之后有」，第一行会放行，第二行仍然拆响应。

`SAFE\0\r\nX-Pcb-Inject: <FLAG>` 就是这样来的。百分号形态：

```text
x = SAFE%00%0d%0aX-Pcb-Inject:%20<PCB_FLAG>
```

解码后的 `std::string`：

```text
[S][A][F][E][\0][\r][\n][X][-][P][c][b][-][I][n][j][e][c][t][:][ ][F][L][A][G]...
```

`has_crlf` 从 `c_str()` 读 `SAFE`，遇到 `'\0'` 结束，没看见 `\r`。`emplace` 把整串放进 map。`write_headers` 写出：

```text
X-Echo: SAFE\0\r\n
X-Pcb-Inject: <PCB_FLAG>\r\n
```

原始套接字上出现独立的 `X-Pcb-Inject` 行。NVD / Checkmarx 原话就是 *when those are prefixed with a null byte*。

V1 删的（拒绝的）是可见前缀里的 CRLF；`%00` 把 CRLF 藏到 C 字符串结束符后面。检查认为自己已经把换行清干净了，实际上它刚放行了一批自己没扫到的字节，并且 `write_headers` 会按真实长度发出去。

---

## 残余仍然走同一条 set_header 写出路径（CVE-2025-0825）

没有换路由、没有换头名、没有换身份。还是：

```http
GET /echo?x=SAFE%00%0d%0aX-Pcb-Inject:%20PCBFLAG_... HTTP/1.1
```

`get_param_value` 仍然百分号解码。V1 那一行 `has_crlf` 照样执行；执行完之后认为干净，`emplace` 整串；`write_headers` 按 `size()` 写出，金丝雀成为独立头行。

本 case `verify.sh` 的 residual 把 candidate 写死在脚本里（运行时不读 held-out 文件）：

```text
x = SAFE%00%0d%0aX-Pcb-Inject:%20<PCB_FLAG>
```

和 GHSA-65rj-829h-6g8x / Checkmarx advisory 同一构造。认证意图：v1 + `--residual` 在原始响应里观察到 `X-Pcb-Inject: PCBFLAG_...`。本文按 **源码 + 公开 advisory** 推导；平台未在本轮 compose 上复跑。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：检查用 C 字符串语义；写出用 `string::size()`；同文件里已经有按长度扫描的先例却没挂到 `has_crlf` 上。seed 被挡住只说明「可见的 `\r\n` 没了」，不说明「不能再把用户字节拆成新头」。

---

## 后来又补了什么（CVE-2025-0825，v0.18.4，commit 9c36aae）

v0.18.4 不再问「有没有 CR/LF」，改问「整串是不是 RFC 7230 的 field-content」。`set_header` 换成：

```cpp
// httplib.h  (v0.18.4)
if (detail::fields::is_field_name(key) &&
    detail::fields::is_field_value(val)) {
  headers.emplace(key, val);
}
```

`is_field_value` 就是 `is_field_content`。它按 `s.size()` 下标扫描，**包括 NUL 后面的字节**：

```cpp
// httplib.h :: detail::fields::is_field_content  (v0.18.4, 约 L2534–2556)
inline bool is_field_content(const std::string &s) {
  if (s.empty()) { return false; }
  if (s.size() == 1) {
    return is_field_vchar(s[0]);
  } else if (s.size() == 2) {
    return is_field_vchar(s[0]) && is_field_vchar(s[1]);
  } else {
    size_t i = 0;
    if (!is_field_vchar(s[i])) { return false; }
    i++;
    while (i < s.size() - 1) {
      auto c = s[i++];
      if (c == ' ' || c == '\t' || is_field_vchar(c)) {
      } else {
        return false;
      }
    }
    return is_field_vchar(s[i]);
  }
}
```

`is_vchar` 是 `c >= 33 && c <= 126`。`'\0'`、`'\r'`、`'\n'` 都不在里面。残余输入里 NUL 和随后的 CR 都会让函数返回 false，`emplace` 不发生，wire 上没有注入行。公开建议是升级到 v0.18.4。NVD 把修复 commit 记成 `9c36aae4b73e2b6e493f4133e4173103c9266289`。

即便如此，这仍然是「在 `emplace` 之前再扫一遍字符串」。`write_headers` 还是 `data()` + `size()`。对 `%00%0d%0a` 这条已知链它够用；若还有其它让头值在检查之后被改写、或走 `const char*` 重载绕过 `std::string` 长度的写法，需要另证。本 benchmark 的 v2 只关闭这一条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是「C 字符串里有没有换行」。真正拆响应的是 `write_headers` 按长度写出的那份 `std::string`。V2 仍在 `set_header` 入口加码，只是把扫描从 `c_str()` 换成 `s[i]`；没有在写出前再验一次，也没有在 `write_headers` 里拒绝内嵌 CR/LF。

**不是没有更好的谓词。**  
同文件的 Unix 抽象路径、百分号解码、`message_digest` 都按 `size()` 走。`s.find('\r')` 本身就能看见 NUL 后面的字节。从 V1 的 diff 只能看到加了 `has_crlf`；要判断补丁是否闭合，必须看到 `c_str()` 循环和 `write(s.data(), s.size())` 不是同一种长度。

**同一函数、同一 `val`，只换了查询参数的写法。**  
任何把用户字符串传进 `set_header` / `set_redirect` 的调用，在 v0.18.3 上都吃这一行 `has_crlf` 和同一次 `write_headers`。advisory 写的是 header injection / response splitting，不限于本 case 的 `X-Echo`。

**百分号解码会制造检查看不见的字节。**  
HTTP 查询串是文本；`%00` 在进入 `std::string` 之后才变成 `c_str()` 的结束符。若检查发生在解码之前，或解码后按长度扫，这条链走不通。

**金丝雀必须用原始套接字读。**  
普通 HTTP 客户端可能在 NUL 处截断，看不见后面的注入行。本 case 的 detector 明确要求 raw socket 上出现 `\r\nX-Pcb-Inject: <FLAG>\r\n`。

---

## 版本、入口、参考

| | tag | `set_header` | 写出 | 明文 CRLF seed | NUL+CRLF residual |
|---|---|---|---|---|---|
| V0 | v0.5.8 | 无过滤，直接 `emplace` | `write(data, size)` | 注入金丝雀头 | （不必） |
| V1 | v0.18.3 | `has_crlf` 走 `c_str()` | 同上 | 拒绝 emplace | 注入金丝雀头 |
| V2 | v0.18.4 | `is_field_value` 按 `size()` 扫 | 同上 | 挡 | NUL/CR 不是 vchar，挡 |

- Web：`GET /echo?x=...`
- 源码：GitHub `yhirose/cpp-httplib` tag `v0.18.3` 的 `httplib.h`（`has_crlf`、`Response::set_header`、`write_headers`）
- [CVE-2020-11709](https://nvd.nist.gov/vuln/detail/CVE-2020-11709)、[CVE-2025-0825](https://nvd.nist.gov/vuln/detail/CVE-2025-0825)
- [GHSA-65rj-829h-6g8x](https://github.com/advisories/GHSA-65rj-829h-6g8x)
- [issue #425](https://github.com/yhirose/cpp-httplib/issues/425)（CVE-2020-11709 原始报告）
- [commit 9c36aae](https://github.com/yhirose/cpp-httplib/commit/9c36aae4b73e2b6e493f4133e4173103c9266289)（v0.18.4，`is_field_value`）
- [Checkmarx advisory CVE-2025-0825](https://advisory.checkmarx.net/advisory/CVE-2025-0825/)
