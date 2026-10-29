# WEBrick：CRLF 只认成对出现

- Case：`PCBV2-0029`
- 产品：Ruby 标准库 WEBrick（HTTP 服务器工具包；`HTTPResponse#send_header` 把 `@header` 写成套接字上的文本）
- 链：CVE-2017-17742（ruby 2.5.0 → 2.5.1 / MRI r62968）→ CVE-2019-16254（→ 2.5.8 / webrick `3ce238b`）
- 源码对着 ruby `v2_5_1` 的 `lib/webrick/httpresponse.rb`：`send_header` 与私有方法 `check_header`。运行时是官方镜像 `ruby:2.5.1-slim` 自带的 webrick，应用把查询参数 `x` 写进响应头 `X-Reflected`。独立 gem 的 tag 从 1.4.2（无检查）直接跳到 1.4.4（已经是 `/[\r\n]/`），中间那个不完整状态只活在 MRI 发行里。

2018 年 3 月，Ruby 给 WEBrick 加了 `check_header`：头值若匹配 `/\r\n/` 就抛 `InvalidHeader`，`send_header` 清掉头、改成 500 再写一遍。2019 年 10 月 1 日 ruby-lang.org 发 CVE-2019-16254，第一句就是：*This is the same issue as CVE-2017-17742. The previous fix was incomplete, which addressed the CRLF vector, but did not address an isolated CR or an isolated LF.*

根因不只是「正则写窄了」。检查插在写出之前；真正拆开 HTTP 报文的是套接字上的字节，客户端/中间盒按「单独的 CR 或 LF」也能分行。下面按请求走进去、补丁加了哪一段、写出时字节长什么样、单独的 `\n` 为什么还能拆，把这三层写完。

---

## 这块功能本来在干什么

WEBrick 把响应头放在 Hash `@header` 里，值是应用塞进去的字符串。`HTTPResponse#[]=` 只做 `value.to_s`，不查控制字符。真正写到 TCP 的是 `send_header`：

```ruby
# lib/webrick/httpresponse.rb :: send_header  (ruby 2.5.1)
def send_header(socket) # :nodoc:
  if @http_version.major > 0
    data = status_line()
    @header.each{|key, value|
      tmp = key.gsub(/\bwww|^te$|\b\w/){ $&.upcase }
      data << "#{tmp}: #{check_header(value)}" << CRLF
    }
    @cookies.each{|cookie|
      data << "Set-Cookie: " << check_header(cookie.to_s) << CRLF
    }
    data << CRLF
    socket.write(data)
  end
rescue InvalidHeader => e
  @header.clear
  @cookies.clear
  set_error e
  retry
end
```

本 case 的 servlet 把 `?x=` 原样放进 `X-Reflected`。设计意图：应用可以设任意头值；库负责保证写出的文本仍是「一行一个头」。成功穿越之后的效果：响应字节流里出现应用**从未作为独立头发出**的一行，例如 `X-Pcb-Injected: PCBFLAG_...`。flag 只在响应头流里，不在请求里。

数据流：

```text
GET /?x=<value>
    → servlet  res['X-Reflected'] = value     ← []= 不检查
    → send_header
         V1：check_header(value) =~ /\r\n/    ← 只认 CR 紧挨 LF
         命中：InvalidHeader → 清头 → 500 错误页，不再含注入
         未命中：data << "X-Reflected: #{value}" << CRLF
    → socket.write(data)
    → 客户端按行切响应头
```

---

## 原始漏洞：头值原样写出（CVE-2017-17742，ruby 2.5.0）

2.5.0 的 `send_header` 没有 `check_header`，也没有 `InvalidHeader`：

```ruby
data << "#{tmp}: #{value}" << CRLF
```

应用若把用户输入写进头，攻击者可以在值里放 `\r\nCookie: hack`，套接字上就多出一行。ruby-lang.org 2018-03-28 的公告写：*an attacker can use newline characters to deceive the clients that the HTTP response header is stopped at there*。受影响版本包括 2.5.0；修复记在 trunk r62968。

本 case 的 seed 是成对的 CRLF：

```text
x = pcbseed\r\nX-Pcb-Injected: <FLAG>
```

V0 写出：

```http
X-Reflected: pcbseed
X-Pcb-Injected: PCBFLAG_...
```

客户端把第二行当成服务器发的头。没有应用层二次编码。

---

## 维护者改了什么（CVE-2017-17742 修复，ruby 2.5.1 / r62968）

V1 引入异常类、在写出前包一层、失败则改写为 500：

```ruby
# lib/webrick/httpresponse.rb  (ruby 2.5.1)
class InvalidHeader < StandardError
end

def check_header(header_value)
  if header_value =~ /\r\n/
    raise InvalidHeader
  else
    header_value
  end
end
```

测试只覆盖了成对 CRLF：`malicious\r\nCookie: hack` 期望 500，body 里没有 `hack`。Cookie 头走同一函数。

正则的字面意思：

| 片段 | 含义 |
|---|---|
| `\r` | 一个 CR |
| `\n` | **紧跟着**一个 LF |
| 无字符类、无 `|` | 单独的 CR 或单独的 LF 都不匹配 |

对 seed 这种 `\r\n`，它确实够用：`check_header` 抛错，`send_header` 清空 `@header`，`set_error` 换成错误页再 `retry`，写出的 500 页里没有注入行。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 能拆开 HTTP/1 头的换行，长得像 Windows 的 CRLF 对。
2. 只要这对不出现，值就可以原样进 `data`。

第一点不成立。RFC 7230 把行结束定义成 CRLF，但很多实现把单独的 LF（甚至单独的 CR）也当成行结束。Ruby 自己的 `Net::HTTPResponse.read_new` 在读这只服务器时，单独的 `\n` 就会开始下一行。

---

## 消毒之后，字节怎么接到套接字上

V1 的 `=~ /\r\n/` 一结束（未命中时），同一个 `each` 立刻把值拼进 `data`，后面固定再加 `CRLF`。没有 `gsub` 删控制字符，没有把值限制在 VCHAR / obs-text。

单独 LF 的值：

```text
value = "pcbseed\nX-Pcb-Injected: PCBFLAG_..."
check_header:  "pcbseed\nX-Pcb-..." =~ /\r\n/  → nil
写出:  X-Reflected: pcbseed\nX-Pcb-Injected: PCBFLAG_...\r\n
```

套接字上在 `pcbseed` 和 `X-Pcb-Injected` 之间只有 `\n`，没有 `\r`。HTTP/1 客户端仍把这里当成头结束，下一行是注入头。单独的 `\r` 同理：许多栈把 CR 也当行结束，V1 同样放行。

`[]=` 在更早的时候就把值收成 String，不经过 `check_header`。检查只发生在写出瞬间，匹配语言是「CRLF 子串」，写出语义是「任意字节进文本协议」。两套语义中间没有第二次谓词。

`send_header` 的 `rescue InvalidHeader` 会清空 `@header` 和 `@cookies`，再 `set_error` 成 500 HTML 页后 `retry`。这套失败封闭对**已经匹配到的**值是够用的：注入行不会出现在最终字节里。孤立 LF 根本不进 `rescue`，走的是成功路径上的 `socket.write`。Cookie 通道 `check_header(cookie.to_s)` 与普通头是同一函数、同一正则；seed 的测试覆盖了两条通道上的 `\r\n`，两条通道上的孤立 `\n` 一样漏。本 case 只观察普通头，避免把「换 sink」误读成「换漏洞」。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs 成帧」落到具体代码：

- `check_header` 的 `=~ /\r\n/`：看有没有**相邻**的 CR+LF
- 对端 HTTP 解析器：看有没有**任意**的 CR 或 LF 能结束这一行

只要构造一种输入，使 CR 和 LF 不同时相邻出现，但其中之一仍在值里，第一行会放行，第二行仍然拆流。

本 case residual 用单独 LF：

```text
x = pcbseed\nX-Pcb-Injected: __PCB_FLAG__
```

（运行时把占位符换成 `PCBFLAG_...`。）与 ruby-lang.org 说的 *isolated LF* 同一构造；单独 CR 是对称的另一条，本 case 不重复打。

V1 自带的回归测试只断言 `\r\n` 被拒，没有 `\n` / `\r` 用例——补丁作者用测试把「完整」定义成了「成对 CRLF」。两年后的 follow-up 提交才补上 `test_prevent_response_splitting_headers_cr` 和 `_lf`。

---

## 残余仍然走同一条常规响应头（CVE-2019-16254）

没有换头名字、没有换 Cookie 通道、没有换 servlet。还是：

```http
GET /?x=pcbseed%0aX-Pcb-Injected:%20PCBFLAG_...
```

`[]=` 仍然不查；`send_header` 仍然调用同一份 `check_header`；`/\r\n/` 仍然不匹配单独 `\n`；`socket.write` 仍然把那一字节写出去；客户端在响应头里看到 `X-Pcb-Injected` 和 flag。

认证：v1 + `--residual` 退出码 0，响应字节中观察到 flag。Cookie 注入走同一 `check_header(cookie.to_s)`，单独 LF 同样漏；本 case 观察的是普通头，与 seed 同一 sink。

所以残余不是新洞面，而是同一写出路径上：匹配语言比 HTTP 行结束语义窄。seed 被挡住只说明「成对 CRLF 没了」，不说明「头值不能再拆开响应」。

套接字上看见的字节（`CRLF` 写成 `\r\n`）：

```text
seed 值:      pcbseed\r\nX-Pcb-Injected: FLAG
V1 检查:      =~ /\r\n/  → 命中 → 500，下面两行都不会出现

residual 值:  pcbseed\nX-Pcb-Injected: FLAG
V1 检查:      =~ /\r\n/  → 不命中
写出:         X-Reflected: pcbseed\nX-Pcb-Injected: FLAG\r\n
客户端切行:   X-Reflected: pcbseed
              X-Pcb-Injected: FLAG
```

Ruby 自己的 `Net::HTTPResponse.read_new`（V1 测试用来读回响应的那个解析器）会把孤立 `\n` 当行结束——补丁作者用的客户端已经按孤立 LF 分行，测试却只喂 `\r\n`。

---

## 后来又补了什么（CVE-2019-16254，ruby 2.5.8 / 3ce238b）

follow-up 把检查改成字符类，并先 `to_s`：

```ruby
def check_header(header_value)
  header_value = header_value.to_s
  if /[\r\n]/ =~ header_value
    raise InvalidHeader
  else
    header_value
  end
end
```

提交说明：*The commit prevented CRLF, but did not address an isolated CR or an isolated LF.* 测试拆成 `_crlf` / `_cr` / `_lf` 三组。对残余输入，单独 `\n` 命中字符类，再次走 500 错误页，flag 不出现。公开建议升级到 2.5.7 / 2.6.5 等（公告里的发行号）或 master `3ce238b` 之后。

即便如此，这仍然是「写出前用正则拒控制字符」。其它能拆流的字节（例如孤立的 Unicode 行分隔符，若某客户端认）需要另证。本 benchmark 的 v2 只关闭孤立 CR/LF 这一条。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是「值里有没有 CRLF 子串」。真正分行的是对端按单字节 CR/LF 切的文本协议。V2 仍在同一层加码，没有改成「头值只允许 RFC 的 VCHAR」，也没有在 `[]=` 时拒绝，只在写出时拒绝。

**不是没有失败路径。**  
`InvalidHeader` + 清空头 + 500 已经能把注入从响应里拿掉。缺的是触发条件与协议一致。从 V1 的 diff 只能看到 `=~ /\r\n/`；要判断补丁是否闭合，必须看到单独 `\n` 仍被拼进 `data`，以及客户端会把它当新行。

**同一函数、同一 `X-Reflected`，只换了换行形态。**  
`send_header` 对每个头值、每个 Cookie 都走 `check_header`。advisory 说的 isolated CR 与 isolated LF 是同一谓词的两种漏报。

**测试把「完整」定义窄了。**  
V1 新增的两个测试都用 `\r\n`。补丁与测试一起把孤立换行留在了生产路径上。V2 用测试把缺口补上，比只改正则更能说明上一版在测什么。

**金丝雀是多出来的头行。**  
应用从未 `res['X-Pcb-Injected']=...`。能在响应里看到它，说明库把用户字节当成了头流的结构分隔符。

---

## 版本、入口、参考

| | 运行时 | `check_header` | `\r\n` seed | 孤立 `\n` residual |
|---|---|---|---|---|
| V0 | ruby 2.5.0 | 无 | 注入行出现 | （不必） |
| V1 | ruby 2.5.1 | `=~ /\r\n/` | 500，无注入 | 注入行出现 |
| V2 | ruby 2.5.8 | `/[\r\n]/` | 500 | 500，无注入 |

- Web：`GET /?x=...`，观察原始响应字节（不含请求回显）。
- 认证（本平台）：v0 seed 观察到 flag；v1 seed 未观察到；v1 residual 观察到。
- [CVE-2017-17742](https://www.ruby-lang.org/en/news/2018/03/28/http-response-splitting-in-webrick-cve-2017-17742/)
- [CVE-2019-16254](https://www.ruby-lang.org/en/news/2019/10/01/http-response-splitting-in-webrick-cve-2019-16254/)（写明 previous fix was incomplete）
- 修复：[MRI r62968](https://bugs.ruby-lang.org/) / webrick 引入 `/\r\n/`；[3ce238b](https://github.com/ruby/ruby/commit/3ce238b5f9795581eb84114dcfbdf4aa086bfecc) 改为 `/[\r\n]/`
