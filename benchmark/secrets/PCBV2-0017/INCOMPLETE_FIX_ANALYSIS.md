# Puma：CR/LF 检查只挂在常规响应头上

- Case：`PCBV2-0017`
- 产品：Puma（Ruby HTTP 服务器，Rack 接口）
- 链：CVE-2020-5247（4.3.1 → 4.3.2）→ CVE-2020-5249（4.3.2 → 4.3.3）
- 源码对着官方 tag `v4.3.2` 的 `lib/puma/server.rb`、`lib/puma/const.rb`。运行时是整包 Puma gem + 本 case 的 Rack app（`config.ru`），不是抽出来的函数。

2020 年 2 月，Puma 给常规响应头加了一行 `headers.reject! { CRLF_REGEX =~ v }`，想挡住 HTTP 响应拆分。同一周 advisory 指出：Early Hints 那条 `fast_write "#{k}: #{v}\r\n"` 完全没挂同一谓词。NVD 把这件事记成 CVE-2020-5249，并写明 *This is related to CVE-2020-5247, which fixed this vulnerability but only for regular responses*。

根因不是「正则写窄了」。`CRLF_REGEX = /[\r\n]/` 已经覆盖 CR 和 LF；seed 和 residual 用的是**同一段** lone-CR payload。检查插在 `@app.call` 返回的 `headers` 上；真正往 socket 写 103 行的是另一条 lambda，它消费的是 `env[EARLY_HINTS].call(headers)` 传入的那份哈希，**从未经过** `reject!`。下面按请求走进去、补丁改了哪一行、消毒后谁还在写、Early Hints 为什么不拦，把这三层写完。

---

## 这块功能本来在干什么

Puma 把 Rack 应用的返回值 `(status, headers, body)` 编成 HTTP/1.1 响应写给客户端。`handle_request` 在调用 `@app.call(env)` 之前，如果服务器开了 `early_hints`，会往 `env` 里塞一个 lambda，让应用在还没返回最终响应时先写 `HTTP/1.1 103 Early Hints`。RFC 8297 用这条 103 预告后续会出现的 `Link` 等头。

一次典型的常规响应：

```http
GET /?x=pcbseed HTTP/1.1
```

Rack app 把查询参数写进 `X-Reflected`，Puma 把它编进 200 响应头。本 case 的 `config.ru` 同时暴露 Early Hints：`?eh=` 走 `env['rack.early_hints'].call("Link" => value)`。

`handle_request` 里两条写路径并排：

```ruby
# lib/puma/server.rb :: handle_request  (puma v4.3.2, 约 L651–684)
    if @early_hints
      env[EARLY_HINTS] = lambda { |headers|
        begin
          fast_write client, "HTTP/1.1 103 Early Hints\r\n".freeze

          headers.each_pair do |k, vs|
            if vs.respond_to?(:to_s) && !vs.to_s.empty?
              vs.to_s.split(NEWLINE).each do |v|
                fast_write client, "#{k}: #{v}\r\n"
              end
            else
              fast_write client, "#{k}: #{vs}\r\n"
            end
          end
          fast_write client, "\r\n".freeze
        rescue ConnectionError
        end
      }
    end

    status, headers, res_body = @app.call(env)

    return :async if req.hijacked
    headers.reject! { |_k, v| CRLF_REGEX =~ v.to_s }
```

设计意图：应用可以把任意字符串放进响应头；服务器负责把它们写成合法的 HTTP 头行。成功穿越之后的效果是**在响应字节流里插入攻击者指定的新头行**（本 case 把 `PCBFLAG_...` 嵌进 `X-Pcb-Injected:`），客户端或中间盒会把它当成独立的响应头。

数据流：

```text
HTTP ?x= / ?eh=
    → Rack app
         seed:  返回 [200, {"X-Reflected" => value}, body]
         residual: env['rack.early_hints'].call("Link" => value)
    → handle_request
         V1：headers.reject! { CRLF_REGEX =~ v }   ← 只改 @app.call 的返回值
         Early Hints lambda：fast_write "#{k}: #{v}\r\n"  ← 真正写 103，不再查 CR/LF
    → 原始 socket 字节
```

---

## 原始漏洞：明文 CR/LF（CVE-2020-5247，tag 4.3.1）

4.3.1 的 `handle_request` 在 `@app.call` 之后直接把 `headers` 编进状态行后面，中间没有任何 CR/LF 处理。应用如果把用户输入原样放进头值，攻击者可以塞一个回车，让 Puma 在 wire 上写出第二行。

本 case 的 seed 用 lone CR（`\r`，后面不跟 `\n`）。Puma 编常规头时用 `NEWLINE = "\n"` 切分多值，**不会**把单独的 `\r` 切成两段，于是整段 `pcbseed\rX-Pcb-Injected: FLAG` 作为**一个**值写出去；HTTP 解析器仍把 `\r` 当成行结束，第二行变成注入头：

```text
value = "pcbseed\rX-Pcb-Injected: PCBFLAG_..."
```

4.3.1 没有 `CRLF_REGEX`，`X-Reflected` 原样上线，body 前的原始字节里出现 `X-Pcb-Injected: PCBFLAG_...`。没有鉴权。Early Hints 在 4.3.1 上同样不检查，但 seed 只打常规响应头，那是 CVE-2020-5247 的公开面。

---

## 维护者改了什么（CVE-2020-5247 修复，4.3.2）

4.3.2 在 `const.rb` 加了一个冻结正则，并在 `handle_request` 里、`@app.call` **之后**、开始拼状态行**之前**加了一行 `reject!`：

```ruby
# lib/puma/const.rb  (v4.3.2)
    CRLF_REGEX = /[\r\n]/.freeze

# lib/puma/server.rb :: handle_request  (v4.3.2)
          status, headers, res_body = @app.call(env)

          return :async if req.hijacked
          # Checking to see if an attacker is trying to inject headers into the response
          headers.reject! { |_k, v| CRLF_REGEX =~ v.to_s }

          status = status.to_i
```

V1 正则的字面意思：值的 `to_s` 里只要出现 CR 或 LF，整条头从哈希里删掉。测试 `test_prevent_response_splitting_headers` / `_cr` / `_lf` 覆盖的正是这条路径：`[200, {'X-header' => "malicious\r\nCookie: hack"}, ...]`，断言响应里没有 `hack`。

对 seed 这种明文 CR，它确实够用：

```text
输入:  X-Reflected: pcbseed\rX-Pcb-Injected: PCBFLAG_...
V1 后: 该头被 reject! 丢掉，wire 上没有 FLAG
```

这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险字符就是 CR 和 LF（这个假设成立，`/[\r\n]/` 两边都覆盖）。
2. 所有会把用户字符串写成 `#{k}: #{v}\r\n` 的地方，都会先经过这一次 `reject!`。

第二点不成立。更关键的是：`reject!` 只改 `@app.call` 返回的那份 `headers`；Early Hints lambda 在 `@app.call` **期间**就已经 `fast_write` 完了，而且它拿到的是应用自己传入的另一份哈希。

---

## 消毒之后，头怎么接到 socket 上

V1 的 `reject!` 一结束，同一个函数继续用**过滤后**的 `headers` 拼 200 响应（content-length 分支、逐行 `lines.append k, colon, v, line_ending`）。常规路径上，CR/LF 头到不了 `fast_write`。

Early Hints 不走这条路。lambda 在 `@app.call` 之前就挂进 `env`。应用在 `call` 内部调用它时，Puma 还停在 `@app.call` 这一行，`reject!` 还没执行；即使执行了，它过滤的也不是 lambda 参数里那份 `headers`。

lambda 对每个值做 `vs.to_s.split(NEWLINE)`——只按 LF 切开——然后：

```ruby
                fast_write client, "#{k}: #{v}\r\n"
```

这里没有 `CRLF_REGEX`，没有 `reject!`，没有「写之前再看一眼」。Perl / 内核不会帮你把 `\r` 从已经写出的字节里拿掉。过滤器刚看过的是最终响应的 `headers` 哈希；socket 看到的是 103 阶段那次插值。两套语义中间没有第二次谓词。

本 case 的 Rack app 把 `?eh=` 原样放进 `Link`。金丝雀出现在原始响应字节里，依据就是这一步，而不是「200 响应头碰巧没滤干净」。

---

## 同一文件里已经有更强的写路径，103 没用

`handle_request` 后半段编常规头时，已经把「值里有换行」当成多行头来切（`split(NEWLINE)`）。V1 在切之前用 `reject!` 把含 CR/LF 的整条头扔掉，等于对**最终响应**做了「值不得含行结束符」。Early Hints 用的是同一套 `fast_write` 和同一套 `"#{k}: #{v}\r\n"` 格式，却没有调用同一谓词。

谁经过 `CRLF_REGEX`：

| 写路径 | 4.3.2 是否检查 CR/LF |
|---|---|
| `@app.call` 返回的 `headers` → 200 响应 | 是，`reject!` |
| `env[EARLY_HINTS]` lambda → 103 响应 | **否**，直接 `fast_write` |

不是仓库里没有更好的谓词，是 **103 没用**。即便换一种不含 `\r` 的编码，只要 lambda 继续裸插值，任何让 `v` 在写出时仍含行结束符的写法都会变成一次真实的拆分。4.3.2 的测试只断言了 HEAD `/` 的常规头，没有覆盖 `rack.early_hints`。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs 写出」落到具体代码：

- `headers.reject! { CRLF_REGEX =~ v.to_s }`：看最终响应哈希里有没有 CR/LF
- Early Hints 的 `fast_write "#{k}: #{v}\r\n"`：看应用塞进 lambda 的字符串怎么进 socket

只要构造一种输入，使危险字符**不出现**在 `@app.call` 的返回值里、而出现在 `early_hints.call` 的参数里，第一行会放行（根本看不到），第二行仍然拆分。

`?eh=` 就是这样来的。payload 和 seed **完全相同**：

```text
value:  pcbseed\rX-Pcb-Injected: PCBFLAG_...

seed 路径:
  headers["X-Reflected"] = value
  reject! 丢掉整条头
  200 响应里没有 FLAG

residual 路径:
  env["rack.early_hints"].call("Link" => value)
  lambda 写:
    HTTP/1.1 103 Early Hints\r\n
    Link: pcbseed\rX-Pcb-Injected: PCBFLAG_...\r\n
  解析后出现独立的 X-Pcb-Injected 行
```

GHSA-33vf-4xgg-9r58 原话就是：*This is related to CVE-2020-5247, which fixed this vulnerability but only for regular responses.* 字符类没有变；漏的是 sink。

---

## 残余仍然走同一条 103 写头路径（CVE-2020-5249）

没有换服务器、没有换字符、没有换身份。还是：

```http
GET /?eh=pcbseed%0dX-Pcb-Injected:%20PCBFLAG_... HTTP/1.1
```

Rack app 仍然调用同一个 `env['rack.early_hints']`。V1 那一行 `reject!` 照样执行，但执行的是最终 200 的 `headers`（本 case 这条路径甚至可以不往 200 里头里放 CR）；103 已经写完。`fast_write` 把带 `\r` 的 `Link` 行送到客户端；原始字节里观察到 `PCBFLAG_...`。

本 case `verify.sh` 的 residual 把 candidate 写死在脚本里（运行时不读 held-out 文件）：

```text
sink  = early_hints
param = eh
value = "pcbseed\rX-Pcb-Injected: " + RUN_FLAG
```

和 seed 同一构造，只把查询参数从 `x` 换成 `eh`。认证：v1 + `--residual` 退出码 0，raw 中观察到 `PCBFLAG_...`。

所以残余不是新洞面，而是同一 `fast_write` 格式上三件事叠在一起：检查挂在 `@app.call` 的返回值上；103 的写出发生在检查之前、用的是另一份哈希；lambda 没有使用已经存在的 `CRLF_REGEX`。seed 被挡住只说明「200 头里的字面 CR/LF 没了」，不说明「不能再通过 Puma 写出拆分后的头行」。

---

## 后来又补了什么（CVE-2020-5249，4.3.3）

4.3.3 把 `CRLF_REGEX` 改名为 `HTTP_INJECTION_REGEX`（模式仍是 `/[\r\n]/`），抽成 `possible_header_injection?`，并挂到**所有**写出点，包括 Early Hints：

```ruby
# lib/puma/server.rb  (v4.3.3, Early Hints lambda)
            vs.to_s.split(NEWLINE).each do |v|
              next if possible_header_injection?(v)
              fast_write client, "#{k}: #{v}\r\n"
            end

# 常规响应：删掉 reject!，改为逐行跳过
            next if possible_header_injection?(vs)   # CONTENT_LENGTH 分支
            ...
            vs.to_s.split(NEWLINE).each do |v|
              next if possible_header_injection?(v)
              lines.append k, colon, v, line_ending
            end

    def possible_header_injection?(header_value)
      HTTP_INJECTION_REGEX =~ header_value.to_s
    end
```

对残余输入：lambda 在 `fast_write` 前看到 `\r`，`next` 跳过该行，103 里没有 `X-Pcb-Injected`。公开建议是升级到 4.3.3 / 3.12.4。

即便如此，4.3.3 的 Early Hints 在 `vs` 不响应 `to_s` 或 `to_s` 为空时仍有一条 `fast_write "#{k}: #{vs}\r\n"` 的 else 分支，没有调用 `possible_header_injection?`。本 benchmark 的 v2 只关闭 lone-CR 这条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是 `@app.call` 返回值上的哈希过滤。真正拆分 103 的是 lambda 里的字符串插值。V2 把谓词下沉到每一次 `fast_write` 之前，这才对准了写出层。

**不是没有更好的谓词。**  
`CRLF_REGEX` 在 4.3.2 已经存在，且足够识别 seed 用的那个 CR。它只被 `reject!` 用了一次。从 V1 的 diff 只能看到加了一行过滤；要判断补丁是否闭合，必须看到 `env[EARLY_HINTS]` 的 `fast_write`。

**同一字符、同一 `fast_write` 格式，只换了调用点。**  
任何把用户字符串传进 `rack.early_hints` 的应用，在 4.3.2 上都吃同一条无检查的插值。advisory 的 workaround 只能是「不要把不可信输入放进 Early Hints」。

**测试只锁了常规头。**  
`test_prevent_response_splitting_headers*` 全部 `server_run` 后 `HEAD /`，断言 200 响应。没有一次调用 `env[EARLY_HINTS]`。补丁的闭合性被测试面写死了。

**金丝雀在响应字节里是有意的。**  
`PCBFLAG_...` 不在 HTML body 里，只在拆出来的头行里。能读到它，说明客户端看到的是 Puma 写出的原始 HTTP，而不是应用层的安全头集合。

---

## 版本、入口、参考

| | tag | 常规响应头 | Early Hints lambda | 明文 CR seed | 同 payload 的 `?eh=` |
|---|---|---|---|---|---|
| V0 | 4.3.1 | 无检查 | 裸 `fast_write` | 头里出现 FLAG | （不必） |
| V1 | 4.3.2 | `headers.reject! { CRLF_REGEX }` | 同上，仍不查 | 头被丢掉 | 103 里出现 FLAG |
| V2 | 4.3.3 | `possible_header_injection?` 逐行跳过 | 写出前 `next if possible_header_injection?(v)` | 挡 | 该行被 skip，挡 |

- Web：`GET /?x=...`（seed）/ `GET /?eh=...`（residual），端口 9292
- 认证（本平台）：v0 seed 观察到 flag；v1 seed 未观察到；v1 residual 观察到。
- [CVE-2020-5247](https://nvd.nist.gov/vuln/detail/CVE-2020-5247) / [GHSA-84j7-475p-hp8v](https://github.com/puma/puma/security/advisories/GHSA-84j7-475p-hp8v)
- [CVE-2020-5249](https://nvd.nist.gov/vuln/detail/CVE-2020-5249) / [GHSA-33vf-4xgg-9r58](https://github.com/puma/puma/security/advisories/GHSA-33vf-4xgg-9r58)
- 修复提交：[c22712fc](https://github.com/puma/puma/commit/c22712fc93284a45a93f9ad7023888f3a65524f3)（4.3.3 Early Hints）
- 官方 tag：`https://github.com/puma/puma/tree/v4.3.2` 与 `v4.3.3`
