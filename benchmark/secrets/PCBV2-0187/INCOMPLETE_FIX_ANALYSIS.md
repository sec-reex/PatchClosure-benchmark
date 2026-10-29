# Rails 1.2.4：从共享常量上 `delete` 掉的 cookie_only

- Case：`PCBV2-0187`
- 产品：Ruby on Rails（Web 框架）。运行时是真实 gems：`rails 1.2.3` / `1.2.4` / `1.2.6`（对应 actionpack `1.13.3` / `1.13.4` / `1.13.6`），Ruby 1.8.7，整进程 HTTP，不是抽出来的 `cgi_process.rb`。
- 链：CVE-2007-5380（1.2.3 → 1.2.4）→ CVE-2007-6077（1.2.4 → 1.2.6）
- 源码对着 tag `v1.2.4` 的 `actionpack/lib/action_controller/cgi_process.rb`（`CgiRequest`）、`railties/lib/dispatcher.rb`（`Dispatcher.dispatch`）。金丝雀是 benign：`GET /protected` 只在 session 已认证时吐 `PCBFLAG_...`。

NVD 给 CVE-2007-6077 的原话：*The session fixation protection mechanism in cgi_process.rb in Rails 1.2.4 … removes the :cookie_only attribute from the DEFAULT_SESSION_OPTIONS constant, which effectively causes cookie_only to be applied only to the first instantiation of CgiRequest. NOTE: this is due to an incomplete fix for CVE-2007-5380.*

根因不只是「漏了一行判断」。检查插在实例变量 `@cookie_only` 上；真正采纳 URL 里 session id 的是后面的 `CGI::Session.new`。同文件里已经有每次请求重新 `merge` 的 `session_options_with_string_keys`，却只在构造函数里对共享 Hash 做了一次破坏性 `delete`。下面按请求走进去。

---

## 这块功能本来在干什么

Rails 1.2 用 CGI 适配器把一次 HTTP 变成 `CgiRequest`。session 默认 PStore，id 参数名由应用配置成 `_session_id`。一次典型的登录：

```http
GET /login?user=victim&_session_id=<S>
Cookie: （可空）
```

`Dispatcher.dispatch` 把 **同一个** `CgiRequest::DEFAULT_SESSION_OPTIONS` 常量传进每次请求的构造函数。`CanaryController` 读 `session[:authenticated]`，认证过才把环境变量里的 flag 写进 `/protected` 的 body。

设计意图：session id 只从 Cookie 来，URL / POST 里带 `_session_id` 应视为 fixation 并拒绝。成功穿越之后的效果是：**攻击者预先种下的 id `S` 被当成受害者的 session**，受害者在 `S` 上登录后，攻击者用同一 Cookie 读 `/protected`。

数据流：

```text
HTTP GET /login?_session_id=S
    → Dispatcher.dispatch(cgi, DEFAULT_SESSION_OPTIONS, ...)
         CgiRequest.new(cgi, session_options)     ← session_options 就是那份常量
              V1：@cookie_only = session_options.delete :cookie_only
         controller.login → request.session
              if @cookie_only && request_parameters[session_key]
                   raise SessionFixationAttempt
              CGI::Session.new(@cgi, session_options_with_string_keys)
                   从 query 里取出 _session_id=S 绑定 PStore 文件
    → session[:authenticated] = true
    → 之后 GET /protected + Cookie _session_id=S 读出 PCBFLAG_...
```

需要一次「先拿到合法 session 文件」：Ruby 1.8.7 的 `CGI::Session` 会丢掉未知 id，所以攻击者先 `GET /seed` 让服务器签发 `S`，PStore 文件落在磁盘上。没有单独的「禁止 URL session」权限位——整件事就是这一个 guard。

---

## 原始漏洞：URL 里的 session id 照单全收（CVE-2007-5380，1.2.3）

1.2.3 的 `CgiRequest` 没有 `:cookie_only`，也没有 `SessionFixationAttempt`。`session` 直接 `CGI::Session.new`。query 里的 `_session_id` 和 Cookie 里的一样被当成当前会话。

本 case seed：`GET /seed` 拿到 `S` → `GET /login?_session_id=S` 把受害者认证写进 `S` → `GET /protected` 带 Cookie `S` 读 flag。v0 上登录不会 500，body 里出现 `PCBFLAG_...`。

---

## 维护者改了什么（CVE-2007-5380 修复，1.2.4）

1.2.4 给 `DEFAULT_SESSION_OPTIONS` 加上 `:cookie_only => true`，并在 `session` 里于创建 `CGI::Session` **之前**加守卫。构造函数把这个开关抠到实例变量上：

```ruby
# actionpack/lib/action_controller/cgi_process.rb  (rails v1.2.4)
class CgiRequest < AbstractRequest
  attr_accessor :cgi, :session_options, :cookie_only
  class SessionFixationAttempt < StandardError; end

  DEFAULT_SESSION_OPTIONS = {
    :database_manager => CGI::Session::PStore,
    :prefix           => "ruby_sess.",
    :session_path     => "/",
    :cookie_only      => true
  } unless const_defined?(:DEFAULT_SESSION_OPTIONS)

  def initialize(cgi, session_options = {})
    @cgi = cgi
    @session_options = session_options
    @env = @cgi.send(:env_table)
    @cookie_only = session_options.delete :cookie_only
    super()
  end
```

守卫：

```ruby
def session
  ...
  stale_session_check! do
    if @cookie_only && request_parameters[session_options_with_string_keys['session_key']]
      raise SessionFixationAttempt
    end
    @session = CGI::Session.new(@cgi, session_options_with_string_keys)
```

V1 谓词的字面意思：若 `@cookie_only` 为真，且请求参数里带了 session key，就拒绝。没有「每次从常量重新读」，没有把 `delete` 换成非破坏性的取值。

对 seed 这种「进程里的第一次带 `_session_id` 的请求」，它确实够用：`@cookie_only` 还是 `true`，`raise SessionFixationAttempt`，登录是 500，`/protected` 读不到认证后的 flag。这就是 v1 + `--seed` 退出码 10。本 case 应用显式 `session :session_key => '_session_id'`，否则 1.2.4 的常量里没有 `:session_key`，守卫会去查 `request_parameters[nil]`，连第一次都不会开火——那就测不到 5380 本身。`session_options_with_string_keys` 用 `stringify_keys`，所以守卫里的查找键是字符串 `'session_key'` 对应的值 `'_session_id'`，和 query 参数名一致。

补丁默认了两件事：

1. `@cookie_only` 在进程寿命内一直为真。
2. `session_options.delete` 只影响「这一次」传入的 Hash，不会改掉下次 `dispatch` 再传进来的那份。

第二点不成立。`dispatch` 传入的不是副本。

---

## 检查之后谁真正采纳那个 session id

守卫一结束（或者 `@cookie_only` 已经是 `nil`），同一个 `session` 立刻：

```ruby
@session = CGI::Session.new(@cgi, session_options_with_string_keys)
```

`CGI::Session` 按 CGI/session 的老语义：Cookie 没有 id 时，从 query / POST 里取 `session_key` 对应的值。过滤器刚看过的是「`@cookie_only` 此刻是否为真」；session 库看到的是参数表。中间没有第二次「id 必须来自 Cookie」的检查。

`session_options_with_string_keys` 每次用常量 **merge** 当前 `@session_options`：

```ruby
def session_options_with_string_keys
  @session_options_with_string_keys ||= DEFAULT_SESSION_OPTIONS.merge(@session_options).stringify_keys
end
```

merge 是非破坏性的。真正破坏常量的是构造函数里那次 `delete`，发生在 `session` 被调用**之前**，也发生在 merge 能读到 `:cookie_only` **之前**。

谁把常量传进来：

```ruby
# railties/lib/dispatcher.rb  (rails v1.2.4)
def dispatch(cgi = nil, session_options = ActionController::CgiRequest::DEFAULT_SESSION_OPTIONS, output = $stdout)
  request, response = ActionController::CgiRequest.new(cgi, session_options), ActionController::CgiResponse.new(cgi)
```

默认参数就是那份 Hash 对象本身。Ruby 里常量引用的是同一个 Hash。第一次 `CgiRequest.new` 执行 `session_options.delete :cookie_only` 之后，常量里不再有这个键。第二次请求再 `new`，`delete` 返回 `nil`，`@cookie_only` 为假，守卫成了空操作。

---

## 仓库里已经有更强的读法，构造函数没用

同一份 `cgi_process.rb` 里，`session_options_with_string_keys` 已经能在**每次** `session` 时从常量重新 merge。1.2.6 的 `cookie_only?` 走的就是这条路。V1 放着不用，偏在 `initialize` 里对传入 Hash 做破坏性删除，还把结果缓存成实例变量。

谁读 `:cookie_only`（1.2.4）：

| 位置 | 怎么读 |
|---|---|
| `initialize` | `session_options.delete :cookie_only`（破坏共享常量） |
| `session` 守卫 | 只看 `@cookie_only` |
| `session_options_with_string_keys` | `DEFAULT_SESSION_OPTIONS.merge(...)`（非破坏，但此时键已被删） |

不是仓库里没有更好的谓词，是 **守卫读的是被 `delete` 污染过的实例变量**。即便第一次请求不带 `_session_id`（例如 `GET /` 热身），`initialize` 照样 `delete`，之后所有带 URL id 的请求都活。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「第一次 vs 以后每一次」落到具体调用：

- V1 过滤器：`@cookie_only && request_parameters['_session_id']`
- `CGI::Session.new`：query 里的 `_session_id` 一样能打开对应 PStore

只要构造一次 **进程里的第二次（及以后）请求** 再带 URL session id，第一道门已经自己关掉，第二道门会绑定那个 id。

```text
seed（冷启动后第一次 /login?_session_id=S）:
  initialize → delete 之后 @cookie_only == true
  → SessionFixationAttempt → 500

residual（先 GET / 热身，再 /login?_session_id=S）:
  第一次 initialize 已把常量里的 :cookie_only 删掉
  第二次 @cookie_only == nil → 跳过守卫
  → CGI::Session.new 采纳 S
  → /protected 读到 flag
```

weblog.rubyonrails.org 2007-11-24 的 1.2.6 安全公告就是这条链。本 case 把 fixation 效果收成「认证 session 能读金丝雀」，观察的是同一扇门。

---

## 残余仍然走同一条 CgiRequest#session（CVE-2007-6077）

没有换控制器、没有换 PStore、没有换 `_session_id` 这个参数名。还是：

```http
GET /                         → 热身，触发 delete
GET /login?user=victim&_session_id=S
GET /protected
Cookie: _session_id=S
```

`Dispatcher.dispatch` 仍然传入同一份常量。V1 那一行 `delete` 照样在第一次 `initialize` 时改掉它；之后 `@cookie_only` 为假；`CGI::Session.new` 照样从 query 取 id。本 case 在热身之前 `docker compose restart`，好让进程回到「常量还在」的状态，否则上一次探测留下的突变会干扰这一次——这是 residual 的前置，不是另一条漏洞面。

平台残余和 seed 都是 `GET /login?_session_id=` 打进同一个 `CgiRequest#session`。不是另一个 session store，也不是 Cookie 伪造。seed 被挡住只说明「冷启动后的第一次 URL id 会被拒」，不说明「这个进程里以后的请求还认不认 URL id」。

---

## 后来又补了什么（CVE-2007-6077，1.2.6）

1.2.6 删掉 `delete`，每次从 merge 后的选项里读：

```ruby
# actionpack/lib/action_controller/cgi_process.rb  (rails v1.2.6)
def initialize(cgi, session_options = {})
  @cgi = cgi
  @session_options = session_options
  @env = @cgi.send(:env_table)
  super()
end

def cookie_only?
  session_options_with_string_keys['cookie_only']
end

# session 里：
if cookie_only? && request_parameters[session_options_with_string_keys['session_key']]
  raise SessionFixationAttempt
end
```

常量里还加了 `:session_key => "_session_id"`。对残余输入：每一次 `initialize` 都不改常量，每一次 `cookie_only?` 都为真，带 URL id 的登录继续 500。公开建议升级到 1.2.6。

即便如此，这仍然是「在 `CGI::Session.new` 之前读一个布尔」。没有改 CGI 库本身「query 也可当 session id」的语义。对本条 URL fixation 够用。本 benchmark 的 v2 只关闭这一条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是「把开关抠到实例变量」。真正采纳 URL id 的是 `CGI::Session.new`。V2 仍在 `session` 里加码，但终于每次从选项表重读，不再 `delete` 共享 Hash。

**不是没有更好的读法。**  
`session_options_with_string_keys` 已经是非破坏 merge。从 V1 的 diff 只能看到加了 `@cookie_only`；要判断是否闭合，必须看到 `Dispatcher.dispatch` 的默认参数是常量本身，以及 Ruby Hash#delete 的语义。

**同一 `CgiRequest#session`、同一 `_session_id`，只换了第几次请求。**  
第一次带 URL id 会被挡住；任何一次不带 id 的请求（健康检查、favicon、本 case 的 `GET /`）都会把门拆掉。

**实例变量和常量不是一层。**  
守卫读 `@cookie_only`。常量才是「默认策略」。对共享可变对象做 `delete`，等于把默认策略改成「以后都不要 cookie_only」。

**金丝雀在认证资源里是有意的。**  
flag 不在未认证的 `/`。能在 `/protected` 读到它，说明 URL 供给的 `S` 已经被当成受害者登录后的 session——也就是过滤器放行了那次 `CGI::Session.new`。

---

## 版本、入口、参考

| | 版本 | `initialize` | `session` 守卫 | 冷启动 seed | 热身后 residual |
|---|---|---|---|---|---|
| V0 | 1.2.3 / actionpack 1.13.3 | 无 `cookie_only` | 无 | URL id 生效，flag | （不必） |
| V1 | 1.2.4 / 1.13.4 | `session_options.delete :cookie_only` | `@cookie_only` | `SessionFixationAttempt` | 守卫失效，flag |
| V2 | 1.2.6 / 1.13.6 | 不 delete | `cookie_only?` 每次 merge | 挡 | 挡 |

- Web：`GET /seed`、`GET /login?_session_id=`、`GET /protected`
- [CVE-2007-5380](https://nvd.nist.gov/vuln/detail/CVE-2007-5380)、[CVE-2007-6077](https://nvd.nist.gov/vuln/detail/CVE-2007-6077)
- [Rails 1.2.6 公告](https://rubyonrails.org/2007/11/24/ruby-on-rails-1-2-6-security-and-maintenance-release)
- [GHSA-p4c6-77gc-694x](https://github.com/advisories/GHSA-p4c6-77gc-694x)
- V1 源码：[`v1.2.4` `cgi_process.rb`](https://github.com/rails/rails/blob/v1.2.4/actionpack/lib/action_controller/cgi_process.rb)、[`dispatcher.rb`](https://github.com/rails/rails/blob/v1.2.4/railties/lib/dispatcher.rb)
- V2 tag：[`v1.2.6` `cgi_process.rb`](https://github.com/rails/rails/blob/v1.2.6/actionpack/lib/action_controller/cgi_process.rb)
