# TWiki：save 只许 POST，跨站表单本来就会 POST

- Case：`PCBV2-0207`
- 产品：TWiki。运行时是 SourceForge 官方 tarball（4.3.0 / 4.3.1 / 4.3.2）+ Apache mod_cgi + 整棵 `bin/`、`lib/`；不是抽出来的方法检查。
- 链：CVE-2009-1339（4.3.0 → 4.3.1）→ CVE-2009-4898（4.3.1 → 4.3.2）。NVD 对 4898 写明 *this issue exists because of an insufficient fix for CVE-2009-1339*。
- 源码对着 4.3.1 tarball 的 `lib/TWiki/UI/Save.pm`（`post_method_only`）以及 4.3.2 的 `TWiki::UI::verifyCryptToken`。金丝雀是 admin-only 话题 `Main.PcbSecret`：伪造 save 把 `%INCLUDE{"Main.PcbSecret"}%` 写进一页，管理员自己的 view 把 flag 带出来。

根因不只是「忘了 GET」。检查插在 HTTP 方法字符串上；真正改话题的是后面的 store save。浏览器对跨站 `<form method="post">` 会自动带上 `TWIKISID` cookie，方法谓词对这条路为真。下面按 `/bin/save` 走进去。

---

## 这块功能本来在干什么

TWiki 用 CGI `bin/save` 把编辑结果写入话题。未登录或权限不够会被 ACL 挡住；**已登录用户的 cookie 足够代表他写**。4.3.0 没有 CSRF token。设计意图（在 1339 之前）只是：带着合法会话的请求可以保存。成功穿越 = **受害者管理员的身份被用来改一页**，本 case 再通过 `%INCLUDE%` 把只许管理员看的 secret 反射到一篇他能看的页上。

一次典型的产品请求：

```http
GET /bin/save/Main/SomeTopic?text=...
Cookie: TWIKISID=<admin session>
```

或 POST 同一脚本。`bin/save` → `TWiki::UI::Save::save` / `buildNewTopic` → `$store->saveTopic`。

数据流：

```text
浏览器（已登录管理员）访问攻击页
    → 攻击页触发对 wiki 的 /bin/save（GET 或 POST）
         Cookie TWIKISID 自动带上          ← 浏览器同源策略不管跨站表单提交
    → lib/TWiki/UI/Save.pm
         V1：request_method 必须是 POST     ← 补丁只加这一行
         （4.3.1 没有 crypttoken）
         权限按会话用户算 → 管理员可写
         store 写入话题文本
    → 管理员 view 被改过的话题
         %INCLUDE{"Main.PcbSecret"}% → PCBFLAG_...
```

需要受害者已登录（NVD 对 1339 写 remote **authenticated** users；4898 的演示是另一站点的 HTML 诱使浏览器发 POST）。没有「这个 save 必须来自本站表单」的 token 谓词，直到 4.3.2。

---

## 原始漏洞：IMG 即可 GET save（CVE-2009-1339，4.3.0）

4.3.0 的 `Save.pm` 在取出 `$query->param` 之后直接进入保存逻辑，不看 method。把 save URL 放进 `<img src="...">`，管理员打开任意页就会发出 GET，wiki 当一次合法保存。这就是 v0 + seed：伪造 GET `/bin/save` 写 INCLUDE，随后 view 出 flag。

NVD CVE-2009-1339：*as demonstrated by a URL for a save script in the SRC attribute of an IMG element*。官方 hotfix 是 4.3.1 的 POST-only。

---

## 维护者改了什么（CVE-2009-1339 修复，4.3.1）

4.3.1 在 `buildNewTopic` 入口加了方法检查（本 case `patch.diff` 即这份官方 diff）：

```perl
# lib/TWiki/UI/Save.pm   TWiki 4.3.1  （CVE-2009-1339，本 case 的目标）
my $reqmethod = $query->request_method();

if( $reqmethod !~ /^POST$/i ) {
    throw TWiki::OopsException(
        'attention',
        def => 'post_method_only',
        web => $session->{webName},
        topic => $session->{topicName},
        params => [ $script ]);
}
```

对 seed：GET save → oops `post_method_only`，话题不写。这就是 v1 + `--seed`。

补丁默认了两件事：

1. CSRF 的实际形态是「第三方页发出 GET」（IMG、script src）。
2. 只要不是 GET，带 cookie 的请求就是用户自己的保存。

第二点不成立。CSRF 的标准形态就是跨站 **POST form** + `onload=submit`。方法谓词对它为真。

---

## 方法检查通过之后，谁写磁盘

`post_method_only` 一过，4.3.1 的 `Save.pm` 和 4.3.0 一样：读 `text` / `action_quietsave` 等参数，按会话用户做 ACL，调用 store。**没有** `crypttoken` 参数，也没有 `verifyCryptToken`。

过滤器看的是 `$query->request_method()` 是否匹配 `^POST$`；store 看的是「当前会话是谁、正文是什么」。跨站页面可以规定 method=POST 和 hidden 字段，不能读 token（因为它还不存在），但也不需要 token。

Secunia 给 4.3.1 的演示（后来写进 SecurityAuditTokenBasedCsrfFix）就是：

```html
<form action="http://example.com/twiki431/bin/save/Sandbox/TestTopic" method="post" name="csrf">
<input type="hidden" name="action_quietsave" value="1">
<input type="hidden" name="text" value="Secunia was here">
</form>
<body onLoad="Javascript:document.csrf.submit()">
```

这和 1339 是同一条 `/bin/save`、同一套 store，只是把 GET 换成 POST。

---

## 仓库里已经有更强的「这次提交来自本站表单」谓词吗

4.3.1 **没有** crypt token 实现。更强的谓词是后来 4.3.2 才引入的：`LoginManager::createCryptToken` / `addCryptTokeninForm` 在本站编辑表单里放一次性字段，`TWiki::UI::verifyCryptToken` 在 save 时校验。那才是 CSRF 要的「请求必须绑到本站刚发的表单」。

4.3.1 能用却没用上的，还有一些较弱的辅助：检查 `Referer` 是否为本机（可被绕过，且当时不是官方修复）。维护者选择的是最窄的那一层——HTTP 方法——而这层对 POST CSRF 恒为真。

---

## 这个补丁挡住了什么、没挡住什么

- V1 `request_method !~ /^POST$/i`：看是不是 GET/HEAD/…
- store save：看会话 cookie + 正文参数

IMG/GET seed 被挡住。同源策略**不阻止**跨站 POST 带 cookie。方法检查对 residual 为真，save 写入 INCLUDE，管理员 view 出 flag。

NVD CVE-2009-4898：*as demonstrated by a URL for a save script in the ACTION attribute of a FORM element, in conjunction with a call to the submit method in the onload attribute of a BODY element. NOTE: this issue exists because of an insufficient fix for CVE-2009-1339.* 和源码、和 Secunia 演示一致。

---

## 残余仍然走同一条 /bin/save 写话题路径（CVE-2009-4898）

没有换脚本、没有换 ACL、没有换「用管理员会话写一页再 INCLUDE secret」这个效果通道。还是伪造 `/bin/save`。差别只是方法：GET 换成自动提交的 POST form。

平台 residual 若用 tokenless POST 打同一 save，和 NVD / SecurityAudit 是同一 sink。不是另起一个编辑 API 或附件上传。

把 V1 的方法谓词对着两种伪造请求展开：

```text
seed  GET /bin/save/Main/PcbLeak?text=%INCLUDE{"Main.PcbSecret"}%
      Cookie: TWIKISID=...
      request_method = "GET"
      "GET" =~ /^POST$/i  → 假
      throw OopsException def=post_method_only
      store 不被调用，话题原样

residual  POST /bin/save/Main/PcbLeak
          Cookie: TWIKISID=...          ← 浏览器跨站表单自动带
          body: action_quietsave=1&text=%INCLUDE{"Main.PcbSecret"}%
          request_method = "POST"
          "POST" =~ /^POST$/i  → 真
          4.3.1 没有下一道 crypttoken
          ACL：会话用户 ∈ TWikiAdminGroup → 可写 Main
          $store->saveTopic(...)
```

`bin/save` 是 TWiki 的普通 CGI：Apache 把 cookie 放进 `%ENV` / CGI 对象，`TWiki::LoginManager` 用 `TWIKISID` 恢复会话，**不**验证 Origin / Referer 是否为本机（4.3.1 源码里 save 路径没有这步）。方法检查通过后，正文里的 `%INCLUDE%` 只是话题标记，保存时不当成「读 secret 的权限检查」——INCLUDE 在**之后**管理员 view 那一页时展开。`Main.PcbSecret` 的 `ALLOWTOPICVIEW = TWikiAdminGroup` 拦的是未授权 view，拦不住管理员自己打开被 CSRF 改过的页。

4.3.0 / 4.3.1 / 4.3.2 在 save 入口上的并排关系：

```perl
# V0  4.3.0     无 method，无 token
my $revision = $query->param( 'rev' ) || undef;
unless( scalar($query->param()) ) { ... }

# V1  4.3.1     只有 method
my $reqmethod = $query->request_method();
if( $reqmethod !~ /^POST$/i ) {
    throw TWiki::OopsException( 'attention', def => 'post_method_only', ... );
}

# V2  4.3.2     method + crypttoken（若 {CryptToken}{Enable}）
TWiki::UI::verifyCryptToken( $session, $query->param('crypttoken') );
```

V1 的 hotfix 文件名就叫 `TWiki-4.3.0-c-hotfix-cve-2009-1339`，diff 只动 `Save.pm` 这十几行。token 所需的 `createCryptToken` / `addCryptTokeninForm` 当时还不在树里。

这就是为什么金丝雀放在 admin-only 话题里：GET 出 flag 证明写入是以管理员身份发生的，而不是匿名写了一页公开文本。1339 和 4898 的效果通道相同，差的只是浏览器发出去的 method。

---

## 后来又补了什么（CVE-2009-4898，4.3.2）

4.3.2 在 save 路径调用：

```perl
TWiki::UI::verifyCryptToken( $session, $query->param('crypttoken') );
```

token 由 `createCryptToken`（MD5(rand) 一类一次性值）生成，编辑表单经 `addCryptTokeninForm` 带出。跨站页拿不到当前 token（且一次性），tokenless POST 走到 `invalidtoken` oops，话题不写。配置项 `{CryptToken}{Enable}` 可关；审计建议关键公网站点打开。

对 residual：没有合法 crypttoken → 挡。公开建议升到 TWiki-4.3.2（TWikiRelease04x03x02）。本 benchmark 的 v2 只关闭这条 tokenless POST。

即便上了 token，若管理员把 `{CryptToken}{Enable}` 关掉，谓词再次缺席——那是配置，不是 4.3.1 那次不完全修复本身。

4.3.2 的 `verifyCryptToken` 从请求里取 `crypttoken`，与会话里尚未消耗的一次性值比较，失败则 `OopsException` `invalidtoken`。编辑页的 HTML 由 `addCryptTokeninForm` 插入 hidden 字段；跨站静态页既读不到这个字段，也没有第二次使用同一 token 的资格。SecurityAudit 把这称为 Severity 3：内容被改写。演示里的 `action_quietsave=1` 只是少一次确认 UI，不绕过 token。4.3.1 的 hotfix tarball（`TWiki-4.3.0-c-hotfix-cve-2009-1339`）和 4.3.1 正式版一样只有 POST-only，没有 token 文件——所以「升到含 1339 修复的版本」并不自动带上 4898。

本 case 的 flag 在 `Main.PcbSecret`，`Set ALLOWTOPICVIEW = TWikiAdminGroup`。CSRF 写入的话题对管理员可 view，INCLUDE 在渲染期展开 secret。观察通道是 view CGI 的 body，sink 是 save CGI 的 store 写入。

---

## 从这条链还能看出什么

**维护者改错了哪一层。**  
他们改的是 CGI 方法。真正被滥用的是「带会话 cookie 的 save」。CSRF 要绑的是**本站表单**，不是 GET vs POST。

**不是 4.3.1 之后才发明 token。**  
只是 1339 的 hotfix 没做到这一层。4898 的审计页把 POST form 整页贴出来，等于指出方法检查从一开始就挡不住演示里的那种请求。

**同一 `Save.pm`、同一 `$query`，只换了 method。**  
任何能改内容的脚本若只学了 POST-only、没有 token，都会重复这个缺口。

**效果是写话题，不是未授权登录。**  
两条 CVE 都是劫持已有会话。金丝雀放在 `ALLOWTOPICVIEW = TWikiAdminGroup` 的页里，是为了证明写入是以管理员身份发生的。

4.3.1 的 oops 模板 `post_method_only` 只是把 GET 用户转到注意页，不改变「POST 即视为自愿保存」这个模型。TWiki 还有 `bin/preview`、`bin/upload` 等会改内容的脚本；4898 的审计和 NVD 演示针对的是 save。本 case 只打 `/bin/save`，与官方演示一致。邮件通知、WebDAV 不在这条 CSRF 链上。

---

---

## CGI 入口和会话恢复

Apache 把 `/bin/save/Main/PcbLeak` 交给 `bin/save`。`setlib.cfg` 设好 `@INC` 后，`TWiki::UI::run` 分发到 `TWiki::UI::Save::save`。`TWIKISID` 由 `TWiki::LoginManager` 恢复成管理员会话，ACL 按这个用户计算。4.3.1 的方法检查发生在 `buildNewTopic` 里、读 `text` 参数之后不久、写 store 之前。它不读 Referer、不读 Origin、不读任何 hidden 字段。跨站 POST 只要 method 对、cookie 在，就会进入与本站编辑表单相同的保存函数。`action_quietsave` 只跳过确认页，不是安全谓词。

官方 1339 diff 只给 `Save.pm` 加了十几行。4.3.2 才在 `UI.pm` / `LoginManager.pm` 增加 token 的生成、入表单、校验。所以「已经打过 1339 hotfix」的站点，save 路径上仍然没有 crypttoken 这个符号。

view 侧：管理员打开被写入 INCLUDE 的话题时，`bin/view` 按会话做 `ALLOWTOPICVIEW`。INCLUDE 的目标 `Main.PcbSecret` 也要求 AdminGroup，管理员自己过。flag 出现在 view 的 HTML 里，不出现在 save 的 302/oops 页上。seed 在 V1 的观察点是 oops `post_method_only` 且话题未变；residual 在 V1 的观察点是 view body 里的 `PCBFLAG_`。两条请求都是外部 HTTP，都打同一 CGI 树。

## 版本、入口、参考

| | 版本 | `Save.pm` 入口 | GET save（IMG） | tokenless POST form |
|---|---|---|---|---|
| V0 | 4.3.0 | 无 CSRF 谓词 | 写入，view 出 flag | （不必） |
| V1 | 4.3.1 | `post_method_only` | oops，不写 | 写入，view 出 flag |
| V2 | 4.3.2 | 同上 + `verifyCryptToken` | 挡 | invalidtoken，不写 |

- 产品 HTTP：`/bin/save/<Web>/<Topic>`（Cookie `TWIKISID`）
- [CVE-2009-1339](https://nvd.nist.gov/vuln/detail/CVE-2009-1339)、[CVE-2009-4898](https://nvd.nist.gov/vuln/detail/CVE-2009-4898)（*insufficient fix for CVE-2009-1339*）
- [SecurityAlert-CVE-2009-1339](http://twiki.org/cgi-bin/view/Codev/SecurityAlert-CVE-2009-1339)、官方 diff：`TWiki-4.3.0-c-diff-cve-2009-1339.txt`
- [SecurityAuditTokenBasedCsrfFix](http://twiki.org/cgi-bin/view/Codev/SecurityAuditTokenBasedCsrfFix)（4.3.2，含 Secunia POST 演示）
- V1 源码：TWiki-4.3.1.tgz 中 `lib/TWiki/UI/Save.pm`（`post_method_only`）
- V2：TWiki-4.3.2.tgz 中同文件调用 `lib/TWiki/UI.pm` 的 `verifyCryptToken`；token 来自 `lib/TWiki/LoginManager.pm`
