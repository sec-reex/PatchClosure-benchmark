# JS Help Desk：一处 SELECT 加了 sanitize_email，拷贝的那份查询没动

- Case：`PCBV2-0132`
- 产品：WordPress 插件 JS Help Desk（slug `js-support-ticket`）
- 链：CVE-2023-50839（2.8.1 → 2.8.2）→ CVE-2023-7337（2.8.2 → 2.8.3）
- 源码对着 WordPress.org tag `2.8.2` 的 `modules/ticket/model.php`：`getTicketidForVisitor`、`validateTicketDetailForVisitor`，以及 `includes/encoder.php` 的 token。运行时是官方 `wordpress` 镜像 + 整包插件 zip，不是抽出来的 SQL 字符串。

2023 年 12 月，2.8.2 给访客查票函数 `getTicketidForVisitor` 加了 `sanitize_email()`，想挡住 `email` / `trackingid` 参数上的 SQL 注入。Wordfence 给 CVE-2023-7337 的原文是：*vulnerable to SQL Injection via the js-support-ticket-token-tkstatus cookie in version 2.8.2 due to an incomplete fix for CVE-2023-50839 where a second sink was left with insufficient escaping*。NVD 同样写明 *incomplete fix for CVE-2023-50839*。

根因不只是「cookie 没过滤」。检查插在「解码 token 之后、拼 SQL 之前」这一层，而且只插进了一个函数；真正执行查询的是另一份字面相同的 `SELECT id ... WHERE email='...' AND ticketid='...'`；WordPress 自己的 `esc_sql` / `$wpdb->prepare` 都在，却没挂上那份拷贝。下面按请求走进去、2.8.2 改了哪几行、消毒之后谁消费那两个字段、更强的谓词有没有挂上 sibling，把这几层写完。

平台 residual 走 cookie + `ticketdetail` 短代码，seed 走 `showticketstatus` 表单。HTTP 入口不同，SQL 文本与保护的 `pcb_secret` 相同。这是这条链自己的第二处 sink，不是另起的洞。

---

## 这块功能本来在干什么

JS Help Desk 让未登录访客用邮箱 + tracking id 查自己的工单。前端把这两项打成 token（`encoder.php`：历史上走 mcrypt，本版本 `JSST_safe_encoding` 退化成普通 base64），再在两处解码后查表。

查状态（seed 入口）大约是：

```http
POST /js-support-ticket-controlpanel/
form_request=jssupportticket&jstmod=ticket&task=showticketstatus
&email=...&ticketid=...
```

控制器把 email/ticketid 封进 token，交给 `getTicketidForVisitor`。它返回的 `id` 被 `showticketstatus` 写进 302 的 `Location`：`...&jssupportticketid=<id>`。UNION 注入因此能把子查询结果反射到 Location。

看工单详情（residual 入口）是短代码页 `jstlay=ticketdetail`，用 cookie `js-support-ticket-token-tkstatus` 证明「我是这张票的访客」。`validateTicketDetailForVisitor` 解码 cookie，跑**同一条** SELECT，用返回的 id 和 URL 上的 `$id` 比较。

成功穿越之后的效果是：**未认证读出 `wp_options.pcb_secret`（值为 `PCBFLAG_...`）**，seed 出现在 Location，residual 出现在页面的 XPATH 错误里。

数据流：

```text
email / ticketid 或 cookie token
    → encoder.decrypt（实为 base64+json）
    → emailaddress, trackingid          ← 仍是用户字符串
    → getTicketidForVisitor             ← V1 只在这里 sanitize_email
         SELECT id FROM wp_js_ticket_tickets
         WHERE email='...' AND ticketid='...'
    → 返回 id → Location
    → validateTicketDetailForVisitor    ← V1 不碰
         同一 SELECT，拼接未转义
    → get_var → 比 id / 报错
```

设计意图：token 证明访客知道那对 email+trackingid，查询只应返回自己的票号。没有登录。两处函数复制了同一条字符串拼接 SQL。

`showticketstatus` 把 `getTicketidForVisitor` 的返回值直接拼进 302：

```text
Location: ...&jssupportticketid=<get_var 的标量>
```

所以 seed 不必靠错误回显：UNION 把 `pcb_secret` 放进 `id` 列，Location 就是 exfil 通道。`validateTicketDetailForVisitor` 只返回 true/false，同一 UNION 反射不到 Location，才改走 `extractvalue` 错误串。效果通道变了，读的仍是 `wp_options.pcb_secret`。

---

## 原始漏洞：参数拼进 SELECT（CVE-2023-50839，2.8.1）

2.8.1 的 `getTicketidForVisitor` 在空值检查之后直接拼接：

```php
// modules/ticket/model.php :: getTicketidForVisitor  (2.8.1)
if($emailaddress == '' && $trackingid == ''){
    return false;
}
$query = "SELECT id FROM `" . jssupportticket::$_db->prefix . "js_ticket_tickets` WHERE email = '" . $emailaddress . "' AND ticketid = '" . $trackingid . "'";
$ticketid = jssupportticket::$_db->get_var($query);
return $ticketid;
```

Wordfence / Patchstack：`email` 与 `trackingid` 转义不足。Nuclei 公开 PoC 是 `email=test@test.com' AND SLEEP(8)-- -`。本 case 的 seed 用 UNION 把 `pcb_secret` 选进 `id` 列，302 Location 里出现 flag。v0 + `--seed` 退出码 0。

nonce 检查在控制器里被注释掉，所以这是未认证的。token 可伪造：base64(json)。

---

## 维护者改了什么（CVE-2023-50839 修复，2.8.2）

2.8.2 只在 `getTicketidForVisitor` 的空值分支改成 else，调用 `sanitize_email`：

```php
// modules/ticket/model.php :: getTicketidForVisitor  (tag 2.8.2)
if($emailaddress == '' && $trackingid == ''){
    return false;
} else{
    $emailaddress = sanitize_email($emailaddress);
    $trackingid = sanitize_email($trackingid);
}
$query = "SELECT id FROM `" . jssupportticket::$_db->prefix . "js_ticket_tickets` WHERE email = '" . $emailaddress . "' AND ticketid = '" . $trackingid . "'";
$ticketid = jssupportticket::$_db->get_var($query);
return $ticketid;
```

`sanitize_email` 会剥掉空格、引号、以及大量非邮箱字符。UNION / 注释 / `SLEEP` 进不了拼接后的引号串。对 seed 这种参数注入，它确实够用：v1 + `--seed` 退出码 10。

同一文件里，sibling 仍是：

```php
// modules/ticket/model.php :: validateTicketDetailForVisitor  (tag 2.8.2)
function validateTicketDetailForVisitor($id) {
    if (!isset($_COOKIE['js-support-ticket-token-tkstatus'])) {
        return false;
    }
    $token = jssupportticket::JSST_sanitizeData($_COOKIE['js-support-ticket-token-tkstatus']);
    include_once JSST_PLUGIN_PATH . 'includes/encoder.php';
    $encoder = new JSSTEncoder();
    $decryptedtext = $encoder->decrypt($token);
    $array = json_decode($decryptedtext, true);
    $emailaddress = $array['emailaddress'];
    $trackingid = $array['trackingid'];
    $query = "SELECT id FROM `" . jssupportticket::$_db->prefix . "js_ticket_tickets` WHERE email = '" . $emailaddress . "' AND ticketid = '" . $trackingid . "'";
    $ticketid = jssupportticket::$_db->get_var($query);
    ...
}
```

补丁默认了两件事：

1. 危险输入只从 `showticketstatus` 的 email/ticketid 进来。
2. `sanitize_email` 作用在「解码后的那两个字段」上，所有跑这条 SQL 的函数都会被盖到。

第二点不成立。`validateTicketDetailForVisitor` 自己解码 cookie，字段从不经过 `getTicketidForVisitor`。`JSST_sanitizeData` 只打在**整段 base64 外表**上，解码之后的 JSON 字段原样进引号。

---

## 消毒之后，谁真正消费那两个字段

`sanitize_email` 的消费者是紧随其后的字符串拼接，且仅限 `getTicketidForVisitor`。`validateTicketDetailForVisitor` 的消费者是 `$wpdb->get_var($query)`（插件把连接挂在 `jssupportticket::$_db` 上）。MySQL 看到的是拼完的文本，不是「曾经对另一函数做过邮箱消毒」。

`validateTicketDetailForVisitor` 返回布尔。UNION 把 `pcb_secret` 反射进 `id` 再写 Location 这条路在这里走不通。错误回显仍然把 `get_var` 的 SQL 错误打到页面上（本 case mu-plugin 打开 `show_errors`）。`extractvalue(..., concat(0x7e, (SELECT option_value ... pcb_secret)))` 把 flag 放进 XPATH 错误字符串。

所以：过滤器刚看过的是「像不像 email」；sink 看到的是「引号里是不是还是攻击者的 SQL」。两套语义中间，sibling 没有第二次谓词。

---

## 仓库里已经有更强的检查，cookie 那份查询没用

WordPress 提供 `esc_sql()` 和 `$wpdb->prepare('%s')`。2.8.3 后来给 sibling 加的就是 `esc_sql($emailaddress)` / `esc_sql($trackingid)`。2.8.2 连 `sanitize_email` 都没在 sibling 上调用。

谁在 2.8.2 用了什么：

| 函数 | 解码后字段如何处理 |
|---|---|
| `getTicketidForVisitor` | `sanitize_email`（V1 新加） |
| `validateTicketDetailForVisitor` | **无**，直接进单引号 |
| `validateTicketDetailForUser` | 对 `$id` 做 `is_numeric`（另一条查询） |

`sanitize_email` 本身也不是 SQL 谓词：它是邮箱字符白名单，碰巧掐死了引号和空格。真正该挂的是参数化查询。不是仓库/平台里没有更好的 API，是 **第二处拷贝没用，第一处用的还是「像邮箱」而不是「像 SQL 字符串」**。

---

## 这个补丁挡住了什么、没挡住什么

- `sanitize_email`：删掉不像邮箱的字符（含 `'`、空格、`UNION` 里的字母数字之外的符号）
- sibling 的 `WHERE email = '" . $emailaddress . "'`：把解码后的字段原样放进 SQL

cookie 里的 JSON 可以是 `{"emailaddress":"' AND extractvalue(1,concat(0x7e,(SELECT option_value FROM wp_options WHERE option_name='pcb_secret')))-- ","trackingid":"1"}`。外表 base64 经得住 `JSST_sanitizeData`；解码后引号和 SQL 关键字都还在。

把同一对字段放进两种消毒里看字符怎么变：

```text
emailaddress = ' UNION SELECT option_value FROM wp_options WHERE option_name='pcb_secret' --

sanitize_email(...) 之后（seed / getTicketidForVisitor）：
  引号、空格、多数 SQL 标点被剥掉
  剩下不像邮箱的碎片
  WHERE email = 'UNIONoption_value...'  → 不再能闭合引号

不消毒（residual / validateTicketDetailForVisitor）：
  WHERE email = '' UNION SELECT ... pcb_secret --' AND ticketid = '1'
  get_var 把 option_value 读进错误或结果集
```

encoder 这一层也不帮忙。2.8.x 去掉 mcrypt 之后 `decrypt` 就是 base64 解码；攻击者本地 `base64(json)` 即可伪造 cookie，不必知道站点密钥。

```text
seed POST showticketstatus email=...' UNION SELECT ... pcb_secret
  V1：sanitize_email 剥掉引号/空格 → 注入死 → Location 无 flag

residual Cookie: js-support-ticket-token-tkstatus=<base64 json>
  GET ... jstlay=ticketdetail
  V1：validateTicketDetailForVisitor 原样拼接 → extractvalue 错误页含 PCBFLAG_...
```

V1 挡的是「经过 getTicketidForVisitor 的那一次拼接」；它没挡「同一条 SQL 的另一份拷贝」。seed 被挡住只说明那一个函数的输入不像 email 了。

---

## 残余仍然读同一张表、同一枚 `pcb_secret`（CVE-2023-7337）

没有换表、没有换 option 名、没有换成已登录用户。还是访客 token → `SELECT id ... email= ... ticketid=`。换的是函数和投递通道（cookie 而不是 POST 字段）。heldout 的 `technique: cookie-error` 与 Wordfence 描述一致。认证：v1 + `--residual` 退出码 0，页面错误里观察到 flag。

所以残余不是新洞面，而是同一查询文本上三件事叠在一起：修复按函数而不是按 SQL 模板；cookie 消毒打在编码外壳上；解码后字段直接进引号。

---

## 后来又补了什么（CVE-2023-7337，2.8.3）

2.8.3 给 sibling 包上 `esc_sql`：

```php
$query = "SELECT id FROM ... WHERE email = '" . esc_sql($emailaddress) . "' AND ticketid = '" . esc_sql($trackingid) . "'";
```

引号被转义，`extractvalue` 进不了 SQL 结构，不再出现带 flag 的 XPATH 错误。公开建议升级到 2.8.3。插件 trac changeset：`tags/2.8.2` → `tags/2.8.3`。

这仍然是字符串转义，不是 `$wpdb->prepare`。对这条 cookie 注入链它够用。本 benchmark 的 v2 只关闭这一条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是一个 PHP 函数的局部变量。真正进 MySQL 的是两处各自拼出来的字符串。V2 仍在第二处加 `esc_sql`，没有抽成单一 parameterized helper。

**不是没有更好的谓词。**  
`esc_sql` / `prepare` 比 `sanitize_email` 更接近「SQL 字符串安全」。V1 选了邮箱消毒，且只盖一处。从 2.8.2 的 diff 只能看到 `getTicketidForVisitor` 多了 else；要判断是否闭合，必须看到下面几十行的 `validateTicketDetailForVisitor`。

**同一 SELECT，只换了 token 从哪来。**  
任何解码出 `emailaddress`/`trackingid` 再拼进这句 SQL 的代码，在 2.8.2 上都可能是第二入口。cookie 只是插件自己留的那条。

**外壳消毒 ≠ 字段消毒。**  
`JSST_sanitizeData` 让人以为 cookie 已经「干净」。攻击者控制的是 base64 里的 JSON，不是外表的尖括号。

**金丝雀在 wp_options 里是有意的。**  
能出现在 SQL 错误里，说明注入读的是数据库，而不是 ticket 表碰巧有一行叫 flag。

---

## 版本、入口、参考

| | 插件 | `getTicketidForVisitor` | `validateTicketDetailForVisitor` | 参数 UNION seed | cookie extractvalue residual |
|---|---|---|---|---|---|
| V0 | 2.8.1 | 无转义 | 无转义 | Location 含 flag | （不必） |
| V1 | 2.8.2 | `sanitize_email` | 仍无转义 | 注入死 | 错误页含 flag |
| V2 | 2.8.3 | 同 V1 | `esc_sql` | 挡 | 无 XPATH 错误 |

- seed：`POST ... task=showticketstatus`
- residual：短代码页 + cookie `js-support-ticket-token-tkstatus`
- [CVE-2023-50839](https://nvd.nist.gov/vuln/detail/CVE-2023-50839)、[CVE-2023-7337](https://nvd.nist.gov/vuln/detail/CVE-2023-7337)
- [Wordfence 50839](https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/js-support-ticket/js-help-desk-281-unauthenticated-sql-injection-via-email-and-trackingid)、[Wordfence 7337](https://www.wordfence.com/threat-intel/vulnerabilities/id/b841531b-8728-4933-b3c4-d4e10cbdca79)
- [trac 2.8.2→2.8.3](https://plugins.trac.wordpress.org/changeset?old_path=/js-support-ticket/tags/2.8.2&new_path=/js-support-ticket/tags/2.8.3)
- 源码：[`tags/2.8.2` model.php](https://plugins.svn.wordpress.org/js-support-ticket/tags/2.8.2/modules/ticket/model.php)
- Patchstack / Nuclei 亦收录 2.8.1 参数注入；2.8.3 才给 cookie 那份查询补 `esc_sql`。
