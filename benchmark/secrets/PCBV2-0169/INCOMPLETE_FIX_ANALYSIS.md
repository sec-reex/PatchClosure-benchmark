# PHPMailer：escapeshellarg 包上 Sender，mail() 内部再逃逸一次把引号撕开

- Case：`PCBV2-0169`
- 产品：PHPMailer（已发布的 `class.phpmailer.php`）。公开 API 是 `setFrom($address)` → `isMail()` → `send()`。本 case harness `require` 各 tag 的未改字节，HTTP `GET /send?from=` 只负责把 From 传进去。
- 链：CVE-2016-10033（5.2.17 → 5.2.18，`validateAddress` + `escapeshellarg` 再拼 `-f`）→ CVE-2016-10045（5.2.18 → 5.2.20，`isShellSafe` 白名单；NVD：*this vulnerability exists because of an incorrect fix for CVE-2016-10033*）。
- 源码对着 tag `v5.2.18` 的 `class.phpmailer.php`（`setFrom`、`mailSend`）。V0 是 `v5.2.17`。V2 是 `v5.2.20`。Dawid Golunski 的 [LegalHackers advisory](https://legalhackers.com/advisories/PHPMailer-Exploit-Remote-Code-Exec-CVE-2016-10045-Vuln-Patch-Bypass.html) 写了二次逃逸。

5.2.18 把信封发件人丢进 `escapeshellarg`，想让 `-f` 变成一个 shell 词。PHP 的 `mail()` 随后对 additional_parameters 再跑 `php_escape_shell_cmd()`。Sender 里若有单引号，`escapeshellarg` 产出 `'\''` 序列，第二趟按自己的引号状态把反斜杠转义掉，外层引号错位，`-X<path>` 重新成为独立 sendmail 参数。NVD 把这记成 CVE-2016-10045。

根因不只是「忘了某种引号」。检查插在「这是不是邮箱 + 用 escapeshellarg 包一层」上；真正进 sendmail 命令行的是 `mail()` 内部逃逸之后的字节。SMTP 路径根本不拼 `-f` 给 shell；`isMail` 才走这条。5.2.18 没有「shell 安全字符」白名单，那是 5.2.20 才加的 `isShellSafe`。下面按 `setFrom` 走进去。

---

## 这块功能本来在干什么

很多 PHP 应用把用户填的 From 交给 PHPMailer，用系统 `mail()`（sendmail 兼容包装）发信。`setFrom` 在 `$auto=true`（默认）时把地址拷到 `$this->Sender`，`mailSend` 再把它变成 sendmail 的 `-f`（信封发件人 / Return-Path）。

一次典型调用（本 case HTTP）：

```http
GET /send?from=%22a'%5C%22%20-X/canary/out.txt%20%5C%22b%22@x.com
```

库内部：

```php
$mail->isMail();
$mail->setFrom($from);
$mail->send();
```

设计意图：Sender 只出现在一个 `-f…` 参数里，不能再塞 `-X` / `-o` 之类。成功穿越之后的效果是 **sendmail argv 上出现独立的 `-X/canary/out.txt`**。本 case 用假 sendmail shim：只有看到独立 `-X` 才把种在 `/canary/flag.txt` 的 flag 拷到该路径，harness 读 `canary_out`。没有真 MTA、没有 webshell。

数据流：

```text
From 地址
    → setFrom
         validateAddress（pcre8 RFC5322）
         Sender = address
    → send / mailSend
         V0：$params = sprintf('-f%s', $this->Sender)
         V1：validateAddress 后再 sprintf('-f%s', escapeshellarg($this->Sender))
         mailPassthru → mail($to, $subject, $body, $header, $params)
              PHP 内部 php_escape_shell_cmd($params)
              sendmail … $params
```

`validateAddress` 管的是「像不像邮箱」，不管「像不像 shell 词」。带引号的 RFC5322 quoted-local-part 可以通过。

---

## 原始漏洞：`-f` 原样拼接（CVE-2016-10033，5.2.17）

V0：

```php
        if (!empty($this->Sender)) {
            $params = sprintf('-f%s', $this->Sender);
        }
```

Sender 为 `"a'\" -X/canary/out.txt \"b"@x.com` 时，shell 在 `-f` 里看到成对双引号和空格，`-X/canary/out.txt` 成为下一个 argv。shim 拷 flag。这就是 v0 + `--seed`。

`setFrom` 在 V0/V1 都是先 `validateAddress`，失败则抛/返回 false，成功则 `$this->From = $address`，`$auto` 时若 `Sender` 为空就拷过去。用户只控制 From，不直接写 `Sender` 属性；应用常见写法正是「把表单 From 丢进 `setFrom`」。`addAddress` 另有自己的 `validateAddress`，不进入 `-f`。

---

## 维护者改了什么（CVE-2016-10033，5.2.18）

V1 `mailSend`：

```php
// class.phpmailer.php  (v5.2.18, 约 L1437–1442)
        $params = null;
        if (!empty($this->Sender) and $this->validateAddress($this->Sender)) {
            $params = sprintf('-f%s', escapeshellarg($this->Sender));
        }
        if (!empty($this->Sender) and !ini_get('safe_mode') and $this->validateAddress($this->Sender)) {
            $old_from = ini_get('sendmail_from');
            ini_set('sendmail_from', $this->Sender);
        }
```

`escapeshellarg` 用**单引号**包起整段，内部 `'` 变成 `'\''`。对 seed 那种靠双引号 / 空格拆词的写法，包完之后是一个词，`-X` 出不去。这就是 v1 + `--seed` 退出码 10。`mailSend` 的 sendmail 二进制路径那条（非 `isMail`）在 5.2.18 也对 Sender 用了 `escapeshellarg`。

补丁默认了两件事：

1. 能进 `-f` 的 Sender 已经是 `validateAddress` 眼里的邮箱。
2. `escapeshellarg` 的结果交给 `mail()` 之后，shell 仍把它当成一个词。

第二点不成立。`mail()` 的 additional_parameters 还会再逃逸一次。

---

## escapeshellarg 之后，参数怎么接到 sendmail 上

`mailPassthru` 把 `$params` 原样传给 `mail(…, $params)`。PHP 源码里 `php_mail` 对第五参调用 `php_escape_shell_cmd`（按当前引号状态转义元字符），再交给 `/bin/sh -c`。

过滤器（`escapeshellarg`）看的是「我包了一对匹配的单引号」。消费者（`php_escape_shell_cmd`）看的是「从左到右哪些字节在引号里」。PHP 的 `escapeshellarg` 对内部 `' ` 的标准展开是：结束当前单引号、输出 `\'`、再打开单引号。Sender `"a' -X/canary/out.txt b"@x.com` 经 `sprintf('-f%s', escapeshellarg(...))` 之后，`$params` 里会出现 `'\''` 这种「闭-反斜杠-开」序列。

`mail()` 并不把 fifth argument 当已经安全的 argv 数组，而是再跑 `php_escape_shell_cmd`：在**当前未加引号**的区段里给元字符加反斜杠。刚才那次闭引号让 `-X/canary/out.txt` 落到未加引号区段，空格成为词界，sendmail 看到独立的 `-X`。LegalHackers 把这称作 escapeshellarg 与 `mail()` 内部逃逸的 **improper interaction**——和 NVD 对 10045 的表述一字不差。

seed 的双引号版本在 `escapeshellarg` 之后整段都在一对单引号里，第二趟看不到可拆的空格，所以 V1 挡 seed、放 residual。差别不在 `-X` 这个 token，在 **哪一种引号让两层逃逸的引号状态机不同步**。

`mailPassthru` 才是 `mail()` 的调用点。5.2.18：

```php
    private function mailPassthru($to, $subject, $body, $header, $params)
    {
        ...
        if (ini_get('safe_mode') or !$this->UseSendmailOptions or is_null($params)) {
            $result = @mail($to, $subject, $body, $header);
        } else {
            $result = @mail($to, $subject, $body, $header, $params);
        }
        return $result;
    }
```

`$this->UseSendmailOptions` 默认 true。V1 在 Sender 合法时 `$params` 非 null，于是走五个参数的 `mail()`，触发 `php_escape_shell_cmd`。V2 `isShellSafe` 失败时不赋值 `$params`，它保持 `null`，`mailPassthru` 走四个参数——**第五参根本不进 sendmail**，不是「空的 -f」。这才是 residual 在 5.2.20 上被关掉的方式。

---

## 仓库里已经有更强的检查，isMail 没用

| 路径 | 如何处理 Sender |
|---|---|
| `smtpSend` | 交给 SMTP `MAIL FROM`，不经过 shell |
| V1 `mailSend` | `validateAddress` + `escapeshellarg` → `mail()` 再逃逸 |
| V2 `isShellSafe` | `[alnum]@_-.` 且 `escapeshellcmd`/`escapeshellarg` 必须是 no-op，否则不传 `-f` |
| `escapeshellcmd($this->Sendmail)` | 只保护二进制路径，不保护 `-f` 的值 |

不是没有「不要把用户字符串当 shell」的做法：改用 SMTP，或对 Sender 做字符白名单。V1 选了「邮箱校验 + arg 包装」，而消费者是会再写一遍转义的 `mail()`。`isShellSafe` 在 5.2.18 **还不存在**。

`mailSend` 里还有 `ini_set('sendmail_from', $this->Sender)`。那是 PHP 的 `sendmail_from` INI，不是 argv。10045 不靠它。`safe_mode` 在 5.2.18 仍被检查：开着时不设 INI，但 `$params` 照样传给 `mail()`——残差发生在 `$params` 上，与 safe_mode 无关（7.x 起 safe_mode 已移除）。

`sendmailSend`（`isSendmail()`）在 5.2.18 把 Sender 放进 `escapeshellarg` 之后自己 `popen`/`mail`，不经过 `php_escape_shell_cmd` 对 additional_parameters 的那一趟。NVD 把 10045 写在 **isMail transport**。本 case harness 固定 `$mail->isMail()`，对准这条双重逃逸，而不是 sendmail 二进制路径。

---

## 这个补丁挡住了什么、没挡住什么

- V1：`validateAddress` + `escapeshellarg` 是否产出带匹配单引号的一个词
- `php_escape_shell_cmd` + sendmail：二次逃逸后 argv 如何切分

seed 用双引号 / 反斜杠拆词，第一层包成单引号词，挡。residual 用**单引号**触发 `'\''` 序列，第二层撕开。本 case residual：

```text
From = "a' -X/canary/out.txt b"@x.com
```

RFC5322 合法，`escapeshellarg` 放行，shim 再次看到独立 `-X`，`canary_out` 里出现 flag。同一 `-f` sink，只换了引号种类。

---

## 残余仍然走同一条 setFrom → mailSend（CVE-2016-10045）

没有换 transport、没有换 `Sender` 字段。还是 `isMail` + `mail(..., $params)`。5.2.18 的 `escapeshellarg` 照跑；`mail()` 再逃逸；`-X/canary/out.txt` 到达 shim。seed 被挡住只说明「双引号拆词没了」，不说明「不能再给 sendmail 塞额外参数」。

---

## 后来又补了什么（CVE-2016-10045，5.2.20）

```php
            if (self::isShellSafe($this->Sender)) {
                $params = sprintf('-f%s', $this->Sender);
            }
```

```php
    protected static function isShellSafe($string)
    {
        if (escapeshellcmd($string) !== $string
            or !in_array(escapeshellarg($string), array("'$string'", "\"$string\""))
        ) {
            return false;
        }
        for ($i = 0; $i < strlen($string); $i++) {
            $c = $string[$i];
            if (!ctype_alnum($c) && strpos('@_-.', $c) === false) {
                return false;
            }
        }
        return true;
    }
```

含引号、空格、`-X` 的 Sender 直接不传 `-f`。不再依赖「包一层再交给会二次逃逸的 mail()」。建议升到 5.2.20（随后还有 5.2.21+ 的跟进）。项目 wiki：[About the CVE-2016-10033 and CVE-2016-10045 vulnerabilities](https://github.com/PHPMailer/PHPMailer/wiki/About-the-CVE-2016-10033-and-CVE-2016-10045-vulnerabilities)。

---

## 从这条链还能看出什么

**维护者改错了哪一层。**  
他们改的是拼 `$params` 之前的 PHP 字符串。真正切 argv 的是 `mail()` 内部的第二趟逃逸。V2 不再把非白名单字符送进那一趟。

**不是没有更好的谓词。**  
SMTP 发送路径从不经过 shell。`escapeshellcmd` 已用在 Sendmail 二进制上。V1 对 Sender 只做了会被下一层拆掉的包装。从 5.2.17→5.2.18 的 diff 只能看到 `escapeshellarg`；要判断闭合，必须看到 `mail()` 会再跑 `php_escape_shell_cmd`。

**同一 `Sender`、同一 `-f`，只换了引号。**  
任何把用户 From 传进 `setFrom` 且使用 `isMail` 的应用，在 5.2.18 上都吃这套双重逃逸。WordPress / Joomla 当时捆绑的 PHPMailer 也在 NVD 的受影响列表里，入口仍是这条 `isMail` 路径。

**`validateAddress` 不是 shell 谓词。**  
默认 `pcre8` 按 RFC5322 收 quoted-local-part，所以 `"a' -X/canary/out.txt b"@x.com` 能过 `setFrom` 和 `mailSend` 里那两次 `validateAddress`。它回答「像不像邮箱」，不回答「`escapeshellarg` 的输出再经 `php_escape_shell_cmd` 会不会裂开」。V2 的 `isShellSafe` 才是后一个问题的谓词：`escapeshellcmd`/`escapeshellarg` 必须是恒等，且字符 ∈ `[A-Za-z0-9@_-.]+`。

**假 sendmail 只证明 argv 边界。**  
shim 见到独立 `-X<path>` 才拷 flag。body 里出现 `PCBFLAG_...` 表示 `-f` 参数边界被撕开，不是「真的执行了 webshell」。历史上 10033/10045 的公开利用是 `-X/var/www/…/shell.php` 把邮件内容写成 Web 脚本；本 case 把该路径换成金丝雀文件。

**5.2.18 上两个 From 对照。**

```text
# seed（双引号拆词）
From = "a'\" -X/canary/out.txt \"b"@x.com
escapeshellarg → 整段落在一对单引号里
php_escape_shell_cmd → 看不到裸空格 → 一个 argv → 挡

# residual（单引号撕包装）
From = "a' -X/canary/out.txt b"@x.com
escapeshellarg → 内部 ' 变成 '\'' 序列
php_escape_shell_cmd → 闭引号后的 -X 落在未加引号区 → 独立 argv → shim 拷 flag
```

`validateAddress` 两条都过。差别不在 `-X`，在两层逃逸的引号状态。

---

## 版本、入口、参考

| | tag | `-f` 构造 | 双引号 `-X` seed | 单引号 `-X` residual |
|---|---|---|---|---|
| V0 | 5.2.17 | `sprintf('-f%s', Sender)` | `-X` 独立，flag | （不必） |
| V1 | 5.2.18 | `escapeshellarg` + `mail()` 再逃逸 | 包成一词，挡 | 二次逃逸撕开，flag |
| V2 | 5.2.20 | 仅 `isShellSafe` 时传未包装的 `-f` | 挡 | 不传 `-f`，挡 |

- 库 API：`setFrom($from)` + `isMail()` + `send()`
- 本 case HTTP：`GET /send?from=...`
- [CVE-2016-10033](https://nvd.nist.gov/vuln/detail/CVE-2016-10033)、[CVE-2016-10045](https://nvd.nist.gov/vuln/detail/CVE-2016-10045)
- [LegalHackers 10045](https://legalhackers.com/advisories/PHPMailer-Exploit-Remote-Code-Exec-CVE-2016-10045-Vuln-Patch-Bypass.html)
- V1：[class.phpmailer.php @ v5.2.18](https://github.com/PHPMailer/PHPMailer/blob/v5.2.18/class.phpmailer.php)（`mailSend` 约 L1429）
- V2：[v5.2.20](https://github.com/PHPMailer/PHPMailer/blob/v5.2.20/class.phpmailer.php)
