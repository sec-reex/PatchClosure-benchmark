# Pheditor：终端 denylist 补了 `$`，单管道 / 反引号 / 换行仍进 shell_exec

- Case：`PCBV2-0167`
- 产品：Pheditor（单文件 PHP 编辑器）。运行时是 git tag 在 `php:8.2-apache` 上的整份 `pheditor.php`，入口是已登录（默认口令）的 terminal POST。
- 链：CVE-2026-54540 / GHSA-9643-6xjp-vx57（2.0.3 → 2.0.5，denylist 加上 `$`，`cd` 的 `$dir` 改 `escapeshellarg`）→ CVE-2026-55578 / GHSA-wg4w-wr5q-6vjc（2.0.5 → 2.0.6，再禁 `|`、`` ` ``、`\n`、`\r`）。advisory 原文：*This is a bypass of the partial fix for GHSA-9643-6xjp-vx57 — that fix addressed `$()` substitution but three additional shell metacharacters remain unblocked*。
- 源码对着 tag `2.0.5` 的 `pheditor.php` `case 'terminal'`。V0 是 `2.0.3`。V2 是 `2.0.6`。

说明：仓库里的 `patch.diff` 只展示了 `escapeshellarg($dir)` 那一行（commit `62b43df`）。**真正挡住 seed 的是同一版本里 denylist 新增的 `$`**。下面以 tag 上的完整函数为准，不以 diff  hunk 当唯一事实。

根因不只是「黑名单又漏了一个字符」。检查插在「command 字符串里有没有某几个子串」以及「是不是以 TERMINAL_COMMANDS 里某个名字开头」上；真正执行的是后面那次 `shell_exec('cd ' . escapeshellarg($dir) . ' && ' . $command)`。`$dir` 已经用了更强的 `escapeshellarg`，`$command` 没有。下面按 POST 走进去。

---

## 这块功能本来在干什么

Pheditor 给已授权用户一个网页终端。`PERMISSIONS` 默认含 `terminal`。一次典型请求：

```http
POST /pheditor.php
Cookie: <登录>
command=echo $(cat /flag)&dir=/var/www/html
```

handler 读 `$_POST['command']` 和 `$_POST['dir']`。设计意图：只能跑 `TERMINAL_COMMANDS` 白名单里的程序（`ls`、`echo` 等），且不能用 shell 元字符拼第二段命令。成功穿越之后的效果是 **web 用户身份执行任意命令**，本 case 读容器根上、DocumentRoot 之外的 `/flag`，JSON 响应里出现 `PCBFLAG_...`。

数据流：

```text
POST command + dir
    → case 'terminal'
         denylist: strpos 若干元字符          ← V1 谓词
         前缀 ∈ explode(',', TERMINAL_COMMANDS)
         shell_exec('cd ' . escapeshellarg($dir) . ' && ' . $command . ' && echo ; pwd')
    → JSON output（htmlspecialchars 之后）
```

默认密码是 `admin`。终端权限默认开。白名单只检查 **前缀相等**，不切 argv。

---

## 原始漏洞：`$()` 不在黑名单里（CVE-2026-54540，2.0.3）

V0 的 denylist：

```php
// pheditor.php  (2.0.3, 约 L526)
if (strpos($command, '&') !== false || strpos($command, ';') !== false || strpos($command, '||') !== false) {
    echo json_error("Illegal character(s) in command (& ; ||)\n");
    exit;
}
```

没有 `$`。`echo $(cat /flag)` 以 `echo` 开头，过白名单。`shell_exec` 让 bash 先跑命令替换，再 echo。响应里是 flag。这就是 v0 + `--seed`。

`shell_exec` 的完整脚本永远是 `cd … && <command> && echo  ; pwd`。末尾的 `pwd` 用来更新前端当前目录，`echo` 当分隔。注入发生在中间的 `$command`，不需要打破这段固定尾巴。`&&` 要求前面命令成功；`echo $(cat /flag)` 的退出码是 echo 的，通常为 0，尾巴照跑。管道 residual `ls | cat /flag` 的退出码是 `cat` 的。

同一版本 `cd` 拼的是未加引号的 `$dir`（`patch.diff` 那一行）；那是另一条注入。seed 走的是 command 里的 `$()`，不依赖 dir。

---

## 维护者改了什么（GHSA-9643，2.0.5）

V1 两处：

```php
// pheditor.php  (2.0.5, 约 L526–555)
if (strpos($command, '&') !== false || strpos($command, ';') !== false
    || strpos($command, '||') !== false || strpos($command, '$') !== false) {
    echo json_error("Illegal character(s) in command (& ; ||)\n");
    exit;
}
...
$output = shell_exec((empty($dir) ? null : 'cd ' . escapeshellarg($dir) . ' && ') . $command . ' && echo \ ; pwd');
```

`$` 让 `$(cat /flag)` 和 `${…}` 直接失败。错误信息甚至没改，还写着 `(& ; ||)`。对 seed：

```text
echo $(cat /flag)  →  strpos($) 命中 → json_error，不调用 shell_exec
```

这就是 v1 + `--seed` 退出码 10。`escapeshellarg($dir)` 让 dir 不能再拆 `cd` 语句。

补丁默认了两件事：

1. 危险元字符就是 `&` `;` `||` `$`。
2. 白名单前缀 + 这段 denylist 之后，把 `$command` 原样接到 `&&` 后面是安全的。

第二点不成立。shell 还有 `|`（注意 denylist 写的是 `||` 不是 `|`）、反引号、换行。

---

## 消毒之后，command 怎么接到 shell 上

denylist 和前缀检查一过，同一分支立刻：

```php
$output = shell_exec((empty($dir) ? null : 'cd ' . escapeshellarg($dir) . ' && ') . $command . ' && echo \ ; pwd');
```

`$dir` 经过 `escapeshellarg`；`$command` **零转义**。过滤器看的是若干 `strpos`；`/bin/sh -c` 看的是完整脚本。中间没有 `escapeshellarg($command)`，也没有 `proc_open` 的 argv 数组。

白名单：

```php
if (strlen($command) >= strlen($value) && substr($command, 0, strlen($value)) == $value) {
    $command_found = true;
```

`ls | cat /flag` 的前缀是 `ls`，合法。`echo \`cat /flag\`` 前缀是 `echo`。`ls\ncat /flag` 第一行是 `ls`。三条都满足「以允许的名字开头」。

---

## 仓库里已经有更强的检查，command 没用

| 谓词 | 用在哪 |
|---|---|
| `escapeshellarg` | V1 起的 `$dir` |
| `PATTERN_FILES` / 路径 `../` 检查 | 读文件、上传，不经过 terminal |
| `TERMINAL_COMMANDS` | 仅前缀 |
| denylist | command 上的若干子串 |
| `proc_open` + argv | **无** |

不是 PHP 里没有把参数当数据传给 exec 的 API，是 **terminal 坚持 `shell_exec` 一整句，只在字符串上做 denylist**。dir 已经用了更强谓词，command 没有对齐。GHSA-wg4w 建议的长期修法正是：解析出可执行文件、精确匹配、参数 `escapeshellarg` 或 `proc_open`。

读文件功能走另一条 `case`：路径要落在 `MAIN_DIR` 下，并 `strpos(..., '../')`。terminal 的 `$command` 不经过那些检查，所以 `cat /flag` 这种绝对路径对读文件 API 非法，对 `shell_exec` 合法。金丝雀放在 DocumentRoot 之外，就是为了证明效果来自命令注入，不是「编辑器打开了某个项目文件」。

默认 `PERMISSIONS` 含 `terminal`，默认密码 `admin`。advisory 写 *authenticated user with the terminal permission (enabled by default)*。本 case 登录之后打 POST，不额外改权限位。

---

## 这个补丁挡住了什么、没挡住什么

- V1 denylist：有没有 `&` `;` `||` `$`
- `shell_exec`：sh 怎么切管道、替换、换行

`$()` 被第一层挡住。三条公开 bypass 都满足「以白名单命令打头」，只是元字符不同：

**单管道 `|`。** denylist 写的是 `||`（或运算），`strpos($command, '||')` 对 `ls | cat /flag` 为假。`substr($command, 0, 2) == 'ls'` 为真。拼出来：

```text
cd '/var/www/html' && ls | cat /flag && echo  ; pwd
```

sh 把 `cat /flag` 接到 `ls` 的 stdout。JSON 里出现 flag 行。这是本 case 平台 residual 用的那条。

**反引号。** `$` 被禁了，`` ` `` 没有。`echo `cat /flag`` 前缀是 `echo`。命令替换在 echo 之前执行，输出同样进 JSON。`$()` 和反引号在 POSIX 里是同一类替换，V1 只禁了前者。

**换行 `0x0A`。** 白名单用 `substr($command, 0, strlen($value))`，只看**整个 POST 字符串的开头**，不按行切。`ls\ncat /flag` 仍以 `ls` 开头。`shell_exec` 把换行交给 sh 当语句分隔，第二行是独立的 `cat /flag`。`;` 在 denylist 里，换行不在——这是用另一种语句分隔符绕过对 `;` 的禁止。

`htmlspecialchars` 只包在 `$output` 回显上，发生在 `shell_exec` **之后**，挡不住读 `/flag`，只影响 XSS。`set_time_limit(15)` 也不改变命令语义。

输出处理会 `explode("\n")`、把最后一行当新的 `dir`（因为尾巴是 `pwd`）。`cat /flag` 的输出若不含额外换行，flag 就在 JSON 的 `output` 字段里；若有多行，最后一行可能被当成目录名剥掉——单行金丝雀不会。这是展示层，不是安全谓词。

---

## 残余仍然走同一条 terminal POST（CVE-2026-55578）

没有换 action、没有换权限位。还是 `command` + `dir`。payload 形如 `ls | cat /flag`（或 `` echo `cat /flag` `` / `ls\ncat /flag`）。V1 的 `$` 检查不命中；`shell_exec` 跑第二条命令；JSON 里出现金丝雀。seed 被挡住只说明「美元替换没了」，不说明「不能再从终端读 `/flag`」。

---

## 后来又补了什么（CVE-2026-55578，2.0.6）

```php
// 2.0.6
if (strpos($command, '&') !== false || strpos($command, ';') !== false
    || strpos($command, '|') !== false || strpos($command, '$') !== false
    || strpos($command, '`') !== false || strpos($command, "\n") !== false
    || strpos($command, "\r") !== false) {
```

`|` 同时盖住单管道和 `||`。三条公开 bypass 都挡。仍是 denylist + `shell_exec`。建议升到 2.0.6；长期仍应丢掉 shell 字符串拼接。

---

## 从这条链还能看出什么

**维护者改错了哪一层。**  
他们改的是 command 里禁止哪些字符。真正执行任意程序的是 `shell_exec` 对用户字符串的解释。dir 已经升到 `escapeshellarg`，command 停在黑名单。

**不是没有更好的谓词。**  
同一次 2.0.5 修丁证明作者知道 `escapeshellarg`。它只包了 dir。从 `patch.diff` 若只看到 dir，会误判 seed 为何在 V1 失败——必须读 2.0.5 完整 terminal 分支里的 `$`。

**同一 POST、同一 `$command`，只换元字符。**  
任何以白名单命令打头的字符串，在 2.0.5 上都吃这张 denylist。

**白名单是前缀，不是 argv[0]。**  
`TERMINAL_COMMANDS` 被 `explode` 成名字列表，匹配条件是 `substr($command, 0, strlen($value)) == $value`。它不拒绝后面的管道、替换或第二行。V2 仍靠加长 denylist 来堵，没有改成「第一个 token 精确等于允许的可执行文件」。

**错误信息和谓词不一致。**  
V1 已经禁 `$`，json_error 仍写 `Illegal character(s) in command (& ; ||)`。这不影响正确性，但说明修丁是在原 strpos 链上追加字符，没有重写执行模型。

**`patch.diff` 不能当 V1 的完整画像。**  
ROUND7 迁上来的 hunk 是 `escapeshellarg($dir)`。seed `echo $(cat /flag)` 不依赖 dir。若只根据 diff 推断「V1 修的是 cd 注入」，会找错 residual。必须以 tag `2.0.5` 的 terminal 分支为准：挡住 seed 的是 `$`，放行 residual 的是仍未列入的 `|` / `` ` `` / `\n`。

**2.0.5 上两条 command 对照。**

```text
echo $(cat /flag)
  denylist: strpos('$') 命中 → 退出，不 exec

ls | cat /flag
  denylist: 无 & 无 ; 无 || 无 $ → 过
  白名单: substr(..., 0, 2) == 'ls' → 过
  shell: cd '…' && ls | cat /flag && echo  ; pwd
       → cat 读 /flag → JSON output 含 PCBFLAG_…
```

`$()` 和 `|` 对 shell 都是「在白名单命令之外再跑一条」。V1 只把第一种从字符串里划掉。2.0.4 若存在，介于 2.0.3 与 2.0.5 之间；本 case V1 钉的是 2.0.5，以该 tag 的 denylist 为准。

---

## 版本、入口、参考

| | tag | denylist | `$dir` | `echo $(cat /flag)` | `ls \| cat /flag` |
|---|---|---|---|---|---|
| V0 | 2.0.3 | `& ; \|\|` | 未转义 | 读到 `/flag` | （不必） |
| V1 | 2.0.5 | 加上 `$` | `escapeshellarg` | json_error | 读到 `/flag` |
| V2 | 2.0.6 | 再加 `\|` `` ` `` `\\n` `\\r` | 同上 | 挡 | 挡 |

- HTTP：登录后 POST `command` / `dir` 到 `pheditor.php`（action=terminal）
- [GHSA-9643-6xjp-vx57](https://github.com/advisories/GHSA-9643-6xjp-vx57)、[GHSA-wg4w-wr5q-6vjc](https://github.com/pheditor/pheditor/security/advisories/GHSA-wg4w-wr5q-6vjc)
- [CVE-2026-55578](https://nvd.nist.gov/vuln/detail/CVE-2026-55578)
- V1：[pheditor.php @ 2.0.5](https://github.com/pheditor/pheditor/blob/2.0.5/pheditor.php)（约 L513–555）
- V2：[pheditor.php @ 2.0.6](https://github.com/pheditor/pheditor/blob/2.0.6/pheditor.php)
