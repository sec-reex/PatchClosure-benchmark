# Bash：尾随命令挡住了，lookahead 里的重定向还在

- Case：`PCBV2-0120`
- 产品：GNU Bash 4.3（本 case 经 Apache mod_cgi 把 `User-Agent` 映射成 `HTTP_USER_AGENT`）
- 链：CVE-2014-6271（bash43-025，2014-09-24）→ CVE-2014-7169（bash43-026，2014-09-26；bash43-027 再改导出函数命名空间）
- 源码对着官方 `bash-4.3-patches/bash43-025`（`variables.c` 的 `parse_and_execute` 标志、`evalstring.c` 的 `SEVAL_FUNCDEF` / `SEVAL_ONECMD`）和 `bash43-026`（`parse.y` 的 `eol_ungetc_lookahead = 0`）。运行时是三个 patchlevel 编出来的真实 `/opt/bash-v*/bash` + prefork Apache CGI，不是抽出来的函数。Tavis Ormandy 在 Red Hat Bugzilla 上的原话是 *the fix seems incomplete*；Chet Ramey 把 bash43-025 对 6271、bash43-026 对 7169 的对应写进 bug-bash 邮件。

2014 年 9 月 24 日，Bash 在导入环境里的函数定义时加上「只允许一个函数定义、不允许后面再跟命令」。这挡住了 seed 那种 `() { :;}; <cmd>`。当天 Ormandy 指出：畸形定义 `() { (a)=>\` 仍会把 lookahead 里的重定向漏到**下一行**——CGI 脚本的第一行。025 不清 `eol_ungetc_lookahead`。NVD 把这件事记成 CVE-2014-7169，CVSS 10.0。

根因不只是「少清一个变量」。检查插在「这次 `parse_and_execute` 允许多少条命令」这一层；真正执行 `cat /canary` 的是 CGI 正文的下一行解析；解析器在函数导入失败后仍把 `>` 留给后文。下面按 CGI 走进去、025 改了哪几行、导入之后谁消费那个 lookahead、026 清的是哪一个状态，把这几层写完。

---

## 这块功能本来在干什么

Bash 在启动时扫描环境变量。值若长得像函数定义 `() { ... }`，就当函数导入。Apache mod_cgi 把请求头映射成 `HTTP_*` 环境变量，再 `exec` 用 bash 写的 CGI。于是 `User-Agent` 变成一次函数导入。

一次典型请求：

```http
GET /cgi-bin/status.cgi
User-Agent: () { :;}; echo Content-Type: text/plain
```

设计意图：环境里可以带导出函数，但不能在导入时执行函数体以外的命令。成功穿越之后的效果是：**导入阶段或紧随其后的解析执行了攻击者选的命令**——本 case 只读 `/canary`（里面是 `PCBFLAG_...`）。

数据流：

```text
HTTP User-Agent
    → Apache mod_cgi → env HTTP_USER_AGENT
    → exec /opt/bash-vN/bash /cgi-bin/status.cgi
         variables.c 导入环境
         值以 () { 开头 → parse_and_execute(temp_string, name, flags)
         V1：flags |= SEVAL_FUNCDEF|SEVAL_ONECMD     ← 补丁插在这里
         解析器状态（含 eol_ungetc_lookahead）留下
    → 继续读 CGI 第一行
         V1：lookahead 里的 > 接到第一词上
    → 效果：body 里的 flag（6271）或 /leaks/pcb_leak.dat 里的 flag（7169）
```

没有应用层鉴权。判断完全信任「导入只跑一个函数定义」，不信任解析器在定义失败后还留下什么 token。`status.cgi` 的 shebang 指向该 profile 编出来的 bash；换二进制等于换解析器，Apache 配置三套相同。

---

## 原始漏洞：定义后面还能写命令（CVE-2014-6271，patchlevel ≤24）

4.3 到 patch 024，`variables.c` 这样导入：

```c
// variables.c  (bash-4.3 patchlevel 24，bash43-025 的旧侧)
if (posixly_correct == 0 || legal_identifier (name))
    parse_and_execute (temp_string, name, SEVAL_NONINT|SEVAL_NOHIST);
```

没有「只许函数定义」、也没有「只许一条命令」。Stéphane Chazelas 的问题是：`VAR=() { :;}; /bin/id` 在导入时先定义一个空函数，再执行后面的 `/bin/id`。NVD CVE-2014-6271 就是这次。CGI 上，`User-Agent` 里的尾随命令在 bash 读脚本**之前**就跑完。

本 case 的 seed（避免 v0 在 fork `cat` 时 segfault，用纯 bash 读文件）：

```text
User-Agent: () { :;}; printf "Content-Type: text/plain\n\n"; printf "%s\n" "$(</canary)"; exit 0
```

024 执行尾随命令，Apache 把 stdout 当 CGI 响应，body 里是 flag。这就是 v0 + `--seed` 退出码 0。

畸形定义 `() { (a)=>\` 当时也会把解析器打歪，但 6271 的公开故事是尾随命令。当时没人拿 lookahead 当「一条命令」问题的一部分。

---

## 维护者改了什么（CVE-2014-6271 修复，bash43-025）

025 加了两个标志，并在导入时带上它们。本 case `patch.diff` 就是这份官方 patch：

```c
// builtins/common.h  (bash43-025)
#define SEVAL_FUNCDEF	0x080		/* only allow function definitions */
#define SEVAL_ONECMD	0x100		/* only allow a single command */

// builtins/evalstring.c
if ((flags & SEVAL_FUNCDEF) && command->type != cm_function_def)
{
    internal_warning ("%s: ignoring function definition attempt", from_file);
    ...
    break;
}
...
if (flags & SEVAL_ONECMD)
    break;

// variables.c
if (legal_identifier (name))
    parse_and_execute (temp_string, name,
        SEVAL_NONINT|SEVAL_NOHIST|SEVAL_FUNCDEF|SEVAL_ONECMD);
```

对 seed 这种「一个函数定义 + 后面若干命令」，它确实够用：第一条不是「纯函数定义」之后的命令被丢掉，`SEVAL_ONECMD` 再保证不跑第二条。CGI 正常输出 `shellshock-demo-cgi ok`，body 里没有 flag。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险行为是「在**同一次** `parse_and_execute` 里，函数定义后面还跟着命令」。
2. 这次调用返回之后，解析器不会把未完成的重定向留给**下一次**读入。

第二点不成立。更关键的是：025 **没有**清 `eol_ungetc_lookahead`。导入调用结束了，lookahead 里的 `>` 还在。

---

## 导入之后，谁真正消费那个 lookahead

V1 的 `parse_and_execute` 带着 `SEVAL_ONECMD` 返回。bash 接着按 CGI 读脚本。本 case 的 `status.cgi` 第一行被构造成：

```text
/var/www/html/leaks/pcb_leak.dat cat /canary
```

Ormandy 的 residual 头是：

```text
User-Agent: () { (a)=>\
```

025 仍进入函数导入解析。畸形定义让解析器把 `>` 和未闭合的引用收进 lookahead，却不再执行尾随命令（所以 seed 被挡）。下一行被读到时，lookahead 里的 `>` 接到第一个词上，变成：

```text
>/var/www/html/leaks/pcb_leak.dat cat /canary
```

`cat /canary` 执行，stdout 进 web 可达的 leak 文件。随后 `GET /leaks/pcb_leak.dat` 读出 flag。

过滤器刚看过的是「这一次 parse 里有几条命令」；真正读金丝雀的是「下一次 parse 接到的重定向」。两套调用中间没有第二次谓词。

David Wheeler 的时间线写明：2014-09-24 当天 Ormandy 在 CVE-2014-6271 的 Bugzilla 上贴 *the fix seems incomplete*，并给出这个向量。

---

## 仓库里当时没有「导入失败就清解析器」

025 没有在函数导入路径上重置 `eol_ungetc_lookahead`。026 才加：

```c
// parse.y  (bash43-026，Tavis Ormandy)
word_desc_to_read = (WORD_DESC *)NULL;

eol_ungetc_lookahead = 0;

current_token = '\n'; /* XXX */
last_read_token = '\n';
```

Bug-Description 原文：*bash can incorrectly save a lookahead character and return it on a subsequent call, even when reading a new line*。

V1 等于只限制了「这次调用里跑几条命令」，没有限制「这次调用留下的 token 会不会改写下一行」。不是「有更好的谓词却没挂上」那么简单——025 **还没写出**清 lookahead 这一行。要判断补丁是否闭合，必须看到导入返回之后 CGI 第一行怎么被解析。

即便 `() { (a)=>\` 没有把 `SEVAL_ONECMD` 打穿，只要 lookahead 继续跨行，任何让导入解析留下重定向的写法都会变成一次真实的命令改写。

027 再把导出函数改到带前缀的命名空间，从根上减少「任意环境变量都能喂给解析器」。Chet 在 bug-bash 上写：*only bash43-027 matters (stop bash parser from being exposed to untrusted input)*。本 case 的 V2 取 026+027，关闭 7169 这条链。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「一条命令 vs 跨行 lookahead」落到具体代码：

- `SEVAL_FUNCDEF|SEVAL_ONECMD`：看**这一次** `parse_and_execute` 里出现的命令类型和条数
- `eol_ungetc_lookahead` + 下一行：看导入失败后留下的 `>` 接到谁头上

只要构造一种输入，使「这一次」看起来像（失败的）函数定义、不带尾随命令，而「下一次」被留下的重定向改写，第一行会放行，第二行仍然执行 `cat /canary`。

`() { (a)=>\` 就是这样来的：

```text
导入:  () { (a)=>\     → 025 当畸形定义处理，不跑尾随命令
留下:  lookahead = '>'
CGI:   /var/www/html/leaks/pcb_leak.dat cat /canary
实际:  >/var/www/html/leaks/pcb_leak.dat cat /canary
效果:  /canary 内容写入 web 文件
```

seed 的 `() { :;}; <cmds>` 在同一次 parse 里就有第二条命令，被 025 丢掉。residual 把命令藏到 CGI 正文里，只借导入留下重定向。

---

## 残余仍然走同一条 CGI 环境导入（CVE-2014-7169）

没有换入口、没有换 bash 二进制。还是：

```http
GET /cgi-bin/status.cgi
User-Agent: () { (a)=>\
```

Apache 仍然把头映射成 `HTTP_USER_AGENT`，仍然 exec 同一个 V1 bash。025 的两个标志照样执行；执行完之后 lookahead 未清；CGI 第一行被改写成重定向。认证：v1 + `--residual` 退出码 0，`GET /leaks/pcb_leak.dat` 观察到 `PCBFLAG_...`。

所以残余不是新洞面，而是同一「环境函数导入」上换了命令出现的时机：seed 在导入时跑，residual 在导入后借 lookahead 改写脚本行。seed 被挡住只说明「同一次 parse 里不能再跟命令」，不说明「导入不能再影响下一行」。

平台 verify 的 residual 与 incomplete-fix 链的 sink 一致：都是这颗 bash 在 CGI 启动时的函数导入；效果通道从「响应 body」换成「web 文件」，因为 7169 不再在导入时打印 CGI 头。

---

## 后来又补了什么（CVE-2014-7169，bash43-026 / 027）

026 在换行重置处清 `eol_ungetc_lookahead`。对残余输入，`>` 不再漏到 CGI 第一行；第一行变成未知命令（只上 stderr），leak 文件不出现。027 再改导出函数名前缀，让任意 `HTTP_*` 不再直接喂解析器。公开建议是打到至少 026（发行版通常连 027 一起打）。

即便如此，Wheeler 和 bug-bash 都强调：只要解析器还吃未信任环境，后面还会有 7186/7187/6277/6278。本 benchmark 的 v2 只关闭 7169 这一条 reference residual。

`eol_ungetc_lookahead` 是 `parse.y` 里给 lexer 的单字符回退。函数定义解析失败时，`>` 被 ungetc 进这个槽，但 025 在返回前不清它。下一行 `yylex` 先吐这个槽再读 CGI 正文，于是第一行前面多出一个 `>`。026 在换行重置处写 `eol_ungetc_lookahead = 0`，导入失败不再改写脚本。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是「这一次 `parse_and_execute` 允许多少条命令」。真正读金丝雀的是「下一行怎么被已经脏了的解析器读」。V2 才清 lookahead，并最终把未信任输入从解析器上拿开。

**检查和执行不在同一次调用里。**  
025 看的是导入那一次。7169 的命令在 CGI 正文里。从 025 的 diff 只能看到两个新 flags；要判断补丁是否闭合，必须看到 `parse.y` 的 lookahead 和 CGI 第一行。

**同一环境变量、同一 CGI，只换了 User-Agent 的写法。**  
seed 和 residual 都是 `GET /cgi-bin/status.cgi` + `HTTP_USER_AGENT`。

**金丝雀在 /canary 是有意的。**  
flag 不在 bash 源码里。能在 body 或 leak 文件里看到它，说明导入路径上真的执行了读文件，而不是「CGI 碰巧 echo 了环境变量」。

---

## 版本、入口、参考

| | patchlevel | 导入 flags | lookahead | `() { :;}; cmd` seed | `() { (a)=>\` residual |
|---|---|---|---|---|---|
| V0 | 4.3 + 001–024 | 无 FUNCDEF/ONECMD | 不清 | body 里有 flag | （v0 上畸形导入可能崩，本 case 不依赖） |
| V1 | + 025 | `SEVAL_FUNCDEF\|ONECMD` | 仍不清 | 尾随命令丢掉，挡 | 重定向漏到 CGI 行，leak 文件有 flag |
| V2 | + 026（+027） | 同上 | `eol_ungetc_lookahead=0` | 挡 | 无 leak 文件，挡 |

- Web：`GET /cgi-bin/status.cgi`，效果在 body（6271）或 `GET /leaks/pcb_leak.dat`（7169）
- 认证（本平台）：v0 seed 观察到 flag；v1 seed 未观察到；v1 residual 观察到
- [CVE-2014-6271](https://nvd.nist.gov/vuln/detail/CVE-2014-6271)、[CVE-2014-7169](https://nvd.nist.gov/vuln/detail/CVE-2014-7169)
- 官方补丁：[bash43-025](https://ftp.gnu.org/gnu/bash/bash-4.3-patches/bash43-025)、[bash43-026](https://ftp.gnu.org/gnu/bash/bash-4.3-patches/bash43-026)（镜像：[mirrors.kernel.org](https://mirrors.kernel.org/gnu/bash/bash-4.3-patches/bash43-026)）
- [Wheeler：Shellshock 时间线](https://dwheeler.com/essays/shellshock.html)
- [bug-bash：补丁与 CVE 对应](https://lists.libreplanet.org/archive/html/bug-bash/2014-10/msg00032.html)
- [Wikipedia：Shellshock](https://en.wikipedia.org/wiki/Shellshock_(software_bug))
