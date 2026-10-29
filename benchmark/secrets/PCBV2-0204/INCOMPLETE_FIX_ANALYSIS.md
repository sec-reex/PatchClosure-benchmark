# SuiteCRM：ModuleScanner 认了带引号的函数名，单字符 token 却把状态清掉

- Case：`PCBV2-0204`
- 产品：SuiteCRM（salesagility/SuiteCRM）。运行时是 git tag 整树 + php:8.1-apache + MySQL，经后台 Module Loader 上传 MLP；不是抽出来的 tokenizer。
- 链：CVE-2024-49774（7.14.5 → 7.15.0 / 先合进 7.14.6）→ CVE-2026-29103（7.15.0 → 7.15.1，GHSA-5jjq-9qch-9rg7）
- 源码对着 tag `v7.15.0` 的 `ModuleInstall/ModuleScanner.php::scanFile`。金丝雀是 benign：`post_execute` 读 `/tmp/pcb_canary.txt`，写到 web 根 `pcb_marker_*.txt`。

GHSA-5jjq-9qch-9rg7 原话：*This vulnerability is a direct Patch Bypass of CVE-2024-49774.* *The scanner incorrectly resets its internal state ($checkFunction flag) when encountering any single-character token (such as =, ., or ;).* 根因不只是「漏了一种字符串写法」。检查插在 `token_get_all` 的线性状态机上；真正执行 PHP 的是扫描通过之后的 `ModuleInstaller`。下面按后台请求走进去。

---

## 这块功能本来在干什么

SuiteCRM 给管理员提供 Module Loader：上传 zip（MLP），扫描 PHP，通过后解包、跑 `manifest.php` 里的 `post_execute`。设计意图：黑名单函数（`file_get_contents`、`system`、`eval`…）不能出现在待装模块里。扫描通过 = 允许这段 PHP 在安装期以 web 用户身份执行。

一次典型请求（需管理员会话）：

```http
POST /index.php?module=Administration&view=module&action=UpgradeWizard&run=upload
Content-Type: multipart/form-data
... upgrade_zip = module.zip ...

POST /index.php  (HandleAjaxCall, performInstall, 带文件 hash)
```

`ModuleScanner::scanPackage` 先 `scanManifest`，再 `scanDir` → 每个 PHP `scanFile`。没有 issue 才进入 `ModuleInstaller::install()`，其中会 include `post_execute` 脚本。

数据流：

```text
管理员上传 MLP zip
    → UpgradeWizard run=upload
    → ModuleScanner.scanPackage
         scanManifest(manifest.php)     ← 先扫清单，恶意代码则根本不 include
         scanDir → scanFile
              token_get_all($contents)
              V1：T_STRING 与 T_CONSTANT_ENCAPSED_STRING 都进黑名单
                  单字符 token 把 $checkFunction 置 false     ← 补丁没动这里
         有 issue → 拒绝安装，页面 ML_INVALID_FUNCTION
         无 issue → ModuleInstaller.install
              跑 installdefs.post_execute                    ← 真正执行用户 PHP
              读 /tmp/pcb_canary.txt，写 web 根 marker
    → GET /pcb_marker_*.txt  → body 里 PCBFLAG_...
```

需要管理员。`.htaccess` 禁止直接访问 `/modules/` 下 PHP，所以效果通道是安装期 `post_execute`，不是事后 GET 一个模块文件。成功穿越 = **黑名单函数在安装时跑起来**。

---

## 原始漏洞：带引号的函数名不是 T_STRING（CVE-2024-49774，7.14.5）

7.14.5 的 `scanFile` 用 `token_get_all`。PHP 里 `'file_get_contents'(...)` 的函数名 token 是 `T_CONSTANT_ENCAPSED_STRING`，不是 `T_STRING`。V0 的函数名分支基本上只认真名 `T_STRING`，引号包起来的可调用名不进黑名单比较。

GHSA-9v56-vhp4-x227：*SuiteCRM uses token_get_all to parse PHP scripts and check the resulted AST against blacklists. But it doesn't take into account all scenarios.* 说是 AST，实现其实是 token 流。seed 用：

```php
'file_get_contents'('/tmp/pcb_canary.txt')
```

扫描器当普通字符串放过；安装期 PHP 把它当可调用名执行，读金丝雀，写出 marker。这就是 v0 + seed。

NVD 记修复版本为 7.14.6 / 8.7.1。本 case V1 取 7.15.0，已经带上这次修补。

---

## 维护者改了什么（CVE-2024-49774 修复，7.15.0 仍是 token 机）

7.15.0 的 `scanFile` 把 `T_CONSTANT_ENCAPSED_STRING` 和 `T_STRING` 放进同一条 `switch`，去掉引号再查 `blackList`：

```php
// ModuleScanner.php::scanFile   tag v7.15.0
case T_STRING:
case T_CONSTANT_ENCAPSED_STRING:
    $token[1] = trim(strtolower($token[1]), '\'"');
    if ($lastToken !== false && $lastToken[0] == T_NEW) {
        // 类黑名单
        ...
    } else {
        if (!in_array($token[1], $this->blackList)) {
            break;
        }
        ...
    }
    // no break
case T_VARIABLE:
    $checkFunction = true;
    $possibleIssue = ... $token[1] . '()';
    break;
```

命中黑名单后不立刻报错，而是把 `$checkFunction = true`，等后面看到 `(` 或 `]` 再记 issue。seed 的 `'file_get_contents'` 现在会进黑名单，下一个 `(` 触发 `ML_INVALID_FUNCTION`。安装被拒。这就是 v1 + `--seed`。

补丁默认了两件事：

1. 危险调用长得像「一个 token 里完整出现函数名」，外加可选引号。
2. 这个名字和 `(` 之间，状态机不会把 `$checkFunction` 清掉。

第二点不成立。同一次循环里，**任何单字符 token** 都会把状态清零。

---

## 扫描通过之后，谁执行这些字节

`scanFile` 返回空数组之后，`scanPackage` 认为包干净。`ModuleInstaller` 按 `installdefs` 拷文件、跑 hook。`post_execute` 是普通 PHP include，**不再走 tokenizer**。PHP 引擎按语言真正的语法求值：字符串拼接的结果可以当函数名调用。

过滤器刚看过的是 token 流上的「当前是不是黑名单单词 + 后面是不是 `(`」；include 看到的是已经拼好的可调用名。两套语义中间没有第二次谓词。

黑名单本身已经包含 `file_get_contents`。V1 不是「忘了把这个函数列入名单」，是名单只挂在「单个 token 恰好等于函数名」这一层上。

---

## 仓库里已经有更强的结构，线性扫描没用上

同一份 `ModuleScanner` 里已经有：

| 谓词 | 作用 | 谁调用 |
|---|---|---|
| `$this->blackList`（含 `file_get_contents`） | 禁止这些函数名 | token 状态机，要求名字落在一个 token 里 |
| `normalizePath` 拒绝 `..` | 拷贝路径穿越 | `scanCopy`，不扫 PHP |
| `isPHPFile` / `isValidExtension` | 是否当 PHP 扫 | 扩展名与 `<?php` |
| （V2 才有）`PhpParser` AST | 按调用表达式认名字 | 7.15.1 `scanFileAST` |

V1 等于在 token 流上把引号字符串也当成候选函数名（比 V0 强一点），但识别「这是一次调用」仍然靠 `$checkFunction` + 下一个 `(`。PHP 手册里 `token_get_all` 对单字符运算符返回**字符串**（`'.'`、`'='`、`';'`），走 `is_string($token[0])` 分支：

```php
if (is_string($token[0])) {
    switch ($token[0]) {
        case '`':  ...
        case '(':
            if ($checkFunction) { $issues[] = $possibleIssue; }
            break;
        case ']':
            if ($checkFunction) { $issues[] = $possibleIssue; }
    }
    if ($return && $checkFunction) { $issues[] = $possibleIssue; }
    $checkFunction = false;   // 任意单字符都清状态
    $possibleIssue = '';
}
```

`.` 会清状态。维护者若要用和 PHP 同一套结构，应当在 AST 的 `FuncCall` 节点上看名字（可以是拼接、变量、括号表达式）。这份黑名单已经在手里，只是挂错层。V2 换成 `nikic/php-parser` 就是把谓词接到那一层。

---

## 这个补丁挡住了什么、没挡住什么

- V1 状态机：看「某一个 T_STRING / T_CONSTANT_ENCAPSED_STRING 去掉引号后是否在黑名单，且之后在状态被清掉之前遇到 `(`」
- PHP 引擎：看求值后的可调用名是什么

seed `'file_get_contents'(...)`：一个 token 就是完整函数名，`(` 紧跟，V1 挡住。

拼接把名字拆开：

```php
('file_get'.'_contents')('/tmp/pcb_canary.txt')
```

token 流大致是：`(`、`'file_get'`、`.`、`'_contents'`、`)`、`(`、…。`'file_get'` 不在黑名单；`.` 是单字符，`$checkFunction = false`；`'_contents'` 也不在黑名单。扫描器无 issue。安装期 PHP 拼出 `file_get_contents` 并调用。GHSA 举的 `system` / `exec` 同理；本 case 用读文件当金丝雀，sink 仍是「黑名单函数被执行」。

---

## 残余仍然走同一条 Module Loader 安装路径（CVE-2026-29103）

没有换入口、没有换 `post_execute`、没有换 marker 文件。还是管理员上传 MLP → `scanFile` → 安装期 include。差别只是 PHP 写法：引号整词换成拼接。NVD / GHSA 明确写 *direct Patch Bypass*，受影响含 7.15.0。

平台 residual 若用 `('file_get'.'_contents')(...)` 打同一 `post_execute` 读金丝雀，和 advisory 的「用拼接藏危险调用」是同一 sink。不是另起一个 RCE 面。

把 V1 循环对着拼接走一遍（忽略空白 token，`T_WHITESPACE` 不更新 `$lastToken`，也不清 `$checkFunction`——清状态的是**字符串 token**）：

```text
(                  单字符：switch 无 '(' 之外的命中后，$checkFunction=false
T_CONSTANT_ENCAPSED_STRING 'file_get'
    trim/lowercase → file_get
    不在 blackList → break（进不了 T_VARIABLE 的 $checkFunction=true）
.                  单字符：再次 $checkFunction=false
T_CONSTANT_ENCAPSED_STRING '_contents'
    → contents     不在 blackList
)                  单字符：清状态
(                  $checkFunction 仍是 false，不记 issue
...
```

对比 seed `'file_get_contents'(`：

```text
T_CONSTANT_ENCAPSED_STRING 'file_get_contents'
    → file_get_contents  在 blackList
    fall-through T_VARIABLE：$checkFunction=true
(  单字符 case '('：记 ML_INVALID_FUNCTION
```

`$this->blackList` 在 7.15.0 里已经包含 `file_get_contents`、`system`、`exec`、`eval`、反引号相关路径。GHSA-5jjq-9qch-9rg7 举的 `system()` / `exec()` 只是同一状态机上换一个黑名单词；本 case 用读文件当金丝雀，是为了让「扫描器认为没有调用、安装期 PHP 认为有调用」能在 HTTP marker 里被观察到，而不是换一个 sink。

`scanManifest` 会先对 `manifest.php` 跑同一 `scanFile`。若清单本身带拼接 bypass，扫描同样放过，随后 `MSLoadManifest` 会 `include` 它——那是同一谓词的另一个消费者。本 case 的 marker 写在 `post_execute`，安装路径更长，但检查函数是同一个。

---

## 后来又补了什么（CVE-2026-29103，7.15.1）

7.15.1 丢掉手写 token 循环，改走 `PhpParser\ParserFactory` + `ModuleScannerVisitor`。visitor 在 AST 上看函数调用、类实例化、方法调用；拼接、括号、变量函数都会在结构层展开或直接当危险模式。解析失败则拒绝安装（畸形 PHP 不能蒙混）。

对残余：AST 上仍是对 `file_get_contents` 的调用（名字由拼接构成），visitor 记 issue，安装被拒。公开建议升到 7.15.1 / 8.9.3。

即便换成 AST，黑名单仍是函数名列表，不是「禁止任意副作用」。对这条已知拼接链它够用。本 benchmark 的 v2 只关闭这一条 reference residual。

`ModuleInstaller` 在扫描通过后会按 `installdefs` 做 copy、mkdir、跑 `pre_execute` / `post_execute`。这些 hook 是普通 PHP 文件，**安装期 include，不再 tokenize**。V1 把「这文件安不安全」完全押在 `scanFile` 的线性状态上；状态被 `.` 清掉之后，后面的 include 就是完整的 PHP 引擎。7.15.1 的 visitor 在 `FuncCall` 上取名字，拼接节点仍然能还原或直接当危险表达式，所以 residual 的括号+点语法过不了 AST。解析失败（故意写不能 parse 的片段）在 V2 会记 parse error 并拒绝安装，堵住「用残缺 PHP 骗过 tokenizer」的旁路。

---

## 从这条链还能看出什么

**维护者改错了哪一层。**  
他们把引号字符串推进了同一套线性状态机。真正执行的是扫描通过之后的 include。V2 才把检查接到解析器的调用节点上。

**不是没有更好的谓词。**  
`file_get_contents` 早就在 `$blackList` 里。失败的是「如何从源码里认出这次调用」。单字符清状态是状态机自己的规则，和 PHP 语法无关。

**同一 `scanFile`、同一安装 hook，只换了函数名的写法。**  
任何进 Module Loader 的 PHP（含 `manifest.php`、`post_execute`）在 7.15.0 上都吃这次 token 循环。

**管理员是预期身份。**  
两条 CVE 都是 PR:H。不完全修复的意思不是「未登录也能打」，而是「装过 49774 补丁的站点仍能用 MLP 执行黑名单函数」。

`token_get_all` 把 `(` `.` `)` `=` `;` 都变成单字符 token，PHP 文档写明 *characters that are not classified as tokens are returned as strings*。V1 用「是字符串就清 `$checkFunction`」来结束一次候选调用，等于把「表达式中间的运算符」当成「这次调用结束了」。赋值 `$a = file_get_contents` 的 `=` 同样清状态，GHSA 把它和 `.` 并列。本 case residual 选拼接，是因为它在 7.15.0 上稳定过扫描，并且安装期 PHP 8.1 把括号表达式当可调用名执行。

---

---

## 安装期 include 不再扫描

`scanPackage` 返回之后，`ModuleInstaller` 按 manifest 的 `installdefs['post_execute']` 去 `include` 脚本。这一次 include 是完整 PHP，字符串拼接、可变函数、括号表达式全部按语言求值。V1 没有「安装前再 parse 一遍」的第二道门。`validExt` 允许 `.php`，所以 hook 文件本身是合法扩展名；拦的只有 token 状态机认出来的调用。拼接把名字拆开之后，扩展名检查和黑名单检查都不触发。

`scanFile` 对反引号 `` ` `` 单独记 `backtick` issue，这是字符串 token 分支里少数「立刻当问题」的路径。`.` `=` `;` 没有对应的立刻拒绝，只清 `$checkFunction`。所以拼接不是「黑名单漏了点运算符」，是状态机把运算符当成了调用边界。`T_EVAL` / `T_ECHO` / `T_EXIT` 在 V1 仍按 token 类型直接记 issue，不走 `$checkFunction`；residual 不需要这些 token。

## 版本、入口、参考

| | 版本 | `scanFile` | `'file_get_contents'(...)` | `('file_get'.'_contents')(...)` |
|---|---|---|---|---|
| V0 | 7.14.5 | 基本只认 T_STRING | 安装期执行，写出 marker | （不必） |
| V1 | 7.15.0 | 加上 T_CONSTANT_ENCAPSED_STRING；单字符清 `$checkFunction` | ML_INVALID_FUNCTION | 扫描放过，安装期执行 |
| V2 | 7.15.1 | `php-parser` AST | 挡 | 挡 |

- 产品 HTTP：登录 → `UpgradeWizard&run=upload` → AJAX `performInstall` → GET `/pcb_marker_*.txt`
- [CVE-2024-49774](https://nvd.nist.gov/vuln/detail/CVE-2024-49774)、[GHSA-9v56-vhp4-x227](https://github.com/salesagility/SuiteCRM/security/advisories/GHSA-9v56-vhp4-x227)
- [CVE-2026-29103](https://nvd.nist.gov/vuln/detail/CVE-2026-29103)、[GHSA-5jjq-9qch-9rg7](https://github.com/salesagility/SuiteCRM/security/advisories/GHSA-5jjq-9qch-9rg7)
- V1 源码：[ModuleScanner.php @ v7.15.0](https://github.com/salesagility/SuiteCRM/blob/v7.15.0/ModuleInstall/ModuleScanner.php)
- V2：同文件在 `v7.15.1` 换成 `scanFileAST`
