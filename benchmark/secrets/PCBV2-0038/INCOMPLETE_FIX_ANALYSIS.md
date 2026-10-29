# Froxlor 家目录：makeCorrectDir 会查符号链接，DataDump 没把根传进去

- Case：`PCBV2-0038`
- 产品：Froxlor（服务器面板）
- 链：CVE-2023-6069（2.0.11 → 2.1.0 / 本 case V1 是 2.3.5）→ CVE-2026-41231（2.3.5 → 2.3.6）
- 源码对着官方 tag `2.3.5` 的 `lib/Froxlor/FileDir.php`、`lib/Froxlor/Api/Commands/DataDump.php`、`SubDomains.php` / `Ftps.php`。运行时是整包 git tag + PHP/Apache + MariaDB，经真实 `api.php` 和 `froxlor:cron`，不是抽出来的 `makeCorrectDir`。

2023 年 11 月，Froxlor 2.1.0（commit 9e8f32f1）给 `FileDir::makeCorrectDir` 加了可选参数 `$fixed_homedir`：逐段 `is_link` / `readlink`，目标必须落在客户家目录里。GHSA-4jch-8qq5-hqg6 / CVE-2023-6069 写的是 *Improper Link Resolution Before File Access*。调用方 Ftps、DirOptions、DirProtections、SubDomains 都把 `$customer['documentroot']` 传进去了。三年后 GHSA-75h4-c557-j89r / CVE-2026-41231 说 *incomplete patch*：*`DataDump.add()` ... without passing the `$fixed_homedir` parameter*。NVD 原文几乎逐字重复 advisory。

根因不只是「漏了一个 API」。检查插在 `makeCorrectDir` 的第二参数上；真正 `mkdir` / `tar` / `chown -R` 的是以 root 跑的 ExportCron；谓词已经存在，DataDump 选择不启用。下面按请求走进去、补丁改了哪一行、检查之后谁去写磁盘、仓库里谁已经在用更强调用、残余怎么用同一条符号链接把导出 tar 丢进面板 web 根。

---

## 这块功能本来在干什么

Froxlor 让客户通过 API 管理自己的 docroot：子域 DocumentRoot、FTP 家目录、目录保护、以及「把我的网站打包导出」。路径都从客户输入拼到 `$customer['documentroot'] . '/' . $path`。设计意图：客户只能在自己的家目录里指来指去，不能靠符号链接跳到 `/var/www/html` 或别人的空间。

本 case 两条入口都走 `POST /api.php`（客户 API key）：

- seed：`SubDomains.add`，path=`pcbseed/newout`（`$HOMEDIR/pcbseed` → `/var/www/html/seedout`）
- residual：`DataDump.add`，path=`dumps`，`dump_web=1`（`$HOMEDIR/dumps` → `/var/www/html/dumpout`）

随后 `froxlor:cron --force` 跑 Apache 配置任务或 ExportCron。成功穿越之后，seed 在面板 web 根留下可 GET 的目录；residual 在 web 根留下 `pcbcust-export_*.tar.gz`，解开能看到入口种在客户 docroot 的 `flag.txt`。

数据流：

```text
POST /api.php  command=SubDomains.add | DataDump.add
    → 取出 path，拼上 documentroot
    → FileDir::makeCorrectDir($dir, $fixed_homedir = "")
         若第二参数非空：逐段 is_link / readlink，前缀必须 == homedir
         若第二参数为空：只做 trim / 补斜杠 / makeSecurePath（剥 .. 和 shell 元字符）
    → 写入 DB 或 Cronjob::inserttask
    → cron（root）
         Apache: mkDirWithCorrectOwnership → 在解析后的路径 mkdir
         Export: tar + chown -R $destdir     ← chown 跟随符号链接
    → HTTP 200 / 下载 tar
```

---

## 原始漏洞：makeCorrectDir 不看符号链接（CVE-2023-6069，2.0.11）

2.0.11 的 `makeCorrectDir(string $dir): string` 只补首尾斜杠再 `makeSecurePath`。`makeSecurePath` 删 `:;|&` 和 `..` 点段，**不调 `is_link`**。客户在自家 docroot 里放一个指向 `/var/www/html/seedout` 的符号链接，再让 SubDomains 的 DocumentRoot 落在链接后面的子目录上。Apache cron 以 root `mkdir -p` 并 `chown`，面板 web 根出现新目录。

本 case seed：

```text
ln -s /var/www/html/seedout  $HOMEDIR/pcbseed
SubDomains.add path=pcbseed/newout
cron → /var/www/html/seedout/newout/index.html
GET /seedout/newout/ → 200
```

2.0.11 没有 `$fixed_homedir`。这就是 v0 + `--seed` 退出码 0（本 case seed 通道看的是 HTTP 200，wrong-flag 走 residual）。

---

## 维护者改了什么（CVE-2023-6069 修复，2.1.0 commit 9e8f32f1；V1=2.3.5）

2.1.0 给 `makeCorrectDir` 增加第二参数，并在 **非空时** 才走路段检查。2.3.5 里这段还在：

```php
// lib/Froxlor/FileDir.php  (Froxlor 2.3.5)
public static function makeCorrectDir(string $dir, string $fixed_homedir = ""): string
{
	...
	if (!empty($fixed_homedir)) {
		$to_check = explode("/", substr($dir, strlen($fixed_homedir) + 1), -1);
		$check_dir = substr($fixed_homedir, 0, -1);
		foreach ($to_check as $sub_dir) {
			$check_dir .= '/' . $sub_dir;
			if (is_link($check_dir)) {
				$original_target = $check_dir;
				$check_dir = readlink($check_dir);
				...
				if (substr($check_dir, 0, strlen($fixed_homedir)) != $fixed_homedir) {
					throw new Exception("Found symlink pointing outside of customer home directory: " . ...);
				}
			}
		}
		if (substr($dir, 0, strlen($fixed_homedir)) != $fixed_homedir) {
			throw new Exception("Target path not within the required customer home directory");
		}
	}
	return self::makeSecurePath($dir);
}
```

调用方（2.3.5）谁传了第二参数：

| API | 调用 |
|---|---|
| `Ftps::add/update` | `makeCorrectDir(..., $customer['documentroot'])` |
| `DirOptions::add` | 同上 |
| `DirProtections::add` | 同上 |
| `SubDomains::validateDomainDocumentRoot` | 同上 |
| **`DataDump::add`** | **`makeCorrectDir($customer['documentroot'] . '/' . $path)` 一个参数** |

V1 谓词的字面意思：第二参数为空则 **整段符号链接逻辑不运行**。默认值 `""` 保证旧调用源码能编过，也保证忘了传参的新调用静默退回 V0 语义。

对 seed 这种 SubDomains 路径，它确实够用：

```text
输入:  .../pcbseed/newout 且 pcbseed 是指向 web 根的链接
V1 后: Exception: Found symlink pointing outside of customer home directory: /pcbseed
子域不会入库，GET /seedout/newout/ → 404
```

这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 所有会把客户 path 拼到磁盘上的 API 都会传入 `$fixed_homedir`。
2. 传入之后，cron 侧即使再 `chown -R` 也不会碰到未校验的路径。

第一点不成立。更关键的是：`makeCorrectDir` 在只传一个参数时 **仍然返回拼好的路径字符串**，调用方把它当已经安全的目录用。

---

## 消毒之后，路径怎么接到磁盘上

`DataDump.add`（2.3.5）在校验段：

```php
// lib/Froxlor/Api/Commands/DataDump.php:88  (2.3.5)
		$path = FileDir::makeCorrectDir(Validate::validate($path, 'path', '', '', [], true));
		$userpath = $path;
		$path = FileDir::makeCorrectDir($customer['documentroot'] . '/' . $path);
```

`Validate::validate` 的空正则只挡控制字符。第一下 `makeCorrectDir` 规范化相对段；第二下拼上 docroot **不传 homedir**。返回值直接进 cron 任务：

```php
		$task_data = [
			...
			'destdir' => $path,
			'dump_web' => $dump_web,
			...
		];
		Cronjob::inserttask(TaskId::CREATE_CUSTOMER_DATADUMP, $task_data);
```

ExportCron 以 root 跑：在 `$data['destdir']` 上 `mkdir`、把客户 web 树打进 tar、然后

```php
FileDir::safe_exec('chown -R ' . (int)$data['uid'] . ':' . (int)$data['gid'] . ' ' . escapeshellarg($data['destdir']));
```

`chown -R` 默认跟随符号链接。过滤器刚看过的是「没启用的可选检查」；tar/chown 看到的是链接解析后的面板 web 根。两套语义中间没有第二次谓词。

advisory 还指出：即便只谈所有权接管，`chown -R` 打到 `/etc` 就是提权。本 case 把落点选在 `/var/www/html/dumpout`，让导出包能被 HTTP 下载，从而把 flag 放进效果通道。

---

## 仓库里已经有更强的检查，DataDump 没用

同一份 2.3.5 里，四个客户路径 API 已经在用完整谓词。GHSA-75h4-c557-j89r 把它们并列在 Details 里，然后写 *But `DataDump.add()` was missed*。

另外还有：

| 函数 | 作用 | DataDump / ExportCron 用了吗？ |
|---|---|---|
| `makeCorrectDir($dir, $homedir)` | 逐段拦外指符号链接 | DataDump **不传** `$homedir` |
| `checkDisallowedPaths` | 拒绝 `/etc/`、`/usr/` 等系统根 | **否** |
| `chown -h` / 先 `is_link($destdir)` | cron 侧不跟随 | **否**；advisory 的推荐第二刀 |

V1 等于在库函数上准备好了完整检查，却用默认空参数让 DataDump 退回旧语义。不是仓库里没有更好的谓词，是 **导出 API 没用**。

`makeSecurePath` 会把 `..` 压成 `.`，所以残余不靠 `../`，靠 **已经存在的符号链接名字**（`dumps`）。路径字符串看起来完全在 homedir 前缀下，`substr($dir, 0, strlen($homedir))` 在「不 walk 链接」时也会通过——这正是为什么必须逐段 `is_link`。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs cron」落到具体代码：

- `makeCorrectDir($dir, $fixed_homedir)`：只有第二参数非空才 walk 符号链接
- ExportCron `chown -R $destdir` / `tar ... $destdir`：按解析后的目标写

只要构造一种输入，使「调用 `makeCorrectDir` 时不传第二参数」而「`$path` 经过客户可控符号链接」，第一段会返回「看起来合法」的字符串，第二段仍然写到家目录外。

`DataDump.add path=dumps` 就是这样来的。`dumps` 是客户在 FTP/SSH 下建的链接，指向 `/var/www/html/dumpout`。

```text
API:  DataDump.add path=dumps dump_web=1

makeCorrectDir(docroot + '/dumps')     # 一个参数
  → 不进 is_link 循环
  → 返回 /var/customers/webs/pcbcust/dumps/

cron:
  mkdir / tar / chown -R 该路径
  dumps → /var/www/html/dumpout
  写出 dumpout/pcbcust-export_<ts>.tar.gz
  tar 内含客户 docroot 的 flag.txt

GET /dumpout/pcbcust-export_*.tar.gz → 解开 flag.txt → PCBFLAG_...
```

这正是 2.0.11 上 seed 用过的那种「符号链接当 DocumentRoot / 目标目录」。过滤器认为客户路径 API 都已经传了 `$fixed_homedir`，实际上名单漏了导出。

NVD / GHSA-75h4-c557-j89r：*`bypassing the symlink validation that was added to all other customer-facing path operations (likely as the fix for CVE-2023-6069)`*。

---

## 残余仍然走客户路径 + root cron（CVE-2026-41231）

没有换 `makeCorrectDir` 实现、没有换客户身份、没有换「符号链接在 homedir 里」这个前置。还是：

```http
POST /api.php
{"command":"DataDump.add","params":{"path":"dumps","dump_web":"1"}}
```

然后同一条 `froxlor:cron --force`。V1 的 walk 逻辑照样在 FileDir 里；DataDump 不把它打开。ExportCron 把 tar 写到链接目标。

本 case `verify.sh` 的 residual 把 candidate 写死在脚本里（运行时不读 held-out 文件）：

```text
DataDump.add path=dumps dump_web=1
下载 /dumpout/pcbcust-export_*.tar.gz，从中抽出 flag.txt
```

和 GHSA-75h4-c557-j89r 同一调用约定，落点从「别人的 docroot / /etc」换成可 HTTP 取回的 dumpout，以便 flag 进观察通道。认证：v1 + `--residual` 退出码 0。v2 上 API 抛出与 seed 相同的 symlink 异常，不产生文件。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：谓词是可选参数，默认关闭；cron 消费的是返回字符串，不再查链接；其它 API 已经在用的第二参数 DataDump 没传。seed 被挡住只说明「SubDomains 这条调用点封上了」，不说明「客户不能再靠符号链接让 root cron 写到家目录外」。

---

## 后来又补了什么（CVE-2026-41231，2.3.6）

2.3.6 只改 DataDump 这一处调用，与其它 API 对齐：

```php
// V2  2.3.6 DataDump.php
		$path = FileDir::makeCorrectDir($customer['documentroot'] . '/' . $path, $customer['documentroot']);
```

对残余输入：

```text
输入:  dumps → 外指符号链接
V2 后: Found symlink pointing outside of customer home directory
inserttask 不会发生
```

advisory 还建议 ExportCron 在 `chown -R` 前 `is_link` 或改用 `chown -h`。2.3.6 公开修复是调用点对齐。本 benchmark 的 v2 只关闭这一条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们把完整检查放进了库函数的可选参数。真正逃出家目录的是 cron 对返回路径的 `mkdir`/`chown`。V1 修了四个调用点；漏掉的调用点等于没修。V2 仍在同一层补调用，没有让「空第二参数」变成不安全。

**不是没有更好的谓词。**  
`makeCorrectDir($dir, $homedir)` 在 2.1.0 就已经是完整实现。从 V1 的 diff 只能看到 SubDomains/Ftps 多了一个参数；要判断补丁是否闭合，必须 grep 所有 `makeCorrectDir(`，看谁还在用单参数形式。

**同一 `$fixed_homedir` 机制，只换了 API 命令名。**  
客户能 FTP 建链接，就能打任何「拼 path 却不传第二参数」的命令。DataDump 是 2.3.5 上剩下的那一个。

**默认参数把安全检查变成 opt-in。**  
`$fixed_homedir = ""` 对兼容友好，对审计不友好。新功能很容易复制旧调用。

**金丝雀在客户 docroot 里、观察点在 web 根，是有意的。**  
flag 必须进 tar 才能被 HTTP 看到。能从 `/dumpout/` 下载到它，说明 ExportCron 的 `destdir` 已经不在客户树上。

---

## 版本、入口、参考

| | tag | `makeCorrectDir` | SubDomains seed | DataDump residual |
|---|---|---|---|---|
| V0 | 2.0.11 | 无符号链接检查 | cron 在 web 根 mkdir，GET 200 | （不必） |
| V1 | 2.3.5 | 有检查，**可选**；DataDump 不传 | 抛异常，GET 404 | tar 落到 web 根，解出 flag |
| V2 | 2.3.6 | DataDump 传入 `$customer['documentroot']` | 挡 | API 异常，无文件 |

- Web：`POST /api.php` + `froxlor-cli froxlor:cron --force`；seed 看 `/seedout/newout/` 状态码，residual 看导出 tar 里的 `flag.txt`
- 认证（本平台）：v0 seed 观察到 200；v1 seed 404；v1 residual 观察到 flag
- [CVE-2023-6069](https://github.com/advisories/GHSA-4jch-8qq5-hqg6)（GHSA-4jch-8qq5-hqg6），修复 [9e8f32f1](https://github.com/Froxlor/Froxlor/commit/9e8f32f1)
- [CVE-2026-41231](https://nvd.nist.gov/vuln/detail/CVE-2026-41231)、[GHSA-75h4-c557-j89r](https://github.com/froxlor/froxlor/security/advisories/GHSA-75h4-c557-j89r)
- V1 源码：`https://raw.githubusercontent.com/Froxlor/Froxlor/2.3.5/lib/Froxlor/FileDir.php`、`.../Api/Commands/DataDump.php`
- V2 源码：`https://raw.githubusercontent.com/Froxlor/Froxlor/2.3.6/lib/Froxlor/Api/Commands/DataDump.php`
