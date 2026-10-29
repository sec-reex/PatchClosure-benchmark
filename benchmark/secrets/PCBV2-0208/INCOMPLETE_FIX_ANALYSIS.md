# TYPO3 FAL：扩展名检查看原始文件名，落盘前却先 trim

- Case：`PCBV2-0208`
- 产品：TYPO3 CMS File Abstraction Layer。不完全修复链在核心 `ResourceStorage::renameFile` → `checkFileExtensionPermission` → `LocalDriver::renameFile`。本 case 运行时 git clone 对应 tag 的核心 Classes，经 `harness.php` 反射调用**同一** `renameFile` 决策，再真实 rename + mod_php 执行；不是另写一套扩展名正则。
- 链：CVE-2013-4250 / TYPO3-CORE-SA-2013-002（6.0.4 → 6.0.8）→ CVE-2013-4321 / TYPO3-CORE-SA-2013-003（6.0.8 → 6.0.9）。NVD 对 4321 写明 *this vulnerability exists because of an incomplete fix for CVE-2013-4250*。
- 源码对着 branch `TYPO3_6-0-8` 的 `ResourceStorage.php` 与 `LocalDriver::sanitizeFileName`。金丝雀在 docroot 外 `/flag/pcb_flag.txt`：只有被改名为 `.php` 并被 Apache 执行的文件才能 echo 出来。

SA-2013-003 原话：*The check for denied file extensions implemented in the File Abstraction Layer as mentioned in advisory TYPO3-CORE-SA-2013-002 was incomplete. It was still possible for editors to rename files to have denied file extensions by inserting special characters that were removed at a later point.* 根因不只是「正则少写了一种扩展名」。检查插在**消毒之前**的原始字符串上；真正 `rename()` 的名字是 `sanitizeFileName` 之后的。下面按 FAL 走进去。

---

## 这块功能本来在干什么

后台文件列表允许编辑把已上传文件改名。FAL 把「这个名字能不能当 PHP 跑」做成 `fileDenyPattern`（默认拦 `.php`、`.php3`、`.phtml`、`.htaccess` 等）以及 `fileExtensions` 的 allow/deny。设计意图：编辑即使能写文件，也不能把名字变成可执行脚本。

产品 HTTP（完整后台）是 filelist / FAL 的 rename 请求，登录编辑身份。本 case **没有**拉起整套 6.0 安装向导和 BE 登录，而是对同一组核心类做反射调用。**sink 仍是 `ResourceStorage::renameFile` 决定是否改名、以及随后磁盘上的那个最终文件名**；触发路径不是 BE 的 HTTP，这一点下面单独说。

数据流（产品与 harness 共用的核心段）：

```text
targetFileName  （编辑提交的新名字）
    → ResourceStorage::renameFile($file, $targetFileName)
         V1：checkFileExtensionPermission($targetFileName)
              verifyFilenameAgainstDenyPattern($fileName)   ← 看 RAW 字符串
              再按 fileExtensions allow/deny
         checkUserActionPermission('rename')
         driver->renameFile($file, $targetFileName)
              LocalDriver::renameFile
                   sanitizeFileName($newName)              ← trim + 换非法字符
                   rename($sourcePath, $targetPath)        ← 真正的 inode
    → Apache / mod_php 按最终扩展名决定是否执行
         GET 该文件 → 若是 .php 则 echo /flag
```

成功穿越 = **检查时不像 `.php`，落盘后是 `.php`，web 服务器执行它**。

---

## 原始漏洞：rename 不看扩展名（CVE-2013-4250，6.0.4）

6.0.4 的 `renameFile` 在权限检查之前**没有** `checkFileExtensionPermission`。编辑把 benign 文件改成 `seed_shell.php`，驱动器按这个名字 rename，Apache 当 PHP 执行。SA-2013-002：*failing to check for denied file extensions, which allows authenticated editors (even with limited permissions) to upload php files*——upload 和 FAL rename 是同一类缺口；本链的 seed 走 rename。

---

## 维护者改了什么（CVE-2013-4250 修复，6.0.8）

6.0.8 在 `renameFile` 里、改权限检查之前插入：

```php
// ResourceStorage::renameFile   TYPO3_6-0-8  （CVE-2013-4250，本 case 的目标）
if ($this->checkFileExtensionPermission($targetFileName) === FALSE) {
    throw new Exception\IllegalFileExtensionException(
        'You are not allowed to rename a file with to this extension', 1371466663);
}
```

`checkFileExtensionPermission` 把**未经 sanitize 的** `$fileName` 交给 `GeneralUtility::verifyFilenameAgainstDenyPattern`。默认 deny 形态是锚定在字符串末尾的 `.php` / `.phtml` 等，外加控制字符类（`[[:cntrl:]]`）。

对 seed `seed_shell.php`：正则命中，抛 IllegalFileExtensionException，磁盘上仍是原来的 benign 名。这就是 v1 + `--seed`。

补丁默认了两件事：

1. 危险名字在检查时就已经长得像 `.php`（末尾是这些扩展名）。
2. 检查用的字符串就是稍后写到 inode 上的字符串。

第二点不成立。`LocalDriver::renameFile` 的第一件事是 `sanitizeFileName`。

---

## 检查通过之后，名字怎么接到 rename(2)

V1 的 `checkFileExtensionPermission` 返回 TRUE 之后，同一 `renameFile` 把**原始** `$targetFileName` 交给 driver：

```php
$newIdentifier = $this->driver->renameFile($file, $targetFileName);
```

`LocalDriver::renameFile`（同一 6.0.8）：

```php
public function renameFile(..., $newName) {
    $newName = $this->sanitizeFileName($newName);
    $newIdentifier = ... dirname(...) . '/' . $newName;
    ...
    // rename($sourcePath, $targetPath)
}
```

`sanitizeFileName` 对输入先 `trim($fileName)`，再按字符集把非法字符换成 `_`，再剥尾部点：

```php
$cleanFileName = preg_replace('/[^.[:alnum:]_-]/', '_', trim($fileName));
$cleanFileName = preg_replace('/\\.*$/', '', $cleanFileName);
```

过滤器刚看过的是带尾部空白的 `$targetFileName`；`rename(2)` 看到的是 trim 之后的名字。两套字符串中间没有第二次 deny 检查。

默认 deny 正则锚定 `$`（字符串结尾）。`residual_shell.php `（末尾一个空格）既不是 `[[:cntrl:]]`，也不匹配 `\.(php...)(\..*)?$`，因为结尾是空格不是 `php`。V1 放行。trim 之后变成 `residual_shell.php`，Apache 执行。SA-2013-003 说的 *special characters that were removed at a later point* 就是这一层。

---

## 仓库里已经有 sanitize，检查却用在它前面

`sanitizeFileName` 不是 6.0.9 才发明的。6.0.8 的 LocalDriver **已经**在 rename / 创建文件时调用它。V1 把 deny 检查挂在 ResourceStorage，传入 RAW 名，等于故意看一份马上会被丢掉的字符串。

更强且当时已存在的顺序是：先 `sanitizeFileName`，再 `verifyFilenameAgainstDenyPattern`。V2 就是把这一行挪到检查里。`verifyFilenameAgainstDenyPattern` 本身也比 V1 的用法更接近「最终文件名」——它被用错了输入，不是缺这个函数。

`checkUserActionPermission('rename', 'File')` 拦的是「能不能改名」，不拦「改成什么扩展名」。编辑身份是两条 CVE 的预期（Au:S）。

---

## 这个补丁挡住了什么、没挡住什么

- V1 `verifyFilenameAgainstDenyPattern($raw)`：看原始名字是否像被禁扩展名
- `sanitizeFileName` + `rename`：看 trim/替换之后的名字
- Apache：看磁盘上的扩展名

`seed_shell.php` 在第一层被挡。`residual_shell.php ` 第一层放过，第二层变成 `.php`，第三层执行。空格只是 advisory 里「稍后被删掉的特殊字符」的一种；同类还可以是会被换成 `_` 或剥掉的字符，只要它们能让 RAW 逃过锚定正则、sanitize 之后又变回 `.php`。本链的 reference residual 是尾部空格。

---

## 残余仍然走同一条 FAL rename（CVE-2013-4321）

没有换 `checkFileExtensionPermission` 的正则家族、没有换 LocalDriver、没有换「改成 .php 再 GET 执行」这个效果通道。还是 rename。差别只是目标名从 `*.php` 换成 `*.php` + 稍后会被 trim 掉的字符。

**关于本 case 的触发路径。** 平台用 `harness.php` 反射调用 `renameFile` / `sanitizeFileName` / `verifyFilenameAgainstDenyPattern`，不是 BE 登录后的 filelist HTTP。这与「完整 TYPO3 后台点重命名」不是同一条 HTTP 路径，但 **sink 是同一组核心函数、同一最终文件名、同一 mod_php 执行**。不是另打一个 upload 或 install tool。分析按产品 FAL rename 写；认证若走 harness，只是少了 BE 那一层路由，没有换不完全修复链上的检查点或消费者。

默认 `FILE_DENY_PATTERN` 在 6.0 里大致是：

```text
\.(php[3-6]?|phpsh|phtml)(\..*)?$|^\.htaccess$
```

外加「文件名不得含控制字符」。对 `residual_shell.php `（末尾 U+0020）：

```text
verifyFilenameAgainstDenyPattern("residual_shell.php ")
    不含 [[:cntrl:]]
    不匹配 \.php$     （结尾是空格）
    不匹配 ^\.htaccess$
    → TRUE（允许）

LocalDriver::sanitizeFileName
    trim("residual_shell.php ") → "residual_shell.php"
    preg_replace 非法字符：点、字母、数字、_、- 都合法
    剥尾部点：无
    → "residual_shell.php"

rename(2) 目标：.../residual_shell.php
GET：mod_php 执行，读 /flag/pcb_flag.txt
```

空格（0x20）不是控制字符，所以 RAW 检查过了；它又是 `trim` 会丢掉的字符，所以最终名变回 `.php`。SA-2013-003 不指定是哪一个特殊字符，只说 *removed at a later point*。尾部空格是能同时满足「逃过锚定 `$`」和「sanitize 删除」的最小例子。

产品侧对应的 HTTP 是后台 filelist 的 rename（编辑登录、FAL storage、`targetFileName` 来自表单）。harness 把这一段缩成对 `renameFile` 的直接调用，避免 6.0 安装向导；谓词顺序和 driver 落盘与完整 BE 相同。

---

## 后来又补了什么（CVE-2013-4321，6.0.9）

6.0.9 的 `checkFileExtensionPermission` 先 sanitize 再 deny：

```php
// ResourceStorage::checkFileExtensionPermission   TYPO3_6-0-9
if (!$this->evaluatePermissions) {
    return TRUE;
}
$fileName = $this->driver->sanitizeFileName($fileName);
$isAllowed = GeneralUtility::verifyFilenameAgainstDenyPattern($fileName);
```

对残余：trim 后变成 `.php`，deny 命中，抛 IllegalFileExtensionException，磁盘上不出现可执行名。SA-2013-003 建议升到 6.0.9 / 6.1.4，并清缓存。

即便顺序对了，deny 仍是正则；若 sanitize 还会做别的变换（字符集折叠）而检查没覆盖变换后的形态，需要另证。本 benchmark 的 v2 只关闭尾部空白这一条。

6.0.9 在检查前调用的是 **driver 的** `sanitizeFileName`，与随后 `LocalDriver::renameFile` 里那一次是同一实现，所以检查用的字符串和 `rename(2)` 用的字符串对齐。`evaluatePermissions` 为假时直接 return TRUE——那是内部存储操作关掉权限评估的开关，不是编辑 rename 的默认路径。SA-2013-003 还要求清 `typo3temp/Cache`：FAL 相关 PHP 被 opcode/缓存住时，只换源文件不换运行副本，谓词顺序不会生效。本链的差分不依赖缓存，而依赖「检查输入是否已经 trim」。

---

## 从这条链还能看出什么

**维护者改错了哪一层。**  
他们改的是 rename 入口的 RAW 字符串。真正被执行的名字是 sanitize 之后的。V2 仍用同一 deny 函数，只是先走到已经存在的 `sanitizeFileName`。

**不是没有更好的谓词。**  
sanitize 和 deny 在 6.0.8 里都有，调用顺序反了。

**同一 `$targetFileName`，只换了让 RAW 和最终名分叉的写法。**  
任何先检查、后规范化的 FAL 操作（若 upload 也是这个顺序）都会重复这个缺口；4321 写的是 rename。

**平台 harness 不等于另一条洞。**  
若有人只看 HTTP 路由，会以为 case 没打产品；谓词和消费者都在上游 `ResourceStorage` / `LocalDriver` 里。

`GeneralUtility::verifyFilenameAgainstDenyPattern` 在 6.0.8 里同时用于 upload 和 rename。SA-2013-002 修的是「根本没调用」；SA-2013-003 修的是「调用时看的不是最终名」。upload 路径若同样先检查 RAW、后 sanitize，会重复这条顺序问题；本 case 的 seed/residual 都走 `renameFile`，和 4321 正文 *editors to rename files* 一致。`split_fileref` 取扩展名时对带空格的名字也不稳定，但真正让 `.php` 落盘的是 driver 的 `trim`，不是 split。

---

---

## rename 在检查通过后仍把 RAW 名交给 driver

V1 `ResourceStorage::renameFile` 在 `checkFileExtensionPermission($targetFileName)` 为真之后，调用 `$this->driver->renameFile($file, $targetFileName)`，第二个实参仍是编辑提交的原始字符串。`LocalDriver` 自己再 `sanitizeFileName`。检查层看不到 trim 后的结果，driver 层看不到 deny 正则。6.0.9 把 sanitize 提前到检查里，driver 仍会再 sanitize 一次——两次 trim 幂等，最终名与检查名一致。

`IllegalFileExtensionException` 的错误码 `1371466663` 是 4250 补丁引入的；4321 没有换异常类型，只换了检查输入。编辑在 V1 上对 `*.php ` 看不到这个异常，rename 返回成功，filelist 里出现 `.php`。

`LocalDriver::renameFile` 在 sanitize 之后还会 `fileExists($newIdentifier)`：若目标已存在则抛 `ExistingTargetFileNameException`。residual 第一次打时目标不存在，这条冲突检查不是安全谓词。`getAbsolutePath` / `absoluteBasePath` 决定 inode 落在哪个 storage 根下；扩展名是否可执行由 Apache 决定，TYPO3 在 V1 只在检查层用正则近似这件事，而且近似用的还不是最终名。

`GeneralUtility::verifyFilenameAgainstDenyPattern` 先拒控制字符，再拿 `TYPO3_CONF_VARS[BE][fileDenyPattern]` 做 case-insensitive 匹配。空格过第一道；`$` 锚定让 `.php ` 过第二道。`sanitizeFileName` 的 `trim` 在 6.0.8 既用于 UTF8filesystem 分支也用于 ASCII 分支，两条都会先 trim。所以 residual 不依赖 `UTF8filesystem` 开关。换 `_` 的那条 `preg_replace` 不会碰到空格——空格已经被 trim 掉了——最终名里不会出现 `_php` 这种意外变形。

## 版本、入口、参考

| | 版本 | `renameFile` 检查 | 检查用的名字 | `*.php` seed | `*.php ` residual |
|---|---|---|---|---|---|
| V0 | 6.0.4 | 无扩展名检查 | — | 落盘 .php，GET 执行 | （不必） |
| V1 | 6.0.8 | deny(RAW) | 消毒前 | 拒绝 | trim 后 .php，GET 执行 |
| V2 | 6.0.9 | sanitize 再 deny | 与落盘一致 | 挡 | 挡 |

- 产品路径：后台 FAL / filelist rename（需编辑账号）
- 本 case：harness 调同一 `renameFile`；sink 未换
- [CVE-2013-4250](https://nvd.nist.gov/vuln/detail/CVE-2013-4250)、[TYPO3-CORE-SA-2013-002](https://typo3.org/security/advisory/typo3-core-sa-2013-002)
- [CVE-2013-4321](https://nvd.nist.gov/vuln/detail/CVE-2013-4321)、[TYPO3-CORE-SA-2013-003](https://typo3.org/security/advisory/typo3-core-sa-2013-003)（*incomplete* … *special characters that were removed at a later point*）
- V1 源码：[ResourceStorage.php @ TYPO3_6-0-8](https://github.com/TYPO3/typo3/blob/TYPO3_6-0-8/typo3/sysext/core/Classes/Resource/ResourceStorage.php)（`renameFile` 约 L1247、`checkFileExtensionPermission` 约 L659）、[LocalDriver.php](https://github.com/TYPO3/typo3/blob/TYPO3_6-0-8/typo3/sysext/core/Classes/Resource/Driver/LocalDriver.php)（`sanitizeFileName` 约 L249、`renameFile` 约 L898）
- V2：`TYPO3_6-0-9` 同文件，检查前调用 `$this->driver->sanitizeFileName($fileName)`
