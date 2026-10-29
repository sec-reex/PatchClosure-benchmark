# PhpSpreadsheet：prohibitWrappers 问的是 parse_url，fopen 认的是 phar:///

- Case：`PCBV2-0171`
- 产品：PhpSpreadsheet（Composer `phpoffice/phpspreadsheet`）。运行时是 Packagist 整包 `1.30.2` / `1.30.3` / `1.30.5`，薄 HTTP 入口只把 `path` 原样交给 `Reader\Csv::load`，不是抽出来的 `File.php`。
- 链：CVE-2026-34084（1.30.2 → 1.30.3，GHSA-q4q6-r8wh-5cgh）→ CVE-2026-45034（1.30.3 → 1.30.5，GHSA-87m4-826x-3crx）
- 源码对着 tag `1.30.3` 的 `src/PhpSpreadsheet/Shared/File.php`（`prohibitWrappers` / `assertFile` / `testFileNoThrow`）、`src/PhpSpreadsheet/Reader/BaseReader.php`（`openFile` / `load`）。金丝雀是 benign：`/work/flag.phar` 里 `sheet.csv` 的 A1 写成 `PCBFLAG_...`，普通磁盘路径读不到。

GHSA-87m4-826x-3crx 的原话：*CVE-2026-34084 was patched by the helper File::prohibitWrappers. The helper calls parse_url($filename, PHP_URL_SCHEME) ... The check is not equivalent to "does the path contain a wrapper".* 当输入是 `phar:///path/file.phar/inner`（scheme 后三个或更多斜杠）时，`parse_url` 返回 `false`，`is_string($scheme)` 为假，抛异常被跳过，但 PHP 流层仍然按 phar wrapper 打开。

根因不只是「正则没写」。检查插在「`parse_url` 能不能取出长度大于 1 的 scheme 字符串」上；真正打开字节的是后面的 `is_file` / `fopen`。同函数注释已经写「All filenames starting with protocol are prohibited」，实现却把「有没有协议」委托给一套对三斜杠会失败的解析器。下面按调用走进去。

---

## 这块功能本来在干什么

PhpSpreadsheet 的 reader 接受一个文件名，打开后解析成工作簿。库 API 是 `IOFactory::load($filename)` 或具体 reader 的 `load($filename)`。一次典型调用：

```php
$reader = new \PhpOffice\PhpSpreadsheet\Reader\Csv();
$spreadsheet = $reader->load($attackerPath);
```

本 case 的 HTTP 面是 `POST /`，body 里的 `path` 原样进入 `Csv::load`。`BaseReader::load` → `loadSpreadsheetFromFile` → `openFile`：

```php
// Reader/BaseReader.php :: openFile  (PhpSpreadsheet 1.30.3)
protected function openFile(string $filename): void
{
    $fileHandle = false;
    if ($filename) {
        File::assertFile($filename);
        $fileHandle = fopen($filename, 'rb');
    }
    ...
}
```

设计意图：`$filename` 是磁盘上的表格文件（csv / xlsx），不是 `phar://`、`php://`、`expect://` 这类流包装。成功穿越之后的效果是：**reader 按 phar wrapper 读出归档成员**，第一行出现金丝雀。本 case 跑在 PHP 8.2，phar 元数据不再自动反序列化，观察点是文件读，不是 RCE gadget。

数据流：

```text
POST /  path=phar://… 或 phar:///…
    → Csv::load($path)
         BaseReader::openFile
              File::assertFile
                   File::prohibitWrappers($filename)   ← V1 谓词
                   is_file($filename)                  ← PHP 流层，仍认 phar:///
                   is_readable($filename)
              fopen($filename, 'rb')
         解析 sheet.csv → JSON surfaced
```

不需要登录。归档事先放在 `/work/flag.phar`（`/app` 之外）。没有「允许 wrapper」这个显式开关。

---

## 原始漏洞：phar:// 直接过 is_file（CVE-2026-34084，1.30.2）

1.30.2 的 `assertFile` **没有** `prohibitWrappers`。NVD / GHSA-q4q6-r8wh-5cgh：当 `IOFactory::load()` 的 filename 受控时，攻击者可以提供 `phar://`、`ftp://`、`ssh2.sftp://` 等路径，它们能通过 `is_file()`。在 PHP 7.x 上，`phar://` 会触发 PHAR 元数据反序列化；`ftp://` / `ssh2.sftp://` 还能做 SSRF。修复版本是 1.30.3、2.1.15、2.4.4、3.10.4、5.6.0。

本 case seed 用规范的两斜杠形式：

```text
phar://work/flag.phar/sheet.csv
```

`parse_url(..., PHP_URL_SCHEME)` 对这种输入返回字符串 `'phar'`。V0 没有这层检查，`is_file` / `fopen` 走 phar wrapper，读出 `sheet.csv` 的 A1。这就是 v0 + `--seed` 观察到 `PCBFLAG_...`。

advisory 自己的负对照就是 `phar://x/dummy.csv`：*returns the string "phar" and the throw fires correctly*——那是 V1 要挡住的形态。

---

## 维护者改了什么（CVE-2026-34084 修复，1.30.3）

1.30.3 新增 `prohibitWrappers`，并在 `assertFile` / `testFileNoThrow` 入口各调一次：

```php
// Shared/File.php :: prohibitWrappers  (PhpSpreadsheet 1.30.3)
/**
 * All filenames starting with protocol (e.g. phar://) are prohibited.
 * Note that many protocols, including http and zip, will already
 * return false for is_file.
 * A whitelist of protocols may be added if needed in future.
 */
public static function prohibitWrappers(string $filename): void
{
    $scheme = parse_url($filename, PHP_URL_SCHEME);
    // strlen check > 1 to avoid issues with Windows absolute paths (e.g. C:\...)
    if (is_string($scheme) && strlen($scheme) > 1) {
        throw new Exception(
            "Stream wrappers are not permitted as file paths: {$filename}"
        );
    }
}
```

`assertFile` 的顺序是：先 `prohibitWrappers`，再 `is_file` / `is_readable`：

```php
public static function assertFile(string $filename, string $zipMember = ''): void
{
    self::prohibitWrappers($filename);
    if (!is_file($filename)) {
        throw new ReaderException('File "' . $filename . '" does not exist.');
    }
    ...
}
```

V1 谓词的字面意思：

| 片段 | 含义 |
|---|---|
| `parse_url($filename, PHP_URL_SCHEME)` | 按 RFC 3986 取 scheme |
| `is_string($scheme)` | 解析失败（`false`）直接放过 |
| `strlen($scheme) > 1` | 放过 Windows `C:\...` 这种单字母盘符 |

对 seed 这种两斜杠 `phar://work/...`，`$scheme === 'phar'`，`strlen > 1`，抛 `Stream wrappers are not permitted as file paths`。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 「有没有 wrapper」等价于「`parse_url` 能取出多字符 scheme」。
2. 解析失败的输入一定不是 wrapper，可以安全地交给 `is_file` / `fopen`。

第二点不成立。PHP 的 `phar` 流对 `phar:///abs/path/file.phar/inner`（绝对归档，三斜杠）是合法的；`parse_url` 在这种形态上返回 `false`。

---

## 检查之后，谁真正打开文件

`prohibitWrappers` 一返回，同一个 `assertFile` 立刻把**原字符串**交给 `is_file`，`openFile` 再 `fopen`。没有第二次 scheme 检查，没有 `realpath`，没有「必须是普通文件 inode」。

```text
prohibitWrappers("phar:///work/flag.phar/sheet.csv")
    parse_url → false
    is_string(false) → 假，return
is_file("phar:///work/flag.phar/sheet.csv")     ← 流层打开 phar
fopen("phar:///work/flag.phar/sheet.csv", "rb")
Csv reader 读 member sheet.csv
```

过滤器刚看过的是「`parse_url` 眼里有没有 scheme 字符串」；`fopen` 看到的是 PHP 流包装器表。两套语义中间没有第二次谓词。

`testFileNoThrow` 的注释写 *Will nevertheless throw if filename uses invalid protocol, e.g. phar*，实现却和 `assertFile` 共用同一套 `parse_url`。探测路径和打开路径一起漏。

本 case 的 HTTP 服务不改写 `path`。三斜杠形式原样到达 `Csv::load`。金丝雀在 `/work/flag.phar` 里能出现在 JSON `surfaced` 字段，依据就是这一步，而不是「/app 下碰巧有同名 csv」。

---

## 仓库里已经有更强的检查，没用上

同一份 `File.php` 里已经有 `realpath()` 辅助函数，注释写 *Returns canonicalized absolute pathname*。advisory 建议的两种修法，仓库当时都没采用：

```php
// GHSA-87m4-826x-3crx Suggested fix
if (str_contains($filename, '://')) {
    throw new Exception("Stream wrappers are not permitted as file paths: {$filename}");
}
// 或者先 realpath()：wrapper 前缀路径会得到 false
```

谁更接近「禁止协议前缀」：

| 谓词 | 两斜杠 `phar://` | 三斜杠 `phar:///` | Windows `C:\` |
|---|---|---|---|
| V1 `parse_url` + `is_string` + `strlen>1` | 拦 | **放行** | 放行（单字母） |
| `str_contains($filename, '://')` | 拦 | 拦 | 放行 |
| `realpath()` 为假则拒 | 拦 | 拦 | 视盘符而定 |

V1 等于用一套**更弱**的 URL 解析去近似「文件名不得带协议」，而真正 open 的 `is_file`/`fopen` 继续按流层解释。不是仓库里想不出 `://` 子串，是 **谓词选了 parse_url**。

即便三斜杠没有把 `parse_url` 打穿，只要 `assertFile` 在检查之后仍把原字符串交给 `fopen`，任何让 `parse_url` 返回非字符串、而流层仍当 wrapper 的写法都会变成一次真实打开。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs open」落到具体代码：

- `prohibitWrappers` 的 `parse_url(..., PHP_URL_SCHEME)`：看能不能取出多字符 scheme
- `is_file` / `fopen`：看 PHP 流层怎么注册 `phar`

只要构造一种输入，使「取 scheme」失败，但「当 wrapper 打开」成功，第一行会放行，第二行仍然读归档。

`phar:///work/flag.phar/sheet.csv` 就是这样来的。scheme 后三个斜杠，权威形式是「绝对路径上的 phar + 内部成员」。advisory 写明：

```text
parse_url('phar://work/flag.phar/sheet.csv',  PHP_URL_SCHEME) === 'phar'   → 抛
parse_url('phar:///work/flag.phar/sheet.csv', PHP_URL_SCHEME) === false    → 漏过
```

带上 reader 前缀：

```text
POST path:  phar:///work/flag.phar/sheet.csv

V1 prohibitWrappers:
  $scheme = false
  is_string → 假，不抛

assertFile / openFile:
  is_file / fopen 走 phar wrapper
  读出 sheet.csv → surfaced 含 PCBFLAG_...
```

这正是 1.30.2 上 seed 用过的那种读。过滤器认为自己已经把 `phar://` 清干净了，实际上它只认识 `parse_url` 肯承认的那一种写法，并且 `fopen` 会按真实 wrapper 打开。

GHSA-87m4 在 1.30.4、2.1.16、2.4.5、3.10.5、5.6.0、5.7.0 上都复现了同一 `prohibitWrappers` 字节；1.x 在 PHP 7.4 上还能走到元数据反序列化 RCE。本 case 钉在 1.30.3 / PHP 8.2，观察的是文件读原语。

---

## 残余仍然走同一条 reader load 路径（CVE-2026-45034）

没有换 reader、没有换 `assertFile`、没有换金丝雀文件。还是：

```http
POST /
path=phar:///work/flag.phar/sheet.csv
```

`Csv::load` 仍然调用同一个 `openFile` → `assertFile` → `prohibitWrappers`。V1 那一行 `parse_url` 照样执行；执行完之后 `$filename` 原样进入 `is_file` / `fopen`；CSV 第一行进 JSON。

这和 GHSA-87m4 的正对照同一构造，只是把 `exploit.phar` 换成带金丝雀的 `/work/flag.phar`。公开 PoC 还保留负对照 `phar://x/dummy.csv`，用来证明两斜杠仍然被挡——本 case 的 seed/residual 差分就是这两条 URL。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：`parse_url` 的语言比流包装语义窄；`fopen` 发生在检查之后且用的是原字符串；注释里的「以协议开头」没有用 `://` 或 `realpath` 实现。seed 被挡住只说明「规范两斜杠没了」，不说明「不能再从 load 路径读 phar 成员」。

平台 residual 与不完整修复链是**同一 sink**（`File::prohibitWrappers` → `is_file`/`fopen`），不是换到另一条 reader 或另一类 wrapper。

---

## 后来又补了什么（CVE-2026-45034，1.30.5）

1.30.5 丢掉 `parse_url`，改成对字符串本身做正则：

```php
// Shared/File.php :: prohibitWrappers  (PhpSpreadsheet 1.30.5)
public static function prohibitWrappers(string $filename): void
{
    if (
        Preg::IsMatch('~^phar://~i', $filename)
        || (Preg::isMatch('/^([\w.\s\x00-\x1f]+):/', $filename) && !Preg::isMatch('/^([\w.]+):/', $filename))
        || Preg::isMatch('~^[\w.]+://.*phar:~is', $filename)
    ) {
        throw new Exception(
            "Disallowed stream wrapper: {$filename}"
        );
    }
}
```

`~^phar://~i` 不关心后面有几个斜杠，两斜杠和三斜杠都抛 `Disallowed stream wrapper`。另外两支拦控制字符混淆的 scheme 和嵌套的 `compress.zlib://...phar:`。公开建议是升级到 1.30.5（以及各分支对应修复版）。

即便如此，这仍然是「在 `fopen` 之前用正则近似 wrapper」，`assertFile` 还是不做 `realpath` 前缀。对 `phar:///` 这条已知链它够用；若还有不以 `phar://` 开头、却仍被流层当 phar 打开的写法，需要另证。本 benchmark 的 v2 只关闭这一条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是「如何从字符串里取出 scheme」。真正读到归档的是 `is_file` / `fopen` 的流层。V2 仍在同一层加码（正则代替 `parse_url`），没有在 open 之后检查「打开的是不是普通文件」。

**不是没有更好的谓词。**  
`str_contains($filename, '://')` 和 `realpath()` 都在 advisory 的建议修法里。`File::realpath` 已经在同文件。从 V1 的 diff 只能看到加了一个 `parse_url` 助手；要判断补丁是否闭合，必须看到 `assertFile` 随后的 `is_file` 以及 PHP 对 `phar:///` 的解析。

**同一函数、同一 `$filename`，只换了斜杠个数。**  
任何把用户字符串传进 `IOFactory::load` / `Reader::*::load` 的应用，在 1.30.3 上都吃这一行 `parse_url` 和同一次 `fopen`。

**注释和实现不是同一句话。**  
注释写 *filenames starting with protocol*；实现问的是 `parse_url` 是否返回多字符 scheme。三斜杠以 `phar://` 开头，却被当成「没有 scheme」。

**金丝雀在 phar 成员里是有意的。**  
`/work/flag.phar` 不在文档根。能读到它，说明 reader 打开的是 wrapper，不是 `/app` 下的普通 csv。

---

## 版本、入口、参考

| | tag | `prohibitWrappers` | `assertFile` 之后 | 两斜杠 seed | 三斜杠 residual |
|---|---|---|---|---|---|
| V0 | 1.30.2 | 无 | `is_file` / `fopen` | 读到金丝雀 | （不必） |
| V1 | 1.30.3 | `parse_url` + `is_string` | 同上 | 抛 Stream wrappers… | `parse_url=false`，读到金丝雀 |
| V2 | 1.30.5 | `^phar://` 等正则 | 同上 | 挡 | 挡 |

- 库 API：`Reader\Csv::load($filename)` / `IOFactory::load($filename)`（本 case HTTP：`POST /` `path=`）
- 观察：响应 JSON `surfaced` 中的 `PCBFLAG_...`
- [CVE-2026-34084](https://nvd.nist.gov/vuln/detail/CVE-2026-34084)、[CVE-2026-45034](https://nvd.nist.gov/vuln/detail/CVE-2026-45034)
- [GHSA-q4q6-r8wh-5cgh](https://github.com/PHPOffice/PhpSpreadsheet/security/advisories/GHSA-q4q6-r8wh-5cgh)
- [GHSA-87m4-826x-3crx](https://github.com/PHPOffice/PhpSpreadsheet/security/advisories/GHSA-87m4-826x-3crx)
- V1 blob：[`File.php@1.30.3`](https://github.com/PHPOffice/PhpSpreadsheet/blob/1.30.3/src/PhpSpreadsheet/Shared/File.php)、[`BaseReader.php@1.30.3`](https://github.com/PHPOffice/PhpSpreadsheet/blob/1.30.3/src/PhpSpreadsheet/Reader/BaseReader.php)
- V2 tag：`1.30.5`
