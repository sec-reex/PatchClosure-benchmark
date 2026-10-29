# FreeScout：扩展名黑名单加完了，Apache 还认 .pht

- Case：`PCBV2-0114`
- 产品：FreeScout（自托管 help desk，Laravel + PHP，本 case 跑在 Debian Apache + `libapache2-mod-php`）
- 链：CVE-2025-48471 / GHSA-h2f3-932h-v38j（1.8.178 → 1.8.179，commit `e136660e`；本 case 的 V1 取 1.8.223）→ CVE-2026-53593 / GHSA-27vp-fpg8-j8wv（1.8.223 → 1.8.224）
- 源码对着 GitHub tag `1.8.178` / `1.8.223` / `1.8.224` 的 `app/Misc/Helper.php`（`$restricted_extensions`、`sanitizeUploadedFileName`、`uploadFile`）和 `app/Http/Controllers/SecureController.php`（`upload`）。运行时是整仓 git tag + 官方 Apache/mod_php 部署，不是抽出来的函数。GHSA-27vp-fpg8-j8wv 原文写明 *This is a direct bypass of the fix for CVE-2025-48471 ... which added phtml/phar but not pht*。

2025 年 5 月，FreeScout 给上传文件名加了 `phtml` 和 `phar`。这挡住了 seed 那种 `.phtml` webshell。一年后 advisory 指出：同一条 `POST /uploads/upload` → `storage/app/public/uploads/` 路径上，黑名单始终没有 `pht`。Debian 默认的 `FilesMatch ".+\.ph(ar|p[3457]?|t|tml)$"` 会把 `.pht` 交给 mod_php。NVD 把这件事记成 CVE-2026-53593。

根因不只是「少写了一个后缀」。检查插在「扩展名是否匹配一张短正则」这一层；真正执行的是 Apache 对 web 可达路径的 handler；同文件里已经有按客户上传用的扩展名白名单，agent 上传这条路径没挂。下面按请求走进去、1.8.179 改了哪几行、改名之后谁消费那个文件名、更宽的谓词有没有挂上，把这几层写完。

---

## 这块功能本来在干什么

FreeScout 给已登录 agent 提供附件/通用上传。`SecureController@upload` 接收 multipart 文件，交给 `Helper::uploadFile`，文件落到 `storage/app/public/uploads/`，经 `public/storage` 符号链接以 `/storage/uploads/<name>` 对外可达。

一次典型请求：

```http
POST /uploads/upload
Content-Type: multipart/form-data
file=@note.txt
```

`uploadFile` 取出客户端扩展名，拼一个随机主名，再交给消毒函数，最后 `storeAs`：

```php
// app/Misc/Helper.php :: uploadFile  (tag 1.8.223, 约 L1609–1632)
public static function uploadFile($file, $allowed_exts = [], $allowed_mimes = [])
{
    $ext = strtolower($file->getClientOriginalExtension());

    if ($allowed_exts) {
        if (!in_array($ext, $allowed_exts)) {
            throw new \Exception(__('Unsupported file type'), 1);
        }
    }
    ...
    $file_name = \Str::random(25).'.'.$ext;

    $file_name = \Helper::sanitizeUploadedFileName($file_name, $file, null, $mime_type);

    $file->storeAs('uploads', $file_name);
    ...
    return self::uploadedFilePath($file_name);
}
```

`SecureController@upload` 调用时**不传** `$allowed_exts`。白名单分支整段跳过，只剩后面那张黑名单。

设计意图：agent 可以上传会话附件；扩展名若属于「会在 Apache 上当 PHP 跑」的集合，就在文件名末尾加 `_`，让 handler 配不上。成功穿越之后的效果是：**黑名单认为危险后缀已经改名，Apache 却仍按 PHP 执行**——本 case 用 webshell 读 `/canary.txt`，响应里出现 `PCBFLAG_...`。

数据流：

```text
POST /uploads/upload  file=shell.<ext>
    → SecureController@upload
         Helper::uploadFile($file)          ← 不传 allowed_exts
         ext = getClientOriginalExtension()
         name = random(25) . '.' . ext
         V1：sanitizeUploadedFileName       ← 补丁插在这里（按黑名单加 _）
         storeAs('uploads', name)
    → GET /storage/uploads/<name>?c=cat /canary.txt
         Apache FilesMatch → mod_php        ← 真正的执行，不再查黑名单
    → 响应 body 里的 PCBFLAG_...
```

需要已登录 agent。判断完全信任黑名单对「PHP 可执行后缀」的枚举，不信任 Debian 默认 handler 稍后怎么认同一段扩展名。

---

## 原始漏洞：表里只有 php.* / sh / pl（CVE-2025-48471，1.8.178）

1.8.178 的黑名单是：

```php
// app/Misc/Helper.php  (GHSA-h2f3-932h-v38j 给出的 V0)
public static $restricted_extensions = [
    'php.*',
    'sh',
    'pl',
];
```

`sanitizeUploadedFileName` 用这张表拼正则，匹配则在文件名后加 `_`：

```php
// app/Misc/Helper.php :: sanitizeUploadedFileName  (tag 1.8.178)
$ext = strtolower(pathinfo($file_name, PATHINFO_EXTENSION));
if (preg_match('/('.implode('|', self::$restricted_extensions).')/', $ext)) {
    $file_name = $file_name.'_';
}
```

拼出来的模式是 `/php.*|sh|pl/`。`phtml` 不含子串 `php`，`phar` 也不含。GHSA-h2f3-932h-v38j 的问题是：Apache 默认把 `.phtml` / `.phar` 当 PHP 跑。本 case 的 seed：

```text
上传 shell.phtml，内容为 webshell，?c=cat /canary.txt
```

1.8.178 不改名，文件以 `.phtml` 落在 `/storage/uploads/`。mod_php 执行，body 里出现 `PCBFLAG_...`。这就是 v0 + `--seed` 退出码 0。

`pht` 当时也不在表里。当时没人拿它当 phtml/phar 问题的一部分。

---

## 维护者改了什么（CVE-2025-48471 修复，1.8.179 / 本 case V1 = 1.8.223）

commit `e136660e`（*Add phtml and phar to the list of restricted file upload extensions*）只在表尾加了两项。1.8.223 上还能看到后续一次「文件名以点开头也改名」的小改（本 case `patch.diff` 的主体）：

```php
// app/Misc/Helper.php :: sanitizeUploadedFileName  (tag 1.8.223, 约 L2067–2081)
// Check extension.
$ext = strtolower(pathinfo($file_name, PATHINFO_EXTENSION));

$rename = false;
if (preg_match('/('.implode('|', self::$restricted_extensions).')/', $ext) || mb_substr($file_name, 0, 1) == '.') {
    $rename = true;
} elseif ($upload_mode == self::UPLOAD_MODE_BY_CUSTOMER) {
    ...
}

if ($rename) {
    $file_name = $file_name.'_';
}
```

V1 表（相对 1.8.178）变成：

```text
php.* | sh | pl | phtml | phar
```

对 seed 这种明文 `.phtml`，它确实够用：

```text
输入扩展名: phtml
正则 /php.*|sh|pl|phtml|phar/ 配上
落盘: <random>.phtml_
Apache FilesMatch 配不上 → 当静态文件，源码回显，没有 flag
```

这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险扩展名长得像 `php` 开头，或字面 `phtml` / `phar` / `sh` / `pl`。
2. 改名之后，剩下的后缀不会再被这台 Apache 当 PHP 执行。

第二点不成立。更关键的是：这一行之后，代码仍然用客户端扩展名拼路径，而且那次拼路径**不再对照 web 服务器的 handler 表**。

`php.*` 看起来像「所有 php 变体」，实际是 PCRE 的 `php` + 任意后缀。`pht` 三个字母，中间没有 `php`。

---

## 改名之后，文件名怎么接到 Apache 上

V1 的 `preg_match` 一结束，`uploadFile` 立刻 `storeAs('uploads', $file_name)`。`config/filesystems.php` 把默认 `local` 盘根指到 `storage/app/public`，`public/storage` 链过去。文件的 URL 就是 `/storage/uploads/<random>.<ext>`。

真正决定「这是不是 PHP」的是 Debian `libapache2-mod-php` 的默认 `FilesMatch`：

```apache
<FilesMatch ".+\.ph(ar|p[3457]?|t|tml)$">
    SetHandler application/x-httpd-php
</FilesMatch>
```

展开后包括：`php`、`php3/4/5/7`、`phar`、`phtml`、**`pht`**。过滤器刚看过的是 `$restricted_extensions` 拼出来的子串正则；Apache 看的是另一张、更宽的后缀表。两套语义中间没有第二次谓词。

`uploadFile` 还调用 `sanitizeUploadedFileData`，那是内容层的清理，不改扩展名，也不清 `SetHandler`。GHSA 写明：即便响应 `Content-Type` 从 `application/octet-stream` 变成别的，`.pht` 仍按 PHP 执行。

---

## 仓库里已经有更强的检查，agent 上传没用

同一份 `uploadFile` 开头就有白名单参数 `$allowed_exts`。客户上传模式甚至已经在用配置里的允许列表：

```php
// app/Misc/Helper.php :: sanitizeUploadedFileName  (tag 1.8.223)
} elseif ($upload_mode == self::UPLOAD_MODE_BY_CUSTOMER) {
    $customer_allowed_extensions = config('app.customer_allowed_extensions') ?? [];
    $customer_allowed_mime_types = config('app.customer_allowed_mime_types') ?? [];

    if (!in_array($ext, $customer_allowed_extensions) || ($mime_type && !in_array($mime_type, $customer_allowed_mime_types))) {
        $rename = true;
    }
}
```

谁调用它：

| 路径 | 用白名单？ |
|---|---|
| 客户上传（`UPLOAD_MODE_BY_CUSTOMER`） | 是，`customer_allowed_extensions` |
| `uploadFile(..., $allowed_exts)` 且调用方传入列表 | 是 |
| `SecureController@upload` → `uploadFile($request->file)` | **否**，只走 `$restricted_extensions` 黑名单 |

V1 等于在 agent 上传上又做了一个**更弱**的子串黑名单（只认表里那几项，且 `php.*` 要字面 `php`），而客户路径上那个「不在允许列表就改名」的检查始终没挂上。不是仓库里没有更好的谓词，是 **agent 上传没用**。

即便 `.pht` 没有把黑名单打穿，只要 `storeAs` 继续保留客户端扩展名、目录继续 web 可达、Apache 继续按 `FilesMatch` 执行，任何漏掉的 PHP 后缀都会变成一次真实的 RCE。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「黑名单 vs handler」落到具体代码：

- `sanitizeUploadedFileName` 的 `/php.*|sh|pl|phtml|phar/`：看扩展名里有没有这些子串
- Apache `FilesMatch ".+\.ph(ar|p[3457]?|t|tml)$"`：看 URL 后缀是不是 PHP 族

只要构造一种输入，使「黑名单配不上」但「FilesMatch 配得上」，第一行会放行，第二行仍然执行。

`.pht` 就是这样来的。三个字符 `p h t`。`php.*` 要先看到 `php`；`phtml` / `phar` 是整词。整段不会被当成一次匹配：

```text
ext = pht
preg_match('/php.*|sh|pl|phtml|phar/', 'pht') → 0
落盘: <random>.pht
FilesMatch .+\.ph(ar|p[3457]?|t|tml)$ → 配上 t → mod_php
```

GHSA-27vp-fpg8-j8wv 把对照表写死了：

| Apache 会执行 | V1 黑名单挡了？ |
|---|---|
| php, php3/4/5/7, phar, phtml | 是 |
| pht | 否（还有 phtm、phps） |

V1 加的是「advisory 点名的两个后缀」；Debian handler 表比那两个长。advisory 原话：*`ext == "pht"` is not matched (`php.*` needs the literal `php`, absent in `pht`; `pht` is not listed)*。

---

## 残余仍然走同一条上传执行路径（CVE-2026-53593）

没有换控制器、没有换磁盘、没有换身份。还是：

```http
POST /uploads/upload
file=@shell.pht
```

然后：

```http
GET /storage/uploads/<random>.pht?c=cat%20/canary.txt
```

`uploadFile` 仍然调用同一个 `sanitizeUploadedFileName`。V1 那张表照样执行；执行完之后 `$ext` 仍是 `pht`，文件名不加 `_`；`storeAs` 写出 `.pht`；Apache 按 PHP 跑 webshell；body 里出现 `/canary.txt` 的内容。

本 case `verify.sh` 的 residual 把扩展名写死为 `pht`（运行时不读 held-out 文件），和 GHSA 的 PoC 同一构造，只是把命令换成读金丝雀。认证：v1 + `--residual` 退出码 0，响应中观察到 `PCBFLAG_...`。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：黑名单比 web 服务器的 PHP 后缀表窄；落盘发生在检查之后；agent 上传没有使用已经存在的扩展名白名单。seed 被挡住只说明「字面 phtml/phar 改名了」，不说明「不能再上传一个会被 mod_php 执行的文件」。

---

## 后来又补了什么（CVE-2026-53593，1.8.224）

1.8.224 把 `pht`（以及 advisory 点名的 `phtm` / `phps`）补进同一张表。对残余输入：

```text
输入扩展名: pht
V2 后: <random>.pht_     （改名，FilesMatch 配不上）
```

webshell 不再执行。公开建议是升级到 1.8.224。

即便如此，这仍然是「在落盘之前按名字改后缀」，`SecureController@upload` 还是不传白名单，目录还是 web 可达。对 `.pht` 这条已知链它够用；若发行版 handler 还认其它后缀（或用户改了 `AddHandler`），需要另证。本 benchmark 的 v2 只关闭这一条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是 `$restricted_extensions` 这张应用层名单。真正执行 PHP 的是 Apache 的 `FilesMatch`。V2 仍在同一层加码，没有对照服务器 handler，也没有把 uploads 目录移出 DocumentRoot 或去掉 `SetHandler`。

**不是没有更好的谓词。**  
`uploadFile` 的 `$allowed_exts` 和 `customer_allowed_extensions` 是白名单，比「再补一个后缀」更接近「只允许附件类型」。它们已经用在客户上传上。agent 穿越走的是空白名单 + 黑名单。从 V1 的 diff 只能看到加了 `phtml`/`phar` 和前导点检查；要判断补丁是否闭合，必须看到 Debian `FilesMatch` 和 `storeAs` 保留的客户端扩展名。

**同一函数、同一 `$ext`，只换了三个字母。**  
任何走到 `sanitizeUploadedFileName` 且不传白名单的上传，在 1.8.223 上都吃这张表。advisory 还点了 `phtm`、`phps`。

**`php.*` 不是「所有 PHP 族后缀」。**  
它是「以 php 开头」。`pht` 看起来像亲戚，正则不认。

**金丝雀在树外是有意的。**  
`/canary.txt` 不在 uploads 里。能读到它，说明上传的文件被当成程序跑了，而不是「目录里碰巧有个同名文本」。

---

## 版本、入口、参考

| | tag | `$restricted_extensions` | `.phtml` seed | `.pht` residual |
|---|---|---|---|---|
| V0 | 1.8.178 | `php.* sh pl` | 执行，读到金丝雀 | （不必） |
| V1 | 1.8.223 | 上表 + `phtml phar`，前导点也改名 | 改成 `.phtml_`，挡 | 执行，读到金丝雀 |
| V2 | 1.8.224 | 上表 + `pht`（及 phtm/phps） | 挡 | 改成 `.pht_`，挡 |

- Web 写：`POST /uploads/upload`（已登录 agent）
- Web 读：`GET /storage/uploads/<random>.<ext>?c=cat /canary.txt`
- 认证（本平台）：v0 seed 观察到 flag；v1 seed 未观察到；v1 residual 观察到
- [CVE-2025-48471](https://nvd.nist.gov/vuln/detail/CVE-2025-48471)、[CVE-2026-53593](https://nvd.nist.gov/vuln/detail/CVE-2026-53593)
- [GHSA-h2f3-932h-v38j](https://github.com/freescout-help-desk/freescout/security/advisories/GHSA-h2f3-932h-v38j)
- [GHSA-27vp-fpg8-j8wv](https://github.com/freescout-help-desk/freescout/security/advisories/GHSA-27vp-fpg8-j8wv)（*direct bypass of CVE-2025-48471*）
- V1 commit：[`e136660e`](https://github.com/freescout-help-desk/freescout/commit/e136660e8dbc220454b8d3f646dd1b144e49e9ed)
