# Vtiger：`mime_content_type` 认 GIF，`saveLogo` 仍按 `.php` 落盘

- Case：`PCBV2-0007`
- 产品：Vtiger CRM（本 case Docker Hub `javanile/vtiger:6.3.0/6.4.0/6.5.0`，真实 Settings → Company Details 上传，admin 会话 + `__vtrftk`）
- 链：CVE-2015-6000（≤6.3.0，客户端 MIME + 弱 `<?php` 正则）→ CVE-2016-1713（6.4.0 加了 `mime_content_type`，仍把原文件名写到 `test/logo/`；NVD 写 *because of an incomplete fix for CVE-2015-6000*）
- 源码对着 6.3.0 / 6.4.0 包里的 `modules/Settings/Vtiger/actions/CompanyDetailsSave.php` 与 `models/CompanyDetails.php`（SourceForge 发行版，与 Mussler advisory 引用一致）。运行时是整份 CRM。金丝雀在 docroot 外 `/flag/pcb_flag.txt`，只有执行上传的 PHP 才能读。

2015-10 的 6.4.0 给 logo 上传加了服务端 MIME sniff。2016-01 Mussler 公开：这是 CVE-2015-6000 的不完整修复——内容像图、扩展名仍是 `.php`，`test/logo/` 可执行。oss-security 上 MITRE 明确 *Use CVE-2016-1713*，并说扩展名问题不算另一张 CVE。

根因不只是「短标签绕过了 `<?php` 正则」。检查插在临时文件的 magic 上；真正 `move_uploaded_file` 的是另一个函数，文件名来自 `$_FILES['logo']['name']`，从来没接到 `$logoSupportedFormats`。下面按请求走进去。

---

## 这块功能本来在干什么

管理员在 CRM Settings → Company Details 上传公司 logo。表单 POST 到 `index.php?parent=Settings&module=Vtiger&action=CompanyDetailsSave`，带 CSRF token `__vtrftk`。通过校验后，文件落到 web 可达的 `test/logo/<原始文件名>`，并复制一份 `application.ico`。

一次典型请求（multipart）：

```http
POST /index.php HTTP/1.1
Content-Type: multipart/form-data; boundary=...

... name="__vtrftk" ...
... name="logo"; filename="pcb_seed.php"
Content-Type: image/gif

<?=file_get_contents('/flag/pcb_flag.txt')?>
```

数据流（6.4.0，本 case 的 V1）：

```text
POST CompanyDetailsSave
    → Settings_Vtiger_CompanyDetailsSave_Action::process
         $logoDetails = $_FILES['logo']
         1. 客户端 MIME: explode('/', $logoDetails['type'])[1]
            必须在 $logoSupportedFormats (jpeg/jpg/png/gif/...)
         2. V1 新增: mime_content_type($tmp_name)
            必须是 image/* 且 subtype 也在 $logoSupportedFormats
         3. preg_match('/(<\?php?(.*?))/i', file_get_contents(tmp))
            命中则 $saveLogo = false
         若 $saveLogo:
              CompanyDetails_Model::saveLogo()
                   $logoName = $uploadDir . $_FILES['logo']['name']
                   move_uploaded_file($tmp, $logoName)
                   copy(..., application.ico)
    → GET /test/logo/pcb_seed.php
         Apache + PHP 按扩展名执行
         短标签回显 /flag/pcb_flag.txt
```

设计意图：logo 必须是图片。成功穿越之后的效果是**在 docroot 下留下可执行 PHP，GET 即 RCE**，读出树外金丝雀。

---

## 原始漏洞：只信 Content-Type，不信磁盘（CVE-2015-6000，6.3.0）

6.3.0 的 `process()` 没有 `mime_content_type`。客户端 `Content-Type: image/gif` 就能过格式表。内容检查是：

```php
// CompanyDetailsSave.php  (6.3.0 与 6.4.0 都有)
$imageContents = file_get_contents($_FILES["logo"]["tmp_name"]);
if (preg_match('/(<\?php?(.*?))/i', $imageContents) == 1) {
    $saveLogo = false;
}
```

`<?php?` 匹配 `<?ph` 或 `<?php`（`p` 被 `?` 量化）。短标签 `<?=` 三个字符对不上。把模式写成 `/<\?/` 就能同时盖住 `<?php`、`<?=`、`<? `；V0/V1 都没这么写。纯文本 PHP（无 GIF 头）在 6.3.0 上既没有 sniff 拦，也没有正则拦。

`saveLogo` 两边一样：

```php
// modules/Settings/Vtiger/models/CompanyDetails.php
var $logoPath = 'test/logo/';
public function saveLogo() {
    $uploadDir = vglobal('root_directory'). '/' .$this->logoPath;
    $logoName = $uploadDir.$_FILES["logo"]["name"];
    move_uploaded_file($_FILES["logo"]["tmp_name"], $logoName);
    copy($logoName, $uploadDir.'application.ico');
}
```

本 case seed：`filename=pcb_seed.php`，body 是带 `<?=` 的纯文本，`Content-Type: image/gif`。6.3.0 写入 `test/logo/pcb_seed.php`，GET 执行，body 里出现 `PCBFLAG_...`。

---

## 维护者改了什么（CVE-2015-6000 修复，6.4.0）

6.4.0（及 6.3 的 2015-10-06 安全补丁）在客户端 MIME 判断**之后**加了服务端 sniff。Mussler 从发行版里摘出的就是这几行：

```php
// modules/Settings/Vtiger/actions/CompanyDetailsSave.php  (vtiger 6.4.0)
                if (!$logoDetails['size'] || !in_array($fileType, Settings_Vtiger_CompanyDetails_Model::$logoSupportedFormats)) {
                    $saveLogo = false;
                }

                //mime type check
                $mimeType = mime_content_type($logoDetails['tmp_name']);
                $mimeTypeContents = explode('/', $mimeType);
                if (!$logoDetails['size'] || $mimeTypeContents[0] != 'image'
                    || !in_array($mimeTypeContents[1], Settings_Vtiger_CompanyDetails_Model::$logoSupportedFormats)) {
                    $saveLogo = false;
                }
 				// Check for php code injection
 				$imageContents = file_get_contents($_FILES["logo"]["tmp_name"]);
 				if (preg_match('/(<\?php?(.*?))/i', $imageContents) == 1) {
                     $saveLogo = false;
                 }
```

对 seed（无图片 magic）：`mime_content_type` 得到 `text/plain`，`$mimeTypeContents[0] != 'image'` → `$saveLogo = false` → 重定向带 `error=LBL_INVALID_IMAGE`，文件不写，GET 404。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险上传的特征是「内容不是 image/*」。
2. 只要 sniff 说是图，写成什么文件名、扩不扩展名成 `.php`，都不可执行——或者正则会抓住 PHP。

两件事都不成立。`mime_content_type` 看文件头；PHP 看扩展名。正则只认 `<?ph`。

---

## 消毒之后，谁真正写下那个文件

`$saveLogo === true` 之后，`saveLogo()` 用 **`$_FILES['logo']['name']` 原样**拼路径。没有：

- 把扩展名改成 sniff 得到的 subtype；
- 对照 `$logoSupportedFormats` 再查一遍扩展名；
- `getimagesize` 失败则拒绝；
- 重新编码成真正的 JPEG/PNG。

`move_uploaded_file` 把临时文件（GIF 头 + PHP）写到 `test/logo/pcb_bypass.php`。Apache 的 `mod_php` 按 `.php` 把整份文件交给解释器；GIF 字节当垃圾输出，`<?=...?>` 执行。

过滤器刚看过的是 tmp 的 MIME；open（这里是 PHP 引擎）看到的是带 `.php` 的 web 路径。中间没有第二道文件名谓词。

---

## 仓库里已经有更强的检查，写路径没用上

`$logoSupportedFormats` 已经在同一条 `process()` 里用来限制 **MIME subtype**。它没有被用来限制 **文件名后缀**。`saveLogo` 甚至看不到这张表。

内容正则也已经在拦 PHP，但写法是 `<?php?`：

```text
<?php   →  命中
<?ph    →  命中（php? 让 p 可选……实际是 `php?` 量化 p）
<?=     →  不命中
<?      →  不命中
```

把正则改成 `<\?` 就能盖住短标签；把保存名改成 `logo.gif`（忽略用户文件名）就能让 Apache 不当 PHP 执行。两条谓词都在旁边，V1 一个都没接到 `move_uploaded_file` 上。

6.5.0 上本平台观察到 `LBL_INVALID_IMAGE` + GET 404，GIF+`<?=` polyglot 被挡住——那是后续版本又加严了内容/扩展，不是 6.4.0 这道 sniff 本身变完整。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「sniff vs 落盘名」落到具体字节：

```text
seed（无 magic）:
  filename=pcb_seed.php
  body=<?=file_get_contents('/flag/pcb_flag.txt')?>
  Content-Type: image/gif
  → mime_content_type = text/plain → V1 拒绝

residual（GIF89a + 同一短标签）:
  filename=pcb_bypass.php
  body=GIF89a....<?=file_get_contents('/flag/pcb_flag.txt')?>
  Content-Type: image/gif
  → 客户端 MIME gif          过
  → mime_content_type=image/gif  过（V1 新增的门）
  → 正则无 <?ph              过
  → saveLogo 写成 test/logo/pcb_bypass.php
  → GET 执行，body 含 PCBFLAG_...
```

Mussler 的公开 PoC 用 JPEG magic + EXIF 里的 `<? system(...) ?>`（有的环境短标签关着就用完整标签藏在二进制里，正则对二进制里的 `<?php` 仍可能误伤；本 case 用 `<?=` 明确绕开这张正则）。NVD 概括为 *crafted image file with an executable extension*。

---

## 残余仍然走同一条 Company Details 上传路径（CVE-2016-1713）

没有换模块、没有换目录、没有换身份。还是管理员 POST logo，还是 `CompanyDetailsSave_Action::process` → `saveLogo` → `GET /test/logo/<name>.php`。

本 case residual candidate：

```text
filename     = pcb_bypass.php
content_kind = gif_polyglot    # GIF89a + <?=
content_type = image/gif
```

和 Mussler / oss-security 同一 sink。认证：v1 residual GET 到上传文件后观察到 flag。NVD 原句：*NOTE: this vulnerability exists because of an incomplete fix for CVE-2015-6000.*

seed 被挡住只说明「纯文本不再被当成图」，不说明「带图头的 `.php` 不能执行」。

客户端 MIME 检查在 V0/V1 都在，而且读的是攻击者控制的 multipart `Content-Type`。V1 没有删掉它，只是在后面加了 sniff。两条都过之后才轮到正则。所以残余要同时满足三件事：`image/gif` 头、GIF magic、没有 `<?ph` 子串、文件名以 `.php` 结尾。少任何一条：要么 6.3.0 上已经能打（纯文本），要么 6.4.0 上 sniff 会挡。polyglot 是专门打「只加了第 2 条」的形状。

`test/logo/` 在 web 根下且没有 `.htaccess` 禁止 PHP。`saveLogo` 还 `copy()` 一份 `application.ico`；那份是图标，不执行。RCE 通道是带原始扩展名的那一份。CERT/CC 把「可执行扩展名」和「内容像图」写进同一条 CVE-2016-1713，没有拆成两个洞号。

`$logoSupportedFormats` 在 model 里是静态数组（jpeg/jpg/png/gif/pjpeg/x-png）。`process()` 用它检查了两次 MIME，一次客户端、一次 sniff，**零次**检查 `pathinfo($logoDetails['name'], PATHINFO_EXTENSION)`。把这一行接到 `$saveLogo` 上，`.php` 会直接失败，polyglot 也过不去——V1 没写。

上传还依赖登录后的 `__vtrftk`。本 case 用安装种子账号 `admin/admin` 走真实表单；NVD 写 *remote authenticated users*。未登录打不到这个 action，但鉴权不是本洞的修复层。

---

## 后来又补了什么

公开 6.4.0 没有对应的「V2 一次改完扩展名 + 正则」的单 commit（6.x 不在 GitHub 主线）。本平台在 `javanile/vtiger:6.5.0` 上对同一 GIF polyglot 看到 `LBL_INVALID_IMAGE` 且 `test/logo/pcb_bypass.php` 404，当作这条 residual 的关闭点。分析不把 6.5.0 的内部 diff 说成已在 6.4.0 源码里读到——那是运行观察。

正道修复是：忽略用户文件名、只允许白名单扩展、保存前重编码图片、或禁止在 `test/logo/` 执行 PHP。6.4.0 只做了 sniff。

---

## 从这条链还能看出什么

**维护者改错了哪一层。**  
他们改的是 tmp 文件的 MIME。真正变成 RCE 的是 `saveLogo` 用原始 `.php` 名写入 docroot。V1 没碰这一层。

**不是没有更好的谓词。**  
`$logoSupportedFormats` 就在旁边。正则已经在扫内容，只是写窄了。`saveLogo` 不调用任何一个来约束文件名。从 V1 的 diff 只能看到 `mime_content_type`；要判断是否闭合，必须看到 `$_FILES['logo']['name']` 原样拼接。

**同一 `process()`、同一 `test/logo/`，只换了文件头。**  
任何让 sniff 返回 `image/*`、又让 PHP 当脚本执行的 polyglot，在 6.4.0 上都是这条残余。

**金丝雀在 docroot 外是有意的。**  
普通 GET 读不到 `/flag/pcb_flag.txt`。token 出现在 `/test/logo/*.php` 的响应里，说明上传文件被当成 PHP 执行。

---

## 版本、入口、参考

| | 版本 | `process()` | `saveLogo` | 纯文本 `.php` seed | GIF+`<?=` residual |
|---|---|---|---|---|---|
| V0 | 6.3.0 | 客户端 MIME + `<?php?` 正则 | 原名写入 `test/logo/` | 执行，读到金丝雀 | （不必） |
| V1 | 6.4.0 | 加上 `mime_content_type` 必须 image/* | 同上 | LBL_INVALID_IMAGE，404 | 执行，读到金丝雀 |
| V2 | 6.5.0（本平台观察） | 更严，polyglot 被拒 | — | 挡 | LBL_INVALID_IMAGE，404 |

- Web：Settings Company Details 上传；GET `/test/logo/<name>.php`
- 认证（本平台）：v0 seed 观察到 flag；v1 seed 404；v1 residual 观察到。
- [CVE-2015-6000](https://nvd.nist.gov/vuln/detail/CVE-2015-6000)、[CVE-2016-1713](https://nvd.nist.gov/vuln/detail/CVE-2016-1713)（*incomplete fix for CVE-2015-6000*）
- [Mussler 2016-01-12](https://b.fl7.de/2016/01/vtiger-crm-6.4-auth-rce.html)
- [oss-security 2016/01/12](https://www.openwall.com/lists/oss-security/2016/01/12/4)
- V1 源码：发行版 `modules/Settings/Vtiger/actions/CompanyDetailsSave.php`（与 advisory 引用一致；6.x 无 GitHub tag 作 blob）
