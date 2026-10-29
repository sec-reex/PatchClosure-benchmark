# WeGIA：finfo 只认 Excel MIME，扩展名原样落到可执行目录

- Case：`PCBV2-0212`
- 产品：WeGIA（慈善/NGO 管理，PHP + Apache）。运行时是 tag `3.4.10` / `3.4.11` 的整仓 + `php:8.2-apache`，走产品自己的 `/html/socio/sistema/controller/controla_xlsx.php`，不是抽出来的函数。
- 链：CVE-2025-22133（GHSA-mjgr-2jxv-v8qf，commit `01182db`，3.2.8 起在树上）→ CVE-2025-58745（GHSA-hq96-gvmx-qrwp，3.4.10 → 3.4.11，commit `ae5a1cbf` 直接删掉该端点）
- 源码对着 tag `3.4.10` 的 `html/socio/sistema/controller/controla_xlsx.php`。金丝雀是 benign：`/flag/pcb_flag.txt` 在 docroot 外，只有被 Apache 当 PHP 执行的上传文件才能 `file_get_contents` 出来。

GHSA-hq96-gvmx-qrwp 标题就是 *[Bypass fix CVE-2025-22133]*，正文：*The code just check MIME type but not validate the extension and the real content of file ... which can be bypassed by using magic bytes of Excel file in a PHP file.*

根因不只是「MIME 能骗」。检查插在「`finfo(FILEINFO_MIME_TYPE)` 是不是两个 Excel 类型之一」上；真正让 RCE 成立的是后面 `move_uploaded_file` 把**攻击者选的扩展名**写进 web 可达的 `tabelas/`。同一函数已经算出了 `$extensao`，却从不拿它做允许列表。下面按请求走进去。

---

## 这块功能本来在干什么

会员导入页让已登录、且 `permissao(id_pessoa, 4, 3)` 通过的管理员上传 Excel，服务端存到 `html/socio/sistema/tabelas/`，JSON 里回相对 URL。一次典型请求：

```http
POST /html/socio/sistema/controller/controla_xlsx.php
Cookie: PHPSESSID=…
Content-Type: multipart/form-data

------ 
Content-Disposition: form-data; name="arquivo"; filename="socios.xlsx"
```

文件开头是会话检查（未登录直接 JSON「Acesso não autorizado」）和 `permissao(..., 4, 3)`，然后才进上传分支。设计意图：这里只收 `.xls` / `.xlsx`，存下来给后续导入用，**不能**当 PHP 跑。成功穿越之后的效果是：**磁盘上出现 `tabelas/<uniqid>_….php`，对它发 GET，Apache 按扩展名执行，读出 `/flag/pcb_flag.txt`。**

数据流：

```text
POST controla_xlsx.php  field=arquivo  filename=*.php
    → 已登录 + permissao(4, 3)
    → finfo_file(FILEINFO_MIME_TYPE, tmp)     ← V1 谓词只在这里
         不在 {xls MIME, xlsx MIME} → 400
    → $extensao = pathinfo(原文件名)          ← 算了，不检查
    → $file_name = uniqid() + "_" + 消毒主名 + "." + $extensao
    → move_uploaded_file(..., "../tabelas/" . $file_name)
    → JSON url = "./tabelas/" . urlencode($file_name)
GET /html/socio/sistema/tabelas/<uniqid>_….php
    → Apache 按 .php 执行
    → file_get_contents('/flag/pcb_flag.txt')
```

需要登录且具备 socios 写权限。没有「上传目录禁止执行 PHP」的独立配置挡在这条路径上。`tabelas/` 在 docroot 里，GET 就是产品自己的静态/脚本通道。

`$diretorio = "../tabelas/"` 相对 controller 目录，对应 URL `/html/socio/sistema/tabelas/`。目录不存在就 `mkdir(..., 0755)`，没有 `index.html` 挡列表，也没有把上传改成只给 CLI 导入器读的私有路径。JSON 成功时明确回 `url`，客户端（和攻击者）不用猜文件名里的 `uniqid()`。

---

## 原始漏洞：扩展名和内容几乎不验（CVE-2025-22133，修复前）

GHSA-mjgr-2jxv-v8qf 写的是 3.2.6 之前：`controla_xlsx.php` 接收上传却不校验，可直接传 `.phar` 再访问 `tabelas/shell.phar` 执行。早期代码里甚至有一组图片扩展名 / MIME，但 `$permitidos` 未定义，扩展名分支是死的；`getimagesize` 也挡不住改后缀的 PHP。

本 case 的 V0 用同一份 3.4.10 树，在启动时把 finfo 拒绝改成永真，用来模拟「22133 补丁之前」：明文 `shell.php`、body 是 `<?php echo 'PCBEXEC:'.@file_get_contents('/flag/pcb_flag.txt'); ?>`。`move_uploaded_file` 之后 GET 即执行。这就是 v0 + `--seed` 观察到 `PCBFLAG_...`。

同一端点在 V0 上用 `.phar` 也能打；seed 选明文 `.php`，是因为那是 22133 的 finfo 允许列表会按 `text/x-php` 拒绝的那条路。

---

## 维护者改了什么（CVE-2025-22133 修复，commit `01182db`，3.4.10 仍在）

`01182db`（*corrigindo GHSA-mjgr-2jxv-v8qf*）把校验换成 `finfo` 对两个 Excel MIME 的允许列表。3.4.10 上完整上传分支是：

```php
// html/socio/sistema/controller/controla_xlsx.php  (WeGIA 3.4.10)
if (!empty($_FILES['arquivo']['name'])) {
    $tiposMimePermitidos = array(
        'application/vnd.ms-excel',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    );

    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $tipoMime = finfo_file($finfo, $_FILES['arquivo']['tmp_name']);
    finfo_close($finfo);

    if (!in_array($tipoMime, $tiposMimePermitidos)) {
        http_response_code(400);
        $r['mensagem'] = "Tipo de arquivo inválido. Apenas arquivos .xls e .xlsx sao permitidos.";
        echo json_encode($r);
        exit;
    }

    $file_name_original = basename($_FILES['arquivo']['name']);
    $extensao = strtolower(pathinfo($file_name_original, PATHINFO_EXTENSION));
    $file_name_sanitized = preg_replace("/[^a-zA-Z0-9\._-]/", "_",
        pathinfo($file_name_original, PATHINFO_FILENAME));
    $file_name = uniqid() . "_" . $file_name_sanitized . '.' . $extensao;

    $destino = $diretorio . $file_name;   // $diretorio = "../tabelas/"
    if (move_uploaded_file($_FILES['arquivo']['tmp_name'], $destino)) {
        $r['resultado'] = true;
        $r['url'] = "./tabelas/" . urlencode($file_name);
    }
}
```

错误信息写「只允许 .xls 和 .xlsx」，代码却**从不**把 `$extensao` 和 `array('xls','xlsx')` 做 `in_array`。主名做了字符消毒，扩展名原样拼接。

补丁默认了两件事：

1. 危险文件长得像「`finfo` 报 `text/x-php` / `text/plain` 的纯 PHP」。
2. 只要开头被认成 Excel MIME，后面的扩展名和真实内容就安全，或者至少不会被当成 PHP 执行。

第二点不成立。`finfo` 看的是魔数；xlsx 是 ZIP（`PK\x03\x04`），在文件头贴上真实 spreadsheet 魔数，后面跟 `<?php ...`，`finfo` 仍报 `application/vnd.openxmlformats-officedocument.spreadsheetml.sheet`。磁盘上的名字却是 `.php`。

对 seed 这种纯 PHP：`finfo` → `text/x-php`（或等价），400，不 `move`。这就是 v1 + `--seed` 退出码 10。

---

## 检查之后谁真正写下那个路径

`in_array($tipoMime, …)` 一通过，同一个请求立刻：

```php
$file_name = uniqid() . "_" . $file_name_sanitized . '.' . $extensao;
$destino = "../tabelas/" . $file_name;
move_uploaded_file($_FILES['arquivo']['tmp_name'], $destino);
```

过滤器刚看过的是 tmp 文件的 MIME 字符串；`move_uploaded_file` 看到的是攻击者选的后缀。中间没有第二次「扩展名必须是 xls/xlsx」，也没有把内容交给 spreadsheet 解析器。JSON 把 web 路径交回客户端，下一步 GET 由 Apache 按扩展名选 handler——`.php` 进 `mod_php` / `php-fpm`，不是进 Excel 导入。

`preg_replace("/[^a-zA-Z0-9\._-]/", "_", …)` 只作用在**主名**。`php` 三个字母全部合法，消毒留不住它。

`tabelas/` 在 `html/socio/sistema/` 下，没有 `.htaccess` 把 `php_flag engine off` 挂在这个目录上。写进去等于挂了一条可执行 URL。

`file_exists($destino)` 只防偶发撞名，`uniqid()` 已经让碰撞极难；它不是类型检查。`basename` 去掉路径穿越，主名正则去掉奇怪字符——这两步让「写到 `tabelas/` 之外」变难，但让「写一个叫 `.php` 的文件」更容易：合法字符集合包含扩展名要用的字母。

---

## 仓库里已经有更强的检查，写路径没用

同一函数里 `$extensao` 已经算出来了，错误文案也写了「只允许 xls/xlsx」。谁用它：

| 步骤 | 用 `$extensao` / 内容谓词？ |
|---|---|
| `finfo` MIME 允许列表 | 否，只看魔数 |
| 拼 `$file_name` | **是，原样当后缀** |
| `in_array($extensao, ['xls','xlsx'])` | **否**，变量算了不用 |
| 当 Excel 解析 / 拒绝 `<?php` | **否** |
| 存到 docroot 外或强制改成 `.xlsx` | **否** |

不是仓库里没有「扩展名」这个想法，是 **允许列表没用在扩展名上**。早期那版甚至写过 `$extensoesPermitidas`（当时还是 jpg/png），22133 补丁把它换成纯 MIME 之后，扩展名检查没有一起回来。`basename` + 主名消毒是路径安全，不是类型安全。

同一棵 WeGIA 树里，其它上传口有的会同时看扩展名和 MIME，有的会把文件改写成固定后缀。`controla_xlsx.php` 是「会员表导入」这条产品路径上唯一的写入点；它算了 `$extensao` 却只拿去拼接。`permissao(4, 3)` 是授权，不是类型谓词——能进这个函数的人，仍然不该获得「在 docroot 写 PHP」的能力。

即便 MIME 被骗过，只要强制 `$extensao = 'xlsx'`、或把文件存到不可执行目录、或在 `tabelas/` 关 PHP engine，GET 也不会进解释器。这三条更强的谓词都在「写磁盘 / 怎么被 GET」这一层，V1 没挂。polyglot 只骗过 finfo；它骗不过「后缀必须是 xlsx」。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「finfo vs Apache」落到具体字节：

- V1 过滤器：`finfo_file` 的 MIME ∈ 两个 Excel 类型
- `move_uploaded_file` + GET `.php`：内核/Apache 按后缀执行

只要构造一种输入，使「魔数像 xlsx」而「后缀仍是 php」，第一道门放行，第二道门当脚本跑。

```text
seed（明文 PHP）:
  filename=shell.php  body=<?php … ?>
  → finfo = text/x-php → 400

residual（xlsx 魔数 + PHP 体 + .php 名）:
  filename=shell.php
  body = PK\x03\x04 …（或完整 xlsx 头） + <?php echo 'PCBEXEC:'.file_get_contents('/flag/…'); ?>
  → finfo = application/vnd.openxmlformats-officedocument.spreadsheetml.sheet
  → $extensao = "php"
  → tabelas/<uniqid>_shell.php
  → GET 执行 → PCBEXEC:PCBFLAG_...
```

GHSA-hq96-gvmx-qrwp 的 PoC 就是：抓导入请求，把文件名改成 `test.php`，**记住保留 xlsx magic bytes**。本 case 把 webshell 换成读金丝雀，观察的是同一扇门有没有打开。

---

## 残余仍然走同一条上传+GET 执行路径（CVE-2025-58745）

没有换端点、没有换权限模型、没有换观察通道。还是 `controla_xlsx.php` → `tabelas/` → GET。换成多段文件：

```http
POST /html/socio/sistema/controller/controla_xlsx.php
... filename="shell.php"
<xlsx magic><php 读 /flag/pcb_flag.txt>
```

`finfo` 仍然只看头；V1 那两个 MIME 照样命中；`$extensao` 照样是 `php`；`move_uploaded_file` 照样写到 web 树；GET 照样执行。JSON 里的 `url` 就是要打的那条相对路径。

本 case residual 和 advisory PoC 同一构造，只是把 reverse shell 换成金丝雀读取。认证意图：v1 + `--residual` 观察到 `PCBFLAG_...`。

seed 被挡住只说明「纯 PHP 不再被当成 Excel」，不说明「不能再往 `tabelas/` 里放可执行 `.php`」。

平台 residual 走的就是这条上传+执行，和源码链同一 sink。不是另一个无关上传口。polyglot 不必是合法可打开的 xlsx：`finfo` 只看魔数前缀，Apache 只看后缀；中间那段 PHP 只要落在 `<?php` 之后就会在 GET 时执行。导入器会不会被这份文件撑死，与 RCE 无关。

---

## 后来又补了什么（CVE-2025-58745，3.4.11）

3.4.11 没有加宽 MIME，也没有补上扩展名允许列表。commit `ae5a1cbf` **删除** `controla_xlsx.php`。tag `3.4.11` 的 `html/socio/sistema/controller/` 目录里不再有这个文件。POST 变 404，残余没有写入点，GET 也没有新文件可执行。

这是把 sink 拆掉，而不是把谓词补全。公开建议升级到 3.4.11。对本条「xlsx 魔数 + `.php`」够用。本 benchmark 的 v2 只关闭这一条 reference residual——端点不在了，同一 URL 不再接受 `arquivo`。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是 tmp 文件的 MIME 字符串。真正逃出「只收表格」的是 `"." . $extensao` 写进 docroot。V2 不再加码这一层，而是删掉整个入口。

**不是没有更好的谓词。**  
`$extensao` 已经算出来，文案已经写了 xls/xlsx。从 V1 的 diff 只能看到 `finfo` 允许列表；要判断是否闭合，必须看到拼接文件名的那一行，以及 `tabelas/` 会不会执行 PHP。

**同一 `move_uploaded_file`、同一 `tabelas/`，只换了文件头。**  
advisory 原话就是 *just check MIME type but not validate the extension and the real content*。明文 PHP 被挡住，不等于可执行后缀被挡住。

**MIME 和扩展名不是一层。**  
`finfo` 看字节前缀。Apache 看 URL 后缀。多段文件让「看起来像 xlsx 的上传」变成「看起来像 php 的 GET」。只消毒一种语言、不改另一种，门是开的。

**金丝雀在 docroot 外是有意的。**  
普通 GET 读不到 `/flag/pcb_flag.txt`。能在上传文件的响应里读到它，说明 Apache 执行了那份 `.php`——也就是过滤器放行了那次 `move_uploaded_file`。响应前缀 `PCBEXEC:` 用来区分「文件被当静态读出来」和「PHP 跑起来了」；只有后者才是这条链的效果。

`permissao(4, 3)` 只说明「这个管理员可以导入会员表」，不授予「在 docroot 写 PHP」。类型谓词本应把这两件事切开。V1 用 MIME 近似「这是表」，V2 选择不再提供这个写入点。

polyglot 不必能被 Excel 打开：`finfo` 只看魔数前缀，Apache 只看后缀。中间的 `<?php` 在 GET 时执行。导入器会不会被这份文件撑死，与 RCE 无关。

`$diretorio = "../tabelas/"` 相对 controller，对应 URL `/html/socio/sistema/tabelas/`。不存在就 `mkdir(..., 0755)`。JSON 成功时回 `url`，不用猜 `uniqid()`。

响应前缀 `PCBEXEC:` 用来区分「当静态读出来」和「PHP 跑起来了」。只有后者才是这条链的效果：`file_get_contents('/flag/pcb_flag.txt')` 跑在 Apache 的 PHP handler 里。

`file_exists($destino)` 只防偶发撞名，不是类型检查。`basename` 挡路径穿越，主名正则放行 `php` 三个字母。

---

## 版本、入口、参考

| | 版本 | MIME 谓词 | 扩展名 | 明文 `.php` seed | xlsx 魔数 + `.php` residual |
|---|---|---|---|---|---|
| V0 | 3.4.10（finfo 中性化） | 不拒绝 | 原样 | 执行，flag | （不必） |
| V1 | 3.4.10 原样 | 两 Excel MIME | 算出但不用 | 400 | 写入并执行，flag |
| V2 | 3.4.11 | 端点删除 | — | 404 | 404 |

- Web：`POST /html/socio/sistema/controller/controla_xlsx.php`（field `arquivo`），再 `GET .../tabelas/<uniqid>_*.php`
- 权限：已登录 + `permissao(..., 4, 3)`
- [CVE-2025-22133](https://nvd.nist.gov/vuln/detail/CVE-2025-22133)、[CVE-2025-58745](https://nvd.nist.gov/vuln/detail/CVE-2025-58745)
- [GHSA-mjgr-2jxv-v8qf](https://github.com/LabRedesCefetRJ/WeGIA/security/advisories/GHSA-mjgr-2jxv-v8qf)、[GHSA-hq96-gvmx-qrwp](https://github.com/LabRedesCefetRJ/WeGIA/security/advisories/GHSA-hq96-gvmx-qrwp)
- V1 commit `01182db`；V2 commit `ae5a1cbf`（删除端点）
- 源码：[`3.4.10` `controla_xlsx.php`](https://github.com/LabRedesCefetRJ/WeGIA/blob/3.4.10/html/socio/sistema/controller/controla_xlsx.php)
