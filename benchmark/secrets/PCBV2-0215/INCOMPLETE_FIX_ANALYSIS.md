# PhpSpreadsheet：`<!DOCTYPE` 扫描前只 decode 一次，双重 UTF-7 留给 libxml

- Case：`PCBV2-0215`
- 产品：PHPOffice/PhpSpreadsheet（PyPI/Packagist 整包）。运行时是 `composer:phpoffice/phpspreadsheet:1.5.0` / `1.5.1` / `1.8.0`，经应用 `POST /upload` → `IOFactory::load()` 走进库自己的 Xlsx reader，不是抽出来的 `scan()`。
- 链：CVE-2018-19277（≤1.5.0 → 1.5.1，`XmlScanner` 单次 charset decode）→ CVE-2019-12331（&lt;1.8.0 → 1.8.0，usd-2019-0046：双重 UTF-7）
- 源码对着 tag `1.5.1` 的 `src/PhpSpreadsheet/Reader/Security/XmlScanner.php`（`scan`）和 `Reader/Xlsx.php`（几乎每份 zip 内 XML 都先 `securityScanner->scan` 再交给 simplexml）。金丝雀是 benign：`/canary/flag.txt`，外部实体 `SYSTEM "file:///canary/flag.txt"` 解析进单元格 A1，再出现在 `/upload` 响应里。

NVD CVE-2019-12331 原话：*The XmlScanner decodes the sheet1.xml from an .xlsx to utf-8 if something else than UTF-8 is declared in the header. This was a security measurement to prevent CVE-2018-19277 but the fix is not sufficient. By double-encoding the xml payload to utf-7 it is possible to bypass the check for the string `<!ENTITY`.*

根因不只是「少 decode 一层」。检查插在「转成 UTF-8 之后的字节里有没有字面 `<!DOCTYPE`」上；真正解析实体的是后面的 libxml。decode 只跑一轮，声明还是 `encoding="UTF-7"` 的第二层留给解析器。下面按调用走进去。

---

## 这块功能本来在干什么

应用收一份用户上传的 `.xlsx`，用官方 API 打开，读 A1。库的 Xlsx reader 会把 zip 里每份 XML（`[Content_Types].xml`、`xl/workbook.xml`、`xl/worksheets/sheet1.xml` …）先交给 `XmlScanner::scan`，再 `simplexml_load_string`。一次典型产品调用：

```php
$ss = \PhpOffice\PhpSpreadsheet\IOFactory::load($uploadedTmpPath);
$v  = (string) $ss->getActiveSheet()->getCell('A1')->getValue();
```

设计意图：spreadsheet 里的 XML 不得声明外部实体；`scan` 看到 `<!DOCTYPE` / ENTITY 就抛异常，load 中止。成功穿越之后的效果是：**libxml 解析 `SYSTEM "file:///canary/flag.txt"`，实体值进 A1，HTTP 响应里出现 `PCBFLAG_...`。**

数据流：

```text
POST /upload  multipart file=.xlsx
    → IOFactory::load
         Xlsx reader 打开 zip
         对每个 XML part:
              XmlScanner::scan($bytes)          ← V1 谓词
                   读 encoding="…"
                   若 ≠ UTF-8：mb_convert_encoding 一次
                   preg_match 字面 <!DOCTYPE（含 \0 间隔变体）
                   命中 → throw
                   否则 return $xml（可能仍带第二层编码）
              simplexml / libxml                ← 再按声明的 charset 解码并解析实体
         单元格 A1 ← 解析后的文本
    → HTTP body  A1=...
```

本 case 钉在 php:7.2.0-cli（libxml 2.9.4）。`XmlScanner::identifyLibxmlDisableEntityLoaderAvailability()` 对 7.2.0 返回 false（要 7.2.1+ 才自动 `libxml_disable_entity_loader(true)`），所以 **regex 是唯一守卫**。这是有意让 1.5.0 / 1.5.1 / 1.8.0 走同一条「只靠扫描」的路径。

`encoding="(.*?)"` 只认双引号声明。UTF-7 的 ASCII 声明正好能被这段正则吃到，所以 V1 会进 `mb_convert_encoding`；问题不在「没认出 UTF-7」，而在「只解一轮」。`mb_convert_encoding` 按 PHP 的 UTF-7 规则还原一层；它不会改 XML 声明里的 `encoding="UTF-7"` 字面量——声明还在，libxml 就还有权再解。

---

## 原始漏洞：只扫原始字节上的 `<!DOCTYPE`（CVE-2018-19277，1.5.0）

1.5.0 的 `BaseReader::securityScan` 在**未做 charset 转换**的字节上找 `<!DOCTYPE`，并允许字节之间插 `\0`：

```php
// BaseReader::securityScan  (PhpSpreadsheet 1.5.0)
$pattern = '/\0?' . implode('\0?', str_split('<!DOCTYPE')) . '\0?/';
if (preg_match($pattern, $xml)) {
    throw new Exception('Detected use of ENTITY in XML, spreadsheet file load() aborted ...');
}
return $xml;
```

NVD：*securityScan() … allows a bypass of protection mechanisms for XXE via UTF-7 encoding in a .xlsx file*。`sheet1.xml` 声明 `encoding="UTF-7"`，把 `<!DOCTYPE` / `<!ENTITY` 编成 UTF-7（例如 `+ADw-!DOCTYPE`），原始字节里没有 ASCII `<!DOCTYPE`，扫描放行；libxml 按 UTF-7 解码后再解析实体。

本 case seed 是单层 UTF-7 的 `sheet1.xml`，实体指向 `file:///canary/flag.txt`。v0 上 `IOFactory::load` 成功，A1 含 flag。

---

## 维护者改了什么（CVE-2018-19277 修复，1.5.1）

1.5.1 抽出 `Reader\Security\XmlScanner`。`scan()` 先读声明的 encoding，非 UTF-8 就 `mb_convert_encoding` **一次**，再跑原来的 `<!DOCTYPE` 模式（默认 `$this->pattern = '<!DOCTYPE'`）：

```php
// XmlScanner::scan  (PhpSpreadsheet 1.5.1)
public function scan($xml)
{
    $pattern = '/encoding="(.*?)"/';
    $result = preg_match($pattern, $xml, $matches);
    $charset = $result ? $matches[1] : 'UTF-8';

    if ($charset !== 'UTF-8') {
        $xml = mb_convert_encoding($xml, 'UTF-8', $charset);  // 只一次
    }

    $pattern = '/\0?' . implode('\0?', str_split($this->pattern)) . '\0?/';
    if (preg_match($pattern, $xml)) {
        throw new Exception('Detected use of ENTITY in XML, spreadsheet file load() aborted ...');
    }

    return $xml;
}
```

构造函数里：若 `identifyLibxmlDisableEntityLoaderAvailability()` 为真，会 `libxml_disable_entity_loader(true)`。7.2.0 上这段不跑。

补丁默认了两件事：

1. 危险 payload 只包一层非 UTF-8（典型是一层 UTF-7）。
2. decode 一次之后，字节里要么出现字面 `<!DOCTYPE`，要么 libxml 也看不到 ENTITY。

第二点不成立。把 payload **再**编一层 UTF-7：声明仍是 ASCII 的 `encoding="UTF-7"`，body 是「UTF-7(UTF-7(`<!DOCTYPE …`))」。`scan` 解码一次，得到的仍是一层 UTF-7，没有 ASCII `<!DOCTYPE`；`return $xml` 之后 libxml 再解一层，ENTITY 出现。

对 seed 这种单层 UTF-7：一次 `mb_convert_encoding` 把 `<!DOCTYPE` 还原成字面量，`preg_match` 命中，抛 `Detected use of ENTITY in XML`。这就是 v1 + `--seed` 退出码 10。

---

## 检查之后谁真正解析实体

`scan` 返回的字符串原样进入 Xlsx reader 的 simplexml 路径。1.5.1 的 `Xlsx.php` 在读 workbook、worksheet、rels 时反复：

```php
$this->securityScanner->scan($this->getFromZipArchive($zip, "$dir/$fileWorksheet"))
```

过滤器刚看过的是「decode 一次之后有没有 `<!DOCTYPE`」；libxml 看到的是返回值上的 XML 声明，并按那个 charset **再**解码。中间没有「decode 之后若 encoding 仍不是 UTF-8 就拒绝」，也没有在 7.2.0 上强制关掉 entity loader。

`Settings::setLibXmlLoaderOptions(LIBXML_DTDLOAD | LIBXML_NOENT)` 是应用侧为了让解析成功的实体进单元格——这是效果通道，不是另一条漏洞面。守卫应当在 `scan` 就把带 DTD 的输入丢掉。许多真实 spreadsheet 上传服务同样会把 A1 / 某列读回给用户，外部实体一旦解析就会进这条反射通道。

A1 能出现 flag，依据是 libxml 解析了 `SYSTEM "file:///canary/flag.txt"`，而不是「表格里碰巧写了同一串字」。xlsx 外壳由库自己的 Writer 生成再换掉 `sheet1.xml`，zip 结构和 Content_Types 合法，reader 会走到 worksheet 那次 `scan`，不会在更早的 rels 上因格式错误退出。

---

## 仓库里已经有更强的检查，二次声明没用

同一份 1.5.1 里已经有 charset 探测和 `mb_convert_encoding`。谁在 decode **之后**再看一眼声明：

| 步骤 | 再读 `encoding=` / 关 entity loader？ |
|---|---|
| `scan` 第一次读 charset | 是 |
| decode 一次 | 是 |
| decode 后再读 charset，非 UTF-8 则抛（V2 `toUtf8`） | **否** |
| 7.2.0 上 `libxml_disable_entity_loader(true)` | **否**，availability 为 false |
| 拒绝一切非 UTF-8 | **否** |

不是仓库里不会 decode，是 **decode 轮数和解析器轮数不对齐**。V2 把「再读一次 encoding」收进 `toUtf8()`：第二次仍不是 UTF-8 就抛 `Suspicious Double-encoded XML`。这个谓词 1.5.1 已经具备所需的两样工具（`preg_match(encoding=)` + `mb_convert_encoding`），只是没有在 return 前再跑一轮。

`libxml_disable_entity_loader` 在更高的 7.2.x 上会开，但本链要测的是扫描器本身；7.2.0 让它成为唯一守卫，这和 1.5.1 作者写的注释一致：*Don't rely purely on libxml_disable_entity_loader()*。

Bishop Fox / #771 公开的是单层 UTF-7；usd-2019-0046 明确说 1.5.1 那次 decode「是为了防 19277，但不够」。维护者在 1.8.0 加的「Suspicious Double-encoded XML」就是把「再读一次 encoding」这条已经能写出来的谓词补上。1.5.1 的 `scan` 在 `return $xml` 前具备再跑同一段 `preg_match('/encoding="(.*?)"/')` 的全部上下文，只是没有写。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「单次 decode + 字面扫描」和「libxml 再解码」落到具体编码层：

- V1 过滤器：最多一层 `mb_convert_encoding`，然后找 ASCII `<!DOCTYPE`
- libxml：按返回 XML 的 `encoding=` 再解码，并加载 DTD/实体

只要构造一种输入，使「decode 一次」之后**仍然**没有字面 `<!DOCTYPE`，但再解一层就有，第一道门放行，第二道门解析实体。

```text
seed（单层 UTF-7）:
  <?xml encoding="UTF-7"?> + UTF-7(<!DOCTYPE … ENTITY …>)
  → scan decode 一次 → 字面 <!DOCTYPE → throw

residual（双层 UTF-7）:
  <?xml encoding="UTF-7"?> + UTF-7( UTF-7(<!DOCTYPE … ENTITY file:///canary/flag.txt>) )
  → scan decode 一次 → 仍是一层 UTF-7，无 ASCII <!DOCTYPE
  → return
  → libxml 再按 UTF-7 解码 → 实体解析 → A1 = flag
```

usd-2019-0046 / NVD 写的就是 *double encode the xml payload to utf-7*。本 case 把实体目标换成金丝雀文件，观察的是同一扇 `scan` → libxml 门。

---

## 残余仍然走同一条 IOFactory::load XXE 路径（CVE-2019-12331）

没有换 API、没有换 zip part、没有换观察通道。还是 `IOFactory::load` 读 `sheet1.xml`：

```text
POST /upload
    file = 合法 xlsx 外壳 + 双重 UTF-7 的 sheet1.xml
           <!ENTITY 指向 file:///canary/flag.txt>
```

`Xlsx` reader 仍然对这份 XML 调同一个 `scan`。V1 那一次 `mb_convert_encoding` 照样执行；执行完仍无字面 `<!DOCTYPE`；`simplexml` 照样按 UTF-7 解析实体；A1 照样进 HTTP body。

本 case residual 和 usd-2019-0046 同一构造。认证意图：v1 + `--residual` 观察到 `PCBFLAG_...`。

seed 被挡住只说明「单层 UTF-7 不再骗过字面扫描」，不说明「不能再让 libxml 在扫描之后自己完成解码」。

平台 residual 走的就是这条 `XmlScanner::scan` → libxml 实体解析，和源码链同一 sink。不是另一个无关的单元格注入。和兄弟 case「UCS-4 / UTF-32 插空字节」不是同一条残余：这里是编码层数，那里是空字节交错。V1 的 `<!DOCTYPE` 模式已经带 `\0?` 间隔，挡得住 UCS-2 式插零，挡不住「声明仍是 UTF-7、body 还套着一层 UTF-7」。

---

## 后来又补了什么（CVE-2019-12331，1.8.0）

1.8.0 把 decode 收进 `toUtf8()`，decode 之后**再读** `encoding=`，仍非 UTF-8 则拒绝：

```php
// XmlScanner::toUtf8  (PhpSpreadsheet 1.8.0)
private function toUtf8($xml)
{
    $charset = /* detect encoding */;
    if ($charset !== 'UTF-8') {
        $xml = mb_convert_encoding($xml, 'UTF-8', $charset);
        $charset = /* detect encoding AGAIN */;
        if ($charset !== 'UTF-8') {
            throw new Reader\Exception(
                'Suspicious Double-encoded XML, spreadsheet file load() aborted ...');
        }
    }
    return $xml;
}
```

对残余输入：第一次 decode 之后声明仍是 UTF-7，抛 `Suspicious Double-encoded XML`，load 中止，A1 不会被实体填上。公开建议升级到 1.8.0。CHANGELOG 把这件事记在 1.8.0（2019-07-01）。

即便如此，这仍然是「decode 后再看声明字符串」，不是循环解到稳定、也不是在 7.2.0 上强制关 entity loader。对本条双重 UTF-7 够用。本 benchmark 的 v2 只关闭这一条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是扫描前的 charset 转换次数。真正解析 `SYSTEM` 文件的是 libxml。V2 仍在扫描层加码，但终于在 return 前确认「现在看起来已经是 UTF-8」。

**不是没有更好的谓词。**  
`encoding=` 探测和 `mb_convert_encoding` 已经在 `scan` 里。从 V1 的 diff 只能看到「decode 一次再扫」；要判断是否闭合，必须看到 return 值还会被 libxml 按声明再解码，以及 7.2.0 上 entity loader 仍开着。

**同一 `scan`、同一 `sheet1.xml`，只换了编码层数。**  
NVD 原话就是 *the fix is not sufficient* / *double-encoding*。单层被挡住，不等于解析器看不到 ENTITY。

**扫描用的字符集和解析用的字符集不是一轮。**  
`scan` 解一层是为了让 `<!DOCTYPE` 变成字面量。libxml 不管你扫过没有，仍按声明解。只对齐一轮，门是开的。

**金丝雀在应用目录外是有意的。**  
xlsx 里没有 flag 字面量。能在 A1 / HTTP body 里读到它，说明外部实体被解析了——也就是 `scan` 把仍带 UTF-7 的 XML 还给了 libxml。`RESULT=LOADED` 且 A1 含 token，和 `RESULT=BLOCKED: … ENTITY` / `Suspicious Double-encoded XML` 是同一条 `load()` 上的两种出口。

`encoding="(.*?)"` 只认双引号。UTF-7 的 ASCII 声明能被吃到，所以 V1 会进 `mb_convert_encoding`；问题不在「没认出 UTF-7」，而在「只解一轮」。`mb_convert_encoding` 不改声明里的 `encoding="UTF-7"` 字面量，libxml 就还有权再解。

V1 的 `<!DOCTYPE` 模式已带 `\0?` 间隔，挡得住 UCS-2 式插零，挡不住「声明仍是 UTF-7、body 还套一层」。那是兄弟 case 的残余，不是这一条。

---

## 版本、入口、参考

| | 版本 | `scan` / 前身 | 单层 UTF-7 seed | 双层 UTF-7 residual |
|---|---|---|---|---|
| V0 | 1.5.0 | 原始字节上找 `<!DOCTYPE` | XXE，flag | （不必） |
| V1 | 1.5.1 | decode **一次**再扫 | `Detected use of ENTITY` | libxml 再解一层，flag |
| V2 | 1.8.0 | decode 后再读 encoding | 挡 | `Suspicious Double-encoded XML` |

- 产品 API：`\PhpOffice\PhpSpreadsheet\IOFactory::load($path)` → Xlsx reader → `XmlScanner::scan`
- 本 case HTTP：`POST /upload`（field `file`）→ 响应里的 A1
- [CVE-2018-19277](https://nvd.nist.gov/vuln/detail/CVE-2018-19277)、[CVE-2019-12331](https://nvd.nist.gov/vuln/detail/CVE-2019-12331)
- [usd-2019-0046](https://herolab.usd.de/security-advisories/usd-2019-0046/)、[PhpSpreadsheet #771](https://github.com/PHPOffice/PhpSpreadsheet/issues/771)
- [1.8.0 CHANGELOG](https://github.com/PHPOffice/PhpSpreadsheet/blob/master/CHANGELOG.md#180---2019-07-01)
- 源码：[`1.5.1` `XmlScanner.php`](https://github.com/PHPOffice/PhpSpreadsheet/blob/1.5.1/src/PhpSpreadsheet/Reader/Security/XmlScanner.php)、[`Xlsx.php` 对 `scan()` 的调用](https://github.com/PHPOffice/PhpSpreadsheet/blob/1.5.1/src/PhpSpreadsheet/Reader/Xlsx.php)；V2 `toUtf8` 见 [`1.8.0` `XmlScanner.php`](https://github.com/PHPOffice/PhpSpreadsheet/blob/1.8.0/src/PhpSpreadsheet/Reader/Security/XmlScanner.php)
