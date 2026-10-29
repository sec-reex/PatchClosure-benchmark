# PhpSpreadsheet：Utf8 扫描按最多一个 NUL，UCS-4 三个 NUL 从中间穿过

- Case：`PCBV2-0014`
- 产品：PHPOffice PhpSpreadsheet。Xlsx 阅读器在 `IOFactory::load` 里用 `XmlScanner` 挡 XXE，然后再交给 libxml / SimpleXML。
- 链：CVE-2019-12331（1.7.0 → 1.8.0 起的 charset 双编码复查；1.29.2 已含这条血统）→ CVE-2024-47873（1.29.2 → 1.29.4，`findCharSet` 先剥全部 NUL / BOM，`scan` 把 `\0?` 改成 `\0*` 并在 toUtf8 前后各扫一次）
- 源码对着 GitHub tag `1.29.2` / `1.29.4` 的 `src/PhpSpreadsheet/Reader/Security/XmlScanner.php`。运行时装的是 Composer 整包。

2019 年 usd 的 USD-2019-0046 / CVE-2019-12331：XmlScanner 为了挡更早的 UTF-7 XXE，会按声明的 encoding 转成 UTF-8 再找 `<!DOCTYPE`。双 UTF-7 能让第一次转换后声明仍是 UTF-7，字面 `<!DOCTYPE` 不出现，libxml 再解一层。1.29.x 的 `toUtf8` 转换后再跑一遍 `findCharSet`，第二次仍不是 UTF-8 就抛 `Suspicious Double-encoded XML`。GHSA-jw4x-v69f-hh5w / CVE-2024-47873：*the regexes used in the scan method and the findCharSet method can be bypassed by using UCS-4 and encoding guessing as described in https://www.w3.org/TR/xml/#sec-guessing-no-ext-info.*

根因不只是「又一种编码」。检查插在「ASCII 正则能否在字节流里看见 `encoding="..."` 和 `<!DOCTYPE`」；真正解析 XML 的是 libxml，它按 W3C 无外部信息时的猜测规则认 UTF-32。同一次 `scan` 里已经 `libxml_disable_entity_loader(true)`（PHP < 8），但 Php 8 上这函数没了，注释写着 *Don't rely purely on libxml_disable_entity_loader()*。下面按 xlsx 走进去、1.29.2 改了哪一层、扫描之后谁把字节交给 libxml、剥光 NUL 的谓词有没有挂上，把这几层写完。

---

## 这块功能本来在干什么

xlsx 是 zip，里面的 `xl/worksheets/sheet1.xml` / `xl/workbook.xml` 是 XML。`IOFactory::load` 走到 Xlsx reader 时，每个 XML 部件先经 `XmlScanner::scan`，再 `simplexml_load_string`。应用侧一次典型上传：

```http
POST /upload  multipart file=.xlsx
```

处理链：

```text
上传的 xlsx
    → IOFactory::load
         Xlsx reader 解开 zip 里的 XML
         XmlScanner::scan($xml)
              disableEntityLoaderCheck()
              toUtf8($xml)           ← findCharSet + 必要时 mb_convert
              preg_match( / \0? < \0? ! \0? D ... / )
         libxml 解析（可能再猜编码、展开 ENTITY）
    → 单元格 A1 的文本回到 HTTP 响应
```

设计意图：任何带 `<!DOCTYPE` / `<!ENTITY` 的表格都拒绝加载，外部实体不能读服务器文件。成功穿越之后的效果是：**扫描器认为没有 DOCTYPE，libxml 却展开了 `SYSTEM "file:///canary/flag.txt"`**，A1 里出现 `PCBFLAG_...`。

`getInstance` 对普通 reader 用 pattern `'<!DOCTYPE'`，对 HTML reader 用 `'<!ENTITY'`。xlsx 走前者。

---

## 原始漏洞：双 UTF-7 让 `<!DOCTYPE` 在扫描时不出现（CVE-2019-12331，1.7.0）

1.7.0 的扫描器会按声明 encoding 做**一次** `mb_convert_encoding` 到 UTF-8，然后在结果里找 DOCTYPE。NVD CVE-2019-12331：*By double-encoding the xml payload to utf-7 it is possible to bypass the check for the string `<!DOCTYPE`.* usd 写这是对更早 UTF-7 修复的不足。

双 UTF-7 的 sheet 头部仍是 ASCII `<?xml encoding="UTF-7"?>`，实体部分再套一层 UTF-7。一次转换之后声明还在 UTF-7，字面 `<!DOCTYPE` 仍不以 UTF-8 出现，scan 放行；libxml 再按 UTF-7 解开 ENTITY。

本 case seed 就是这种双 UTF-7 sheet（base64 藏在 original_poc 里）。1.7.0 上 A1 出现金丝雀。

---

## 维护者改了什么（CVE-2019-12331 血统，1.29.2）

1.29.2 的 `toUtf8` 转换后再跑 `findCharSet`；若仍不是 UTF-8，视为双编码：

```php
// XmlScanner.php  (1.29.2)
private function toUtf8($xml)
{
    $charset = $this->findCharSet($xml);
    if ($charset !== 'UTF-8') {
        $xml = self::forceString(mb_convert_encoding($xml, 'UTF-8', $charset));
        $charset = $this->findCharSet($xml);
        if ($charset !== 'UTF-8') {
            throw new Reader\Exception('Suspicious Double-encoded XML, spreadsheet file load() aborted to prevent XXE/XEE attacks');
        }
    }
    return $xml;
}

private function findCharSet(string $xml): string
{
    $patterns = [
        '/encoding\\s*=\\s*"([^"]*]?)"/',
        "/encoding\\s*=\\s*'([^']*?)'/",
    ];
    foreach ($patterns as $pattern) {
        if (preg_match($pattern, $xml, $matches)) {
            return strtoupper($matches[1]);
        }
    }
    return 'UTF-8';
}

public function scan($xml)
{
    $xml = "$xml";
    $this->disableEntityLoaderCheck();
    $xml = $this->toUtf8($xml);
    $pattern = '/\\0?' . implode('\\0?', str_split($this->pattern)) . '\\0?/';
    if (preg_match($pattern, $xml)) {
        throw new Reader\Exception('Detected use of ENTITY in XML, ...');
    }
    ...
    return $xml;
}
```

`str_split('<!DOCTYPE')` 再插入 `\0?`，得到「每个字母之间最多一个 NUL」——够匹配 UTF-16 的 `00 3C 00 21 ...`，不够匹配 UTF-32 的 `00 00 00 3C 00 00 00 21 ...`。

对 seed 这种双 UTF-7，它确实够用：第一次 `findCharSet` 用 ASCII 正则读到 `UTF-7`，转换后再读仍是 UTF-7，抛 `Suspicious Double-encoded XML`。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 编码声明能被那两条 **8 位** ASCII 正则看见；看不见就当 UTF-8，不必转换。
2. 危险的 `<!DOCTYPE` 即使隔着 NUL，也最多隔一个（16 位）。

两点在 UCS-4 / UTF-32 上都不成立。W3C XML 1.0 §4.3.3 / F 附录：没有 encoding 声明、没有外部信息时，处理器按前几个字节猜；`00 00 00 3C` 就是 UTF-32BE 的 `<`。

---

## 消毒之后，字节怎么接到 libxml 上

`scan` 的 `preg_match` 一结束，返回的仍是**原始或 toUtf8 之后的字节**（UCS-4 路径上 `findCharSet` 失败则 `toUtf8` 原样返回）。Xlsx reader 把这份字符串交给 SimpleXML / libxml。libxml 不使用 PhpSpreadsheet 的 `findCharSet`；它自己猜编码、自己展开 ENTITY。

过滤器刚看过的是「正则眼中的 ASCII / 单 NUL」；解析器看到的是四字节宽字符流。两套编码语义中间没有「禁止非 UTF-8 输入」或「剥光 NUL 再扫」的第二次谓词。

PHP 8 上 `libxml_disable_entity_loader` 已移除，`disableEntityLoaderCheck` 变成空操作。1.29.2 注释明确说不要只靠它。本 case V1/V2 跑在 php:8.2 上，ENTITY 能否展开完全取决于 scan 有没有先拒绝。

GHSA 的 PoC 把 payload 放进 `workbook.xml`，用 CyberChef 做成 UCS-4，打开表格时会向 `127.0.0.1:12345` 发 HTTP——即外部实体被解析。本 case 把 SYSTEM 改成 `file:///canary/flag.txt`，把结果反射进 A1。

---

## 仓库里已经在插 NUL，只插了「零或一个」

`scan` 明明知道 UTF-16 会在 ASCII 字母之间插 `00`，所以写了 `\0?`。这是一张「我们考虑过多字节」的收据，强度却停在 16 位。

谁处理 NUL / BOM：

| 函数（1.29.2） | 对 NUL / 宽编码 |
|---|---|
| `findCharSet` | 无。正则要连续的 `encoding="` |
| `toUtf8` | 只信 `findCharSet` 的返回值 |
| `scan` 的 pattern | `\0?` 每个间隙最多一个 |
| 1.29.4 `findCharSet` | BOM 探测 + `str_replace("\0", '', $xml)` 后再跑 encoding 正则 |
| 1.29.4 `scan` | `\0*`，并且 **toUtf8 前后各 match 一次** |

不是没有「先去掉 NUL 再当 ASCII 看」这种谓词。1.29.4 才加上。1.29.2 的双编码复查只覆盖「声明能被 ASCII 正则读到、转换后声明还在」的 UTF-7 形状。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「ASCII 正则 vs libxml 猜测」落到具体字节。

残余用 UTF-32BE、声明 `encoding="UTF-16"`、无 BOM（本 case 实证向量 `ucs4be_declUTF16_nobom`）：

```text
字节前缀: 00 00 00 3C 00 00 00 3F 00 00 00 78 ...     （"<", "?", "x", ...）
声明区:   encoding = "UTF-16"  但每个 ASCII 字符后跟三个 00
```

`findCharSet`：`/encoding\s*=\s*"([^"]*?)"/` 要连续的 `encoding`，中间的 `00` 打断匹配，返回默认 `'UTF-8'`。`toUtf8` 认为已是 UTF-8，**不做** `mb_convert`。`scan` 的 `\0?` 在 `<` 和 `!` 之间要吞三个 `00`，匹配失败。libxml 看见 `00 00 00 3C`，按 W3C 猜 UTF-32BE，解码出：

```xml
<!DOCTYPE x [ <!ENTITY xxe SYSTEM "file:///canary/flag.txt"> ]>
...
<t>&xxe;</t>
```

实体展开，A1 变成金丝雀。GHSA 写 *the regex does not expect null bytes, and the XML library will also autodetect the encoding*。

双 UTF-7 seed 在 V1 上被挡，只说明「声明仍能被 ASCII 正则看见的二次 UTF-7」没了。UCS-4 让声明和 DOCTYPE **对正则不可见**，对 libxml 可见。

---

## 残余仍然走同一条 XmlScanner → libxml XXE（CVE-2024-47873）

没有换 IOFactory、没有换 SYSTEM 路径、没有换 A1 反射。还是：

```text
xlsx 里的 sheet XML（UTF-32BE + ENTITY file:///canary/flag.txt）
→ scan() 放行 → libxml 展开 → A1
```

`scan` 仍然 `toUtf8` 再 `\0?` match。两次都 miss；ENTITY 进解析器。

本 case residual 以无 BOM 的 UTF-32BE + 声明 UTF-16 为确认向量；带 BOM 的变体也能绕过扫描器（RESULT=LOADED），但 libxml 不一定把实体写进单元格。认证意图：v1 + `--residual` 在 /upload 响应里观察到 `PCBFLAG_...`。双 UTF-7 seed 在同一 V1 上抛 Suspicious Double-encoded XML。

所以残余不是新洞面，而是同一扫描器上三件事叠在一起：编码探测用 8 位正则；DOCTYPE 探测只容忍一个 NUL；真正的 XML 消费者按四字节猜编码并展开实体。seed 被挡住只说明「UTF-7 双编码这一形」没了，不说明「不能再让表格 XML 读出 `/canary/flag.txt`」。

与 utf7 兄弟 case 的差别：那边残余仍是 UTF-7 多层解码；这里是更宽的字宽让探测正则失效。sink 都是 `XmlScanner::scan`。

---

## 后来又补了什么（CVE-2024-47873，1.29.4）

1.29.4 同时加宽探测和扫描：

```php
// XmlScanner.php  (1.29.4)
private function findCharSet(string $xml): string
{
    if (substr($xml, 0, 4) === "\x4c\x6f\xa7\x94") {
        throw new Reader\Exception('EBCDIC encoding not permitted');
    }
    $encoding = Reader\Csv::guessEncodingBom('', $xml);
    if ($encoding !== '') {
        return $encoding;
    }
    $xml = str_replace("\0", '', $xml);
    if (preg_match(self::ENCODING_PATTERN, $xml, $matches)) {
        return strtoupper($matches[2]);
    }
    return 'UTF-8';
}

public function scan($xml)
{
    $this->disableEntityLoaderCheck();
    $pattern = '/\\0*' . implode('\\0*', str_split($this->pattern)) . '\\0*/';
    $xml = "$xml";
    if (preg_match($pattern, $xml)) {          // 转换前
        throw new Reader\Exception('Detected use of ENTITY ...');
    }
    $xml = $this->toUtf8($xml);
    if (preg_match($pattern, $xml)) {          // 转换后
        throw new Reader\Exception('Detected use of ENTITY ...');
    }
    ...
}
```

`toUtf8` 另外禁止 UTF-7、检查「转换后 XML 声明还在不在」（双编码）。对残余 UTF-32：`\0*` 在转换前就能配上 `<!DOCTYPE`（字母之间任意多个 NUL），抛 `Detected use of ENTITY`。公开修复：1.29.4 / 2.1.3 / 2.3.2 / 3.4.0。

即便如此，这仍然是「在 libxml 之前用正则近似」。若还有 libxml 能认、正则仍看不见的编码，需要另证。本 benchmark 的 v2 只关闭 UCS-4/UTF-32 这条 residual。NVD 有一处把 1.29.4 误写成 1.9.4，以 GHSA 的 patched versions 为准。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是「声明 encoding 转换后再读一遍」。真正展开实体的是 libxml。V1 仍把「正则看不见」当成「是 UTF-8、没有 DOCTYPE」。V2 仍在同一 `XmlScanner` 里加宽正则，没有改成「强制 UTF-8 输入」或「打开 libxml 的 NONET + 禁用实体」作为唯一来源。

**不是没有更好的谓词。**  
`\0*` 比 `\0?` 只差一个量词。BOM 探测在 `Csv::guessEncodingBom` 里已经存在。从 1.29.2 只能看到双编码复查和单 NUL；要判断补丁是否闭合，必须对照 W3C 猜测表里 UTF-32 的四字节模式，以及 scan 的 pattern 是 `?` 还是 `*`。

**同一 `scan()`，只换了 XML 的字宽。**  
双 UTF-7 和 UCS-4 都是「扫描器的编码模型和 libxml 的编码模型不一致 → ENTITY 活到解析期」。flag 都是 A1 里的文件内容。

**注释已经不信任 libxml_disable_entity_loader。**  
PHP 8 上它不存在。扫描器就是唯一的门。门的正则比解析器的编码猜测窄，门就是开的。

---

## 版本、入口、参考

| | PhpSpreadsheet | `findCharSet` / `scan` | 双 UTF-7 seed | UTF-32BE residual |
|---|---|---|---|---|
| V0 | 1.7.0 | 单次转换，无双编码复查 | A1 金丝雀 | （不必） |
| V1 | 1.29.2 | 二次 findCharSet；`\0?` | Suspicious Double-encoded XML | 正则 miss，libxml 展开 ENTITY |
| V2 | 1.29.4 | 剥 NUL + BOM；`\0*` 前后各扫 | UTF-7 not permitted / ENTITY | 转换前 `\0*` 命中 ENTITY |

- Web：`POST /upload` → `IOFactory::load` → 响应 A1
- 认证意图：v0 seed 观察到 flag；v1 seed BLOCKED；v1 residual 观察到 flag。
- [CVE-2019-12331](https://nvd.nist.gov/vuln/detail/CVE-2019-12331)、[usd-2019-0046](https://herolab.usd.de/security-advisories/usd-2019-0046/)
- [CVE-2024-47873](https://nvd.nist.gov/vuln/detail/CVE-2024-47873)、[GHSA-jw4x-v69f-hh5w](https://github.com/PHPOffice/PhpSpreadsheet/security/advisories/GHSA-jw4x-v69f-hh5w)
- [W3C XML encoding guessing](https://www.w3.org/TR/xml/#sec-guessing-no-ext-info)
- 源码：[XmlScanner.php @ 1.29.2](https://github.com/PHPOffice/PhpSpreadsheet/blob/1.29.2/src/PhpSpreadsheet/Reader/Security/XmlScanner.php)、[1.29.4](https://github.com/PHPOffice/PhpSpreadsheet/blob/1.29.4/src/PhpSpreadsheet/Reader/Security/XmlScanner.php)
