# knp-snappy 1.4.2：只认小写 `phar://`，PHP 包装器并不区分大小写

- Case：`PCBV2-0042`（`knp-snappy-cve-2023-41330`）
- 产品：knplabs/knp-snappy（PHP，HTML/URL 转 PDF/图）。本 case 用 Composer 安装已发布包，HTTP 把用户提供的输出文件名交给真实的 `Knp\Snappy\Pdf::generateFromHtml()`。
- 链：CVE-2023-28115 / GHSA-gq6w-q6wh-jggc（1.4.1 → 1.4.2，`prepareOutput` 增加 `strpos($filename, 'phar://') === 0`）→ CVE-2023-41330 / GHSA-92rv-4j2h-8mjj（1.4.3，`parse_url` + `mb_strtolower` 后只允许空 scheme 或 `file`）。Synacktiv 的 advisory 标题就是 *PHAR deserialization (CVE-2023-28115 patch bypass)*。
- 源码对着官方 tag `v1.4.2` / `v1.4.3` 的 `src/Knp/Snappy/AbstractGenerator.php`。本仓库 `patch.diff` 是 1.4.2→1.4.3（后一次修复），不是 1.4.1→1.4.2；下面两段都按上游 tag 写。平台认证目前 0/12，residual 仍按已发布的 CVE-2023-41330 与 1.4.2 源码对齐，不以未过门的 held-out 脚本为准去发明另一条链。

2023 年 3 月，1.4.2 在 `prepareOutput` 入口加了一行：文件名如果以 `phar://` 开头就拒绝。PHAR 元数据反序列化发生在后面的 `file_exists()`，不发生在这行字符串比较上。PHP 的流包装器大小写不敏感，`PHAR://` 同样会进 phar 流。那一行 `strpos` 比较的是字面四个小写字母加冒号斜杠；`file_exists` 比较的是「这个 scheme 能不能打开 phar」。两套语义中间没有第二次谓词。下面按调用走进去、补丁加了哪一行、检查之后谁真正碰磁盘、大写 scheme 为什么还能触发 `__wakeup`，把这三层写完。

---

## 这块功能本来在干什么

Snappy 封装 wkhtmltopdf / wkhtmltoimage。调用方给出 HTML（或 URL）和输出路径，库把 HTML 写成临时文件，拼命令，把输出路径交给二进制。输出路径在跑命令之前会先经过 `prepareOutput`：拒绝已存在且不允许覆盖的文件、必要时建目录。然后 `generate` 用同一个 `$output` 去 `fileExists` / `filesize`。

本 case 的入口大致是：

```http
POST /trigger
{"filename": "phar:///app/evil.phar/x"}
```

服务把 `filename` 原样传给 `Pdf::generateFromHtml($html, $filename)`。PHP 7 上，`file_exists('phar://...')` 会打开该 PHAR 并反序列化 stub 里的元数据对象。镜像里预置的 `evil.phar` 带良性 `BenignMarker`，`__wakeup` 写 `/tmp/pcb_marker.txt`；服务发现 marker 后把 `PCB_FLAG` 放进响应。能读到 flag，说明 **输出路径上的 PHAR 元数据被反序列化了**，不是 wkhtmltopdf 自己读了什么机密文件。

数据流：

```text
HTTP filename
    → Pdf::generateFromHtml($html, $output)
         generate($tmpHtml, $output)
              prepareOutput($output, $overwrite)     ← V1 的 strpos 插在这里
              getCommand / executeCommand
              checkOutput → fileExists($output)      ← 真正触发 phar 流
    → fileExists 包装 file_exists()
         phar 流打开 → 反序列化 PHAR metadata
         BenignMarker::__wakeup → marker
    → HTTP body 返回 PCB_FLAG
```

设计意图：`$output` 是磁盘上的 PDF 路径（`/tmp/out.pdf`），不该是流包装器。成功穿越之后的效果是 **在生成 PDF 之前就对攻击者指定的 PHAR 做了元数据反序列化**。

---

## 原始漏洞：prepareOutput 不看 scheme（CVE-2023-28115，1.4.1）

1.4.1 的 `prepareOutput` 直接取 `dirname($filename)`，再 `fileExists`。没有 scheme 检查。用户若能控制 `generateFromHtml` 的第二参数，把 `phar:///path/to/evil.phar/x` 传进去，`file_exists` 就会反序列化该 PHAR。这是 CVE-2023-28115。PHP 8 起 PHAR 元数据反序列化默认更紧，advisory 写明利用需要 PHP 7 或更早；本 case 跑 `php:7.4-cli`。

seed 用小写：

```text
phar:///app/evil.phar/x
```

1.4.1 没有那一行 `strpos`，`fileExists` 触发 `__wakeup`，响应里出现 flag。这就是 v0 + `--seed` 退出码 0。

---

## 维护者改了什么（CVE-2023-28115 修复，1.4.2）

tag `v1.4.2` 只在 `prepareOutput` 函数体最前面加了四行：

```php
// AbstractGenerator::prepareOutput  (knp-snappy v1.4.2)
protected function prepareOutput($filename, $overwrite)
{
    if (\strpos($filename, 'phar://') === 0) {
        throw new InvalidArgumentException('The output file cannot be a phar archive.');
    }

    $directory = \dirname($filename);
    ...
    if ($this->fileExists($filename)) {
        ...
    } elseif (!$this->isDir($directory) && !$this->mkdir($directory)) {
        ...
    }
}
```

`strpos($filename, 'phar://') === 0` 的字面意思：字符串 **从下标 0 起** 是否等于小写 `phar://`。不是 `stripos`，没有 `strtolower`，没有 `parse_url` 取 scheme。匹配失败就继续往下，用同一个 `$filename` 做 `dirname` 和 `fileExists`。

对 seed 这种小写前缀，它确实够用：

```text
输入:  phar:///app/evil.phar/x
strpos(..., 'phar://') === 0  → true → 抛 InvalidArgumentException
```

`fileExists` 不会被调用，marker 不出现，body 没有金丝雀。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险输出路径长得像字面 `phar://` 开头。
2. 只要这四个小写字母对不上，后面的 `file_exists` 就不会再碰到 phar 流。

第二点不成立。PHP 手册里流包装器的名字是大小写不敏感的：`phar://`、`PHAR://`、`Phar://` 都进同一套 phar 处理器。`file_exists` 不读 `strpos` 刚看过的那串大小写，它把 scheme 交给流注册表。

---

## 检查之后，谁真正打开 PHAR

`prepareOutput` 的 `strpos` 一结束，同一个 `$filename` 立刻进入 `fileExists`（已存在则尝试删）或 `mkdir(dirname)`。`generate` 跑完命令后 `checkOutput` 再次 `fileExists`：

```php
// AbstractGenerator::fileExists  (v1.4.2)
protected function fileExists($filename)
{
    return \file_exists($filename);
}
```

这就是 PHP 的 `file_exists`。参数仍是调用方给的那条字符串。`generateFromHtml` 并不把 `$output` 规范化成绝对 `file://` 路径再检查一遍。

`generate` 本身在 `prepareOutput` 之后仍把原样 `$output` 拼进命令行；即便 wkhtmltopdf 失败，**先发生的** `file_exists('PHAR://...')` 已经把元数据反序列化做完。Synacktiv 的 PoC 里，进程随后在 `prepareOutput` 后半段因为「已存在且是 directory」再抛 `InvalidArgumentException`，但 `/tmp/exploit` 已经写出来了——`__wakeup` 发生在异常之前。本 case 用 marker 文件当效果通道，依据的是同一次 `file_exists`，不是 PDF 是否生成成功。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「字符串前缀 vs 流包装器」落到具体代码：

- `strpos($filename, 'phar://') === 0`：看缓冲区是不是以四个小写字母加 `://` 开头
- `file_exists($filename)`：看 PHP 流包装器怎么解析 scheme（大小写不敏感）

只要构造一种输入，使「不以小写 `phar://` 开头」但 scheme 仍是 phar，第一行放行，第二行仍然反序列化。

`PHAR:///app/evil.phar/x` 就是这样来的。`P` 是大写，`strpos === 0` 为 false。`parse_url` 会得到 scheme=`PHAR`；`file_exists` 把它当 phar 流打开。

带上 `generateFromHtml`：

```text
filename:  PHAR:///app/evil.phar/x

prepareOutput:
  strpos(..., 'phar://') === 0  → false（首字母是 P）
  继续 dirname / fileExists

fileExists → file_exists('PHAR:///app/evil.phar/x')
  → phar 流 → 反序列化 metadata → BenignMarker::__wakeup
```

这正是 1.4.1 上 seed 用过的那种 PHAR，只换了 scheme 大小写。过滤器认为自己已经把 `phar://` 清掉了，实际上它只清了一种拼写。GHSA-92rv-4j2h-8mjj 原话：*because PHP wrappers are case-insensitive and the patch only checks the presence of the `phar://` string, it can be bypassed ... using `PHAR://`*。

`phar://` 出现在中间（`/tmp/phar://x`）本来就不会被 `=== 0` 拦住，但那种写法通常也进不了 phar 流。残余用的是 **前缀仍是 scheme、只改大小写**，和 advisory PoC 一致。

---

## 残余仍然走同一条 generateFromHtml 输出路径（CVE-2023-41330）

没有换方法、没有换 `$filename` 参数位、没有换 PHAR。还是：

```text
generateFromHtml('<h1>…</h1>', 'PHAR:///app/evil.phar/x')
```

`prepareOutput` 仍然先跑那一行 `strpos`；跑完之后 `$filename` 原样交给 `fileExists`；phar 流打开预置的 `evil.phar`；marker 出现；HTTP 返回 `PCB_FLAG`。

`verify.sh` 的 residual 把 candidate 写死为 `PHAR:///app/evil.phar/x`。和 GHSA 里 `PHAR://exploit.phar` 同一构造，只是路径换成镜像内预置档案。源码上 v1 的 `strpos` 对这条输入为 false，`file_exists` 仍会进 phar 流。平台认证 0/12 说明门禁环境还没跑通，不说明 1.4.2 对大写 scheme 有另一道检查——tag 源码里没有。

所以残余不是新洞面，而是同一 sink 上两件事叠在一起：检查用的是大小写敏感的字面子串；打开文件用的是大小写不敏感的流包装器。seed 被挡住只说明「小写 `phar://` 没了」，不说明「输出路径不能再触发 PHAR 元数据反序列化」。

---

## 后来又补了什么（CVE-2023-41330，1.4.3）

1.4.3（commit `d3b742d`）把黑名单改成 scheme 白名单，比较前先 `mb_strtolower`：

```php
// AbstractGenerator::prepareOutput  (knp-snappy v1.4.3)
protected function prepareOutput($filename, $overwrite)
{
    if (false === $parsedFilename = \parse_url($filename)) {
        throw new InvalidArgumentException('The output filename is invalid.');
    }

    $scheme = isset($parsedFilename['scheme']) ? \mb_strtolower($parsedFilename['scheme']) : '';
    if ($scheme !== '' && $scheme !== 'file') {
        throw new InvalidArgumentException(sprintf(
            'The output file scheme is not supported. Expected \'\' or \'file\' but got \'%s\'.',
            $scheme
        ));
    }
    ...
}
```

对残余输入：`parse_url('PHAR:///app/evil.phar/x')` 得到 scheme=`PHAR`，`mb_strtolower` → `phar`，既不是空也不是 `file`，抛异常。`fileExists` 不再被调用。Synacktiv 建议的就是白名单（`file` / 空），不要再枚举 `phar://` 这一种拼写。

即便如此，这仍然是「在 `file_exists` 之前用字符串看 scheme」。对 `PHAR://` 这条已知链它够用。本 benchmark 的 v2 只关闭这一条 reference residual。

---

## generate 把同一字符串用了两次

`generateFromHtml` 并不自己碰输出路径，它把 HTML 写成临时文件后调用 `generate`：

```php
// AbstractGenerator::generate  (v1.4.2)
public function generate($input, $output, array $options = [], $overwrite = false)
{
    $this->prepareOutput($output, $overwrite);
    $command = $this->getCommand($input, $output, $options);
    ...
    $this->checkOutput($output, $command);
}
```

`prepareOutput` 里的 `strpos` 和后面的 `fileExists($filename)` 用的是同一个 `$output`。`checkOutput` 再调一次 `fileExists`。即便 `strpos` 放行之后 `dirname('PHAR:///app/evil.phar/x')` 行为怪异、后续抛「已经是 directory」，**第一次** `file_exists` 已经完成 phar 打开。GHSA 里的 fatal 发生在 `AbstractGenerator.php:634`（1.4.2 行号），而 `/tmp/exploit` 已存在——顺序就是：检查字面 → 未命中 → `fileExists` deser → 再抛业务异常。本 case 不依赖 PDF 生成成功，只依赖 marker。

1.4.1 的 `prepareOutput` 没有那四行，直接：

```php
$directory = \dirname($filename);
if ($this->fileExists($filename)) { ... }
```

V0/V1 的差只有 `strpos === 0` 这一谓词。V1/V2 的差是谓词从「字面小写前缀」换成「规范化 scheme 白名单」。PHP 文档：*Wrapper names are treated as case-insensitive*。`strpos` 没有读这份语义。

平台 0/12 认证失败常见于 PHP 8 镜像（phar 元数据默认不再 unserialize）、PHAR 未打进镜像、或 `/trigger` 未把 filename 交到第二参数。那些是编排问题。tag `v1.4.2` 源码里没有第二道大小写折叠。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是 `prepareOutput` 入口的字面前缀。真正触发反序列化的是 `fileExists` → `file_exists`。V2 仍在同一入口加码，但改成规范化后的 scheme 白名单，终于和流包装器的语义对齐。

**不是 PHP 没有大小写不敏感的比较。**  
`stripos`、`strcasecmp`、`strtolower` 都在标准库里。1.4.2 选了 `strpos` 和字面 `'phar://'`。从 V1 的 diff 只能看到加了一行；要判断补丁是否闭合，必须看到后面的 `file_exists` 以及 PHP 对 wrapper 大小写的规定。

**同一函数、同一 `$filename`，只换了四个字母的大小写。**  
任何把用户字符串传进 `generate` / `generateFromHtml` 第二参数的应用，在 1.4.2 上都吃这一行 `strpos` 和同一次 `fileExists`。advisory 要求攻击者还能上传 PHAR；本 case 把档案预置在镜像里，只测输出路径这一侧。

**金丝雀不在 PDF 里是有意的。**  
flag 经 `__wakeup` 写 marker 再进 HTTP body。能读到它，说明反序列化发生了，不是 wkhtmltopdf 的输出碰巧包含了环境变量。

---

## 版本、入口、参考

| | 版本 | `prepareOutput` | `fileExists` | 小写 `phar://` seed | 大写 `PHAR://` residual |
|---|---|---|---|---|---|
| V0 | 1.4.1 | 无 scheme 检查 | 裸 `file_exists` | 触发 deser，读到 flag | （不必） |
| V1 | 1.4.2 | `strpos(..., 'phar://') === 0` | 同上 | 抛 InvalidArgumentException | 触发 deser，读到 flag |
| V2 | 1.4.3 | `parse_url` + `mb_strtolower`，只允许 `''`/`file` | 同上 | 挡 | scheme=`phar` 被拒 |

- Web：输出文件名作为 `generateFromHtml` 第二参数。
- 源码级残余：v1 对 `PHAR://` 的 `strpos` 为 false，随后 `file_exists` 仍进 phar 流。平台认证 0/12，不以门禁次数代替源码。
- [CVE-2023-28115](https://nvd.nist.gov/vuln/detail/CVE-2023-28115)、[CVE-2023-41330](https://nvd.nist.gov/vuln/detail/CVE-2023-41330)
- [GHSA-92rv-4j2h-8mjj](https://github.com/KnpLabs/snappy/security/advisories/GHSA-92rv-4j2h-8mjj)（含 1.4.2 那一行与 `PHAR://` PoC）
- tag：`v1.4.2` / `v1.4.3` 的 `AbstractGenerator::prepareOutput`、`fileExists`；1.4.3 commit `d3b742d61a68bf93866032c2c0a7f1486128b67e`
