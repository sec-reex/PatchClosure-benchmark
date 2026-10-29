# Froxlor DNS：LOC/RP/SSHFP/TLSA 验过了，TXT 只加了引号

- Case：`PCBV2-0039`
- 产品：Froxlor（服务器面板）
- 链：CVE-2026-30932（2.3.4 → 2.3.5）→ CVE-2026-41234（2.3.5 → 2.3.7）
- 源码对着官方 tag `2.3.5` 的 `lib/Froxlor/Api/Commands/DomainZones.php`、`lib/Froxlor/Validate/Validate.php`、`lib/Froxlor/Dns/Dns.php`。运行时是整包 git tag + 真实 `DomainZones.add` + `froxlor:cron -r 4` 写 BIND zone，不是抽出来的正则。

2026 年 3 月，Froxlor 2.3.5 给 `DomainZones.add` 的 LOC / RP / SSHFP / TLSA 分支加上了 `Validate::validateDnsLoc` 等函数：按字段个数、域名、十六进制长度拒绝非法 `content`。GHSA-x6w6-2xwp-3jh6 / CVE-2026-30932 针对的是记录内容里的换行会打进 zone 文件。三个月后 GHSA-37m5-m4q3-fc6x / CVE-2026-41234 写明 *This is an incomplete fix for CVE-2026-30932 ... which patched the same newline injection for LOC, RP, SSHFP, and TLSA record types but did not patch TXT records.* NVD 几乎逐字引用。

根因不只是「TXT 忘了写 validator」。检查插在按 `type` 分派的 elseif 链上；真正写成 zone 行的是 `DnsEntry::__toString`（`record TTL IN TYPE content\n`）；文件开头还有一行 TODO *regex validate content for invalid characters*，从未对所有类型执行。下面按请求走进去、补丁改了哪几个分支、检查之后谁去写 zone、仓库里已经有什么更强的谓词、残余怎么用 TXT 的 `encloseTXTContent` 把同一条 `; pcb_<FLAG>` 写进 `/etc/bind/domains/pcb.local.zone`。

---

## 这块功能本来在干什么

Froxlor 让 DNS 已启用的客户通过 API 往自己的 BIND 域里加记录。`DomainZones.add` 把 `record/type/content/ttl` 存进 `panel_domains_dns`。DNS 重建 cron（`froxlor:cron -r 4`）调用 `Dns::createDomainZone`，每条 `DnsEntry` 变成 zone 文件里的一行。

一次典型请求：

```http
POST /api.php
{"header":{"apikey":"...","secret":"..."},
 "body":{"command":"DomainZones.add",
         "params":{"domainname":"pcb.local","type":"RP","content":"mbox.example.com. txt.example.com."}}}
```

设计意图：`content` 是该类型的合法 RDATA。成功穿越之后的效果是 **换行把一条 RDATA 拆成 zone 文件里的第二行**，从而注入 BIND 注释、`$INCLUDE`、额外记录。本 case 把注入行写成 `; pcb_<FLAG>`，oracle 读 zone 文件的注释行。

数据流：

```text
POST DomainZones.add  type + content
    → trim(content)
    → 按 type 走 elseif
         A/AAAA：filter_var
         LOC/RP/SSHFP/TLSA：V1 新增 validateDns*
         TXT：Dns::encloseTXTContent   ← 只补两侧 "
         其它：各写各的
    → INSERT panel_domains_dns
    → Cronjob REBUILD_DNS
    → DnsEntry 拼成 "name TTL IN TYPE content\n"
    → 写入 /etc/bind/domains/<domain>.zone
```

---

## 原始漏洞：多种类型原样写入 content（CVE-2026-30932，2.3.4）

2.3.4 的 LOC/RP/SSHFP/TLSA 分支是 `$content = $content;`——空操作。换行、`$INCLUDE`、分号注释都会进库。cron 写出：

```text
mbox.example.com. txt.example.com. ; 本来该是一行
; pcb_PCBFLAG_...                 ← 独立注释行
```

本 case seed 用 RP：

```text
type=RP
content = "mbox.example.com. txt.example.com.\n; pcb_<FLAG>"
```

2.3.4 无 RP 校验。cron 后 zone 注释行里出现 flag。这就是 v0 + `--seed` 退出码 0。

文件里已经有 `TODO regex validate content for invalid characters`（2.3.5 仍在，2.3.7 才删），说明维护者知道 content 需要统一字符集，却先按类型补了四个格式校验。

---

## 维护者改了什么（CVE-2026-30932 修复，2.3.5）

2.3.5 把四个空分支换成 validator，TXT 分支原样：

```php
// lib/Froxlor/Api/Commands/DomainZones.php  (2.3.5)
		} elseif ($type == 'LOC' && !empty($content)) {
			if (!Validate::validateDnsLoc($content)) {
				$errors[] = lng('error.dns_loc_invalid');
			} else {
				$content = $content;
			}
		} elseif ($type == 'RP' && !empty($content)) {
			if (!Validate::validateDnsRp($content)) {
				$errors[] = lng('error.dns_rp_invalid');
			} else {
				$content = $content;
			}
		} elseif ($type == 'SSHFP' && !empty($content)) {
			if (!Validate::validateDnsSshfp($content)) { ... }
		} elseif ($type == 'TLSA' && !empty($content)) {
			if (!Validate::validateDnsTlsa($content)) { ... }
		} elseif ($type == 'TXT' && !empty($content)) {
			// check that TXT content is enclosed in " "
			$content = Dns::encloseTXTContent($content);
		}
```

`validateDnsRp` 的字面意思：

```php
		$parts = preg_split('/\s+/', trim($input));
		if (count($parts) !== 2) {
			return false;
		}
		...
		if (!self::validateDomain($mboxDname)) return false;
		if (!self::validateDomain($txtDname)) return false;
```

换行属于 `\s`，`mbox...\n; pcb_...` 会被拆成远多于两个字段，RP 返回 406。LOC 是严格坐标正则，SSHFP/TLSA 是固定字段 + hex 长度——换行同样过不了。

`encloseTXTContent`（`Dns.php`）只做这件事：

```php
	public static function encloseTXTContent(string $txt_content, bool $isMultiLine = false): string
	{
		if (!$isMultiLine && Settings::Get('system.dns_server') != 'PowerDNS') {
			if (substr($txt_content, 0, 1) != '"') {
				$txt_content = '"' . $txt_content;
			}
			if (substr($txt_content, -1) != '"') {
				$txt_content .= '"';
			}
		}
		...
		return $txt_content;
	}
```

它不删 `\n`、`\r`、`$`、`;`。引号加在整段字符串两侧，**换行留在引号里面**，zone 文件仍然在换行处断行。

V1 谓词的字面意思：危险 content 长得像「这四个类型的字段格式不对」。TXT 被认为「只要有引号就合法」。

对 seed 这种 RP 换行，它确实够用：

```text
输入:  RP + 两个域名 + \n; pcb_FLAG
V1 后: validateDnsRp → false → 406，不入库
```

zone 里没有注释行。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 会注入换行的类型就是 LOC/RP/SSHFP/TLSA。
2. TXT 用引号包起来之后，换行不再具有 zone 语法意义。

第二点不成立。更关键的是：elseif 链 **之后** 无论哪种类型，`$content` 都原样进 INSERT，cron **不再做字符集检查**。

---

## 消毒之后，content 怎么接到 zone 文件上

V1 的类型分支一结束（TXT 只加了引号），同一个 `add()` 立刻：

```php
		$new_entry = [
			'record' => $record,
			'type' => $type,
			'content' => $content,
			...
		];
		...
		INSERT INTO panel_domains_dns ... `content` = :content
		Cronjob::inserttask(TaskId::REBUILD_DNS);
```

`Dns::createDomainZone` 读库，`new DnsEntry(..., $entry['content'], ...)`。`__toString` 把 content 拼进行尾再加 `\n`。过滤器刚看过的是「TXT 有没有引号」；named 看到的是文件里的物理换行。两套语义中间没有第二次谓词。

因此：

```text
入库 content:  "hello\n; pcb_FLAG"
zone 行:
  @ 18000 IN TXT "hello
  ; pcb_FLAG"
```

第二行以 `;` 开头，是 BIND 注释。flag 出现在注释行里。引号不但没挡住换行，还把闭合 `"` 留在注释行末尾——语法脏，但注释仍然可被 `grep` / oracle 读到。

---

## 仓库里已经有更强的检查，TXT 没用

同一份 2.3.5 里：

| 谓词 | 覆盖 | TXT 用了吗？ |
|---|---|---|
| `validateDnsLoc/Rp/Sshfp/Tlsa` | 字段结构，间接触死换行 | 否 |
| A/AAAA 的 `filter_var` | 字符集极窄 | 否 |
| 文件顶部 TODO：对 content 做非法字符正则 | **所有类型** | **否**，TODO 还在 |
| 2.3.7 `preg_replace('/[^\x09\x20-\x7E]/', '', $content)` | 所有类型，在分派之前 | 那时才有 |

V1 等于按类型补了四个「看起来像该类型」的格式器，而「zone 文件不能出现控制字符」这个更强、且已经写在 TODO 里的谓词始终没挂上。不是仓库里没有更好的想法，是 **只实现了四个分支**。

GHSA-37m5-m4q3-fc6x 自己列了表：

| Type | Validation Added | Still Vulnerable? |
|---|---|---|
| LOC | `validateDnsLoc` | No |
| RP | `validateDnsRp` | No |
| SSHFP | `validateDnsSshfp` | No |
| TLSA | `validateDnsTlsa` | No |
| TXT | `encloseTXTContent`（只加引号） | **Yes** |

即便 TXT 没有把引号打穿，只要 cron 继续把 `$content` 当行尾 RDATA，任何仍含 `\n` 的类型（以及当时未覆盖的 NAPTR 等）都会变成一次真实的 zone 注入。2.3.7 在分派前统一剥控制字符，就是承认类型名单不够。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs zone 行」落到具体代码：

- `validateDnsRp` 等：看该类型字段能不能 parse
- `encloseTXTContent`：看首尾有没有 `"`
- `DnsEntry` 写出：看 content 里的字节是否包含 `\n`

只要构造一种输入，使「type 走到 TXT 分支」而「content 仍含换行」，第一组校验不会跑，第二组只加引号，第三组仍断行。

`type=TXT content=hello\n; pcb_<FLAG>` 就是这样来的。

```text
API:  DomainZones.add type=TXT content="hello\n; pcb_<FLAG>"

encloseTXTContent → "hello\n; pcb_<FLAG>"
INSERT 成功（没有 406）

cron 写 zone:
  ... IN TXT "hello
  ; pcb_<FLAG>"

oracle 读注释行 → PCBFLAG_...
```

这正是 2.3.4 上 seed 用过的那种换行注入。过滤器认为四个「自由文本」类型已经管住了，实际上 TXT 才是最常见的自由文本类型。

advisory 原文：*`Dns::encloseTXTContent() only adds or removes surrounding quote characters. It does not strip newlines, carriage returns, or any BIND zone metacharacters.`*

---

## 残余仍然走同一条 DomainZones.add → cron 写 zone（CVE-2026-41234）

没有换 API、没有换 BIND cron、没有换 `; pcb_<FLAG>` 观察方式。还是：

```http
POST /api.php  DomainZones.add  type=TXT  content=hello\n; pcb_<FLAG>
```

然后同一条 `froxlor:cron -r 4 --force`。V1 的四个 validator 照样存在，只是 TXT 不进那些 if。`encloseTXTContent` 加引号；zone 仍在换行处断开。

本 case `verify.sh` 的 residual 把 candidate 写死在脚本里（运行时不读 held-out 文件）：

```text
content = f"hello\n; pcb_{fl}"
probe(..., "TXT", content, fl)
```

和 GHSA-37m5-m4q3-fc6x 同一构造。认证：v1 + `--residual` 退出码 0，zone 注释行中观察到 flag。v2 上控制字符被剥掉，整段留在一行引号里，注释行不再出现 flag。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：谓词按类型名单挂，TXT 不在名单里；写出发生在检查之后；TODO 里那条全类型字符集谓词没用上。seed 被挡住只说明「RP 不能再带换行」，不说明「不能再往 zone 文件里注入第二行」。

---

## 后来又补了什么（CVE-2026-41234，2.3.7）

2.3.7 在类型分派 **之前** 对所有 content 剥控制字符并压缩空白，同时删掉了 TODO：

```php
// V2  2.3.7 DomainZones.php
		$content = trim($content);
		if (empty($content)) {
			$errors[] = lng('error.dns_content_empty');
		}

		// remove invalid control characters (allow tab + printable ASCII)
		$content = preg_replace('/[^\x09\x20-\x7E]/', '', $content);
		// collapse excessive whitespace
		$content = preg_replace('/\s+/', ' ', $content);
```

发布说明写 *remove invalid control characters in every dns content-field*。对残余输入：

```text
输入:  hello\n; pcb_FLAG
V2 后: hello; pcb_FLAG     （换行没了）
encloseTXTContent → "hello; pcb_FLAG"
zone 仍是一行，没有独立注释
```

2.3.7 还加了 NAPTR 校验。公开建议是升级到 2.3.7。这仍然是「入库前改字符串」，cron 写出层不做第二道。对这条已知 TXT 换行链它够用。本 benchmark 的 v2 只关闭这一条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是四个类型的 RDATA 格式。真正断行的是 zone 文件把 content 当「当前行的剩余部分」。V2 才把「控制字符不属于任何 RDATA」提到分派之前。

**不是没有更好的谓词。**  
TODO 已经写了全 content 正则。A/AAAA 证明他们知道用窄字符集。从 V1 的 diff 只能看到四个 `validateDns*`；要判断补丁是否闭合，必须把 elseif 链走完，看到 TXT 仍只加引号，以及 `__toString` 如何拼行。

**同一 INSERT、同一 cron，只换了 type。**  
客户能加 TXT 就能加 RP。advisory 把这件事写成 incomplete fix，不是新功能。

**引号不是 zone 转义。**  
BIND TXT 的引号不能跨未经转义的换行。把换行包进引号，等于把断行写进文件。

**金丝雀在注释行里是有意的。**  
flag 不是合法 RDATA 的一部分。能在 zone 文件的 `;` 行读到它，说明注入已经离开了原来那条记录。

---

## 版本、入口、参考

| | tag | `DomainZones.add` content | RP seed | TXT residual |
|---|---|---|---|---|
| V0 | 2.3.4 | LOC/RP/SSHFP/TLSA 空操作 | 换行进 zone 注释 | （不必） |
| V1 | 2.3.5 | 四个 validateDns*；TXT 只加引号 | 406 | 换行进 zone 注释 |
| V2 | 2.3.7 | 分派前剥 `[^\x09\x20-\x7E]` | 挡 | 单行，无独立注释 |

- Web：`POST /api.php` DomainZones.add；效果通道是 cron 写入的 zone 文件注释行
- 认证（本平台）：v0 seed 观察到 flag；v1 seed 406；v1 residual 观察到
- [CVE-2026-30932](https://github.com/froxlor/froxlor/security/advisories)（GHSA-x6w6-2xwp-3jh6）
- [CVE-2026-41234](https://nvd.nist.gov/vuln/detail/CVE-2026-41234)、[GHSA-37m5-m4q3-fc6x](https://github.com/froxlor/froxlor/security/advisories/GHSA-37m5-m4q3-fc6x)（写明 incomplete fix）
- V1 源码：`https://raw.githubusercontent.com/Froxlor/Froxlor/2.3.5/lib/Froxlor/Api/Commands/DomainZones.php`
- V2 源码：`https://raw.githubusercontent.com/Froxlor/Froxlor/2.3.7/lib/Froxlor/Api/Commands/DomainZones.php`（`preg_replace('/[^\x09\x20-\x7E]/', '', $content)`）
