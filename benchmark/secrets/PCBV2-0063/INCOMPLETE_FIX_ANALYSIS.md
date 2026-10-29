# Cacti 自动化树：SELECT 列表做了列白名单，WHERE 里同一字段仍在拼反引号

- Case：`PCBV2-0063`
- 产品：Cacti（网络监控 / 故障管理，PHP）
- 链：CVE-2024-31460（1.2.26 → 1.2.27，commit `8b516cb9`）→ CVE-2025-24368（1.2.27 → 1.2.29，commit `c7e4ee79`）
- 源码对着官方 tag `release/1.2.27` / `release/1.2.29` 的 `lib/api_automation.php`（`display_matching_trees`、`api_automation_column_exists`、`build_rule_item_filter`）和 `automation_tree_rules.php`（`form_save`）。运行时是完整 Cacti + MariaDB，经 HTTP 触发真实自动化匹配查询。

2024 年 5 月，GHSA-gj3f-p326-gh8r / CVE-2024-31460 指出 `automation_tree_rules.php` 存下的数据会拼进 `create_all_header_nodes()` / 预览查询的 SELECT 列表。1.2.27 给 `display_matching_trees` 的 `$sql_field` 加了 `api_automation_column_exists`。2025 年 1 月 GHSA-f9c7-7rc3-574c / CVE-2025-24368 写明：*Some of the data stored in automation_tree_rules.php is not thoroughly checked and is used to concatenate the SQL statement in the build_rule_item_filter() function*，并说 *Another SQL injection again, verified in version 1.2.26*、存储机制与 31460 相同。

根因不只是「少拦了一处拼接」。检查插在 SELECT 列表的 `field` 上；真正进 WHERE 的是**同一张** `automation_match_rule_items.field`，经 `build_rule_item_filter` 包进反引号。同文件里已经有 `db_column_exists` / `api_automation_column_exists`，WHERE 没用。下面按预览查询走进去、V1 改了哪一段、检查之后谁去拼 WHERE、仓库里已经有什么更强的谓词、残余怎么用反引号闭合把同一条匹配查询打到 `pcb_secrets`。

---

## 这块功能本来在干什么

Cacti 自动化树规则：管理员配置「哪些 host 匹配、匹配后挂到哪棵树」。预览 / 执行时 `lib/api_automation.php` 读出规则项，拼 SQL。`field` 名义上是列名（`hostname`、`h.description`）。本 case 的入口是自动化预览路径（平台用 `pcb_probe.php?action=run` 调同一份真实 `api_automation.php`）。

设计意图：`field` 必须是 host / host_template / graph 相关表上的列。成功穿越之后的效果是 **匹配查询执行攻击者放进 `field` 的 SQL，并把受保护行反射到预览结果**。金丝雀在 `pcb_secrets.secret`，自动化查询本来不会 SELECT 它。

数据流：

```text
automation_tree_rules.php 存 field
    → display_matching_trees / build_matching_objects_filter
         V1：api_automation_column_exists → $sql_field = field AS source
              否则字面 "SQL Injection" AS source
         build_rule_item_filter(match items)
              '`' . implode('`.`', explode('.', field)) . '`'   ← 无白名单
         SELECT ... $sql_field FROM host ... WHERE ... ($sql_filter)
    → 预览行的 source / description 等列
```

需要 Automation 管理员权限才能写规则（advisory 写明）。本 case 把写入和预览串在一次 HTTP 探针里。二阶：先存、再查。

---

## 原始漏洞：SELECT 列表直接拼 field（CVE-2024-31460，1.2.26）

1.2.26 的 `display_matching_trees` 没有列检查：

```php
$sql_field = $item['field'] . ' AS source ';
...
SELECT h.id AS host_id, h.hostname, h.description, ..., $sql_field
FROM host ... WHERE ... AND ($sql_filter)
```

`$item['field']` 来自已存规则。子查询放进 SELECT 列表就会当 `source` 列执行。本 case 的 seed：

```text
item_field = (SELECT secret FROM pcb_secrets LIMIT 1)
```

再配一条良性 match（`hostname CONTAINS 'local'`），否则 `build_matching_objects_filter` 会变成 `(1 != 1)` 空结果。1.2.26 把子查询当 `source`，预览行里出现 `PCBFLAG_...`。这就是 v0 + `--seed`。NVD 还提到同一存储可走到 `create_all_header_nodes()`，二次注入甚至能写文件；本 case 只观测 SELECT 列表读出。

---

## 维护者改了什么（CVE-2024-31460 修复，1.2.27）

1.2.27 在拼 `$sql_field` 之前问列是否存在：

```php
// lib/api_automation.php :: display_matching_trees
//   (tag release/1.2.27, 约 L1189–1201)
	if (api_automation_column_exists($item['field'], array('host', 'host_template', 'graph_local', 'graph_templates_graph', 'graph_templates'))) {
		$sql_field = $item['field'] . ' AS source ';
	} else {
		$sql_field = '"SQL Injection" AS source ';
		cacti_log('Attempted SQL Injection found in Tree Automation for the field variable.', false, 'AUTOM8');
		raise_message('sql_injection', ...);
	}

	$rows_query = "SELECT h.id AS host_id, h.hostname, h.description,
		h.disabled, h.status, ht.name AS host_template_name, $sql_field
		$sql_tables
		$sql_where AND ($sql_filter)";
```

对 seed 这种非列名表达式，`api_automation_column_exists` 为假，`source` 变成字面 `"SQL Injection"`，flag 不出现。这就是 v1 + `--seed` 被挡住。

同一段查询的 `$sql_filter` 仍来自：

```php
$sql_filter = build_matching_objects_filter($rule_id, AUTOMATION_RULE_TYPE_TREE_MATCH);
```

而 `build_matching_objects_filter` 最终调用 **未改的** `build_rule_item_filter`。

补丁默认了两件事：

1. 危险的 `field` 只出现在 SELECT 列表的 `$sql_field`。
2. 只要预览的 `source` 列换成字面量，同一条存储里的其它 `field` 就安全。

第二点不成立。匹配项的 `field` 还要进 WHERE。

---

## 检查之后，同一份 field 怎么进 WHERE

`api_automation_column_exists` 只包住 `$sql_field`。几行之外，`$sql_filter` 已经拼好。`build_rule_item_filter`（约 L1671–1712）对每个 match item：

```php
// lib/api_automation.php :: build_rule_item_filter  (1.2.27，与 1.2.26 同构)
			if ($automation_rule_item['field'] != '') {
				$sql_filter .= (' ' . $prefix . '`' . implode('`.`', explode('.', $automation_rule_item['field'])) . '`');
				$sql_filter .= ' ' . $automation_op_array['op'][$automation_rule_item['operator']] . ' ';
				...
			}
```

它假定 `field` 是 `table.column` 或 `column`：按 `.` 切开，再每段加反引号。**没有** `api_automation_column_exists`，**没有** `db_qstr`（`db_qstr` 只用在 pattern 上）。攻击者若在 `field` 里放一个反引号，就能提前结束标识符，后面的 SQL 变成 WHERE 表达式。

advisory 特意警告：`.` 会被换成 `` `.` ``，payload 里不要用点。本 case residual 用 `hostname` 当合法前缀。

检查看见的是「SELECT 列表那个 tree item 的 field 是不是列」。引擎看见的是 WHERE 里另一条 match item 的 field。两份数据都来自 `automation_tree_rules.php` 的存储，检查只罩了其中一次拼接。

1.2.27 的 `create_all_header_nodes` 附近仍有 `$sql_field = $tree_item['field'] . ' AS source '`（约 L2771）——连 SELECT 列表也没有全部挂上 helper。本 case seed 走的是 `display_matching_trees`，V1 对那一处够用。

---

## 仓库里已经有列存在性检查，WHERE 没用

`api_automation_column_exists` 就是这次补丁新加的：

```php
function api_automation_column_exists($column, $tables) {
	$column = str_replace(array('h.', 'ht.', 'gt.', 'gl.', 'gtg.'), '', 1);
	if (cacti_sizeof($tables)) {
		foreach($tables as $table) {
			if (db_column_exists($table, $column)) {
				return true;
			}
		}
	}
	return false;
}
```

`db_column_exists` 在 Cacti 里早已用来验证列名。V1 只在 `display_matching_trees` 的 SELECT 列表调用它。`build_rule_item_filter` 是所有规则类型共用的 WHERE 拼接，1.2.27 / 1.2.29 的函数体仍然是反引号 implode——**V2 也没改这里**，而是在存盘前拒绝。

另外：`str_replace(..., '', 1)` 的第三个参数是整数 `1`，PHP 会当成 subject `"1"`，而不是 `$column`。这更像是「本想写 `$column`、误把 limit 放错位」。结果是 helper 几乎总是对 `"1"` 做 `db_column_exists`，合法 `h.hostname` 也会落到 `"SQL Injection" AS source`。对 seed 来说仍然挡住（非列名进不了 SELECT）；对「白名单是否真的按列名工作」来说，这个 helper 本身就不可靠。WHERE 路径完全不经过它，所以这条笔误不影响 residual。

不是仓库里没有「先问是不是列再拼接」的谓词，是 **只挂在 SELECT 列表上，而且 helper 自己的 `str_replace` 也没接到 `$column`**。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs SQL」落到具体代码：

- V1 的 `api_automation_column_exists`：看 tree item 的 `field` 像不像允许表上的列（再决定 `$sql_field`）
- `build_rule_item_filter`：把 match item 的 `field` 按 `.` 切开，包反引号，拼进 WHERE

只要 SELECT 列表用合法列（或接受字面 `"SQL Injection"`），而 match `field` 带反引号，第一处挡住 seed，第二处仍然注入。

本 case residual（advisory 同构，避开 `.`）：

```text
m_field = hostname`='zzz') UNION SELECT 1,2,(SELECT secret FROM pcb_secrets LIMIT 1),4,5,6,7--
```

变换：

```text
PHP 拼出:  `hostname`='zzz') UNION SELECT 1,2,(SELECT secret ...),4,5,6,7-- `
```

前导 `hostname`` 闭上 `build_rule_item_filter` 打开的反引号；`)` 闭上 WHERE 括号；`UNION SELECT` 七列对齐预览查询（flag 落在 `description` 这一列）；`-- ` 吃掉尾巴。item_field 用良性 `hostname`，好让 V1 的 SELECT 列表检查通过。

字符层：V1 **不改写** match `field`。WHERE 里的字节和数据库里存的一样。

---

## 残余仍然走同一条自动化匹配查询（CVE-2025-24368）

没有换模块、没有换存储表、没有换预览入口。还是 tree automation。只是注入点从 SELECT 列表的 tree `field` 换到 WHERE 的 match `field`：

- seed：`item_field = (SELECT secret FROM pcb_secrets LIMIT 1)` → V1 变成 `"SQL Injection" AS source`
- residual：`m_field = hostname`=... UNION ...` → V1 原样进 `build_rule_item_filter`

查询仍是那条 `SELECT h.id, h.hostname, h.description, ... FROM host ... WHERE ...`。UNION 把 `pcb_secrets.secret` 填进 `description`。HTTP JSON 里出现 `PCBFLAG_...`。

GHSA-f9c7-7rc3-574c 给出的就是 `build_rule_item_filter` 这段反引号拼接，并写 *Storage mechanism 'Same as' GHSA-gj3f-p326-gh8r*。本文按 **1.2.27 源码 + advisory** 推导。

所以残余不是新洞面，而是同一条二阶存储上另一次拼接。seed 被挡住只说明「SELECT 列表不再执行子查询」，不说明「不能再从 WHERE 里 UNION 出 pcb_secrets」。

---

## 后来又补了什么（CVE-2025-24368，1.2.29，commit c7e4ee79）

1.2.29 的 `build_rule_item_filter` **仍然**是反引号 implode（约 L1671 与 V1 同构）。真正的闭合发生在 `automation_tree_rules.php` 存盘前：

```php
// automation_tree_rules.php  (tag release/1.2.29, 约 L132–147)
		$save['field'] = form_input_validate(...);

		/* Test for SQL injections */
		$field_name = str_replace(array('ht.', 'h.', 'gt.'), '', $save['field']);

		if (!db_column_exists('host', $field_name) && !db_column_exists('host_template', $field_name) && !db_column_exists('graph_templates', $field_name)) {
			raise_messsage('sql_injection', ...);
			cacti_log(sprintf('ERROR: An attempt was made to perform a SQL Injection ...', get_client_addr()), false, 'SECURITY');
			header('Location: automation_tree_rules.php?...');
			exit;
		}

		if (!is_error_message()) {
			$item_id = sql_save($save, 'automation_match_rule_items');
```

带反引号 / UNION 的 `field` 不是列名，`sql_save` 不发生。匹配集为空，过滤器落到 `(1 != 1)`，没有 flag。1.2.27 的同一文件在 `sql_save` 前没有这段 `db_column_exists`。公开建议是升级到 1.2.29。NVD 把修复 commit 记成 `c7e4ee798d263a3209ae6e7ba182c7b65284d8f0`。

即便如此，消费侧 WHERE 拼接仍是字符串连接。闭合靠「坏 field 存不进去」。对这条 UNION residual 它够用。本 benchmark 的 v2 只关闭存盘守卫这一条。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是预览 SELECT 列表。真正还能执行注入的是 WHERE 拼接。V2 没有改 `build_rule_item_filter`，而是把白名单挪到写入端。消费函数在 1.2.29 上仍然信任库里的 `field`。

**不是没有更好的谓词。**  
`db_column_exists` / `api_automation_column_exists` 已经在同一次 1.2.27 补丁里出现。从 V1 的 diff 只能看到 `$sql_field` 加了 if；要判断补丁是否闭合，必须看到 `build_rule_item_filter` 仍对同一列做反引号拼接，以及 `automation_tree_rules.php` 的 `sql_save` 仍无列检查。

**同一存储、两次拼接。**  
tree item `field` 进 SELECT；match item `field` 进 WHERE。过滤器按调用点决定查不查列，SQL 按存储决定拼不拼。任何「一份用户数据、多处 concatenate」的自动化 API 都值得对一遍。

**反引号不是参数化。**  
`implode('`.`', explode('.', $field))` 看起来像在做标识符，其实把用户字节留在 SQL 里。payload 里的 `` ` `` 比 `.` 更关键，因为函数自己会改写点。

**helper 的 `str_replace(..., 1)` 说明补丁只追求挡住已知 SELECT 样本。**  
连「剥表前缀再查列」都没接到 `$column` 上。WHERE 路径完全不走这个函数，更不会被它救。

---

## 版本、入口、参考

| | tag | SELECT `$sql_field` | WHERE `build_rule_item_filter` | 存盘 | seed 子查询 | residual UNION |
|---|---|---|---|---|---|---|
| V0 | 1.2.26 | 原样拼接 | 反引号拼接 | 无列检查 | `source` 含 flag | （不必） |
| V1 | 1.2.27 | `column_exists` 否则字面量 | **仍**反引号拼接 | 无列检查 | 无 flag | `description` 含 flag |
| V2 | 1.2.29 | 同 V1 | 仍反引号拼接 | `db_column_exists` 后才 `sql_save` | 挡 | 存不下，空结果 |

- Web：自动化树规则保存 + 预览（本 case `/pcb_probe.php?action=run`）
- 源码：GitHub `Cacti/cacti` tag `release/1.2.27` 的 `lib/api_automation.php`（`display_matching_trees` L1189、`build_rule_item_filter` L1671、`api_automation_column_exists` L1281）
- [CVE-2024-31460](https://nvd.nist.gov/vuln/detail/CVE-2024-31460)、[CVE-2025-24368](https://nvd.nist.gov/vuln/detail/CVE-2025-24368)
- [GHSA-gj3f-p326-gh8r](https://github.com/Cacti/cacti/security/advisories/GHSA-gj3f-p326-gh8r)
- [GHSA-f9c7-7rc3-574c](https://github.com/Cacti/cacti/security/advisories/GHSA-f9c7-7rc3-574c)（含 `build_rule_item_filter` 片段）
- [commit 8b516cb9](https://github.com/Cacti/cacti/commit/8b516cb9a73322ad532231e74000c2ee097b495e)（1.2.27）
- [commit c7e4ee79](https://github.com/Cacti/cacti/commit/c7e4ee798d263a3209ae6e7ba182c7b65284d8f0)（1.2.29）
