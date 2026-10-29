# Superset sqlExpression：拒绝名单认函数名，不认带引号的标识符

- Case：`PCBV2-0040`
- 产品：Apache Superset（BI）
- 链：CVE-2025-48912（4.0.2 → 4.1.2；更早还有 CVE-2024-39887 在 4.0.2 引入名单）→ CVE-2026-23980（4.1.2 → 6.0.0）
- 源码对着官方 tag `4.1.2` 的 `superset/config.py`、`superset/sql_parse.py`。运行时是官方 `apache/superset:4.1.2` + Postgres，经 `/api/v1/chart/data` 的 `sqlExpression`，不是抽出来的字符串匹配。

2024 年 Superset 为 CVE-2024-39887 引入 `DISALLOWED_SQL_FUNCTIONS`，先挡住 `query_to_xml` 等。Quarkslab 随后指出 `table_to_xml` 等亲戚不在名单里，子查询被藏进函数参数，`has_table_query` 看不到 `FROM`。4.1.2 把 postgresql 集合扩成含 `table_to_xml`、`query_to_xml_and_xmlschema` 等，并修了 RLS 相关的 CVE-2025-48912。2026 年 2 月 CVE-2026-23980 说明：名单检查走 sqlparse 的 `Function.get_name().lower()`，**处理不了 PostgreSQL 双引号标识符**；`"query_to_xml"(...)` 对解析器不是 Function 名匹配，对 Postgres 仍是内建函数。6.0.0 用 sqlglot 规范化，带引号的名字被大写，库里找不到 `"QUERY_TO_XML"`。

根因不只是「名单又漏了一个拼写」。检查插在 sqlparse 的 Function 令牌上；真正执行的是 Postgres 对标识符的折叠规则；sqlglot 已经在同一棵解析树里做表提取，名单匹配没用它。下面按请求走进去、补丁改了哪一份集合、检查之后谁去跑 SQL、仓库里已经有什么更强的解析、残余怎么给函数名加上双引号把金丝雀表读进 XML。

---

## 这块功能本来在干什么

Superset 图表的 adhoc 列允许分析师写 `sqlExpression`。请求进 `ChartDataRestApi` → `QueryContext` → `SqlaTable.get_sqla_query`，表达式被拼进对数据集的 SELECT。引擎执行前，`BaseEngineSpec.execute`（以及 SQL Lab）会用 `sql_parse.check_sql_functions_exist` 对照 `DISALLOWED_SQL_FUNCTIONS[engine]`。

一次典型请求：

```http
POST /api/v1/chart/data
Authorization: ...
{"datasource":{"id":1,"type":"table"},
 "queries":[{"columns":[{"label":"x","sqlExpression":"CAST(table_to_xml('canary', true, false, '') AS TEXT)"}]}]}
```

设计意图：数据集是 `public_data`，表达式不该执行任意 SQL。PostgreSQL 的 `query_to_xml` / `table_to_xml` 会把参数里的 SQL 或表名当查询跑，结果变成 XML。成功穿越之后的效果是 **在图表结果里带出数据集之外的 `canary.flag`**。

数据流：

```text
POST /api/v1/chart/data  sqlExpression
    → 拼进 SELECT
    → check_sql_functions_exist(sql, DISALLOWED_SQL_FUNCTIONS['postgresql'])
         ParsedQuery → sqlparse
         V1：token 是 Function 且 get_name().lower() in 名单
    → cursor.execute 同一条 SQL          ← Postgres 自己解析标识符
    → 结果 XML/文本回图表 API
```

本 case 的 `canary` 表由 `init-db.sh` 从 `$PCB_FLAG` 写入，合法数据集从不查询它。

---

## 原始漏洞：XML 函数不在名单里（CVE-2024-39887 / CVE-2025-48912 之前，4.0.2）

4.0.2 的 postgresql 集合大致是 `version`、`query_to_xml`、`inet_*`。Quarkslab 写明 `table_to_xml` 等仍可用：sqlparse 把函数参数当字符串，`has_table_query` 看不到里面的 `FROM`。CVE-2025-48912 在 4.1.2 修 RLS/sqlExpression 注入，同时名单已经扩过一轮。

本 case seed 用 4.0.2 **还不挡** 的 `table_to_xml`：

```text
sqlExpression = CAST(table_to_xml('canary', true, false, '') AS TEXT)
```

4.0.2 名单没有 `table_to_xml`。Postgres 把 `canary` 表转成 XML，响应里出现 `PCBFLAG_...`。这就是 v0 + `--seed` 退出码 0。

---

## 维护者改了什么（CVE-2025-48912 / 名单扩充，4.1.2）

4.1.2 的 `superset/config.py`：

```python
DISALLOWED_SQL_FUNCTIONS: dict[str, set[str]] = {
    "postgresql": {
        "database_to_xml",
        "inet_client_addr",
        "inet_server_addr",
        "query_to_xml",
        "query_to_xml_and_xmlschema",
        "table_to_xml",
        "table_to_xml_and_xmlschema",
        "version",
    },
    ...
}
```

匹配在 `sql_parse.py`：

```python
    def _check_functions_exist_in_token(self, token, functions):
        if (
            isinstance(token, Function)
            and token.get_name() is not None
            and token.get_name().lower() in functions
        ):
            return True
        if hasattr(token, "tokens"):
            for inner_token in token.tokens:
                if self._check_functions_exist_in_token(inner_token, functions):
                    return True
        return False
```

命中则 `DisallowedSQLFunction`。V1 谓词的字面意思：

| 片段 | 含义 |
|---|---|
| `isinstance(token, Function)` | sqlparse 必须把这段当成 **Function** 节点 |
| `get_name().lower()` | 名字小写后与集合比 |
| 集合是字面函数名 | `"query_to_xml"` 这种带引号的写法不在集合里，且往往 **根本不是 Function 节点** |
| 递归 `token.tokens` | 只在 sqlparse 树里走，不求值参数字符串 |

它拒绝的是「解析器认为这是名为 table_to_xml 的函数调用」，不是「执行计划里会不会调用这个内建函数」。

对 seed 这种裸 `table_to_xml(...)`，它确实够用：

```text
输入:  CAST(table_to_xml('canary', ...) AS TEXT)
sqlparse Function.get_name() → table_to_xml
in DISALLOWED → 抛错，图表失败
```

响应里没有金丝雀。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险调用长得像未加引号的函数名令牌。
2. Postgres 看到的名字和 sqlparse 的 `get_name()` 是同一个字符串。

第二点不成立。更关键的是：检查通过之后，**同一条用户 SQL** 交给驱动执行，不再对照名单。

---

## 消毒之后，表达式怎么接到数据库上

V1 的 `check_functions_exist` 返回 false 之后，引擎照常 `cursor.execute`。PostgreSQL 标识符规则：未加引号则折成小写；双引号保持原样，但内建函数本来就是小写名字，所以 `"query_to_xml"` 仍解析到同一函数。

sqlparse 对 `"query_to_xml"(...)` 的典型拆分是 Identifier / Punctuation，而不是 `Function` 且 `get_name()==query_to_xml`。过滤器刚看过的是 Function 节点集合；执行器看到的是内建 XML 函数。两套语义中间没有第二次谓词。

`table_to_xml` / `query_to_xml` 的返回值被 `CAST(... AS TEXT)` 送进图表单元格。`canary.flag` 出现在 API body 里，依据就是 Postgres 跑了函数参数里的查询，而不是「数据集碰巧包含 canary」。

---

## 仓库里已经有更强的解析，名单匹配没用

同一份 4.1.2 的 `ParsedQuery` 已经用 sqlglot 抽表（`_extract_tables_from_sql`）。sqlglot 知道引号、大小写、方言。谁用 sqlglot：

| 用途 | 4.1.2 | 6.0.0 |
|---|---|---|
| 抽表 / 安全访问 | sqlglot | sqlglot |
| `DISALLOWED_SQL_FUNCTIONS` | **sqlparse Function.get_name()** | 经 sqlglot 规范化后再比（带引号标识符被大写） |

V1 等于用更弱的令牌器做安全名单，而旁边已经有一份能看懂 `"query_to_xml"` 的解析器。不是仓库里没有更好的谓词，是 **函数拒绝名单没用 sqlglot**。

即便不升级到 6.0.0，把 `get_name()` 改成剥引号再 `.lower()` 也会挡住这条残余——那仍是字符串层。6.0.0 选择规范化后再查，让 `"query_to_xml"` 变成 `QUERY_TO_XML`，Postgres 找不到该名字（未加引号的内建是小写，加引号则大小写敏感）。

Quarkslab 文里 `has_table_query` 扫 `FROM`/`JOIN` 也是同一类「看令牌不看求值」的谓词。XML 函数把 SQL 藏进字符串参数，那一层已经被名单对付；引号则对付的是名单自己的令牌形状。

sqlparse 的 `Function` 节点来自「名字后面紧跟括号」的启发式。PostgreSQL 允许 `"query_to_xml"`、`pg_catalog.query_to_xml`、甚至空白与换行夹在名字和 `(` 之间。4.1.2 的匹配函数既不剥引号，也不展开 `pg_catalog` 限定。本 case residual 只需要双引号：它已经足够让 `isinstance(token, Function)` 对不上名单里的小写名字，同时足够让执行器找到内建。

`execute` 路径把名单检查和 `cursor.execute` 写在同一个方法里、中间没有重写 SQL。因此 residual 不需要第二处注入点——chart data 的 `sqlExpression` 既是过滤器看到的字符串，也是 Postgres 收到的字符串，只是两套解析器对同一字节的解释不同。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs Postgres」落到具体代码：

- `_check_functions_exist_in_token`：看 sqlparse 是否给出名为 `query_to_xml` 的 Function
- Postgres：看标识符 `"query_to_xml"` 是否仍是 XML 内建

只要构造一种输入，使「sqlparse 不把它当 Function 名」而「Postgres 仍调用该内建」，第一行会放行，第二行仍然执行参数里的 SQL。

双引号就是这样来的。

```text
sqlExpression:
  CAST("query_to_xml"('SELECT flag FROM canary LIMIT 1', true, false, '') AS TEXT)

sqlparse:
  不是 Function.get_name()==query_to_xml  → 名单未命中

Postgres:
  "query_to_xml" → 内建 query_to_xml
  参数 SQL 读 canary.flag
  XML/文本进图表响应 → PCBFLAG_...
```

这正是 4.0.2 上 seed 用过的那种 XML 函数读旁路表。过滤器认为自己已经把函数名列全了，实际上它列的是 **一种拼写在一种令牌类型下** 的名字。

held-out 注释写明：*the deny list check matches function names via sqlparse token inspection, which does NOT handle PostgreSQL quoted identifiers*。

---

## 残余仍然走同一条 chart data sqlExpression（CVE-2026-23980）

没有换 API、没有换 Postgres 引擎、没有换 `canary` 表。还是：

```http
POST /api/v1/chart/data
sqlExpression = CAST("query_to_xml"('SELECT flag FROM canary LIMIT 1', true, false, '') AS TEXT)
```

`check_sql_functions_exist` 仍然跑。V1 名单里有 `query_to_xml`，只是 `"query_to_xml"` 匹配不上。驱动把同一字符串交给 Postgres；XML 里出现 flag。

本 case `verify.sh` 的 residual 把 candidate 写死在脚本里（运行时不读 held-out 文件）：

```text
PAYLOAD = CAST("query_to_xml"('SELECT flag FROM canary LIMIT 1', true, false, '') AS TEXT)
```

认证：v1 + `--residual` 退出码 0，图表响应中观察到 `PCBFLAG_...`。v2（6.0.0）规范化后函数名对不上内建，查询失败，body 无 flag。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：谓词用 sqlparse Function 名，比 Postgres 标识符语义窄；执行发生在检查之后且不再查；旁边的 sqlglot 没用在名单上。seed 被挡住只说明「裸 table_to_xml 没了」，不说明「不能再让 sqlExpression 通过 XML 函数读 canary」。

---

## 后来又补了什么（CVE-2026-23980，6.0.0）

6.0.0 把表达式送进 sqlglot，带引号的标识符按方言规范化（PostgreSQL 下通常变成大写）。名单仍是小写内建名；`"QUERY_TO_XML"` 不再解析到 `query_to_xml`。NVD：*Users are recommended to upgrade to version 6.0.0*。

对残余输入：

```text
输入:  "query_to_xml"(...)
V2 后: 规范化成 QUERY_TO_XML，Postgres 找不到该函数
图表错误，无 canary XML
```

公开建议是升级到 6.0.0。这仍然是「执行前改写/规范化 SQL」，不是在驱动层拦内建。对这条已知引号链它够用。本 benchmark 的 v2 只关闭这一条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是一份小写函数名集合，以及 sqlparse 是否能看见 Function 令牌。真正读旁路表的是 Postgres 执行 XML 函数。V2 把解析器换成更接近执行器的 sqlglot，而不是把 XML 函数从角色权限里拿掉。

**不是没有更好的谓词。**  
sqlglot 已经在抽表。从 V1 的 diff 只能看到 `DISALLOWED_SQL_FUNCTIONS` 变长；要判断补丁是否闭合，必须看到 `_check_functions_exist_in_token` 的 `isinstance(..., Function)`，以及 Postgres 对 `"name"` 的规则。

**同一 sqlExpression、同一 XML 函数，只换了拼写。**  
`table_to_xml('canary')` 和 `"query_to_xml"('SELECT ...')` 都是「函数参数里的 SQL/表对解析器不可见」。前者靠扩名单堵住，后者靠令牌形状再逃一次。

**名单是执行器语法的近似。**  
每多一种引号、空白、模式前缀（`pg_catalog.query_to_xml`），近似就再偏一截。6.0.0 用 AST 规范化，是承认字符串相等不够。

**金丝雀表不在数据集里是有意的。**  
`public_data` 查不到 flag。能在图表 JSON 里读到它，说明执行的不是数据集扫描，而是 XML 函数打开了另一张表。

---

## 版本、入口、参考

| | tag | 名单 / 匹配 | 裸 `table_to_xml` seed | `"query_to_xml"` residual |
|---|---|---|---|---|
| V0 | 4.0.2 | 无 / 不全 `table_to_xml` | XML 里有 flag | （不必） |
| V1 | 4.1.2 | 名单含 table_to_xml；sqlparse Function 名 | DisallowedSQLFunction | Postgres 仍执行，XML 里有 flag |
| V2 | 6.0.0 | sqlglot 规范化后再比 | 挡 | 函数名对不上内建 |

- Web：登录后 `POST /api/v1/chart/data`；效果通道是响应 body 里的 XML/文本
- 认证（本平台）：v0 seed 观察到 flag；v1 seed 未观察到；v1 residual 观察到
- [CVE-2024-39887](https://osv.dev/vulnerability/CVE-2024-39887)、[CVE-2025-48912](https://nvd.nist.gov/vuln/detail/CVE-2025-48912)
- [CVE-2026-23980](https://nvd.nist.gov/vuln/detail/CVE-2026-23980)
- [Quarkslab：Bypass Apache Superset restrictions](https://blog.quarkslab.com/bypass-apache-superset-restrictions-to-perform-sql-injections.html)
- 名单引入：[PR #28639](https://github.com/apache/superset/pull/28639) / [56f0103](https://github.com/apache/superset/commit/56f0103b5771d477dd106272abbd8021c9ea7506)
- V1 源码：`https://raw.githubusercontent.com/apache/superset/4.1.2/superset/config.py`、`https://apache.googlesource.com/superset/+/refs/tags/4.1.2/superset/sql_parse.py`
