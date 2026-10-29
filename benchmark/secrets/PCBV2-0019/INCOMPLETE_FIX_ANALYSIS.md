# pgAdmin 4：qtLiteral 换了十六处，漏掉 Index Statistics

- Case：`PCBV2-0019`
- 产品：pgAdmin 4（PostgreSQL 管理界面，Flask + Jinja SQL 模板）
- 链：CVE-2026-12044（9.15 → 9.16）→ CVE-2026-17346（9.16 → 9.17，commit `73b3218`）
- 源码对着官方 `REL-9_16` 的 `web/pgadmin/utils/driver/psycopg3/__init__.py :: qtLiteral`、`.../indexes/sql/default/coll_stats.sql`、`.../indexes/__init__.py :: statistics`。运行时是官方镜像 `dpage/pgadmin4:9.16` 整包，不是抽出来的模板。

2026 年 pgAdmin 9.16 把 `qtLiteral` 改成「没有 conn 就抛 ValueError」，并把十六处 `COMMENT ON ... IS '{{ description }}'` 换成 `{{ description|qtLiteral(conn) }}`，想挡住描述字段里的单引号注入。同一份提交里新增的 lint 测试 `test_sql_string_literal_lint.py` 把 Index Statistics 的 `coll_stats.sql` 写进 ALLOWLIST，理由是「schema/table 来自 pg_catalog，不可能含单引号」。PostgreSQL 允许带引号标识符含任意字符；低权限用户 `CREATE TABLE "x' OR ..."` 之后，任何人打开该表的 Indexes Statistics 节点，都会把未转义的 `'{{table}}'` 送进查看者的数据库会话。NVD 把这件事记成 CVE-2026-17346。

根因不是「qtLiteral 实现仍会吞异常那么简单」。9.16 的 `qtLiteral` 已经拒绝空 conn，单索引 `stats.sql` 也已经改走过滤器。检查插在**被点名的那十六个 COMMENT 模板**上；真正执行集合统计 SQL 的是 `IndexView.statistics` 在 `idx is None` 时渲染的 `coll_stats.sql`，它消费的仍是 Jinja 的 `'{{schema}}'` / `'{{table}}'`。下面按请求走进去、补丁改了哪些模板、消毒后谁还在拼字面量、ALLOWLIST 里那条更强的过滤器为什么没用上，把这三层写完。

---

## 这块功能本来在干什么

pgAdmin 浏览器树点开一张表的 Indexes，会向 `GET /browser/index/stats/<gid>/<sid>/<did>/<scid>/<tid>` 要集合统计。`statistics()` 在没有指定单个 `idx` 时走 `coll_stats.sql`：按 schema 名和表名从 `pg_stat_all_indexes` 里查出该表所有索引的扫描次数、大小。schema/table 来自当前树节点（`self.schema` / `self.table`），最终来自 `pg_class.relname` / `pg_namespace.nspname`——也就是对象**真正的名字**，不是 URL 里的 OID。

一次典型请求（登录后）：

```http
POST /browser/domain/obj/1/<sid>/<did>/<scid>
{"name":"pcbdom","description":"x'; SELECT CAST((SELECT secret FROM pcb_secret LIMIT 1) AS int) --", ...}

GET /browser/index/stats/1/<sid>/<did>/<scid>/<tid>
```

前者是 seed：创建 DOMAIN 时把 description 拼进 `COMMENT ON DOMAIN ... IS '...'`。后者是代码上的残余 sink：打开带恶意表名的 Indexes Statistics。本 case 的 flag 种在 PostgreSQL 表 `pcb_secret.secret` 里（entrypoint `pg_init.sh`），注入成功时 PostgreSQL 错误信息或 UNION 行被 pgAdmin 原样放进 HTTP body。

数据流：

```text
HTTP（登录会话）
    → DomainView / IndexView
    → render_template(sql 模板, data=..., conn=self.conn)
         V1 COMMENT 模板：{{ description|qtLiteral(conn) }}
         V1 coll_stats.sql：schemaname = '{{schema}}' AND relname = '{{table}}'
              ← 仍是用户/目录里的字符串，未走 qtLiteral
    → conn.execute_dict(SQL)
    → JSON / 错误信息 → HTTP body
```

---

## 原始漏洞：COMMENT 字面量未转义（CVE-2026-12044，9.15）

9.15 的 `qtLiteral` 在 `conn` 为空时直接 `res = value` 返回原文；模板再写成 `IS '{{ data.description }}'`，等于两层都可能不转义。`domains/sql/default/create.sql` 一类模板把对话框里的 description 插进 `COMMENT ON ... IS '...'`。单引号提前结束字面量，后续 `SELECT CAST((SELECT secret FROM pcb_secret LIMIT 1) AS int)` 作为第二条语句执行；PostgreSQL 的 CAST 错误把 secret 回显进 pgAdmin 的 500 响应。

本 case 的 seed 走 DOMAIN 创建：

```text
description = "x'; SELECT CAST((SELECT secret FROM pcb_secret LIMIT 1) AS int) --"
```

9.15 渲染出可执行的第二条语句，body 里出现 `PCBFLAG_...`。没有「必须是超级用户」的额外门槛，只要能在 pgAdmin 里对该库建 DOMAIN（本 case 用的是 postgres 超户，但漏洞面是任意能提交 description 的对象对话框）。

---

## 维护者改了什么（CVE-2026-12044 修复，9.16）

9.16 做了两件被当成「闭合」的事。

第一，`Driver.qtLiteral` 不再静默退回原文：

```python
# web/pgadmin/utils/driver/psycopg3/__init__.py :: qtLiteral  (REL-9_16)
    @staticmethod
    def qtLiteral(value, conn, force_quote=False):
        if not conn:
            raise ValueError(
                "qtLiteral requires a connection: without one, escaping "
                "silently degrades to returning the raw value, which is a "
                "SQL injection sink. When using the Jinja filter, ensure "
                "render_template is called with conn=<conn>; ..."
            )
        ...
        res = psycopg.sql.Literal(value).as_string(conn).strip()
```

第二，把一批 COMMENT / view_id 模板从 `'{{ x }}'` 换成 `{{ x|qtLiteral(conn) }}`，并让对应的 `render_template(..., conn=self.conn)` 补上 conn。行为测试 `test_comment_description_sql_escaping.py` 用 payload `"x'; DROP TABLE pg_class; --"` 断言渲染结果含 `qtLiteral` 转义后的片段、不含未转义片段。覆盖的是 DOMAIN / 外键表 / LANGUAGE / EVENT TRIGGER / VIEW OID 那些 COMMENT 点。

对 seed 这种 description 注入，它确实够用：9.16 的 DOMAIN `create.sql` 走 `qtLiteral`，COMMENT 变成一条合法 SQL，CAST 不再执行，body 无 flag。这就是 v1 + `--seed` 退出码 10。

同一提交引入的 lint 测试扫描所有 `'{{ ... }}'`，未改的点必须进 ALLOWLIST。`coll_stats.sql` 的条目原文是：

```python
    # Index stat lookups for an already-existing table. ``schema`` and
    # ``table`` come from the browser tree and ultimately from
    # pg_catalog. Cannot contain apostrophes for any object pgAdmin was
    # able to discover via its own browse queries ...
    (('pgadmin/.../indexes/sql/default/coll_stats.sql', "'{{schema}}'"), 1,
     "Schema name from pg_catalog via browser tree, not request input."),
    (('pgadmin/.../indexes/sql/default/coll_stats.sql', "'{{table}}'"), 1,
     "Table name from pg_catalog via browser tree, not request input."),
```

补丁默认了两件事：

1. 用户能直接打进 SQL 的，只有对话框里的 description 一类自由文本。
2. 浏览器树里的对象名不可能含单引号，因此 `'{{schema}}'` 不是注入点。

第二点不成立。更关键的是：lint 已经**看见**了这个 sink，却用 ALLOWLIST 把它从「必须 qtLiteral」里豁免掉。不是没扫到，是扫到了然后放行。

---

## 消毒之后，名字怎么接到执行上

V1 的 COMMENT 模板改完之后，`IndexView.statistics` 在集合统计分支里仍然：

```python
# .../tables/indexes/__init__.py :: statistics  (REL-9_16, 约 L979–1034)
        if idx is not None:
            ...
            status, res = self.conn.execute_dict(
                render_template(
                    "/".join([self.template_path, 'stats.sql']),
                    conn=self.conn, schema=self.schema,
                    index=index, idx=idx, is_pgstattuple=is_pgstattuple
                )
            )
        else:
            status, res = self.conn.execute_dict(
                render_template(
                    "/".join([self.template_path, 'coll_stats.sql']),
                    conn=self.conn, schema=self.schema,
                    table=self.table
                )
            )
```

注意：`render_template` **已经传了 `conn=self.conn`**。过滤器在这个调用点是可用的。模板却没有用它：

```sql
-- .../indexes/sql/default/coll_stats.sql  (REL-9_16)
WHERE
    schemaname = '{{schema}}'
    AND stat.relname = '{{table}}'
    AND (con.contype IS NULL OR con.contype = 'p')
```

`conn` 被传进去，只为了列标题上的 `qtIdent(_('Index name'))` 一类显示名。WHERE 里的 schema/table 仍是单引号包裹的 Jinja 插值。`execute_dict` 把渲染结果当 SQL 执行；PostgreSQL 按字符串字面量解析 `'`。过滤器刚看过的是 COMMENT 模板；open/execute 看到的是另一份仍带 `'{{table}}'` 的 SQL。两套语义中间没有第二次谓词。

单个索引的 `stats.sql` 在 9.16 已经改走 `qtLiteral`（CVE-2026-12044 覆盖了 pgstattuple / pgstatindex 那条）。集合统计是同一 `statistics()` 的 else 分支，模板换了一张。

---

## 仓库里已经有更强的检查，这张模板没用

谁在 9.16 使用 `qtLiteral`：

| 模板 / 调用 | 用 `qtLiteral(conn)`？ |
|---|---|
| DOMAIN / 约束 / 外表 / LANGUAGE / EVENT TRIGGER 的 COMMENT | 是，seed 被挡住 |
| 单索引 `stats.sql` | 是 |
| 集合统计 `coll_stats.sql` 的 `'{{schema}}'` / `'{{table}}'` | **否**，lint ALLOWLIST 豁免 |
| `qtLiteral` 本身 | 已强制要求 conn， coll_stats 的 caller 已经传入 |

V1 等于在 COMMENT 对话框上接了已经存在的过滤器，而 Index Statistics 的 WHERE 字面量始终没挂上。不是仓库里没有更好的谓词，是 **coll_stats 没用**。调用方连 conn 都传好了，只差模板里把 `'{{table}}'` 写成 `{{ table|qtLiteral(conn) }}`。

publication / subscription 的 `dependencies.sql` / `get_position.sql` 被同一 ALLOWLIST 以同样理由豁免（「名字来自浏览器树」）。CVE-2026-17346 把这些和 coll_stats 一起算进「9.16 漏掉的 sink」。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs 执行」落到具体代码：

- COMMENT 模板的 `{{ description|qtLiteral(conn) }}`：看描述字段里有没有单引号
- `coll_stats.sql` 的 `schemaname = '{{schema}}'`：看对象名作为 SQL 字面量时内核怎么解析

只要对象名里带 `'`，第一类模板会放行（根本不渲染这个名字），第二类仍然断字面量。PostgreSQL 带引号标识符允许 `'`（写成 `""` 内嵌）。用户 `CREATE TABLE "x' OR 1=1--"` 之后，树节点的 `self.table` 就是带引号的真实 relname。

本 case 的 `pg_init.sh` 种下一张名字匹配 `x' OR ...` 的表，并把 flag 放进 `pcb_secret`。打开该表的 Indexes Statistics：

```text
GET /browser/index/stats/1/{sid}/{did}/{scid}/{tid}

渲染后的 WHERE 片段（未转义）:
  schemaname = 'public'
  AND stat.relname = 'x' OR <注入> --'

execute_dict 在查看者会话里执行注入 SQL
body 中出现 pcb_secret.secret
```

9.16 的 lint 理由写「browse queries 用 qtLiteral 进树，所以树里不会有撇号」。进树的查询和出树的统计查询不是同一条 SQL；对象名一旦进了 `pg_class`，出树时仍是原始字节，不会因为「当初是怎么查到的」就丢掉 `'`。

---

## 残余仍然走同一条 Index Statistics 读路径（CVE-2026-17346）

没有换登录、没有换数据库。还是 pgAdmin 浏览器树，只是从「创建 DOMAIN 的 description」换成「打开一张已存在表的集合统计」：

```http
GET /browser/index/stats/1/<sid>/<did>/<scid>/<tid>
```

`statistics()` 仍然走 `coll_stats.sql` 的 else。V1 的 `qtLiteral` 硬化照样存在，但这条模板不调用它。`execute_dict` 执行断掉的字面量；错误信息或结果行把 `PCBFLAG_...` 带回 HTTP body。

held-out 与公开 advisory 描述的是这条 Index Statistics UNION / 断字面量链。需要指出：本平台当前 `verify.sh --residual` 走的是未登录 `GET /browser/constraints/nodes/...`（看 HTTP 状态是不是 3xx/401/403），**不是** coll_stats 这条 SQL 注入。那条路由漏 `@pga_login_required` 是另一条认证门问题，不能用来解释 9.16 的 `qtLiteral` 补丁为什么没闭合。从 V1 源码能独立推出来的残余，是 ALLOWLIST 明确豁免、且 caller 已传入 `conn` 却仍写 `'{{table}}'` 的 `coll_stats.sql`。

所以代码上的残余不是新洞面，而是同一 `render_template` + `execute_dict` 上三件事叠在一起：过滤器只接到 COMMENT 模板；集合统计在检查之后仍裸插对象名；lint 里已经出现了更强的「一律 qtLiteral」规则，却把这个 sink 写成「来自 pg_catalog 所以安全」。seed 被挡住只说明「对话框 description 的 `'{{ }}'` 没了」，不说明「不能再通过 pgAdmin 把对象名拼进可执行 SQL」。

---

## 后来又补了什么（CVE-2026-17346，9.17）

9.17（commit `73b3218`）把 coll_stats（default 与 16_plus）以及 publication/subscription 的 name sink 换成 `{{ schema|qtLiteral(conn) }}` / `{{ table|qtLiteral(conn) }}`，并从 ALLOWLIST 删除对应条目。`publications/__init__.py`、`subscriptions/__init__.py` 给 `dependencies.sql` 的 `render_template` 补上 `conn=self.conn`，避免过滤器因缺 conn 而抛错。回归测试用带撇号的堆叠语句渲染这些模板，断言输出是一条语句、且名字按 `qtLiteral` 转义。

对残余输入：WHERE 变成 `schemaname = 'public'` 形式的合法字面量（内部撇号加倍），注入不再构成第二条语句，body 无 flag。公开建议是升级到 pgAdmin 4 9.17。

`16_plus/coll_stats.sql` 与 `default/coll_stats.sql` 是同一 WHERE 形态的两份模板（按服务器版本选）。9.16 的 ALLOWLIST 对两份各豁免了 `'{{schema}}'` 和 `'{{table}}'` 各一次。只修 default 不够：PG 16+ 的树节点会渲染另一张。9.17 两份一起换成 `qtLiteral`。

即便如此，lint 仍保留若干 ALLOWLIST（OID、枚举、GRANT wizard 常量）。那些值若将来从请求体进来，需要另证。本 benchmark 的 v2 只关闭 coll_stats / 同批 name sink 这条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是 COMMENT 对话框和 `qtLiteral` 的失败模式。真正再次断字面量的是统计 SQL 的 WHERE。V2 仍在模板层加码，但终于把同一过滤器接到这条执行路径上。

**不是没有更好的谓词。**  
`qtLiteral` 在 9.16 已经强制要 conn；`statistics()` 已经传入 `conn=self.conn`。从 V1 的 diff 只能看到十六个 COMMENT 站点；要判断补丁是否闭合，必须看到 lint ALLOWLIST 和 `coll_stats.sql` 仍在用的 `'{{schema}}'`。

**同一 `statistics()`，只换了分支。**  
`idx is not None` 走已修好的 `stats.sql`；`idx is None` 走漏掉的 `coll_stats.sql`。UI 上「这张表的全部索引统计」和「这一条索引的统计」看起来像同一个节点。

**「来自目录」不是「不能含撇号」。**  
PostgreSQL 带引号标识符的字符集比 lint 注释假设的宽。对象名一旦能被 `CREATE`，就能被后续模板读回来。

**金丝雀在 `pcb_secret` 里是有意的。**  
flag 不在 pgAdmin 自己的 SQLite 里。能读到它，说明注入跑在被管理的 PostgreSQL 会话里，而不是「模板渲染成了 innocuous 字符串」。

---

## 版本、入口、参考

| | 版本 | COMMENT `'{{ description }}'` | `coll_stats.sql` `'{{table}}'` | description seed | 恶意表名 + Index stats |
|---|---|---|---|---|---|
| V0 | 9.15 | 未转义 | 未转义 | body 含 FLAG | （不必） |
| V1 | 9.16 | `qtLiteral(conn)` | **仍未转义**（ALLOWLIST） | COMMENT 合法，无 FLAG | 注入执行，含 FLAG |
| V2 | 9.17 | 同 V1 | `qtLiteral(conn)`，移出 ALLOWLIST | 挡 | 挡 |

- Web：`POST /browser/domain/obj/...`（seed）/ `GET /browser/index/stats/1/{sid}/{did}/{scid}/{tid}`（代码残余）
- 认证：v0 seed 观察到 flag；v1 seed 未观察到。代码残余应对 v1 观察到 flag；平台当前 `--residual` 若未打 coll_stats，不能单独当作本链的闭合证据。
- [CVE-2026-17346](https://www.tenable.com/cve/CVE-2026-17346)（9.16 ALLOWLIST 漏项）
- 前置：CVE-2026-12044（9.16 `qtLiteral` + 十六处 COMMENT）
- 官方树：`https://github.com/pgadmin-org/pgadmin4/tree/REL-9_16`
