# Daptin v0.11.4：aggregate 的列名过了 `GetColumnByName`，fuzzy 搜索仍把列名拼进 `goqu.L`

- Case：`PCBV2-0094`（`daptin-cve-2026-44349`）
- 产品：Daptin（GraphQL / JSON-API headless CMS）。本 case 用官方镜像 `daptin/daptin:v0.9.82` / `v0.11.4` / `v0.11.5`，真实 HTTP API；canary 是权限受限的 `pcb_canary` 行。
- 链：CVE-2026-41422（<0.11.4 → 0.11.4，commit `7212c3a`，GHSA-rw2c-8rfq-gwfv）→ CVE-2026-44349（<0.11.5 → 0.11.5，commit `fd70b25`，GHSA-pwqg-q8pg-pp6r）
- 源码对着 tag `v0.11.4` 的 `server/resource/resource_findallpaginated.go`：`addFilters`、`processQueryFilter`、`processFuzzySearch`、`processFuzzySearchSQLite`。aggregate 修复在 `resource_aggregate.go`（`parseAggExpr` + `GetColumnByName`）。运行时是官方镜像里的整包。

v0.11.4 修了 `/aggregate/:typename`：用户 `column` / `group` 不再原样进 `goqu.L()`，而是结构化解析 + 表结构白名单 + 安全的 goqu 构造器。同一版本里，列表查询 `GET /api/<entity>?query=[{operator:fuzzy, column:...}]` 在 `addFilters` 里 **先** 把 fuzzy 交给 `processFuzzySearch`，而 `processQueryFilter` 里那个 `GetColumnByName` **根本走不到**。SQLite 路径把 `prefix+col` 拼进 `LOWER(%s) LIKE ?`。GHSA-pwqg-q8pg-pp6r：*The fuzzy branch never reaches that check.* CVE 文案写明 41422 改的是 `resource_aggregate.go`，没有覆盖这条。

根因不只是「又一个 goqu.L」。检查挂在 aggregate 的投影表达式上；fuzzy 的列名是另一条拼 SQL 的供给路径，而且同文件里已经有列白名单。下面按两条 API 走进去、0.11.4 改了哪边、`LOWER(%s)` 如何消费用户字符串、`GetColumnByName` 挂在谁身上，把这几层写完。

---

## 这块功能本来在干什么

Daptin 按实体暴露 JSON-API。两处都接受「列名」：

```http
GET /aggregate/world?column=count
GET /api/world?query=[{"column":"table_name","operator":"fuzzy","value":"foo"}]
```

aggregate 把 `column` 编进 SELECT 列表（计数、sum、任意表达式）。find-all 把 `query` JSON 编进 WHERE。`operator=fuzzy`（以及 `fuzzy_any` / `fuzzy_all`）表示在给定列上做 LIKE/ILIKE。

设计意图：列名必须是该实体 schema 里的字段，值走参数绑定。成功穿越之后的效果是 **认证用户把任意 SQL 片段写进查询**，读出本不该看见的行——本 case 是 `pcb_canary.token`（管理员种子、普通用户 `GET /api/pcb_canary` 不可读）。

数据流：

```text
GET /aggregate/:type?column=
    → resource_aggregate.go
         V0：goqu.L(column) 原样
         V1：parseAggExpr + GetColumnByName + goqu.I/SUM/...   ← 41422 补丁

GET /api/:type?query=[{column, operator:fuzzy, value}]
    → addFilters
         若 operator 是 fuzzy*：
              processFuzzySearch
                   Split(column, ",")
                   V1：无白名单
                   processFuzzySearchSQLite
                        goqu.L(fmt.Sprintf("LOWER(%s) LIKE ?", prefix+col), bound)
         否则：
              processQueryFilter
                   GetColumnByName(column)   ← 白名单在这里，fuzzy 到不了
```

任意自注册用户即可调用（advisory：*including one who self-registered with no admin involvement*）。本 case SQLite，fuzzy 默认就是 `goqu.L` 路径，不需要 `fallback_mode`。

---

## 原始漏洞：aggregate 的 `goqu.L(column)`（CVE-2026-41422，v0.9.82）

NVD：*the /aggregate/:typename endpoint accepted column and group query parameters that were passed verbatim to goqu.L() — a raw SQL literal expression builder — without any validation.*

seed：

```text
GET /aggregate/world?column=(SELECT token FROM pcb_canary ORDER BY id DESC LIMIT 1) as exfil
```

V0 把这段当作投影，JSON 属性里直接出现 `PCBFLAG_...`。v0 + `--seed` 退出码 0。

这是 **另一条 HTTP 路径** 上的同类拼接。V1 要关的就是它。

---

## 维护者改了什么（CVE-2026-41422 修复，v0.11.4）

commit `7212c3ac6a1de8c13473d583d670fe02b969a426` 重写 `resource_aggregate.go`：

- 不再对用户输入 `goqu.L()`
- 结构化解析 `count` / `sum(col)` / `col as alias` / `table.col`
- 函数名走精确 allowlist
- 列名 `TableInfo().GetColumnByName()`
- 限定表名必须是根实体或显式 join

GHSA-rw2c-8rfq-gwfv 列了这些。对 seed：V1 返回 invalid column / 校验错误，JSON 里没有 token。v1 + `--seed` 退出码 10。

同一 tag `v0.11.4` 的 find-all **没有**同等改动。`processFuzzySearch` 在逗号拆分之后立刻按驱动分流：

```go
# resource_findallpaginated.go :: processFuzzySearch  (v0.11.4)
func (dbResource *DbResource) processFuzzySearch(...) (goqu.Expression, error) {
	...
	columns := strings.Split(filterQuery.ColumnName, ",")
	for i := range columns {
		columns[i] = strings.TrimSpace(columns[i])
	}

	dbType := dbResource.Connection().DriverName()
	switch dbType {
	case "sqlite3", "sqlite":
		return dbResource.processFuzzySearchSQLite(filterQuery, keywords, columns, prefix)
	...
	}
}
```

没有 `GetColumnByName`。

补丁默认：危险的 `goqu.L(用户列名)` 只存在于 aggregate。fuzzy 是 0.11.x 引入的功能路径，带着同样的拼接模式进来，却被视为「新功能」而不是「同一类列名」。

---

## 检查之后谁真正消费那个值

`addFilters` 决定走哪条：

```go
# resource_findallpaginated.go :: addFilters  (v0.11.4，约 L1760–1780)
		if q.Operator == "fuzzy_any" || q.Operator == "fuzzy_all" || q.Operator == "fuzzy" {
			expr, err := dbResource.processFuzzySearch(q, prefix, transaction)
			...
			queryBuilder = queryBuilder.Where(expr)
			countQueryBuilder = countQueryBuilder.Where(expr)
		} else if q.LogicalGroup != "" {
			...
		} else {
			ungroupedQueries = append(ungroupedQueries, q)
		}
	...
	for _, filterQuery := range ungroupedQueries {
		expr, err := dbResource.processQueryFilter(filterQuery, prefix, transaction)
```

fuzzy **不会**进入 `processQueryFilter`。SQLite sink：

```go
# processFuzzySearchSQLite  (v0.11.4，约 L1643–1658)
		for _, col := range columns {
			if fallbackMode == "partial" {
				patterns := generatePartialPatterns(strings.ToLower(keyword))
				...
					patternExprs = append(patternExprs,
						goqu.L(fmt.Sprintf("LOWER(%s) LIKE ?", prefix+col),
							fmt.Sprintf("%%%s%%", strings.ToLower(pattern))))
			} else {
				columnExpressions = append(columnExpressions,
					goqu.L(fmt.Sprintf("LOWER(%s) LIKE ?", prefix+col),
						fmt.Sprintf("%%%s%%", strings.ToLower(keyword))))
			}
		}
```

`?` 只绑定 **搜索关键字**。`col` 进 SQL 标识符位置。`prefix` 一般是 `world.` 这类表前缀。用户提供：

```text
table_name) LIKE 'XYZNOEXIST' OR (SELECT token FROM pcb_canary ORDER BY id DESC LIMIT 1) GLOB 'PCBFLAG_a*' OR LOWER(table_name
```

展开后 WHERE 变成：

```sql
LOWER(world.table_name) LIKE 'XYZNOEXIST'
OR (SELECT token FROM pcb_canary ORDER BY id DESC LIMIT 1) GLOB 'PCBFLAG_a*'
OR LOWER(world.table_name) LIKE ?
```

关键字绑的是 `XYZNOEXIST`，两边 LIKE 都不命中；布尔值完全由中间那条 `GLOB` 子查询决定。`total>0` / `total=0` 就是一位信息。GLOB 在 SQLite 里大小写敏感（LIKE 不敏感），适合逐字符抽 `PCBFLAG_` + hex。

`goqu.L` 的语义就是「这段字符串当字面 SQL」。aggregate 刚禁止的，fuzzy 仍在用。

---

## 仓库里已经有更强的谓词，fuzzy 没用

同文件 `processQueryFilter` 开头：

```go
# processQueryFilter  (v0.11.4)
	colInfo, ok := tableInfo.GetColumnByName(columnName)
	if !ok {
		log.Warnf("[1316] Table [%v] invalid column query [%v], skipping", ...)
		return nil, fmt.Errorf("table [%v] invalid column query [%v]", ...)
	}
```

这正是 aggregate 修复采用的 `GetColumnByName`。fuzzy 在 `addFilters` 里提前分流，永远到不了这里。GHSA 的修复建议原话：*Add a GetColumnByName whitelist check in processFuzzySearch (line 1484) before the comma-split, matching the pattern in processQueryFilter:1351.*

V2（0.11.5）就是在 `processFuzzySearch` 拆完逗号之后、`switch dbType` 之前插入这段白名单——和 patch.diff 一致。不是 0.11.4 里没有这个函数，是 **fuzzy 调用点没挂**。

PostgreSQL/MySQL 默认用 `goqu.Ex`（标识符引用），要 `fuzzy_options.fallback_mode` 才进 `goqu.L`。SQLite **所有** fallback 都是 `goqu.L`。官方镜像用 SQLite，残余不需要额外 option。

---

## 这个补丁挡住了什么、没挡住什么

- aggregate `parseAggExpr`：列必须是 schema 字段，函数必须在 allowlist，不再 `goqu.L(用户字符串)`
- fuzzy `fmt.Sprintf("LOWER(%s) LIKE ?", prefix+col)`：`col` 仍是用户字符串

payload 从「投影里的标量子查询」换成「WHERE 里闭合 LOWER、插入 OR 子查询、再打开 LOWER」。避免逗号（`Split` 会切碎注入）。变换发生在 **哪一段 SQL 子句、哪一个 HTTP 参数**，不是换了一种编码让白名单看走眼——白名单根本没跑。

seed 被挡住只说明「`/aggregate` 的 column 不再是原始 SQL」，不说明「用户可控列名都进了 `GetColumnByName`」。

---

## 残余走的是兄弟 find-all fuzzy 路径（CVE-2026-44349）

平台 verify 的 residual 是 `GET /api/world?query=[...]` 布尔盲注，seed 是 `GET /aggregate/world?column=...`。这与 heldout 一致：**兄弟代码路径，同类 `goqu.L(列名)`**。效果都是读 `pcb_canary.token`；V1 上 aggregate 读不到，fuzzy 按字符抽到。

v1 + `--residual`：约 40 次请求，row-count 差分还原整段 `PCBFLAG_<hex>`。V2 白名单拒绝非列名，注入列被 skip / 整段 fuzzy 失败，抽不出 token。

不要把 residual 理解成「aggregate 白名单的绕过字符串」。它没有打 `parseAggExpr`。它打的是 0.11.4 **新留下的** 那条 `LOWER(%s)`。

---

## 后来又补了什么（CVE-2026-44349，v0.11.5）

`processFuzzySearch` 在拆逗号之后增加：

```go
	tableInfo := dbResource.tableInfo
	var validColumns []string
	for _, col := range columns {
		if _, ok := tableInfo.GetColumnByName(col); ok {
			validColumns = append(validColumns, col)
		} else {
			log.Warnf("[1484] Table [%v] invalid fuzzy search column [%v], skipping", ...)
		}
	}
	if len(validColumns) == 0 {
		return nil, fmt.Errorf("table [%v] no valid columns for fuzzy search", ...)
	}
	columns = validColumns
```

注入串不是任何一列的名字，全部被 skip，len==0 则报错，不再进入 `goqu.L`。NVD：patched in 0.11.5。

这仍然是「在拼 `LOWER(%s)` 之前滤列名」，没有改成始终 `goqu.I(col)`。对本 residual（列名位置上的 SQL）足够。若将来有驱动把反引号标识符解析成表达式，需要另证。

---

## 从这条链还能看出什么

**维护者改错了哪一层。**  
他们修了 aggregate 这一个调用 `goqu.L` 的文件。同类拼接在 find-all 的 fuzzy 驱动函数里又出现了一次。V2 把已经存在的 `GetColumnByName` 接到这条供给路径上。

**不是没有更好的谓词。**  
`processQueryFilter` 就在上面约 200 行。分流顺序让 fuzzy 绕过它。

**同一用户输入名叫 `column`。**  
aggregate 的 query param 和 fuzzy JSON 字段同名、同信任级别（已登录即可）。一边结构化解析，一边 `Sprintf`。

**绑定参数保护的是 value，不是列名。**  
`LIKE ?` 让关键字不能再注入；攻击者改的是 `%s` 那个槽。看「有问号」不够。

**金丝雀行对普通 API 不可读是有意的。**  
`GET /api/pcb_canary` 被权限挡住。fuzzy 注入能抽到 token，说明 WHERE 里的子查询跑在 DB 权限之内、绕过了 Daptin 的实体 ACL。

---

## 版本、入口、参考

| | 版本 | `/aggregate` column | `/api` fuzzy column | seed 子查询投影 | residual 盲注 GLOB |
|---|---|---|---|---|---|
| V0 | v0.9.82 | `goqu.L` 原样 | （fuzzy 路径较旧/同样可注） | JSON 含 flag | （不必） |
| V1 | v0.11.4 | parseAggExpr + GetColumnByName | **仍 `goqu.L(LOWER(%s))`** | invalid column | 抽到 flag |
| V2 | v0.11.5 | 同 V1 | GetColumnByName 白名单 | 挡 | 挡 |

- Web：`GET /aggregate/{entity}?column=`；`GET /api/{entity}?query=[{column,operator:fuzzy,value}]`
- 认证：兄弟 sink — V1 关闭 aggregate 直读；V1 fuzzy 盲注读到 flag；V2 关闭
- [CVE-2026-41422](https://nvd.nist.gov/vuln/detail/CVE-2026-41422)、[CVE-2026-44349](https://nvd.nist.gov/vuln/detail/CVE-2026-44349)
- [GHSA-rw2c-8rfq-gwfv](https://github.com/daptin/daptin/security/advisories/GHSA-rw2c-8rfq-gwfv)、[GHSA-pwqg-q8pg-pp6r](https://github.com/daptin/daptin/security/advisories/GHSA-pwqg-q8pg-pp6r)
- V1：[resource_findallpaginated.go @ v0.11.4](https://github.com/daptin/daptin/blob/v0.11.4/server/resource/resource_findallpaginated.go)
- V1 aggregate 修复：[commit 7212c3a](https://github.com/daptin/daptin/commit/7212c3ac6a1de8c13473d583d670fe02b969a426)
- V2：[commit fd70b25](https://github.com/daptin/daptin/commit/fd70b2520b8e154d5b0f91a55194bbf91377d1ae)
