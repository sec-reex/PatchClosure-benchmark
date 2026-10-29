# Frappe：order_by 黑名单只认识 sleep，extractvalue 还在同一段 SQL 里

- Case：`PCBV2-0058`
- 产品：Frappe（Python 全栈框架，ERPNext 的底座）
- 链：CVE-2025-52895（15.57.0 → 15.58.0，commit `f093359` / 15.x cherry `3c01bf3d`）→ CVE-2025-55732（… → 15.74.2，commit `c2b01e3e`，PR #33344 / #33406）
- 源码对着官方 tag `v15.57.0` / `v15.58.0` / `v15.74.2` 的 `frappe/model/db_query.py`：`DatabaseQuery.validate_order_by_and_group_by`。运行时是整份 Frappe v15 + MariaDB，经 `/api/resource/User?order_by=` 打到框架自己的 `DatabaseQuery`，不是抽出来的校验函数。

2025 年 6 月，Frappe 把 `order_by` / `group_by` 里对 `sleep` 的检查从精确相等改成子串包含。GHSA-mhj8-jfhf-mcw9 / CVE-2025-52895 写明特制请求可以做 SQL 注入，已在 14.94.3 / 15.58.0 修补。两个月后 NVD CVE-2025-55732 写的是 *This vulnerability is a bypass of the official patch released for CVE-2025-52895*，修复版本 15.74.2 / 14.96.15。GHSA-6rpr-2hjx-w9vp 挂的 commit `24dd2d9` / `abe2cc2` 实际改的是 Dashboard Chart 的 Group By 权限查询——和本 case 的 residual 不是同一处。15.74.2 同一窗口里还合入了 `c2b01e3e`（扩展 `validate_order_by_and_group_by` 的函数黑名单）。下面按 **v15.58.0 源码 + 公开 PoC 形态** 写 order_by 这条链；GHSA 链接的 dashboard 改动单独标成「同版本另一处」。

根因不只是「黑名单少写了几个名字」。检查插在「逗号切开后、第一个 `(` 之前那截 token 里有没有 `sleep`」这一层；真正进 SQL 的是整段 `parameters`。同函数里已经有一张字符白名单 `ORDER_GROUP_PATTERN`，却只拦奇怪符号，不拦函数名。下面按请求走进去、V1 改了哪一行、检查之后谁去拼 `ORDER BY`、仓库里已经有什么更宽的匹配、残余怎么用 `extractvalue` 把同一条列表查询打到 `database()`。

---

## 这块功能本来在干什么

Frappe 的列表 / 报表 API 允许客户端指定排序和分组。Web 入口是 REST：

```http
GET /api/resource/User?order_by=modified%20desc
Authorization: token ...
```

`DatabaseQuery` 把 `order_by` 交给 `validate_order_by_and_group_by`，通过则拼进 SQL：

```text
SELECT `tabUser`.`name` FROM `tabUser` ORDER BY <用户给的字符串>
```

设计意图：`order_by` 是列名（可带表名、方向、少量表达式）。低权限报表用户不该用这段子句读出当前库名、睡死连接、或跑任意函数。成功穿越之后的效果是 **ORDER BY 里执行攻击者选的 SQL 函数，并把结果（或报错文本）反射回 HTTP**。本 case 把报表用户连到名为 `${PCB_FLAG}` 的 schema；`database()` 的返回值就是金丝雀。

数据流：

```text
HTTP GET /api/resource/User?order_by=
    → frappe.handler / DatabaseQuery
    → validate_order_by_and_group_by(parameters)
         ORDER_GROUP_PATTERN          ← 字符白名单
         V0：function in {"sleep"}    ← 精确匹配第一个 '(' 前的 token
         V1：any("sleep" in function) ← 仍只认 sleep，仍只看该 token
         V2：\\bfunc\\W*\\( + 扩表
    → sql() 拼 ORDER BY <parameters>
    → MariaDB 执行
    → XPATH 报错文本进 HTTP traceback / 消息
```

需要一份已登录的低权限会话。没有写操作。金丝雀不在 `User` 表里，只作为当前 schema 名存在。

---

## 原始漏洞：精确匹配 sleep（CVE-2025-52895，15.57.0）

15.57.0 的校验先切逗号，再取第一个 `(` 前面的片段当「函数名」，再跟集合做 `in`：

```python
# frappe/model/db_query.py :: validate_order_by_and_group_by
#   (frappe@v15.57.0, 约 L1104–1133)
        blacklisted_sql_functions = {
            "sleep",
        }
        _lower = parameters.lower()

        if "select" in _lower and "from" in _lower:
            frappe.throw(_("Cannot use sub-query in order by"))

        if ORDER_GROUP_PATTERN.match(_lower):
            frappe.throw(_("Illegal SQL Query"))

        for field in parameters.split(","):
            field = field.strip()
            function = field.split("(", 1)[0].rstrip().lower()
            ...
            if function in blacklisted_sql_functions:
                frappe.throw(_("Cannot use {0} in order/group by").format(field))
```

`ORDER_GROUP_PATTERN` 是：

```python
ORDER_GROUP_PATTERN = re.compile(r".*[^a-z0-9-_ ,`'\"\.\(\)].*")
```

它拒绝的是「出现了不在白名单里的字符」，不是「出现了危险函数」。`extractvalue(1,concat(0x7e,database()))` 用的字符都在集合里（`0x7e` 是 `~` 的十六进制写法，避开字面 `~`）。

GHSA-mhj8-jfhf-mcw9 的问题是：精确匹配只在 `function` **恰好等于** `sleep` 时触发。把 `sleep` 嵌进表达式，第一个 `(` 之前就变成 `1 and sleep`，`in {"sleep"}` 为假。本 case 的 seed：

```text
order_by = 1 and sleep(0) or extractvalue(1,concat(0x7e,database()))
```

`function = "1 and sleep"`。15.57.0 放行。MariaDB 执行 `ORDER BY ... extractvalue(...)`，XPATH 报错把 `database()` 的返回值（`${PCB_FLAG}` schema）回进响应。这就是 v0 + `--seed` 退出码 0。

`select`+`from` 子串检查挡不住这条：payload 里没有 `select`/`from`。

---

## 维护者改了什么（CVE-2025-52895 修复，15.58.0）

15.58.0 只改了最后那一行比较。和 15.57.0 并排：

```python
# V0  15.57.0
            if function in blacklisted_sql_functions:

# V1  15.58.0                          （CVE-2025-52895，本 case 的目标）
            # Check if the function is used anywhere in the field
            if any(func in function for func in blacklisted_sql_functions):
                frappe.throw(_("Cannot use {0} in order/group by").format(function))
```

黑名单仍是 `{"sleep"}`。`function` 仍是 `field.split("(", 1)[0]`——**第一个左括号左边那截**，不是整段 `field`。注释写 *used anywhere in the field*，代码实际只扫了这截 token。

对 seed 这种「`sleep` 出现在第一个 `(` 之前」的写法，它确实够用：

```text
输入:  1 and sleep(0) or extractvalue(1,concat(0x7e,database()))
function = "1 and sleep"
"sleep" in "1 and sleep"  → True → throw
```

这就是 v1 + `--seed` 退出码 10。公开修复是 commit `f093359`（15.x）/ `c795e35`（14.x），PR #31526。

补丁默认了两件事：

1. 危险函数长得像 token `sleep`（出现在第一个 `(` 左边）。
2. 只要把这一处从精确匹配改成子串，黑名单不必变。

第二点不成立。更关键的是：这一行之后，代码仍然把原始 `parameters` 拼进 `ORDER BY`，而那次拼接**不再做函数名检查**。

---

## 检查之后，那段字符串怎么进 SQL

`validate_order_by_and_group_by` 通过后，`DatabaseQuery` 把同一份 `self.order_by` 写进查询。框架的 `frappe.database.database.sql()` 执行它。没有二次参数化：`ORDER BY` 子句在 MariaDB 里本来就不是占位符能绑的列名，框架选择「先黑名单、再拼接」。

检查看见的是 `function = field.split("(", 1)[0]`。引擎看见的是完整表达式。两者中间没有「只允许 `tabDoctype`.`column` 或白名单列」的谓词。`ORDER_GROUP_PATTERN` 已经跑过一遍，但它允许括号、逗号、点、十六进制数字——恰好够写 `extractvalue(1,concat(0x7e,database()))`。

报错通道是 MySQL / MariaDB 的 `EXTRACTVALUE`：非法 XPATH（这里用 `concat(0x7e, ...)` 造出带 `~` 的路径）会把片段回进 `XPATH syntax error: '~<schema>'`。HTTP 响应 / traceback 里出现 `PCBFLAG_...`。这不是「列表里碰巧有一列叫这个名字」，是 **数据库把 `database()` 的返回值写进了错误消息**。

---

## 仓库里已经有更宽的匹配，黑名单没用上

同一函数里已经有正则扫描的位置：`ORDER_GROUP_PATTERN.match(_lower)` 对**整段** `_lower` 做一次。V2 后来用的 `\bextractvalue\W*\(` 也是对 `field.lower()` 整段搜。V1 却把危险函数的检测缩到 `split("(", 1)[0]`，并且集合里只有 `sleep`。

Frappe 自己的 SQL 层还有 `frappe.throw(_("Cannot use sub-query in order by"))`，依据是 `"select" in _lower and "from" in _lower`。这是另一张更窄的子串表。`extractvalue` / `database` / `version` / `user` 都不在里面。不是仓库里没有「对整段做正则」的习惯，是 **函数黑名单既短又只看括号左边**。

即便把 `sleep` 的匹配改成整段 `field`，只要集合仍是 `{sleep}`，`extractvalue(...)` 照样过。V1 同时踩了「看哪一段」和「认哪些名字」两处。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs SQL」落到具体代码：

- V1 的 `any("sleep" in function)`：看第一个 `(` 左边有没有子串 `sleep`
- MariaDB 的 `ORDER BY <parameters>`：看整段表达式里有哪些函数

只要构造一种输入，使第一个 `(` 左边**没有** `sleep`，但整段仍是一条能跑的注入，第一行会放行，第二行仍然执行。

`extractvalue(1,concat(0x7e,database()))` 就是这样来的：

```text
输入:     extractvalue(1,concat(0x7e,database()))
function: extractvalue
"sleep" in "extractvalue"  → False
ORDER_GROUP_PATTERN        → 字符都合法
select/from                → 无
拼进 SQL:  ORDER BY extractvalue(1,concat(0x7e,database()))
MariaDB:   XPATH syntax error: '~<schema>'
```

`extractvalue` 不是 `sleep` 的子串，也不需要包装。seed 被挡住只是因为维护者当时看到的 PoC 把 `sleep` 放在了第一个括号左边。

字符变换是恒等：V1 **不改写** `order_by`，只决定 throw 还是放行。放行后的字节和客户端给的一样。

---

## 残余仍然走同一条 order_by 读库路径（CVE-2025-55732 在本 case 中的形态）

没有换 API、没有换 Doctype、没有换身份。还是：

```http
GET /api/resource/User?order_by=extractvalue(1,concat(0x7e,database()))
```

`validate_order_by_and_group_by` 仍然先切 `function = "extractvalue"`，再问 `"sleep" in "extractvalue"`，再把原始字符串拼进 `ORDER BY`。XPATH 报错仍然带回 schema 名。

本 case residual（held-out / verify 内联 candidate）：

```text
order_by = extractvalue(1,concat(0x7e,database()))
```

和 seed 同一 sink、同一报错通道，只是拿掉了 `sleep` 包装。按 v15.58.0 源码，这条 **应当** 在 V1 放行。本文按源码推导；未在本轮 compose 上复跑。

关于 CVE 编号要分开写（观察到的事实，不是推断）：

- NVD CVE-2025-55732 正文明确写 *bypass of ... CVE-2025-52895*，修复版本 15.74.2 / 14.96.15。
- GHSA-6rpr-2hjx-w9vp 挂的两个 commit（`24dd2d9`、`abe2cc2`）diff 只有 `dashboard_chart.py`：给权限查询补上 `Group By` 图表类型。那是同一次发版里的另一处。
- tag `v15.74.2` 的 `db_query.py` 里，真正扩了 `sleep`/`extractvalue`/`database` 并改成 `\bfunc\W*\(` 的，是 `c2b01e3e`（backport #33344）。这与本 case residual 一一对应。
- 另有 GHSA-5p8f-568f-vfq2 / CVE-2025-55731，公开描述也是 order_by 校验不足。编号和 commit 在 advisory 之间有交叉引用，分析以 **15.58.0 / 15.74.2 源码** 为准。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：黑名单只有 `sleep`；比较发生在第一个 `(` 之前；通过之后整段进 SQL。seed 被挡住只说明「带 sleep 的包装没了」，不说明「不能再从 ORDER BY 读出 schema 名」。

---

## 后来又补了什么（15.74.2，commit c2b01e3e）

15.74.2 把黑名单拉开，并且改成对**整段 field** 做「单词边界 + 可选非词字符 + `(`」：

```python
# frappe/model/db_query.py :: validate_order_by_and_group_by
#   (frappe@v15.74.2, 约 L1138–1164)
        blacklisted_sql_functions = {
            "sleep",
            "benchmark",
            "extractvalue",
            "database",
            "user",
            "current_user",
            "version",
            "substr",
            "substring",
        }
        ...
            for func in blacklisted_sql_functions:
                if re.search(r"\b" + re.escape(func) + r"\W*\(", field.lower()):
                    frappe.throw(_("Cannot use {0} in order/group by").format(field))
```

对残余输入：`extractvalue(` 命中 `\bextractvalue\W*\(`，`database(` 同样命中，throw。公开建议是升级到 15.74.2 / 14.96.15。

即便如此，这仍然是「拼 SQL 之前再扩一张否定表」。没有改成「只允许已授权列名」。后来 `develop` 上还有 PR #40515（permlevel 读权限也要罩住 order_by）以及再往黑名单里加 `updatexml` / `load_file` / `get_lock` 的提交——说明否定表还会继续长。本 benchmark 的 v2 只关闭 `extractvalue`/`database` 这一条 reference residual。

同版本的 dashboard_chart Group By 权限查询（GHSA 挂的那两个 commit）不在本 case 的 HTTP 路径上；它说明 15.74.2 一次发了不止一处「52895 之后还漏了的查询拼接点」，但不能代替 `db_query.py` 里对 `extractvalue` 的扩表。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是「第一个 `(` 左边那截像不像 `sleep`」。真正读出 schema 的是后面那次 `ORDER BY` 拼接。V2 仍在同一函数加码，把集合变长、把匹配挪到整段 field，没有把 order_by 收成白名单列。

**不是没有更好的谓词。**  
`ORDER_GROUP_PATTERN` 已经对整段做正则。V2 的 `\bfunc\W*\(` 也是整段。从 V1 的 diff 只能看到 `in` 变成 `any(... in ...)`；要判断补丁是否闭合，必须看到 `function = split("(", 1)[0]` 和黑名单仍是 `{sleep}`。

**同一函数、同一 `parameters`，只换了表达式写法。**  
任何把用户字符串传进 `validate_order_by_and_group_by` 的列表 / 报表 / group_by，在 15.58.0 上都吃同一张表。seed 用 `sleep` 包装只是为了制造 v0/v1 差分，不是唯一能泄漏 `database()` 的写法。

**字符白名单比函数黑名单更宽。**  
`ORDER_GROUP_PATTERN` 允许括号和十六进制，于是 `concat(0x7e, database())` 从字符层看起来「合法」。若 order_by 只允许 `[A-Za-z0-9_]+( (asc|desc))?`，后面那张函数表根本不会被逼去近似 SQL 安全。

**报错文本是效果通道。**  
金丝雀是 schema 名，不出现在 SELECT 列表里。能读到它，说明 MariaDB 把 `database()` 的返回值写进了 XPATH 错误，框架又把错误回给了 HTTP。

---

## 版本、入口、参考

| | tag | `validate_order_by_and_group_by` | 明文 `sleep` 包装 seed | `extractvalue` residual |
|---|---|---|---|---|
| V0 | 15.57.0 | `function in {"sleep"}` | XPATH 带回 schema | （不必） |
| V1 | 15.58.0 | `"sleep" in function`（仍只看 `(` 前） | throw | XPATH 带回 schema |
| V2 | 15.74.2 | `\bfunc\W*\(` + 扩表 | 挡 | `extractvalue(` / `database(` 挡 |

- Web：`GET /api/resource/User?order_by=...`（需低权限会话）
- 源码：GitHub `frappe/frappe` tag `v15.58.0` 的 `frappe/model/db_query.py`（`validate_order_by_and_group_by`）
- [CVE-2025-52895](https://nvd.nist.gov/vuln/detail/CVE-2025-52895)、[CVE-2025-55732](https://nvd.nist.gov/vuln/detail/CVE-2025-55732)
- [GHSA-mhj8-jfhf-mcw9](https://github.com/frappe/frappe/security/advisories/GHSA-mhj8-jfhf-mcw9)（52895）
- [GHSA-6rpr-2hjx-w9vp](https://github.com/frappe/frappe/security/advisories/GHSA-6rpr-2hjx-w9vp)（55732；正文称 bypass 52895，链接 commit 为 dashboard_chart）
- [commit f093359](https://github.com/frappe/frappe/commit/f0933590103c80c6393647dd0403d399e64c951c)（15.x，exact → substring）
- [commit c2b01e3e](https://github.com/frappe/frappe/commit/c2b01e3eb6f50e9bd05df0440f5cbf5dfbc1badd)（15.x，扩黑名单 + `\W*\(`）
- [PR #31526](https://github.com/frappe/frappe/pull/31526)、[PR #33344](https://github.com/frappe/frappe/pull/33344)
