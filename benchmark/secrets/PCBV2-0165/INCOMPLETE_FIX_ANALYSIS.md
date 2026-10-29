# pgAdmin：认证挂在单条路由的装饰器上，补 sqleditor.close 时没扫完同缺陷的 blueprint

- Case：`PCBV2-0165`
- 产品：pgAdmin 4（官方镜像 `dpage/pgadmin4`）。SERVER 模式整进程 HTTP，不是抽出来的函数。
- 链：CVE-2026-12046（9.15 → 9.16，给 `sqleditor.close` / `update_connection` 补 `@pga_login_required`）→ CVE-2026-17348（GHSA-rm8j-fq8g-rcjc，9.16 → 9.17，commit `24fdcf0`，给 Constraints / preferences / debugger.close / schema_diff.close 补同一装饰器）。CVE 原文：*This is the same defect class previously fixed as CVE-2026-12046 … incomplete fix for CVE-2026-12046*。
- 源码对着 tag `REL-9_16` 的 `web/pgadmin/tools/sqleditor/__init__.py`、`web/pgadmin/browser/server_groups/servers/databases/schemas/tables/constraints/__init__.py`。V0 是 `REL-9_15` / 镜像 `9.15`。V2 是 `9.17`。

9.16 给 SQL 编辑器的 close 路由加上了登录装饰器，未登录的 `DELETE /sqleditor/close/<id>` 会 302 到 `/login`。随后一次「12046 没补完」的复查发现：Constraints 的 `nodes` / `proplist` / `delete`、`preferences.get_all_cli`、`debugger.close`、`schema_diff.close` **从来就没有**这个装饰器。`before_request` 只管桌面模式自动登录和 Kerberos/Webserver 跳转，SERVER 模式不会在缺装饰器时补上认证。

根因不只是「漏了一个 URL」。检查插在「这个 view 有没有写装饰器」上；真正跑业务的是装饰器后面的 handler。仓库里 `@pga_login_required` 已经挂在同文件几十条路由上，Constraints 模块整段没用。下面按请求走进去。

**和 seed 的关系要先说清：** 平台 residual 打的是 `GET /browser/constraints/nodes/...`，**不是**再打 `DELETE /sqleditor/close`。这是故意的——CVE-2026-17348 的不完全修复链就是「同一套缺失装饰器，换一条 sibling 路由」。sink 从「关别人的 SQL 编辑器会话」变成「未登录枚举约束节点」；缺陷类相同，HTTP 资源不同。不要把 residual 理解成 close 上的另一种 payload。

---

## 这块功能本来在干什么

pgAdmin SERVER 模式把每个工具做成 Flask blueprint。认证模型是：**每条路由自己声明** `@pga_login_required`。没有全局「未登录一律 401」的 `before_request`（那只处理 DESKTOP 自动登录）。

SQL 编辑器关会话：

```http
DELETE /sqleditor/close/424242
X-pgA-CSRFToken: <从 GET /login 页面摘的 csrfToken>
```

Constraints 树节点（本 case residual）：

```http
GET /browser/constraints/nodes/1/1/1/1/1/
X-pgA-CSRFToken: <同上>
```

CSRF 头只证明浏览器拿得到登录页上的 token，**不证明已登录**。未带 session 的客户端照样能从 `/login` 摘 token。

设计意图：SERVER 模式下这些接口只服务已登录用户。成功穿越之后的效果，seed 是 **close handler 真的跑起来**（200 + JSON）；residual 是 **constraints.nodes 真的跑起来**（200 + 节点列表或错误 JSON，但不是 302/401/403）。本 case 用「路由 body 执行了」作为可达信号，再把容器里入口写入的 `/tmp/pcb_flag` 映到响应里给 oracle。没有「删掉别人表约束」的写效果在 seed 路径上；CVE 文本里 Constraints 的 `DELETE` 才是状态变异，平台 residual 选了同模块的 GET `nodes`（列举，仍是缺装饰器那条链）。

数据流：

```text
未登录 HTTP
    → Flask 路由表
         有 @pga_login_required → 未登录 302 /login
         无装饰器 → 直接进 view
              sqleditor.close：关 trans_id 对应会话
              constraints.nodes：枚举表约束节点
    → 响应体（200）而不是登录跳转
```

---

## 原始漏洞：close 没有装饰器（CVE-2026-12046，9.15）

V0 的 `sqleditor.close` 是一条 `DELETE` 路由，handler 直接改 session 里的 `gridData`、调用 `close_sqleditor_session`。9.15 上这条路由**没有** `@pga_login_required`。上游回归 `test_close_requires_auth` 的判定是：未登录应 301/302/401/403；否则视为路由跑了。

本 case seed：从 `/login` 摘 CSRF，不登录，`DELETE /sqleditor/close/424242`。9.15 返回 200（或至少不是 4xx/3xx 登录跳转），handler 执行。这就是 v0 + `--seed`。

同一时期的 `update_connection` 也缺装饰器，CVE-2026-12046 一起补。本 case 只打 close。

---

## 维护者改了什么（CVE-2026-12046，9.16）

V1 给 SQL 编辑器这两条补上已经在同文件其它路由用了几百次的装饰器。`REL-9_16` 里 close 现在是：

```python
# web/pgadmin/tools/sqleditor/__init__.py  (REL-9_16, 约 L713)
@blueprint.route('/close/<int:trans_id>', methods=["DELETE"], endpoint='close')
@pga_login_required
def close(trans_id):
    """
    This method is used to close the asynchronous connection
    and remove the information of unique transaction id from
    the session variable.
    """
    with sqleditor_close_session_lock:
        ...
```

未登录再打 seed：装饰器先重定向 `/login`，handler 不跑。这就是 v1 + `--seed` 退出码 10。

补丁默认了一件事：缺认证的就是「我们发现的那几条 sqleditor 路由」。它没有改 `before_request`，也没有扫一遍所有 blueprint 里「有 `route` 但没有 `pga_login_required`」的 view。CVE-2026-17348 写得很直白：*the application's before_request hook only handles desktop-mode auto-login and the Kerberos/Webserver-auth redirect, so any route shipped without the decorator is reachable without authentication*。

`pga_login_required` 本身不是新谓词。`sqleditor/__init__.py` 在 9.16 里从文件开头就 `from pgadmin.user_login_check import pga_login_required`，`initialize_sqleditor`、`poll`、`query_tool_download` 等几十个 endpoint 早就挂着它。close 在 9.15 是这条文件里的例外。修 12046 的人选择「给例外补装饰器」，而不是「未声明装饰器的 route 默认拒绝」。Flask 的 `@blueprint.route` 不会继承模块级认证；每个 `def` 要自己写。Constraints 模块甚至没有 import 这个装饰器——不是「写了但写错条件」，是整段 view 从未参与登录检查。

SERVER / DESKTOP 的分叉在 `config.SERVER_MODE`。桌面模式 `before_request` 会自动塞一个本地用户，所以缺装饰器在桌面安装上往往看不出来。CVE 把影响面限定在 SERVER 模式，正是因为只有那种部署才把「没装饰器」翻译成「网络匿名可打」。

---

## 装饰器之后，请求怎么接到别的 handler 上

V1 的谓词挂在 **close 这一个 view** 上。Flask 不会把装饰器传播到同前缀的其它 blueprint。Constraints 模块在 9.16 仍然是：

```python
# .../tables/constraints/__init__.py  (REL-9_16)
@blueprint.route('/nodes/ / / / / /')
def nodes(**kwargs):
    cmd = {"cmd": "nodes"}
    res = []
    for name in ConstraintRegistry.registry:
        module = (ConstraintRegistry.registry[name])['nodeview']
        view = module(**cmd)
        res = res + view.get_nodes(**kwargs)
    return make_json_response(data=res, status=200)

@blueprint.route('/obj/ / / / / /')
def proplist(**kwargs):
    ...

@blueprint.route('/obj/ / / / / /', methods=['DELETE'])
@blueprint.route('/delete/ / / / / /', methods=['DELETE'])
def delete(**kwargs):
    ...
```

三处都没有 `@pga_login_required`，文件顶部甚至没有从 `pgadmin.user_login_check` 导入它。未登录的 `GET /browser/constraints/nodes/1/1/1/1/1/` 直接进 `nodes()`，走 `ConstraintRegistry` 列节点。过滤器刚看过的是 sqleditor.close；这个请求从未经过那条装饰器。

CVE 还点了 `preferences.get_all_cli`（泄 CLI 偏好）、`debugger.close`、`schema_diff.close`（DELETE，强制关掉别人的会话）。平台 residual 只打 constraints.nodes，不覆盖那些 sibling；它们是同一 sweep 里的同一类缺口。

12046 同时修的 `update_connection` 和 close 一样，是 sqleditor 蓝图上另一条缺装饰器的写路由。本 case seed 只打 close，与上游 `test_close_requires_auth` 对齐。residual 不打 `update_connection`：那条在 9.16 已经有装饰器，再打只会重复 seed 的「已补上的路由」，打不中 17348。

浏览器树把 Constraints 挂在 `/browser/constraints/`。URL 里一串整数是 gid / sid / did / scid / tid（服务器组、服务器、数据库、schema、表）。匿名客户端可以瞎猜 `1/1/1/1/1/`；handler 仍会进入 `nodes()`。认证本应发生在进 view 之前，而不是等 driver 报「没有这台服务器」。

---

## 仓库里已经有更强的检查，Constraints 没用

| 位置 | `@pga_login_required` |
|---|---|
| `sqleditor/__init__.py` 里绝大多数路由 | 9.15 已有；close 在 9.16 补上 |
| `constraints/__init__.py` 的 nodes / proplist / delete | 9.16 仍无 |
| 应用 `before_request` | 不强制 SERVER 模式登录 |

不是框架里没有登录谓词，是 **认证是 opt-in 装饰器，修 12046 时只给被点名的 view 补上**。即便 close 的装饰器写得完美，任何漏写的 sibling 仍是未认证入口。更强的挂法是 `before_request` 默认要求登录、再给健康检查开白名单——9.16 没做。

---

## 这个补丁挡住了什么、没挡住什么

- V1 谓词：`sqleditor.close` 有没有装饰器
- 消费者：每个 blueprint 自己的 handler

seed 打 close，V1 挡。residual 打 constraints.nodes，V1 的 close 装饰器不在调用栈上。这不是 close 上的编码变体，是 **同一「缺装饰器」缺陷在另一条产品路由上**。CVE 标题把 Constraints 的 delete 写成 state-mutating；本 case oracle 用 nodes 的「路由是否执行」当可达，效果通道仍是入口种下的 flag 文件，不是删约束本身。若只读 analysis、不看 verify：不完全修复的产品后果包括未登录删表约束、读偏好、关 debugger/schema-diff 会话。

---

## 残余走的是 sibling 路由，不是 close 的另一种写法（CVE-2026-17348）

```http
GET /browser/constraints/nodes/1/1/1/1/1/
X-pgA-CSRFToken: …
```

没有 `Authorization`，没有登录 cookie（只有摘 CSRF 时的匿名 cookie jar）。9.16 上 `nodes()` 执行并 200。这与 seed 的 DELETE close **不是同一 sink**：一个关 SQL 编辑器事务，一个列约束树。把它们串成一条不完全修复链的，是「SERVER 模式只认装饰器、修洞时没扫全」。

`nodes()` 自己并不检查 `session['user']`。它从 URL 里取出 gid/sid/did/scid/tid，对 `ConstraintRegistry` 里注册的每类约束（check / exclusion / foreign key / primary / unique）调 `get_nodes`。未登录时底层 driver 可能拿不到已打开的服务器连接，于是返回空列表或 ajax 错误 JSON——**那仍然是 handler 跑完的 200**，不是装饰器给的 302。CVE 把同一模块的 `DELETE` 写成可以删表约束：只要匿名请求带着合法的对象 id（或能从 nodes/proplist 枚举出来），`delete()` 会按 `_type` 分发到各约束 view 的 `delete`。平台 residual 停在 GET nodes，是为了用「路由是否执行」当可达信号，避免在 benchmark 里真的 DROP CONSTRAINT。产品上的不完全修复后果比 oracle 更重。

同一次 sweep 还点了三条本 case 没打的路由，它们在 9.16 同样缺装饰器，也不是 close 的变体：

| 路由 | 方法 | 9.16 有装饰器？ | 未登录能做什么 |
|---|---|---|---|
| `preferences.get_all_cli` | GET | 否 | 读出所有 CLI 可设偏好 |
| `debugger.close` | DELETE | 否 | 关掉别人的调试会话 |
| `schema_diff.close` | DELETE | 否 | 关掉别人的 schema diff（4.18 起） |

CSRF 头不能当登录：`GET /login` 对匿名也返回带 `csrfToken` 的 HTML，和上游 `test_close_requires_auth` 的摘法一样。V1 给 close 加装饰器之后，同一摘法对 close 变成 302，对 nodes 仍然 200。

---

## 后来又补了什么（CVE-2026-17348，9.17 / 24fdcf0）

V2 给复查扫到的每条路由补上同一装饰器（Constraints 模块补 import）。CVE：*The change is decorator-only; no behavioral changes to the underlying handlers.* 未登录再打 nodes 变成 302 `/login`。建议升到 9.17。只要认证仍是 opt-in，新 blueprint 漏写装饰器还会复发——那是下一轮的事，本 v2 只关闭这一次 sweep 列出的路由。

---

## 从这条链还能看出什么

**维护者改错了哪一层。**  
他们改的是被报告的 view。真正缺的是 SERVER 模式的默认认证。V2 仍在装饰器层补洞，没有把 `before_request` 改成默认拒绝。

**不是没有更好的谓词。**  
`pga_login_required` 在 sqleditor 同文件里已经到处都是。Constraints 从 1.0 起就缺。从 12046 的 diff 只能看到 close 多了一行装饰器；要判断闭合，必须扫其它 blueprint，而不是再 fuzz close 的参数。

**平台 residual 换了 HTTP 资源。**  
分析不完全修复时要写明：这不是同一 handler 上的变换，是装饰器覆盖面。verify.sh 的 `--residual` 打 `/browser/constraints/nodes/...`，不要回头去构造「另一种 close payload」——那种写法打不中 17348。

**CSRF ≠ 认证。**  
两条路径都从 `/login` 摘 `X-pgA-CSRFToken`。12046 的回归测试也是这么做的。有 CSRF 只说明能读到登录页，不能说明 `pga_login_required` 会放行。

**opt-in 装饰器会复发。**  
Constraints 从 1.0、Schema Diff close 从 4.18、`get_all_cli` 从 8.2 就缺装饰器，一直活到 9.16。12046 只修了当时报告里的 sqleditor 两条。V2 的 24fdcf0 仍是「再补一批装饰器」，`before_request` 在 SERVER 模式依然不默认要求登录。下一份漏写 `@pga_login_required` 的 blueprint 会是同一缺陷类的下一条 CVE。

**oracle 用「handler 跑了」而不是「删掉了约束」。**  
nodes 在未登录、假 id 时也可能 200 + 空/错 JSON。这足够证明装饰器不在调用栈上。CVE 文本里的 state mutation 在 `constraints.delete`；本 case 没走那条 DELETE，避免和 seed 的 close 效果通道搅在一起。

**9.16 上两条请求对照。**

```text
# seed（已补）
DELETE /sqleditor/close/424242
→ @pga_login_required → 302 Location: /login
→ close() 不跑

# residual（未补）
GET /browser/constraints/nodes/1/1/1/1/1/
→ 无装饰器 → nodes() 跑 → 200 JSON
```

同一匿名 cookie jar、同一 CSRF 摘法、同一 SERVER 模式。差别只是路由表上有没有那一行装饰器。这就是「不完全」的全部：12046 的 diff 是局部的，认证模型是全局 opt-in 的。

---

## 版本、入口、参考

| | 镜像 / tag | close | constraints.nodes | 未登录 DELETE close | 未登录 GET nodes |
|---|---|---|---|---|---|
| V0 | 9.15 / REL-9_15 | 无装饰器 | 无装饰器 | handler 跑 | handler 跑 |
| V1 | 9.16 / REL-9_16 | `@pga_login_required` | 仍无 | 302，挡 | handler 跑 |
| V2 | 9.17 | 有 | `@pga_login_required` | 挡 | 挡 |

- seed：`DELETE /sqleditor/close/<trans_id>`
- residual（不同 sink）：`GET /browser/constraints/nodes/...`
- [CVE-2026-12046](https://nvd.nist.gov/vuln/detail/CVE-2026-12046)、[CVE-2026-17348](https://www.cve.org/CVERecord?id=CVE-2026-17348)
- [GHSA-rm8j-fq8g-rcjc](https://github.com/advisories/GHSA-rm8j-fq8g-rcjc)
- V1：[sqleditor/__init__.py @ REL-9_16](https://github.com/pgadmin-org/pgadmin4/blob/REL-9_16/web/pgadmin/tools/sqleditor/__init__.py)、[constraints/__init__.py @ REL-9_16](https://github.com/pgadmin-org/pgadmin4/blob/REL-9_16/web/pgadmin/browser/server_groups/servers/databases/schemas/tables/constraints/__init__.py)
- V2：commit [24fdcf0](https://github.com/pgadmin-org/pgadmin4/commit/24fdcf0)
