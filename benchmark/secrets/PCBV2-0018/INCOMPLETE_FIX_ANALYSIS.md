# Gitea：public-only 令牌检查没挂上 /user/orgs

- Case：`PCBV2-0018`
- 产品：Gitea（自托管 Git 服务，Go HTTP API）
- 链：CVE-2025-68941（1.22.2 → 1.26.1，PR #32204）→ CVE-2026-25714（1.26.1 → 1.26.2，PR #37118 / GHSA-8629-vc8r-5p58）
- 源码对着官方 tag `v1.26.1` 的 `routers/api/v1/api.go`、`routers/api/v1/org/org.go`。运行时是整包 Gitea 进程，不是抽出来的中间件。

2025 年 Gitea 给带 `public-only` 范围的 API 令牌加了 `checkTokenPublicOnly`，想挡住「声明只读公开资源、实际读到私有仓/私有组织」。2026 年 advisory 指出两件事同时成立：`GET /api/v1/user/orgs` **没有**挂这个中间件；即使挂上，Go 的 `switch` 也只跑第一个匹配的 category，User+Organization 组合会在 Organization 分支因 `ctx.Org.Organization == nil` 而放行，永远走不到 User 可见性检查。NVD 把这件事记成 CVE-2026-25714，并写明 *leaving an incomplete fix for CVE-2025-68941*。

根因不是「令牌解析错了」。`ctx.PublicOnly` 已经标好；检查插在部分路由的中间件链上；真正列出组织的是 `org.ListMyOrgs` → `listUserOrgs`，它按「当前用户能看见什么」查库，**不问** `PublicOnly`。下面按请求走进去、补丁挂在哪条路上、查询怎么拼可见性、旁边那条已经设防的兄弟路由为什么没用上，把这三层写完。

---

## 这块功能本来在干什么

Gitea 的 API 令牌可以勾选 public-only：持有者仍然是登录用户，但声明「这个令牌只能碰公开对象」。Web UI 里 Settings → Applications 生成令牌时勾选即可。`tokenRequiresScopes` 负责 scope 类别（repo / org / user / notification…）；`checkTokenPublicOnly` 负责在 `ctx.PublicOnly` 为真时，按类别拒绝私有对象。

一次典型请求：

```http
GET /api/v1/orgs/{org}/repos
Authorization: token <public-only token>
```

以及兄弟接口：

```http
GET /api/v1/user/orgs
Authorization: token <public-only token>
```

前者列出某个组织下的仓库；后者列出**当前用户所属的全部组织**。`ListMyOrgs` 把 `ctx.Doer` 交给 `listUserOrgs`，用 `FindOrgOptions{UserID, IncludeVisibility: DoerViewOtherVisibility(doer, u)}` 查库，JSON 数组里带组织名。本 case 把 flag 的短哈希嵌进私有组织名，能在 body 里读到它就说明令牌读到了不该读的私有组织。

数据流：

```text
HTTP + token
    → tokenRequiresScopes(User, Organization)   ← 只检查 scope 类别，不滤可见性
    → （V1 在部分路由）checkTokenPublicOnly()
         switch 第一个匹配的 category
         Organization：看 ctx.Org.Organization / ctx.ContextUser 是不是组织
    → ListMyOrgs
         listUserOrgs(ctx, ctx.Doer)
         FindOrgOptions.IncludeVisibility = DoerViewOtherVisibility
         ← 仍按「我能看见我自己的私有组织」查，未读 PublicOnly
    → JSON 组织列表
```

---

## 原始漏洞：public-only 形同虚设（CVE-2025-68941，tag 1.22.2）

1.22.2 没有 `checkTokenPublicOnly`。令牌只要 scope 对，就以 `ctx.Doer` 的完整身份查库。public-only 位即使被解析进 `ctx.PublicOnly`，也没有中间件读它。seed 用 public-only 令牌打 `GET /api/v1/orgs/{私有组织}/repos`，私有组织名（嵌 flag token）出现在仓库列表相关字段里，或至少 200 返回组织下的私有仓。本 case 的 seed 观察 body 里是否含 flag 的 12 字符哈希。

没有额外鉴权。令牌持有者本来就能在 Web UI 里看见这些组织；漏洞是**令牌声明的范围被忽略**。

---

## 维护者改了什么（CVE-2025-68941 修复，1.26.1）

PR #32204 引入 `checkTokenPublicOnly`，并把它挂到一批仓库/组织/包路由上。1.26.1 里函数本体是一个 Go `switch`（不是循环）：

```go
# routers/api/v1/api.go :: checkTokenPublicOnly  (gitea v1.26.1, 约 L248–300)
func checkTokenPublicOnly() func(ctx *context.APIContext) {
	return func(ctx *context.APIContext) {
		if !ctx.PublicOnly {
			return
		}
		requiredScopeCategories, ok := ctx.Data["requiredScopeCategories"].([]auth_model.AccessTokenScopeCategory)
		if !ok || len(requiredScopeCategories) == 0 {
			return
		}

		// public Only permission check
		switch {
		case auth_model.ContainsCategory(requiredScopeCategories, auth_model.AccessTokenScopeCategoryRepository):
			if ctx.Repo.Repository != nil && ctx.Repo.Repository.IsPrivate {
				ctx.APIError(http.StatusForbidden, "token scope is limited to public repos")
				return
			}
		case auth_model.ContainsCategory(..., AccessTokenScopeCategoryIssue):
			...
		case auth_model.ContainsCategory(..., AccessTokenScopeCategoryOrganization):
			if ctx.Org.Organization != nil && ctx.Org.Organization.Visibility != api.VisibleTypePublic {
				ctx.APIError(http.StatusForbidden, "token scope is limited to public orgs")
				return
			}
			if ctx.ContextUser != nil && ctx.ContextUser.IsOrganization() && ... {
				ctx.APIError(http.StatusForbidden, "token scope is limited to public orgs")
				return
			}
		case auth_model.ContainsCategory(..., AccessTokenScopeCategoryUser):
			...
		}
	}
}
```

对 seed 这种「已经绑定了私有组织、再列它的仓」的路径，Organization 或 Repository 分支能看到 `ctx.Org.Organization` / `ctx.Repo.Repository`，私有对象返回 403。本 case 的 seed 在 v1 上拿到 `"token scope is limited to public orgs"`，flag 不在 body 里。这就是 v1 + `--seed` 退出码 10。

同一文件里，组织相关路由是这样挂的（v1.26.1 原文）：

```go
# routers/api/v1/api.go :: Routes  (约 L1606–1611)
		m.Get("/user/orgs", reqToken(), tokenRequiresScopes(
			auth_model.AccessTokenScopeCategoryUser,
			auth_model.AccessTokenScopeCategoryOrganization,
		), org.ListMyOrgs)
		m.Group("/users/{username}/orgs", func() {
			m.Get("", reqToken(), org.ListUserOrgs)
			...
		}, tokenRequiresScopes(...User, ...Organization), context.UserAssignmentAPI(), checkTokenPublicOnly())
```

`/users/{username}/orgs` 有 `checkTokenPublicOnly()`。**紧挨着的** `/user/orgs` 没有。GHSA-8629-vc8r-5p58 把这写成 Issue 1，并标出「Missing `checkTokenPublicOnly()`」。

补丁默认了两件事：

1. 凡是会泄露私有组织的列表接口，都会经过 `checkTokenPublicOnly`。
2. `switch` 里第一个匹配的 category 足以代表这条路由的全部约束。

两条都不成立。`/user/orgs` 的 scope 类别是 `[User, Organization]`，即便日后补上中间件，Organization 分支先匹配、`ctx.Org` 为空、检查空转。

---

## 中间件之后，列表怎么接到数据库上

`ListMyOrgs` 不读 `ctx.PublicOnly`。它把当前用户交给 `listUserOrgs`：

```go
# routers/api/v1/org/org.go :: listUserOrgs / ListMyOrgs  (v1.26.1)
func listUserOrgs(ctx *context.APIContext, u *user_model.User) {
	opts := organization.FindOrgOptions{
		ListOptions:       listOptions,
		UserID:            u.ID,
		IncludeVisibility: organization.DoerViewOtherVisibility(ctx.Doer, u),
	}
	orgs, maxResults, err := db.FindAndCount[organization.Organization](ctx, opts)
	...
	ctx.JSON(http.StatusOK, &apiOrgs)
}

func ListMyOrgs(ctx *context.APIContext) {
	listUserOrgs(ctx, ctx.Doer)
}
```

`DoerViewOtherVisibility(doer, u)` 在 `doer == u`（看自己）时包含私有/limited 组织——这是 Web UI「我的组织」的正确语义。API 令牌若声明 public-only，语义应当收窄成「只返回公开组织」。1.26.1 的 `listUserOrgs` 没有这层收窄。过滤器（如果挂了）看的是 `ctx.Org.Organization` 这种**已绑定**的上下文对象；列表接口在查询前并不绑定某一个组织，`ctx.Org.Organization` 是 nil。中间件语言和查询语言对不上。

1.26.1 里 `GetAll`（`GET /orgs`）已经会读 `PublicOnly`：

```go
	vMode := []api.VisibleType{api.VisibleTypePublic}
	if ctx.IsSigned && !ctx.PublicOnly {
		vMode = append(vMode, api.VisibleTypeLimited)
		...
	}
```

这是同一文件、同一「列出组织」问题下已经写好的更强谓词。`ListMyOrgs` 没用。

---

## 仓库里已经有更强的检查，这条路由没用

谁调用 `checkTokenPublicOnly`：

| 路由 | 1.26.1 是否挂中间件 | 查询是否滤 PublicOnly |
|---|---|---|
| `GET /orgs/{org}/repos` 等已绑定组织的路径 | 是（seed 被 403） | 往往根本走不到查询 |
| `GET /users/{username}/orgs` | 是 | `listUserOrgs` 仍不滤（靠中间件） |
| `GET /user/orgs` | **否** | **否**，`DoerViewOtherVisibility` 含私有 |
| `GET /orgs`（GetAll） | 视挂载而定 | 查询侧已有 `!ctx.PublicOnly` |

V1 等于在「已经有组织上下文」的路由上加了一个**绑定对象**检查，而「列出我所在组织」这条没有组织上下文的路由既没挂中间件，查询也不收窄。不是仓库里没有更好的谓词，是 **/user/orgs 没用**。

即便给 `/user/orgs` 补上同一 `switch` 中间件，Issue 2 仍然在：`ContainsCategory(..., Organization)` 为真 → Organization 分支看到 nil → 不 403 → `case User` 被 Go switch 跳过。advisory 建议把 `switch` 改成 `for _, category := range requiredScopeCategories`。1.26.2 同时做了这件事，并且在查询侧加了 `ApplyPublicOnly`。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「中间件 vs 查询」落到具体代码：

- `checkTokenPublicOnly` 的 Organization 分支：看 `ctx.Org.Organization` 是不是私有
- `listUserOrgs` 的 `FindOrgOptions`：看 `DoerViewOtherVisibility` 允许哪些可见性

seed 走已绑定组织的路由，中间件看得到那个组织，403。residual 走未绑定的列表路由，中间件不在链上；查询按「我看我自己」返回私有组织。

```text
seed:
  GET /api/v1/orgs/{privateOrg}/repos
  + public-only token
  → checkTokenPublicOnly 看到私有 org → 403
  body 无 flag

residual:
  GET /api/v1/user/orgs
  + 同一 public-only token
  → 无 checkTokenPublicOnly
  → ListMyOrgs → IncludeVisibility 含 private
  → JSON 里出现私有组织名（嵌 flag token）
```

GHSA-8629-vc8r-5p58 的复现步骤就是这条 curl，期望「只返回公开组织」。

---

## 残余仍然走同一条组织列表路径（CVE-2026-25714）

没有换身份、没有换令牌类型。还是同一个 public-only token，只把路径从 `/orgs/{org}/repos` 换成 `/user/orgs`：

```http
GET /api/v1/user/orgs
Authorization: token <public-only>
```

`tokenRequiresScopes` 仍然要求 User+Organization scope（public-only 令牌可以同时带这些 scope）。`ListMyOrgs` 仍然调用同一个 `listUserOrgs`。私有组织出现在 JSON 里；本 case 用 `flag_token(flag)`（sha256 前 12 字符，因为 Gitea 名长限制）判断 body。

本 case `verify.sh` 的 residual 调用 `gitea_util.residual_probe`（语义与 held-out 相同，运行时不读 hidden 文件）：同一 setup 建私有组织，然后 GET `/api/v1/user/orgs`。认证：v1 + `--residual` 退出码 0，body 中观察到 flag token。

所以残余不是新洞面，而是同一 `PublicOnly` 标志上三件事叠在一起：中间件按路由枚举漏挂；`switch` 只覆盖「已绑定对象」形态；查询层已有 `GetAll` 那种 `!ctx.PublicOnly` 收窄，`ListMyOrgs` 没用。seed 被挡住只说明「对着一个已经解析出来的私有组织，中间件会 403」，不说明「public-only 令牌列不出私有组织」。

---

## 后来又补了什么（CVE-2026-25714，1.26.2）

PR #37118 做了三处对齐，而不是只给 `/user/orgs` 加一行中间件。

查询侧给 `FindOrgOptions` 增加 `ApplyPublicOnly`，并在 `listUserOrgs` 里调用：

```go
# routers/api/v1/org/org.go :: listUserOrgs  (v1.26.2)
	opts := organization.FindOrgOptions{ ... }
	opts.ApplyPublicOnly(ctx.PublicOnly)
	orgs, maxResults, err := db.FindAndCount[organization.Organization](ctx, opts)
```

`PublicOnly` 为真时 `IncludeVisibility` 被收成 Public，私有组织不再进结果集。即便中间件再漏挂，查询也不会把私有组织交出去。

路由侧把 `checkTokenPublicOnly()` 加到 `GET /user/orgs`。中间件侧把 `switch` 改成按 category 循环，避免 User+Organization 组合跳过 User 检查。`GetAll` 也改成 `searchOpts.ApplyPublicOnly(ctx.PublicOnly)`，不再依赖 `if ctx.IsSigned && !ctx.PublicOnly` 那条容易漏的手写分支。

对残余输入：1.26.2 上 `/user/orgs` 仍返回 200，但数组里没有私有组织，flag token 不在 body 里。公开建议是升级到 1.26.2。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是「已经有 Repo/Org 上下文」的中间件。真正泄露出私有组织名的是 `FindOrgOptions` 的可见性集合。V2 把谓词下沉到查询选项，这才对准了列表 sink。

**不是没有更好的谓词。**  
`GetAll` 在 1.26.1 已经用 `!ctx.PublicOnly` 限制可见性。`/users/{username}/orgs` 已经挂了 `checkTokenPublicOnly`。从 V1 的 diff 只能看到一批路由加上了中间件；要判断补丁是否闭合，必须把 `Routes()` 里每一条组织列表和 `listUserOrgs` 的查询条件并排看。

**同一 `listUserOrgs`，只换了入口。**  
`ListMyOrgs` 和 `ListUserOrgs` 共用 `listUserOrgs`。后者的路由挂了中间件（且有 `UserAssignmentAPI`，`ContextUser` 可能不是组织，Organization 分支照样空转）。前者连中间件都没有。

**switch 的匹配语言比 scope 列表窄。**  
`tokenRequiresScopes` 接受多个 category；`checkTokenPublicOnly` 用 `switch` 只处理第一个命中的。多 category 路由在设计上就是给这个中间件挖的坑。

**金丝雀在组织名里是有意的。**  
flag token 是组织名的一部分，不在公开仓的 README 里。能读到它，说明 JSON 里出现了私有组织对象，而不是「公开组织碰巧同名」。

---

## 版本、入口、参考

| | tag | `/orgs/{org}/repos` + public-only | `/user/orgs` + public-only | `listUserOrgs` |
|---|---|---|---|---|
| V0 | 1.22.2 | 无中间件，200 含私有 | 无中间件，200 含私有 | `DoerViewOtherVisibility` |
| V1 | 1.26.1 | `checkTokenPublicOnly` → 403 | **未挂**中间件，200 含私有 | 仍不读 `PublicOnly` |
| V2 | 1.26.2 | 403 / 过滤 | 挂中间件 + `ApplyPublicOnly`，列表无私有 | `opts.ApplyPublicOnly(ctx.PublicOnly)` |

- Web：`GET /api/v1/orgs/{org}/repos`（seed）/ `GET /api/v1/user/orgs`（residual），端口 3000
- 认证（本平台）：v0 seed 观察到 flag token；v1 seed 未观察到；v1 residual 观察到。
- [CVE-2026-25714](https://nvd.nist.gov/vuln/detail/CVE-2026-25714) / [GHSA-8629-vc8r-5p58](https://github.com/go-gitea/gitea/security/advisories/GHSA-8629-vc8r-5p58)
- 前置：[CVE-2025-68941](https://nvd.nist.gov/vuln/detail/CVE-2025-68941)（PR #32204）
- 官方 tag：`https://github.com/go-gitea/gitea/tree/v1.26.1` 与 `v1.26.2`
