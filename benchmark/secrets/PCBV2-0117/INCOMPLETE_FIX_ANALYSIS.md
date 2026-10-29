# Gitea：public-only 挂到了 /users/{name}，没挂到 /user

- Case：`PCBV2-0117`
- 产品：Gitea（自托管 Git 服务）
- 链：CVE-2025-68941 / GHSA-xfq3-qj7j-4565（1.22.2 → 1.22.3，PR #32204 / backport #32218；本 case V1 = 1.26.1）→ CVE-2026-24791 / GHSA-wrr5-99h5-gq57（1.26.1 → 1.26.2，PR #37118）
- 源码对着 GitHub tag `v1.26.1` / `v1.26.2` 的 `routers/api/v1/api.go`（`checkTokenPublicOnly`、`Routes` 里 `/users/{username}` 与 `/user` 两组）。运行时是官方 Gitea 进程 + REST，不是抽出来的函数。GHSA-wrr5-99h5-gq57 原文写明 *this should be treated as an incomplete fix / residual gap in a different route family, not as a duplicate of the older advisory*。

2025 年，Gitea 为 `public-only` 令牌加了 `checkTokenPublicOnly()`，并把它接到对外的 `/api/v1/users/{username}` 组上。这挡住了 seed 那种「用 public-only token 读私有用户 `GET /users/alice`」。一年后 advisory 指出：同一套 `tokenRequiresScopes` + `ctx.PublicOnly` 机制上，`/api/v1/user` 自路由族始终没挂这个守卫。私有账号 alice 拿自己的 `public-only,read:user` token 访问 `GET /api/v1/user`，仍能读到带 flag 的邮箱。NVD 把这件事记成 CVE-2026-24791。

根因不只是「少写了一条路由」。检查插在「按 ContextUser 可见性拒绝」这一层；真正返回私有字段的是 `GetAuthenticatedUser`（读的是 `ctx.Doer`）；同文件里守卫已经写好，自路由组的收尾中间件列表里没有它，而且自路由默认也不设置 `ContextUser`。下面按请求走进去、1.22.3 改了哪几行、守卫之后谁消费那个 token、更宽的挂载点有没有接上，把这几层写完。

---

## 这块功能本来在干什么

Gitea 的个人访问令牌可以带 `public-only`：调用方声称自己只能碰公开资源。对外查人用 `/api/v1/users/{username}`；查「我自己」用 `/api/v1/user`。两者都要求 user scope，都返回用户对象（含 email 等）。

一次典型自路由：

```http
GET /api/v1/user
Authorization: token <alice 的 public-only,read:user>
```

`GetAuthenticatedUser` 返回当前登录者（`ctx.Doer`）的账号 JSON。设计意图：`public-only` 令牌即使属于私有账号，也不能读出该账号的私有资料。成功穿越之后的效果是：**对外按用户名查被 403，自路由却把私有 email 放进 body**——本 case 把 alice 的 email 设成 `${PCB_FLAG}@pcb.local`。

数据流：

```text
GET /api/v1/users/alice     vs     GET /api/v1/user
    → tokenRequiresScopes(User)        → tokenRequiresScopes(User), reqToken()
         设置 ctx.PublicOnly                设置 ctx.PublicOnly
    → UserAssignmentAPI()              → （V1 无 ContextUser 赋值）
         ContextUser = alice
    → V1：checkTokenPublicOnly()       → V1：没有 checkTokenPublicOnly
         alice 非 public → 403
    → user.GetInfo                     → user.GetAuthenticatedUser
                                           返回 Doer（alice）含 email
```

需要持有 alice 自己签发的 token。判断完全信任「挂了守卫的那一组路由」，不信任同文件里另一组自路由稍后怎么读同一个 `ctx.PublicOnly`。

---

## 原始漏洞：public-only 根本不执法（CVE-2025-68941，1.22.2）

1.22.2 没有 `checkTokenPublicOnly`。`tokenRequiresScopes` 会把 `public-only` 记到 `ctx.PublicOnly`，但没有中间件读这个标志去拒绝私有资源。NVD CVE-2025-68941 写的是 *Gitea before 1.22.3 mishandles access to a private resource upon receiving an API token with scope limited to public resources*。

本 case 的 seed：

```text
GET /api/v1/users/alice
token = alice-public-only-token
```

1.22.2 返回 alice 的账号对象，email 里是 `PCBFLAG_...`。这就是 v0 + `--seed` 退出码 0。

`/api/v1/user` 当时同样没有守卫。当时没人拿自路由当「按用户名查私有账号」问题的一部分。

---

## 维护者改了什么（CVE-2025-68941 修复，1.22.3 / 本 case V1 = 1.26.1）

PR #32204 增加守卫，并把它接到 `/users/{username}` 组的收尾链上。1.26.1 上仍是这个形状：

```go
// routers/api/v1/api.go :: checkTokenPublicOnly  (tag v1.26.1, 约 L241–275)
func checkTokenPublicOnly() func(ctx *context.APIContext) {
    return func(ctx *context.APIContext) {
        if !ctx.PublicOnly {
            return
        }
        requiredScopeCategories, ok := ctx.Data["requiredScopeCategories"].([]auth_model.AccessTokenScopeCategory)
        if !ok || len(requiredScopeCategories) == 0 {
            return
        }
        switch {
        case auth_model.ContainsCategory(..., AccessTokenScopeCategoryRepository):
            if ctx.Repo.Repository != nil && ctx.Repo.Repository.IsPrivate {
                ctx.APIError(http.StatusForbidden, "token scope is limited to public repos")
                return
            }
        // ... issue / org / ...
        case auth_model.ContainsCategory(..., AccessTokenScopeCategoryUser):
            if ctx.ContextUser != nil && ctx.ContextUser.IsTokenAccessAllowed() &&
                ctx.ContextUser.Visibility != api.VisibleTypePublic {
                ctx.APIError(http.StatusForbidden, "token scope is limited to public users")
                return
            }
        }
    }
}
```

挂载点（对外按用户名）：

```go
// routers/api/v1/api.go :: Routes  (tag v1.26.1, 约 L975–991)
m.Group("/{username}", func() {
    m.Get("", reqExploreSignIn(), user.GetInfo)
    ...
}, context.UserAssignmentAPI(), checkTokenPublicOnly(), individualPermsChecker)
```

对 seed，它确实够用：`UserAssignmentAPI` 把 `ContextUser` 设成 alice，alice 的 Visibility 不是 public，守卫 403。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 读私有用户资料只走 `/users/{username}`。
2. 守卫只看 `ctx.ContextUser`；没赋值就当「没有目标用户」，直接 return。

第二点在自路由上不成立。更关键的是：守卫写好了，`/user` 组的收尾中间件列表里**没有它**。

---

## 守卫之后，谁真正消费那个 token

1.26.1 的自路由组是：

```go
// routers/api/v1/api.go :: Routes  (tag v1.26.1, 约 L1012–1129)
m.Group("/user", func() {
    m.Get("", user.GetAuthenticatedUser)
    m.Combo("/emails").Get(user.ListEmails)...
    m.Group("/keys", func() { ... })
    m.Group("/applications", func() { ... })
    ...
}, tokenRequiresScopes(auth_model.AccessTokenScopeCategoryUser), reqToken())
```

收尾只有 `tokenRequiresScopes` 和 `reqToken()`。没有 `checkTokenPublicOnly`，也没有后来才出现的 `contextAuthenticatedUser`。`GetAuthenticatedUser` 读的是 `ctx.Doer`（令牌主人），把整个用户对象（含私有 email）写进 JSON。

即便有人「机械地」把 `checkTokenPublicOnly()` 接到这组上，User 分支仍要求 `ctx.ContextUser != nil`。自路由默认不跑 `UserAssignmentAPI`，`ContextUser` 是 nil，守卫会直接 return。GHSA-wrr5-99h5-gq57 把这写进修复建议：*mechanically adding `checkTokenPublicOnly()` is not sufficient unless `ctx.ContextUser` is set to `ctx.Doer`*。

过滤器刚看过的是「对外那组的 ContextUser」；真正泄露的是「自路由的 Doer」。两套路由中间没有第二次谓词。

同文件里，个别嵌套组（例如 `/user/starred/{username}/{reponame}`、`/user/blocks/{username}`）**确实**挂了 `checkTokenPublicOnly`——因为那些子组有 `UserAssignmentAPI` / `repoAssignment`。`GET /user` 本身不在那些子组里。

---

## 仓库里已经有更强的检查，自路由没用

`checkTokenPublicOnly` 已经存在，并且已经证明能挡住 seed。谁调用它（1.26.1）：

| 路由组 | 挂了 `checkTokenPublicOnly`？ |
|---|---|
| `/api/v1/users/{username}` | 是，且有 `UserAssignmentAPI` |
| `/api/v1/users/{username}/orgs` | 是 |
| `/api/v1/user`（`GetAuthenticatedUser` 等） | **否** |
| `/api/v1/user/orgs` | **否**（这是另一条 sibling，CVE-2026-25714） |

V1 等于写出了一个通用守卫，却只挂在「按用户名寻址」的那一组。不是仓库里没有更好的谓词，是 **自路由没用**。

要让 User 分支真的开火，还需要把 `ContextUser` 设成 `Doer`。1.26.2 的 `contextAuthenticatedUser` 就是做这件事。V1 两边都缺。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「挂载点 vs 消费点」落到具体代码：

- `checkTokenPublicOnly` + `ContextUser.Visibility`：看对外路由的目标用户是不是 public
- `GetAuthenticatedUser`：看 Doer 的完整账号对象

只要走一条**不经过**该守卫、但仍返回同一份私有账号的路由，第一行不会开火，第二行仍然写出 email。

`GET /api/v1/user` 就是这样来的。token 一样，scope 一样，alice 一样私有。只是路径少了用户名，多了「我自己」：

```text
seed:      GET /api/v1/users/alice   → 403（V1）
residual:  GET /api/v1/user          → 200，email = PCBFLAG_...@pcb.local
```

advisory 还列了同一组里的 `/user/emails`、`/user/keys`、`/user/applications/oauth2`、`/user/actions/secrets` 等。本 case 的平台 residual 打的是 `GET /api/v1/user` 读 email，与 incomplete-fix 链的 sink 一致（同一私有账号对象）；其它自路由是同一缺口的兄弟消费点。

---

## 残余仍然走同一套 public-only 令牌（CVE-2026-24791）

没有换用户、没有换 token、没有换可见性。还是 alice 的 `public-only,read:user`。只是：

```http
GET /api/v1/user
Authorization: token alice-public-only-token
```

`tokenRequiresScopes` 仍然把 `PublicOnly` 设上；没有人读它。`GetAuthenticatedUser` 返回 alice，body 里出现 flag。

本 case residual 把路径写死为 `/api/v1/user`。认证：v1 + `--residual` 退出码 0。

所以残余不是新洞面，而是同一「public-only 不得读私有用户」策略上换了路由族。seed 被挡住只说明「按用户名查私有账号 403 了」，不说明「持有 public-only token 的私有账号不能读自己」。

---

## 后来又补了什么（CVE-2026-24791，1.26.2）

1.26.2（PR #37118）做了三件事：

```go
// routers/api/v1/api.go  (tag v1.26.2)
func contextAuthenticatedUser() func(ctx *context.APIContext) {
    return func(ctx *context.APIContext) {
        ctx.ContextUser = ctx.Doer
    }
}

func rejectPublicOnly() func(ctx *context.APIContext) {
    return func(ctx *context.APIContext) {
        if !ctx.PublicOnly {
            return
        }
        ctx.APIError(http.StatusForbidden, "this endpoint is not available for public-only tokens")
    }
}

// /user 组收尾：
}, tokenRequiresScopes(...User), reqToken(), contextAuthenticatedUser(), checkTokenPublicOnly())
```

敏感子路由（emails / keys / applications / actions / hooks …）再加 `rejectPublicOnly()`。对残余输入：`ContextUser = alice`，非 public，守卫 403。公开建议是升级到 1.26.2。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是「按用户名寻址」那一组的中间件列表。真正还能读出私有账号的是「我自己」那一组。V2 才把同一守卫接到自路由，并补上 `ContextUser = Doer`。

**不是没有更好的谓词。**  
`checkTokenPublicOnly` 已经能挡住 seed。它已经用在 `/users/{username}` 上。自路由穿越走的是没挂守卫的 `/user`。从 V1 的 diff 只能看到对外组加了一项；要判断补丁是否闭合，必须把 `Routes()` 里两组收尾中间件并排看。

**机械加守卫也不够。**  
User 分支读 `ContextUser`。自路由不跑 `UserAssignmentAPI`。advisory 把这写成独立修复项。

**同一 token、同一私有账号，只换了 URL。**  
seed 和 residual 都是 alice 的 `public-only,read:user`。`/user/orgs` 上还有另一条 incomplete-fix（CVE-2026-25714），说明「只挂一组」会重复发生。

**金丝雀在 email 字段是有意的。**  
flag 不在公开 profile 里。能在 `GET /user` 的 JSON 里看到它，说明返回的是私有账号对象，而不是「公开字段碰巧同名」。

---

## 版本、入口、参考

| | tag | `/users/{username}` | `/user` 自路由 | 按用户名 seed | `GET /user` residual |
|---|---|---|---|---|---|
| V0 | 1.22.2 | 无守卫 | 无守卫 | 读到 email/flag | （也可） |
| V1 | 1.26.1 | `UserAssignmentAPI` + `checkTokenPublicOnly` | 只有 `reqToken` | 403 | 读到 email/flag |
| V2 | 1.26.2 | 同上 | `contextAuthenticatedUser` + `checkTokenPublicOnly` + 敏感子路 `rejectPublicOnly` | 挡 | 403 |

- Web seed：`GET /api/v1/users/alice`
- Web residual：`GET /api/v1/user`
- 认证（本平台）：v0 seed 观察到 flag；v1 seed 未观察到；v1 residual 观察到
- [CVE-2025-68941](https://nvd.nist.gov/vuln/detail/CVE-2025-68941)、[CVE-2026-24791](https://nvd.nist.gov/vuln/detail/CVE-2026-24791)
- [GHSA-xfq3-qj7j-4565](https://github.com/advisories/GHSA-xfq3-qj7j-4565)
- [GHSA-wrr5-99h5-gq57](https://github.com/go-gitea/gitea/security/advisories/GHSA-wrr5-99h5-gq57)
- V1 PR [#32204](https://github.com/go-gitea/gitea/pull/32204)；V2 PR [#37118](https://github.com/go-gitea/gitea/pull/37118)
