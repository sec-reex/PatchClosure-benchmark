# File Browser：signup 只清了 Admin

- Case：`PCBV2-0025`
- 产品：File Browser（Web 文件管理，自注册 + JWT + 服务端命令执行）
- 链：CVE-2026-32760（≤2.61.2 → 2.62.0）→ CVE-2026-34528（2.62.0 / 2.62.1 → 2.62.2）
- 源码对着官方 tag `v2.62.0` 的 `http/auth.go`、`settings/defaults.go`、`users/permissions.go`、`http/commands.go`。运行时是官方镜像 `filebrowser/filebrowser:v2.62.0` 的整包二进制，不是抽出来的函数。

2026 年 3 月，File Browser 给公开注册入口加了一行 `user.Perm.Admin = false`，想挡住「默认模板里勾了管理员」时自注册直接变成超管。一周后同一条 `signupHandler` 被再次点名：`Apply` 拷过去的不只 Admin，还有 `Perm.Execute` 和 `Commands`。NVD / GHSA-x8jc-jvqm-pm3f 写明这是 commit `a63573b` 的直接后果——*applied the strip only to Admin, not to Execute and Commands*。

根因不只是「少清了一个布尔」。检查插在拷贝默认值之后、入库之前；真正决定能不能跑命令的是另一扇门，读的是入库后的同一份 `User`。下面按请求走进去、补丁改了哪一行、默认值怎么落到磁盘上、命令通道为什么不拦，把这三层写完。

---

## 这块功能本来在干什么

File Browser 允许管理员打开 `settings.Signup`，未登录访客 `POST /api/signup` 就能建号。设计意图是：公开注册出来的应该是普通用户，权限来自「默认用户模板」，但模板里那些管理级能力不该跟着走。

一次典型注册：

```http
POST /api/signup
{"username":"...","password":"..."}
```

`signupHandler` 只从 JSON 取出用户名，其余字段全部靠默认模板填：

```go
// http/auth.go :: signupHandler  (filebrowser v2.62.0)
user := &users.User{
    Username: info.Username,
}

d.settings.Defaults.Apply(user)

// Users signed up via the signup handler should never become admins, even
// if that is the default permission.
user.Perm.Admin = false

pwd, err := users.ValidateAndHashPwd(info.Password, d.settings.MinimumPasswordLength)
...
err = d.store.Users.Save(user)
```

`Apply` 是整结构体赋值，不是逐字段白名单：

```go
// settings/defaults.go :: UserDefaults.Apply  (v2.62.0)
func (d *UserDefaults) Apply(u *users.User) {
    u.Scope = d.Scope
    u.Locale = d.Locale
    u.ViewMode = d.ViewMode
    u.SingleClick = d.SingleClick
    u.RedirectAfterCopyMove = d.RedirectAfterCopyMove
    u.Perm = d.Perm          // 整份 Permissions，含 Admin / Execute / Create / ...
    u.Sorting = d.Sorting
    u.Commands = d.Commands  // 命令白名单切片，原样拷
    u.HideDotfiles = d.HideDotfiles
    u.DateFormat = d.DateFormat
    u.AceEditorTheme = d.AceEditorTheme
}
```

`Permissions` 里 Admin 和 Execute 是并列的两个布尔，没有「Admin 包含 Execute」这种从属：

```go
// users/permissions.go
type Permissions struct {
    Admin    bool `json:"admin"`
    Execute  bool `json:"execute"`
    Create   bool `json:"create"`
    Rename   bool `json:"rename"`
    Modify   bool `json:"modify"`
    Delete   bool `json:"delete"`
    Share    bool `json:"share"`
    Download bool `json:"download"`
}
```

数据流：

```text
POST /api/signup {username, password}
    → signupHandler
         user = {Username}
         Defaults.Apply(user)          ← Perm、Commands 整份拷过来
         user.Perm.Admin = false       ← V1 只改这一位
         Users.Save(user)              ← 入库的是清完 Admin 之后的对象
    → POST /api/login → JWT（claims 里带 Perm 和 Commands）
    → 后续请求 withUser 再从 DB 读 d.user
         GET /api/users     → withAdmin：看 Perm.Admin
         WS  /api/command   → commandsHandler：看 EnableExec && Perm.Execute && Commands
```

成功穿越之后的效果，要看走哪扇门：管理员列表里能读到金丝雀用户名，或者命令通道能 `cat` 出树外的 `/opt/flagdir/flag`。金丝雀故意不放在对外文件根 `/srv` 里，文件 API 读不到。

---

## 原始漏洞：默认模板整份继承（CVE-2026-32760，≤2.61.2）

2.61.2 的 `signupHandler` 在 `Apply` 之后没有任何剥离。GHSA-5gg9-5g7w-hm73 的原话是：*The signup handler blindly applies all default settings (including Perm.Admin) to the new user without any server-side guard*。

若管理员把默认模板配成 `perm.admin = true`（设置 API 允许这样做），每个自注册账号都是超管。本 case 的 seed 走管理员通道：

```text
POST /api/signup → POST /api/login → GET /api/users
```

`withAdmin` 只看 `d.user.Perm.Admin`：

```go
// http/auth.go :: withAdmin  (v2.62.0，与 2.61.2 同形)
func withAdmin(fn handleFunc) handleFunc {
    return withUser(func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
        if !d.user.Perm.Admin {
            return http.StatusForbidden, nil
        }
        return fn(w, r, d)
    })
}
```

V0 上自注册用户 `Perm.Admin == true`，`GET /api/users` 返回 200，body 里有一个专门种下的、用户名等于 `PCBFLAG_...` 的管理员。没有登录墙挡在 signup 前面。

同一份默认模板里通常还带着 `execute: true` 和 `commands: ["cat"]`。当时没人单独谈它们，因为已经是超管了，命令通道只是附带品。

---

## 维护者改了什么（CVE-2026-32760 修复，v2.62.0 / a63573b）

V1 只在 `Apply` 之后、哈希密码之前加了三行注释加一行赋值。和前后两个 tag 并排：

```go
// V0  v2.61.2                          （无剥离）
d.settings.Defaults.Apply(user)
pwd, err := users.ValidateAndHashPwd(...)

// V1  v2.62.0                          （CVE-2026-32760，本 case 的目标）
d.settings.Defaults.Apply(user)
// Users signed up via the signup handler should never become admins, even
// if that is the default permission.
user.Perm.Admin = false
pwd, err := users.ValidateAndHashPwd(...)

// V2  v2.62.2                          （CVE-2026-34528）
d.settings.Defaults.Apply(user)
user.Perm.Admin = false
// Self-registered users should not inherit execution capabilities from
// default settings, regardless of what the administrator has configured
// as the default. Execution rights must be explicitly granted by an admin.
user.Perm.Execute = false
user.Commands = []string{}
pwd, err := users.ValidateAndHashPwd(...)
```

注释写的原则是「signup 用户永远不该成为 admin，即便那是默认权限」。它默认了两件事：

1. 自注册不该继承的特权，等价于 `Perm.Admin`。
2. 清掉这一位之后，入库的用户就是「非特权」的。

第一点从产品语义上就不完整：`Permissions` 里还有 `Execute`，旁边还有独立的 `Commands` 切片。第二点也不成立——`Apply` 刚写进去的那两份能力，V1 一行都没动。

对 seed 这种「靠 Admin 读用户列表」的打法，它确实够用：

```text
Apply 之后: Perm.Admin=true, Perm.Execute=true, Commands=["cat"]
V1 之后:    Perm.Admin=false, Perm.Execute=true, Commands=["cat"]
GET /api/users → withAdmin → 403
```

这就是 v1 + `--seed` 退出码 10。seed 被挡住只说明「自注册不再是管理员」，不说明「自注册不再能在服务器上跑命令」。

---

## 入库之后，谁真正看这些位

V1 那一行结束之后，同一个函数立刻 `Users.Save(user)`。JWT 登录时 `printToken` 把 `user.Perm` 和 `user.Commands` 写进 claims；但后续受保护接口并不信 JWT 里的权限快照，而是 `withUser` 按 ID 再从数据库取出完整 `User`：

```go
// http/auth.go :: withUser  (约 L103)
d.user, err = d.store.Users.Get(d.server.Root, tk.User.ID)
```

所以 signup 写进 DB 的 `Perm.Execute` / `Commands` 就是请求时的权威值。

命令通道在 `http/commands.go`。WebSocket 升级之后，先看两道开关，再看白名单：

```go
// http/commands.go :: commandsHandler  (v2.62.0, 约 L63–86)
if !d.server.EnableExec || !d.user.Perm.Execute {
    conn.WriteMessage(websocket.TextMessage, cmdNotAllowed)
    return 0, nil
}

command, name, err := runner.ParseCommand(d.settings, raw)
...
if !slices.Contains(d.user.Commands, name) {
    conn.WriteMessage(websocket.TextMessage, cmdNotAllowed)
    return 0, nil
}

cmd := exec.Command(command[0], command[1:]...)
cmd.Dir = d.user.FullPath(r.URL.Path)
```

三道门：

| 检查 | 来源 | V1 自注册用户 |
|---|---|---|
| `d.server.EnableExec` | 服务器配置 | 本 case 打开，否则通道不存在 |
| `d.user.Perm.Execute` | signup 时 `Apply` 拷进来的 | **仍为 true** |
| `Commands` 含命令名 | 同上，切片原样拷 | **仍含 `cat`** |

过了这三道就 `exec.Command`。金丝雀在 `/opt/flagdir/flag`，不在用户 scope / `/srv` 里；文件浏览 API 到不了，命令通道可以，因为 `cat` 的参数是绝对路径。

`withAdmin` 和 `commandsHandler` 读的是同一份 `d.user`，只是看的字段不同。V1 改了前者关心的那一位，后者关心的两位原样入库。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs 真正的特权」落到具体代码：

- `signupHandler` 的 `user.Perm.Admin = false`：看自注册用户能不能进管理员 API
- `commandsHandler` 的 `EnableExec && Perm.Execute && Commands`：看自注册用户能不能在服务器上起进程

只要默认模板里 `Execute=true` 且 `Commands` 非空，第一行会放行（用户确实不是 admin），第二行仍然跑命令。

GHSA-x8jc-jvqm-pm3f 把这条因果写死了：*This is a direct consequence of the incomplete fix in commit a63573b (CVE-2026-32760 / GHSA-5gg9-5g7w-hm73), which applied the same rationale ("signup users should not inherit privileged defaults") only to Admin, not to Execute and Commands.*

注释里的原则其实已经够用——「signup 不该继承特权默认值」。维护者只把这句话落实到了 `Admin` 这一个字段上。`Apply` 仍然是整份拷贝；剥离是事后逐字段打补丁，漏一个就漏一个。

---

## 残余仍然走同一条 signup 入库路径（CVE-2026-34528）

没有换注册入口、没有换身份、没有绕过 `signupHandler`。还是：

```http
POST /api/signup
POST /api/login
```

然后改走命令通道：

```text
WS /api/command/   （尾斜杠：cmd.Dir 落到 served root）
payload: cat /opt/flagdir/flag
```

`signupHandler` 仍然 `Apply` + 只清 Admin；`Users.Save` 仍然把 `Execute=true` 和 `Commands=["cat"]` 写进库；`commandsHandler` 三道门全过，`exec.Command("cat", "/opt/flagdir/flag")` 的 stdout 经 WebSocket 回给客户端，里面是 `PCBFLAG_...`。

本 case `verify.sh` 的 residual 把 candidate 写死在脚本里（运行时不读 held-out 文件）：

```text
channel = exec
endpoint = /api/command/
command  = cat /opt/flagdir/flag
```

和 GHSA 描述的同一构造，只是把任意命令换成读金丝雀。认证：v1 + `--residual` 退出码 0，命令输出中观察到 flag。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：`Apply` 按结构体拷特权；剥离只覆盖了 Admin；真正起进程的那扇门读的是没被清掉的两位。seed 被挡住只说明「字面超管没了」。

---

## 后来又补了什么（CVE-2026-34528，v2.62.2）

v2.62.2 在 Admin 剥离后面补了执行权：

```go
user.Perm.Admin = false

user.Perm.Execute = false
user.Commands = []string{}
```

注释这次写明：无论管理员把默认模板配成什么样，自注册用户都不该继承执行能力，执行权必须由管理员事后显式授予。

对残余输入：

```text
Apply 之后: Execute=true, Commands=["cat"]
V2 之后:    Execute=false, Commands=[]
WS /api/command → "Command not allowed."
```

`commandsHandler` 第一道用户侧检查就失败，不会 `exec`。公开建议是升级到 2.62.2。

即便如此，这仍然是「`Apply` 之后再逐字段清」。`Create` / `Delete` / `Share` 等其它默认位，本 benchmark 的 v2 不关闭；reference residual 只打 Execute + Commands 这一条。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是 signup 入口上的一个布尔。真正能读树外文件的是 `commandsHandler` 的 `exec.Command`。V2 仍在同一层加码，没有改 `Apply` 本身（例如「公开注册只用一份硬编码的非特权模板」），也没有在 `commandsHandler` 里拒绝「此用户由 signup 创建」。

**不是没有更完整的特权集合。**  
`Permissions` 把 Admin 和 Execute 并列；`Commands` 是另一份允许列表。CVE-2026-32760 的 advisory 已经提到超管可以「Execute arbitrary commands if enableExec = true」，说明项目知道执行权是独立特权。V1 的 diff 只能看到加了一行 `Admin = false`；要判断补丁是否闭合，必须看到 `Apply` 拷了什么、以及 `commandsHandler` 读什么。

**同一函数、同一 `$user`，只换了事后观察的字段。**  
任何在 `Save` 之后读 `d.user.Perm` / `d.user.Commands` 的接口，在 2.62.0 上都吃这一次不完整剥离。admin 通道关上了，exec 通道还开着。

**默认模板是攻击面的一部分。**  
若 signup 启用时强制使用一份写死的最小权限、忽略 `Defaults.Perm` / `Defaults.Commands`，后面那两行剥离根本不会被逼去近似「非特权」。设置 API 允许把 Admin/Execute 写进 defaults，signup 却只纠正其中一位。

**金丝雀在文件树外是有意的。**  
`/opt/flagdir/flag` 不在 `/srv`。能读到它，说明走的是命令执行而不是文件 API。Admin 通道的金丝雀则是用户列表里的用户名，两种观察都绑定在 signup 留下的权限位上。

---

## 版本、入口、参考

| | tag | `signupHandler` 剥离 | `commandsHandler` | 明文 Admin seed | Execute residual |
|---|---|---|---|---|---|
| V0 | 2.61.2 | 无 | 看 EnableExec && Execute && Commands | `GET /api/users` 读到 flag | （不必） |
| V1 | 2.62.0 | 仅 `Perm.Admin=false` | 同上 | withAdmin → 403 | WS 跑 `cat`，读到 flag |
| V2 | 2.62.2 | 再清 `Execute` + `Commands=[]` | 同上 | 挡 | 「Command not allowed.」 |

- 注册：`POST /api/signup`；登录：`POST /api/login`；seed 观察：`GET /api/users`；residual 观察：`WS /api/command/`。
- 认证（本平台）：v0 seed 观察到 flag；v1 seed 未观察到；v1 residual 观察到。
- [CVE-2026-32760](https://nvd.nist.gov/vuln/detail/CVE-2026-32760)、[CVE-2026-34528](https://nvd.nist.gov/vuln/detail/CVE-2026-34528)
- [GHSA-5gg9-5g7w-hm73](https://github.com/filebrowser/filebrowser/security/advisories/GHSA-5gg9-5g7w-hm73)（Admin 继承）
- [GHSA-x8jc-jvqm-pm3f](https://github.com/filebrowser/filebrowser/security/advisories/GHSA-x8jc-jvqm-pm3f)（Execute/Commands 继承；写明是 a63573b 的不完整修复）
- 修复提交：[`a63573b`](https://github.com/filebrowser/filebrowser/commit/a63573b67eb302167b4c4f218361a2d0c138deab)（v2.62.0）、v2.62.2 在同一位置补 `Execute`/`Commands`
