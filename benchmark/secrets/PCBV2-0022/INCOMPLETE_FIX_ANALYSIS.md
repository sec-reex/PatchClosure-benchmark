# FreeScout：mute 加了 can('view')，通知页仍走过宽的 update

- Case：`PCBV2-0022`
- 产品：FreeScout（Laravel 共享收件箱）
- 链：CVE-2025-48472（1.8.178 → 1.8.216）→ CVE-2026-41903（1.8.216 → 1.8.217 / GHSA-f489-qxv6-gvgg）
- 源码对着官方 tag `1.8.216` 的 `app/Http/Controllers/MailboxesController.php :: ajax`（mute 分支）、`app/Http/Controllers/UsersController.php :: notifications` / `notificationsSave`、`app/Policies/UserPolicy.php :: update`。运行时是整包 FreeScout PHP 应用，不是抽出来的 policy 方法。

1.8.179+ 给 `POST /mailbox/ajax` 的 `action=mute` 加上 `$user->can('view', $mailbox)`，并把「尚未关联就 attach」限制为管理员，想挡住任意坐席把管理员邮箱挂到自己名下。GHSA-f489-qxv6-gvgg 写明：这是 CVE-2025-48472 的**兄弟路径**——`notificationsSave`（以及读侧的 `notifications`）仍然 `$this->authorize('update', $user)`，而 `UserPolicy::update` 对任何持有 `PERM_EDIT_USERS` 的人返回 true，**没有**「只能改自己 / 不能改管理员」的收窄。NVD 把这件事记成 CVE-2026-41903。

根因不是「mute 的 can('view') 写错了」。那条检查对 seed 够用。检查插在邮箱 ajax 上；真正读出管理员 `last_name`（本 case 的 flag）的是用户通知页，它消费的是另一套 policy。下面按请求走进去、补丁改了哪一分支、消毒后谁还在 authorize('update')、已经更窄的 password 自检为什么通知页没用，把这三层写完。

---

## 这块功能本来在干什么

FreeScout 里坐席可以静音某个邮箱的通知（`mute`），也可以打开「用户 → 通知」页查看/修改订阅（邮件、浏览器、手机）。`PERM_EDIT_USERS` 设计给「编辑他人资料」（姓名、电话、时区），不是给「关掉管理员的安全通知」。

一次典型 seed：

```http
POST /mailbox/ajax
action=mute&mailbox_id=1&mute=1
```

一次典型残余：

```http
GET /users/notifications/1
```

mute 成功时，未关联用户会被 `mailboxes()->attach`，随后 `GET /mailbox/1` 的标题带邮箱名。本 case 把 flag 种在管理员专属邮箱的 `name` 里（seed）以及管理员的 `last_name` 里（residual，`varchar(30)` 故截成 `PCBFLAG_` + 16 hex）。通知页 `<title>` 渲染 `Notifications - {first} {last}`。

数据流：

```text
登录会话（agent / editor）
    → MailboxesController::ajax 'mute'
         V1：can('view', $mailbox)；attach 仅 isAdmin()
    → UsersController::notifications($id)
         authorize('update', $user)     ← UserPolicy::update 含 PERM_EDIT_USERS
         视图输出目标用户姓名
    → 页面 HTML（title / 邮箱名）
```

---

## 原始漏洞：mute 即 attach（CVE-2025-48472，1.8.178）

1.8.178 的 mute 分支大致是：找到 mailbox；若当前用户还没有 `mailbox_user` 行，就 `attach`；再改 mute 标记。没有 `can('view')`。任意坐席对管理员专属邮箱发 mute，自己被加进该邮箱成员，打开 `/mailbox/{id}` 读到带 flag 的邮箱名。seed 用 `agent@pcb.local` 打这条 ajax。

这是授权缺失：静音是写通知偏好，附带了「获得邮箱访问」的副作用。

---

## 维护者改了什么（CVE-2025-48472 修复，1.8.216）

mute 分支加上登录校验、`can('view')`，并把 attach 收成管理员：

```php
# app/Http/Controllers/MailboxesController.php :: ajax  'mute'  (1.8.216)
            case 'mute':
                if (!$user) {
                    \Helper::denyAccess();
                }

                $mailbox = Mailbox::find($request->mailbox_id);

                if (!$mailbox) {
                    $response['msg'] = __('Mailbox not found');
                } elseif (!$user->can('view', $mailbox)) {
                    $response['msg'] = __('Not enough permissions');
                }

                if (!$response['msg']) {
                    $mailbox_user = $user->mailboxesWithSettings()->where('mailbox_id', $mailbox->id)->first();
                    if (!$mailbox_user && $user->isAdmin()) {
                        // Admin may not be connected to the mailbox yet
                        $user->mailboxes()->attach($mailbox->id);
                        ...
                    }
```

对 seed 这种「坐席 mute 自己看不见的邮箱」：`can('view')` 失败，JSON `{"status":"error","msg":"Not enough permissions"}`，agent 仍不是成员，邮箱页读不到 flag。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. CVE-2025-48472 的授权问题就是 mute/attach。
2. 其它「拿着别人的 id 改用户相关状态」的入口，要么已经有更窄的 policy，要么不在这次修复范围且安全。

第二点不成立。`UsersController::notifications` / `notificationsSave` 在 1.8.216 **一行没改**，仍授权 `update`。

---

## 消毒之后，姓名怎么接到页面上

V1 的 mute 一拒绝，同一应用里通知页照样：

```php
# app/Http/Controllers/UsersController.php :: notifications  (1.8.216)
    public function notifications($id)
    {
        $user = User::findOrFail($id);
        $this->authorize('update', $user);
        ...
        return view('users/notifications', [
            'user' => $user,
            ...
        ]);
    }

    public function notificationsSave($id, Request $request)
    {
        $user = User::findOrFail($id);
        $this->authorize('update', $user);
        Subscription::saveFromArray($request->subscriptions, $user->id);
        ...
    }
```

`authorize('update', $user)` 走到：

```php
# app/Policies/UserPolicy.php :: update  (1.8.216)
    public function update(User $user, User $model)
    {
        if ($user->isAdmin()
            || $user->id == $model->id
            || $user->hasPermission(User::PERM_EDIT_USERS)
        ) {
            return true;
        } else {
            return false;
        }
    }
```

`PERM_EDIT_USERS` 持有者对**任意** `$model` 为 true，包括管理员。视图用 `$user->last_name` 拼 title。过滤器刚看过的是 mailbox 的 `view`；open/渲染看到的是另一个用户模型上的 `update`。两套 policy 中间没有「通知订阅只能自己或管理员改」的谓词。

advisory 强调的写路径是 `notificationsSave`（关掉管理员登录告警、分派通知）。本 case 的 oracle 用读路径：同一 `authorize('update')`，GET 页面就能把管理员 `last_name`（flag）带出来。写和读是同一把钥匙。

---

## 仓库里已经有更强的检查，通知页没用

同一 `UsersController` 里，改密码已经是「只能改自己」：

```php
    public function passwordSave($id, Request $request)
    {
        $user = auth()->user();
        if ($user->id != $id) {
            abort(403);
        }
        ...
    }
```

`permissions` / `permissionsSave` 直接 `if (!$user->isAdmin()) abort(403)`。`UserPolicy::delete` 只有管理员。`update` 却把资料编辑权限扩到所有用户的所有「被 authorize('update') 的动作」。

谁在 1.8.216 用 `update`：

| 动作 | 授权 | PERM_EDIT_USERS 能否打管理员 |
|---|---|---|
| 资料 `profileSave` | `update` | 能改非管理员字段（admin 字段会 unset） |
| 通知 GET/POST | `update` | **能**，姓名和订阅 |
| 密码 | 自检 `$user->id != $id` | 否 |
| mute 他人邮箱 | `can('view', mailbox)` | 否（seed 已挡） |

V1 等于在 mute 上接了已经存在的 mailbox `view`，而通知入口始终挂着更宽的 `update`。不是仓库里没有「只能自己」的写法，是 **notifications 没用**。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs 渲染」落到具体代码：

- mute 的 `$user->can('view', $mailbox)`：看坐席能不能看见这只邮箱
- `authorize('update', $targetUser)`：看编辑者有没有 PERM_EDIT_USERS

seed 只碰第一行。residual 用独立账号 `editor@pcb.local`（有 PERM_EDIT_USERS、不是管理员）GET `/users/notifications/{admin_id}`。第一行根本不跑；第二行放行；title 里出现 `PCBFLAG_...`。

```text
seed:
  agent POST /mailbox/ajax action=mute
  V1 can('view') 失败 → 无 attach → 邮箱页无 FLAG

residual:
  editor GET /users/notifications/1
  update policy 因 PERM_EDIT_USERS 为 true
  <title>Notifications - Ada PCBFLAG_...</title>
```

GHSA 把这写成 *sibling of CVE-2025-48472's notification authorization bypass — the prior fix did not cover this code path*。

---

## 残余仍然走同一条用户通知授权（CVE-2026-41903）

没有换成匿名、没有换模型。还是登录用户拿着别人的数字 id：

```http
GET /users/notifications/1
```

`notifications()` 仍然 `authorize('update')`。V1 的 mute 检查照样存在，和这条路由无关。blade 把目标用户姓名写进 title；flag 在 `last_name`。写路径 `POST` 同一授权可以改 `subscriptions` 行（advisory 的完整性影响）；本 case 只要求读出 flag。

本 case `verify.sh` 的 residual 调用 `poc_common.residual_exploit`（editor 登录 + GET notifications）。认证：v1 + `--residual` 退出码 0，body 中观察到 flag。

所以残余不是新洞面，而是同一「对他人用户 id 的写/读」上三件事叠在一起：补丁只改了 mailbox ajax；通知控制器消费的是资料用的 `update`；已经存在的自检/管理员-only 谓词没有接到订阅上。seed 被挡住只说明「不能再靠 mute attach 进管理员邮箱」，不说明「PERM_EDIT_USERS 不能再读管理员通知页上的姓名」。

---

## 后来又补了什么（CVE-2026-41903，1.8.217）

1.8.217 增加更窄的 `updateNotifications` policy（管理员，或自己，或「有 PERM_EDIT_USERS 且目标不是管理员」），`notifications` / `notificationsSave` 改授权到这个方法。editor 打开管理员通知页得到 403。公开建议是升级到 1.8.217。

对残余输入：`authorize` 失败，Laravel 403，title 里没有管理员 last_name，flag 不可见。本 benchmark 的 v2 关闭这条 reference residual；其它仍挂 `update` 的入口若还有「资料编辑不该覆盖的状态」，需要另证。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是 mute 分支的 mailbox 可见性。真正把管理员个人数据（姓名、订阅）交给编辑者的是 `UserPolicy::update`。V2 为通知单独开了谓词，这才对准 sink。

**不是没有更好的谓词。**  
`passwordSave` 的「只能自己」、`permissions` 的「只能管理员」已经在同一控制器里。从 V1 的 diff 只能看到 mute 多了 `can('view')`；要判断补丁是否闭合，必须看到所有 `authorize('update', $user)` 的调用点。

**同一 policy、同一 `$id`，只换了控制器方法。**  
mute 用 mailbox_id；通知用 user id。都是「低权限角色对高权限对象的 IDOR」，对象类型不同。

**PERM_EDIT_USERS 的名字比实际授权窄。**  
权限文案是编辑用户，实现却等于「对 User 模型的 update 能力」，被通知这种非资料字段复用。

**金丝雀在 last_name / 邮箱名里是有意的。**  
flag 不是通用 CSRF 响应。能在通知页 title 读到它，说明打开的是管理员那条用户记录，而不是编辑者自己。

---

## 版本、入口、参考

| | tag | mute 他人邮箱 | `GET /users/notifications/{admin}` | `UserPolicy::update` |
|---|---|---|---|---|
| V0 | 1.8.178 | attach + 读邮箱名 FLAG | （亦可） | 含 PERM_EDIT_USERS |
| V1 | 1.8.216 | `can('view')` 拒绝 | 200，title 含 FLAG | 仍含 PERM_EDIT_USERS |
| V2 | 1.8.217 | 同 V1 | 403 | 通知改走 `updateNotifications` |

- Web：`POST /mailbox/ajax`（seed）/ `GET /users/notifications/{id}`（residual），端口 80
- 认证（本平台）：v0 seed 观察到 flag；v1 seed 未观察到；v1 residual 观察到。
- [CVE-2026-41903](https://nvd.nist.gov/vuln/detail/CVE-2026-41903) / [GHSA-f489-qxv6-gvgg](https://github.com/freescout-help-desk/freescout/security/advisories/GHSA-f489-qxv6-gvgg)
- 前置：CVE-2025-48472
- 官方 tag：`https://github.com/freescout-help-desk/freescout/tree/1.8.216` 与 `1.8.217`
