# phpMyFAQ：密码改写加了 SuperAdmin 谓词，同文件的编辑/授权没加

- Case：`PCBV2-0170`
- 产品：phpMyFAQ（FAQ / 知识库，PHP + Symfony 路由 + MariaDB）。运行时是整仓 `thorsten/phpMyFAQ` 在 tag `4.1.2` / `4.1.3` / `4.1.4` 上 `composer install` 后走官方 Web 安装器，不是抽出来的控制器。
- 链：CVE-2026-35671（4.1.2 → 4.1.3，GHSA-xvp4-phqj-cjr3）→ CVE-2026-56396（4.1.3 → 4.1.4，GHSA-985r-q3qp-299h）
- 源码对着 tag `4.1.3` 的 `phpmyfaq/src/phpMyFAQ/Controller/Administration/Api/UserController.php`（`overwritePassword` / `editUser` / `updateUserRights` / `addUser` / `activate`）、`AbstractController.php`（`userHasUserPermission` / `userHasPermission` / `userIsSuperAdmin`）、`User.php`（`setSuperAdmin` / `changePassword`）、`Permission/BasicPermission.php`（`hasPermission`）。金丝雀是 benign：`api.apiClientToken` 被写成 `PCBFLAG_...`，只在 SuperAdmin 能进的配置页出现。

NVD 对 CVE-2026-56396 的原话：*phpMyFAQ before 4.1.4 contains missing authorization vulnerabilities in editUser() and updateUserRights() endpoints*。GHSA-985r-q3qp-299h 标题直接写 *incomplete fix for GHSA-xvp4-phqj-cjr3*，并引用 4.1.3 补丁自己的注释：*Only SuperAdmins may change other users' [attributes]*。

根因不只是「漏了两个路由」。检查插在「谁可以改别人的密码」上；真正把权限写进库的是后面的 `setSuperAdmin` / `grantUserRight`。同文件、同基类里已经有 `userIsSuperAdmin()` 和「禁止动 SuperAdmin / protected」的谓词，却只挂在 `overwritePassword`。下面按请求走进去。

---

## 这块功能本来在干什么

phpMyFAQ 后台给「用户管理员」一组 REST 风格的管理接口，用来改密码、改资料、改权限。一次典型的密码覆盖：

```http
POST /admin/api/user/overwrite-password
Cookie: PHPSESSID=…
Content-Type: application/json

{"userId":1,"csrf":"<page token>","newPassword":"…","passwordRepeat":"…"}
```

`UserController::overwritePassword` 先做 `userHasUserPermission()`（要求同时持有 `add_user` + `edit_user` + `delete_user`），再验 CSRF，再按 body 里的 `userId` 取出目标用户并 `changePassword`。`editUser` / `updateUserRights` 只要求 `userHasPermission(USER_EDIT)`，同样从 body 取 `userId`。

设计意图：持有用户管理权的人可以维护普通账号；SuperAdmin 旗标、protected 账号、uid=1 不应被同级管理员改掉。成功穿越之后的效果是：**低权用户管理员把自己写成 SuperAdmin**，随后 `hasPermission` 对一切权限短路为真，从而读出只有 `CONFIGURATION_EDIT` 才该看见的 `api.apiClientToken`。

数据流：

```text
POST /admin/authenticate          （editor：有 USER_*，不是 SuperAdmin）
    → 刮 CSRF（overwrite-password / update-user-data）
    → POST /admin/api/user/overwrite-password   ← seed，V1 已拦
         userHasUserPermission()
         isSelf / isSuperAdmin / target SuperAdmin|protected
         User::changePassword
    → POST /admin/api/user/edit                 ← residual，V1 未拦
         userHasPermission(USER_EDIT)
         （没有 SuperAdmin 谓词）
         User::setSuperAdmin((bool)$is_superadmin)
              UPDATE faquser SET is_superadmin=1
    → GET /admin/api/configuration/list/api
         hasPermission(CONFIGURATION_EDIT)
              isSuperAdmin() → true  ← 短路
         响应里出现 PCBFLAG_...
```

需要登录。`editor` 事先被授予可委派的用户管理权，但不是 SuperAdmin，也没有 `editconfig`。没有「改 SuperAdmin 旗标」这个单独权限位。

---

## 原始漏洞：userId 直接进 changePassword（CVE-2026-35671，4.1.2）

4.1.2 的 `overwritePassword` 在 CSRF 和密码长度之后，直接用当前会话对象去加载目标：

```php
// UserController.php :: overwritePassword  (phpMyFAQ 4.1.2)
$this->userHasUserPermission();
$currentUser = CurrentUser::getCurrentUser($this->configuration);
$data = json_decode($request->getContent());
$userId = Filter::filterVar($data->userId, FILTER_VALIDATE_INT);
...
$currentUser->getUserById((int) $userId, allowBlockedUsers: true);
$authSource = $auth->selectAuth($currentUser->getAuthSource(key: 'name'));
...
if (!$currentUser->changePassword($newPassword)) {
```

`userHasUserPermission` 只问「你有没有用户管理权」，不问「你能不能改 *这个* `userId`」。GHSA-xvp4-phqj-cjr3 写明：*NO check that $userId belongs to a user the admin should manage*，*Can overwrite password for ANY user, including SuperAdmin (userId=1)*。

本 case seed 走这条 HTTP 路径：以 `editor` 登录，从真实后台页刮 `overwrite-password` CSRF，POST `userId=1` 和新密码，再以 SuperAdmin 登录，读 `GET /admin/api/configuration/list/api`。金丝雀是安装时写入 `faqconfig.api.apiClientToken` 的 `PCBFLAG_...`。这就是 v0 + `--seed` 观察到 flag。

同一文件里 `editUser` / `updateUserRights` 在 4.1.2 同样没有对象级检查；seed 选密码覆盖，是因为那是 35671 补丁明确加了谓词的那条路。

---

## 维护者改了什么（CVE-2026-35671 修复，4.1.3）

4.1.3 只改了 `overwritePassword`（`deleteUser` 顺带整理了一下错误 JSON）。补丁自己写的不变量：

```php
// UserController.php :: overwritePassword  (phpMyFAQ 4.1.3)
$isSelf = $this->currentUser->getUserId() === (int) $userId;
$actingIsSuperAdmin = $this->currentUser->isSuperAdmin();

// Only SuperAdmins may change other users' passwords. Self-service is always allowed.
if (!$isSelf && !$actingIsSuperAdmin) {
    return $this->json(['error' => Translation::get(key: 'msgNoPermission')], Response::HTTP_FORBIDDEN);
}

$targetUser = new User($this->configuration);
$targetUser->getUserById((int) $userId, allowBlockedUsers: true);

// Defense in depth: a non-SuperAdmin must never be able to alter a SuperAdmin or protected account,
// even when isSelf would short-circuit the check above.
if (!$actingIsSuperAdmin && ($targetUser->isSuperAdmin() || $targetUser->getStatus() === 'protected')) {
    return $this->json(['error' => Translation::get(key: 'msgNoPermission')], Response::HTTP_FORBIDDEN);
}

...
if (!$targetUser->changePassword($newPassword)) {
```

V1 谓词的字面意思：

| 谓词 | 含义 |
|---|---|
| `userHasUserPermission()` | 调用者持有 add/edit/delete_user（入口仍在） |
| `!$isSelf && !$actingIsSuperAdmin` | 改别人密码必须是 SuperAdmin |
| 目标是 SuperAdmin 或 `protected` | 非 SuperAdmin 一律 403，即使 `isSelf` |

对 seed 这种「`editor` 改 uid=1 密码」它确实够用：`isSelf` 为假、`actingIsSuperAdmin` 为假，403。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险操作长得像「改别人的密码」。
2. 同一不变量会自动覆盖同控制器里其它「按 `userId` 做特权写」的方法。

第二点不成立。`git diff 4.1.2 4.1.3` 对 `editUser`、`updateUserRights`、`setSuperAdmin`、`grantUserRight` 没有任何改动。

---

## 检查之后，谁真正改库

V1 的 403 只发生在 `overwritePassword` 里。同一次会话、同一个 `editor`，还可以打 `editUser`。4.1.3 的 `editUser` 在 CSRF 和 `userId` 非零之后，**立刻**把请求体里的 `is_superadmin` 写进库：

```php
// UserController.php :: editUser  (phpMyFAQ 4.1.3)
$this->userHasPermission(PermissionType::USER_EDIT);
...
$isSuperAdmin = Filter::filterVar($data->is_superadmin, FILTER_SANITIZE_SPECIAL_CHARS);
...
$user = new User($this->configuration);
$user->getUserById($userId, allowBlockedUsers: true);

// Set the super-admin flag
$user->setSuperAdmin((bool) $isSuperAdmin);
```

`User::setSuperAdmin` 自己没有鉴权，就是一条 UPDATE：

```php
// User.php :: setSuperAdmin  (phpMyFAQ 4.1.3)
public function setSuperAdmin(bool $isSuperAdmin): bool
{
    $this->isSuperAdmin = $isSuperAdmin;
    $update = sprintf(
        'UPDATE %sfaquser SET is_superadmin = %d WHERE user_id = %d',
        Database::getTablePrefix(),
        (int) $this->isSuperAdmin,
        $this->userId,
    );
    $res = $this->configuration->getDb()->query($update);
    return (bool) $res;
}
```

过滤器刚看过的是「这次请求是不是在改密码」；库看到的是「`faquser.is_superadmin` 被写成 1」。两套语义中间没有第二次谓词。

`updateUserRights` 更直接：先 `refuseAllUserRights`，再按 body 里的数组 `grantUserRight`，同样没有「只能授自己有的权」或「不能改 SuperAdmin」：

```php
// UserController.php :: updateUserRights  (phpMyFAQ 4.1.3)
$this->userHasPermission(PermissionType::USER_EDIT);
...
$user->getUserById($userId);
$userRights = Filter::filterVar($data->userRights, FILTER_SANITIZE_SPECIAL_CHARS, []);
if (!$user->perm->refuseAllUserRights($userId)) { ... }
foreach ($userRights as $userRight) {
    $user->perm->grantUserRight($userId, (int) $userRight);
}
```

金丝雀为什么在升级之后能被读到：`BasicPermission::hasPermission` 对 SuperAdmin 短路：

```php
// Permission/BasicPermission.php :: hasPermission  (phpMyFAQ 4.1.3)
if ($currentUser->isSuperAdmin()) {
    return true;
}
return $this->checkUserRight($currentUser->getUserId(), $right);
```

`GET /admin/api/configuration/list/api` 要的是 `CONFIGURATION_EDIT`。`editor` 本来没有这项；`is_superadmin=1` 之后短路为真，HTML 里渲染出 `api.apiClientToken`。能读到树外配置，依据就是这一步，而不是「配置页碰巧对普通管理员开放」。

---

## 仓库里已经有更强的检查，兄弟方法没用

同一份 `AbstractController.php` 里已经有专门拦 SuperAdmin 的入口：

```php
// AbstractController.php  (phpMyFAQ 4.1.3)
protected function userIsSuperAdmin(): void
{
    if (!$this->currentUser->isSuperAdmin()) {
        throw new UnauthorizedHttpException(challenge: 'User is not super admin.');
    }
}
```

谁调用它、谁没用：

| 函数 | 对象级 SuperAdmin / protected 谓词？ |
|---|---|
| `overwritePassword`（V1） | 是，补丁新加的两段 |
| `deleteUser` | 部分：`protected` 或 `userId === 1` 直接拒绝 |
| `editUser` / `updateUserRights` | **否**，只做 `USER_EDIT` |
| `addUser` | **否**，仍执行 `$newUser->setSuperAdmin((bool) $userIsSuperAdmin)` |
| `activate` | **否**，GHSA-985r 点名为较低影响的同形兄弟 |

V1 等于在调用方 `overwritePassword` 又做了一个**只覆盖密码写**的检查，而「任意 `userId` + 特权 mutation」这条原语在同文件另外几处始终没挂上。不是仓库里没有更好的谓词，是 **edit / rights / add 没用**。

即便不走 `is_superadmin` 质量赋值，只要 `updateUserRights` 继续按请求数组授权，任何让 `editor` 拿到 `editconfig` 的写法也会打开同一扇配置页。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs 写库」落到具体代码：

- `overwritePassword` 的 `!$isSelf && !$actingIsSuperAdmin`：看这次是不是在改别人密码
- `editUser` 的 `$user->setSuperAdmin((bool) $isSuperAdmin)`：看请求体里有没有 SuperAdmin 旗标
- `hasPermission` 的 `isSuperAdmin()` 短路：看库里那一列现在是不是 1

只要构造一种输入，使「改密码」被 403，但「改资料」仍把 `is_superadmin` 写进去，第一行会放行（对 seed），第二行仍然完成提权。

`is_superadmin=1` 打自己就是这样来的。GHSA-985r 的 Exploit 1：*editor (non-SuperAdmin, passes userHasPermission(edit_user)) flips their own is_superadmin 0→1*。不需要碰 uid=1，也不需要再改密码。

带上 CSRF 和真实路由：

```text
POST /admin/api/user/edit
  userId = editor 自己的 uid
  is_superadmin = "1"
  csrfToken = 页面 update-user-data

V1：没有 actingIsSuperAdmin 谓词
    → setSuperAdmin(true)
    → faquser.is_superadmin = 1

下一请求 GET /admin/api/configuration/list/api
    → hasPermission(CONFIGURATION_EDIT) 因 SuperAdmin 短路
    → body 里出现 PCBFLAG_...
```

这正是 4.1.2 上 seed 用过的那种「低权管理员越过 SuperAdmin 边界」的效果。过滤器认为自己已经把「改别人密码」清干净了，实际上特权写还在隔壁方法里，并且 `setSuperAdmin` 会按布尔值落库。

---

## 残余仍然走同一条用户管理 API（CVE-2026-56396）

没有换身份、没有换后台、没有换金丝雀通道。还是 `editor`，还是用户管理权，还是最后读 `api.apiClientToken`。换的是 mutation：

```http
POST /admin/api/user/edit
{"userId":<editor>,"csrfToken":"…","is_superadmin":"1","display_name":"Editor",…}
```

`editUser` 仍然只做 `USER_EDIT` + CSRF。V1 那两段 SuperAdmin 谓词不在这条方法里；执行完之后 `faquser.is_superadmin` 变成 1；配置列表把 token 渲染进 HTML。

公开 advisory 还给出第二条同形残余：`POST /admin/api/user/update-rights` 给任意账号授 `editconfig`。那是**同一条不完整修复链上的另一个 sink**（`grantUserRight`），不是换产品面。本平台 residual 选的是 `editUser` 质量赋值，和 GHSA-985r Exploit 1 同一构造，只是把「自己变成 SuperAdmin」之后的观察点换成金丝雀配置项。

所以残余不是新洞面，而是同一特权边界上三件事叠在一起：谓词只挂在密码写上；`setSuperAdmin` 发生在检查之后（对兄弟方法而言是「根本没有检查」）；已经存在的 `userIsSuperAdmin()` / `deleteUser` 的 uid=1 保护没有复用到 edit/rights。seed 被挡住只说明「不能再改 uid=1 的密码」，不说明「不能再跨过 SuperAdmin 边界」。

---

## 后来又补了什么（CVE-2026-56396，4.1.4）

4.1.4 把同一套不变量补到兄弟方法上。`editUser`：

```php
$actingIsSuperAdmin = $this->currentUser->isSuperAdmin();

// Only SuperAdmins may grant or revoke the SuperAdmin flag.
if (!$actingIsSuperAdmin && (bool) $isSuperAdmin) {
    return $this->json(['error' => Translation::get(key: 'msgNoPermission')], Response::HTTP_FORBIDDEN);
}

$user->getUserById($userId, allowBlockedUsers: true);

if (!$actingIsSuperAdmin && ($user->isSuperAdmin() || $user->getStatus() === 'protected')) {
    return $this->json(['error' => Translation::get(key: 'msgNoPermission')], Response::HTTP_FORBIDDEN);
}

if ($actingIsSuperAdmin) {
    $user->setSuperAdmin((bool) $isSuperAdmin);
}
```

`updateUserRights` 加上「非 SuperAdmin 只能授自己已有的权」以及目标 SuperAdmin/protected 拒绝。`activate` 也补了目标保护。

对残余输入：`editor` 设 `is_superadmin=1` 在第一段就被 403，`setSuperAdmin` 不再执行。公开建议是升级到 4.1.4。

即便如此，`User::setSuperAdmin` 本身仍然无守卫；闭合靠的是每个调用方都记得问一遍。`addUser` 在 4.1.4 的 diff 里不是本 CVE 的主修复面。本 benchmark 的 v2 关闭的是 reference residual 这条 `editUser` 质量赋值。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是 `overwritePassword` 入口的调用者/目标关系。真正越过 SuperAdmin 边界的是 `User::setSuperAdmin` 和 `grantUserRight`。V2 仍在控制器层给每个兄弟方法加码，没有把「写 SuperAdmin 旗标」收进 `setSuperAdmin` 自己。

**不是没有更好的谓词。**  
`userIsSuperAdmin()` 已经在基类里。`deleteUser` 已经拒绝 uid=1 和 `protected`。`overwritePassword` 的注释已经把不变量写清楚。从 V1 的 diff 只能看到密码方法多了两段 if；要判断补丁是否闭合，必须看到同文件里其它 `getUserById` → 特权 mutation 的调用点。

**同一控制器、同一 `userId`，只换了 mutation。**  
任何把用户 JSON 传进 `editUser` / `updateUserRights` 的后台页，在 4.1.3 上都吃同一道 `USER_EDIT` 门和同一次无守卫写。advisory 已指出 CSRF 对已登录的用户管理员不是障碍。

**权限位和 SuperAdmin 旗标不是同一层。**  
`USER_EDIT` 可委派；`is_superadmin` 让 `hasPermission` 对一切权利短路。V1 守住了密码，没守住让短路发生的那一列。

**金丝雀在配置项里是有意的。**  
`api.apiClientToken` 不在 FAQ 正文里。能读到它，说明会话已经按 SuperAdmin 通过了 `CONFIGURATION_EDIT`。

---

## 版本、入口、参考

| | tag | `overwritePassword` | `editUser` / `updateUserRights` | 改 uid=1 密码 seed | `is_superadmin` residual |
|---|---|---|---|---|---|
| V0 | 4.1.2 | 无对象级检查 | 无 | 接管后读到金丝雀 | （不必） |
| V1 | 4.1.3 | isSelf + SuperAdmin + 目标保护 | 仍无 | 403 | 自己升 SuperAdmin，读到金丝雀 |
| V2 | 4.1.4 | 同上 | 拒绝非 SuperAdmin 设旗标 / 超权授权 | 挡 | 403 |

- Web：`POST /admin/api/user/overwrite-password`、`POST /admin/api/user/edit`、`GET /admin/api/configuration/list/api`
- 观察：配置列表 HTML 中的 `PCBFLAG_...`（`api.apiClientToken`）
- [CVE-2026-35671](https://nvd.nist.gov/vuln/detail/CVE-2026-35671)、[CVE-2026-56396](https://nvd.nist.gov/vuln/detail/CVE-2026-56396)
- [GHSA-xvp4-phqj-cjr3](https://github.com/thorsten/phpMyFAQ/security/advisories/GHSA-xvp4-phqj-cjr3)
- [GHSA-985r-q3qp-299h](https://github.com/thorsten/phpMyFAQ/security/advisories/GHSA-985r-q3qp-299h)
- V1 blob：[`UserController.php@4.1.3`](https://github.com/thorsten/phpMyFAQ/blob/4.1.3/phpmyfaq/src/phpMyFAQ/Controller/Administration/Api/UserController.php)、[`AbstractController.php@4.1.3`](https://github.com/thorsten/phpMyFAQ/blob/4.1.3/phpmyfaq/src/phpMyFAQ/Controller/AbstractController.php)、[`User.php@4.1.3`](https://github.com/thorsten/phpMyFAQ/blob/4.1.3/phpmyfaq/src/phpMyFAQ/User.php)、[`BasicPermission.php@4.1.3`](https://github.com/thorsten/phpMyFAQ/blob/4.1.3/phpmyfaq/src/phpMyFAQ/Permission/BasicPermission.php)
- V2 tag：`4.1.4`
