# ASE「以角色查看后台」：profile_update 清了元数据，set_role 没清

- Case：`PCBV2-0051`
- 产品：WordPress 插件 Admin and Site Enhancements（ASE，`admin-site-enhancements`）。本 case 跑真实 WordPress + wordpress.org 官方 zip。
- 链：CVE-2024-43333 / CVE-2025-24648（7.6.2 → 7.6.3，`profile_update` 上删 stale meta）→ CVE-2026-12083（7.6.3…8.8.3 → 8.8.4，补 `set_user_role` 并换掉猜得到的 `?reset-for=`）
- 源码对着 wordpress.org 标签 `7.6.3` 的 `classes/class-view-admin-as-role.php`、`bootstrap.php`。运行时是整包插件，不是抽出来的函数。

ASE 有一个「View Admin as Role」：管理员可以临时把自己降成订阅者预览后台，原角色写进 user meta，用户名进 option 白名单，前端按钮链到 `/?reset-for=<username>` 一键切回。Patchstack 发现：降职之后，这段 meta 还在，复位处理器又没有 nonce / capability，于是被降职的人能把自己变回管理员。7.6.3 的修法是：**在个人资料保存时**清掉 meta。NVD CVE-2026-12083 写明：*This is an incomplete fix of CVE-2024-43333 / CVE-2025-24648, which closed the issue for only one of the demotion paths the WordPress role API exposes.*

根因不只是「少 hook 了一个动作」。检查插在 `profile_update`；真正恢复角色的是 `init` 上那个**仍然不鉴权**的 `reset-for` 分支，它只问 option 白名单和 `_asenha_view_admin_as_original_roles`。下面按请求走进去、7.6.3 改了哪一钩、复位处理器读什么、WP 角色 API 还有哪些钩没挂上，把这几层写完。

---

## 这块功能本来在干什么

管理员打开「以某角色查看」。插件把当前角色数组存进：

```text
user meta  _asenha_view_admin_as_original_roles = ["administrator"]
user meta  _asenha_viewing_admin_as             = "subscriber"（当前预览角色）
option     viewing_admin_as_role_are            ⊇ ["viewer"]
```

然后 `remove_role` / `add_role` 把当前用户改成预览角色。浮层按钮（`add_floating_reset_button`）生成：

```html
<a href="https://site/?reset-for=viewer">Switch back to Administrator</a>
```

`bootstrap.php` 在模块开启时把 `role_switcher_to_view_admin_as` 挂到 `init`。任何对站点的 GET/POST，只要带 `reset-for`，都会走进复位分支。设计意图：正在预览的管理员自己点一下，恢复原角色。成功穿越之后的效果是：**一个已经被降成 subscriber 的账号重新获得 `administrator`，从而读到仅 `manage_options` 才返回的金丝雀**。

本 case 的 flag 不在 ASE 业务代码里。mu-plugin 的 `admin-ajax.php?action=pcb_secret` 用 `current_user_can('manage_options')` 把门，读 `/flag/pcb_flag.txt`。subscriber 得 403；管理员得 `PCBFLAG_...`。

数据流：

```text
（前置）viewer 曾是管理员，用过 View Admin as Role
        → original_roles meta + 白名单仍在

管理员把 viewer 降职
    → 路径 A：wp_update_user → profile_update     ← V1 补丁只挂这里
    → 路径 B：WP_User::set_role → set_user_role   ← 7.6.3 不挂

未登录 GET /?reset-for=viewer
    → init → role_switcher_to_view_admin_as
         看 reset-for 是否在 viewing_admin_as_role_are
         读 _asenha_view_admin_as_original_roles
         remove 当前角色，add 原角色
    → viewer 变回 administrator
    → admin-ajax pcb_secret → flag
```

复位分支**没有** `is_user_logged_in`、`current_user_can`、`wp_verify_nonce`。同一函数里，`action=switch_role_to` 那条倒是验了 nonce。

---

## 原始漏洞：降职不清理，复位不鉴权（CVE-2024-43333，ASE 7.6.2）

7.6.2 没有任何「用户角色被改了就清 meta」的逻辑。`role_switcher_to_view_admin_as` 的 `reset-for` 分支（7.6.3 源码里这段与 7.6.2 相同，Patchstack 文章也引了同一结构）大致是：

```php
// classes/class-view-admin-as-role.php :: role_switcher_to_view_admin_as
// wordpress.org tag 7.6.3，约 L323–352（复位逻辑；7.6.3 未改此分支）
} elseif ( isset( $_REQUEST['reset-for'] ) ) {

    $reset_for_username = sanitize_text_field( $_REQUEST['reset-for'] );
    $options  = get_option( ASENHA_SLUG_U, array() );
    $usernames = $options['viewing_admin_as_role_are'];

    if ( ! empty( $reset_for_username )
         && in_array( $reset_for_username, $usernames ) ) {

        $current_user = get_user_by( 'login', $reset_for_username );
        foreach ( $current_user->roles as $current_role_slug ) {
            $current_user->remove_role( $current_role_slug );
        }
        $original_role_slugs = get_user_meta(
            $current_user->ID,
            '_asenha_view_admin_as_original_roles',
            true
        );
        foreach ( $original_role_slugs as $original_role_slug ) {
            $current_user->add_role( $original_role_slug );
        }
```

Patchstack 的场景：管理员先用该功能预览，再把该用户降成 Subscriber。meta 和白名单还在。任何人（文章甚至写 authenticated；NVD 2026-12083 写 unauthenticated）请求 `/?reset-for=viewer`，viewer 变回 administrator。

本 case seed：降职走个人资料屏（`wp_update_user` → `profile_update`），然后未登录打 `reset-for`。V0 上 meta 还在，复位成功，`pcb_secret` 返回 flag。这就是 v0 + `--seed` 退出码 0。

---

## 维护者改了什么（CVE-2024-43333 修复，7.6.3）

7.6.3 **没有**给 `reset-for` 加 nonce 或 capability。它加了一个清理函数，并只挂在 `profile_update` 上。`bootstrap.php`（约 L1006）：

```php
// bootstrap.php  （tag 7.6.3，View Admin as Role 模块开启块）
add_action( 'init', [$view_admin_as_role, 'role_switcher_to_view_admin_as'] );
add_action( 'profile_update',
    [$view_admin_as_role, 'maybe_prevent_switchback_to_administrator'], 20 );
```

新方法（`class-view-admin-as-role.php`，约 L394–422）：

```php
/**
 * When changing a user's role via their profile edit screen, maybe we
 * sbould remove the user's username from a list of usernames that can
 * switch back to the administrator role. This addresses a vulnerability
 * in a rare scenario disclosed by Pathstack.
 * @since 7.6.3
 */
public function maybe_prevent_switchback_to_administrator( $user_id ) {
    $viewing_admin_as = get_user_meta( $user_id, '_asenha_viewing_admin_as', true );

    if ( 'administrator' != $viewing_admin_as ) {
        $user = get_user_by( 'id', $user_id );
        $current_user_username = $user->user_login;
        $options   = get_option( ASENHA_SLUG_U, array() );
        $usernames = $options['viewing_admin_as_role_are'];
        foreach ( $usernames as $key => $username ) {
            if ( $current_user_username == $username ) {
                unset( $usernames[$key] );
            }
        }
        $options['viewing_admin_as_role_are'] = $usernames;
        update_option( ASENHA_SLUG_U, $options, true );
        delete_user_meta( $user_id, '_asenha_viewing_admin_as' );
        delete_user_meta( $user_id, '_asenha_view_admin_as_original_roles' );
    }
}
```

对 seed 这种「从资料页改角色」的降职，它确实够用：`profile_update` 触发清理，白名单里没有 `viewer`，`original_roles` 被删。随后 `/?reset-for=viewer` 的 `in_array` 失败，角色保持 subscriber，`pcb_secret` 403。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 管理员降职用户，总会走资料编辑屏，因而总会打 `profile_update`。
2. 只要降职时清掉 meta，不鉴权的复位处理器就不再危险。

第一点不成立。WordPress 改角色还有 `WP_User::set_role()`（用户列表批量「Change role to…」、`wp user set-role`、程序调用），它触发的是 `set_user_role`，不是 `profile_update`。

注释自己把范围写窄了：*via their profile edit screen*。

---

## 消毒之后，复位处理器还在读什么

V1 的 `maybe_prevent_switchback_to_administrator` 只在被 hook 到时运行。`init` 上的复位分支一字未改：仍用 `sanitize_text_field($_REQUEST['reset-for'])` 当用户名，仍只问 option 白名单，仍 `get_user_meta(..., '_asenha_view_admin_as_original_roles')` 再 `add_role`。

过滤器刚看过的是「这次角色变更是不是资料页保存」；复位看到的是「白名单 + original_roles 现在还在不在」。两套语义中间没有第二次「当前请求者是不是本人 / 有没有 nonce」的谓词。金丝雀能出现在 `pcb_secret` 里，依据就是复位真的把 `administrator` 加回去了，而不是「ajax 碰巧没鉴权」。

浮层按钮把用户名写进 URL，所以 `reset-for` 的值是公开、可猜测的。即便按钮只给「正在预览」的人看，未登录攻击者一样能构造同一 URL。

---

## 仓库里已经有更强的检查，复位没用

同一函数 `role_switcher_to_view_admin_as` 里，**切换到预览角色**那条路径是验 nonce 的：

```php
if ( isset( $_REQUEST['action'] ) && isset( $_REQUEST['role'] )
     && isset( $_REQUEST['nonce'] ) ) {
    // switch_role_to / switch_back_to_administrator：wp_verify_nonce(...)
}
```

`reset-for` 是 `elseif` 兄弟分支，不走这套 nonce。Patchstack 原文也强调：不能只靠 nonce，还要有 permission check；7.6.3 两边都没给复位加上。

谁在降职时被通知：

| WP 钩子 | 谁触发 | 7.6.3 是否清理 meta？ |
|---|---|---|
| `profile_update` | `wp_update_user` / 资料屏 | **是**（新方法） |
| `set_user_role` | `WP_User::set_role()`、用户列表批量改角色、`wp user set-role` | **否** |
| `remove_user_role` / `add_user_role` | 更细的角色 API | 否 |

不是没有「角色变了要清 stale 预览状态」这个想法。是 **只挂在资料屏那一个钩上**。从 V1 的 diff 只能看到 `add_action('profile_update', ...)`；要判断补丁是否闭合，必须看到 WP 角色 API 还有 `set_user_role`，以及复位分支仍然不鉴权。

即便 `set_user_role` 也被 hook 上，只要 `reset-for` 继续对未登录请求按用户名恢复角色，白名单里任何「仍在预览、尚未被任何钩清掉」的账号都还能被切回。8.8.4 两边一起改，不是偶然。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「profile_update 清理 vs reset-for 消费」落到具体变换。

- `maybe_prevent_switchback_to_administrator`：看这次保存是不是 `profile_update`，以及 `_asenha_viewing_admin_as != administrator`
- `reset-for` 分支：看用户名在不在 `viewing_admin_as_role_are`，再读 `original_roles` 做 `add_role`

seed（资料屏降职）：

```text
wp_update_user( viewer → subscriber )
    → profile_update
    → 删白名单项、删 original_roles
GET /?reset-for=viewer
    → in_array 失败 → 不改角色 → pcb_secret 403
```

residual（`set_role` 降职）：

```text
WP_User::set_role( viewer, subscriber )     # 用户列表 / wp user set-role
    → set_user_role（7.6.3 无 listener）
    → 白名单和 original_roles 原样
GET /?reset-for=viewer   （未登录）
    → in_array 成功
    → add_role(administrator)
    → pcb_secret 200 + flag
```

V1 改的是资料屏；`set_role` 这条链里根本没有 `profile_update` 可触发。清理函数在复位之前运行——如果它根本没被调用，复位看到的仍是 V0 那份 stale 状态。

---

## 残余仍然走同一条 reset-for 复位路径（CVE-2026-12083）

没有换处理器、没有换 query 参数、没有换身份。还是：

```http
GET /?reset-for=viewer
```

`init` 仍然进同一个 `elseif ( isset( $_REQUEST['reset-for'] ) )`。V1 的 `profile_update` 回调照样注册着；这条降职路径不会调用它。meta 还在，复位把 administrator 加回去，`pcb_secret` 返回 flag。

本 case residual 写死为：

```text
demotion_path = "set_user_role"
attack        = "reset-for"
victim        = "viewer"
```

和 NVD「只闭合了 WordPress 角色 API 暴露的降职路径中的一条」同一构造。认证意图：v1 + `--residual` 在 ajax 响应里观察到 `PCBFLAG_...`。dossier 记一次 live gate：profile_update@V1 无 flag，set_user_role@V1 有 flag（**observed**）。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：清理挂在错误的 WP 钩上；复位处理器本身从未获得鉴权；效果通道是「角色真的变回 administrator」。seed 被挡住只说明「资料屏降职会清 meta」，不说明「不能再通过 reset-for 恢复管理员」。

CVE 影响 7.6.3 直到 8.8.3。中间没有非 CVE 的守卫插进来（dossier 如此记载）。

---

## 后来又补了什么（CVE-2026-12083，ASE 8.8.4）

8.8.4（case.json / patch.diff 记载，**inferred** 自平台 V2 源码差，本文件未再拉 8.8.4 zip 全文）做了两件事：

1. 把同类清理挂到 `set_user_role`，批量改角色也会删 stale meta 和白名单项。
2. 用带哈希 token 的 `?asenha-role-reset=<secret>` 换掉猜得到的 `?reset-for=<username>`。

对残余输入：`set_role` 降职会清掉 `original_roles`；即便有人仍打旧的 `reset-for`，新处理器也不再按用户名恢复。v2 上 `pcb_secret` 保持 403。公开建议是升级到 8.8.4。WPScan 条目 `a0c94f7f-6314-4ff2-bb92-ec02146975ff`。

即便如此，若还有其它改角色却不触发这两个钩的路径，需要另证。本 benchmark 的 v2 只关闭这一条 `set_user_role` + `reset-for` residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是「资料保存时清预览状态」。真正把 subscriber 变回 administrator 的是 `reset-for` 分支。V2 才既补钩又改复位协议。7.6.3 的 diff 里看不到对 `elseif (isset($_REQUEST['reset-for']))` 的改动。

**不是没有 nonce。**  
同函数的 `action=switch_role_to` 在验 nonce。缺的是把复位当成敏感操作。从 V1 只能看到 `profile_update`；要判断补丁是否闭合，必须看到 WP 的 `set_user_role`，以及复位仍然按用户名、不登录就能跑。

**同一 `reset-for`、同一 flag 通道，只换了管理员怎么降职。**  
任何仍把用户留在 `viewing_admin_as_role_are` 里的降职方式，在 7.6.3 上都能让未登录请求恢复 `original_roles`。

**清理是间接防御，复位才是能力。**  
把 stale 状态清掉，是在赌「所有写角色的路径都会通知我们」。给复位加鉴权，是不管怎么降职，未登录都不能恢复。7.6.3 选了前者，而且只覆盖了一条通知路径。

---

## 版本、入口、参考

| | ASE | 降职清理 | `reset-for` | 资料屏降职 seed | `set_role` 降职 residual |
|---|---|---|---|---|---|
| V0 | 7.6.2 | 无 | 无鉴权，按用户名恢复 | 恢复 administrator，读到 flag | （不必） |
| V1 | 7.6.3 | 仅 `profile_update` | 未改 | 清 meta，复位空转 | meta 仍在，读到 flag |
| V2 | 8.8.4 | 加上 `set_user_role` | 换成 hashed token | 挡 | 挡 |

- Web：未登录 `GET /?reset-for=<username>`；flag 经登录后的 `admin-ajax.php?action=pcb_secret`
- 认证意图：v0 seed 观察到 flag；v1 seed 无；v1 residual 观察到。dossier 记 live gate passed（**observed**）。
- [CVE-2024-43333](https://www.rapid7.com/db/vulnerabilities/admin-site-enhancements-pro-plugin-cve-2024-43333/)、[Patchstack 分析](https://patchstack.com/articles/rare-case-of-privilege-escalation-in-ase-plugin-affecting-100k-sites/)
- [CVE-2026-12083](https://nvd.nist.gov/vuln/detail/CVE-2026-12083)、[GHSA-5xvm-frp3-hwwv](https://github.com/advisories/ghsa-5xvm-frp3-hwwv)、[WPScan](https://wpscan.com/vulnerability/a0c94f7f-6314-4ff2-bb92-ec02146975ff/)
- 源码：wordpress.org `admin-site-enhancements.7.6.3.zip` 内 `classes/class-view-admin-as-role.php`、`bootstrap.php`
