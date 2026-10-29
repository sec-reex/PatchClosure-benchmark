# EazyDocs `delete_doc`：nonce 加上了，能力检查没挂上

- Case：`PCBV2-0106`（legacy `eazydocs-wordpress-plugin-cve-2024-0248`）
- 产品：WordPress 插件 EazyDocs（Spider-Themes）。本 case 跑官方 `wordpress:php8.2-apache` + wordpress.org zip `2.3.5` / `2.3.9` / `2.4.0`。
- 链：CVE-2023-6029（&lt;2.3.6，无 nonce、无能力）→ 2.3.8 回归 → CVE-2024-0248（2.3.9 只加 nonce，2.4.0 才加能力）
- 源码对着 GitHub tag `v2.3.9` 的 `includes/Admin/Delete_Post.php`（`Delete_Post::delete_doc`）、`includes/Admin/Assets.php`、`includes/functions.php`（`ezd_is_admin_or_editor`）。运行时是整包插件，不是抽出来的函数。

2023 年底 WPScan 报：EazyDocs 在处理文档时既没有授权也没有 CSRF，未登录也能删任意文章。2.3.6 修过一次。2.3.8 把洞原样请回来。2.3.9 在 `delete_doc` 的三个 GET 分支上加了 `wp_verify_nonce($_GET['_wpnonce'], $id)`。NVD CVE-2024-0248 写明：*The issue was partially fixed in 2.3.9*；完整修复要到 2.4.0。

根因不只是「nonce 可以泄漏」。检查插在 CSRF 这一层；真正把文章送进回收站的是 `wp_trash_post`，它不问当前用户是不是作者、有没有 `delete_posts`。同文件树里已经有 `ezd_is_admin_or_editor($post_id, 'delete')`，却只定义、不调用。下面按请求走进去、2.3.9 改了哪几行、nonce 从哪发出来、能力谓词挂在哪，把这几层写完。

---

## 这块功能本来在干什么

EazyDocs 在 wp-admin 里管知识库文档。删除走 GET 查询串，不是 REST、也不是 `wp_ajax_*`。`EazyDocs\Admin\Delete_Post` 挂在 `admin_init` 上——**任何**已登录用户打开 `/wp-admin/` 下的页面都会跑到 `delete_doc()`。subscriber 能进仪表盘，因此能进这个函数。

一次典型（管理员自己点删除）的请求：

```http
GET /wp-admin/index.php?Doc_Delete=yes&DeleteID=<id>&_wpnonce=<nonce>
Cookie: wordpress_logged_in_...
```

`DeleteID` 是父文档 ID。函数用 `get_children` 把整棵子树收齐，然后对每个 ID 调 `wp_trash_post(..., true)`，再 302 回 `admin.php?page=eazydocs`。另两个分支 `Section_Delete` / `Last_Child_Delete` 同一套。

设计意图：文档作者或管理员在后台点「删除」，带上防 CSRF 的 nonce。成功穿越之后的效果是：**一个 subscriber 把管理员名下的文档送进回收站**。本 case 的 flag 不在插件业务代码里。mu-plugin 的 `admin-ajax.php?action=pcb_flagcheck` 只在 option `pcb_victim_doc` 指向的那篇文档已被 trash 时才吐 `PCBFLAG_...`。

数据流：

```text
subscriber 会话
    → GET /wp-admin/?Doc_Delete=yes&DeleteID=<victim>
         V1：要求 _wpnonce，wp_verify_nonce(nonce, DeleteID)   ← 补丁只插这里
         仍无 current_user_can / 作者比对
    → get_children 整棵子树
    → wp_trash_post($id, true)                               ← 真正的 sink
    → pcb_flagcheck 看到 victim 已 trash → flag
```

`admin_init` 没有 `current_user_can('edit_posts')` 之类的门。同一插件里创建文档的路径后来有更严的检查；删除这条在 2.3.9 仍然只问 nonce。

---

## 原始漏洞：无 nonce、无能力（CVE-2023-6029，EazyDocs 2.3.5）

2.3.5 的入口条件只看查询串在不在：

```php
# includes/Admin/Delete_Post.php :: delete_doc  (2.3.5，patch.diff 左侧)
if ( isset ( $_GET['Doc_Delete'] ) && ! empty ( $_GET['DeleteID'] )
     && ! empty ( $_GET['Doc_Delete'] == 'yes' ) ) {
    $posts = sanitize_text_field( $_GET['DeleteID'] );
    // ... get_children ...
    foreach ( $doc_ids_int as $deletes ) {
        wp_trash_post( $deletes, true );
    }
    header( "Location:" . admin_url( 'admin.php?page=eazydocs' ) );
}
```

没有 `wp_verify_nonce`，没有 `current_user_can`，没有 `get_post_field('post_author')`。NVD CVE-2023-6029：*does not have authorization and CSRF checks ... allowing unauthenticated users to delete arbitrary posts*。本 case 的 seed 用 subscriber（比「未登录」略高一档，因为 `admin_init` 对未登录通常进不了 wp-admin）发裸 GET：

```text
Doc_Delete=yes&DeleteID=<pcb_victim_doc>     # 无 _wpnonce
```

2.3.5 走进分支，`wp_trash_post` 把管理员的文档丢掉，`pcb_flagcheck` 放出 flag。这就是 v0 + `--seed`。

2.3.6 / 2.3.7 在 wordpress.org 上已不可下载；case 用 2.3.5 当 V0。2.3.8 把洞回归回来，所以 CVE-2024-0248 的受影响区间从 2.3.8 起。

---

## 维护者改了什么（CVE-2023-6029 的 2.3.9 再修）

2.3.9 把三个分支的条件改成「查询串 + `_wpnonce` + `wp_verify_nonce`」。GitHub tag `v2.3.9` 的 `Delete_Post::delete_doc`（与 `patch.diff` 右侧一致）：

```php
# includes/Admin/Delete_Post.php :: delete_doc  (eazydocs tag v2.3.9)
if ( isset($_GET['Doc_Delete']) && $_GET['Doc_Delete'] == 'yes'
     && isset($_GET['DeleteID']) && isset($_GET['_wpnonce'])
     && wp_verify_nonce($_GET['_wpnonce'], $_GET['DeleteID']) ) {

    $posts     = sanitize_text_field( $_GET['DeleteID'] );
    $parent_id = $posts . ',';
    $parent    = get_children( [ 'post_parent' => $posts ] );
    // ... 收集 section / child id ...
    foreach ( $doc_ids_int as $deletes ) {
        wp_trash_post( $deletes, true );
    }
    header( "Location:" . admin_url( 'admin.php?page=eazydocs' ) );

} elseif ( isset($_GET['Section_Delete']) && $_GET['Section_Delete'] == 'yes'
           && isset($_GET['ID']) && isset($_GET['_wpnonce'])
           && wp_verify_nonce($_GET['_wpnonce'], $_GET['ID']) ) {
    // 同样：sanitize → get_children → wp_trash_post，无能力检查
} elseif ( isset($_GET['Last_Child_Delete']) && $_GET['Last_Child_Delete'] == 'yes'
           && isset($_GET['ID']) && isset($_GET['_wpnonce'])
           && wp_verify_nonce($_GET['_wpnonce'], $_GET['ID']) ) {
    wp_trash_post( sanitize_text_field( $_GET['ID'] ), true );
}
```

`wp_verify_nonce( $nonce, $action )` 的 `$action` 被设成文档 ID 本身。这是 CSRF 令牌：它绑定 **当前用户会话 + 这个 ID + 时间窗**，不绑定「这个用户能不能删这篇」。

对 seed 这种「根本没有 `_wpnonce`」的输入，`isset($_GET['_wpnonce'])` 为假，整段不进，victim 还在，`pcb_flagcheck` 不给 flag。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险请求长得像「没有合法 nonce」。
2. 谁能出示合法 nonce，谁就有权 `wp_trash_post`。

第二点不成立——只要插件自己把 nonce 发给 subscriber，第一条闸就变成欢迎垫。

---

## 检查之后，谁真正消费那个 ID

nonce 通过之后，同一个函数立刻用用户给的 ID 当 `post_parent` 去拉子树，然后 **无差别** `wp_trash_post`。WordPress 核心的 `wp_trash_post` 假定调用方已经做过 `current_user_can('delete_post', $id)`；插件这边没有做。

`DeleteID` 经过 `sanitize_text_field` 再 `intval`，这是字符消毒，不是授权。过滤器刚看过的是「这个会话知不知道这个 ID 的 nonce」；trash 看到的是「任意正整数 ID」。两套语义中间没有第二次谓词。

`pcb_flagcheck` 读的是「这篇 victim 文档现在是不是 trash」。能观察到 flag，依据就是这一步，而不是「subscriber 碰巧是作者」。

---

## 仓库里已经有更强的检查，删除路径没用

同一份 2.3.9 的 `includes/functions.php` 末尾已经有按作者 / 管理员判断的函数：

```php
# includes/functions.php :: ezd_is_admin_or_editor  (tag v2.3.9，约 L893–901)
function ezd_is_admin_or_editor( $post_id = '', $action = '' ) {
    if ( $action == 'delete' && get_current_user_id() == get_post_field( 'post_author', $post_id ) ) {
        return true;
    } elseif ( $action == 'edit' && current_user_can('edit_pages')
               && get_current_user_id() == get_post_field( 'post_author', $post_id ) ) {
        return true;
    } elseif ( current_user_can('manage_options') ) {
        return true;
    }
    return false;
}
```

对 `action == 'delete'`：作者本人，或 `manage_options`。subscriber 删别人的文档会得到 `false`。

谁调用它：2.3.9 的 `delete_doc` **不调用**。V1 等于在调用方又做了一个更弱的检查（CSRF），而读路径上那个「作者或管理员才能删」的谓词始终没挂上。不是仓库里没有更好的谓词，是 **delete_doc 没用**。

2.4.0 的 `ezd_perform_edit_delete_actions('delete', $id)`（本 case 文档与 verify 注释）把能力检查接到删除上：`current_user_can('delete_posts')` 并且（作者 == 调用者 或 `manage_options`）。那是把已经存在的「谁能改这篇」想法真正接到 sink 前面。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs trash」落到具体代码：

- `wp_verify_nonce($_GET['_wpnonce'], $_GET['DeleteID'])`：看当前会话是否持有「以这个 ID 为 action」的令牌
- `wp_trash_post($id)`：看这个 ID 在不在数据库里，不看角色

WordPress nonce 的哈希输入是 `tick | action | uid | session_token`。subscriber 自己的会话签发的 nonce，用 subscriber 自己的 cookie 送回去，**会通过**。它挡的是「跨站、跨用户伪造」；它不挡「低权限用户拿自己的令牌做高权限动作」。

nonce 从哪来？同一版本 `Admin\Assets` 在 `admin_enqueue_scripts` 上对后台脚本 `wp_localize_script`：

```php
# includes/Admin/Assets.php  (tag v2.3.9)
'nonce'                => wp_create_nonce( 'eazydocs-admin-nonce' ),
'one_page_prompt_docs' => eazydocs_pro_doc_list(),
```

`eazydocs_pro_doc_list()` 给每个父文档吐：

```html
<option _wpnonce="<wp_create_nonce($doc->ID)>" value="<id>">
```

没有 `current_user_can`、没有「只列出自己的文档」。subscriber 打开任意 `/wp-admin/` 页面，HTML / 内联 JSON 里就有 victim 的 ID 和对应 nonce。action 是 ID，和 `wp_verify_nonce(..., $_GET['DeleteID'])` 对得上。

字符串层面几乎没有变换。seed 缺一个查询参数；残余把同一个参数补上，值来自插件自己的页面。token 还是那个文档 ID；变的是「请求里有没有一个对本会话有效的 10 字符 nonce」。

NVD / WPScan 把 2.3.9 叫 *partially fixed*，正是因为闸从「谁都能进」变成了「谁有令牌都能进」，而令牌在后台是广播的。

---

## 残余仍然走同一条 Doc_Delete 路径（CVE-2024-0248）

没有换 hook、没有换 `wp_trash_post`、没有换 victim。还是：

```http
GET /wp-admin/index.php?Doc_Delete=yes&DeleteID=<victim>&_wpnonce=<leaked>
Cookie: subscriber 会话
```

`delete_doc` 仍然调用同一个 `wp_verify_nonce`。V1 那一行照样执行；执行完之后 `$posts` 还是 victim ID；`wp_trash_post` 把它丢掉；`pcb_flagcheck` 看到 trash 放出 flag。

本 case `verify.sh` 的 residual 把 candidate 写死为 `technique=leaked-nonce`（运行时不读 held-out 文件），执行器登录 subscriber、抓 `eazydocs_local_object` / option 标签上的 `_wpnonce`，再打同一条 `Doc_Delete`。认证：v1 + `--residual` 退出码 0，响应中观察到 `PCBFLAG_...`。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：CSRF 检查被当成授权；真正的 trash 发生在检查之后；删除路径没有使用已经存在的 `ezd_is_admin_or_editor`。seed 被挡住只说明「空 nonce 没了」，不说明「subscriber 不能再删管理员的文档」。

平台 verify 的 residual 与 heldout 是同一条 `Doc_Delete` sink，不是另一条 AJAX。

---

## 后来又补了什么（CVE-2024-0248，EazyDocs 2.4.0）

2.4.0 在删除前调用 `ezd_perform_edit_delete_actions('delete', $id)`：要求 `current_user_can('delete_posts')`，并且调用者是作者或 `manage_options`。subscriber 两头都不满足，`wp_trash_post` 不再执行。公开建议升级到 2.4.0。NVD 写 *before 2.4.0*；WPScan WPVDB `faf50bc0-64c5-4ccc-a8ac-e73ed44a74df` 的 Fixed in 也是 2.4.0。

即便如此，若其它入口（创建、排序、one-page）仍只验 nonce、不验能力，需要另证。本 benchmark 的 v2 只关闭这条 Doc_Delete residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是 `delete_doc` 入口的 CSRF。真正改数据的是 `wp_trash_post`。V2 才把能力接到 sink 前面；V1 把「有令牌」当成「有权力」。

**不是没有更好的谓词。**  
`ezd_is_admin_or_editor(..., 'delete')` 在 2.3.9 已经按作者 / `manage_options` 判断。`delete_doc` 不用它。从 V1 的 diff 只能看到条件里多了 `_wpnonce`；要判断补丁是否闭合，必须看到 trash 之前有没有能力检查，以及 nonce 是不是发给了低权限用户。

**同一函数、同一 `$posts`，只换了查询串里有没有 nonce。**  
`Section_Delete` / `Last_Child_Delete` 吃同一套 `wp_verify_nonce($_GET['_wpnonce'], $_GET['ID'])`。泄漏的 option 标签对这三个分支都有效。

**nonce 的 action 选成了文档 ID。**  
这让「列出所有文档时顺便签发」变得自然：每个 `<option>` 都能带一个能过验证的令牌。若 action 是 `eazydocs_delete_<id>` 且只在「当前用户对这篇有 `delete_post`」时才 `wp_create_nonce`，泄漏面会窄得多。

**金丝雀在业务树外是有意的。**  
`/flag/pcb_flag.txt` 不在文档内容里。能读到它，说明 victim 文档真的被跨权 trash，而不是页面上碰巧印出了字符串。

---

## 版本、入口、参考

| | zip | `delete_doc` | `ezd_is_admin_or_editor` | 无 nonce seed | 泄漏 nonce residual |
|---|---|---|---|---|---|
| V0 | 2.3.5 | 无 nonce、无能力 | （即使有也不调用） | trash → flag | （不必） |
| V1 | 2.3.9 | `wp_verify_nonce(_wpnonce, DeleteID)` | 已定义，删除不用 | 不进分支 | trash → flag |
| V2 | 2.4.0 | 再加 `ezd_perform_edit_delete_actions` | 接到删除上 | 挡 | subscriber 无能力，挡 |

- Web：`GET /wp-admin/?Doc_Delete=yes&DeleteID=...[&_wpnonce=...]`
- 认证（本平台）：v0 seed 观察到 flag；v1 seed 未观察到；v1 residual 观察到。
- [CVE-2023-6029](https://nvd.nist.gov/vuln/detail/CVE-2023-6029)、[WPScan 7a0aaf85](https://wpscan.com/vulnerability/7a0aaf85-8130-4fd7-8f09-f8edc929597e/)
- [CVE-2024-0248](https://nvd.nist.gov/vuln/detail/CVE-2024-0248)、[WPScan faf50bc0](https://wpscan.com/vulnerability/faf50bc0-64c5-4ccc-a8ac-e73ed44a74df/)
- 源码：`https://github.com/spider-themes/eazydocs/blob/v2.3.9/includes/Admin/Delete_Post.php`、`.../includes/Admin/Assets.php`、`.../includes/functions.php`
- zip：`https://downloads.wordpress.org/plugin/eazydocs.2.3.9.zip`、`eazydocs.2.4.0.zip`
