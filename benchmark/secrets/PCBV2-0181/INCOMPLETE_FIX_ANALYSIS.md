# qdPM：.htaccess 挡住了 PHP，unlink 仍按用户字符串拼路径

- Case：`PCBV2-0181`
- 产品：qdPM（PHP 项目管理）。运行时是 SourceForge 发行 zip `qdPM_9.1` / `qdPM_9.2` + `php:7.4-apache`，整站 HTTP，不是抽出来的 `unlink`。
- 链：CVE-2015-3884（8.3 任意上传 → 9.x 用 `uploads/**/.htaccess` 禁 PHP）→ CVE-2020-7246（9.1 的 `photo_preview` 穿越删除 .htaccess → 9.2 `app::is_image()`）
- 源码对着 9.1 的 `core/apps/qdPM/modules/myAccount/actions/actions.class.php`（上传 `move_uploaded_file`、删除 `unlink`）和 9.2 新增的 `core/lib/model/app.class.php::is_image`。金丝雀在 docroot 外 `/flag/pcb_flag.txt`：只有执行上传的 PHP 才能读出来。

NVD CVE-2020-7246 的原话：*An attacker can upload a malicious PHP code file via the profile photo functionality, by leveraging a path traversal vulnerability in the users['photop_preview'] delete photo feature, allowing bypass of .htaccess protection. NOTE: this issue exists because of an incomplete fix for CVE-2015-3884.*

根因不只是「删除接口能删 .htaccess」。检查插在 Apache 的 `FilesMatch \.php` Deny 上；真正决定删谁的是 PHP 里 `sf_upload_dir.'/users/'.$photo_preview` 的拼接，**没有路径谓词**。9.1 业务代码和「修了 2015-3884」的 9.1 是同一份；V0/V1 的差别是 .htaccess 在不在。下面按 HTTP 走进去。

---

## 这块功能本来在干什么

登录用户在「我的账户」改头像。表单 POST 到 Symfony 模块 `myAccount/update`，字段包括 `users[photo]`（新文件）和 `users[photo_preview]`（当前文件名，hidden）。勾选「删除照片」时 `users[remove_photo]=1`。

一次典型请求：

```http
POST /index.php/myAccount/update
Content-Type: multipart/form-data

users[id]=…
users[photo_preview]=123456-old.jpg
users[remove_photo]=1
users[photo]=<file>
```

9.1 的 `executeUpdate` 里，有文件就 `move_uploaded_file` 到 `uploads/users/`；没文件就把 `photo_preview` 写回；勾了删除就 `unlink` 拼出来的路径：

```php
# core/apps/qdPM/modules/myAccount/actions/actions.class.php  (qdPM 9.1)
      if(strlen($userPhoto)>0)
      {
        $userPhoto =  rand(111111,999999) . '-' . $userPhoto;
        $filename = sfConfig::get('sf_upload_dir') . '/users/' . $userPhoto;
        move_uploaded_file($files['users']['photo']['tmp_name'], $filename);
        ...
      }
      ...
      if($form['remove_photo']->getValue()==1 && strlen($form['photo_preview']->getValue())>0)
      {
        unlink(sfConfig::get('sf_upload_dir') . '/users/' . $form['photo_preview']->getValue());
        $form->setFieldValue('photo','');
      }
```

设计意图：头像落在 `uploads/users/`，删除只删「当前那张图」。成功穿越之后的效果是：**先上传 PHP，再让 `photo_preview` 指向 `.htaccess` 或 `../.htaccess`，Apache 不再禁脚本，GET `/uploads/users/<shell>.php` 执行并把 `/flag/pcb_flag.txt` 读进 body**。

需要登录（普通成员即可）。没有「删除 uploads 根上的防护文件」这种权限位。`photo_preview` 来自客户端，不是服务端 session 里记的规范文件名。

---

## 原始漏洞：上传即执行（CVE-2015-3884，8.3 / 无脚本拦截）

Ross Marks 的 writeup（`qdPM_8.3.txt`）和 NVD：myAccount / projects / tasks 等页把可执行扩展名直接放到 `uploads/attachments/` 或 `uploads/users/`，再直接请求该 URL。

9.x 没有改这段 `move_uploaded_file`。所谓「修复」是在 `uploads/` 和 `uploads/users/` 各放一份 `.htaccess`：

```apache
<FilesMatch "\.(php|php3|php4|php5|phtml|exe|html)$">
  Deny from all
</FilesMatch>
```

Apache `AllowOverride All` 时，GET `/uploads/users/foo.php` 返回 403。文件仍在磁盘上，只是不能当脚本跑。

本 case V0 是**同一份 9.1 代码**，entrypoint 抽掉这些 `.htaccess`，用来模拟 2015-3884 尚未用脚本拦截补上的状态。seed：登录 → 把头像上传成 PHP → GET 该文件 → 读 `/flag/pcb_flag.txt`。V0 上脚本能跑，body 里出现 `PCBFLAG_...`。

---

## 维护者改了什么（CVE-2015-3884 的 9.1「修复」）

9.1 相对 8.3，业务上传路径没有加 MIME / 扩展名白名单。闸门在 Web 服务器：

```text
GET /uploads/users/<uploaded>.php
    → Apache 读 uploads/users/.htaccess
    → FilesMatch \.php → 403
```

V1 是库存 9.1 zip，`.htaccess` 在。seed 的 PHP 仍被 `move_uploaded_file` 写进去，但 GET 是 403。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险结果是「浏览器直接请求 `uploads/users/*.php`」。
2. `.htaccess` 会一直留在 `uploads/` 和 `uploads/users/` 里。

第二点不成立：同一 `executeUpdate` 里的 `unlink` 把 `photo_preview` 拼到 `users/` 后面，没有 `basename`、没有「必须落在 users 目录内」、没有「必须是图片」。

---

## 消毒之后，谁还在消费用户字符串

`.htaccess` 只影响 **Apache 怎么对待已存在的 .php**。PHP 侧的删除在检查之外：

```php
unlink(sfConfig::get('sf_upload_dir') . '/users/' . $form['photo_preview']->getValue());
```

`$form['photo_preview']` 来自 POST。过滤器（Apache）从未看见这个字符串。消费者是 `unlink`：内核按 POSIX 解析 `users/../.htaccess`。

上传分支同样不看内容：`$userPhoto` 只是 `rand + 原始文件名`，`.php` 原样留下。9.1 里没有 `is_image()`——那个函数是 9.2 才加的。

数据流（残余）：

```text
POST myAccount/update
    users[remove_photo]=1
    users[photo_preview]=.htaccess          → unlink(.../users/.htaccess)
    users[photo_preview]=../.htaccess       → unlink(.../uploads/.htaccess)

POST myAccount/update
    users[photo]=shell.php                  → move_uploaded_file(.../users/NNNNNN-shell.php)

GET /uploads/users/NNNNNN-shell.php         → 不再 403，include 执行
    → 读 /flag/pcb_flag.txt → body
```

需要两次删除，因为防护文件有两份。PacketStorm / Loginsoft / Medium（Tobin Shields）写的都是这条链。

`photo_preview` 是 Symfony 表单 hidden，浏览器提交「当前头像文件名」。服务端没有把它和数据库 `users.photo` 做一次相等校验，也没有 `basename()`。`.htaccess` 对 PHP 来说只是一个可 `unlink` 的路径字符串；Apache 要等下一次 GET 才会发现配置文件已经没了。上传和删除可以分两次 POST，也可以夹在同一次会话里。

---

## 仓库里已经有更强的检查吗

9.1 **没有**挂在这条路径上的 MIME / realpath 谓词。旁边也没有「删除前必须 `is_file` 且扩展名在白名单」的 helper。所谓更强的检查出现在 9.2：`app::is_image()` 用 `mime_content_type` 对 jpeg/png/gif/ico 白名单。

| 操作 | 9.1 | 9.2 |
|---|---|---|
| 上传 `move_uploaded_file` | 无类型检查 | `is_image(tmp)` 为真才 move |
| 复用 `photo_preview` | 原样写回 | `is_image(users/preview)` |
| `unlink(users/preview)` | 无检查 | 仅当 `is_image(...)` |

V1 等于用 Web 服务器配置代替上传/删除上的路径谓词。不是「有 `is_image` 没用」，是 **9.1 根本没写**。`.htaccess` 挡的是执行，不是删除。

即便 Apache 配置再严，只要 `unlink` 继续裸拼 `photo_preview`，防护文件本身就是可删目标。

---

## 这个补丁挡住了什么、没挡住什么

- `uploads/**/.htaccess` 的 `FilesMatch`：看这次 GET 的 URL 是不是 `.php`，以及该目录里还有没有这份配置
- `unlink(sf_upload_dir.'/users/'.$photo_preview)`：看用户字符串拼完之后内核删哪个 inode

只要让第二行删掉第一行依赖的文件，403 消失，seed 那种 PHP 又能跑。`photo_preview=.htaccess` 删 users 目录内的；`../.htaccess` 上溯到 `uploads/.htaccess`。没有 `str_contains('..')`，也没有 `realpath` 前缀比较。

NVD 把参数写成 `users['photop_preview']`（拼写如此）；表单字段是 `users[photo_preview]`。

---

## 残余仍然走 myAccount 上传 + 删除（CVE-2020-7246）

没有换模块、没有换身份。还是 `POST /index.php/myAccount/update`。先借删除把两份 `.htaccess` 拿掉，再走 seed 用过的上传 + GET。平台残余和 NVD / PacketStorm 156063 是同一 sink：profile photo 的 `unlink` 拼接 + 随后对 `uploads/users/*.php` 的执行。不是换了一个上传页。

v1 + `--residual` 在 GET shell 的 body 里观察到 `PCBFLAG_...`。seed 被挡住只说明「.htaccess 还在时 Apache 不跑 PHP」，不说明「不能让 .htaccess 消失」。

`unlink` 的返回值没有被检查。删掉不存在的路径只是 PHP warning；删成功则防护文件 inode 消失。随后 `move_uploaded_file` 仍把 `.php` 写进 `users/`。两步之间没有「uploads 目录里是否还有 FilesMatch」。Apache 按请求时的 .htaccess 做决定，文件没了就是 Allow。

拼路径时没有任何规范化：

```text
sf_upload_dir . '/users/' . '.htaccess'      →  .../uploads/users/.htaccess
sf_upload_dir . '/users/' . '../.htaccess'   →  .../uploads/users/../.htaccess
                                                 →  .../uploads/.htaccess
```

第二行不需要 `..` 出现在「看起来像穿越」的过滤器里——9.1 根本没有这个过滤器。

---

## 后来又补了什么（9.2，`app::is_image`）

9.2 给上传、preview 复用、删除都包了 `is_image()`，并改了落盘文件名：

```php
# actions.class.php  (qdPM 9.2)
        if(app::is_image($files['users']['photo']['tmp_name']))
        {
          $pathinfo = pathinfo($userPhoto);
          $userPhoto =  'app_user_' . time() . '.' . $pathinfo['extension'];
          ...
          move_uploaded_file(...);
        }

      if($form['remove_photo']->getValue()==1 && strlen($form['photo_preview']->getValue())>0)
      {
        if(app::is_image(sfConfig::get('sf_upload_dir') . '/users/' . $form['photo_preview']->getValue()))
        {
          unlink(...);
        }
      }
```

```php
# app.class.php  (9.2 新增)
    public static function is_image($path)
    {
        if (is_file($path))
        {
            $type = mime_content_type($path);
            if (in_array($type, array('image/jpeg', 'image/png', 'image/gif',
                                      'image/vnd.microsoft.icon', 'image/x-icon')))
            { return true; }
        }
        return false;
    }
```

`.htaccess` 的 MIME 不是 image/*，`is_file` 虽为真但白名单失败，`unlink` 不跑。PHP 上传同样进不了 `move_uploaded_file`。公开建议升到 9.2。

即便如此，`unlink` 仍把 `photo_preview` 拼进路径再测 MIME——若能让 `users/<穿越>` 指向一张真图片，仍可能删那张图。本 benchmark 的 v2 关闭的是「删 .htaccess + 上传 PHP」这条链；`.htaccess` 本身不是 image，过不了闸。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
2015 年改的是 Apache 对已落地 PHP 的执行。真正让防护失效的是 PHP `unlink` 的拼接。9.2 才把谓词挪到业务层（MIME），仍然没有 `realpath` 必须落在 `users/` 下。

**不是没有更好的模型，是 9.1 选了配置当补丁。**  
扩展名白名单、`basename($photo_preview)`、拒绝 `..`，都不必等 9.2。从 9.1 相对 8.3 的「修复」里看不到 `actions.class.php` 的删除分支有任何变化；要判断是否闭合，必须看到 `unlink` 仍信任 hidden 字段。

**同一 `executeUpdate`、同一 `$form['photo_preview']`。**  
上传和删除共享这次 POST。先删防护、再上传，不必找第二个入口。

**hidden 字段被当成服务器状态。**  
`photo_preview` 看起来像「当前头像文件名」，实际是客户端可改的路径片段。若删除只用数据库里存的 `photo` 列，穿越字符串进不了 `unlink`。

**金丝雀在 docroot 外是有意的。**  
普通 GET 读不到 `/flag/pcb_flag.txt`。能出现在 body 里，说明上传的 PHP 真的被解释执行了，不是文件名反射。

**V0 和 V1 是同一份 9.1 业务代码。**  
差别只在 `.htaccess` 在不在。这不是「换了一个版本号的补丁」，是 2015-3884 那次缓解根本没改 `actions.class.php`。要判断 incomplete-fix，必须把 Apache 配置和 PHP `unlink` 当成两层，而不是只看发行版数字。

**`move_uploaded_file` 的目标名仍含用户文件名。**  
9.1 是 `rand(111111,999999) . '-' . $userPhoto`，扩展名跟着走。9.2 改成 `app_user_`.time().`.`.extension，但仍用 `pathinfo` 的 extension；真正挡住 PHP 的是 `is_image(tmp)`，不是改名。

---

## 版本、入口、参考

| | 发行 | 上传 | 删除 | `.htaccess` | PHP seed | 穿越删防护 residual |
|---|---|---|---|---|---|---|
| V0 | 9.1 代码，抽掉 .htaccess | 无 MIME | 裸 unlink | 无 | GET 执行，读到 flag | （不必） |
| V1 | 9.1 库存 | 无 MIME | 裸 unlink | 有 | 403 | 删掉后 GET 执行 |
| V2 | 9.2 | `is_image(tmp)` | `is_image` 为真才 unlink | 有 | PHP 不落地 | .htaccess 不是 image，挡 |

- Web：`POST /index.php/myAccount/update`（需登录）；执行：`GET /uploads/users/<file>.php`
- [CVE-2015-3884](https://nvd.nist.gov/vuln/detail/CVE-2015-3884)、[rossmarks qdPM_8.3](http://rossmarks.uk/whitepapers/qdPM_8.3.txt)
- [CVE-2020-7246](https://nvd.nist.gov/vuln/detail/CVE-2020-7246)、[GHSA-c89p-wjj4-mr4g](https://github.com/advisories/GHSA-c89p-wjj4-mr4g)
- [PacketStorm 156063](http://packetstormsecurity.com/files/156063/qdPM-9.1-Remote-Code-Execution.html)、[Loginsoft writeup](https://www.loginsoft.com/zero-day-discovery/cve-2020-7246-path-traversal-in-qdpm-9-1)、[Medium: Tobin Shields](https://medium.com/@tobinmshields/qdpm-v9-1-authenticated-rce-exploit-f4b84e19df00)
- V1：SourceForge `qdPM_9.1` → `core/apps/qdPM/modules/myAccount/actions/actions.class.php`
- V2：SourceForge `qdPM_9.2` → 同上 + `core/lib/model/app.class.php::is_image`
