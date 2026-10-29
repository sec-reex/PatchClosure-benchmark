# FileOrganizer：upload 开始查类型了，mkfile / put 还没有

- Case：`PCBV2-0112`（legacy `fileorganizer-wordpress-plugin-cve-2026-11962`）
- 产品：WordPress 插件 FileOrganizer（Softaculous / fileorganizer.net）。运行时是官方 `wordpress:php8.2-apache` + 从 wordpress.org 安装整包插件，不是抽出来的 `ajax.php`。
- 链：CVE-2024-7985（≤1.0.9 → 1.1.0，只给 elFinder `upload.presave` 加 `wp_check_filetype`）→ CVE-2026-11962 / GHSA-mfx2-4vh3-fj3j（<1.2.0 → 1.2.0，把同一谓词接到 `mkfile.pre` / `put.pre` / `rename.pre` / `paste.pre`，并关掉非管理员的 `extract`）
- 源码对着 WordPress.org SVN tag `1.1.0` / `1.2.0` 的 `main/ajax.php`、`init.php::fileorganizer_get_capability`。V1 补丁在 Trac changeset [`3149878`](https://plugins.trac.wordpress.org/changeset/3149878/)。

2024 年 10 月 Wordfence 把 1.0.9 记成 *Authenticated (Subscriber+) Arbitrary File Upload*：`fileorganizer_ajax_handler` 不查类型，Pro 把文件管理能力授给订阅者之后，可以直接 upload 一个 `.php`。1.1.0 changelog 写 *Added additional checks for file uploading*。NVD CVE-2026-11962 几乎把后话写进了标题：*This is an incomplete fix of CVE-2024-7985, which only added file-type validation to the upload operation.*

根因不只是「少绑了一个命令」。检查插在 elFinder 的 `upload.presave` 回调上；真正往磁盘写的是同一 connector 里其它 cmd；`wp_check_filetype` 已经在这个文件里，却只问 `upload` 的文件名。下面按订阅者请求走进去、1.1.0 改了哪一段、检查之后谁 `fopen`、更强的谓词挂在哪，把这几层写完。

本 case 的平台 `--residual` 走的就是 heldout 的 `mkfile` + `put`，和源码层残余是同一条写文件 → 浏览器执行 PHP 的效果通道。金丝雀在 `/flag/pcb_flag.txt`，文档根之外，只有落地并被 Apache 执行的 `.php` 才能读出来。

---

## 这块功能本来在干什么

FileOrganizer 在 wp-admin 里嵌一套 elFinder，让拿到文件管理能力的用户改 WordPress 根目录（默认 `ABSPATH`）里的文件。AJAX 入口是：

```http
POST /wp-admin/admin-ajax.php?action=fileorganizer_file_folder_manager
Cookie: wordpress_logged_in_...
Content-Type: application/x-www-form-urlencoded

cmd=upload&target=<hash>&fileorganizer_nonce=...
```

`fileorganizer_ajax_handler` 先核对 nonce，再按能力放行，然后把请求交给 `elFinderConnector`。elFinder 的 `cmd` 决定走哪条写路径：`upload`、`mkfile`、`put`、`rename`、`paste`、`extract` 都会在同一个 root 上落盘。

身份不是管理员。插件默认能力是 `activate_plugins`：

```php
// init.php :: fileorganizer_get_capability  (SVN tags/1.1.0)
function fileorganizer_get_capability(){
	$capability = 'activate_plugins';
	return apply_filters('fileorganizer_get_capability', $capability);
}
```

Pro 扩展和本 case 的 mu-plugin 都走这只公开过滤器，把它改成 `read`，于是订阅者 `subscriber` / `subpass` 可以进文件管理器。Wordfence 对 CVE-2024-7985 的 NOTE 写明：*The FileOrganizer Pro plugin must be installed and active to allow Subscriber+ users to upload files.* 本环境用同一 hook 复现这个授权面，不是改插件源码。

设计意图：低权限用户可以管文件，但不能把可执行脚本写进文档根。成功穿越之后的效果是：**文档根下出现一个 `.php`，GET 它会在 Apache 用户下执行，读出 `/flag/pcb_flag.txt`。**

数据流：

```text
subscriber 登录
    → GET /wp-admin/admin.php?page=fileorganizer  （页面内嵌 nonce）
    → POST admin-ajax.php?action=fileorganizer_file_folder_manager
         check_admin_referer('fileorganizer_ajax')
         current_user_can(fileorganizer_get_capability())   ← 过滤器后是 read
         elFinderConnector::run()
              cmd=upload  → bind['upload.presave']     ← V1 只改这里
              cmd=mkfile  → volume->mkfile(name)       ← 1.1.0 无类型检查
              cmd=put     → volume->put(target, content)
         文件落在 ABSPATH / 文件名
    → GET /pcb_bypass.php
         Apache 执行 PHP → file_get_contents('/flag/pcb_flag.txt')
```

`upload.presave` 对管理员（`activate_plugins`）直接跳过类型检查。所以差分必须用非管理员：管理员在 V0/V1/V2 都能 upload `.php`，看不出补丁有没有挂上。

---

## 原始漏洞：upload 不查类型（CVE-2024-7985，1.0.9）

1.0.9 的 `upload.presave` 只扫 SVG / XSS，不管扩展名是不是 `php`。elFinder 默认 `acceptedName => 'validName'`，主 volume 也没有 `uploadDeny`。订阅者（经过滤器拿到能力）用 `cmd=upload` 带上 `upload[] = pcb_seed.php` 即可把 web shell 写到站点根。

本 case 的 seed 文件体是：

```php
<?php echo @file_get_contents('/flag/pcb_flag.txt'); ?>
```

1.0.9 上 `POST ... cmd=upload` 返回 elFinder 的 `added`，随后 `GET /pcb_seed.php` 的 body 里出现 FLAG。这就是 v0 + `--seed` 的阳性。

NVD CVE-2024-7985：*missing file type validation in the "fileorganizer_ajax_handler" function in all versions up to, and including, 1.0.9.* 说的是整颗 handler；实现上是 handler 把所有 cmd 交给 elFinder，而 bind 里没有任何类型谓词。

---

## 维护者改了什么（CVE-2024-7985 修复，1.1.0）

Trac changeset `3149878`（1.1.0，2024-09-10）只改 `main/ajax.php` 里 `bind['upload.presave']` 这一段。SVN tag `1.1.0` 现在长这样：

```php
// main/ajax.php :: fileorganizer_ajax_handler  bind  (tags/1.1.0)
'upload.presave' => function(&$path, &$name, $src, $elfinder, $volume) {

	if( !current_user_can('activate_plugins') ) {
		$validate = wp_check_filetype( $name );

		if( $validate['type'] == false ){
			return array( 'error' => __('File type is not allowed.', 'fileorganizer'));
		}
	}

	if( !current_user_can('unfiltered_html') ) {
		$content = file_get_contents($src);
		// ... fileorganizer_xss_content($content) ...
	}

	return true;
}
```

同一 changeset 还给 `fileorganizer_xss_content` 加了 PDF `/JavaScript`、`/JS` 扫描，并把 SVG 的放行收窄到「确实是 svg 才允许 svg/xml 标签」。这些都还在 **upload 读到的临时文件 `$src`** 上。

`wp_check_filetype($name)` 是 WordPress 核心函数：按扩展名查 `get_allowed_mime_types()`。默认表里没有 `php`。订阅者 upload `pcb_seed.php` 时 `$validate['type']` 为 `false`，回调返回 `File type is not allowed.`，elFinder 不落盘。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险写操作等于 `upload`。用户「上传一个文件」才会把陌生扩展名带进文档根。
2. 有 `activate_plugins` 的人不必受这张表约束（管理员本来就能改插件）。

第一点不成立：elFinder 把「新建空文件」和「把编辑器内容写进已有文件」做成了另外两条 cmd。它们不经过 `upload.presave`，也就不问 `$name` 的类型。

`bind` 数组在 1.1.0 里除了 `upload.presave` 只有一个 `mkdir` 回调（给回收站写 `index.php`）。没有 `mkfile`、没有 `put`。

---

## 检查之后，谁真正把文件写到磁盘上

`upload.presave` 是 elFinder 在 **将要保存上传内容之前** 调的 hook。它返回 error 数组，upload 中止。其它 cmd 的执行路径是：

```text
elFinderConnector::run()
    → elFinder->exec($cmd, $args)
         mkfile: volume->mkfile($target, $name)   // 按名字建空文件
         put:    volume->put($target, $content)   // 按 hash 覆盖内容
```

1.1.0 没有任何 bind 拦这两步。LocalFileSystem 驱动用 PHP 在 `ABSPATH` 下 `file_put_contents`。过滤器刚看过的是 upload 临时文件的 `$name`；磁盘看到的是 mkfile 参数里的 `name=pcb_bypass.php` 和 put 参数里的 PHP 源码。两套语义中间没有第二次 `wp_check_filetype`。

随后 Apache 按文档根映射 `GET /pcb_bypass.php` → 执行。金丝雀不在插件里、不在 wp-content 上传目录的「禁止 PHP」约定里——它在 `/flag/`，只有这段被执行的 PHP 能读。所以 FLAG 出现在 GET body 里，依据就是「文档根下有一个可执行的 `.php`」，而不是「upload 目录碰巧能解析 PHP」。

`put` 甚至不带文件名：它只带已有文件的 hash。类型检查如果只写在「创建时」，覆盖内容时还要再问一次名字。V1 两次都没问。

---

## 仓库里已经有更强的检查，兄弟命令没用

`wp_check_filetype` 不是 1.2.0 才发明的。它已经在 1.1.0 的 `upload.presave` 里，对非 `activate_plugins` 用户生效，错误文案也写好了。把它复制到 `mkfile.pre` / `put.pre` 是几行 bind，V2 后来就是这么做的。

同一 `$el_config` 里还有现成的、更粗的旋钮，1.1.0 都没拧到写路径上：

| 已有机制 | 1.1.0 怎么用 | 能否挡住 `.php` |
|---|---|---|
| `wp_check_filetype($name)` | 只在 `upload.presave` | 能，但 mkfile 不问 |
| `$disable_commands` | 只禁 `help` / `preference` / `hide` / `netmount` | 没禁 `mkfile` / `put` / `rename` / `extract` |
| volume `uploadDeny` / `uploadAllow` | 主根未设；回收站设了空表 | 本来就只约束 upload |
| `acceptedName => 'validName'` | 默认 elFinder 名规则 | 允许 `pcb_bypass.php` |
| `fileorganizer_xss_content` | 只在 upload 读 `$src` | mkfile 创建的是空文件，put 不走这段 |

不是仓库里没有更好的谓词，是 **谓词只挂在一条 cmd 上**。elFinder 的 `bind` 设计本来就是「按事件名扩展」；维护者加了 `upload.presave`，等于承认「写文件前要查类型」，却把事件名理解成了「用户点上传按钮」。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs 落盘」落到具体 cmd：

| cmd | 1.1.0 是否经过 `wp_check_filetype` | seed / 残余 |
|---|---|---|
| `upload` | 是（`upload.presave`，非管理员） | seed：`pcb_seed.php` → `File type is not allowed.` |
| `mkfile` | 否 | 残余第一步：建空 `pcb_bypass.php` |
| `put` | 否 | 残余第二步：写入 shell 体 |
| `rename` | 否 | 可把 `a.txt` 改成 `a.php` |
| `paste` | 否 | 可把别处的 `.php` 拷进文档根 |
| `extract` | 否 | 可从 zip 里解出 `.php` |

heldout 选的是最直的一条：不需要事先有文件，也不需要 zip。

```text
cmd=mkfile  target=<cwd>  name=pcb_bypass.php     → added[0].hash
cmd=put     target=<hash> content=<?php echo file_get_contents('/flag/pcb_flag.txt'); ?>
GET /pcb_bypass.php
```

字符串层面没有双重扩展名、没有 `php.`、没有空字节。token 还是「一个 `.php` 文件名 + PHP 源码」；变的是「走哪一个 elFinder 命令」。seed 走 `upload`，V1 认识；残余走 `mkfile`/`put`，V1 当普通新建/保存。

`rename` / `extract` 是同一缺口上的平行写法。NVD 说 *several of its file-management operations*，没有点名 mkfile。本 case 用 mkfile+put，因为两条都未绑定，而且不依赖「先有一个合法文件」。

---

## 残余仍然走同一条 AJAX 写文件路径（CVE-2026-11962）

没有换 action、没有换 nonce、没有换用户。还是：

```http
POST /wp-admin/admin-ajax.php?action=fileorganizer_file_folder_manager
cmd=mkfile&name=pcb_bypass.php&target=...&fileorganizer_nonce=...
```

然后同一会话 `cmd=put`。`fileorganizer_ajax_handler` 仍然只检查 nonce 和 `current_user_can('read')`，然后 `new elFinder($el_config)`。1.1.0 的 `$el_config['bind']` 里仍然只有 `upload.presave` 会问 `wp_check_filetype`。mkfile 返回 `added`，put 把 shell 写进刚建的文件，GET 执行。

认证：v1 + `--residual` 在 `fetched_body` 里看到 `RUN_FLAG`。平台 `verify.sh` 的 else 分支写的就是这条 `mkfile_put` 候选，和 heldout、和 1.1.0 源码是同一 sink。不是「换一个无关的 RCE」，而是 upload 被挡住之后，同一 connector 上隔壁的写 cmd 把同一个 `.php` 送进同一个文档根。

所以残余不是新洞面，而是同一效果上三件事叠在一起：类型谓词只挂在 upload 事件上；elFinder 把创建和写入拆成独立 cmd；磁盘和 Apache 不区分文件是 upload 来的还是 mkfile 来的。seed 被挡住只说明「这条上传回调会拒绝 `.php`」，不说明「订阅者不能再让站点执行自己的 PHP」。

---

## 后来又补了什么（CVE-2026-11962，1.2.0）

1.2.0（2026-06-10）changelog 写成 *Minor Security Fix*，WP Scan 报告人 Revanth Hari Narayana Matte。SVN tag `1.2.0` 的 `bind` 在原有 `upload.presave` 后面加上：

```php
// main/ajax.php  bind  (tags/1.2.0)
'mkfile.pre' => function($cmd, &$args, $elfinder, $volume) {
	if(!current_user_can('activate_plugins')){
		$name = !empty($args['name']) ? $args['name'] : '';
		if($name !== ''){
			$validate = wp_check_filetype($name);
			if($validate['type'] === false){
				return array('preventexec' => true, 'results' => array(
					'error' => __('File type is not allowed.', 'fileorganizer')));
			}
		}
	}
	return array();
},
'put.pre' => function($cmd, &$args, $elfinder, $volume) {
	if(!current_user_can('activate_plugins')){
		$target = !empty($args['target']) ? $args['target'] : '';
		if($target !== ''){
			$file = $volume->file($target);
			if(!empty($file) && !empty($file['name'])){
				$validate = wp_check_filetype($file['name']);
				if($validate['type'] === false){
					return array('preventexec' => true, 'results' => array(
						'error' => __('File type is not allowed.', 'fileorganizer')));
				}
			}
		}
	}
	return array();
},
```

同文件还有结构对称的 `rename.pre`、`paste.pre`。`extract.pre` 更干脆：非 `activate_plugins` 直接 `preventexec`（解压不再做类型白名单，而是整条禁掉）。

对残余：`mkfile.pre` 在 elFinder 建文件之前看到 `name=pcb_bypass.php`，`wp_check_filetype` 失败，返回 `preventexec`。没有 `added`，后续 `put` 也没有合法 target。`GET /pcb_bypass.php` 是 404，FLAG 不出现。

谓词仍是 1.1.0 那一个 `wp_check_filetype`，仍跳过管理员。变的是 **事件名列表**。1.2.0 还把默认路径从硬编码 `ABSPATH` 换成 `$fileorganizer->default_path`，那是另一处产品改动，关不上这条残余。

公开建议：升到 1.2.0+；收回 `fileorganizer_get_capability` 授给低角色的能力；文档根下禁 PHP 执行只能当纵深，不能当补丁。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是「上传按钮对应的 hook」。真正需要约束的是「任何会在文档根创建或改写文件的 cmd」。V2 仍在同一 `$el_config['bind']` 里加码，没有把检查收到一个 `fileorganizer_reject_bad_type($name)` 再让所有写事件调用——但至少 mkfile/put/rename/paste/extract 都问了。

**不是没有更好的谓词。**  
从 1.1.0 的 diff 只能看到 `upload.presave` 变厚了。要判断补丁是否闭合，必须看到同一个 `bind` 数组里还有哪些写事件是空的。`wp_check_filetype` 已经在十行之外。

**同一 connector、同一文档根，只换了 cmd 名字。**  
Apache 执行 `.php` 时不关心这个文件是 upload 来的还是 mkfile 来的。过滤器按事件名分区，内核按路径执行，中间没有第二次身份。

**管理员旁路让差分只在订阅者上可见。**  
`current_user_can('activate_plugins')` 时 V1 的类型检查整段不跑。用管理员测 seed，会误判「1.1.0 仍然能 upload php」。本 case 用 `fileorganizer_get_capability` → `read` 是在复现 Wordfence 写明的授权面，不是另开后门。

**「上传」在文件管理器里不是唯一写入口。**  
changelog 写 additional checks for file *uploading*，和代码里只绑 `upload.presave` 一致。产品把新建、保存、重命名、解压都叫「管理文件」，安全补丁却按 UI 按钮切了一刀。

---

## 版本、入口、参考

| | 插件 | `upload.presave` | `mkfile` / `put` / `rename` / `paste` / `extract` | seed upload `.php` | residual mkfile+put `.php` |
|---|---|---|---|---|---|
| V0 | 1.0.9 | 无类型检查 | 无 | GET shell → FLAG | 同样 FLAG |
| V1 | 1.1.0 | `wp_check_filetype`，非管理员 | 仍无 | `File type is not allowed.` | GET shell → FLAG |
| V2 | 1.2.0 | 同 V1 | `*.pre` 同一谓词；extract 直接禁 | 被挡 | mkfile `preventexec`，无 FLAG |

- Web：订阅者会话 + `action=fileorganizer_file_folder_manager`；FLAG 在 `/flag/pcb_flag.txt`，出现在被执行 PHP 的 GET body 时算命中
- 认证（本平台）：v0 seed 命中；v1 seed 被挡；v1 residual 命中。平台 residual 与 heldout 同为 mkfile+put，同一 sink
- [CVE-2024-7985](https://nvd.nist.gov/vuln/detail/CVE-2024-7985)、[Wordfence advisory](https://www.wordfence.com/threat-intel/vulnerabilities/id/f79164c2-be3b-496d-b747-3e4b60b7fc2b?source=cve)
- V1 补丁：[Trac changeset 3149878](https://plugins.trac.wordpress.org/changeset/3149878/)；changelog 1.1.0 *Added additional checks for file uploading*
- [CVE-2026-11962](https://nvd.nist.gov/vuln/detail/CVE-2026-11962)、[GHSA-mfx2-4vh3-fj3j](https://github.com/advisories/GHSA-mfx2-4vh3-fj3j)
- V2：[FileOrganizer 1.2.0 Launched](https://fileorganizer.net/blog/fileorganizer-1-2-0-launched/)（2026-06-11）；[wordpress.org 插件页 changelog](https://wordpress.org/plugins/fileorganizer/)
- 源码：`https://plugins.svn.wordpress.org/fileorganizer/tags/1.1.0/main/ajax.php`、`.../tags/1.2.0/main/ajax.php`
