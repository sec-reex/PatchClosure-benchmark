# WP Super Cache：一条评论里要开闭成对，拆成两条就进缓存 PHP

- Case：`PCBV2-0213`
- 产品：WordPress 插件 WP Super Cache（页面缓存，把 HTML 烘焙成可 include 的 PHP）。运行时是官方 wordpress.org zip `1.2` / `1.3.1` / `1.3.2` 的整包字节；产品路径是访客评论 → `no_mfunc_in_comments` → 页面缓冲 → `wp-cache-phase2.php` 把 mfunc 写成 `<?php`。
- 链：CVE-2013-2009（1.2 → 1.3 / 1.3.1）→ CVE-2013-2011（1.3.1 → 1.3.2）。NVD 对 2011 的原话：*This issue exists because of an incomplete fix for CVE-2013-2009.*
- 源码对着 tag `1.3.1` 的 `wp-cache.php`（`no_mfunc_in_comments`）和 `wp-cache-phase2.php`（缓冲里的 mfunc → PHP）。金丝雀是 benign：sink 发出的 PHP 被收成读 `/flag/pcb_flag.txt`，不跑攻击者任意代码。

oss-security 2013-04-25 Kurt Seifried 指定 CVE-2013-2011，并写明 *NOTE: this issue exists because of an incomplete fix for CVE-2013-2009*。作者 Donncha 在 1.3.2 博文里承认：*When it became clear that mfunc could be exploited still I released version 1.3.2*。

根因不只是「正则少写了一种写法」。检查插在「**这一条**评论字符串里是否同时出现开标签和闭标签」上；真正把评论变成可执行缓存的是稍后整页缓冲上的另一条正则，它跨注释匹配。下面按请求走进去。

---

## 这块功能本来在干什么

WP Super Cache 的「动态内容」允许主题在页面里写：

```html
<!--mfunc echo date('Y'); --><!--/mfunc-->
```

生成缓存时，`wp-cache-phase2.php` 把中间那段变成 `<?php echo date('Y') ;?>` 写进缓存文件，下次直接 include。WordPress 的 kses 默认**保留** HTML 注释，所以未登录访客的评论里如果带上同样的标签，也会进页面缓冲，再被同一套转换烤进缓存。一次典型路径：

```http
POST /wp-comments-post.php
comment=<!--mfunc echo PHP_VERSION; -->x<!--/mfunc-->
```

`preprocess_comment` / `comment_text` 会先跑插件挂上的过滤器，然后评论出现在文章页，缓存生成器扫整页。设计意图：访客评论里不能带 mfunc；只有站点自己启用的动态片段才能进缓存 PHP。成功穿越之后的效果是：**缓存文件里出现 `<?php … ?>`，include 时读出 `/flag/pcb_flag.txt`。**

数据流：

```text
访客评论（一条或多条）
    → preprocess_comment / comment_text
         no_mfunc_in_comments($text)          ← V1 谓词：同一 $text 里开闭成对
    → 文章页 HTML（多条评论拼进同一 buffer）
    → wp_cache_get_ob / phase2
         preg_replace('|<!--mfunc (.*?)-->(.*?)<!--/mfunc-->|is',
                      "<?php $1 ;?>", $buffer)  ← 真正写 PHP，跨注释
    → 磁盘上的 cache PHP
    → 下次请求 include → 金丝雀进响应
```

评论可以未登录（站点若允许）。不需要后台。mfunc 默认在老版本是开的；1.3.2 才加「设置页关掉动态缓存」的第二道门。

---

## 原始漏洞：评论里的 mfunc 直接进缓存（CVE-2013-2009，1.2）

1.2 的 `wp-cache.php` **没有** `no_mfunc_in_comments`。oss-security 2013-04-24 写测试评论（当时用伪标签避开邮件过滤器）等价于：

```text
<!--mfunc echo PHP_VERSION; --><!--/mfunc-->
```

Sucuri / kisscsaby 公开后，1.3 加上过滤器。1.2 上 phase2 已经会做：

```php
$store = preg_replace('|<!--mfunc (.*?)-->(.*?)<!--/mfunc-->|is',
    "<!--mfunc-->\n<?php $1 ;?>\n<!--/mfunc-->", $buffer);
```

本 case seed 是**单条评论**里放完整一对：

```text
<!--mfunc echo @file_get_contents('/flag/pcb_flag.txt'); -->x<!--/mfunc-->
```

V0 没有过滤器，整段进缓冲，phase2 烤成 PHP，include 读出金丝雀。这就是 v0 + `--seed` 观察到 `PCBFLAG_...`。

---

## 维护者改了什么（CVE-2013-2009 修复，1.3.1）

1.3 / 1.3.1 在 `wp-cache.php` 末尾挂上四条 filter，核心是 `no_mfunc_in_comments`。1.3.1 的替换要求**开标签和闭标签出现在同一次匹配里**：

```php
// wp-cache.php :: no_mfunc_in_comments  (WP Super Cache 1.3.1)
add_filter( 'preprocess_comment','no_mfunc_in_comments' );
add_filter( 'comment_text','no_mfunc_in_comments' );
add_filter( 'comment_excerpt','no_mfunc_in_comments' );
add_filter( 'comment_text_rss','no_mfunc_in_comments' );

function no_mfunc_in_comments( $comment_data ) {
    if ( is_array( $comment_data ) )
        $text = $comment_data[ 'comment_content' ];
    else
        $text = $comment_data;

    if ( preg_match( '/<!--\s*mclude|<!--\s*mfunc|<!--\s*dynamic-cached-content/i', $text )) {
        $text = preg_replace(
            '#(<!--\s*(mclude|mfunc|dynamic-cached-content).*<!-+\s*/\s*(mfunc|mclude|dynamic-cached-content)\s*-+>)#ism',
            '<!-- unsafe comment zapped -->',
            $text
        );
        ...
    }
    return $comment_data;
}
```

`preg_match` 只要看到开标签就进分支；真正删除却要求 `.` 从开标签一路吃到 `<!--/mfunc-->`（或 mclude / dynamic-cached-content）。`#ism` 让 `.` 跨行，但**跨不了「这是另一条评论、另一次函数调用」**。

补丁默认了两件事：

1. 危险写法长得像「同一条评论字符串里开闭成对」。
2. 拆开之后，phase2 不会再把散落在整页里的开闭标签拼回去。

第二点不成立。phase2 的 sink 正则看的是**整页 buffer**，不是单条评论。

对 seed 这种单条成对：开闭都在同一个 `$text` 里，整段被换成 `<!-- unsafe comment zapped -->`，phase2 看不到 mfunc。这就是 v1 + `--seed` 退出码 10。

---

## 检查之后谁真正写出 PHP

`no_mfunc_in_comments` 返回之后，评论按普通 HTML 注释进主题。缓存生成时 `wp-cache-phase2.php`（1.3.1）在缓冲里搜动态标记，**没有** `wp_cache_mfunc_enabled` 这道门：

```php
// wp-cache-phase2.php  (WP Super Cache 1.3.1)
if ( preg_match( '/<!--mclude|<!--mfunc|<!--dynamic-cached-content-->/', $buffer ) ) {
    $store = preg_replace('|<!--mclude (.*?)-->(.*?)<!--/mclude-->|is',
        "<!--mclude-->\n<?php include_once('" . ABSPATH . "$1'); ?>\n<!--/mclude-->", $buffer);
    $store = preg_replace('|<!--mfunc (.*?)-->(.*?)<!--/mfunc-->|is',
        "<!--mfunc-->\n<?php $1 ;?>\n<!--/mfunc-->", $store);
    ...
}
```

过滤器刚看过的是「这一条 `$comment_data`」；`preg_replace` 看到的是整页里先后出现的 `<!--mfunc …-->` 和 `<!--/mfunc-->`。`.*?` 跨过中间任意 HTML，包括另一条评论的边界。中间没有第二次「必须来自同一条评论」的谓词。

写进磁盘的 `$store` 是 PHP。下次命中缓存就是 `include` 这份文件。金丝雀出现在响应里，依据是这次转换，而不是「评论里碰巧有一段看起来像 PHP 的文本」。

---

## 仓库里已经有更强的检查，拆开的标签没用

同一份 1.3.1 里，`preg_match` 已经能单独认出开标签：`/<!--\s*mfunc/i`。谁用「只看开标签就删」：

| 层 | 只看到开标签就处理？ |
|---|---|
| `no_mfunc_in_comments` 的 `preg_match` | 是，用来决定进不进分支 |
| 同一函数的 `preg_replace` | **否**，还要匹配到闭标签 |
| phase2 的 mfunc → `<?php` | **否**，也要开闭成对，但是在整页上 |
| 关掉动态缓存、根本不转换 | **否**，1.3.2 才加 `$wp_cache_mfunc_enabled` |

不是仓库里看不见开标签，是 **删除谓词比探测谓词更窄**。V2 把 replace 改成只吃开标签，等于把已经存在的 `preg_match` 语义用到删除上。phase2 在 1.3.2 还加了「设置页禁用则不转换」——那是第二条更强的门，1.3.1 也没有。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「单条评论成对」和「整页开闭」落到具体字符串：

- V1 过滤器：一条 `$text` 里同时有 `<!--mfunc` … `<!--/mfunc-->`
- phase2：整页里 `<!--mfunc (.*?)-->(.*?)<!--/mfunc-->`

只要把开闭拆进**两次** `no_mfunc_in_comments` 调用，第一道门各看各的，第二道门在拼页之后仍能配成一对。

```text
seed（单条）:
  comment = "<!--mfunc PAYLOAD-->x<!--/mfunc-->"
  → 同一 $text 命中 replace → zapped
  → phase2 无 mfunc

residual（两条评论）:
  comment1 = "<!--mfunc PAYLOAD-->"
  comment2 = "<!--/mfunc-->"
  → 每条都有开或闭，但没有「开…闭」同串
  → V1 replace 不删
  → 页面 buffer = …<!--mfunc PAYLOAD-->…<!--/mfunc-->…
  → phase2 配成 <?php PAYLOAD ;?>
```

Reddit / oss-security 指出 1.3.1 仍能打；1.3.2 changelog 写 *Any mfunc/mclude/dynamic-cached-content tags in comments are now removed*——从「成对才删」变成「见到开标签就删」。本 case 把 PAYLOAD 收成读金丝雀，观察的是同一扇 phase2 门有没有打开。

---

## 残余仍然走同一条评论→缓存 PHP 路径（CVE-2013-2011）

没有换插件、没有换缓存生成器、没有换观察通道。还是 `comment_text` 之后的那次 phase2 转换。换成两条评论：

```text
POST 评论 1: <!--mfunc echo @file_get_contents('/flag/pcb_flag.txt'); -->
POST 评论 2: <!--/mfunc-->
```

（或一次请求里提交两段、渲染时相邻。）每条单独经过 V1 过滤器；拼进文章页后，phase2 的 `|<!--mfunc (.*?)-->(.*?)<!--/mfunc-->|is` 跨过中间的 `-->` 和 HTML，把第一条里的 payload 写成 `<?php`。include 缓存文件，金丝雀进 body。

本 case residual 和「拆开 mfunc」同一构造。认证意图：v1 + `--residual` 观察到 `PCBFLAG_...`。

seed 被挡住只说明「单条成对注释会被 zap」，不说明「不能再让 phase2 在整页上拼出一对 mfunc」。

平台 residual 走的就是这条 mfunc → 缓存 PHP sink，和源码链同一 sink。不是另一条无关的缓存写入。注意：平台为了不跑任意代码，会把 sink 发出的 PHP 收成固定读 flag；观察的仍是「过滤器有没有让 mfunc 活到 phase2」。

---

## 后来又补了什么（CVE-2013-2011，1.3.2）

1.3.2 把 replace 改成只吃开标签，不再要求闭标签在同一串里：

```php
// wp-cache.php  (WP Super Cache 1.3.2)
$text = preg_replace(
    '#(<!--\s*(mclude|mfunc|dynamic-cached-content))#ism',
    '<!-- unsafe comment zapped -->',
    $text
);
```

对残余输入：第一条评论里的 `<!--mfunc` 被 zap，页面上不再有开标签，phase2 配不成对。

同一版本 phase2 还加了默认关闭动态缓存：

```php
if ( !isset( $wp_cache_mfunc_enabled ) || $wp_cache_mfunc_enabled == 0 ) {
    $buffer = preg_replace(
        '#(<!--\s*(mclude|mfunc|dynamic-cached-content).*<!-+\s*/\s*(mfunc|mclude|dynamic-cached-content)\s*-+>)#ism',
        '', $buffer );
    $store = $buffer;
} else {
    // 原来的 mfunc → <?php
}
```

即便有人再绕过评论过滤器，默认配置下 phase2 也不再把标签烤成 PHP。公开建议升级到 1.3.2。Donncha 甚至考虑彻底删掉 mfunc。本 benchmark 的 v2 关闭这一条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是单条评论字符串。真正逃出「注释」语义的是 phase2 对整页的 `preg_replace`。V2 在评论层改成见开即删，并在 phase2 加了禁用门——终于碰到消费层。

**不是没有更好的谓词。**  
`preg_match` 已经只看开标签。从 V1 的 diff 只能看到「加了一条要成对的 replace」；要判断是否闭合，必须看到过滤器的调用粒度（每条评论一次）和 sink 的匹配粒度（整页一次）。

**同一 phase2、同一 `$buffer`，只换了标签是不是拆开。**  
NVD 原话就是 incomplete fix。单条被挡住，不等于整页拼不回一对。

**HTML 注释边界和 PHP 缓存不是一层。**  
kses 留下 `<!-- … -->`。过滤器按评论切开；sink 按字节流切开。只消毒一种切法，门是开的。

**金丝雀在 docroot 外是有意的。**  
评论正文里没有 flag。能在「被 include 的缓存输出」里读到它，说明 phase2 把 mfunc 写成了 PHP——也就是 V1 那次成对 replace 没删掉开标签。

---

## 版本、入口、参考

| | 版本 | `no_mfunc_in_comments` | phase2 | 单条成对 seed | 拆成两条 residual |
|---|---|---|---|---|---|
| V0 | 1.2 | 无 | 无条件 mfunc→PHP | 执行，flag | （不必） |
| V1 | 1.3.1 | 开闭成对才 zap | 仍无条件转换 | zap | 整页配成对，flag |
| V2 | 1.3.2 | 见开即 zap | 默认禁用转换 | 挡 | 开标签被删，挡 |

- 产品路径：`POST /wp-comments-post.php` → 文章页 → Super Cache 生成/include
- [CVE-2013-2009](https://nvd.nist.gov/vuln/detail/CVE-2013-2009)、[CVE-2013-2011](https://nvd.nist.gov/vuln/detail/CVE-2013-2011)
- [oss-security 2013-04-24](https://www.openwall.com/lists/oss-security/2013/04/24/8)、[oss-security 2013-04-25](https://www.openwall.com/lists/oss-security/2013/04/25/4)
- [Donncha 1.3.2 公告](https://odd.blog/2013/04/24/wp-super-cache-1-3-2/)
- 源码：[`1.3.1` `wp-cache.php`](https://github.com/wp-plugins/wp-super-cache/blob/1.3.1/wp-cache.php)、[`wp-cache-phase2.php`](https://github.com/wp-plugins/wp-super-cache/blob/1.3.1/wp-cache-phase2.php)；V2 开标签正则见 [`1.3.2` `wp-cache.php`](https://github.com/wp-plugins/wp-super-cache/blob/1.3.2/wp-cache.php)
