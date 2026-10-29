# GLPI：sort 的 int-cast 挂在 manageParams，map.php 不经过它

- Case：`PCBV2-0119`
- 产品：GLPI（IT 资产 / 服务台，PHP）
- 链：CVE-2024-27096 / GHSA-2x8m-vrcm-2jqv（10.0.12 → 10.0.13，commit `61a0c230`；本 case V1 = 10.0.14，`Search.php` 与 10.0.13 字节级相同）→ CVE-2024-31456 / GHSA-gcj4-2cp3-6h5j（10.0.14 → 10.0.15，commit `730c3db2`）
- 源码对着 GitHub tag `10.0.14` 的 `src/Search.php`（`manageParams`、`prepareDatasForSearch`、`addSelect`）和 `ajax/map.php`，以及 tag `10.0.15` 的 `cleanParams`。运行时是官方 release tarball + php:7.4-apache，不是抽出来的函数。Borelenzo 的 writeup 原文写明 *CVE-2024-27096 was insufficiently patched ... only finding a path in the code that called the vulnerable function without passing through the patched routine*。

2024 年 3 月，GLPI 在 `Search::manageParams` 末尾给 `sort` 做 `(int)` 转换。这挡住了 seed 那种经 `/ajax/search.php` 进来的 SELECT 别名注入。两个月后同一条 `Search::addSelect` 上，`/ajax/map.php` 直接调用 `prepareDatasForSearch` / `constructSQL` / `constructData`，不经过 `manageParams`。`prepareDatasForSearch` 只对**标量** `sort` 做 int-cast，数组元素原样拼进 `` `ITEM_<type>_<ID>` ``。NVD 把这件事记成 CVE-2024-31456。

根因不只是「少写了一个入口」。检查插在「搜索表单那条常规路径」上；真正拼 SQL 的是 `addSelect` 的别名；同文件里 10.0.15 才抽出的 `cleanParams` 当时只内联在 `manageParams` 尾部。下面按请求走进去、10.0.13 改了哪几行、cast 之后谁消费那个值、更宽的挂载点有没有接上，把这几层写完。

---

## 这块功能本来在干什么

GLPI 的搜索引擎按用户给的列 id 拼 `SELECT` / `ORDER BY`。常规 UI 走 `/ajax/search.php?action=display_results`，先 `manageParams` 再 `getDatas`。地图视图走 `/ajax/map.php`，自己调查询构造。

一次典型地图请求：

```http
POST /ajax/map.php
itemtype=User&params[sort][]=1
```

`addSelect` 把 search-option id 嵌进反引号别名：

```php
// src/Search.php :: addSelect  (tag 10.0.14, 约 L2979–2992)
public static function addSelect($itemtype, $ID, $meta = false, $meta_type = '')
{
    ...
    $NAME = "ITEM_{$itemtype}_{$ID}";
```

设计意图：`sort` 是整数列 id。成功穿越之后的效果是：**应用认为 id 已经是 int，SQL 里却出现了关掉反引号之后的表达式**——本 case 用 `extractvalue` 把 `pcb_canary.secret` 反射进 DEBUG 错误页。

数据流：

```text
POST /ajax/search.php                POST /ajax/map.php
    → Search::manageParams              → 不调用 manageParams
         V1：$int_params=['sort']        $params 原样
         数组元素 (int)                  → Search::prepareDatasForSearch
    → getDatas → prepareDatasForSearch       标量 sort 才 (int)
         constructSQL / addSelect            数组 sort 原样进 $p['sort']
         `ITEM_User_<ID>`                    constructSQL / addSelect
```

需要已登录会话，且 PHP 7.4（advisory 写明的前置：7.* 的 `8 == "8-..."` 松比较；8.0+ 这条链自己断）。本 case 的 admin 开着 DEBUG，SQL 错误进响应。

---

## 原始漏洞：sort 原样进别名（CVE-2024-27096，10.0.12）

10.0.12 的 `manageParams` 不把 `sort` 转成 int。PHP 7.4 上，搜索选项的松比较会让 `"1`,extractvalue..."` 通过「这是列 1」的检查，反引号被关掉，后面的 SQL 执行。Borelenzo 的第一篇 writeup 把 `EXTRACTVALUE` 错误外带写清楚了。NVD CVE-2024-27096：*An authenticated user can exploit a SQL injection vulnerability in the search engine*，修复版本 10.0.13。

本 case 的 seed（经 search.php）：

```text
sort[] = 1`,extractvalue(rand(),concat(0x7e,(SELECT secret FROM pcb_canary LIMIT 1)))-- -
```

10.0.12 拼出 `` `ITEM_User_1`,extractvalue(...)-- -` ``，DEBUG 页出现 `XPATH syntax error: '~PCB...'`。这就是 v0 + `--seed` 退出码 0。

`/ajax/map.php` 当时同样不经过任何 int-cast。当时没人拿地图入口当「搜索 sort 注入」问题的一部分。

---

## 维护者改了什么（CVE-2024-27096 修复，10.0.13 / 本 case V1 = 10.0.14）

10.0.13 在 `manageParams` **返回之前**加了一段。10.0.14 上原样还在：

```php
// src/Search.php :: manageParams  (tag 10.0.14, 约 L7047–7063)
$int_params = [
    'sort'
];

foreach ($params as $key => &$val) {
    if (in_array($key, $int_params)) {
        if (is_array($val)) {
            foreach ($val as &$subval) {
                $subval = (int)$subval;
            }
        } else {
            $val = (int)$val;
        }
    }
}

return $params;
```

`/ajax/search.php` 走 `manageParams`，所以 seed 的数组元素变成整数 `1`，别名变回 `` `ITEM_User_1` ``，错误页没有金丝雀。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 所有会把用户 `sort` 送进 `addSelect` 的路径，都先经过 `manageParams`。
2. `prepareDatasForSearch` 自己不会再接受未 cast 的数组 `sort`。

两点都不成立。更关键的是：这段 cast 之后，`addSelect` 仍然把 `$ID` **当字符串拼进 SQL**，没有第二次「必须是纯整数」的谓词。

---

## cast 之后，谁真正消费那个值

地图入口把用户参数直接交给查询构造：

```php
// ajax/map.php  (tag 10.0.14)
$itemtype = $_POST['itemtype'];
$params   = $_POST['params'];

$data = Search::prepareDatasForSearch($itemtype, $params);
Search::constructSQL($data);
Search::constructData($data);
```

`prepareDatasForSearch` 对 `sort` 的处理是：

```php
// src/Search.php :: prepareDatasForSearch  (tag 10.0.14, 约 L141–150)
case 'sort':
    if (!is_array($val)) {
        // Backward compatibility with GLPI < 10.0 links
        $val = (int) $val;
        if ($val >= 0) {
            $p[$key] = [$val];
        }
        break;
    }
    $p[$key] = $val;   // 数组：原样
    break;
```

标量会被 `(int)`；`params[sort][]=...` 是数组，整段 payload 留下。随后 `$p['sort']` 进 `toview`，再进 `addSelect` 的 `$ID`，变成 `` `ITEM_User_1`,extractvalue(...)-- -` ``。

过滤器刚看过的是「走了 manageParams 的那份 `$params`」；地图看到的是另一份、没走过那段循环的 `$params`。两套入口中间没有第二次谓词。

`extractvalue` 把结果截到约 32 字符，所以本 case 的 flag 故意缩短。DEBUG 模式把 `SQL Error "1105": XPATH syntax error: '~<flag>'` 写进 body。

---

## 仓库里已经有更强的检查，地图路径没用

V1 的「数组元素也 `(int)`」已经写在 `manageParams` 里，并且已经证明能挡住 seed。谁调用它（10.0.14）：

| 入口 | 调用 `manageParams`？ | `prepareDatasForSearch` 对数组 sort |
|---|---|---|
| `/ajax/search.php` → `getDatas` | 是 | 收到的已经是 int |
| `/ajax/map.php` | **否** | 原样拷贝 |

V1 等于把完整的数组 int-cast 只挂在常规搜索入口。不是仓库里没有更好的谓词，是 **地图没用**。

10.0.15 把同一段循环抽成 `cleanParams`，并在 `prepareDatasForSearch` **和** `manageParams` 都调用。那才是「谁拼 SQL 谁先 cast」。V1 还没做这一步。

即便数组 payload 没有把 `manageParams` 打穿，只要还有一条路把未 cast 的 `$ID` 送进 `addSelect`，同一条 SELECT 别名注入就会再响一次。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「入口守卫 vs SQL 拼装」落到具体代码：

- `manageParams` 的 `(int)$subval`：看常规搜索的 `sort` 元素
- `addSelect` 的 `"ITEM_{$itemtype}_{$ID}"`：看别名里是不是还能关反引号

只要走一条**不经过** `manageParams`、且仍把数组 `sort` 送进 `addSelect` 的路，第一行不会开火，第二行仍然注入。

`params[sort][]` + `/ajax/map.php` 就是这样来的：

```text
seed:      POST /ajax/search.php  sort[]=<payload>  → manageParams 收成 1 → 挡
residual:  POST /ajax/map.php     params[sort][]=<payload>
           → prepareDatasForSearch 原样
           → addSelect ID = 1`,extractvalue(...)-- -
           → DEBUG 页 '~PCB...'
```

Borelenzo 第二篇 writeup 的 PoC 就是这个 POST，只是 `extractvalue` 读 `database()`；本 case 改成读 `pcb_canary.secret`。

---

## 残余仍然走同一条 addSelect 别名（CVE-2024-31456）

没有换 payload、没有换 sink。还是：

```text
1`,extractvalue(rand(),concat(0x7e,(SELECT secret FROM pcb_canary LIMIT 1)))-- -
```

只是入口从 `search.php` 换成 `map.php`。V1 的 `manageParams` 照样存在，照样碰不到。认证：v1 + `--residual` 退出码 0，body 中观察到 flag。

所以残余不是新洞面，而是同一 sink 上换了调用方。seed 被挡住只说明「常规搜索的 sort 被 cast 了」，不说明「所有送到 addSelect 的 sort 都是 int」。

平台 verify 的 residual 与 incomplete-fix 链的 sink 一致：都是 `addSelect` 的 SELECT 别名，只是 HTTP 入口不同。

---

## 后来又补了什么（CVE-2024-31456，10.0.15）

10.0.15 抽出 `cleanParams`（循环与 V1 `manageParams` 尾部相同），并在 `prepareDatasForSearch` 里、拼 `$data['search']` 之前调用：

```php
// src/Search.php  (tag 10.0.15, 约 L175、L7051)
$p = self::cleanParams($p);

public static function cleanParams(array $params): array
{
    $int_params = ['sort'];
    foreach ($params as $key => &$val) {
        if (in_array($key, $int_params)) {
            if (is_array($val)) {
                foreach ($val as &$subval) {
                    $subval = (int)$subval;
                }
            } else {
                $val = (int)$val;
            }
        }
    }
    return $params;
}
```

`manageParams` 改为 `return self::cleanParams($params)`。地图和常规搜索都经过同一段。对残余输入，数组元素变成 `1`，别名关不上。公开建议是升级到 10.0.15（或 PHP ≥ 8.0，松比较不再帮这一下）。

即便如此，这仍然是「在拼 SQL 之前把 sort 收成 int」，`addSelect` 还是字符串拼接。对这条已知链它够用。本 benchmark 的 v2 只关闭这一条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是 `manageParams` 的出口。真正拼出可注入别名的是 `addSelect`。V2 才把 cast 移到所有调用 `prepareDatasForSearch` 的路径上。

**不是没有更好的谓词。**  
「数组元素也 `(int)`」已经写在 V1 里。它已经用在 search.php 上。地图穿越走的是没调用 `manageParams` 的 `map.php`。从 V1 的 diff 只能看到 `manageParams` 多了一段循环；要判断补丁是否闭合，必须 grep 谁调用 `prepareDatasForSearch` / `constructSQL`。

**同一 `$ID`、同一反引号，只换了 HTTP 入口。**  
seed 和 residual 的 payload 字节级相同。writeup 的原话就是 *only finding a path ... without passing through the patched routine*。

**PHP 7.4 是前置，不是根因。**  
8.0 上松比较变严，这条利用会难很多；但「未 cast 的字符串进 SQL 别名」在 10.0.14 的地图路径上仍然成立。

**金丝雀在受限表里是有意的。**  
`pcb_canary.secret` 不是 User 搜索会选出的列。能在错误页看到它，说明注入读到了搜索结果之外的表。

---

## 版本、入口、参考

| | tag | `manageParams` | `prepareDatasForSearch` | search.php seed | map.php residual |
|---|---|---|---|---|---|
| V0 | 10.0.12 | 无 sort int-cast | 数组 sort 原样 | 错误页有 flag | （也可） |
| V1 | 10.0.14 | 数组元素 `(int)` | 只 cast 标量 | 挡 | 数组原样，错误页有 flag |
| V2 | 10.0.15 | `return cleanParams` | 先 `cleanParams` | 挡 | 数组元素 `(int)`，挡 |

- Web seed：`POST /ajax/search.php`
- Web residual：`POST /ajax/map.php`（`params[sort][]=...`）
- 认证（本平台）：v0 seed 观察到 flag；v1 seed 未观察到；v1 residual 观察到
- [CVE-2024-27096](https://nvd.nist.gov/vuln/detail/CVE-2024-27096)、[CVE-2024-31456](https://nvd.nist.gov/vuln/detail/CVE-2024-31456)
- [GHSA-2x8m-vrcm-2jqv](https://github.com/glpi-project/glpi/security/advisories/GHSA-2x8m-vrcm-2jqv)
- [GHSA-gcj4-2cp3-6h5j](https://github.com/glpi-project/glpi/security/advisories/GHSA-gcj4-2cp3-6h5j)
- [Borelenzo：CVE-2024-27096](https://borelenzo.github.io/stuff/2024/03/24/exploit-CVE-2024-27096.html)
- [Borelenzo：CVE-2024-31456](https://borelenzo.github.io/stuff/2024/05/09/exploit-CVE-2024-29889-31456.html)
- V1 commit：[`61a0c230`](https://github.com/glpi-project/glpi/commit/61a0c2302b4f633f5065358adc36058e1abc37f9)；V2 commit：[`730c3db2`](https://github.com/glpi-project/glpi/commit/730c3db29a1edc32f9b9d1e2a940e90a0211ab26)
