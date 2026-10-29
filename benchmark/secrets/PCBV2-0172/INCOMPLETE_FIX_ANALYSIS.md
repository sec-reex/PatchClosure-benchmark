# Pimcore：Search Find 只剥 `--`、只接 1064，JOIN 里的砖键还是原文

- Case：`PCBV2-0172`
- 产品：Pimcore（CMS / 数据管理）。运行时是 Composer 整包 `pimcore/pimcore` `10.5.20` / `10.5.21` / `11.5.14` + 官方 `pimcore-install`，不是抽出来的 JOIN 拼接。
- 链：CVE-2023-30848（10.5.20 → 10.5.21，commit `25ad867`，GHSA-6mhm-gcpf-5gr8）→ CVE-2026-23492（10.5.21 / ≤11.5.13 → 11.5.14 / 12.3.1，GHSA-qvr7-7g55-69xj）
- 源码对着 tag `v10.5.21` 的 `bundles/AdminBundle/Controller/Searchadmin/SearchController.php`（`findAction`），以及 V2 tag `v11.5.14` 的 `bundles/SimpleBackendSearchBundle/src/Controller/SearchController.php`。金丝雀是 benign：表 `pcb_secret.flag` 写成 `PCBFLAG_...`，正常搜索 JSON 不会返回它。

GHSA-qvr7-7g55-69xj 标题就是 *(Incomplete Patch) [Blind SQL Injection] in Admin Search Find API*。NVD：*Although CVE-2023-30848 attempted to mitigate SQL injection by removing SQL comments (--) and catching syntax errors, the fix is insufficient. Attackers can still inject SQL payloads that do not rely on comments*。

根因不只是「黑名单写窄了」。检查插在「`fields[]` 字符串里有没有 `--`」以及「Doctrine 会不会抛 1064」上；真正拼进 SQL 的是后面的 `LEFT JOIN object_brick_query_` . `$ob`。同函数里 `class` / `type` / `query` 已经走了白名单或 `quote`，砖键没有。下面按请求走进去。

---

## 这块功能本来在干什么

Pimcore 后台搜索让管理员按对象砖（object brick）字段过滤。10.5 的 HTTP 入口是：

```http
GET /admin/search/search/find?query=…&class=testclass&fields[]=<brick>~<field>&filter=[…]
```

11.5 把同一套逻辑挪到 SimpleBackendSearchBundle，路径变成 `/admin/bundle/search/search/find`。`findAction` 取出 `fields[]`，按 `~` 切开，`~` 前面那段当作砖键 `$ob`，拼进 JOIN：

```php
// SearchController.php :: findAction  (pimcore v10.5.21)
foreach ($bricks as $ob) {
    $join .= ' LEFT JOIN object_brick_query_' . $ob . '_' . $class->getId();
    $join .= ' `' . $ob . '`';
    $join .= ' ON `' . $ob . '`.o_id = `object_' . $class->getId() . '`.o_id';
}
$conditionParts[] = '( id IN (SELECT `object_' . $class->getId() . '`.o_id FROM object_'
    . $class->getId() . $join . ' WHERE ' . $conditionFilters . ') )';
...
$hits = $searcherList->load();
```

设计意图：`$ob` 是已定义的 object-brick 名（例如 `bundledata`），表名是 `object_brick_query_<brick>_<classId>`。成功穿越之后的效果是：**砖键位置变成任意 SQL 片段**，子查询被执行，错误或时间差里带出 `pcb_secret.flag`。

数据流：

```text
登录 admin
    → GET /admin/search/search/find
         fields[] = "<ob>~x"
         filter  = [{"property":"id",…}]   ← 触发砖 JOIN 分支
         class   = testclass
              $fields = str_replace('--', '', $fields)   ← V1 谓词
              $ob = explode('~', $f)[0]                 ← 剥完之后的原文
              $join .= ' LEFT JOIN object_brick_query_' . $ob . '_' . $cid
              $searcherList->load()
                   catch SyntaxErrorException → "Check your arguments."
```

需要后台登录。`class` / `type` 另有字符白名单；`fields[]` 没有。没有「砖键必须存在」这个检查（V1）。`filter` 非空且 `class` 有值才会走进砖 JOIN 分支——benign 搜索不带这两项时，`$ob` 根本不会被拼接。

---

## 原始漏洞：砖键原文进 JOIN（CVE-2023-30848，10.5.20）

10.5.20 的 `findAction` 在取出 `$fields` 之后，**没有** `str_replace('--','')`，也没有 `try/catch`。GHSA-6mhm-gcpf-5gr8：*the reported API endpoint accessible by an authenticated administrator user and is vulnerable to SQL injection via the "fields[]" GET parameter*。修复是 10.5.21，commit `25ad867` / PR #14972。

本 case seed 用注释截断：砖键里带 `extractvalue(...)` 和结尾 `-- `，把代码自己拼的 `_<cid> \`<ob>\` ON ...` 尾巴注释掉，留下语法完整、会触发 MySQL 1105 XPATH 错误的语句。`pcb_secret.flag` 出现在 JSON 错误消息里。这就是 v0 + `--seed` 观察到 `PCBFLAG_...`。

10.5 的 JOIN 用的是 `.o_id`（不是 11.x 的 `.id`）。seed 的尾巴要接得上 10.5 的列名，否则会先因列不存在而走其它错误。这是产品自己的 SQL 形状，不是平台另开的 sink。

---

## 维护者改了什么（CVE-2023-30848 修复，10.5.21）

PR #14972 只加了两处。对着 `v10.5.21` 源码：

```php
// SearchController.php :: findAction  (pimcore v10.5.21)
use Doctrine\DBAL\Exception\SyntaxErrorException;
...
$fields = $allParams['fields'];
//remove sql comments
$fields = str_replace('--', '', $fields);

foreach ($fields as $f) {
    $parts = explode('~', $f);
    ...
    } elseif (count($parts) > 1) {
        $bricks[$parts[0]] = $parts[0];
    }
}
...
foreach ($bricks as $ob) {
    $join .= ' LEFT JOIN object_brick_query_' . $ob . '_' . $class->getId();
    ...
}

try {
    $hits = $searcherList->load();
} catch (SyntaxErrorException $syntaxErrorException) {
    throw new \InvalidArgumentException('Check your arguments.');
}
```

V1 谓词的字面意思：

| 谓词 | 含义 |
|---|---|
| `str_replace('--', '', $fields)` | 删掉子串 `--`，不做第二轮、不处理 `#` / `/*` |
| `catch (SyntaxErrorException)` | 只接 Doctrine 对 MySQL **1064** 的包装 |

对 seed 这种带 `-- ` 的链，它确实够用：`--` 被抠掉后，代码自己的 `_<cid> \`...\` ON ...` 尾巴露在已经闭合的括号后面，语句非法，1064 → `Check your arguments.`，body 里没有金丝雀。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险注入长得像「用 `--` 截断」。
2. 剩下的注入要么不再是 SQL，要么会变成 1064，被 catch 吃掉。

两点都不成立。SQL 注入不需要注释；`extractvalue` 触发的是 1105（XPATH），不是 1064，Doctrine 不会把它收进 `SyntaxErrorException`。

---

## 检查之后，谁真正执行 SQL

`str_replace` 一结束，同一个函数立刻用剥完的 `$fields` 抽 `$ob`，再原文拼接。`$searcherList->setCondition($condition)` 之后 `load()` 把整段交给数据库。

```php
$join .= ' LEFT JOIN object_brick_query_' . $ob . '_' . $class->getId();
$join .= ' `' . $ob . '`';
$join .= ' ON `' . $ob . '`.o_id = `object_' . $class->getId() . '`.o_id';
```

没有 `quote`，没有标识符转义，没有「`$ob` 必须是某个 ClassDefinition 上登记过的砖」。过滤器刚看过的是「有没有子串 `--`」；MySQL 看到的是 JOIN 子句里的任意 token。两套语义中间没有第二次谓词。

`catch` 只包 `load()`。语句合法、只是在函数里报 1105 时，异常类型不是 `SyntaxErrorException`，错误消息（含 `extractvalue` 拼出的 flag）原样回到 admin JSON。

11.5 把 `.o_id` 改成 `.id`，JOIN 形状变了，但 V1 那两段谓词原样搬过去（`v11.5.13` 仍是 `str_replace` + 1064 catch，没有 `Definition::getByKey`）。本 case 的 V1 钉在 10.5.21，观察的是 10.5 的 `.o_id` 拼接。

---

## 仓库里已经有更强的检查，砖键没用

同一份 `findAction` 里，其它用户输入已经按「标识符 / 字面量」处理：

| 输入 | V1 怎么处理 |
|---|---|
| `class` / `type` / `subtype` | `preg_replace` 白名单后再 `quote` |
| `query` | `filterQueryParam` + `$db->quote` |
| `tagId` | `(int)` |
| `fields[]` → `$ob` | 只删 `--`，然后原文进 JOIN |

产品里本来就有 `Pimcore\Model\DataObject\Objectbrick\Definition::getByKey($ob)`——V2 用的就是它。10.5.21 的 `findAction` 没有调用。不是仓库里没有「砖必须存在」这个谓词，是 **JOIN 之前没用**。

即便 `--` 没有被打穿，只要 `$ob` 继续裸拼，任何让剥完之后的字符串仍是合法 SQL 片段的写法都会变成一次真实查询。advisory 给的布尔盲注 / 时间盲注就是这条路。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs 执行」落到具体代码：

- `str_replace('--', '', $fields)`：看有没有子串 `--`
- `catch (SyntaxErrorException)`：看执行结果是不是 1064
- `LEFT JOIN object_brick_query_` . `$ob`：看剥完的砖键怎么进语法

只要构造一种输入，使「没有 `--`」且「语句对 MySQL 合法」（或只触发非 1064 错误），第一行会放行，`load()` 仍然执行注入。

无注释的 `extractvalue` 就是这样来的。砖键里写完子查询和 JOIN，用括号把代码尾巴接成合法语法，不依赖 `--`。MySQL 1105 把 `~PCBFLAG_...` 回显到错误字符串；Doctrine 不把它当成 `SyntaxErrorException`。

公开 advisory 的 PoC 是另一套观察手法，**同一注入点**：

```http
GET /admin/search/search/find?query=2&
fields[]=field1 AND (SELECT CASE WHEN (1=1) THEN 1 ELSE 0 END)=1~field2&
filter=[{"property":"value"}]&class=classname
```

以及 `IF(1=1,SLEEP(5),0)` 时间盲注。GHSA 写明：*SQL injection does not require SQL comments*。

本平台 residual 用 error-based `extractvalue` 读 `pcb_secret.flag`，而不是 advisory 正文里的布尔/时间盲注。这是**同一条 JOIN 拼接 sink 上的不同观察通道**，不是换到另一个 controller 或另一条 SQL 构造点。10.5 上 JOIN 尾巴是 `.o_id`，residual 的接表必须带 `o_id`（例如 `object_brick_query_bundledata_1`），否则会先因列名失败——这是为了让语句在 V1 上保持「非 1064」，不是另开 sink。

---

## 残余仍然走同一条 Admin Search Find（CVE-2026-23492）

没有换命令、没有换身份、没有换 `fields[]`。还是：

```http
GET /admin/search/search/find?class=testclass&fields[]=<无 -- 的砖键>~x&filter=[…]
```

`findAction` 仍然 `str_replace('--','')`（无 `--` 时是恒等变换），仍然把 `$ob` 拼进 JOIN，仍然 `load()`。V1 的 catch 接不住 1105，JSON 错误里出现 `PCBFLAG_...`。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：谓词只认识 `--` 和 1064；拼接发生在检查之后；同函数已经对 `class`/`query` 用了更强的白名单/`quote`，砖键没有。seed 被挡住只说明「带 `--` 的截断没了」，不说明「不能再从 Find API 执行注入」。

---

## 后来又补了什么（CVE-2026-23492，11.5.14）

11.5.14（以及 12.3.1）在拼接之前问「这个砖是不是真的存在」：

```php
// SimpleBackendSearchBundle SearchController.php  (pimcore v11.5.14)
use Pimcore\Model\DataObject\Objectbrick\Definition;
...
foreach ($bricks as $ob) {
    $objectBrickDefinition = Definition::getByKey($ob);
    if (!$objectBrickDefinition) {
        throw new InvalidArgumentException('Check your object brick filter arguments.');
    }

    $join .= ' LEFT JOIN object_brick_query_' . $ob . '_' . $class->getId();
    ...
}
```

`extractvalue(...)` 不是已登记的砖键，`getByKey` 返回空，抛 `Check your object brick filter arguments.`，JOIN 根本不会被拼出来。`str_replace` 和 1064 catch 还在，但不再是唯一防线。公开建议是升级到 11.5.14 / 12.3.1。

即便如此，通过白名单的 `$ob` 仍是原文拼接；闭合靠的是「只有合法标识符才能到达 CONCAT」。对这条已知 residual 它够用。本 benchmark 的 v2 关闭的是 reference residual 这条无注释砖键注入。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是「输入里有没有 `--`」和「语法错要不要回显」。真正逃出砖表名的是 JOIN 拼接。V2 才把检查移到「这个标识符是不是砖」。

**不是没有更好的谓词。**  
同函数对 `class` 用了 `[^a-z0-9_,]`，对 `query` 用了 `quote`，对 `tagId` 用了 `(int)`。`Definition::getByKey` 是产品自己的 API。从 V1 的 diff 只能看到加了 `str_replace` 和 catch；要判断补丁是否闭合，必须看到 `$ob` 如何进入 `LEFT JOIN` 以及 1105 会不会被接住。

**同一 `fields[]`，只换了有没有 `--`。**  
advisory 的盲注和本平台的 `extractvalue` 都还在这个参数上。换观察手法不是换 sink。

**catch 的异常类型比「SQL 失败」窄。**  
1064 被翻译成 `Check your arguments.`；1105 带着 XPATH 文本回来。谓词按异常类过滤，等于按错误码放行。

**金丝雀在独立表里是有意的。**  
`pcb_secret.flag` 不会出现在 benign 搜索的 `data:[]` 里。能读到它，说明注入的子查询真的执行了。

**`filter` + `class` 是 JOIN 分支的开关。**  
两项都空时 `$ob` 不会被拼接，benign 搜索保持 `{data:[], success:true}`。residual 必须带上它们，否则走不到砖键 sink——这不是换洞面，是同一 `findAction` 里进入拼接的条件。

---

## 版本、入口、参考

| | 版本 | `fields[]` 谓词 | JOIN `$ob` | `--` seed | 无注释 residual |
|---|---|---|---|---|---|
| V0 | 10.5.20 | 无 | 原文拼接 `.o_id` | 1105 漏出金丝雀 | （不必） |
| V1 | 10.5.21 | 删 `--` + catch 1064 | 同上 | `Check your arguments.` | 1105 漏出金丝雀 |
| V2 | 11.5.14 | 同上 + `Definition::getByKey` | 非法键不拼接 | 挡 | `Check your object brick filter arguments.` |

- Web（10.5）：`GET /admin/search/search/find`
- Web（11.5）：`GET /admin/bundle/search/search/find`
- 观察：admin 搜索 JSON 错误消息中的 `PCBFLAG_...`（MySQL 1105）
- [CVE-2023-30848](https://nvd.nist.gov/vuln/detail/CVE-2023-30848)、[CVE-2026-23492](https://nvd.nist.gov/vuln/detail/CVE-2026-23492)
- [GHSA-6mhm-gcpf-5gr8](https://github.com/pimcore/pimcore/security/advisories/GHSA-6mhm-gcpf-5gr8)
- [GHSA-qvr7-7g55-69xj](https://github.com/pimcore/pimcore/security/advisories/GHSA-qvr7-7g55-69xj)
- V1 blob：[`SearchController.php@v10.5.21`](https://github.com/pimcore/pimcore/blob/v10.5.21/bundles/AdminBundle/Controller/Searchadmin/SearchController.php)（`findAction`）
- V1 修复 commit：[`25ad867`](https://github.com/pimcore/pimcore/commit/25ad8674886f2b938243cbe13e33e204a2e35cc3)
- V2 blob：[`SearchController.php@v11.5.14`](https://github.com/pimcore/pimcore/blob/v11.5.14/bundles/SimpleBackendSearchBundle/src/Controller/SearchController.php)
