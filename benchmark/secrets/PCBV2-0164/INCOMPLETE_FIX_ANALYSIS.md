# Parse Server：literalizeRegexPart 只加倍「前面不是引号」的 `'`，连续引号仍能破出 ~ 字面量

- Case：`PCBV2-0164`
- 产品：Parse Server（npm `parse-server`）。本 case 跑整包 Parse + PostgreSQL，入口是官方 REST：`GET /parse/classes/<Class>?where=`。
- 链：CVE-2024-27298（GHSA-6927-3vr9-fxf2，6.4.0 → 6.5.0，给 `replace` 加 `/g`）→ CVE-2024-39309（GHSA-c2hr-cqg6-8j6r / ZDI-CAN-23894，6.5.0 → 6.5.7，改成把奇数长度的引号串补成偶数）。
- 源码对着 tag `6.5.0` 的 `src/Adapters/Storage/Postgres/PostgresStorageAdapter.js`（`literalizeRegexPart`、`$regex` 分支的 `:raw` 拼接）。V0 是 `6.4.0`。V2 是 `6.5.7`（commit `f332d545`）。

2024 年 3 月，维护者发现 `$regex` 进 PostgreSQL `~` 操作符时，单引号只被替换一次，第二条引号能破出字符串、把 `_rperm` ACL 注释掉。修丁给 `.replace(/([^'])'/ , …)` 加了 `/g`。同年 6 月 ZDI-CAN-23894 指出：**`([^'])'` 仍然加倍不了「前面已经是引号」的那一个**，`a''` 这种偶数引号串在 `/g` 之后仍是奇数个引号。NVD 把后一件事记成 CVE-2024-39309。

根因不只是「忘了写 g 标志」。检查插在「把 `'` 变成 `''`」上；真正进 PostgreSQL 的是后面那条 **未绑定参数的** `'${regex}:raw'`。同一文件里 `createLiteralRegex` 已经按字符把 `'` 写成 `''`，却只用于 `\Q…\E` 分支。下面按 REST where 走进去。

---

## 这块功能本来在干什么

Parse 把 Mongo 风格的 JSON where 编译成 SQL。`$regex` 对应 PostgreSQL 的正则匹配。一次典型未登录查询（本 case 的 `Vault` 类有一行 ACL 受限的金丝雀）：

```http
GET /parse/classes/Vault?where={"name":{"$regex":"a'b' OR 1=1 -- "}}
X-Parse-Application-Id: pcbApp
```

`PostgresStorageAdapter` 在 `fieldValue.$regex` 分支里：

```javascript
// PostgresStorageAdapter.js  (6.5.0, 约 L741–758)
    if (fieldValue.$regex) {
      let regex = fieldValue.$regex;
      let operator = '~';
      ...
      regex = processRegexPattern(regex);
      patterns.push(`$${index}:raw ${operator} '$${index + 1}:raw'`);
      values.push(name, regex);
```

`processRegexPattern` 走到 `literalizeRegexPart`。拼出来的 WHERE 片段语义是：

```sql
<col> ~ '<消毒后的 pattern>'
```

`:raw` 告诉 pg-promise：**不要再引号转义，按字符串原样插入**。Parse 还要 AND 上 `_rperm` 读权限。设计意图：`$regex` 只是字段上的正则，不能改 WHERE 结构，更不能关掉 ACL。成功穿越之后的效果是 **破出 `~` 的字符串字面量，`OR 1=1` 让受限行回到响应 JSON**，body 里出现 `PCBFLAG_...`。

数据流：

```text
HTTP where.name.$regex
    → RestQuery / PostgresStorageAdapter
         processRegexPattern
         literalizeRegexPart          ← V1 谓词在这里
         patterns: $n:raw ~ '$n+1:raw'
    → pg-promise 把 :raw 拼进 SQL
    → PostgreSQL 执行 WHERE（含 _rperm）
    → JSON results
```

不需要 session token；应用 ID 即可。金丝雀行本身带 ACL，正常 `$regex` 匹配不到它。

---

## 原始漏洞：只加倍第一个裸引号（CVE-2024-27298，6.4.0）

V0 的 `literalizeRegexPart` 在剥掉 `\Q`/`\E` 之后：

```javascript
// 6.4.0
  return s
    .replace(/([^\\])(\\E)/, '$1')
    .replace(/([^\\])(\\Q)/, '$1')
    .replace(/^\\E/, '')
    .replace(/^\\Q/, '')
    .replace(/([^'])'/, `$1''`)      // 没有 /g：只改第一处
    .replace(/^'([^'])/, `''$1`);
```

`([^'])'` 匹配「非引号 + 引号」，替换成「非引号 + 两个引号」。没有 `g` 时，`a'b' OR 1=1 -- ` 只把第一处 `a'` 变成 `a''`，第二处 `b'` 原样留下。

```text
输入:  a'b' OR 1=1 --
V0 后: a''b' OR 1=1 --
SQL:   name ~ 'a''b' OR 1=1 -- '
```

PostgreSQL 里 `a''b` 是字符串 `a'b`，随后 `'` 结束字面量，`OR 1=1` 成为 WHERE 的一部分，`--` 注释掉后面的 `_rperm` 子句。响应返回 ACL 本不该看见的行。这就是 v0 + `--seed`。

GHSA-6927-3vr9-fxf2：*This vulnerability allows SQL injection when Parse Server is configured to use the PostgreSQL database.* 修丁说明只写 *The algorithm to detect SQL injection has been improved*——实际 diff 就是加 `/g`。

---

## 维护者改了什么（CVE-2024-27298，6.5.0）

V1 只动最后两行里的第一行，加上全局标志：

```javascript
// 6.5.0 literalizeRegexPart
  return s
    .replace(/([^\\])(\\E)/, '$1')
    .replace(/([^\\])(\\Q)/, '$1')
    .replace(/^\\E/, '')
    .replace(/^\\Q/, '')
    .replace(/([^'])'/g, `$1''`)     // 唯一的变化：/g
    .replace(/^'([^'])/, `''$1`);
```

对 seed（两个引号都被非引号字符隔开）：

```text
输入:  a'b' OR 1=1 --
/g 后: a''b'' OR 1=1 --
SQL:   name ~ 'a''b'' OR 1=1 -- '
```

两处都变成 SQL 转义后的字面量，`OR` 仍在引号里，ACL 还在。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险引号都长得像「前面是非引号字符」。
2. 从左到右配完所有 `([^'])'` 之后，剩下的字符串里不会再有未转义的 `'`。

第二点不成立。`''` 里第二个引号的前面是引号，**不匹配** `([^'])'`。`/g` 不会回头再扫一遍已经被跳过的字符。

---

## 消毒之后，pattern 怎么接到 SQL 上

`literalizeRegexPart` 返回之后，没有任何第二次转义。同一函数立刻：

```javascript
      patterns.push(`$${index}:raw ${operator} '$${index + 1}:raw'`);
      values.push(name, regex);
```

pg-promise 的 `:raw` 把 `regex` 嵌进已经写好的单引号之间。过滤器看的是「有没有 `非' + '` 子串」；PostgreSQL 看的是「单引号是否成对」。两套计数法中间没有「奇数个 `'` 就拒绝」的谓词。

`createLiteralRegex`（`\Q…\E` 字面量分支）反而按字符处理：

```javascript
function createLiteralRegex(remaining) {
  return remaining.split('').map(c => {
    ...
    return c === `'` ? `''` : `\\${c}`;
  }).join('');
}
```

每个 `'` 都变成 `''`，不依赖前一个字符。这条更强的规则只服务 `\Q` 包装的片段；普通 `$regex` 走的是下面那个 `replace`。

---

## 仓库里已经有更强的检查，普通 $regex 没用

| 路径 | 如何处理 `'` |
|---|---|
| `createLiteralRegex`（`\Q…\E`） | 逐字符 `'` → `''` |
| 其它约束（`$eq`、指针…） | 绑定参数，不 `:raw` |
| V1 `literalizeRegexPart` 默认分支 | `([^'])'` 全局替换 |
| `_rperm` 过滤 | 另 AND 一段，假定前面的 WHERE 没有破出字面量 |

不是没有参数化或逐字符转义，是 **`$regex` 选择了 `:raw` 加手写加倍，而且加倍谓词比 `\Q` 分支更弱**。即便 `a'b'` 被 `/g` 挡住，只要还有一种让「SQL 看到的引号数」和「replace 看到的匹配数」不一致的写法，`:raw` 仍会把破出交给 PostgreSQL。

---

## 这个补丁挡住了什么、没挡住什么

`([^'])'/g` 对 `a'b'` 配两次，因为两处前面都是字母。对 `a''`：

```text
输入:  a'' OR 1=1 --
位置:  a  '  '   OR…

第一次匹配: 「a'」→「a''」，从第二个 ' 之后继续
第二个 ' 前面是 '，([^']) 失败
结果: a''' OR 1=1 --
```

三个引号。拼进 SQL：

```sql
name ~ 'a''' OR 1=1 -- '
```

`'a'''` 在 PostgreSQL 里是字符串 `a'`（标准的引号加倍），随后字面量结束，`OR 1=1 --` 再次注释掉 `_rperm`。这就是 verify 里的 inline residual：`"regex": "a'' OR 1=1 -- "`。和 seed 同一 `:raw ~` sink、同一 ACL 外泄，只是把「两个被字母隔开的引号」换成「一对相邻引号」。

`processRegexPattern` 对 `^…` / `…$` 会切掉锚点再调 `literalizeRegexPart`，对普通 contains 则整段进入。seed/residual 都不依赖锚点，直接走默认分支。`:raw` 模板是：

```javascript
patterns.push(`$${index}:raw ${operator} '$${index + 1}:raw'`);
```

左边的 `$n:raw` 是已经过 `transformDotField` 的列名，右边是 pattern。pg-promise 对 `:raw` 不做 `'` → `''`。其它操作符（`$eq`、指针）走绑定参数，同一份 adapter 里两种转义策略并存——`$regex` 选了弱的那种。

---

## 残余仍然走同一条 $regex REST 路径（CVE-2024-39309）

没有换类、没有换操作符、没有换数据库。还是：

```http
GET /parse/classes/Vault?where={"name":{"$regex":"a'' OR 1=1 -- "}}
```

`literalizeRegexPart` 的 `/g` 照样执行；执行完之后引号个数是奇数；`:raw` 拼进 `~`；PostgreSQL 把后半当 SQL。GHSA-c2hr-cqg6-8j6r 标题仍是 *literalizeRegexPart SQL Injection*，ZDI 写成认证绕过是因为 `_User` 上同一注入能改查询；本 case 打的是读受限行，sink 相同。

---

## 后来又补了什么（CVE-2024-39309，6.5.7 / f332d545）

V2 不再用「前面不是引号」当匹配条件，而是把连续引号串的长度补成偶数：

```javascript
// 6.5.7
    .replace(/'+/g, match => {
      return match.length % 2 === 0 ? match : match + "'";
    });
```

对 residual：`''` 长度 2，保持；前面的逻辑仍会把 `a'` 变成 `a''`，整体是偶数个引号，字面量不破出。对 seed 同样成立。公开建议是升到 6.5.7 或 7.1.0。

即便如此，`$regex` 仍走 `:raw`。V2 只保证引号成对；若还有其它让 `:raw` 改变 SQL 结构的字符，需要另证。本 benchmark 的 v2 关闭这条相邻引号 residual。

---

## 从这条链还能看出什么

**维护者改错了哪一层。**  
他们改的是替换次数。真正进引擎的是未绑定的字符串字面量。V2 仍在同一层改计数规则，没有把 `$regex` 改成参数绑定。

**不是没有更好的谓词。**  
`createLiteralRegex` 已经逐字符转义。从 6.4.0→6.5.0 的 diff 只能看到加了 `g`；要判断闭合，必须用 `a''` 走一遍匹配，并看到 `:raw` 不再二次转义。

**同一函数、同一 `$regex`，只换了引号的相邻方式。**  
任何 Postgres 上的 `$regex` where，在 6.5.0 上都吃这套 replace。

**`/g` 不是「所有引号都加倍」。**  
JavaScript 的 `[^']` 要求前一字符存在且不是引号。串首的 `'` 靠第二行 `.replace(/^'([^'])/, …)`，而且那一行**没有** `/g`，只处理开头一次。`a''` 的第二个引号两个规则都不收。ZDI-CAN-23894 能在 6.5.0–6.5.6 上继续打，说明 27298 的「algorithm improved」只改进了非相邻引号。

**V2 改的是奇偶，仍不是参数绑定。**  
`/'+/g` 把奇数长度的引号串补一个 `'`，让 SQL 字面量成对。`createLiteralRegex` 的逐字符 `'` → `''` 仍然只服务 `\Q`。闭合这条 residual 够用；`$regex` 作为 `:raw` 通道还在。

---

## 版本、入口、参考

| | tag | `literalizeRegexPart` | `a'b' OR 1=1` seed | `a'' OR 1=1` residual |
|---|---|---|---|---|
| V0 | 6.4.0 | `([^'])'` 无 `/g` | 破出，读到金丝雀 | （不必） |
| V1 | 6.5.0 | 同一正则 + `/g` | 两处都加倍，挡 | 奇数引号破出 |
| V2 | 6.5.7 | 奇数引号串补一个 `'` | 挡 | 挡 |

- REST：`GET /parse/classes/Vault?where={"name":{"$regex":"..."}}`
- [CVE-2024-27298](https://nvd.nist.gov/vuln/detail/CVE-2024-27298) / [GHSA-6927-3vr9-fxf2](https://github.com/parse-community/parse-server/security/advisories/GHSA-6927-3vr9-fxf2)
- [CVE-2024-39309](https://nvd.nist.gov/vuln/detail/CVE-2024-39309) / [GHSA-c2hr-cqg6-8j6r](https://github.com/parse-community/parse-server/security/advisories/GHSA-c2hr-cqg6-8j6r)
- V1：[PostgresStorageAdapter.js @ 6.5.0](https://github.com/parse-community/parse-server/blob/6.5.0/src/Adapters/Storage/Postgres/PostgresStorageAdapter.js)
- V2：[PR 9168](https://github.com/parse-community/parse-server/pull/9168) / [f332d545](https://github.com/parse-community/parse-server/commit/f332d54577608c5ad927255e06d8c694e2e0ff5b)
