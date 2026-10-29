# Keystone 6：where 做了 isFilterable，findMany 的 cursor 原样交给 Prisma

- Case：`PCBV2-0061`
- 产品：`@keystone-6/core`（Keystone 6，TypeScript headless CMS / GraphQL）
- 链：CVE-2025-46720（6.4.0 → 6.5.0/6.5.1，GHSA-hg9m-67mm-7pg3）→ CVE-2026-33326（6.5.1 → 6.5.2，GHSA-cgcg-q9jh-5pr2，commit `e1d0789`，PR #9790）
- 源码对着 npm `@keystone-6/core@6.5.1` / `6.5.2` 的 `src/lib/core/queries/resolvers.ts`：`findMany`、`checkFilterOrderAccess`。运行时是真实 `keystone dev` + SQLite，经 `/api/graphql` 打框架自己的 list query。

2025 年 5 月，Keystone 修了 update/delete 上「只检查 `WhereUniqueInput` 的第一个键」的问题：把完整 `where` 丢进 `traverse` + `checkFilterOrderAccess`。GHSA-cgcg-q9jh-5pr2 / CVE-2026-33326 写明：*the previous fix for CVE-2025-46720 added checks to the `where` parameter in `update` and `delete` mutations, however the `cursor` parameter in `findMany` was not patched and accepts the same `UniqueWhere` input type*。

根因不只是「漏了一个参数名」。检查插在 `findMany` 的 `where` 上；真正拿去定位行的还有 `cursor`，Prisma 按 unique 字段做分页锚点。同函数里已经有 `checkFilterOrderAccess([...traverse(list, where)])`，`cursor` 没用。下面按 GraphQL 走进去、V1 改了哪一段、检查之后谁消费那个 unique 输入、仓库里已经有什么更强的谓词、残余怎么用 `cursor:{ code }` 把同一条值预言打到受保护字段。

---

## 这块功能本来在干什么

Keystone 按 schema 生成 GraphQL。字段可以标 `isFilterable`：静态 `false` 会从 schema 里拿掉过滤；**函数** `() => false` 仍出现在 schema 里，运行时由 `checkFilterOrderAccess` 拒绝。本 case 的 `Secret.code`：

- `isIndexed: 'unique'` → 出现在 `SecretWhereUniqueInput`（findOne / update / delete / **cursor**）
- `isFilterable: () => false` → advisory 写明只有这种函数形态受影响
- `access.read: denyAll` → 读结果里永远是 `null`，不能 SELECT 出值

设计意图：外人不能用 `code` 做过滤或存在性探测。成功穿越之后的效果是 **用 unique 输入当布尔预言：猜对则命中一行，猜错则空 / 拒绝**。本 case 把 `${PCB_FLAG}` 种在一条 `Secret.code` 里；正确猜测让 query 返回该行 `id`。

数据流：

```text
HTTP POST /api/graphql
    → findMany({ where, cursor, take, orderBy })
         resolveWhereInput(where)
         V1：checkFilterOrderAccess(traverse(list, where))   ← 只罩 where
         resolveOrderBy
         prisma.findMany({ where: filter, cursor, take, skip })
              cursor 原样进 Prisma unique 查询              ← 没挂 isFilterable
    → 返回行（或空）
```

列表本身 `access: allowAll`。机密边界只在字段级 `isFilterable` + `access.read`。没有登录。

本 case schema 把 `code` 配成函数形态，正是为了踩 advisory 写明的受影响配置：

```typescript
// app/schema.ts  （本 case 的真实 Keystone schema）
code: text({
  isIndexed: 'unique',
  isFilterable: () => false,   // 函数：字段仍在 WhereUniqueInput 里
  access: { read: denyAll },
})
```

静态 `isFilterable: false` 会在生成 schema 时拿掉过滤参数，cursor 里根本不能写 `code`。函数形态把拒绝推迟到 `checkFilterOrderAccess`——谁没调用它，谁就是洞。

---

## 原始漏洞：只检查 unique where 的第一个键（CVE-2025-46720，6.4.0）

6.4.0 的 update/delete 对 `WhereUniqueInput` 只取 `Object.keys(uniqueWhere)[0]` 做 `checkFilterOrderAccess`。第二个键（例如 `code`）可以夹带进去。Prisma 的 unique where 会 **同时** 要求这些字段匹配，于是：

```graphql
mutation {
  updateSecret(where:{ id:"<已知 id>", code:"<猜测>" }, data:{ label:"seed" }) { id }
}
```

猜对 → mutation 成功（或按预期更新）；猜错 → 找不到行。`code` 从未出现在输出类型里，但存在性被确认。这就是 v0 + `--seed`。

V1（6.5.1）把 `getFilteredItem` 改成对完整 `traverse(list, where)` 做检查。夹带 `code` 会得到 `KS_FILTER_DENIED`。seed 在 V1 被挡住。`findMany` 的 `where` 同样走了 `checkFilterOrderAccess`。**`cursor` 没有。**

---

## 维护者改了什么（CVE-2025-46720 修复，6.5.1）

6.5.1 的 `findMany`（npm 包内 `resolvers.ts`，约 L103–139）：

```typescript
// @keystone-6/core@6.5.1  src/lib/core/queries/resolvers.ts :: findMany
  const resolvedWhere = await resolveWhereInput(where, list, context)

  // check filter access (TODO: why isn't this using resolvedWhere)
  await checkFilterOrderAccess([...traverse(list, where)], context, 'filter')

  // WARNING: this checks .isOrderable
  const orderBy = await resolveOrderBy(rawOrderBy, list, context)

  const filter = await accessControlledFilter(list, context, resolvedWhere, accessFilters)
  const results = await context.prisma[list.listKey].findMany({
    where: extraFilter === undefined ? filter : { AND: [filter, extraFilter] },
    orderBy,
    take: take ?? undefined,
    skip,
    cursor: cursor ?? undefined,
  })
```

`where` 在进 Prisma 之前经过 `traverse` + `checkFilterOrderAccess`。`cursor` 出现在同一参数列表里（`FindManyArgsValue`），类型是同一份 `WhereUniqueInput`，却直接 `cursor: cursor ?? undefined`。注释 TODO 还问 why isn't this using resolvedWhere——说明作者知道过滤输入和 Prisma 输入不是同一层，但只处理了 `where`。

对 seed 这种 update `where:{ id, code }`，`getFilteredItem` 里的完整 traverse 会看到 `code`，`isFilterable` 函数返回 false，抛 `KS_FILTER_DENIED`。

补丁默认了两件事：

1. 危险的 unique 输入只从 update/delete（以及 findMany 的 `where`）进来。
2. 只要把 `traverse(where)` 挂上，同一类型的其它参数不会被 Prisma 当成过滤。

第二点不成立。Prisma `findMany({ cursor })` 的语义就是「从这条 unique 记录开始」——它必须按 cursor 里的字段去查行。

---

## 检查之后，谁真正用那个 unique 值

`checkFilterOrderAccess` 一返回，`prisma.findMany` 把 `cursor` 原样交给 Prisma Client。Prisma 把它编译成按 unique 字段定位的 SQL（`WHERE code = ?` 一类）。数据库比较的是真实列值。GraphQL 输出仍然受 `access.read: denyAll` 限制，**不会**把 `code` 选出来；命中与否本身就是预言。

检查看见的是 `where` 对象上出现了哪些键。Prisma 看见的是 `cursor` 对象上出现了哪些键。两份输入类型相同，检查只读了其中一份。

`findMany` 的 TypeScript 参数把 `cursor` 和 `where` 写在同一份 `FindManyArgsValue` 里。GraphQL 层把 `secrets(cursor: { code: "..." })` 解成这个对象。V1 解构了 `cursor`，却只把它用在 Prisma 选项上，中间没有 `traverse`。

`traverse(list, cursor)` 在 V1 **可以**调用——V2 就是加上这一行。谓词已经在同文件 import 里：

```typescript
import { checkFilterOrderAccess } from '../filter-order-access'
```

`findMany` 开头已经用它扫过 `where`。`cursor` 在签名里与 `where` 并列，却在扫完之后才第一次出现，而且是作为 Prisma 选项。

---

## 仓库里已经有更强的检查，cursor 没用

`checkFilterOrderAccess` + `traverse` 是 CVE-2025-46720 专门加强过的谓词：它走完整 unique/filter 树，而不是第一个键。6.5.1 已经把它用在：

| 调用点 | 扫了什么 |
|---|---|
| `findMany` | `where` |
| `getFilteredItem`（update/delete） | 完整 unique where |
| `findMany` | **没有** `cursor` |

不是仓库里没有「对 UniqueWhere 做 isFilterable」的函数，是 **分页锚点没挂**。advisory 写的 workaround 也从侧面证明这件事：把 `isFilterable: false` 写成静态值，字段会从 schema 里消失，cursor 根本收不到这个键；函数形态才会在运行时被绕过。

即便 cursor 没有漏，只要还有第三个接受 `WhereUniqueInput` 却不走 `checkFilterOrderAccess` 的参数，也是同一类问题。本 case residual 只打 `findMany.cursor`。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs Prisma」落到具体代码：

- V1 的 `checkFilterOrderAccess(traverse(list, where))`：看 `where` 里有没有不可过滤字段
- `prisma.findMany({ cursor })`：看 `cursor` 里的 unique 字段是否匹配一行

只要构造一种输入，使 `where` 干净（或不含受保护键），但 `cursor` 带上 `code`，第一行会放行，第二行仍然按 `code` 定位。

```graphql
query {
  secrets(cursor:{ code:"<猜测>" }, take:1, orderBy:{ id:asc }) { id }
}
```

没有字符串变换。V1 不改写 cursor，只是不检查它。猜对 → 返回种了 flag 的那一行 `id`；猜错 → 空列表。输出里仍然没有 `code` 字段。

advisory 原话：*This can be used to confirm the existence of records by protected field values.* 本 case 把「存在性」钉在种好的 `${PCB_FLAG}` 上，避免变成任意数据外泄。

---

## 残余仍然走同一条 findMany 值预言路径（CVE-2026-33326）

没有换 list、没有换字段、没有换 `isFilterable` 函数。还是 `Secret.code`。GraphQL 从 update `where` 换成 findMany `cursor`：

```graphql
{ secrets(cursor:{ code:"PCBFLAG_..." }, take:1, orderBy:{ id:asc }) { id } }
```

`findMany` 仍然先检查 `where`（这里是空 / 默认）。V1 那一行 `checkFilterOrderAccess(where)` 看不见 `cursor`。Prisma 按 `code` 锚到那一行。`access.read: denyAll` 照样不把值选出来；`id` 出现即确认猜测。

这不是新洞面：同一 `WhereUniqueInput`、同一 `isFilterable` 函数、同一「用匹配当预言」的效果。seed 被挡住只说明「update/delete 的 where 会 traverse 全键」，不说明「不能再用另一份 unique 输入确认 code」。

公开修复 commit `e1d0789` 的说明与此一致：*The cursor parameter in findMany accepted uniqueWhere inputs without validating them against isFilterable access controls.* 同 commit 还加了两个测试：`cursor with isFilterable: false` 期望 `users: null` + filter denied；`cursor with isFilterable: true` 允许按 email 锚到那一行。这把「cursor 必须走同一谓词」写进了回归，而不是只改一行。

值预言的观测（case.json / repro.log，非本轮 compose）：V0 上 original(update-where)=REACHED 且 cursor=REACHED；V1 上 original=BLOCKED(`KS_FILTER_DENIED`) 且 cursor=REACHED；V2 上两者都 BLOCKED。差分落在「同一 unique 字段、两个 GraphQL 参数」。

---

## 后来又补了什么（CVE-2026-33326，6.5.2，commit e1d0789）

6.5.2 在 `where` 检查之后、`resolveOrderBy` 之前加上：

```typescript
// @keystone-6/core@6.5.2  findMany
  await checkFilterOrderAccess([...traverse(list, where)], context, 'filter')

  // check filter access for cursor
  if (cursor) {
    await checkFilterOrderAccess([...traverse(list, cursor)], context, 'filter')
  }
```

`prisma.findMany({ cursor })` 还在。只是 cursor 里的 `code` 会先被 `isFilterable` 拒绝，变成 `KS_FILTER_DENIED`。公开建议是升级到 6.5.2。workaround：敏感字段用静态 `isFilterable: false`，或 `graphql.omit.read: true`（从 schema 去掉过滤）。

即便如此，这仍然是「在进 Prisma 之前再扫一次 cursor」。对这条 unique cursor 链它够用。本 benchmark 的 v2 只关闭这一条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是「unique where 要 traverse 全键」。真正当预言的是 Prisma 对 unique 输入的匹配。V2 仍在同一层把 cursor 接进已有谓词，没有在 Prisma 调用前把 cursor 收成「仅内部 id」。

**不是没有更好的谓词。**  
`checkFilterOrderAccess` + `traverse` 已经用在同函数的 `where` 上。从 V1 的 `findMany` 只能看到 `where` 被扫、`cursor` 被传入。要判断补丁是否闭合，必须看到 Prisma 选项里还有一份未扫描的 UniqueWhere。

**同一输入类型、两个参数名。**  
GraphQL 的 `cursor` 和 `where` 都是 `SecretWhereUniqueInput`。过滤器按参数名决定扫不扫，Prisma 按类型决定查不查。任何「类型相同、参数名不同」的入口都值得对一遍。

**静态 false 与函数 false 不是同一条路。**  
advisory 写明静态 `isFilterable: false` 不受影响，因为字段根本不进 schema。本 case 必须用 `() => false` 才能让 cursor 里出现 `code`。配置形态本身就是攻击面的一部分。

**读权限挡不住过滤预言。**  
`access.read: denyAll` 只挡 SELECT。unique 匹配发生在读投影之前。金丝雀不能从输出字段里读到，却能从「有没有这一行」读到。

**分页参数不是装饰。**  
`take` / `skip` / `orderBy` 在 V1 上分别有 maxTake 限制和 `isOrderable` 检查（`resolveOrderBy` 的 WARNING 注释写明这一点）。`cursor` 与它们同级，却是唯一直接进 Prisma、且类型为 UniqueWhere 的参数。修 `where` 却不修 `cursor`，等于承认「过滤要授权」，又留下一个等价的定位通道。

**函数形态把检查从 schema 推迟到运行时。**  
静态 `false` 让代码生成器不发出 `code` 这个 unique 输入字段，攻击者在 GraphQL 层就写不进去。`() => false` 仍发出字段，依赖每一次 resolver 记得调用 `checkFilterOrderAccess`。V1 在 `where` 上记得，在 `cursor` 上忘了。这不是配置错误，是「运行时谓词必须覆盖所有同类型参数」没写完。

---

## 版本、入口、参考

| | npm | update `where:{id,code}` seed | findMany `cursor:{code}` residual |
|---|---|---|---|
| V0 | 6.4.0 | 只检查第一键，预言打穿 | 同样能打（不必） |
| V1 | 6.5.1 | 完整 traverse → `KS_FILTER_DENIED` | cursor 未检查，预言打穿 |
| V2 | 6.5.2 | 挡 | `checkFilterOrderAccess(cursor)` → `KS_FILTER_DENIED` |

- Web：`POST /api/graphql`
- 源码：npm `@keystone-6/core@6.5.1` 的 `src/lib/core/queries/resolvers.ts`（`findMany` L103–139）
- [CVE-2025-46720](https://github.com/keystonejs/keystone/security/advisories/GHSA-hg9m-67mm-7pg3)、[CVE-2026-33326](https://nvd.nist.gov/vuln/detail/CVE-2026-33326)
- [GHSA-cgcg-q9jh-5pr2](https://github.com/keystonejs/keystone/security/advisories/GHSA-cgcg-q9jh-5pr2)
- [commit e1d0789](https://github.com/keystonejs/keystone/commit/e1d07896c383af3cd50051e2ffbe55bec8ac4639)
- [release 2026-03-19](https://github.com/keystonejs/keystone/releases/tag/2026-03-19)（`@keystone-6/core@6.5.2`）
