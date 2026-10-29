# Mongoose populate().match：$where 只扫了第一层

- Case：`PCBV2-0147`
- 产品：npm `mongoose`（Node.js MongoDB ODM）。运行时是整包 `mongoose@8.8.3`，应用通过 `Model.find().populate({ path, match })` 调用，不是抽出来的函数。
- 链：CVE-2024-53900（8.8.2 → 8.8.3，commit `33679bc` / `c9e86bff`，GHSA-m7xq-9374-9rvx）→ CVE-2025-23061（8.8.3 → 8.9.5，commit `64a9f970`，GHSA-vg7j-7cwx-8wgw）
- 源码对着 tag `8.8.3` 的 `lib/helpers/populate/getModelsMapForPopulate.js`（守卫）和 `lib/helpers/populate/assignVals.js`（`sift(match)`）。金丝雀是被 `secret:true` 挡住的 Book 文档标题里的 `PCBFLAG_...`，不是对 Mongo 进程的任意 JS payload。

NVD / GHSA-vg7j-7cwx-8wgw 的原话：*Mongoose before 8.9.5 can improperly use a nested $where filter with a populate() match, leading to search injection. NOTE: this issue exists because of an incomplete fix for CVE-2024-53900.* OPSWAT 把缺口写得更具体：8.8.3 只看 array item 自己的 `$where` 键，`$or: [{ $where: ... }]` 没有这把键。

根因不只是「忘了递归」。检查插在「match 对象顶层有没有 `$where`」上；真正编译 JS 的是后面的 `sift`，它认嵌套的 `$or`/`$and`。同一次 populate 里已经决定把 array-form match 交给进程内 sift，却只在入口做了一层键名扫描。下面按调用走进去。

---

## 这块功能本来在干什么

`populate()` 把引用 ID 换成关联文档。`match` 是叠加在关联查询上的过滤。一次典型调用：

```javascript
Author.find().populate({
  path: 'books',
  match: { secret: false }     // 意图：只填充公开书
})
```

HTTP 侧常见写法是应用把用户 JSON 直接塞进 `match`（本 case 的 harness 就是这样）。`getModelsMapForPopulate` 取出 `options.match`，做完守卫之后原样放进 `data.match`，后续查询和进程内过滤都用这份对象。

设计意图：调用者只能用普通字段比较来收窄关联集。成功穿越之后的效果是：**`$where: "true"` 让 sift 把本应排除的 secret 文档留在 populate 结果里**，标题中的金丝雀出现在 HTTP 响应。需要能调用到这段 populate 的应用身份（本 case 是对外 HTTP 包装）。

数据流：

```text
应用：Author.find().populate({ path:'books', match: <用户 JSON> })
    → getModelsMapForPopulate
         match = options.match
         V1：只看 item.$where / match.$where     ← 补丁插在这里
         data.match = match                      ← 原对象继续往下
    → 关联查询从 Mongo 拉回候选（含 secret 书）
    → assignVals
         Array.isArray(o.match)
              rawIds.filter(v => sift(o.match[i])(v))
                   sift 认 $or / $where
                   $where 字符串 → new Function('return ' + str)
    → 填充后的 books 进 HTTP body
```

`$where` 在 Mongo 服务端也会跑 JS；array-form match 这条路额外走 sift，JS 跑在 **Node 进程**里。本 case 用良性 `"true"` 只为放宽过滤，观察的是同一扇门有没有打开。

---

## 原始漏洞：match 里的 `$where` 直达 sift（CVE-2024-53900，8.8.2）

8.8.2 的 `getModelsMapForPopulate` 取出 `match` 之后，没有任何 `$where` 检查，直接 `data.match = match`。OPSWAT 复现的 payload 是 array-form：

```javascript
match: [{ $where: 'true' }]
```

`assignVals` 对 array match 走 sift：

```javascript
// lib/helpers/populate/assignVals.js  （8.8.3 与 8.8.2 相同，守卫不在这里）
} else if (Array.isArray(o.match)) {
    valueToSet = Array.isArray(rawIds[i])
      ? rawIds[i].filter(v => v == null || sift(o.match[i])(v))
      : [rawIds[i]].filter(v => v == null || sift(o.match[i])(v))[0];
}
```

sift 把 `$where` 当成可执行表达式。字符串会进 `new Function`。本 case seed 用 `[{$where:"true"}]`：所有候选书都留下，secret 书的标题出现在 populate 结果里。这就是 v0 + `--seed` 观察到 `PCBFLAG_...`。

对象形式 `{ $where: '...' }` 会进 Mongo 查询而不是 sift；NVD 把整类都算 search injection。seed 选 array-form，是因为那是守卫加上之后仍能被嵌套绕过、并且 JS 跑在 Node 里的那条路。

---

## 维护者改了什么（CVE-2024-53900 修复，8.8.3）

commit `33679bc` / `c9e86bff`（*fix: disallow using $where in match*）在 `getModelsMapForPopulate` 和 `_virtualPopulate` **各**加了一段非递归扫描，紧挨在 `data.match = match` 之前：

```javascript
// lib/helpers/populate/getModelsMapForPopulate.js  （mongoose 8.8.3）
let match = get(options, 'match', null);
const hasMatchFunction = typeof match === 'function';
if (hasMatchFunction) {
  match = match.call(doc, doc);
}
if (Array.isArray(match)) {
  for (const item of match) {
    if (item != null && item.$where) {
      throw new MongooseError('Cannot use $where filter with populate() match');
    }
  }
} else if (match != null && match.$where != null) {
  throw new MongooseError('Cannot use $where filter with populate() match');
}
data.match = match;
```

虚拟 populate 那份是同一段逻辑，只是换了取 `match` 的来源。测试只断言了顶层 `{ $where: 'console.log("oops!");' }` 会抛。

V1 谓词的字面意思：

| 形态 | 检查 |
|---|---|
| `match` 是数组 | 每个 `item.$where` 是否为真 |
| `match` 是对象 | `match.$where != null` |
| 嵌套在 `item.$or` / `item.$and` 里的 `$where` | **不看** |

对 seed 这种顶层 `$where`，它确实够用：`item.$where` 为真，抛 `Cannot use $where filter with populate() match`。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险过滤长得像「这个对象自己有一把叫 `$where` 的键」。
2. sift / Mongo 不会从别的运算符下面再取出 `$where`。

第二点不成立。sift 和 Mongo 都把 `$or` 的数组元素当成完整查询。

---

## 守卫放过之后，谁真正跑那段 JS

V1 的 `if` 一结束，同一个函数把**原对象**交给后续。没有深拷贝，没有把 `$` 键剥掉。关联文档从 Mongo 拉回来之后，`assignVals` 仍然：

```javascript
rawIds[i].filter(v => v == null || sift(o.match[i])(v))
```

`sift` 来自依赖包 `sift`。它对 Mongo 风格运算符做进程内匹配。`$where` 的实现会把字符串编译成函数。过滤器刚看过的是「顶层有没有这把键」；sift 看的是整棵查询树。中间没有第二次键名扫描。

非 array 的 `match` 会进 Mongo `find` 的 filter。Mongo 同样执行 `$where`。本 case 的 array-form 让效果落在 Node 里，但「守卫浅、消费者深」是同一件事。

`populate` 的结果写回 `Author.books`，HTTP 响应把标题序列化出去。金丝雀出现在 body 里，依据就是 sift 留下了 `secret:true` 的那本，而不是「Mongo 里碰巧没有 secret 标记」。

---

## 仓库里已经有更强的检查，浅扫描没用

8.8.3 **没有**现成的递归 walker——那是 8.9.5 才加的 `throwOn$where`。但当时已经能看到两条更强、且几乎零成本的做法，都没用上：

1. **沿对象树走所有 key**。`match` 本来就是普通 JSON，深度有限。V2 整段 `throwOn$where` 不到 20 行，就写在同一个文件末尾。
2. **array-form 根本不要走 sift 执行 `$where`**。`assignVals` 已经特殊处理了 `Array.isArray(o.match)`。可以在进 sift 之前再拦一次，或者对 array match 拒绝一切 `$` 运算符。

谁调用浅扫描（8.8.3）：

| 位置 | 看嵌套 `$where`？ |
|---|---|
| `getModelsMapForPopulate` 主路径 | 否，只看 `item.$where` |
| `_virtualPopulate` | 否，同一段 |
| `assignVals` → `sift(o.match[i])` | **否**，sift 会执行它 |
| Mongo `find` filter | **否**，服务端会执行它 |

不是「Mongo 查询语言里没有嵌套」，是 **入口谓词比消费者认的语言窄一层**。即便 `$or` 没有把浅扫描打穿，只要 `assignVals` 继续把用户对象交给 sift，任何让 `$where` 出现在第二层的写法都会变成一次真实的 `new Function`。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「键扫描 vs sift」落到具体形状：

- V1 过滤器：`item.$where` 是否为真
- `sift(match)`：按 Mongo 查询语义求值，包括 `$or: [ { $where: ... } ]`

只要构造一种输入，使「顶层 item 没有 `$where` 键」但「sift 仍能走到 `$where`」，第一道门放行，第二道门会编译字符串。

```text
seed:
  match = [{ $where: "true" }]
  → item.$where 为真 → throw

residual:
  match = [{ $or: [{ $where: "true" }] }]
  → item.$where === undefined → 放行
  → data.match 原样下传
  → sift({ $or: [{ $where: "true" }] })(secretBook) === true
  → secret 书留在 populate 结果里
```

OPSWAT 原话：*it fails to detect $where when embedded inside an $or operator — a structure both MongoDB and the sift library fully support.* `$and`、更深的 `$or` 嵌套是同一条缝。

---

## 残余仍然走同一条 populate → sift 路径（CVE-2025-23061）

没有换 API、没有换 `path:'books'`、没有换观察通道。还是：

```javascript
Author.find().populate({
  path: 'books',
  match: [{ $or: [{ $where: 'true' }] }]
})
```

`getModelsMapForPopulate` 仍然执行那两段浅 `if`；执行完之后 `$where` 还在树里；`assignVals` 仍然 `sift(o.match[i])`；secret 书仍然进响应。NVD 写明 *incomplete fix for CVE-2024-53900*。

本 case residual 和公开绕过同一构造，只是把 RCE 表达式换成良性 `"true"`，观察的是同一扇门。平台 residual 打的就是这条 populate match，和源码链同一 sink（`assignVals` → `sift`）。不是另一条无关查询。

seed 被挡住只说明「顶层 `$where` 没了」，不说明「populate match 不能再在 Node 里执行用户 JS」。

---

## 后来又补了什么（CVE-2025-23061，8.9.5）

commit `64a9f970` 把两段浅扫描换成同一个递归函数，数组就对每个元素调一次：

```javascript
// lib/helpers/populate/getModelsMapForPopulate.js  （mongoose 8.9.5）
function throwOn$where(match) {
  if (match == null) {
    return;
  }
  if (typeof match !== 'object') {
    return;
  }
  for (const key of Object.keys(match)) {
    if (key === '$where') {
      throw new MongooseError('Cannot use $where filter with populate() match');
    }
    if (match[key] != null && typeof match[key] === 'object') {
      throwOn$where(match[key]);
    }
  }
}

throwOn$where(match);
data.match = match;
```

对残余输入：`$or` 的数组元素是对象，递归进去看到 `$where`，抛同一句错。公开建议升级到 8.9.5 / 7.8.4 / 6.13.6。

即便如此，这仍然是「在交给 sift / Mongo **之前**扫键名」，`assignVals` 没有自己再拦一遍。对 `$or`/`$and` 套 `$where` 这条已知链够用。本 benchmark 的 v2 只关闭这一条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是入口对象的第一层键。真正执行 JS 的是 `sift`（以及 Mongo）。V2 仍在同一入口加码，但终于按消费者认的树形语言来扫。

**不是没有更好的谓词。**  
递归 walker 和「禁止 match 里任意 `$` 运算符」在 8.8.3 都写得下。从 V1 的 diff 只能看到 `item.$where`；要判断是否闭合，必须看到 `assignVals` 的 `sift(o.match[i])`，以及 sift 对 `$or` 的语义。

**同一 `data.match`、同一 sift 调用，只换了 JSON 形状。**  
对象形式、数组形式、virtual populate 三处守卫曾经是复制粘贴；漏递归就会漏三处。advisory 把它们算成同一个 CVE。

**浅相等不是查询语言。**  
`item.$where` 是 JavaScript 属性访问。`$or` 是查询运算符。只检查前者、把后者交给 sift，等于用对象形状去近似「不许执行 JS」。

**金丝雀在被 match 排除的文档里是有意的。**  
`secret:true` 的书按 `{secret:false}` 不该出现。能在 populate 标题里读到 flag，说明过滤器放行了一次会让 sift 返回 true 的 `$where`。

---

## 版本、入口、参考

| | 版本 | `getModelsMapForPopulate` | `assignVals` | 顶层 `$where` seed | `$or` 嵌套 residual |
|---|---|---|---|---|---|
| V0 | 8.8.2 | 无守卫 | `sift(match)` | 泄漏 secret 书 | （不必） |
| V1 | 8.8.3 | 非递归 `item.$where` | 同上 | throw | sift 执行，泄漏 |
| V2 | 8.9.5 | 递归 `throwOn$where` | 同上 | throw | throw |

- 库 API：`Model.find().populate({ path, match })`；array-form match 走 sift
- [CVE-2024-53900](https://nvd.nist.gov/vuln/detail/CVE-2024-53900)、[CVE-2025-23061](https://nvd.nist.gov/vuln/detail/CVE-2025-23061)
- [GHSA-m7xq-9374-9rvx](https://github.com/advisories/GHSA-m7xq-9374-9rvx)、[GHSA-vg7j-7cwx-8wgw](https://github.com/advisories/GHSA-vg7j-7cwx-8wgw)
- [OPSWAT 技术分析](https://www.opswat.com/blog/technical-discovery-mongoose-cve-2025-23061-cve-2024-53900)
- V1 commit [`33679bc`](https://github.com/Automattic/mongoose/commit/33679bc)；V2 commit [`64a9f970`](https://github.com/Automattic/mongoose/commit/64a9f9706f2428c49e0cfb8e223065acc645f7bc)
- 源码：[`8.8.3` `getModelsMapForPopulate.js`](https://github.com/Automattic/mongoose/blob/8.8.3/lib/helpers/populate/getModelsMapForPopulate.js)、[`assignVals.js`](https://github.com/Automattic/mongoose/blob/8.8.3/lib/helpers/populate/assignVals.js)
