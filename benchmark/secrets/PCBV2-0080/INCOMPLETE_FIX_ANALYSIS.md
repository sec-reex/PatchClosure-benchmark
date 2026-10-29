# ArcadeDB：UPDATE_SCHEMA 只加到了 createProperty，dropProperty 仍让只读令牌改 schema

- Case：`PCBV2-0080`
- 产品：ArcadeDB（官方镜像 `arcadedata/arcadedb:26.3.2` / `26.4.2` / `26.6.1`，HTTP `POST /api/v1/command/<db>`）
- 链：CVE-2026-44221（26.3.2 → 26.4.2，给 `createProperty` 加 `UPDATE_SCHEMA`）→ CVE-2026-54076（≤26.5.1 → 26.6.1，commit `2ee76fe` / PR `#4423`）
- 源码对着 GitHub tag `26.4.2` / `26.6.1` 的 `engine/.../schema/LocalDocumentType.java`：`createProperty`、`dropProperty`、`checkForSchemaMutation`。运行时是整份服务器。只读 API token：`permissions.database=[]`，`types.*.access=[readRecord]`，没有 `updateSchema`。

2026 年 4 月前后，CVE-2026-44221 / GHSA-fxc7-fm93-6q77 修了一批授权问题。GHSA-fxc7 **自己的正文**写的是跨库 `fileAccessMap` 未初始化、以及 `createDatabase` 漏挂 `factory.setSecurity`；补丁版本写 26.4.1 / 26.4.2。GHSA-vg6x-6pg9-6qwg 标题就是 *Read-only users can mutate database schema (incomplete fix of CVE-2026-44221)*，并把「只给 `createProperty` 加了 `UPDATE_SCHEMA`」**归因**给那次修复：*The fix … added an UPDATE_SCHEMA authorization check to a single schema-mutating method (`LocalDocumentType.createProperty`). The remaining public schema mutators were left unchecked.* 本文跟 GHSA-vg6x + tag `26.4.2` 源码：`createProperty` 是当时唯一带检查的 mutator（observed）；不把 GHSA-fxc7 的跨库面当成这条 residual。

根因不只是「漏了 DROP」。检查插在**一个** mutator 的入口；HTTP 命令接口把 SQL DDL 派发到 `createProperty` / `dropProperty` / `setSuperTypes` / `LocalProperty` setter 等一排兄弟方法，它们写的是同一份内存+磁盘 schema。V1 只给创建属性那一条加了锁。下面按请求走进去。

---

## 这块功能本来在干什么

ArcadeDB 用 HTTP 命令接口执行 SQL。schema 变更是一类 DDL：`CREATE PROPERTY`、`DROP PROPERTY`、`ALTER TYPE`、`ALTER PROPERTY …`。文档里 `UPDATE_SCHEMA` 是这类操作的门闩。只读身份（包括 API token）应当能 `SELECT`，不应当改类型定义。

本 case 由 root 种下一份文档类型 `Widget`，上面有一个 STRING 属性，名字等于 per-run `${PCB_FLAG}`。只读 token 再对同一数据库发 DDL。成功穿越之后的效果是：**schema 被只读身份改掉**——seed 是多出一个属性，residual 是种下的 flag 属性消失。检测看 HTTP 2xx **并且** 管理员后续 `SELECT properties FROM schema:types` 状态真的变了。

数据流（26.4.2，本 case 的 V1）：

```text
POST /api/v1/server/api-tokens     → 只读 token（无 UPDATE_SCHEMA）
POST /api/v1/command/pcb
    Authorization: Bearer at-...
    SQL DDL
         CREATE PROPERTY Widget.injected_... STRING
              → LocalDocumentType.createProperty
                   V1：checkPermissionsOnDatabase(UPDATE_SCHEMA)  ← 补丁只插在这里
                   无权限 → SecurityException → HTTP 403
         DROP PROPERTY Widget.<PCB_FLAG>
              → LocalDocumentType.dropProperty
                   V1：没有检查，直接 properties.remove
                   → HTTP 200，schema 上属性消失
```

身份始终是同一把只读 token。没有换库、没有用 root 做 residual。

---

## 原始漏洞：schema mutator 全无 UPDATE_SCHEMA（CVE-2026-44221 所关的那条，26.3.2）

26.3.2 的 `createProperty` / `dropProperty` 都没有数据库级 `UPDATE_SCHEMA` 检查（V0，observed：官方镜像上 CREATE 返回 200）。只读 token 发：

```sql
CREATE PROPERTY Widget.injected_<flag> STRING
```

返回 200，schema 查询能看到新属性。这是 v0 + `--seed`。GHSA-fxc7 还描述了跨库授权、新建库未挂安全等其它缺陷；本 case 的 seed 通道**观察到的**是「只读身份 CREATE PROPERTY 成功」。其它 44221 面不在本分析展开。

---

## 维护者改了什么（CVE-2026-44221 在 schema 上的可见修复，26.4.2）

tag `26.4.2` 的三参数 `createProperty` 开头多了一行：

```java
// engine/src/main/java/com/arcadedb/schema/LocalDocumentType.java
// LocalDocumentType.createProperty(String, Type, String)  (tag 26.4.2 / V1, L402–403)
  @Override
  public LocalProperty createProperty(final String propertyName, final Type propertyType, final String ofType) {
    ((DatabaseInternal) schema.getDatabase()).checkPermissionsOnDatabase(SecurityDatabaseUser.DATABASE_ACCESS.UPDATE_SCHEMA);

    if (properties.containsKey(propertyName))
      throw new SchemaException(
          "Cannot create the property '" + propertyName + "' in type '" + name + "' because it already exists");
    ...
    recordFileChanges(() -> {
      properties.put(propertyName, property);
      return null;
    });
    return property;
  }
```

对 seed 这种 `CREATE PROPERTY`，它确实够用：只读 token 没有 `UPDATE_SCHEMA`，抛 `SecurityException`，HTTP 403，响应类似 *User 'apitoken:…' is not allowed to update schema*。这就是 v1 + `--seed` 退出码 10。

同文件的 `dropProperty` **一字未加**：

```java
// LocalDocumentType.dropProperty  (tag 26.4.2 / V1, L498–508)
  @Override
  public Property dropProperty(final String propertyName) {
    for (final TypeIndex index : getAllIndexes(true)) {
      if (index.getPropertyNames().contains(propertyName))
        throw new SchemaException(
            "Error on dropping property '" + propertyName + "' because used by index '" + index.getName() + "'");
    }

    return recordFileChanges(() -> {
      return properties.remove(propertyName);
    });
  }
```

补丁默认了两件事：

1. 危险形态长得像「只读身份 CREATE PROPERTY」。
2. 只要创建属性前检查 `UPDATE_SCHEMA`，只读身份就不能再改 schema。

第二点不成立。删除、改继承、改约束都是 schema 突变，走别的 public 方法，HTTP 命令接口照样能从只读 token 调到。

---

## 消毒之后，DDL 怎么接到真正写 schema 的方法上

SQL `DROP PROPERTY Widget.x` 被解析后调用 `LocalDocumentType.dropProperty`，不经过 `createProperty`。V1 的权限检查因此不会跑。`recordFileChanges` 把 `properties.remove` 持久化。管理员再查 `schema:types`，种下的 `${PCB_FLAG}` 属性不在了。

命令接口本身不做「这条 SQL 是不是 schema DDL」的二次授权。HTTP 层只把 Bearer token 绑成当前用户，再把 `command` 字符串交给 SQL 执行器；CREATE / DROP / ALTER 各自落到 `LocalDocumentType` / `LocalProperty` 的不同 public 方法。过滤器刚看过的是「创建属性这条入口有没有 UPDATE_SCHEMA」；磁盘上的类型定义看的是 **任何一个** mutator 是否写了 `properties` / 超类 / 约束。两套入口中间没有共享 helper。

金丝雀能从 schema 里消失，依据就是这次 `remove` 真的提交了，而不是命令接口回了一句成功、底层没改。本 case 要求 2xx **且** 后续查询证实状态变化（observed on real images，见 legacy `repro.log` / case.json：V1 DROP → 200 且属性消失；inferred：同一未加锁的 `setSuperTypes` / `LocalProperty` setter 也能改 schema，GHSA-vg6x 并列列出，本 residual 没有逐条复现）。

HTTP 入口是同一条 `POST /api/v1/command/<db>`。身份头不变。

---

## 仓库里已经有 UPDATE_SCHEMA 检查，只挂在一个方法上

`checkPermissionsOnDatabase(UPDATE_SCHEMA)` 在 V1 已经作为可调用的安全原语存在——`createProperty` 就是这么用的。26.6.1 把它提成 helper，在每个 mutator 开头调用：

```java
// LocalDocumentType.checkForSchemaMutation  (tag 26.6.1 / V2, L135–141)
  /**
   * Enforces the UPDATE_SCHEMA permission for any schema-mutating operation. No-op in embedded mode or when no
   * current user is bound to the thread (e.g. schema load at startup, replication apply).
   */
  protected void checkForSchemaMutation() {
    ((DatabaseInternal) schema.getDatabase()).checkPermissionsOnDatabase(SecurityDatabaseUser.DATABASE_ACCESS.UPDATE_SCHEMA);
  }
```

`dropProperty` 在 V2 第一行就是 `checkForSchemaMutation()`（L547–548）。GHSA-vg6x 列出 V1 仍开放的兄弟：

- `DROP PROPERTY`
- `ALTER TYPE SUPERTYPE +/-`、`ALTER TYPE NAME`
- 类型 alias / bucket
- `ALTER PROPERTY` 的 MANDATORY / READONLY / NOTNULL / MIN / MAX / REGEXP / DEFAULT / CUSTOM（`LocalProperty` setter 完全没有检查）

| 方法 | 26.4.2 (V1) | 26.6.1 (V2) |
|---|---|---|
| `createProperty(...)` | 内联 `UPDATE_SCHEMA` | `checkForSchemaMutation()` |
| `dropProperty` | **无** | 有 |
| `addSuperType` / `setSuperTypes` / rename / buckets | **无** | 有 |
| `LocalProperty` setters | **无** | 有 |

不是没有授权谓词。是 **谓词只挂在创建属性上**。文档宣称 `UPDATE_SCHEMA` 门闩所有 schema 变更；实现只锁了一扇门。

即便 residual 不用 DROP，只读 token 改超类或约束同样破坏「只读不能改 schema」的模型。本 case 选 DROP 是因为它能把种下的 flag 属性拿掉，状态通道干净。

---

## 这个补丁挡住了什么、没挡住什么

- `createProperty` 开头的 `UPDATE_SCHEMA`：挡住 seed 的 `CREATE PROPERTY Widget.injected_...`
- 其它 mutator：只读 token 仍能改同一份 schema

变换：

```text
同一 Bearer token（database=[]，types.*.access=[readRecord]）

seed:
  CREATE PROPERTY Widget.injected_<flag> STRING
  V0: 200，schema 出现新属性
  V1: 403 not allowed to update schema

residual:
  DROP PROPERTY Widget.<PCB_FLAG>
  V1: 200，schema 上 flag 属性消失
  V2: 403
```

Snyk / GHSA 还指出 impact 不直接泄记录、但会破坏所有已存文档的含义（改类型名、继承、约束）。本 case 的效果通道是「种下的属性还在不在」，不读业务行。

---

## 残余仍然走同一条 HTTP 命令 + 同一把只读令牌（CVE-2026-54076）

没有换身份、没有换数据库、没有换命令接口。还是：

```http
POST /api/v1/command/pcb
Authorization: Bearer <readonly>
{ "command": "DROP PROPERTY Widget.<PCB_FLAG>" }
```

V1 的 `createProperty` 检查照样在；这条 SQL 不进那个方法。`dropProperty` 无检查，属性被删。本 case residual 与 seed 共用 oracle 的 token 铸造逻辑，只换 DDL。认证意图：v1 + `--residual` 观察到种下属性消失（wrong-flag 走 residual 通道，因为 seed 的「多一个属性」与 flag 字符串无关）。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：门闩原语已经存在；V1 只在一个 mutator 调用它；HTTP DDL 可以打到未加锁的兄弟方法，写同一份 schema。seed 被挡住只说明「不能再 CREATE PROPERTY」，不说明「只读身份不能突变 schema」。

---

## 后来又补了什么（CVE-2026-54076，26.6.1）

commit `2ee76fe`（*Require UPDATE_SCHEMA permission on all schema mutators (#4423)*）。26.6.1 release notes：*All LocalDocumentType/LocalProperty schema mutators now require the UPDATE_SCHEMA permission (previously only createProperty was gated).* `dropProperty`：

```java
// LocalDocumentType.dropProperty  (tag 26.6.1 / V2, L547–548)
  public Property dropProperty(final String propertyName) {
    checkForSchemaMutation();
    for (final TypeIndex index : getAllIndexes(true)) {
      ...
    }
    return recordFileChanges(() -> { ... });
  }
```

对残余输入：只读 token 在 helper 处失败，HTTP 403，种下的属性仍在。公开建议升到 26.6.1。helper 在 embedded、无绑定用户（启动加载、HA 复制）时 no-op，避免把内部路径误杀。即便如此，26.6.1 之后仍有后续 GHSA 给其它 mutator 补检查（例如 ALTER TYPE CUSTOM）；那是后话。本 benchmark 的 v2 只关闭 DROP PROPERTY 这条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是 `createProperty` 这一个入口。真正需要门闩的是「任何会 `recordFileChanges` 改类型定义的 public 方法」。V2 才把谓词提成共享 helper。

**不是没有 UPDATE_SCHEMA。**  
V1 已经会在创建时抛 *not allowed to update schema*。缺的是同样的调用点覆盖 DROP/ALTER。从 V1 的 diff 只能看到 `createProperty` 多了一行；要判断是否闭合，必须打开 `dropProperty` 和 `LocalProperty` setter，看它们是否调用同一检查。

**同一只读 token、同一 `/command`，只换 DDL 动词。**  
CREATE 被挡、DROP 放行，说明授权写在方法上而不是写在「这是不是 schema 语句」这一层。GHSA 把 DROP / ALTER TYPE / ALTER PROPERTY 并列，本 case 用 DROP 做可观察状态。

**seed 的 flag 出现方式与 residual 不同，但都是 schema 被只读身份改写。**  
seed：多一个属性（属性名带 flag 或 injected_ 前缀）。residual：种下的 flag 属性没了。wrong-flag 必须走 residual，因为 CREATE 成功与 flag 字符串无关。

---

## 版本、入口、参考

| | 镜像 | `createProperty` | `dropProperty` | CREATE PROPERTY seed | DROP PROPERTY residual |
|---|---|---|---|---|---|
| V0 | 26.3.2 | 无 UPDATE_SCHEMA | 无 | 200，新属性出现 | （不必） |
| V1 | 26.4.2 | 内联检查 | **无** | 403 | 200，种下属性消失 |
| V2 | 26.6.1 | `checkForSchemaMutation` | 同样 helper | 403 | 403 |

- Web：`POST /api/v1/command/pcb`，Bearer 为只读 API token
- 认证意图：v0 seed schema 被创建；v1 seed 403；v1 residual 种下属性被删
- [CVE-2026-44221 / GHSA-fxc7-fm93-6q77](https://github.com/ArcadeData/arcadedb/security/advisories/GHSA-fxc7-fm93-6q77)（advisory 正文是跨库授权；schema 单 mutator 检查以 GHSA-vg6x 的归因为准）
- [CVE-2026-54076 / GHSA-vg6x-6pg9-6qwg](https://github.com/ArcadeData/arcadedb/security/advisories/GHSA-vg6x-6pg9-6qwg)（*incomplete fix of CVE-2026-44221*）。NVD 条目撰写时仍为 RESERVED，以 GitHub Advisory 为准。
- [Snyk SNYK-JAVA-COMARCADEDB-18021396](https://security.snyk.io/vuln/SNYK-JAVA-COMARCADEDB-18021396)
- 修复提交：[2ee76fe](https://github.com/ArcadeData/arcadedb/commit/2ee76fe442b974b2482f1e9eddd1ab429bcac614)（PR `#4423`，26.6.1）
- [ArcadeDB 26.6.1 发布说明](https://arcadedb.com/blog/arcadedb-26-6-1/)：*All schema mutators now require the UPDATE_SCHEMA permission (previously only createProperty was gated).*
- V1 源码：tag [`26.4.2` LocalDocumentType.java](https://raw.githubusercontent.com/ArcadeData/arcadedb/26.4.2/engine/src/main/java/com/arcadedb/schema/LocalDocumentType.java)（`createProperty` L402–403；`dropProperty` L498–508）
