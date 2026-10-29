# AdonisJS bodyparser：根对象换成了 null-proto，lodash.set 仍会造出带原型的中间层

- Case：`PCBV2-0073`
- 产品：npm `@adonisjs/bodyparser`（AdonisJS 的 HTTP 请求体解析中间件）
- 链：CVE-2026-25754（10.1.2 → 10.1.3/10.1.4，commit `40e1c71`）→ CVE-2026-48795（10.1.3–10.1.4 → 10.1.5，commit `8a85eb0`）
- 源码对着 GitHub tag `v10.1.4` / `v10.1.5` 的 `src/form_fields.ts`：`FormFields.add`、`#fields`。运行时装的是发布包本身，multipart 字段名原样当 lodash 路径。

2026 年 2 月，bodyparser 把 `FormFields` 的内部存储从普通 `{}` 换成 `Object.create(null)`，想挡住 multipart 字段名 `__proto__.polluted`。GHSA-qcm7-3vpr-hj5h 写明：*The original patch … preventing direct payloads such as `__proto__.polluted`. However, payloads containing a non-dangerous segment before `__proto__` or `constructor.prototype`, such as `user.__proto__.polluted`, still lead to Object.prototype pollution.* NVD CVE-2026-48795 原话也是 *incompletely fixed CVE-2026-25754 because nested multipart field payloads … still caused lodash `_.set()` … to create plain intermediate objects*。

根因不只是「忘了嵌套」。检查插在**根对象有没有 `Object.prototype`** 这一层；真正写属性的是 `lodash.set(#fields, key, value)`，缺的中间段会新建普通 `{}`。下面按请求走进去、10.1.4 改了哪一行、set 之后谁消费那个路径、更强的段名白名单有没有挂上，把这几层写完。

---

## 这块功能本来在干什么

AdonisJS 的 `BodyParserMiddleware` 解析 `multipart/form-data`、urlencoded、JSON。multipart 的**字段名**不是当普通字符串存，而是当对象路径展开：`user.name` 变成 `{ user: { name: ... } }`，`tags[]` 变成数组。展开发生在 `FormFields.add`。

一次典型请求（本 case 的 `/probe` 走真实中间件）：

```http
POST /probe HTTP/1.1
Content-Type: multipart/form-data; boundary=----pcb

------pcb
Content-Disposition: form-data; name="username"
...
```

数据流：

```text
HTTP multipart 字段名 + 字段值
    → BodyParserMiddleware.handle
    → Multipart.process → #handleField
    → FormFields.add(key, value)
         V1：#fields = Object.create(null)   ← 补丁只改了根对象
         lodash.get(#fields, key)
         lodash.set(#fields, key, value)     ← 真正写属性，路径仍是用户字符串
    → FormFields.get() 交给下游
    → 本 case 在**另一个全新空对象**上读 ({}).pcbPolluted
         污染成功则 canary_value = PCBFLAG_...
```

设计意图：字段名是表单键（`username`、`user.email`），值落到请求体对象上，**不应该**改到 `Object.prototype`。没有登录。成功穿越之后的效果是：进程全局的 `Object.prototype.pcbPolluted` 变成攻击者给的字段值；之后任意 `{}` 都能读到金丝雀。本 case 用独立 worker 解析，只反射 `( {}).pcbPolluted`，不回显解析后的 body，所以 flag 出现当且仅当原型被写到。

---

## 原始漏洞：明文 `__proto__` 当 lodash 路径（CVE-2026-25754，10.1.2）

10.1.2 的存储是普通对象：

```ts
// src/form_fields.ts  (v10.1.2 / V0)
export class FormFields {
  #fields: any = {}
```

`add` 把字段名原样交给 lodash：

```ts
// src/form_fields.ts :: FormFields.add
    key = key.replace(/\[]$/, () => {
      isArray = true
      return ''
    })

    const existingValue = lodash.get(this.#fields, key)
    if (!existingValue) {
      lodash.set(this.#fields, key, isArray ? [value] : value)
      return
    }
```

对普通 `{}`，`lodash.set(obj, '__proto__.pcbPolluted', flag)` 会沿着 `__proto__` 走到 `Object.prototype`，再赋 `pcbPolluted`。GHSA-f5x2-vj4h-vg4c / CVE-2026-25754 的问题就是：未认证的 multipart 请求可以污染进程全局原型。本 case 的 seed：

```text
field_name  = __proto__.pcbPolluted
field_value = <PCB_FLAG>
```

10.1.2 之后 `( {}).pcbPolluted === <FLAG>`。这是 v0 + `--seed` 能观察到 flag 的路径。回归测试后来也只覆盖了这种**直接**段：`__proto__.polluted`、`constructor.prototype.polluted`。

---

## 维护者改了什么（CVE-2026-25754 修复，10.1.3/10.1.4）

commit `40e1c71`（*fix: prevent prototype pollution via multipart field names*）只动了一行初始化，10.1.4 的源码是：

```ts
// src/form_fields.ts  (v10.1.4 / V1)
export class FormFields {
  #fields: any = Object.create(null)
  #config: { convertEmptyStringsToNull: boolean }

  constructor(config: { convertEmptyStringsToNull: boolean }) {
    this.#config = config
  }
```

`add` 的路径处理**一字未改**：去掉尾部 `[]` 之后立刻 `lodash.get` / `lodash.set`。配套测试只断言直接 `__proto__` 和 `constructor.prototype` 不会污染空对象。

对 seed 这种明文 `__proto__.pcbPolluted`，它确实够用：null-proto 的根对象没有 `[[Prototype]]`，`__proto__` 变成自己的 own key，写不到 `Object.prototype`。`({}).pcbPolluted` 仍是 `undefined`。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险形态长得像「路径的第一段就是 `__proto__` / `constructor.prototype`」。
2. 只要根对象没有原型，后面的 `lodash.set` 就不会再碰到 `Object.prototype`。

第二点不成立。lodash 在路径上缺中间容器时，会 `obj[seg] = {}` 造一个**普通对象**。那个普通对象的 `__proto__` 又是 `Object.prototype`。

---

## 消毒之后，字段名怎么接到真正的赋值上

V1 的 `Object.create(null)` 一结束，同一个 `add` 立刻把用户字符串当路径：

```ts
// src/form_fields.ts :: FormFields.add  (v10.1.4)
    key = key.replace(/\[]$/, () => {
      isArray = true
      return ''
    })

    const existingValue = lodash.get(this.#fields, key)
    if (!existingValue) {
      lodash.set(this.#fields, key, isArray ? [value] : value)
      return
    }
    if (Array.isArray(existingValue)) {
      existingValue.push(value)
      return
    }
    lodash.set(this.#fields, key, [existingValue, value])
```

过滤器刚看过的是「`#fields` 自己有没有原型」；`lodash.set` 看到的是点号拆开的段列表。两套语义中间没有「段名不得叫 `__proto__`」的谓词。

lodash（经 `@poppinss/utils/lodash`）对缺失的中间段用字面量 `{}` 建对象。对路径 `user.__proto__.pcbPolluted`：

```text
#fields                     Object.create(null)   ← V1 改过
#fields.user                不存在 → 新建 {}     ← 普通对象，带 Object.prototype
#fields.user['__proto__']   解析成 Object.prototype
Object.prototype.pcbPolluted = <FLAG>
```

本 case 的 worker 在**另一次** `{}` 上读 `pcbPolluted`。金丝雀能出现在 `/probe` 的 `canary_value` 里，依据就是这一步：污染发生在进程全局原型上，不依赖解析结果有没有被回显。

---

## 仓库里已经有路径展开，却没有段名检查

同一份 `form_fields.ts` 里，字段名已经被当成路径：尾部 `[]` 会剥掉，注释写明要迁就 `_.set` / `_.get`。V1 没有、V0 也没有「拆段之后丢掉危险名字」的逻辑。

| 位置 | 看什么 | 拦 `__proto__`？ |
|---|---|---|
| `#fields = Object.create(null)` | 根对象的原型 | 只拦**第一段**是 `__proto__` 的情况 |
| `key.replace(/\[]$/, …)` | 数组语法 | 否 |
| `lodash.get` / `lodash.set` | 整条路径 | 否，缺段时造 `{}` |
| `FormFields.get()` | 把 `#fields` 交出去 | 否 |

不是没有路径解析。是 **解析之后没有把危险段当非法名丢掉**。V1 等于在调用 `set` 之前把根换成了更安全的对象，却继续把攻击者字符串交给会自己造普通对象的 `set`。

即便没有 `user.__proto__`，`constructor.prototype` 嵌在任意良性段后面也是同一条路。GHSA 把这两种都点名了。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「根对象 vs 中间对象 vs 真正赋值」落到具体变换。

- `#fields = Object.create(null)`：看根上有没有 `Object.prototype`
- `lodash.set(path)`：按 `.` / `[n]` 走段；缺的中间段用 `{}` 填
- 消费者：之后任意字面量 `{}` 的继承属性

只要构造一种输入，使「第一段不是危险名、后面某段是 `__proto__`」，根上的 null-proto 无事可做，`set` 会在第一段造出带原型的对象。

GHSA-qcm7-3vpr-hj5h 给的例子就是 `user.__proto__.polluted`。本 case residual：

```text
field_name:  user.__proto__.pcbPolluted
field_value: <PCB_FLAG>

V1 add():
  根 #fields 仍是 null-proto
  lodash.set 建 #fields.user = {}
  再沿 user.__proto__ 写到 Object.prototype.pcbPolluted

worker 读 ({}).pcbPolluted → <FLAG>
```

直接 `__proto__.pcbPolluted` 在 V1 变成 own key `__proto__`，污染失败。嵌套写法里 `__proto__` 不再是第一段，V1 那一行初始化根本看不到它。

---

## 残余仍然走同一条 multipart → FormFields.add 路径（CVE-2026-48795）

没有换接口、没有换字段、没有换身份。还是：

```http
POST /probe
Content-Type: multipart/form-data
name="user.__proto__.pcbPolluted"
```

`BodyParserMiddleware` 仍然把字段名交给 `FormFields.add`。V1 的 null-proto 根照样生效；生效完之后 lodash 在 `user` 上建了普通 `{}`，污染再次发生。本 case residual 写死为：

```text
field_name = "user.__proto__.pcbPolluted"
```

和 advisory 的 `user.__proto__.polluted` 同一构造，只是属性名换成金丝雀键 `pcbPolluted`。认证意图：v1 + `--residual` 在 `/probe` JSON 的 `canary_value` 里观察到 `PCBFLAG_...`。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：补丁只加固了根对象；真正赋值的 `lodash.set` 会为缺失段分配普通 `{}`；消费者读的是进程全局原型，不是 `#fields` 自己。seed 被挡住只说明「第一段 `__proto__` 不再能碰到 `Object.prototype`」，不说明「任意段都不能叫 `__proto__`」。

---

## 后来又补了什么（CVE-2026-48795，10.1.5）

commit `8a85eb0`（*fix: prevent nested prototype pollution*）在 `lodash.set` **之前**按段丢掉危险名。tag `v10.1.5`：

```ts
// src/form_fields.ts  (v10.1.5 / V2)
const PROTOTYPE_POLLUTING_KEYS = new Set(['__proto__', 'prototype', 'constructor'])

  add(key: string, value: any): void {
    ...
    key = key.replace(/\[]$/, () => {
      isArray = true
      return ''
    })

    if (lodash.toPath(key).some((segment) => PROTOTYPE_POLLUTING_KEYS.has(segment))) {
      return
    }

    const existingValue = lodash.get(this.#fields, key)
    if (!existingValue) {
      lodash.set(this.#fields, key, isArray ? [value] : value)
```

对残余输入：`toPath('user.__proto__.pcbPolluted')` 含 `__proto__`，`add` 直接 return，`set` 不跑，`( {}).pcbPolluted` 仍是 `undefined`。公开建议是升级到 `@adonisjs/bodyparser@10.1.5`（以及 11.x 的 11.0.3）。即便如此，若下游自己再对解析结果做一次 `_.set`，需要另证。本 benchmark 的 v2 只关闭这一条 nested-segment residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是 `#fields` 的原型。真正把用户字符串写进对象图的是 `lodash.set`。V2 才回到 `add()` 入口，在 set 之前按段拒绝。`40e1c71` 的 diff 里看不到 `toPath`。

**不是没有路径解析。**  
`[]` 处理和 `_.get`/`_.set` 从 V0 就在。缺的是「路径段不得叫 `__proto__` / `prototype` / `constructor`」。从 V1 的 diff 只能看到 `Object.create(null)`；要判断补丁是否闭合，必须看到 lodash 如何为 `user` 分配 `{}`，以及污染发生在 `Object.prototype` 而不是 `#fields` 自身。

**同一函数、同一字段名，只换了路径前缀。**  
任何把 multipart / urlencoded 字段名传进 `FormFields.add` 的路由，在 10.1.4 上都吃同一次 `set`。advisory 写明默认配置、未认证即可。

**回归测试和补丁一样窄。**  
V1 的测试只覆盖直接 `__proto__` 和 `constructor.prototype`。嵌套写法当时没有用例，所以「根换成 null-proto」看起来已经绿了。

---

## 版本、入口、参考

| | npm | `#fields` | `FormFields.add` | `__proto__.x` seed | `user.__proto__.x` residual |
|---|---|---|---|---|---|
| V0 | 10.1.2 | `{}` | 无段检查，直接 `lodash.set` | 污染 Object.prototype | （不必） |
| V1 | 10.1.4 | `Object.create(null)` | 同上，仍无段检查 | 变成 own key，不污染 | 中间 `{}` 再污染 |
| V2 | 10.1.5 | 仍是 null-proto | `toPath` 含危险段则 return | 挡 | 挡 |

- Web：`POST /probe`，multipart 字段名即 lodash 路径，字段值即 flag
- 认证意图：v0 seed 的 `canary_value` 为 flag；v1 seed 为 null；v1 residual 为 flag
- [CVE-2026-25754](https://nvd.nist.gov/vuln/detail/CVE-2026-25754)、[GHSA-f5x2-vj4h-vg4c](https://github.com/adonisjs/core/security/advisories/GHSA-f5x2-vj4h-vg4c)
- [CVE-2026-48795](https://nvd.nist.gov/vuln/detail/CVE-2026-48795)、[GHSA-qcm7-3vpr-hj5h](https://github.com/advisories/GHSA-qcm7-3vpr-hj5h)
- 修复提交：[40e1c71](https://github.com/adonisjs/bodyparser/commit/40e1c71f958cffb74f6b91bed6630dca979062ed)（10.1.3/10.1.4）、[8a85eb0](https://github.com/adonisjs/bodyparser/commit/8a85eb0c2061b0caca10faedbfc2cf24b56cf9f6)（10.1.5）
- 源码：tag [`v10.1.4`](https://github.com/adonisjs/bodyparser/blob/v10.1.4/src/form_fields.ts)、[`v10.1.5`](https://github.com/adonisjs/bodyparser/blob/v10.1.5/src/form_fields.ts)
