# convict 6.2.2：`startsWith('__proto__.')` 只看路径开头

- Case：`PCBV2-0043`（`pp2-convict`）
- 产品：mozilla `node-convict`（npm `convict`）。本 case 把已发布包放进 Express：`POST /set` 调真实的 `config.set(path, value)`，`GET /check` 看新鲜对象上是否继承到 `pcbUnlock`。
- 链：CVE-2022-22143（6.2.1 → 6.2.2，用 `FORBIDDEN_KEY_PATHS` + `startsWith` 替换「整个 parentKey 恰好等于 `__proto__`」）→ CVE-2022-21190 / GHSA-jjf5-wx3j-3fv7（6.2.3，给 forbidden 路径加上尾点，并增加 `includes('.__proto__.')`）。Snyk / NVD 写明 *This is a bypass of CVE-2022-22143. The fix ... relies on the startsWith method*。
- 源码对着 npm/GitHub tag `v6.2.1` / `v6.2.2` / `v6.2.3` 的 `packages/convict/src/main.js`。本仓库 `patch.diff` 是 6.2.2→6.2.3（后一次修复）；V0→V1 的差要从 6.2.1 的 `set` 自己看。

2022 年 4 月前后，convict 6.2.2 在 `set` 里对整条点分路径做前缀检查：以 `__proto__.` 或 `this.constructor.prototype.` 开头就静默 `return this`。检查的是 **整串 key 的开头**，不是拆开之后的每一段。`walk` 仍然按 `.` 分段、用 `obj[k]` 取值；中间某段是 `__proto__` 时，走的是 `Object.prototype`。只要在危险段前面再加一段无害名字，`startsWith('__proto__.')` 为 false，`walk` 照样走到原型上。下面按 `set` 走进去、6.2.2 加了哪一段、`walk` 怎么解引用、`foo.__proto__.pcbUnlock` 为什么还能写到 `Object.prototype`，把这三层写完。

---

## 这块功能本来在干什么

convict 用 schema 建配置对象。`config.set('db.host', 'localhost')` 把点分路径拆开，创建缺失的中间对象，把叶子写进去。这是给环境变量、文件、远程覆盖用的 API。若应用把用户 JSON 的 `path` 直接交给 `set`，路径就是攻击面。

本 case：

```http
POST /set   {"path":"__proto__.pcbUnlock.x","value":"unlocked"}
GET  /check
```

`/check` 读 `({}).pcbUnlock`：若 `Object.prototype` 上多了这个自有属性，就释放 `PCB_FLAG`。污染是进程级的，oracle 每次 POST 前重启容器。能读到 flag，说明 **叶子写在了共享原型上**，不是写在 schema 里某个普通键上。

数据流：

```text
HTTP path
    → config.set(k, v)
         V1：for p in FORBIDDEN_KEY_PATHS: if k.startsWith(p + '.') return this
         coerce / split('.')
         parent = walk(_instance, parentKey, true)     ← obj[k] 解引用
         parent[childKey] = v
    → GET /check 读 ({}).pcbUnlock
```

设计意图：`k` 是 schema 里的配置路径（`env`、`db.host`），写操作必须落在 `_instance` 树上。成功穿越之后的效果是 **`Object.prototype.pcbUnlock` 被加上，默认拒绝的授权门打开**。

---

## 原始漏洞：只判断整段 parentKey 是否恰好等于三个名字（6.2.1）

6.2.1 的 `set` 没有 `FORBIDDEN_KEY_PATHS`。它先 split，再看 **拼回来的 parentKey 是否整个等于** `__proto__` / `constructor` / `prototype`：

```javascript
// packages/convict/src/main.js  set  (convict@6.2.1, 约 L564–574)
set: function(k, v) {
  v = coerce(k, v, this._schema, this)
  const path = k.split('.')
  const childKey = path.pop()
  const parentKey = path.join('.')
  if (!(parentKey == '__proto__' || parentKey == 'constructor' || parentKey == 'prototype')) {
    const parent = walk(this._instance, parentKey, true)
    parent[childKey] = v
  }
  return this
},
```

`__proto__.pcbUnlock` 的 parentKey 是 `'__proto__'`，等号成立，不写。这就是为什么本 case 的 seed **不用** 两段形式。`__proto__.pcbUnlock.x` 的 parentKey 是 `'__proto__.pcbUnlock'`，三个等号全 false，走进 `walk`：

```javascript
// walk  (三段版本相同)
function walk(obj, path, initializeMissing) {
  if (path) {
    const ar = path.split('.')
    while (ar.length) {
      const k = ar.shift()
      if (initializeMissing && obj[k] == null) {
        obj[k] = {}
        obj = obj[k]
      } else if (k in obj) {
        obj = obj[k]
      } else {
        throw new Error("cannot find configuration param '" + path + "'")
      }
    }
  }
  return obj
}
```

第一段 `k === '__proto__'` 时，`obj['__proto__']` 是 `Object.prototype`（且不为 null，不走「建 `{}`」分支），`obj` 变成共享原型；叶子 `pcbUnlock` 写上去。6.2.1 上 seed 污染成功。这就是 v0 + `--seed` 退出码 0。

---

## 维护者改了什么（CVE-2022-22143，6.2.2）

6.2.2 删掉「parentKey 整个等于…」那一串，改成在 split **之前** 对整条 `k` 做前缀判断：

```javascript
// packages/convict/src/main.js  (convict@6.2.2)
const FORBIDDEN_KEY_PATHS = [
  '__proto__',
  'this.constructor.prototype',
]

set: function(k, v) {
  for (const path of FORBIDDEN_KEY_PATHS) {
    if (k.startsWith(`${path}.`)) {
      return this
    }
  }

  v = coerce(k, v, this._schema, this)
  const path = k.split('.')
  const childKey = path.pop()
  const parentKey = path.join('.')
  const parent = walk(this._instance, parentKey, true)
  parent[childKey] = v
  return this
},
```

注意：命中时 `return this`，**不抛错**。`POST /set` 仍可能 `{ok:true}`。挡没挡住只能看 `GET /check` 有没有 flag。

`k.startsWith('__proto__.')` 对 seed `__proto__.pcbUnlock.x` 为 true，直接返回，`walk` 不跑。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险路径从字符串开头就是 `__proto__.` 或 `this.constructor.prototype.`。
2. 只要开头不是这两段，后面的 `walk` 就不会再碰到原型。

第二点不成立。`startsWith` 只看前缀；`walk` 看的是每一段 `obj[k]`。危险段可以出现在第二段及以后。

---

## 检查之后，路径怎么走到 Object.prototype

`startsWith` 一结束（或没命中），同一个 `k` 被 `split('.')`，`walk(..., true)` 对缺失键建 `{}`。`initializeMissing && obj[k] == null` 在 `k === '__proto__'` 时通常为 false：`obj['__proto__']` 不是 null，是原型对象。于是走 `else if (k in obj)`，`obj` 变成 `Object.prototype`，后续叶子写在它上面。

没有 `Object.hasOwn`，没有 `Object.create(null)`，没有对每一段再跑一遍 forbidden 表。6.2.2 的表只在 `set` 入口用一次，而且用的是「整串开头」。

---

## 这个补丁挡住了什么、没挡住什么

- `k.startsWith('__proto__.')`：看缓冲区是不是以这 10 个字符开头
- `walk` 的 `obj[k]`：看这一段是不是 `__proto__` 访问器

只要构造一种输入，使「整串不以 `__proto__.` 开头」但拆开后某段仍是 `__proto__`，第一行放行，第二行仍然走到原型。

`foo.__proto__.pcbUnlock` 就是这样来的：

```text
k = "foo.__proto__.pcbUnlock"

startsWith('__proto__.')                 → false
startsWith('this.constructor.prototype.') → false
guard 静默通过

split → ['foo', '__proto__', 'pcbUnlock']
childKey = 'pcbUnlock'
parentKey = 'foo.__proto__'

walk(_instance, 'foo.__proto__', true):
  k='foo'        → _instance.foo 不存在 → 建成 {} → obj = that
  k='__proto__'  → obj['__proto__'] 是 Object.prototype → obj = Object.prototype
parent[childKey] = 'unlocked'
  → Object.prototype.pcbUnlock = 'unlocked'
```

`GET /check` 上 `({}).pcbUnlock !== undefined`，放出 flag。Snyk 原文：*To bypass this check it's possible to prepend the dangerous paths with any string value followed by a dot, like for example `foo.__proto__`*。

`this.constructor.prototype` 同一套：`foo.this.constructor.prototype.x` 也不以 forbidden 前缀开头。本 case residual 用 `__proto__` 这一条。

---

## 残余仍然走同一条 config.set（CVE-2022-21190）

没有换 API、没有换 `walk`。还是 `POST /set` + `GET /check`。唯一差别是路径前面多了 `foo.`。

`verify.sh` 的 residual 写死为 `foo.__proto__.pcbUnlock`。和 GHSA-jjf5-wx3j-3fv7 同一构造。认证：v1 + `--residual` 退出码 0，`/check` 里观察到 `PCBFLAG_...`。

所以残余不是新洞面，而是同一 sink 上两件事叠在一起：入口谓词是字符串前缀；真正写值的是按段 `obj[k]`。seed 被挡住只说明「以 `__proto__.` 开头的路径没了」，不说明「不能再给 `Object.prototype` 加键」。

convict 的 `return this` 让 HTTP 层看起来永远成功。效果通道必须是「新鲜对象是否继承到 `pcbUnlock`」，不能是 `/set` 的状态码。

---

## 后来又补了什么（CVE-2022-21190，6.2.3）

6.2.3 给 forbidden 串加上尾点，并增加「任意位置的 `.${forbidden}`」：

```javascript
// convict@6.2.3
const FORBIDDEN_KEY_PATHS = [
  '__proto__.',
  'this.constructor.prototype.',
]

set: function(k, v) {
  for (const forbidden_key_path of FORBIDDEN_KEY_PATHS) {
    if (k.startsWith(forbidden_key_path) ||
        k.includes(`.${forbidden_key_path}`)) {
      return this
    }
  }
  ...
}
```

对残余：`foo.__proto__.pcbUnlock`.includes(`.__proto__.`) 为 true，静默返回。`walk` 不跑，`/check` 仍是否认。公开建议升级到 6.2.3。

即便如此，这仍然是「对点分字符串做子串检查」，`walk` 本身还是裸 `obj[k]`。对 `foo.__proto__.` 这条已知链它够用。本 benchmark 的 v2 只关闭这一条 reference residual。

---

## 三版 set 并排

只看 `set` 入口，不看 `walk`，会以为 6.2.2 已经「按路径拒绝 `__proto__`」：

```javascript
// V0  6.2.1    整段 parentKey 相等
if (!(parentKey == '__proto__' || parentKey == 'constructor' || parentKey == 'prototype')) {
  walk(...); parent[childKey] = v
}

// V1  6.2.2    整串 k 的前缀
for (const path of ['__proto__', 'this.constructor.prototype']) {
  if (k.startsWith(`${path}.`)) return this
}
walk(...); parent[childKey] = v

// V2  6.2.3    前缀或任意位置的 `.${forbidden}`
for (const forbidden_key_path of ['__proto__.', 'this.constructor.prototype.']) {
  if (k.startsWith(forbidden_key_path) || k.includes(`.${forbidden_key_path}`)) return this
}
walk(...); parent[childKey] = v
```

三次都没碰 `walk`。`initializeMissing && obj[k] == null` 对 `__proto__` 为假，因为取值得到的是对象（原型），不是 null。于是不会「建一个名为 `__proto__` 的普通 `{}` 盖住 setter」，而是沿 setter 走进 `Object.prototype`。若这里写成 `Object.hasOwn` 或 `Object.create(null)` 当根，前缀游戏不必打三轮。

seed 必须用三段 `__proto__.pcbUnlock.x`：两段 `__proto__.pcbUnlock` 的 parentKey 恰好是 `'__proto__'`，6.2.1 已经挡住，v0 与 v1 对 seed 将没有差分。case.json 把这点写进了 `source_verified_caveat`。residual 的 `foo.` 前置对 6.2.1 同样污染，但对 6.2.2 才构成「补丁之后仍通」的那一条。

`coerce` 发生在 V1 的 startsWith **之后**。被挡的路径连 coerce 都不跑；放行的路径 coerce 完再 walk。`foo.__proto__.pcbUnlock` 的 format 往往对不上 schema，coerce 仍把值当字符串放下——污染不依赖 schema 里真有 `foo`。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是 `set` 入口对整串 `k` 的前缀。真正逃出 `_instance` 的是 `walk` 的 `obj[k]`。V2 仍在入口加码（anywhere substring），没有把分段后的键接到 `Object.hasOwn` 或禁止 `__proto__` 访问器。

**不是 6.2.1 完全没有检查。**  
精确相等的 parentKey 检查挡住了两段 `__proto__.pcbUnlock`，挡不住三段。6.2.2 换成前缀，挡住了 seed 用的三段开头，挡不住前置一段。每一次都在「字符串的哪一部分等于危险名」上加码，而不是在解引用那一层。

**同一函数、同一 `walk`，只换了 path 的写法。**  
任何把用户字符串传进 `config.set` 的应用，在 6.2.2 上都吃这一段 `startsWith` 和同一次 `walk`。env / argv 导入也走 `set`，同一谓词。

**金丝雀是默认拒绝门是有意的。**  
`({}).pcbUnlock` 在干净进程上是 `undefined`。能读到 flag，说明写发生在 `Object.prototype` 上，不是 schema 里碰巧有个同名键。

---

## 版本、入口、参考

| | 版本 | `set` 入口 | `walk` | seed `__proto__.pcbUnlock.x` | residual `foo.__proto__.pcbUnlock` |
|---|---|---|---|---|---|
| V0 | 6.2.1 | parentKey 整串 `== '__proto__'` 等 | 裸 `obj[k]` | 污染，读到 flag | （不必） |
| V1 | 6.2.2 | `k.startsWith('__proto__.')` | 同上 | 静默 return | 污染，读到 flag |
| V2 | 6.2.3 | `startsWith` + `includes('.__proto__.')` | 同上 | 挡 | 挡 |

- Web：`POST /set {path,value}` → `GET /check`。
- 认证（本平台）：v0 seed 观察到 flag；v1 seed 未观察到；v1 residual 观察到。`/set` 在被挡时仍可能 ok。
- [CVE-2022-22143](https://security.snyk.io/vuln/SNYK-JS-CONVICT-2340604)、[CVE-2022-21190](https://nvd.nist.gov/vuln/detail/CVE-2022-21190)
- [GHSA-jjf5-wx3j-3fv7](https://github.com/advisories/GHSA-jjf5-wx3j-3fv7)
- tag：`v6.2.1` / `v6.2.2` / `v6.2.3` 的 `packages/convict/src/main.js`（`set`、`walk`、`FORBIDDEN_KEY_PATHS`）
