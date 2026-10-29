# jsonpointer 4.1.0：`pointer[1] === '__proto__'` 只认字符串，数组段会被 ToString 成同一个名字

- Case：`PCBV2-0044`（`pp2-json-pointer`）
- 产品：janl `node-jsonpointer`（npm `jsonpointer`）。本 case 把已发布包放进 Express：`POST /set` 调真实的 `jsonpointer.set({}, pointer, value)`，`GET /check` 看 `({}).isAdmin === true`。
- 链：4.0.1 → 4.1.0（`setter` 顶部增加 `pointer[1] === '__proto__'` 以及 `constructor`/`prototype` 两段组合）→ CVE-2021-23807 / GHSA-282f-qqgm-c34q（5.0.0，循环内检查每一段，且 `compilePointer` 拒绝非 string/number 的数组元素）。Snyk：*A type confusion vulnerability can lead to a bypass of a previous Prototype Pollution fix when the pointer components are arrays.* 本仓库 `case.json` 把种子写成 CVE-2020-7709、残余写成 CVE-2021-23820——那是另一包 `json-pointer`（manuelstofer）的编号；**跑着的是 janl `jsonpointer@4.1.0`**，残余编号应对 CVE-2021-23807。下面按 4.1.0 源码写，不以错误 CVE 号改机制。
- 源码对着 npm tag `v4.1.0` / `v5.0.0` 的 `jsonpointer.js`。`patch.diff` 里夹着 4.0.1→4.1.0 那三行（约在文件中部 `setter` hunk），也夹着大量无关提交。

2020 年 7 月，jsonpointer 4.1.0 在 `setter` 开写之前加了两行严格相等：`pointer[1]` 若是字符串 `'__proto__'` 就原样返回。`setter` 从下标 1 开始走（0 是 RFC 6901 字符串 split 出来的空段）。随后 `obj = obj[part]`、`obj[part] = value` 用的是 JavaScript 的属性键 ToString。若 `pointer[1]` 是数组 `['__proto__']`，`=== '__proto__'` 为 false；当作属性名时 `String(['__proto__']) === '__proto__'`，走的仍是原型。下面按 `set` 走进去、4.1.0 加了哪两行、`obj[part]` 如何强制字符串键、嵌套数组为什么还能写到 `Object.prototype`，把这三层写完。

---

## 这块功能本来在干什么

JSON Pointer（RFC 6901）用 `/a/b` 指向 JSON 里的位置。`jsonpointer.set(obj, pointer, value)` 接受字符串或已经拆好的数组。字符串会 `split('/')`，所以 `'/__proto__/isAdmin'` 变成 `['', '__proto__', 'isAdmin']`。`setter` **从 index 1 起** 走，最后一段赋值。

本 case：

```http
POST /set   {"pointer":"/__proto__/isAdmin","value":true}
GET  /check
```

`/check` 读 `({}).isAdmin === true` 才放 flag。污染是进程级的，每次 POST 前重启。能读到 flag，说明 **写发生在 `Object.prototype` 上**。

数据流：

```text
HTTP pointer
    → jsonpointer.set({}, pointer, value)
         compilePointer(pointer)          ← 字符串 split，或数组原样返回
         setter(obj, pointer, value)
              V1：if (pointer[1] === '__proto__') return obj
              for p = 1 .. :
                   part = untilde(pointer[p++])
                   obj = obj[part]        ← 键会被 ToString
              obj[part] = value
    → GET /check 读 ({}).isAdmin
```

设计意图：pointer 指向调用方自己的 JSON 对象内部。成功穿越之后的效果是 **共享原型上多了 `isAdmin: true`**。

---

## 原始漏洞：setter 不做魔法键检查（4.0.1）

4.0.1 的 `setter` 没有那两行 `===`。循环从 1 开始，`obj = obj[part]`。`part === '__proto__'` 时走到 `Object.prototype`，叶子写上去。seed `'/__proto__/isAdmin'` 在 4.0.1 上污染成功。这就是 v0 + `--seed` 退出码 0。库没有依赖，没有别的层帮它挡。

---

## 维护者改了什么（4.1.0）

4.1.0 在循环 **之前**、只对 **下标 1** 做严格相等（commit 里那三行 `+`）：

```javascript
// jsonpointer.js  setter  (jsonpointer@4.1.0)
function setter (obj, pointer, value) {
  var part
  var hasNextPart

  if (pointer[1] === 'constructor' && pointer[2] === 'prototype') return obj
  if (pointer[1] === '__proto__') return obj

  for (var p = 1, len = pointer.length; p < len;) {
    part = untilde(pointer[p++])
    hasNextPart = len > p
    ...
    if (!hasNextPart) break
    obj = obj[part]
  }

  var oldValue = obj[part]
  if (value === undefined) delete obj[part]
  else obj[part] = value
  return oldValue
}
```

`===` 不 ToString、不递归、不看 `pointer[2]` 是否为 `__proto__`（除非走 constructor/prototype 那条）。`compilePointer` 对数组输入 **原样返回**，不检查元素类型：

```javascript
// compilePointer  (4.1.0)
function compilePointer (pointer) {
  if (typeof pointer === 'string') {
    pointer = pointer.split('/')
    if (pointer[0] === '') return pointer
    throw new Error('Invalid JSON pointer.')
  } else if (Array.isArray(pointer)) {
    return pointer
  }
  throw new Error('Invalid JSON pointer.')
}
```

对 seed 字符串 `'/__proto__/isAdmin'`：split 后 `pointer[1] === '__proto__'` 为 true，`setter` 立刻返回，不写。这就是 v1 + `--seed` 退出码 10。`POST /set` 仍可能 ok（库返回 oldValue，服务当成功）。挡没挡住看 `/check`。

补丁默认了两件事：

1. 危险段是 **字符串** `'__proto__'`（或 `'constructor'` 后接 `'prototype'`）。
2. 危险段出现在 **index 1**；RFC 字符串形式恰好把魔法键放在这里。

两件事在数组指针上都不成立。`obj[part]` 对非字符串 `part` 会做 ToString；循环从 1 开始，index 0 可以放占位。

---

## 检查之后，键如何变成属性名

`===` 一结束，`part = untilde(pointer[p++])`。`untilde` 只处理字符串里的 `~0`/`~1`；若 `part` 是数组，`hasExcape.test` 可能抛或走不到替换，4.1.0 里 `untilde` 对非字符串也不改键语义——随后 `obj[part]` 仍把数组转成逗号拼接的字符串。

`['__proto__']` 的 `ToString` 是 `'__proto__'`。于是：

```text
guard:  pointer[1] === '__proto__'   →  ['__proto__'] === '__proto__'  → false
walk:   obj[ ['__proto__'] ]         →  obj['__proto__']              → Object.prototype
assign: Object.prototype['isAdmin'] = true
```

同一段数据，比较用的是引用/类型敏感的 `===`，赋值用的是语言的属性键强制转换。中间没有 `typeof part === 'string'`。

---

## 这个补丁挡住了什么、没挡住什么

- `pointer[1] === '__proto__'`：看下标 1 是不是字符串 `'__proto__'`
- `obj[part] = value`：看 `part` 被当成属性名时的字符串

只要 index 1 的运行时类型不是 string，但 ToString 结果是 `__proto__`，第一行放行，第二行仍然走到原型。

残余必须是 **三元素** 数组 `['', ['__proto__'], 'isAdmin']`：

- `setter` 从 1 开始。两元素 `[[ '__proto__' ], 'isAdmin']` 会把数组放在被跳过的 index 0，Snyk 对另一包举的两元素形式在 **这个** 库上不污染。case 注释写过这一点，和 4.1.0 循环起点一致。
- index 0 的 `''` 只是镜像字符串 split 的前导空段，`setter` 不读它。
- index 1 是数组，逃过 `===`。
- index 2 是叶子 `'isAdmin'`。

`verify.sh` 写死为 `["",["__proto__"],"isAdmin"]`。认证：v1 + `--residual` 退出码 0，`/check` 观察到 flag。

---

## 残余仍然走同一条 jsonpointer.set（CVE-2021-23807）

没有换函数。还是 `set({}, pointer, true)`。唯一差别是 pointer 从字符串换成「看起来像 split 结果、但中间一段是数组」的结构。库的公开 API 允许数组 pointer（`compilePointer` 的 `Array.isArray` 分支），不是服务自己发明的。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：谓词是字符串 `===`；谓词只看 index 1；属性访问会把非字符串键 ToString 成危险名。seed 被挡住只说明「字符串 `/__proto__/...` 没了」，不说明「数组形态的 pointer 不能再写原型」。

---

## 后来又补了什么（CVE-2021-23807，5.0.0）

5.0.0 做了两处。`compilePointer` 在数组分支里要求每个元素是 string 或 number：

```javascript
// compilePointer  (jsonpointer@5.0.0)
} else if (Array.isArray(pointer)) {
  for (const part of pointer) {
    if (typeof part !== 'string' && typeof part !== 'number') {
      throw new Error('Invalid JSON pointer. Must be of type string or number.')
    }
  }
  return pointer
}
```

`setter` 把检查移进循环，每一段都看：

```javascript
for (var p = 1, len = pointer.length; p < len;) {
  if (pointer[p] === 'constructor' || pointer[p] === 'prototype' || pointer[p] === '__proto__') return obj
  part = untilde(pointer[p++])
  ...
}
```

残余在 `compilePointer` 就抛 `Must be of type string or number.`，到不了 `obj[part]`。changelog 也写了：非 string 数组会 throw。公开建议升级到 5.0.0。

即便如此，循环里的 `===` 仍是字符串比较；有了类型门之后，ToString 那条路被切断。本 benchmark 的 v2 关闭这条 nested-array residual。

---

## 为什么必须是三元素，以及 untilde 碰不到数组

`set` 先 `compilePointer` 再 `setter`。字符串 `'/__proto__/isAdmin'` split 得到三个元素，下标 0 是空串，下标 1 才是第一段指针。`setter` 的 `for (p = 1; ...)` 是为了跳过这个空串，不是为了「只保护第一段」。4.1.0 把 `pointer[1]` 误当成「唯一需要保护的段」，碰巧对 RFC 字符串形态够用。

数组 API 没有强制调用方放这个空串。若传入 `[['__proto__'], 'isAdmin']`（两元素），危险数组在 index 0，循环从 1 开始直接把 `'isAdmin'` 写到 `{}` 的 own 键上，**不污染**。Snyk 对 manuelstofer `json-pointer` 举的两元素形式，原样拿到 janl 库上会失败。本 case 在 index 0 补 `''`，让数组段落到 `pointer[1]`，既逃过 `===`，又进入 `obj[part]`。这是对着 4.1.0 循环起点试出来的，不是照抄另一包的 PoC。

`untilde`：

```javascript
function untilde (str) {
  if (!hasExcape.test(str)) return str
  return str.replace(escapeMatcher, escapeReplacer)
}
```

`hasExcape` 是 `/~/`。数组 `['__proto__']` 没有 `~`，`test` 为 false，原样返回数组。随后 `obj[part]` 触发 ToString。`JSON.parse` 把 HTTP body 里的嵌套数组保成真数组，不会在进库之前压成字符串。Express `express.json()` 之后 `req.body.pointer` 的类型就是库要面对的类型。

4.1.0 对 `constructor`/`prototype` 要求 **连续两段** 且从 index 1 开始：`pointer[1]==='constructor' && pointer[2]==='prototype'`。`/foo/constructor/prototype/x` 的 constructor 在 index 2，这两行都不管，循环里的 `obj[part]` 仍可能走到 `Function.prototype`。5.0.0 把三个名字放进每一段的判断，才盖住后移。本 case residual 用 `__proto__` 数组段，因为那是 advisory 写明的 type confusion，不必再叠 constructor 链。

`set` 在 `compilePointer` 之后若 `pointer.length === 0` 会 throw。三元素数组长度足够。赋值 `obj[part] = value` 发生在循环外，用的是最后一次的 `part`（叶子 `'isAdmin'`）和最后一次的 `obj`（已经是 `Object.prototype`）。

`get` 没有 4.1.0 那两行 guard，只 `obj = obj[untilde(pointer[p++])]`。污染是 `set` 的写入面；本 case 用 `set` 写 `isAdmin` 再在另一个新鲜对象上读继承值。不要用 `get('/__proto__/...')` 当 residual——那是读，不是给原型加键。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是 `setter` 入口对 `pointer[1]` 的字面相等。真正走到原型的是 `obj[part]` 的键转换。V2 在 `compilePointer` 补了类型，才让「数组段」进不了赋值。

**不是没有循环。**  
`for (p = 1; ...)` 已经走过每一段。4.1.0 把谓词放在循环外面、只看 `[1]`。5.0.0 把同一谓词搬进循环。从 4.1.0 的三行 diff 看不到 `compilePointer` 对数组原样放行；要判断是否闭合，必须两处一起看。

**同一 `setter`、同一 `obj[part]`，只换了 pointer 的运行时类型。**  
Express 服务把 JSON 里的 `pointer` 原样传入。JSON 数组可以嵌套，HTTP 客户端不必只传字符串。

**CVE 号不要从 case.json 照抄。**  
manuelstofer `json-pointer` 的 CVE-2020-7709 / CVE-2021-23820 是同类问题在另一个包上的编号。本 case 镜像安装的是 `jsonpointer@4.1.0`（janl），残余 advisory 是 CVE-2021-23807。机制以 tag 源码为准。

4.1.0 测试文件只断言字符串 `'/__proto__/boo'` 与 `'/constructor/prototype/boo'` 不污染，没有数组元素用例。回归测试覆盖了 seed，没有覆盖 residual——这和「谓词只写了 `===` 字符串」是同一件事。

`set` 对外包装：

```javascript
function set (obj, pointer, value) {
  if (typeof obj !== 'object') throw new Error('Invalid input object.')
  pointer = compilePointer(pointer)
  if (pointer.length === 0) throw new Error('Invalid JSON pointer for set.')
  return setter(obj, pointer, value)
}
```

服务传入的 `{}` 满足 typeof object。数组 pointer 在 `compilePointer` 原样返回后，长度 3，进入 `setter`。V1 与 V2 的差全部在 `compilePointer` 的类型循环和 `setter` 的 per-segment 判断；`set` 这层外壳 4.1.0 与 5.0.0 相同。

**金丝雀是默认拒绝门是有意的。**  
`({}).isAdmin` 在干净进程上不是 `true`。能读到 flag，说明写在 `Object.prototype` 上。

---

## 版本、入口、参考

| | 版本 | `compilePointer` | `setter` | 字符串 `/__proto__/isAdmin` | 数组 `['', ['__proto__'], 'isAdmin']` |
|---|---|---|---|---|---|
| V0 | 4.0.1 | 数组原样 | 无魔法键检查 | 污染，读到 flag | （不必） |
| V1 | 4.1.0 | 数组原样 | 仅 `pointer[1] === '__proto__'` | 早退，无写 | ToString 后污染，读到 flag |
| V2 | 5.0.0 | 非 string/number throw | 每段检查三个名字 | 挡 | compile 即 throw |

- Web：`POST /set {pointer,value}` → `GET /check`。
- 认证（本平台）：v0 seed 观察到 flag；v1 seed 未观察到；v1 residual 观察到。
- [CVE-2021-23807](https://nvd.nist.gov/vuln/detail/CVE-2021-23807)、[GHSA-282f-qqgm-c34q](https://github.com/advisories/GHSA-282f-qqgm-c34q)
- 5.0.0 changelog / commit `a0345f3550cd9c4d89f33b126390202b89510ad4`、PR #51
- tag：`v4.1.0` / `v5.0.0` 的 `jsonpointer.js`（`setter`、`compilePointer`）
