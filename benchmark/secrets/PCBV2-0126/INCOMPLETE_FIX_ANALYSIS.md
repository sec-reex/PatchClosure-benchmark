# Handlebars：lookup helper 走了 lookupProperty，strict 终端还在 `obj[name]`

- Case：`PCBV2-0126`
- 产品：handlebars.js。运行时是 npm `handlebars@4.5.2` / `4.7.6` / `4.7.7` 整包，HTTP harness `POST` 未信任模板。
- 链：CVE-2019-20920（4.5.2 → 4.7.6，`lookup` 改走 `options.lookupProperty`）→ CVE-2021-23369（4.7.6 → 4.7.7，commit `b6d3de7`，`container.strict` 改走 `lookupProperty`）
- 源码对着 tag `v4.7.6` 的 `lib/handlebars/helpers/lookup.js`、`lib/handlebars/runtime.js`（`container.strict` / `lookupProperty`）、`lib/handlebars/internal/proto-access.js`。金丝雀是 `Ctx.prototype.pcbCanary = $PCB_FLAG`，模板读到非 own 属性才出现在渲染结果里。

GHSA-3cqr-58rm-57f8（2019-20920）说 lookup helper 没有正确校验模板，允许执行任意 JS，并且是 *incomplete fix for a previous issue*。CVE-2021-23369 / SNYK-JS-HANDLEBARS-1056767：*when selecting certain compiling options to compile templates coming from an untrusted source*。修复 commit `b6d3de7` 标题就是 *check prototype property access in strict-mode*，回归测试加了 `describe('in strict-mode', ...)`。

根因不只是「strict 模式少写一行」。检查插在 helper 和默认路径解析上；编译器在 `{strict:true}` 时把**最后一段**发给另一个函数 `container.strict`。同一次 `template()` 里已经有 `lookupProperty`（own + proto 白名单）。下面按请求走进去。

---

## 这块功能本来在干什么

Handlebars 把模板字符串编译成对 context 的属性读取。未信任模板如果能读到原型链上的 `constructor` / `__proto__`，历史上就是 RCE 面。一次典型渲染：

```javascript
Handlebars.compile(userTemplate)(ctx)
// 或
Handlebars.compile(userTemplate, {strict: true})(ctx)
```

本 case harness 接收 JSON `{template, strict}`，用真实 handlebars 渲染。context 是 `new Ctx()`，**own 属性没有 `pcbCanary`**，值在 `Ctx.prototype` 上。

设计意图：默认禁止原型访问；模板只能读 own 属性。成功穿越之后的效果是：**渲染输出里出现原型上的金丝雀**。

数据流（V1 = 4.7.6）：

```text
POST {template, strict}
    → Handlebars.compile(template, {strict})
         默认路径 / lookup helper → container.lookupProperty
         strict 终端段 → container.strict(obj, name)
    → 渲染字符串
```

没有登录。判断完全信任运行时那几条 lookup 函数，不信任编译器会不会给某一段开后门。

---

## 原始漏洞：lookup helper 直接 `obj[field]`（CVE-2019-20920，4.5.2）

4.5.2 的 lookup helper 只对 `constructor` 做了 `propertyIsEnumerable` 这种弱判断，然后原生读取：

```javascript
// lib/handlebars/helpers/lookup.js  (handlebars v4.5.2)
instance.registerHelper('lookup', function(obj, field) {
  if (!obj) {
    return obj;
  }
  if (String(field) === 'constructor' && !obj.propertyIsEnumerable(field)) {
    return undefined;
  }
  return obj[field];
});
```

`{{lookup this "pcbCanary"}}` 的 `obj[field]` 会沿原型链找到 `pcbCanary`。本 case seed：

```text
template = '{{lookup this "pcbCanary"}}'
strict = false
```

V0 输出 `PCBFLAG_...`。4.6+ 引入了 `proto-access` 子系统；到 4.7.6，lookup helper 已经被接到那套守卫上。

---

## 维护者改了什么（CVE-2019-20920 修复，4.7.6）

4.7.6 的 lookup helper 不再自己 `obj[field]`：

```javascript
// lib/handlebars/helpers/lookup.js  (handlebars v4.7.6)
instance.registerHelper('lookup', function(obj, field, options) {
  if (!obj) {
    return obj;
  }
  return options.lookupProperty(obj, field);
});
```

`options.lookupProperty` 来自 runtime 包装 helper 时注入的 `container.lookupProperty`：

```javascript
// lib/handlebars/runtime.js :: container  (handlebars v4.7.6)
    lookupProperty: function(parent, propertyName) {
      let result = parent[propertyName];
      if (result == null) {
        return result;
      }
      if (Object.prototype.hasOwnProperty.call(parent, propertyName)) {
        return result;
      }

      if (resultIsAllowed(result, container.protoAccessControl, propertyName)) {
        return result;
      }
      return undefined;
    },
    strict: function(obj, name, loc) {
      if (!obj || !(name in obj)) {
        throw new Exception('"' + name + '" not defined in ' + obj, {
          loc: loc
        });
      }
      return obj[name];
    },
```

`resultIsAllowed` 默认把 `__proto__` 和一批方法（含 `constructor`）关掉，非 own 属性返回 `undefined`（并打一次日志）。对 seed：`pcbCanary` 不是 own，`lookupProperty` 返回 `undefined`，输出空。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 模板读属性都会经过 `lookupProperty`。
2. `name in obj` 为真时，直接 `obj[name]` 也安全——因为「在对象上」等于「可以读」。

第二点把原型链算进了 `in`。`pcbCanary in ctx === true`（继承），`obj[name]` 读到原型值。而 `lookupProperty` 会拒绝它。

---

## 检查之后谁真正读那个名字

`{strict:true}` 时，编译器对路径**最后一段**发出 `container.strict(stack, terminal)`，中间段仍走 `lookupProperty`。单段 `{{pcbCanary}}` 的终端就是 `pcbCanary` 自己，于是整次读取都在 `strict` 里：

```text
strict:
  ("pcbCanary" in ctx) === true     // 原型上有
  return ctx["pcbCanary"]           // 读到 PCBFLAG_...
```

`lookupProperty` 在同一个 `container` 对象上，**这次调用没用它**。过滤器（V1）刚看过的是 helper 路径；open（这里是属性读）看的是 `in` + 原生下标。中间没有 `hasOwnProperty`。

编译器侧（`lib/handlebars/compiler/javascript-compiler.js` 的 `strictLookup`）对路径发出的伪代码是：中间段 `container.lookupProperty(stack, "foo")`，终端 `container.strict(stack, "bar")`。单段 `{{pcbCanary}}` 没有中间段，所以一次 `strict` 就决定了整个读。多段 `{{a.pcbCanary}}` 在 V1 上会把 `a` 走守卫、把 `pcbCanary` 走 `obj[name]`——终端仍然漏。本 case residual 用单段，足够证明终端函数本身没接上。

`proto-access.js` 的默认白名单把 `__proto__` 设为 false：

```javascript
// lib/handlebars/internal/proto-access.js :: createProtoAccessControl  (v4.7.6)
  let defaultPropertyWhiteList = Object.create(null);
  defaultPropertyWhiteList['__proto__'] = false;
```

这只对走 `resultIsAllowed` 的路径有效。`strict` 不调用它。

---

## 仓库里已经有更强的检查，strict 没用

`container.lookupProperty` 就是更强的谓词：先读，own 则放行，否则问 proto 白名单，默认拒绝。lookup helper、默认模式的路径查找、`container.lookup` 都已经用它。V1 唯独让 `strict` 在确认 `name in obj` 之后原生返回。

把 `return obj[name]` 换成 `return container.lookupProperty(obj, name)` 就是 V2 的整次修复（加上回归测试）。不是仓库里没有更好的谓词，是 **strict 终端没用**。

---

## 这个补丁挡住了什么、没挡住什么

- V1 `lookup` helper：`options.lookupProperty` → 非 own 得 `undefined`
- V1 `container.strict`：`name in obj` 后 `obj[name]` → 非 own 也能读

```text
seed:
  {{lookup this "pcbCanary"}}     compile 默认
  → lookupProperty → undefined → 输出空

residual:
  {{pcbCanary}}                   compile {strict:true}
  → container.strict
  → "pcbCanary" in ctx
  → ctx["pcbCanary"] → flag
```

只换了「同一属性的读法」和编译选项。context、属性名、观察通道都不变。Snyk / Miggo 写的 *certain compiling options* 指的就是 `strict`（以及 commit 里同时修的 compat 路径相关问题；本 case 钉的是 strict 终端）。

---

## 残余仍然读同一颗原型上的金丝雀（CVE-2021-23369）

没有换 context、没有换属性名。还是 `pcbCanary`：

```text
template = "{{pcbCanary}}"
strict = true
```

编译器发出 `strict` 而不是 helper。V1 的 `return obj[name]` 照样执行。渲染结果里是 `PCBFLAG_...`。

本 case residual 与 `b6d3de7` 新增的 `describe('in strict-mode')` 回归同一构造。认证：v1 + `--residual` 观察到 flag。V2 上 `lookupProperty` 拒绝非 own，输出空（或按实现变成 missing）。

seed 被挡住只说明「lookup helper 不能再读原型」，不说明「strict 编译的终端段不能读原型」。

平台 verify 与这条链是同一 sink：运行时属性解析 → 渲染输出。seed 走 helper，residual 走 `container.strict`，守卫函数是同一个 `lookupProperty`，V1 只给 helper 接上了。

---

## 后来又补了什么（CVE-2021-23369，4.7.7）

commit `b6d3de7123eebba603e321f04afdbae608e8fea8`：

```javascript
    strict: function(obj, name, loc) {
      if (!obj || !(name in obj)) {
        throw new Exception('"' + name + '" not defined in ' + obj, {
          loc: loc
        });
      }
-      return obj[name];
+      return container.lookupProperty(obj, name);
    },
```

`spec/security.js` 增加 `describe('in strict-mode', function() { checkProtoPropertyAccess({ strict: true }); })`。对残余：`in` 仍为真（否则 strict 会抛「not defined」），但 `lookupProperty` 发现不是 own、白名单默认拒绝，返回 `undefined`。公开建议 `handlebars@4.7.7`。

这仍然是「把漏掉的那条读接到已有守卫」。`allowProtoPropertiesByDefault` 仍可主动打开原型访问——那是运行时选项，不是这条 residual。本 benchmark 的 v2 关闭 strict 终端这条。

---

## 从这条链还能看出什么

**维护者改错了哪一层。**  
他们改的是 lookup **helper**。真正还在原生下标的是编译器为 strict 发出的**终端**函数。V2 仍在 runtime 同一处加码，没有改编译器，只让终端也走守卫。

**不是没有更好的谓词。**  
`lookupProperty` + `resultIsAllowed` 在 4.7.6 已经是默认路径的标准答案。从 helper 的 diff 只能看到 `obj[field]` → `lookupProperty`；要判断是否闭合，必须看到 `container.strict` 的 `return obj[name]`，以及编译器 `strictLookup` 把最后一段发给谁。

**同一属性、两种操作码。**  
`{{lookup this "pcbCanary"}}` 和 `{{pcbCanary}}`+`strict` 读的是同一个继承值。一种走守卫，一种不走。

**`in` 不是 own。**  
strict 用 `name in obj` 决定「有没有这个名字」（缺失则抛错），却用原生 `[]` 去取值。`in` 含原型，取值也就含原型。守卫需要的是 `hasOwnProperty`（或等价物）。V2 保留了 `in` 做「缺失则抛」的 strict 语义，取值改走 `lookupProperty`：原型上「有这个名字」不再等于「模板能读到它」。

**compat 模式是同一 commit 里的另一条缝。**  
`b6d3de7` 的测试同时覆盖 `compat: true`。本 case 钉的是 `strict: true` 终端；不要把两条编译选项当成同一个 bytecode，只是它们都曾绕开 `lookupProperty`。

**金丝雀在原型上是有意的。**  
own 属性读不到它。输出里出现 token，说明读穿过了 proto-access 门，不是模板字面量里写了 flag。

---

## 版本、入口、参考

| | 版本 | lookup helper | `container.strict` | seed `{{lookup}}` | residual `{{pcbCanary}}`+strict |
|---|---|---|---|---|---|
| V0 | 4.5.2 | `obj[field]` | （同样未守卫） | 输出 flag | （不必） |
| V1 | 4.7.6 | `lookupProperty` | `return obj[name]` | 空 | 输出 flag |
| V2 | 4.7.7 | 同上 | `lookupProperty` | 空 | 空 |

- HTTP harness：`POST` JSON `{template, strict}`
- [CVE-2019-20920](https://nvd.nist.gov/vuln/detail/CVE-2019-20920)、[CVE-2021-23369](https://nvd.nist.gov/vuln/detail/CVE-2021-23369)
- [GHSA-3cqr-58rm-57f8](https://github.com/advisories/GHSA-3cqr-58rm-57f8)、[GHSA-f2jv-r9rf-7988](https://github.com/advisories/GHSA-f2jv-r9rf-7988)
- V2 commit [`b6d3de7`](https://github.com/handlebars-lang/handlebars.js/commit/b6d3de7123eebba603e321f04afdbae608e8fea8)
- 源码：[`v4.7.6` `lookup.js`](https://github.com/handlebars-lang/handlebars.js/blob/v4.7.6/lib/handlebars/helpers/lookup.js)、[`runtime.js` `strict`](https://github.com/handlebars-lang/handlebars.js/blob/v4.7.6/lib/handlebars/runtime.js)
