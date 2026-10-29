# Thymeleaf：受限 SpEL 的关键字扫描器和真正解析器不是同一种语言

- Case：`PCBV2-0202`
- 产品：Thymeleaf（`org.thymeleaf:thymeleaf-spring6`）。运行时是 Maven Central 整包，钉在 Spring Boot 3 MVC 里，经 HTTP 打进预处理表达式；不是抽出来的扫描函数。
- 链：CVE-2026-40478（3.1.3.RELEASE → 3.1.4.RELEASE）→ CVE-2026-41901（3.1.4.RELEASE → 3.1.5.RELEASE，GHSA-c9ph-gxww-7744）
- 源码对着 tag `thymeleaf-3.1.4.RELEASE` 的 `SpringStandardExpressionUtils.containsExternalAccess`、`ExpressionUtils.normalize`、`SPELVariableExpressionEvaluator.obtainComputedSpelExpression`。金丝雀是 benign：受限上下文里 `new pcb.PcbFlagReader()` 的构造函数读 `/flag`，token 写进 HTTP body。

GHSA-c9ph-gxww-7744 的原话：*Although the library provides mechanisms to avoid the execution of potentially dangerous expressions in some specific sandboxed (restricted) contexts, it fails to properly neutralize specific constructs*。根因不只是「漏了一种空白」。检查插在字符串关键字扫描上；真正做实例化的是后面的 Spring SpEL 解析器。扫描器用字面小写 `new`，解析器用忽略大小写的 token。下面按表达式走进去。

---

## 这块功能本来在干什么

Thymeleaf 给 Spring MVC 视图提供 `__${...}__` 预处理。预处理在拼最终表达式之前，先把内层表达式求值一次，上下文是 `StandardExpressionExecutionContext.RESTRICTED`：不允许 `new SomeClass(...)`、不允许 `T(SomeClass)` 静态访问。设计意图是：即便应用把用户字符串嵌进模板，受限位置也不能实例化任意类。

本 case 的 HTTP 入口是库的真实消费路径：

```http
GET /render?expr=new%09pcb.PcbFlagReader()
```

控制器把 `expr` 原样嵌进预处理位置，再交给已发布的 `SpringTemplateEngine`：

```text
template = "<div th:text=\"__${" + expr + "}__\">x</div>"
engine.process(template, new Context())
```

数据流：

```text
HTTP expr
    → SpringTemplateEngine.process
         StandardExpressionPreprocessor  求值 __${EXPR}__
              StandardExpressionExecutionContext.RESTRICTED
              SPELVariableExpressionEvaluator.evaluate
                   obtainComputedSpelExpression
                        V1：containsExternalAccess(EXPR)
                             ExpressionUtils.normalize(EXPR)     ← 只改空白，不大写转小写
                             倒序扫字面 "new" / "param" / T( / @
                        通过后：SpelExpressionParser.parseExpression(EXPR)
                        exp.expression.getValue(...)            ← 真正的 new
         预处理结果内联进外层 th:text
    → HTTP body
```

需要「表达式能流进受限预处理」这一应用条件。成功穿越之后的效果是：**在沙箱里实例化任意类**（本 case 是 benign 的 `pcb.PcbFlagReader`，构造函数读 `/flag`）。没有单独的「禁止 new」权限位；整条防线就是那一次字符串扫描。

---

## 原始漏洞：空白把 `new` 粘成标识符（CVE-2026-40478，3.1.3.RELEASE）

3.1.3 的 `ExpressionUtils.normalize` 遇到控制字符（含 TAB，`\u0009`）就**丢掉**，不换成空格。扫描器认 `new` 的条件是：倒序配上 `wen`，并且 `new` **后面**必须是空白：

```java
// SpringStandardExpressionUtils.containsExternalAccess  （3.1.3 / 3.1.4 同一套匹配）
if (ni < NEW_LEN
        && c == NEW_ARRAY[ni]
        && (ni > 0 || ((n + 1 < explen) && Character.isWhitespace(exp.charAt(n + 1))))) {
```

`NEW_ARRAY` 是倒过来的 `"wen"`。对 `new<TAB>pcb.PcbFlagReader()`：

```text
normalize (3.1.3):  丢掉 TAB  →  newpcb.PcbFlagReader()
扫描器:             "new" 后面是 'p'，不是空白  →  不命中
SpEL:               解析器仍把 new + 类名当成实例化（TAB 对它是空白）
```

扫描看的是丢掉 TAB 之后的字符串；解析器看的是原始（或它自己的 tokenizer）输入。两套空白语义不一致。这就是 v0 + seed 能在 body 里看到 `PCBFLAG_...` 的原因。

同一份 advisory（GHSA-xjw8-8c5c-9r79）还提到：若应用把未消毒输入直接交给模板引擎，未认证攻击者可以 SSTI。本 case 的 `/render` 就是这条库 API 的 HTTP 包装。

---

## 维护者改了什么（CVE-2026-40478 修复，3.1.4.RELEASE）

3.1.4 改的是 `normalize`：凡 `Character.isWhitespace(c)`（且不是 `\n`）都改写成一个普通空格，而不是删掉。扫描函数改名为 `containsExternalAccess`，并额外拦 `@bean`：

```java
// V0  3.1.3.RELEASE
if (c != '\n' && (c < '\u0020' || (c >= '\u007F' && c <= '\u009F'))) {
    // 控制字符：丢掉
}

// V1  3.1.4.RELEASE   （CVE-2026-40478，本 case 的目标）
if (c != '\n' && (c < '\u0020' || (c >= '\u007F' && c <= '\u009F')
        || Character.isWhitespace(c))) {
    if (Character.isWhitespace(c)) {
        strBuilder.append(' ');   // TAB → 空格
    }
}

// V2  3.1.5.RELEASE   （CVE-2026-41901）
public static String normalize(final String expression, boolean normalizeCase) {
    final String exp = (normalizeCase ? expression.toLowerCase() : expression);
    // 其后仍把空白收成空格
}
```

对 seed：

```text
输入:     new<TAB>pcb.PcbFlagReader()
V1 后:    new pcb.PcbFlagReader()
扫描器:   倒序看到 "new" + 后面是空格  →  命中
异常:     Instantiation of new objects ... is forbidden in this context
```

这就是 v1 + `--seed` 被挡住。补丁默认了两件事：

1. 危险形态是「`new` + 空白 + 类型名」，空白种类（TAB、`\f`、NBSP）可以先收成空格。
2. 关键字本身是小写字面量 `new`。扫描数组是 `"wen"`，比较用的是 `c == NEW_ARRAY[ni]`，**区分大小写**。

第一点对 TAB seed 成立。第二点不成立：后面真正解析表达式的 Spring SpEL，把 `NEW` 也当成实例化运算符。

---

## 扫描通过之后，谁真正做 `new`

`containsExternalAccess` 返回 false 之后，同一个 `obtainComputedSpelExpression` **立刻**把**原始**表达式交给 `SpelExpressionParser`。注意：扫描看的是 `normalize` 后的副本；parse 用的是未经扫描器大小写折叠的原串：

```java
// SPELVariableExpressionEvaluator.obtainComputedSpelExpression
// tag thymeleaf-3.1.4.RELEASE
if (expContext.getRestrictExternalAccess()
        && SpringStandardExpressionUtils.containsExternalAccess(spelExpression)) {
    throw new TemplateProcessingException(
        "Instantiation of new objects and access to static classes or parameters is forbidden in this context");
}
// …缓存未命中则：
final SpelExpression spelExpressionObject =
    (SpelExpression) spelExpressionParser.parseExpression(spelExpression);
```

`evaluate` 随后 `exp.expression.getValue(...)`。Spring 的 tokenizer 对 `new` 用的是忽略大小写匹配（`equalsIgnoreCase`）。所以：

| 层 | 看到的字符串 | 对 `NEW pcb.PcbFlagReader()` |
|---|---|---|
| `normalize`（V1） | 不改大小写 | `NEW pcb.PcbFlagReader()` |
| `containsExternalAccess` | 倒序配 `"wen"` | `N`≠`n`，不命中 |
| `SpelExpressionParser` | 原串 | `NEW` 就是 `new`，实例化 |

过滤器刚看过的是「有没有小写子串 `new` + 空白」；求值器看到的是 SpEL AST 上的 ConstructorReference。两套语言中间没有第二次谓词。`pcb` 包也不在 `BLOCKED_TYPE_REFERENCE_PACKAGE_NAME_PREFIXES` 里——V1 顺手加的 jackson / `org.springframework.core.` 黑名单对这条链是空操作。金丝雀能出现在 body 里，依据是这一次 `getValue`，而不是「扫描器碰巧漏了一个类名」。

---

## 仓库里已经有更接近解析器的谓词，扫描没用上

同一份 3.1.4 里已经有：

- `ExpressionUtils.isTypeForbidden` / `isMemberForbidden`：按类型名黑名单拦静态和成员访问。它们在求值期由 `ThymeleafEvaluationContext` 调用，**不**负责拦 `new`。
- `checkRestrictedVariables`：在 **已经 parse 完的 AST** 上走 `SpelNode`，禁止 `#vars` 一类变量。它就在 `evaluate` 里，紧挨着 `getValue` 之前。

维护者若要把「禁止实例化」做成和解析器同一套语法，最直接的做法是：要么 `normalize(..., true)` 先折叠大小写（V2 就是这个），要么像 `checkRestrictedVariables` 那样在 AST 上认 ConstructorReference。V1 两样都没做。扫描器继续用手写倒序状态机，匹配语言比 SpEL 窄。

`isSafeIdentifierChar` 在 V1 里仍接受 `A`–`Z`。V2 把它收成只认小写，因为此时整个表达式已经 `toLowerCase`。这也说明维护者后来承认：扫描器的字符类必须跟规范化后的字母表对齐。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「扫描器 vs 解析器」落到具体输入：

- `normalize` + `containsExternalAccess`：看规范化后的字符串里有没有小写 `new`/`param`、`T(`、`@`
- `SpelExpressionParser.parseExpression`：看 SpEL 语法，`new` 忽略大小写

只要构造一种输入，使「小写字面 `new`」扫描为假，而 SpEL 仍把它当成实例化，第一层放行，第二层仍然 `new`。

`NEW pcb.PcbFlagReader()` 就是这样来的。四个字母 `N E W` 加空格。扫描从右往左配 `"wen"`，第一个字母就是 `N`，不等于 `n`，`ni` 保持 0。解析器把 `NEW` 收成实例化 token，构造 `pcb.PcbFlagReader`，构造函数读 `/flag`，预处理把 `toString()` 内联进 `th:text`。

TAB seed 在 V1 被挡住，只说明「空白种类被收成空格了」，不说明「受限上下文不能再 `new`」。

---

## 残余仍然走同一条受限预处理路径（CVE-2026-41901）

没有换端点、没有换预处理位置、没有换求值器。还是：

```http
GET /render?expr=NEW%20pcb.PcbFlagReader()
```

`containsExternalAccess` 照样先跑；跑完认为没有 `new`；`parseExpression` + `getValue` 照样实例化。GHSA-c9ph-gxww-7744 写的是 *improper recognition of unauthorized syntax patterns*，和源码一致：扫描器认不出解析器仍接受的写法。

公开残余就是大小写这一档。平台若用 `NEW ` 打同一 sink，和 advisory / 3.1.5 的 `normalize(exp, true)` 对得上。不是换了一个表达式注入面，而是同一 sink 上扫描语言比求值语言窄。

把 `NEW pcb.PcbFlagReader()` 从右往左走一遍 V1 状态机（`NEW_ARRAY = {'w','e','n'}`，下标 0 要从「关键字最后一个字母且后面是空白」开始）：

```text
下标:  N E W [space] p c b . P c b F l a g R e a d e r ( )
倒序先碰到 ')':  不是 w，ni=0
…
碰到关键字末字母位置的 'W':  'W' != 'w'，ni 仍为 0
整个表达式扫完，containsExternalAccess = false
```

同一串交给 `SpelExpressionParser.parseExpression`。Spring 的 tokenizer 对实例化运算符做 `equalsIgnoreCase("new")`，`NEW` 收成 ConstructorReference，类型名 `pcb.PcbFlagReader` 走普通类加载。V1 的类型黑名单新增了 `org.springframework.core.` 和 `com.fasterxml.jackson.`，`pcb` 不在任何前缀里，`isTypeForbidden` 不会在实例化这一步插手——那份名单拦的是 `T(type)` 和成员访问，不是 `new`。

预处理把构造函数里读到的 flag 收成字符串，内联进外层 `th:text`，body 出现 `<div>PCBFLAG_...</div>`。若扫描器拒绝，控制器捕获 `TemplateProcessingException`，返回 `ERROR ... Instantiation of new objects...`，body 里没有 flag。

---

## 后来又补了什么（CVE-2026-41901，3.1.5.RELEASE）

3.1.5 让扫描走大小写折叠后的副本，并把静态标记 `T` 改成只认小写 `t`：

```java
// V1
final String exp = ExpressionUtils.normalize(expression);

// V2
final String exp = ExpressionUtils.normalize(expression, true);
// normalize(..., true) 里：expression.toLowerCase()
```

对残余：

```text
输入:   NEW pcb.PcbFlagReader()
V2 后:  new pcb.PcbFlagReader()
扫描器: 命中 "new" + 空白
```

GHSA 建议升级到 3.1.5.RELEASE。即便如此，防线仍是「parse 之前扫一遍规范化字符串」，不是 AST 上禁止 ConstructorReference。对 `NEW` 这条已知链它够用；若还有扫描器和解析器继续分叉的写法（编码、空白之外的 token 拼接），需要另证。本 benchmark 的 v2 只关闭这一条 reference residual。

---

## 从这条链还能看出什么

**维护者改错了哪一层。**  
他们改的是扫描前的空白规范化。真正做 `new` 的是 `SpelExpressionParser`。V2 仍在扫描层加码（先 `toLowerCase`），没有把「禁止实例化」挂到已经存在的 AST 遍历 `checkRestrictedVariables` 上。

**不是没有更接近解析器的谓词。**  
同一求值函数里已经在 AST 上拦受限变量。类型黑名单在求值期拦 `T(...)` 和成员调用，不拦 `new`。`pcb` 不在任何版本的包前缀黑名单里，所以这条链的差分干净地落在关键字扫描上。

**同一函数、同一 `$spelExpression`，只换了关键字的写法。**  
任何把用户字符串送进受限 `__${...}__`（或其它 `getRestrictExternalAccess()` 为真的位置）的应用，在 3.1.4 上都吃这一次扫描和同一次 `parseExpression`。

**扫描器默认关键字是小写 ASCII。**  
SpEL 文档和 tokenizer 都按忽略大小写收 `new`。手写 `"wen"` 状态机没有跟这份语法对齐。

3.1.4 的 `isPreviousStaticMarker` 仍认大写 `T`（`T(SomeClass)`）。3.1.5 改成只认小写 `t`，因为整个表达式已经 `toLowerCase`。这和 `new` 是同一类分叉：扫描器的字母表必须跟规范化后的副本一致，否则静态访问和实例化会各漏一种大小写。V1 只修了空白，没有修字母表。`@bean` 是 3.1.4 顺手加的另一道扫描（`c == '@'`），同样区分不了编码层的变体，但本链的 residual 不走它。

---

## 版本、入口、参考

| | 版本 | `normalize` | `containsExternalAccess` | `new<TAB>` seed | `NEW ` residual |
|---|---|---|---|---|---|
| V0 | 3.1.3.RELEASE | 丢掉控制字符 | 小写 `"wen"` | 实例化，body 有 flag | （不必） |
| V1 | 3.1.4.RELEASE | 空白→空格 | 同上，仍区分大小写 | 拒绝 | 实例化，body 有 flag |
| V2 | 3.1.5.RELEASE | `normalize(exp, true)` 先小写 | `"wen"` 配上已小写的副本 | 挡 | 挡 |

- 库 API：`SpringTemplateEngine.process`，受限预处理 `__${expr}__` → `SPELVariableExpressionEvaluator`
- 本 case HTTP：`GET/POST /render?expr=...`（真实已发布 thymeleaf-spring6，未改引擎源码）
- [GHSA-xjw8-8c5c-9r79](https://github.com/thymeleaf/thymeleaf/security/advisories/GHSA-xjw8-8c5c-9r79)（CVE-2026-40478）
- [GHSA-c9ph-gxww-7744](https://github.com/thymeleaf/thymeleaf/security/advisories/GHSA-c9ph-gxww-7744)（CVE-2026-41901）
- V1 源码：[SpringStandardExpressionUtils.java @ thymeleaf-3.1.4.RELEASE](https://github.com/thymeleaf/thymeleaf/blob/thymeleaf-3.1.4.RELEASE/lib/thymeleaf-spring6/src/main/java/org/thymeleaf/spring6/util/SpringStandardExpressionUtils.java)、[ExpressionUtils.java](https://github.com/thymeleaf/thymeleaf/blob/thymeleaf-3.1.4.RELEASE/lib/thymeleaf/src/main/java/org/thymeleaf/util/ExpressionUtils.java)、[SPELVariableExpressionEvaluator.java](https://github.com/thymeleaf/thymeleaf/blob/thymeleaf-3.1.4.RELEASE/lib/thymeleaf-spring6/src/main/java/org/thymeleaf/spring6/expression/SPELVariableExpressionEvaluator.java)
- V2：`normalize(expression, true)` 见 [ExpressionUtils.java @ thymeleaf-3.1.5.RELEASE](https://github.com/thymeleaf/thymeleaf/blob/thymeleaf-3.1.5.RELEASE/lib/thymeleaf/src/main/java/org/thymeleaf/util/ExpressionUtils.java)
