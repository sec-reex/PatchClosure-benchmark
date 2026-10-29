# HAPI FHIR DSTU2：replaceMatches 加了超时，matches 还在跑裸的 String.matches

- Case：`PCBV2-0059`
- 产品：HAPI FHIR / `org.hl7.fhir.core`（Java，HL7 FHIR 参考实现）
- 链：CVE-2026-45367（6.9.6 → 6.9.7，PR #2403 / commit `e4aa38e` 等）→ CVE-2026-55470（6.9.7 → 6.9.10，commit `56376f7`）
- 源码对着官方 tag `6.9.7` / `6.9.10` 的 `org.hl7.fhir.dstu2/.../FHIRPathEngine.java`：`funcReplaceMatches`、`funcMatches`，以及 `org.hl7.fhir.utilities.regex.RegexTimeout`。运行时是 Maven Central 的 `ca.uhn.hapi.fhir:org.hl7.fhir.dstu2`，经 HTTP `POST /eval` 调用库自己的 `FHIRPathEngine.evaluate`。

2026 年 5 月，GHSA-3653-68v6-rq57 / CVE-2026-45367 写明 FHIRPath 的 `matches()` / `matchesFull()` / `replaceMatches()` 把用户正则交给 Java 引擎时没有有效超时。6.9.7 引入 `RegexTimeout`（默认 500ms）。NVD CVE-2026-55470 / GHSA-fxj4-p9xp-37v5 随后写明：*the fix for CVE-2026-45367 incompletely patched the DSTU2 module, leaving FHIRPathEngine.matches() ... to call raw String.matches(sw) without RegexTimeout protection while replaceMatches() was updated*。

根因不只是「少改了一个函数名」。检查插在 `replaceMatches` 这一条 FHIRPath 函数上；真正吃 CPU 的是 `java.util.regex`。同一次发版已经在 DSTU3/R4/R5 的 `matches()` 以及 **同一份 DSTU2 文件里的 `replaceMatches()`** 挂上了 `RegexTimeout`，DSTU2 的 `funcMatches` 没用。下面按求值走进去、V1 改了哪一行、检查之后谁去跑正则、仓库里已经有什么更强的包装、残余怎么用同一条灾难正则走 `matches()`。

---

## 这块功能本来在干什么

FHIRPath 是 FHIR 资源上的表达式语言。`matches()` / `replaceMatches()` 的参数是正则。校验器、服务器、以及任何 `FHIRPathEngine.evaluate(focus, expr)` 的嵌入点都会跑到这里。本 case 的入口是：

```http
POST /eval
Content-Type: application/json

{"expr":"replaceMatches('(.*a){30}','x')","input":"aaaaaaaa...X"}
```

服务端用 DSTU2 的 `FHIRPathEngine` 对一个 `StringType(input)` 求值，同步占用 handler 线程。设计意图：表达式里的正则用来匹配或替换字符串。成功穿越之后的效果是 **单次求值陷入灾难性回溯，handler 线程在超时前不返回**。本 case 没有金丝雀字符串，oracle 是 HTTP 往返时延：>5s（或 10s 读超时）算打穿，<2s 算被界住。

数据流：

```text
HTTP POST /eval {expr, input}
    → FHIRPathEngine.evaluate(StringType(input), expr)
    → 分发到 funcReplaceMatches / funcMatches
         V1：funcReplaceMatches → RegexTimeout.replaceAll(..., 500ms)
         V1：funcMatches        → String.matches(sw)     ← 没挂超时
    → java.util.regex.Pattern
    → 返回或把 handler 线程钉死
```

没有登录。现代 JDK 会剪掉经典 `(a+)+$`；advisory 与本 case 用的 `(.*a){N}` 仍能打出超多项式回溯（公开 PoC / 本 case 用 N=30、输入 250 个 `a` + `X`）。

---

## 原始漏洞：三条 FHIRPath 正则函数都没有超时（CVE-2026-45367，6.9.6）

6.9.6 的 DSTU2 `funcReplaceMatches` 直接 `String.replaceAll`，`funcMatches` 直接 `String.matches`。GHSA-3653-68v6-rq57 还指出 `ValidationTimeout` 只罩 `InstanceValidator`，不罩 `evaluateFhirPath()`。本 case 的 seed：

```text
expr  = replaceMatches('(.*a){30}','x')
input = 'a' × 250 + 'X'
```

6.9.6 上这次求值把 handler 钉到客户端 10s 读超时（观测约 10002ms）。这就是 v0 + `--seed` 的「打穿」。同一条正则走 `matches()` 同样挂——当时两条函数都没有超时。

---

## 维护者改了什么（CVE-2026-45367 修复，6.9.7）

6.9.7 增加 `org.hl7.fhir.utilities.regex.RegexTimeout`，默认 500ms，用独立执行把 `Pattern.compile` / `matches` / `replaceAll` 包起来，超时抛 `TimeoutException`。DSTU2 的 `funcReplaceMatches` 换成：

```java
// org.hl7.fhir.dstu2/.../FHIRPathEngine.java :: funcReplaceMatches
//   (tag 6.9.7, 约 L2218–2233)
  private List<Base> funcReplaceMatches(...) throws PathEngineException {
    ...
    String regex = convertToString(execute(context, focus, exp.getParameters().get(0), true));
    String repl  = convertToString(execute(context, focus, exp.getParameters().get(1), true));
    if (focus.size() == 1 && !Utilities.noString(regex)) {
      try {
        result.add(new StringType(
            RegexTimeout.replaceAll(
                convertToString(focus.get(0)), regex, repl, regexTimeoutMillis)));
      } catch (TimeoutException e) {
        throw new PathEngineException("Timeout evaluating regex: " + regex, e);
      }
    }
    ...
  }
```

`RegexTimeout.replaceAll` 内部是 `executeWithTimeout(() -> Pattern.compile(regex).matcher(string).replaceAll(replacement), timeoutMillis)`。对 seed 这种 `replaceMatches('(.*a){30}', ...)`，约 500ms 后抛 `PathEngineException`，HTTP 在 ~510ms 返回。这就是 v1 + `--seed` 被界住。

同一文件、往下不到 250 行，`funcMatches` **没有**改：

```java
// 同上文件 :: funcMatches  (tag 6.9.7, 约 L2456–2466)
  private List<Base> funcMatches(...) throws PathEngineException {
    List<Base> result = new ArrayList<Base>();
    String sw = convertToString(execute(context, focus, exp.getParameters().get(0), true));

    if (focus.size() == 1 && !Utilities.noString(sw))
      result.add(new BooleanType(convertToString(focus.get(0)).matches(sw)));
    else
      result.add(new BooleanType(false));
    return result;
  }
```

`.matches(sw)` 是 `java.lang.String` 的方法，内部 `Pattern.matches`，没有超时、不能中断。GHSA-fxj4-p9xp-37v5 把对照写得很直：DSTU2 `replaceMatches` ✅、`matches` ❌；DSTU2016MAY / DSTU3 / R4 / R4B / R5 的 `matches` 都已经是 `RegexTimeout.matches`。

补丁默认了两件事：

1. 危险正则主要从 `replaceMatches` 进来（或 DSTU2 的 `matches` 会被同样改到）。
2. 只要 `replaceAll` 有超时，同一引擎上的 `String.matches` 可以先不动。

第二点不成立。用户选哪一个 FHIRPath 函数，检查并不控制。

---

## 检查之后，谁真正跑那条正则

`funcReplaceMatches` 里，用户正则经过 `RegexTimeout` 才进 `Pattern`。`funcMatches` 里，同一份 `convertToString(... exp.getParameters().get(0) ...)` 得到的 `sw` 直接交给 `String.matches`。求值器对两条函数的分发是：

```java
      return funcMatches(context, focus, exp);          // expr 里写 matches(...)
      return funcReplaceMatches(context, focus, exp);   // expr 里写 replaceMatches(...)
```

检查插在其中一个 case 上。另一个 case 仍然把同一类用户正则送到同一个 `java.util.regex`。超时包装看不到它。handler 线程也中断不了一次已经在跑的 `Pattern.matches`——所以本 case 每个探针都换新进程，避免慢探针毒化下一个。

`RegexTimeout` 的超时不是合作式取消：它把 `Pattern.matches` / `replaceAll` 丢进带时限的执行包装，到期抛 `TimeoutException`，再被 FHIRPath 收成 `PathEngineException`。正在跑的 `java.util.regex` 仍然占着那条工作线程直到包装器放弃这次调用——所以 500ms 是「最多再等多久才向调用方报错」，不是「正则引擎保证 500ms 内停」。对 handler 线程来说，有包装和没包装的差别是：有包装时 HTTP 还能在约半秒返回异常；没包装时只能等客户端读超时。

`RegexTimeout.matches` 在 6.9.7 **已经存在**：

```java
// org.hl7.fhir.utilities.regex.RegexTimeout  (tag 6.9.7)
  public static boolean matches(String string, String regex, long timeoutMillis)
      throws TimeoutException {
    return executeWithTimeout(() -> Pattern.matches(regex, string), timeoutMillis);
  }
```

DSTU2 的 `funcMatches` 没有调用它。真正消耗 CPU 的从来不是 FHIRPath 的函数名，是 Java 正则引擎。

---

## 仓库里已经有更强的包装，DSTU2 matches 没用

`RegexTimeout` 是这次修复专门加的工具类，默认 500ms，同时提供 `matches` / `find` / `replaceAll` / `replaceFirst` / `split`。6.9.7 把它接到了：

| 模块 | `matches()` | `replaceMatches()` |
|---|---|---|
| DSTU2 | 仍 `str.matches(sw)` | `RegexTimeout.replaceAll` |
| DSTU2016MAY / DSTU3 / R4 / R4B / R5 | `RegexTimeout.matches` | 已接 |

不是仓库里没有 `RegexTimeout.matches`，是 **DSTU2 的 `funcMatches` 没挂**。GHSA 用 DSTU3 约 L2447 做对照：`RegexTimeout.matches(st, sw, regexTimeoutMillis)`。同一份 6.9.7 源码里，更强谓词已经在隔壁模块和同文件的另一条函数上。

即便 `matches()` 没有漏，只要还有第三条把用户正则交给 `Pattern.compile` 的 FHIRPath 函数（advisory 还点过 `matchesFull`），也要逐个看有没有超时。本 case 的 residual 只打 DSTU2 `matches()`。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs 引擎」落到具体代码：

- V1 的 `funcReplaceMatches`：用户正则进 `RegexTimeout.replaceAll`，500ms 截止
- V1 的 `funcMatches`：用户正则进 `String.matches`，没有截止

正则本身不必改。把 FHIRPath 函数名从 `replaceMatches` 换成 `matches`，第一个包装看不见，第二个照样把 `(.*a){30}` 交给 Java。

```text
seed:      replaceMatches('(.*a){30}','x')   +  250×a + X
           → RegexTimeout → ~510ms PathEngineException

residual:  matches('(.*a){30}')              +  250×a + X
           → String.matches → handler 钉死 → HTTP 10s 超时
```

没有字符串变换。V1 不改写正则，只在其中一条函数外面包了计时器。另一条函数的参数协议与 seed 相同：第一个参数就是正则。

公开 Kodem / SentinelOne 写的是同一对照：6.9.7 上 `replaceMatches` 被界住，`matches` 仍按输入长度恶化。Kodem 还给出过较短输入上的数字（JDK 25 上未包装约 1410ms、包装约 508ms）；本 case 把输入加到 250 个 `a`，未包装路径直接打到 10s 读超时，包装路径仍约 500ms。本 case `gate_result` 记录（既有观测，来自 case.json，非本轮 compose）：V0 original/residual 皆 10002.4ms；V1 original 510.1ms、residual 10002.4ms；V2 两者约 510–515ms。良性 `matches('a+')` 全程约 4ms，说明慢的是回溯而不是引擎启动。

---

## 残余仍然走同一条 FHIRPath 求值路径（CVE-2026-55470）

没有换模块、没有换引擎、没有换正则。还是 DSTU2 `FHIRPathEngine.evaluate`，还是 `(.*a){30}` 打 250 个 `a` + `X`。只是表达式写成：

```http
POST /eval
{"expr":"matches('(.*a){30}')","input":"<250 a's>X"}
```

分发走进 `funcMatches`。V1 那一行 `RegexTimeout.replaceAll` 根本不执行。`String.matches` 把 handler 钉到读超时。

这不是新洞面：同一 class、同一用户正则、同一 `java.util.regex`，只是 FHIRPath 函数名不同。seed 被界住只说明「`replaceMatches` 外包了 500ms」，不说明「DSTU2 上用户正则不能再把 CPU 吃满」。

advisory 写明无需认证，攻击者只需提交带 `matches()` 参数的 FHIR 资源或 FHIRPath 表达式。本 case 用 HTTP `/eval` 模拟校验器 / 服务器那种同步求值。

---

## 后来又补了什么（CVE-2026-55470，6.9.10，commit 56376f7）

6.9.10 给 DSTU2 `funcMatches` 接上已经存在的 `RegexTimeout.matches`：

```java
// org.hl7.fhir.dstu2/.../FHIRPathEngine.java :: funcMatches
//   (tag 6.9.10, 约 L2459–2475)
        final boolean matchResult = RegexTimeout.matches(
            convertToString(focus.get(0)), regex);
        result.add(new BooleanType(matchResult));
      } catch (TimeoutException e) {
          throw new PathEngineException("Timeout evaluating regex: " + regex, e);
      }
```

对残余输入：约 500ms 抛超时，HTTP ~515ms 返回。公开建议是升级到 6.9.10。NVD 把修复 commit 记成 `56376f7986222626af061ca7fc27ee1ab030e590`。

即便如此，这仍然是「在 Java 正则外面再包计时器」。`java.util.regex` 本身不能中断；超时依赖 `RegexTimeout` 的执行包装。对这条 `(.*a){30}` 链它够用。本 benchmark 的 v2 只关闭 DSTU2 `matches()` 这一条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是 DSTU2 里其中一条 FHIRPath 函数。真正把 CPU 吃满的是 `Pattern.matches`。V2 仍在同一层把另一条函数接到同一个包装器，没有在 `evaluate()` 入口给整次 FHIRPath 求值加预算（advisory 已指出 `ValidationTimeout` 不罩这条路径）。

**不是没有更好的谓词。**  
`RegexTimeout.matches` 在 6.9.7 已经存在，DSTU3+ 的 `matches()` 已经在用，同文件的 `replaceMatches` 已经在用。从 V1 的 DSTU2 diff 只能看到 `replaceAll` 换了包装；要判断补丁是否闭合，必须看到 `funcMatches` 仍调用 `String.matches`。

**同一引擎、同一正则，只换了函数名。**  
任何把用户正则送进 DSTU2 `FHIRPathEngine` 的 `matches` / `replaceMatches` 的入口，在 6.9.7 上只有后者有超时。校验器 HTTP 端点是 advisory 点名的交付面。

**JDK 优化不是补丁。**  
`(a+)+$` 在 JDK 11/17/21 上可能被剪掉；`(.*a){N}` 仍然活着。补丁必须按「用户正则 + 超时」来写，不能按「某一个经典 ReDoS 样本已经被引擎优化掉」来写。

**模块矩阵比单点 diff 更重要。**  
CVE-2026-45367 的 PR #2403 有单独 commit「Use RegexTimeout in FHIRPathEngine (dstu2, dstu2016may, dstu3)」。DSTU2 的 `replaceMatches` 被改到了，`matches` 没有。只看 `RegexTimeout.java` 新增、或只看 R4/R5 模块，会误以为 6.9.7 已经闭合。要判断 DSTU2 是否闭合，必须打开 `org.hl7.fhir.dstu2/.../FHIRPathEngine.java` 的 `funcMatches`，看它调用的是 `String.matches` 还是 `RegexTimeout.matches`。

**效果是线程可用性，不是文件。**  
oracle 用时延而不是金丝雀。一次打穿会永久占用该 handler 线程，所以探针之间要换进程——这本身说明检查没有把求值从请求线程上拉开。

---

## 版本、入口、参考

| | tag | DSTU2 `replaceMatches` | DSTU2 `matches` | seed `(.*a){30}` | residual `matches` |
|---|---|---|---|---|---|
| V0 | 6.9.6 | 裸 `replaceAll` | 裸 `String.matches` | HTTP ~10s 超时 | 同样挂 |
| V1 | 6.9.7 | `RegexTimeout.replaceAll` ~500ms | 仍裸 `String.matches` | ~510ms 异常 | HTTP ~10s 超时 |
| V2 | 6.9.10 | 同上 | `RegexTimeout.matches` ~500ms | 挡 | ~515ms 异常 |

- Web：`POST /eval` `{"expr","input"}`
- 源码：GitHub `hapifhir/org.hl7.fhir.core` tag `6.9.7` 的 `org.hl7.fhir.dstu2/.../FHIRPathEngine.java`（`funcReplaceMatches` L2218、`funcMatches` L2456）及 `RegexTimeout.java`
- 既有时延观测（case.json，非本轮 compose）：V1 original 510.1ms / residual 10002.4ms；V2 residual 514.6ms
- [CVE-2026-45367](https://nvd.nist.gov/vuln/detail/CVE-2026-45367)、[CVE-2026-55470](https://nvd.nist.gov/vuln/detail/CVE-2026-55470)
- [GHSA-3653-68v6-rq57](https://github.com/hapifhir/org.hl7.fhir.core/security/advisories/GHSA-3653-68v6-rq57)
- [GHSA-fxj4-p9xp-37v5](https://github.com/hapifhir/org.hl7.fhir.core/security/advisories/GHSA-fxj4-p9xp-37v5)
- [PR #2403](https://github.com/hapifhir/org.hl7.fhir.core/pull/2403)（RegexTimeout）
- [commit 56376f7](https://github.com/hapifhir/org.hl7.fhir.core/commit/56376f7986222626af061ca7fc27ee1ab030e590)
