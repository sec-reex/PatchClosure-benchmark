# Apache Struts：`id` 不再二次求值，`name` 在 evaluateParams 里仍会再跑一遍 OGNL

- Case：`PCBV2-0079`
- 产品：Apache Struts 2（本 case 把官方 `struts2-core` 2.5.25 / 2.5.26 / 2.5.30 打进 Tomcat 9 WAR，外部 HTTP 触发）
- 链：CVE-2020-17530 / S2-061（2.5.25 → 2.5.26）→ CVE-2021-31805 / S2-062（2.0.0–2.5.29 → 2.5.30，PR `#496`）
- 源码对着 GitHub tag `STRUTS_2_5_25` / `STRUTS_2_5_26` / `STRUTS_2_5_30` 的 `UIBean.setId`、`UIBean.evaluateParams`。运行时 `eval.jsp` 里两个真实 `<s:textfield>`，分别把 `id` / `name` 写成 `%{prop}`。金丝雀只活在 ValueStack 的 `#pcbflag` 上。

2020 年 12 月，S2-061 修掉 UI 标签 `id` 属性被强制 OGNL 求值两次的问题。2022 年 4 月 S2-062 原话：*The fix issued for CVE-2020-17530 (S2-061) was incomplete. Still some of the tag's attributes could perform a double evaluation if a developer applied forced OGNL evaluation by using the `%{...}` syntax.* NVD / CERT-EU 把 31805 写成对 17530 的不完整修复。

根因不只是「漏了一个属性名」。检查插在 `setId` 要不要 `findString` 上；真正第二次求值发生在 `evaluateParams` 计算 `nameValue` 时：先把 `%{prop}` 求成攻击者字符串，再因为结果里没有 `%{` 而再 `findValue` 一次。下面按请求走进去。

---

## 这块功能本来在干什么

Struts UI 标签允许开发者写 `%{expr}`（alt syntax），在渲染时对属性做 OGNL。常见误用是把**未校验的请求参数**直接放进 `%{}`。本 case 的 `eval.jsp`：

```jsp
ID-VECTOR:[<s:textfield theme="simple" name="idfield" id="%{prop}"/>]
NAME-VECTOR:[<s:textfield theme="simple" id="namefield" name="%{prop}"/>]
```

`EvalAction` 把 `prop` 绑成普通 String（**不**先求值），并把 `${PCB_FLAG}` 放进 ValueStack 上下文 `#pcbflag`。外部触发：

```http
GET /eval.action?prop=%{#pcbflag}
```

设计意图：`%{prop}` 只应求值一次，得到攻击者字符串本身（例如字面 `%{#pcbflag}` 或 `#pcbflag`），**不应**再把那次结果当 OGNL 跑第二遍——否则就会读到 `#pcbflag`，或在真实漏洞里 RCE。本 case 的 OGNL 只读种植的上下文变量，没有 `Runtime.exec`。成功穿越之后的效果是：渲染出的 `<input>` 的 `id` 或 `value` 里出现 `PCBFLAG_...`。

数据流（2.5.26，本 case 的 V1）：

```text
GET /eval.action?prop=...
    → EvalAction 绑定 prop，种植 #pcbflag
    → eval.jsp 渲染 <s:textfield>
         setXxx 属性
              V1：setId(id) { this.id = id; }   ← 不再 findString
         evaluateParams()
              name = findString(this.name)          ← 第一次：%{prop} → 攻击者串
              计算 nameValue:
                   completeExpressionIfAltSyntax(name)
                   recursion(name)?  看的是是否还含 %{
                   否则 findValue(expr)            ← 第二次 OGNL
              id：findStringIfAltSyntax(id)        ← 现在只此一次
    → HTML <input id="..." name="..." value="...">
```

没有登录。两条向量共用同一套 `UIBean`，只是强制 OGNL 写在不同属性上。

---

## 原始漏洞：`id` 求值两次（CVE-2020-17530，2.5.25）

2.5.25 的 `setId` 立刻求值：

```java
// core/src/main/java/org/apache/struts2/components/UIBean.java
// UIBean.setId  (tag STRUTS_2_5_25 / V0, L1023–1027)
    public void setId(String id) {
        if (id != null) {
            this.id = findString(id);
        }
    }
```

之后 `populateComponentHtmlId` 又 `findStringIfAltSyntax(id)`。对 `id="%{prop}"` 且 `prop=%{#pcbflag}`：

```text
第一次 setId:     %{prop}     →  %#{pcbflag}   （还是一段 OGNL 文本）
第二次 evaluateParams:  %{#pcbflag} →  <FLAG>
<input id="<FLAG>" ...>
```

S2-061 / oss-security：forced OGNL on untrusted input → RCE。本 case seed：`prop = %{#pcbflag}`，走 ID-VECTOR。V0 的 HTML 里 `id` 等于 flag。这是 v0 + `--seed`。

---

## 维护者改了什么（CVE-2020-17530 修复，2.5.26）

2.5.26 让 `setId` 只保存原字符串：

```java
// core/src/main/java/org/apache/struts2/components/UIBean.java
// UIBean.setId  (tag STRUTS_2_5_26 / V1, L1026–1028)
    public void setId(String id) {
        this.id = id;
    }
```

`id` 只在 `evaluateParams` → `populateComponentHtmlId` 里求一次：`%{prop}` → `%{#pcbflag}`，第二次不再发生，HTML 里 `id` 是字面 `%{#pcbflag}`。这就是 v1 + `--seed` 退出码 10。

`evaluateParams` 里给 `name` / `nameValue` 的逻辑**没改**。同一 tag 的同一文件（raw blob 已对过）：

```java
// UIBean.evaluateParams  (STRUTS_2_5_26 / V1, L663–666 与 L790–802)
        if (this.name != null) {
            name = findString(this.name);
            addParameter("name", name);
        }
        // ... 中间处理 css/title ...
            if (evaluateNameValue()) {
                final Class valueClazz = getValueClassType();
                if (valueClazz != null) {
                    if (value != null) {
                        addParameter("nameValue", findValue(value, valueClazz));
                    } else if (name != null) {
                        String expr = completeExpressionIfAltSyntax(name);
                        if (recursion(name)) {
                            addParameter("nameValue", expr);
                        } else {
                            addParameter("nameValue", findValue(expr, valueClazz));
                        }
                    }
```

`recursion(name)` 为真当且仅当字符串里**还**有 `%{`。第一次 `findString("%{prop}")` 若得到 `#pcbflag`，里面没有 `%{`，于是走 `findValue("%{#pcbflag}")`，把上下文变量求出来。

补丁默认了两件事：

1. 危险形态长得像「`id` 在 setter 和 evaluateParams 各求一次」。
2. 只要 `setId` 不再 `findString`，forced `%{}` 就不会二次求值。

第二点不成立。`name` 的 setter 并不求值，但 `evaluateParams` 自己就会 findString 一次再 findValue 一次。S2-062 说的 *still some of the tag's attributes* 指的就是这类。

---

## 消毒之后，属性值怎么接到第二次 OGNL 上

V1 的 `setId` 一结束，同一 `evaluateParams` 仍用 `findString` / `findValue` 处理几乎所有属性。对 NAME-VECTOR `name="%{prop}"`、`prop=#pcbflag`：

```text
this.name = "%{prop}"          （setter 原样保存）
findString("%{prop}") → "#pcbflag"
recursion("#pcbflag") → false  （没有 %{）
completeExpressionIfAltSyntax("#pcbflag") → "%{#pcbflag}"
findValue("%{#pcbflag}", String.class) → <FLAG>
addParameter("nameValue", <FLAG>)
→ <input value="<FLAG>" ...>
```

过滤器刚看过的是「`id` 有没有在 setter 里多求一次」；HTML `value` 看的是 `nameValue` 这次 `findValue`。两套属性中间没有「已经 forced 求值过的结果不得再当表达式」的谓词——`recursion()` 只认 `%{` 包裹，认不出 `#pcbflag` 已经是表达式。

金丝雀能出现在响应里，依据就是这次第二次 OGNL 读了 `#pcbflag`，而不是 JSP 自己把环境变量打进页面。

---

## 仓库里已经有 recursion()，谓词却只认 `%{`

同一份 `UIBean.java` 里，`recursion(name)` 本意是：若 `name` 已经是 `%{...}` 形态，就不要再 `findValue`，以免套娃。它对「第一次求值已经剥掉 `%{}`、剩下 `#foo` / `ognl 表达式`」这种情况返回 false，于是**反而去求第二遍**。

| 属性 | V1 setter | V1 evaluateParams | 二次求值？ |
|---|---|---|---|
| `id` | 原样保存 | `findStringIfAltSyntax` 一次 | 否（S2-061 已关） |
| `name` | 原样保存 | `findString` 再可能 `findValue` | **是** |
| 其它 onclick/css/… | 多数原样 | 各自 `findString` | 视属性而定；S2-062 说还有 |

不是没有「别求第二遍」的检查。是 **检查看错了字符串长什么样**。V2 换成 `isAcceptableExpression`：表达式必须像 `\w+...` 这种可接受模式，`#pcbflag` 这种上下文访问直接拒绝。

即便没有 `#pcbflag`，任何第一次 `findString` 得到「不含 `%{` 但仍是 OGNL」的串，都会走进 `findValue`。

---

## 这个补丁挡住了什么、没挡住什么

- `setId` 不再 `findString`：挡住 seed 那种 `id="%{prop}"` + `prop=%{#pcbflag}` 的双重求值
- `evaluateParams` 的 `nameValue`：第一次把 `%{prop}` 变成 `#pcbflag`，`recursion` 放行第二次

变换：

```text
seed  prop=%{#pcbflag}  标签 id="%{prop}"
  V0: setId + evaluateParams → id 属性 = FLAG
  V1: 只 evaluateParams 一次 → id 属性 = 字面 %{#pcbflag}

residual  prop=#pcbflag  标签 name="%{prop}"
  V1: findString → #pcbflag
      recursion false → findValue %{#pcbflag} → value=FLAG
```

S2-062 没有点名一定是 `name`。Day Zero Sec 对 2.5.26 的公开分析写明：部分 UIBean 在没有对应 `value` 时，会用已经 `findString` 过的 `name` 去填 `nameValue`，并在 `recursion()` 为假时再求一遍——这和 tag `STRUTS_2_5_26` 的 L790–802 对得上。本 case 选 `name`/`nameValue` 就是走这条公开路径。公开 PoC 多为 RCE；本 case 用只读 `#pcbflag` 当效果通道（observed：legacy `repro.log` / case.json 记 v1 residual 的 `<input value>` 含 flag；inferred：同一二次求值在真实应用里可换成 exec）。

---

## 残余仍然走同一条 UIBean.evaluateParams OGNL 路径（CVE-2021-31805）

没有换标签类型、没有换 action、没有换身份。还是：

```http
GET /eval.action?prop=#pcbflag
```

JSP 仍渲染同一个 `<s:textfield name="%{prop}"/>`。V1 的 `setId` 修补照样存在，这条请求不依赖 `id`。`evaluateParams` 仍对 `translatedName` 做第二次 `findValue`。本 case residual 写死 `vector=name`、`prop=#pcbflag`。认证意图：v1 + `--residual` 在 NAME-VECTOR 的 `<input value>` 里观察到 `PCBFLAG_...`。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：forced `%{}` 第一次把用户串代进去；`recursion()` 只拦仍带 `%{` 的结果；`nameValue` 用 `findValue` 再跑一遍。seed 被挡住只说明「`id` 不再求两次」，不说明「其它已经 findString 过的属性不会再 findValue」。

---

## 后来又补了什么（CVE-2021-31805，2.5.30）

PR `#496`（merge `e1209fd`，*fix double evaluations*）在第二次求值前询问 `NotExcludedAcceptedPatternsChecker`。tag `STRUTS_2_5_30`：

```java
// UIBean.evaluateParams  (tag STRUTS_2_5_30 / V2, L798–806)
                    } else if (translatedName != null) {
                        boolean evaluated = !translatedName.equals(this.name);
                        boolean reevaluate = !evaluated || isAcceptableExpression(translatedName);
                        if (!reevaluate) {
                            addParameter(NAME_VALUE, translatedName);  // 字面量，不再求
                        } else {
                            String expr = completeExpressionIfAltSyntax(translatedName);
                            addParameter(NAME_VALUE, findValue(expr, valueClazz));
                        }
                    }
```

`#pcbflag` 以 `#` 开头，默认 accepted pattern 是 `\w+...` 一类，`isAcceptableExpression` 为 false，`nameValue` 保持字面 `#pcbflag`。S2-062 仍警告：不要对未校验输入使用 forced OGNL；框架只保证不再接受「因上次修漏了而导致的双重求值」。公开建议升到 2.5.30。本 benchmark 的 v2 只关闭 `#pcbflag` 这条 nameValue residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是 `id` 的 setter。真正二次求值的是 `evaluateParams` 对「已经替换过的属性值」再 `findValue`。V2 才在这一层加可接受模式。

**不是没有 recursion 检查。**  
`recursion()` 在 V1 就在 `nameValue` 分支里。缺的是「第一次 forced 求值的结果不得再当 OGNL」，而不是「结果里还有没有 `%{`」。从 V1 的 diff 只能看到 `setId`；要判断是否闭合，必须读 `evaluateParams` 里 `else if (name != null)` 那一段。

**同一 UIBean、同一 `%{prop}`，只换了写在哪个属性上。**  
S2-061 是 `id`，S2-062 是「仍有一些属性」。本 case 的 JSP 把两条并排放着，方便对照哪一次求值把 `#pcbflag` 读出来。

**金丝雀只活在 OGNL 上下文里。**  
页面源码和 action 字段都不含 flag。能读到它，说明发生了第二次求值，而不是模板把 `prop` 原样印出去。

---

## 版本、入口、参考

| | struts2-core | `setId` | `evaluateParams` / nameValue | `id="%{prop}"` seed | `name="%{prop}"` residual |
|---|---|---|---|---|---|
| V0 | 2.5.25 | `findString` | 二次 findValue | HTML id=FLAG | （不必） |
| V1 | 2.5.26 | 原样保存 | 仍二次 findValue（recursion 只认 `%{`） | id 为字面 `%{#pcbflag}` | value=FLAG |
| V2 | 2.5.30 | 原样保存 | `isAcceptableExpression` 拦 `#...` | 挡 | value 为字面 `#pcbflag` |

- Web：`GET /eval.action?prop=...`；JSP 两个 `<s:textfield>`
- 认证意图：v0 seed 的 ID-VECTOR 含 flag；v1 seed 不含；v1 residual 的 NAME-VECTOR 含 flag
- [S2-061](https://cwiki.apache.org/confluence/display/WW/S2-061) / [CVE-2020-17530](https://nvd.nist.gov/vuln/detail/CVE-2020-17530)
- [S2-062](https://cwiki.apache.org/confluence/display/WW/S2-062) / [CVE-2021-31805](https://nvd.nist.gov/vuln/detail/CVE-2021-31805)（NVD 原文：*The fix issued for CVE-2020-17530 was incomplete*）
- [PR #496](https://github.com/apache/struts/pull/496) merge `e1209fde`；[GitHub Security Lab 双重求值研究](https://securitylab.github.com/research/apache-struts-double-evaluation/)（PR 描述指向此文）
- [Day Zero Sec：Exploiting Struts RCE on 2.5.26](https://dayzerosec.com/vulns/2022/04/25/exploiting-struts-rce-on-2-5-26.html)（点名 `name` / 缺 `value` 时二次求值）
- V1 源码：tag [`STRUTS_2_5_26` UIBean.java](https://raw.githubusercontent.com/apache/struts/STRUTS_2_5_26/core/src/main/java/org/apache/struts2/components/UIBean.java)（`setId` L1026；`evaluateParams` L663–666、L790–802）
