# jackson-databind：黑名单是一张名单，不在名单上的类照样 `new`

- Case：`PCBV2-0004`
- 产品：FasterXML jackson-databind（本 case 官方 Maven 包 `2.8.8` / `2.8.11` / `2.8.11.1`，挂在真实 `POST /deser` 服务上，`enableDefaultTyping()` + `readValue`）
- 链：CVE-2017-7525（#1599，2.8.11 引入 `SubTypeValidator`）→ CVE-2017-15095 / CVE-2017-17485（同一张表继续加名）→ CVE-2018-5968（#1899，2.8.11.1 再加两个）
- 源码对着 `jackson-databind-2.8.11` 与 `2.8.11.1` 的 `SubTypeValidator.java`。运行时是整包 jackson-databind，不是抽出来的函数。金丝雀是 benign shadow class：classpath 上只有同名空 bean，构造器读 `/canary/flag.txt`；没有真 gadget。

NVD 对 CVE-2018-5968 的原话：*allows unauthenticated remote code execution because of an incomplete fix for the CVE-2017-7525 and CVE-2017-17485 deserialization flaws. This is exploitable via two different gadgets that bypass a blacklist.* Issue #1899 标题就是 *Another two gadgets to exploit default typing*。

根因不只是「又发现两个 gadget」。检查插在「FQCN 是否等于集合里某一串」上；真正 `new` 的是后面的 BeanDeserializer。同文件里已经有按前缀走继承链的 Spring 检查，Hibernate / iBatis 用不上。下面按请求走进去。

---

## 这块功能本来在干什么

Jackson 的 default typing 让 JSON 自己指名要实例化哪个类。典型 wire 格式：

```json
["org.apache.commons.collections.functors.InvokerTransformer", {}]
```

`ObjectMapper.enableDefaultTyping()` 之后，`readValue(body, Object.class)` 会按第一个元素的字符串去加载类、建 deserializer、调用无参构造器。这是 REST 服务反序列化多态 body 的真实路径。

数据流（2.8.11，本 case 的 V1）：

```text
POST /deser  JSON ["<FQCN>", {}]
    → ObjectMapper.readValue
         读出 type id = FQCN
         BeanDeserializerFactory.createBeanDeserializer
              SubTypeValidator.validateSubType(ctxt, javaType)
                   1. DEFAULT_NO_DESER_CLASS_NAMES.contains(full)  → 拒绝
                   2. full.startsWith("org.springframework.")
                      则沿 superclass 找 AbstractPointcutAdvisor /
                      AbstractApplicationContext                  → 拒绝
                   3. 否则 return                                ← 放行
              再构建 BeanDeserializer
         deserializer.deserialize → 无参构造器
    → 本 case：shadow bean 读 /canary/flag.txt，响应带 PCB_CANARY_FLAG
```

设计意图：default typing 仍然可用，但「已知危险类名」不能过。成功穿越之后的效果是**命名的类被实例化**；本 case 用构造器读金丝雀代替 RCE，观察的是同一道门是否打开。

---

## 原始漏洞：没有任何类名门（CVE-2017-7525，2.8.8）

2.8.8 没有 `SubTypeValidator`（该类 `@since 2.8.11`）。`readValue` 对 JSON 里写的任何 FQCN 都会去加载。#1599 把 commons-collections `InvokerTransformer` 等一批名字收进第一张黑名单，这就是 CVE-2017-7525 的修复，也是本 case 的 V0→V1。

本 case seed：

```text
["org.apache.commons.collections.functors.InvokerTransformer", {}]
```

2.8.8 上 `RESULT=DESERIALIZED`，响应里有 `PCB_CANARY_FLAG=PCBFLAG_...`。没有鉴权、没有 allowlist。邮件和公开 writeup 里这条是经典 default-typing RCE 入口；这里只验证「这个名字会不会被 new」。

---

## 维护者改了什么（CVE-2017-7525 修复，2.8.11）

2.8.11 新增 `SubTypeValidator`，在建 bean deserializer **之前**查表。静态集合在类加载时填好，之后不可变：

```java
// jsontype/impl/SubTypeValidator.java  (jackson-databind-2.8.11)
    protected final static Set<String> DEFAULT_NO_DESER_CLASS_NAMES;
    static {
        Set<String> s = new HashSet<String>();
        // Courtesy of [https://github.com/kantega/notsoserial]:
        // (and wrt [databind#1599])
        s.add("org.apache.commons.collections.functors.InvokerTransformer");
        s.add("org.apache.commons.collections.functors.InstantiateTransformer");
        ...
        s.add("com.sun.rowset.JdbcRowSetImpl");           // #1680
        s.add("java.util.logging.FileHandler");           // #1737
        s.add("org.springframework.beans.factory.config.PropertyPathFactoryBean");
        s.add("com.mchange.v2.c3p0.JndiRefForwardingDataSource");
        s.add("com.mchange.v2.c3p0.WrapperConnectionPoolDataSource");
        s.add("org.apache.tomcat.dbcp.dbcp2.BasicDataSource");  // #1855
        s.add("com.sun.org.apache.bcel.internal.util.ClassLoader");
        DEFAULT_NO_DESER_CLASS_NAMES = Collections.unmodifiableSet(s);
    }

    public void validateSubType(DeserializationContext ctxt, JavaType type)
            throws JsonMappingException
    {
        final Class<?> raw = type.getRawClass();
        String full = raw.getName();

        main_check:
        do {
            if (_cfgIllegalClassNames.contains(full)) {
                break;
            }
            if (full.startsWith(PREFIX_SPRING)) {  // "org.springframework."
                for (Class<?> cls = raw; cls != Object.class; cls = cls.getSuperclass()) {
                    String name = cls.getSimpleName();
                    if ("AbstractPointcutAdvisor".equals(name)
                            || "AbstractApplicationContext".equals(name)) {
                        break main_check;
                    }
                }
            }
            return;   // 放行
        } while (false);

        throw JsonMappingException.from(ctxt,
            String.format("Illegal type (%s) to deserialize: prevented for security reasons", full));
    }
```

对 seed `InvokerTransformer`：`contains(full)` 为真 → 抛 `Illegal type ... prevented for security reasons` → 构造器不跑 → 响应 `RESULT=BLOCKED`，没有 flag。这就是 v1 + `--seed` 退出码 10。2.8.11 已经含 #1680/#1737/#1855，所以本 case 的 V1 不是「还没黑名单」，而是「黑名单已经打过三轮补丁」。

补丁默认了两件事：

1. 危险类的名字等于集合里某一条，或属于 Spring 那两个抽象基类。
2. 不在这两条规则里的 FQCN 可以安全地 `new`。

第二点是黑名单的结构缺陷，不是漏写一行那么简单：每发现一个 gadget 就往集合里 `s.add`，集合永远落后于 classpath 上还没被点名的类。

---

## 消毒之后，谁真正 `new` 那个类

`validateSubType` 返回之后，`BeanDeserializerFactory` 继续为这个 `JavaType` 建 deserializer。default typing 的 type id 已经解析成 `Class`；Jackson 调用无参构造器（或带 `@JsonCreator` 的工厂）。**没有第二道类名检查。**

本 case 的 HTTP 服务在 `readValue` 成功后把 shadow bean 构造器里读到的 token 写进响应。观察通道和真实 RCE 是同一扇门：名字过了 `validateSubType`，对象就会被建出来。

过滤器刚看过的是 `String full = raw.getName()` 是否在 HashSet 里；open（这里是 `new`）看到的是任意 `Class`。中间没有 allowlist。

---

## 仓库里已经有更强的检查，Hibernate / iBatis 没用上

同一函数里，Spring 已经不是精确 FQCN，而是：

```text
full.startsWith("org.springframework.")
    AND 继承链上有 AbstractPointcutAdvisor 或 AbstractApplicationContext
```

这是 #1855（CVE-2017-17485）加的，专门避免「再发现一个 Spring ApplicationContext 子类又要加一行」。2.8.11 **没有**对等的：

- `org.hibernate.` 前缀
- `org.apache.ibatis.` 前缀
- `com.mchange.v2.c3p0.` 前缀（2.8.11.1 才加 `PREFIX_C3P0` + `endsWith("DataSource")`）

`org.hibernate.jmx.StatisticsService` 既不在 HashSet 里，也不以 `org.springframework.` 开头，继承链走不到那两个抽象类 → `return` 放行。

更强、当时已经写在注释和后续版本里的做法：

- 把 default typing 换成 allowlist（Jackson 2.10 的 `PolymorphicTypeValidator` / `DefaultTyping` 收紧）；
- 或对第三方包做前缀规则，而不是等 gadget 一篇篇披露。

V1 选择继续 `s.add`。#1899 仍然是 `s.add` 两行。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「集合 vs new」落到具体名字：

- `validateSubType`：`full` 是否等于已枚举的字符串，或是否 Spring 那两个基类
- BeanDeserializer：按这个 `Class` 做实例化

只要 JSON 里的 FQCN 不在 2.8.11 的集合里、又不是 `org.springframework.*` 的那两个家族，第一道门放行，第二道门会 `new`。

#1899 点名的两个（NVD 说的 *two different gadgets*）：

```text
org.hibernate.jmx.StatisticsService
org.apache.ibatis.datasource.jndi.JndiDataSourceFactory
```

在 2.8.11 源码的 `static { ... }` 里搜这两串：没有。`validateSubType` 走到 `return`。`readValue` 实例化 shadow bean，构造器读金丝雀。

```text
seed:      ["org.apache.commons.collections.functors.InvokerTransformer", {}]
residual:  ["org.hibernate.jmx.StatisticsService", {}]
           ["org.apache.ibatis.datasource.jndi.JndiDataSourceFactory", {}]
```

只换了数组第一个字符串。同一 `POST /deser`，同一 `readValue`，同一 `validateSubType`。

---

## 残余仍然走同一条 default-typing 反序列化路径（CVE-2018-5968）

没有换 endpoint、没有关 default typing、没有换观察通道。还是：

```http
POST /deser
Content-Type: application/json

["org.hibernate.jmx.StatisticsService", {}]
```

`validateSubType` 照样执行；2.8.11 的 HashSet 照样查；查完放行；构造器读 `/canary/flag.txt`；响应里出现 `PCB_CANARY_FLAG=PCBFLAG_...`。

本 case residual candidate（两条任一即可证明）：

```text
json_body = '["org.hibernate.jmx.StatisticsService", {}]'
json_body = '["org.apache.ibatis.datasource.jndi.JndiDataSourceFactory", {}]'
```

和 #1899 / NVD 同一对名字。认证：v1 residual 观察到 flag；2.8.11.1 上两条都是 `Illegal type ... prevented for security reasons`。

seed 被挡住只说明「#1599 写进集合的那些名字没了」，不说明「default typing 不能再 new 危险类」。

---

## 后来又补了什么（CVE-2018-5968，2.8.11.1）

2.8.11.1 就是 #1899 那次微发布。还是往同一张表加两行，另外补上 c3p0 前缀（#1931 方向）：

```java
// SubTypeValidator.java  (jackson-databind-2.8.11.1)
        s.add("org.apache.tomcat.dbcp.dbcp2.BasicDataSource");
        s.add("com.sun.org.apache.bcel.internal.util.ClassLoader");
        // [databind#1899]: more 3rd party
        s.add("org.hibernate.jmx.StatisticsService");
        s.add("org.apache.ibatis.datasource.jndi.JndiDataSourceFactory");

        DEFAULT_NO_DESER_CLASS_NAMES = Collections.unmodifiableSet(s);
```

`contains(full)` 现在对这两个名字为真 → 抛同样的 `Illegal type`。Debian 的 jackson-databind 补丁把 #1855 和 #1899 写在一起，注释即 *incomplete fix for CVE-2017-7525*。

这仍然是黑名单加行。后来的 CVE-2018-7489、CVE-2019-*、CVE-2020-24616 继续在同一张表上长。2.10 才把「默认允许 + 枚举拒绝」换成可配置的 `PolymorphicTypeValidator`。本 benchmark 的 v2 只关闭 #1899 这一条 residual。

---

## 从这条链还能看出什么

**维护者改错了哪一层。**  
他们改的是 `DEFAULT_NO_DESER_CLASS_NAMES` 的内容。真正 `new` 的是 BeanDeserializer。V2 仍在同一层加两行，没有把 default typing 接到 allowlist。

**不是没有更好的谓词。**  
同函数的 Spring 继承链检查已经比精确 FQCN 宽。Hibernate JMX / iBatis JNDI 完全可以按前缀拦。V1 只对 Spring 用了这种宽规则。从 V1 的 diff 只能看到一堆 `s.add`；要判断是否闭合，必须看到 `validateSubType` 在 `contains` 失败之后直接 `return`。

**同一 `validateSubType`、同一 JSON 形状，只换了 FQCN。**  
任何未枚举、又不是 Spring 那两个基类的 gadget 名，在 2.8.11 上都是这条残余。

**金丝雀不在 JSON 里是有意的。**  
body 只有类名。token 出现在响应里，说明无参构造器跑过，也就是过滤器放行了实例化。

---

## 版本、入口、参考

| | 版本 | `SubTypeValidator` | InvokerTransformer seed | StatisticsService residual |
|---|---|---|---|---|
| V0 | 2.8.8 | 不存在 | 实例化，读到金丝雀 | （不必） |
| V1 | 2.8.11 | HashSet + Spring 基类走 | `Illegal type` | 实例化，读到金丝雀 |
| V2 | 2.8.11.1 | HashSet 加 #1899 两行 | 挡 | `Illegal type` |

- HTTP：`POST /deser`，body `["<FQCN>", {}]`
- 认证（本平台）：v0 seed 观察到 flag；v1 seed BLOCKED；v1 residual 观察到。
- [CVE-2017-7525](https://nvd.nist.gov/vuln/detail/CVE-2017-7525)、[CVE-2018-5968](https://nvd.nist.gov/vuln/detail/CVE-2018-5968)（CWE-184 Incomplete List of Disallowed Inputs）
- [databind#1899](https://github.com/FasterXML/jackson-databind/issues/1899)
- V1 源码：[`SubTypeValidator.java` @ jackson-databind-2.8.11](https://github.com/FasterXML/jackson-databind/blob/jackson-databind-2.8.11/src/main/java/com/fasterxml/jackson/databind/jsontype/impl/SubTypeValidator.java)
- V2 源码：[`SubTypeValidator.java` @ jackson-databind-2.8.11.1](https://github.com/FasterXML/jackson-databind/blob/jackson-databind-2.8.11.1/src/main/java/com/fasterxml/jackson/databind/jsontype/impl/SubTypeValidator.java)
