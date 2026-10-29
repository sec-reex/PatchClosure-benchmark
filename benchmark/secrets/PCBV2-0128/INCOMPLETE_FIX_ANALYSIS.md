# jackson-databind：第一张黑名单挡住了 InvokerTransformer，名单外的类照样 `new`

- Case：`PCBV2-0128`
- 产品：FasterXML jackson-databind。运行时是 Maven 整包 `2.8.8` / `2.8.9` / `2.8.10`，挂在真实 `POST /deser`（`enableDefaultTyping()` + `readValue`）。
- 链：CVE-2017-7525（#1599，2.8.8 → 2.8.9，引入 `checkIllegalTypes` + 第一张表）→ CVE-2017-15095（#1680 + #1737，2.8.9 → 2.8.10，同一张表继续加名）
- 源码对着 tag `jackson-databind-2.8.9` 与 `2.8.10` 的 `BeanDeserializerFactory.java`。金丝雀是 benign shadow class：classpath 上只有同名空 bean，构造器读 `/canary/flag.txt`；没有真 gadget。
- 同系列后段见 `PCBV2-0004`（2.8.11 `SubTypeValidator` → 2.8.11.1 #1899）。本 case 停在黑名单刚出现、第一次加长这一截。

NVD CVE-2017-15095 原话：*This issue extends the previous flaw CVE-2017-7525 by blacklisting more classes that could be used maliciously.* oss-security（Red Hat，2017-11-02）把新 CVE 的理由写得很直：*blacklists being what they are, a further set of dangerous classes have been added since*；下游已经按 2.8.9 发过 7525 的安全更新，所以必须再给加进去的那些名字一个新编号。

**仓库里的 `patch.diff` 不是这条安全链。** ROUND7 迁过来的是 #1607（`ObjectIdInfo` / `@JsonIdentityReference`），commit `ec859af`。下面按 2.8.9 真实 `BeanDeserializerFactory` 和 heldout 残余分析，不把 #1607 当 V1 修复。

根因不只是「又发现两个 gadget」。检查插在「FQCN 是否等于集合里某一串」上；真正 `new` 的是后面的 BeanDeserializer。同一次 `createBeanDeserializer` 在 `contains` 失败之后直接继续建 deserializer。下面按请求走进去。

---

## 这块功能本来在干什么

Jackson 的 default typing 让 JSON 自己指名要实例化哪个类。典型 wire 格式：

```json
["org.apache.commons.collections.functors.InvokerTransformer", {}]
```

`ObjectMapper.enableDefaultTyping()` 之后，`readValue(body, Object.class)` 按第一个元素的字符串加载类、建 deserializer、调用无参构造器。这是 REST 服务反序列化多态 body 的真实路径。

数据流（2.8.9，本 case 的 V1）：

```text
POST /deser  JSON ["<FQCN>", {}]
    → ObjectMapper.readValue
         读出 type id = FQCN
         BeanDeserializerFactory.createBeanDeserializer
              checkIllegalTypes(ctxt, javaType, beanDesc)
                   full = type.getRawClass().getName()
                   _cfgIllegalClassNames.contains(full)  → 抛 Illegal type
                   否则 return                           ← 放行
              buildBeanDeserializer
         deserializer.deserialize → 无参构造器
    → 本 case：shadow bean 读 /canary/flag.txt，响应带 PCB_CANARY_FLAG
```

设计意图：default typing 仍然可用，但「已知危险类名」不能过。成功穿越之后的效果是**命名的类被实例化**；本 case 用构造器读金丝雀代替 RCE，观察的是同一道门是否打开。

---

## 原始漏洞：没有任何类名门（CVE-2017-7525，2.8.8）

2.8.8 没有 `checkIllegalTypes`（该方法 `@since 2.8.9`）。`readValue` 对 JSON 里写的任何 FQCN 都会去加载。#1599 把 commons-collections `InvokerTransformer` 等一批名字收进第一张黑名单，这就是 CVE-2017-7525 的修复，也是本 case 的 V0→V1。

本 case seed：

```text
["org.apache.commons.collections.functors.InvokerTransformer", {}]
```

2.8.8 上 `RESULT=DESERIALIZED`，响应里有 `PCB_CANARY_FLAG=PCBFLAG_...`。没有鉴权、没有 allowlist。公开 writeup 里这条是经典 default-typing RCE 入口；这里只验证「这个名字会不会被 new」。

---

## 维护者改了什么（CVE-2017-7525 修复，2.8.9）

2.8.9 在 `BeanDeserializerFactory` 里加静态集合，在建 bean deserializer **之前**查表。集合在类加载时填好，之后不可变：

```java
// deser/BeanDeserializerFactory.java  (jackson-databind-2.8.9)
    /**
     * @since 2.8.9
     */
    protected final static Set DEFAULT_NO_DESER_CLASS_NAMES;
    static {
        Set s = new HashSet<>();
        // Courtesy of [https://github.com/kantega/notsoserial]:
        // (and wrt [databind#1599]
        s.add("org.apache.commons.collections.functors.InvokerTransformer");
        s.add("org.apache.commons.collections.functors.InstantiateTransformer");
        s.add("org.apache.commons.collections4.functors.InvokerTransformer");
        s.add("org.apache.commons.collections4.functors.InstantiateTransformer");
        s.add("org.codehaus.groovy.runtime.ConvertedClosure");
        s.add("org.codehaus.groovy.runtime.MethodClosure");
        s.add("org.springframework.beans.factory.ObjectFactory");
        s.add("com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl");
        s.add("org.apache.xalan.xsltc.trax.TemplatesImpl");
        DEFAULT_NO_DESER_CLASS_NAMES = Collections.unmodifiableSet(s);
    }
```

调用点在 `createBeanDeserializer`：

```java
        // For checks like [databind#1599]
        checkIllegalTypes(ctxt, type, beanDesc);
        // Use generic bean introspection to build deserializer
        return buildBeanDeserializer(ctxt, type, beanDesc);
```

谓词本身只有精确 FQCN：

```java
    protected void checkIllegalTypes(DeserializationContext ctxt, JavaType type,
            BeanDescription beanDesc)
        throws JsonMappingException
    {
        String full = type.getRawClass().getName();

        if (_cfgIllegalClassNames.contains(full)) {
            ctxt.reportBadTypeDefinition(beanDesc,
                    "Illegal type (%s) to deserialize: prevented for security reasons", full);
        }
    }
```

对 seed `InvokerTransformer`：`contains(full)` 为真 → `Illegal type ... prevented for security reasons` → 构造器不跑 → `RESULT=BLOCKED`，没有 flag。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险类的名字等于集合里某一条。
2. 不在集合里的 FQCN 可以安全地 `new`。

第二点是黑名单的结构缺陷：每发现一个 gadget 就 `s.add`，集合永远落后于 classpath 上还没被点名的类。2.8.9 甚至还没有后来的 Spring 继承链、c3p0 前缀。cowtowncoder 在 #1723 里自己写：*More work is probably needed to refine set of classes blocked: about 10 or so are blacklisted*。

---

## 消毒之后，谁真正 `new` 那个类

`checkIllegalTypes` 返回之后（没抛），`createBeanDeserializer` 继续 `buildBeanDeserializer`。default typing 的 type id 已经解析成 `Class`；Jackson 调用无参构造器。**没有第二道类名检查。**

本 case 的 HTTP 服务在 `readValue` 成功后把 shadow bean 构造器里读到的 token 写进响应。观察通道和真实 RCE 是同一扇门：名字过了 `contains`，对象就会被建出来。

过滤器刚看过的是 `String full = raw.getName()` 是否在 HashSet 里；open（这里是 `new`）看到的是任意 `Class`。中间没有 allowlist。

---

## 仓库里已经有更强的检查，2.8.9 没用上

2.8.9 的 `checkIllegalTypes` **只有** `contains(full)`。没有：

- `full.startsWith("org.springframework.")` 再沿继承链找 advisor/context（那是 2.8.11 / #1855）
- `com.mchange.v2.c3p0.` 前缀（更晚）
- `PolymorphicTypeValidator` allowlist（2.10）

#1680 在 2.8.9 发布后立刻出现：*Looks like there is at least one other "well-known" type to block besides 9 already added: `com.sun.rowset.JdbcRowSetImpl`*。也就是说第一张表合进去的时候，维护者已经知道名单会变长，却仍然只做精确匹配。

更强、当时讨论过的做法：关掉 default typing；或白名单。#1737 标题甚至写 *Although eventual approach is likely (white-listing), at this point addition in databind is needed.* V1 选择继续 `s.add`。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「集合 vs new」落到具体名字：

- `checkIllegalTypes`：`full` 是否等于已枚举的九个字符串
- BeanDeserializer：按这个 `Class` 做实例化

只要 JSON 里的 FQCN 不在 2.8.9 的集合里，第一道门放行，第二道门会 `new`。

#1737 点名、2.8.10 才写入的 c3p0 名字（本 case residual 用这一条）：

```text
com.mchange.v2.c3p0.WrapperConnectionPoolDataSource
```

在 2.8.9 源码的 `static { ... }` 里搜这串：没有。`checkIllegalTypes` 走到函数结尾，静默返回。`readValue` 实例化 shadow bean，构造器读金丝雀。

```text
seed:      ["org.apache.commons.collections.functors.InvokerTransformer", {}]
residual:  ["com.mchange.v2.c3p0.WrapperConnectionPoolDataSource", {}]
```

只换了数组第一个字符串。同一 `POST /deser`，同一 `readValue`，同一 `checkIllegalTypes`。#1680 的 `JdbcRowSetImpl` 是同一轮加长里的另一个名字，效果相同。

---

## 残余仍然走同一条 default-typing 反序列化路径（CVE-2017-15095）

没有换 endpoint、没有关 default typing、没有换观察通道。还是：

```http
POST /deser
Content-Type: application/json

["com.mchange.v2.c3p0.WrapperConnectionPoolDataSource", {}]
```

`checkIllegalTypes` 照样执行；2.8.9 的 HashSet 照样查；查完放行；构造器读 `/canary/flag.txt`；响应里出现 `PCB_CANARY_FLAG=PCBFLAG_...`。

本 case residual candidate：

```text
json_body = '["com.mchange.v2.c3p0.WrapperConnectionPoolDataSource", {}]'
```

和 #1737 / NVD「blacklisting more classes」同一类名字。认证：v1 residual 观察到 flag；2.8.10 上是 `Illegal type ... prevented for security reasons`。

seed 被挡住只说明「#1599 写进集合的那些名字没了」，不说明「default typing 不能再 new 危险类」。

平台 verify 与这条链是同一 sink：真实 jar 的 `checkIllegalTypes`。`patch.diff` 虽是 #1607，heldout 打的仍是黑名单缺口，不是 ObjectId。

---

## 后来又补了什么（CVE-2017-15095，2.8.10）

2.8.10 仍是往同一张表加行。#1680 加 JdbcRowSetImpl；#1737 加 FileHandler、RMI、Spring advisor、c3p0 两个 DataSource 等：

```java
// deser/BeanDeserializerFactory.java  (jackson-databind-2.8.10)
        s.add("org.apache.xalan.xsltc.trax.TemplatesImpl");

        // [databind#1680]: may or may not be invocations to a limited degree
        s.add("com.sun.rowset.JdbcRowSetImpl");
        // [databind#1737]: JDK types
        s.add("java.util.logging.FileHandler");
        s.add("java.rmi.server.UnicastRemoteObject");
        // [databind#1737]: more 3rd party
        s.add("org.springframework.aop.support.AbstractBeanFactoryPointcutAdvisor");
        s.add("org.springframework.beans.factory.config.PropertyPathFactoryBean");
        s.add("com.mchange.v2.c3p0.JndiRefForwardingDataSource");
        s.add("com.mchange.v2.c3p0.WrapperConnectionPoolDataSource");

        DEFAULT_NO_DESER_CLASS_NAMES = Collections.unmodifiableSet(s);
```

`contains(full)` 现在对 residual 名字为真 → 抛同样的 `Illegal type`。这仍然是黑名单加行。几个月后 #1855 / CVE-2017-17485、#1899 / CVE-2018-5968（`PCBV2-0004`）继续在同一张表上长；2.8.11 才把这张表搬进 `SubTypeValidator`。2.10 才有可配置的 `PolymorphicTypeValidator`。本 benchmark 的 v2 只关闭 #1737 这条 c3p0 residual。

---

## 从这条链还能看出什么

**维护者改错了哪一层。**  
他们改的是 `DEFAULT_NO_DESER_CLASS_NAMES` 的内容。真正 `new` 的是 BeanDeserializer。V2 仍在同一层加行，没有把 default typing 接到 allowlist。

**不是没有更好的谓词。**  
#1737 讨论里已经提到 white-listing「最终会是正路」。2.8.9 只有精确 FQCN。从 V1 能看到的安全 diff（#1599，**不是**仓库里那份 #1607 patch.diff）只是九个 `s.add`；要判断是否闭合，必须看到 `checkIllegalTypes` 在 `contains` 失败之后直接返回。

**同一 `checkIllegalTypes`、同一 JSON 形状，只换了 FQCN。**  
任何未枚举的 gadget 名在 2.8.9 上都是这条残余。c3p0 只是 #1737 里被点名、本 case 选来当金丝雀的那一个。

**金丝雀不在 JSON 里是有意的。**  
body 只有类名。token 出现在响应里，说明无参构造器跑过，也就是过滤器放行了实例化。真 commons-collections / c3p0 不在 classpath 上，名单是按**字符串**做决定，不是按 gadget 能不能打。

**`patch.diff` 对不上这条 CVE 链。**  
读 case 的人如果只看 diff，会以为 V1 修的是 ObjectId。以 tag `jackson-databind-2.8.9` 的 `BeanDeserializerFactory` 和 NVD「extends CVE-2017-7525 by blacklisting more classes」为准。

---

## 版本、入口、参考

| | 版本 | `checkIllegalTypes` | InvokerTransformer seed | c3p0 WrapperConnectionPoolDataSource residual |
|---|---|---|---|---|
| V0 | 2.8.8 | 不存在 | 实例化，读到金丝雀 | （不必） |
| V1 | 2.8.9 | HashSet 九个 #1599 名字 | `Illegal type` | 实例化，读到金丝雀 |
| V2 | 2.8.10 | HashSet 加 #1680/#1737 | 挡 | `Illegal type` |

- HTTP：`POST /deser`，body `["<FQCN>", {}]`
- [CVE-2017-7525](https://nvd.nist.gov/vuln/detail/CVE-2017-7525)、[CVE-2017-15095](https://nvd.nist.gov/vuln/detail/CVE-2017-15095)
- [#1599](https://github.com/FasterXML/jackson-databind/issues/1599)、[#1680](https://github.com/FasterXML/jackson-databind/issues/1680)、[#1737](https://github.com/FasterXML/jackson-databind/issues/1737)、[#1723](https://github.com/FasterXML/jackson-databind/issues/1723)
- [oss-security：CVE-2017-15095 follow-up to CVE-2017-7525](https://www.openwall.com/lists/oss-security/2017/11/02/3)
- 源码：[`2.8.9` `BeanDeserializerFactory`](https://github.com/FasterXML/jackson-databind/blob/jackson-databind-2.8.9/src/main/java/com/fasterxml/jackson/databind/deser/BeanDeserializerFactory.java)、[`2.8.10` 加长后的同一文件](https://github.com/FasterXML/jackson-databind/blob/jackson-databind-2.8.10/src/main/java/com/fasterxml/jackson/databind/deser/BeanDeserializerFactory.java)
- 后续同一黑名单：`PCBV2-0004`（CVE-2018-5968）
