# Spring：classLoader 只在 `Class` 上被滤掉，JDK9 的 `module` 绕一圈又回来

- Case：`PCBV2-0196`
- 产品：Spring Framework（`spring-beans` / `spring-webmvc`）。运行时是 Maven Central 的整包 JAR + 最小 MVC WAR，部署在 Tomcat 上，不是抽出来的函数。
- 链：CVE-2010-1622（3.0.2 无黑名单 → 5.3.17 已滤 `Class.classLoader`）→ CVE-2022-22965（5.3.17 → 5.3.18，Spring4Shell）
- 源码对着 tag `v5.3.17` / `v5.3.18` 的 `spring-beans/.../CachedIntrospectionResults.java`。金丝雀是把 Tomcat `AccessLogValve` 的 `pattern` 绑成 flag，写出 `webapps/ROOT/pcb_*.txt`，再被 DefaultServlet 读回。

Spring 官方博客（2022-03-31）写的是 JDK 9+ 上的 data binding RCE，影响 5.3.0–5.3.17。NVD 对 CVE-2010-1622 的原话是 *class.classLoader.URLs[0]=jar:*。两条 CVE 打的是同一条属性链的入口：`Object.getClass()` 之后还能摸到 `ClassLoader`，再摸到容器内部。

根因不只是「又多了一个属性名」。检查插在「正在内省的类是不是 `Class.class`，属性名是不是 `classLoader`/`protectionDomain`」上；真正把值写进 Tomcat 的是后面 `BeanWrapper` 对嵌套属性的 `setPropertyValue`。同一次内省循环里完全可以按**属性类型**丢掉所有 `ClassLoader`，V1 却只在 `beanClass == Class.class` 时按名字跳过。下面按请求走进去。

---

## 这块功能本来在干什么

Spring MVC 把 query / form 绑到控制器方法参数上。本 case 的 `HelloController.hello(Greeting greeting)` 没有 `@RequestBody`，就是这条默认 data-binding 面。一次典型请求：

```http
GET /hello?content=hi
```

`ServletRequestDataBinder` 按点号拆属性，每一步用 `CachedIntrospectionResults.getPropertyDescriptor` 找 getter/setter，再 `BeanWrapper` 读/写。`Greeting` 是普通 POJO，但它继承了 `Object.getClass()`，所以 `class` 是合法属性。

设计意图：调用方只能改 `Greeting` 自己的字段（`content` 之类）。成功穿越之后的效果是：**顺着 `class` 走进 JDK / Tomcat 的可变对象，重配 `AccessLogValve`，把 flag 写进 webapp 目录**。

数据流：

```text
GET /hello?class.classLoader.resources.context.parent.pipeline.first.pattern=<FLAG>
    → HelloController.hello(Greeting)
         ServletRequestDataBinder.bind
              CachedIntrospectionResults.forClass(当前类型)
                   V1：仅当 beanClass==Class 时丢掉 classLoader
              BeanWrapper.setPropertyValue
                   内核/反射调用 AccessLogValve.setPattern / setDirectory / …
    → Tomcat 写出 webapps/ROOT/pcb_original.txt
    → GET /pcb_original.txt  → body 里 PCBFLAG_...
```

不需要登录。WAR 必须跑在独立 Tomcat + JDK 9+ 上（官方「Am I Impacted」清单）。嵌入式 Spring Boot jar 不是这条 PoC 的场景。

---

## 原始漏洞：`class.classLoader` 一直通到 ClassLoader（CVE-2010-1622，3.0.2）

3.0.2 的 `CachedIntrospectionResults` 把 `Introspector.getBeanInfo` 给出的所有 `PropertyDescriptor` 放进缓存，**没有**丢掉 `classLoader`。NVD：*allows remote attackers to execute arbitrary code via an HTTP request containing `class.classLoader.URLs[0]=jar:` followed by a URL of a crafted .jar file*。

本 case seed 不走远程 jar，走 Tomcat 的 AccessLogValve（和 2010 年那条链同一入口，sink 换成良性写文件）：

```text
class.classLoader.resources.context.parent.pipeline.first.pattern = <FLAG>
class.classLoader.resources.context.parent.pipeline.first.suffix  = .txt
class.classLoader.resources.context.parent.pipeline.first.directory = webapps/ROOT
class.classLoader.resources.context.parent.pipeline.first.prefix = pcb_original
class.classLoader.resources.context.parent.pipeline.first.fileDateFormat = （空）
```

`class` 得到 `Greeting.class`，`classLoader` 得到 WebApp classloader，后面是 Tomcat 内部的 `resources.context.parent.pipeline.first`——也就是 AccessLogValve。setter 一跑，valve 往 `webapps/ROOT/pcb_original.txt` 写一行 flag。`GET /pcb_original.txt` 读到 `PCBFLAG_...`。这就是 v0 + `--seed` 观察到 flag。

---

## 维护者改了什么（CVE-2010-1622 修复，落到 5.3.17）

2010 年的修复把 `Class.getClassLoader()` / `getProtectionDomain()` 从 `Class` 的属性表里拿掉。5.3.17（本 case V1，Spring4Shell 之前最后一个 5.3.x）里这段还在，对着 tag `v5.3.17`：

```java
// CachedIntrospectionResults 构造器  (spring-framework v5.3.17)
PropertyDescriptor[] pds = this.beanInfo.getPropertyDescriptors();
for (PropertyDescriptor pd : pds) {
  if (Class.class == beanClass &&
      ("classLoader".equals(pd.getName()) || "protectionDomain".equals(pd.getName()))) {
    // Ignore Class.getClassLoader() and getProtectionDomain() methods
    // - nobody needs to bind to those
    continue;
  }
  pd = buildGenericTypeAwarePropertyDescriptor(beanClass, pd);
  this.propertyDescriptors.put(pd.getName(), pd);
}
```

V1 谓词的字面意思：

| 条件 | 含义 |
|---|---|
| `Class.class == beanClass` | **正在内省的那个类**必须是 `java.lang.Class` |
| 属性名是 `classLoader` 或 `protectionDomain` | 按名字丢掉 |
| 其它类型上的同名属性 | **不过滤** |
| `Class` 上的其它属性（JDK9 起有 `module`） | **不过滤** |

对 seed 这种 `class.classLoader.*`，第二步的当前类型就是 `Class`，`classLoader` 被 `continue`，binder 找不到描述符，AccessLogValve 不会被改。`GET /pcb_original.txt` 404。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险的 `ClassLoader` 只作为 `Class` 的直接属性出现。
2. 以后 `Class` 上不会再长出「能拿到 ClassLoader 的新属性」。

第二点在 JDK 9 被 `Class.getModule()` 打破。`java.lang.Module` 自己有 `getClassLoader()`，而那时当前 `beanClass` 是 `Module`，不是 `Class`，V1 的 `if` 整段不进。

---

## 消毒之后，属性怎么接到 Tomcat 上

`CachedIntrospectionResults` 只决定「这个类型暴露哪些属性」。真正写值的是 `AbstractNestablePropertyAccessor` / `BeanWrapperImpl`：按点号一段一段 `getPropertyValue`，最后 `setPropertyValue` 调 setter。V1 滤掉的是 `Class.classLoader` 这一跳；后面的 `resources.context.parent.pipeline.first.pattern` 没有任何额外谓词。

所以只要还能从 `Class` 走到一个**别的类型**上的 `classLoader`，binder 就会继续往下写。JDK 9 的路径是：

```text
class          → java.lang.Class          （V1 会滤这个类型上的 classLoader）
class.module   → java.lang.Module         （V1 不认识 module）
class.module.classLoader → ClassLoader    （当前类型是 Module，名字过滤不触发）
class.module.classLoader.resources.context.parent.pipeline.first.*
               → AccessLogValve setters
```

过滤器刚看过的是「`Class` 的属性名表」；open/write 看到的是「`Module.getClassLoader()` 返回的那个对象上的嵌套 setter」。两套语义中间没有「属性类型是 ClassLoader 就拒绝」的第二次谓词。

嵌套路径的每一步都重新 `forClass(当前对象的运行时类型)`。所以 V1 的 `if (Class.class == beanClass)` 只在**恰好走到 Class 实例**的那一跳生效：

```text
Greeting                          → forClass(Greeting)     不过滤 class
  .class                          → forClass(Class)        丢掉 classLoader，留下 module
    .module                       → forClass(Module)       beanClass 不是 Class，不过滤
      .classLoader                → forClass(ClassLoader)  名字过滤不触发
        .resources.context.parent.pipeline.first.pattern
                                  → AccessLogValve.setPattern(flag)
```

`HelloController` 拿到的 `Greeting` 本身没变；被改的是 Tomcat 全局 pipeline 上的 valve。金丝雀出现在 `GET /pcb_decisive.txt`，依据就是这次 setter，而不是「Greeting 里碰巧有个同名字段」。

5.3.17 的接口内省循环（`introspectInterfaces`）同样**没有**按 `PropertyType` 丢掉 ClassLoader。V2 才在这条循环里补了同样的类型判断。也就是说，即便某个 ClassLoader 属性是从接口 BeanInfo 进来的，V1 也放行。

---

## 仓库里已经有更强的检查，V1 没用

Spring 自己的 data-binder 早就支持 `WebDataBinder.setDisallowedFields`。官方 Spring4Shell 应急博客给出的 workaround 就是全局禁掉 `class.*` / `*.class.*`：

```java
String[] denylist = new String[]{"class.*", "Class.*", "*.class.*", "*.Class.*"};
dataBinder.setDisallowedFields(denylist);
```

谁调用它：

| 位置 | 用 `disallowedFields` / 按类型滤 ClassLoader？ |
|---|---|
| 应用自己的 `@InitBinder`（可选） | 可以，但默认没有 |
| V1 `CachedIntrospectionResults` | **否**，只按 `Class` + 属性名 |
| V2 `CachedIntrospectionResults` | 是，`ClassLoader.isAssignableFrom(pd.getPropertyType())` |

V1 等于在内省层做了一个**更弱**的名字黑名单（只罩 `Class` 这一个类型），而「任何返回 ClassLoader 的属性都不该能绑」这个更强谓词要到 5.3.18 才写上。不是框架里没有字段级拒绝，是 **默认 binder 没用**。

即便没有 `module`，只要 `Class` 上再出现第三个能拿到 ClassLoader 的属性，V1 的两名字列表也会漏。V2 改成按 `PropertyType` 判断，就是承认名字列表不够。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs setter」落到具体代码：

- V1：`beanClass == Class && name ∈ {classLoader, protectionDomain}` → 不进缓存
- `BeanWrapper.setPropertyValue`：缓存里有描述符就调 setter

只要构造一条嵌套路径，使「拿到 ClassLoader 的那一跳」发生在**不是** `Class` 的类型上，第一行会放行，第二行仍然写到 Tomcat。

`class.module.classLoader` 就是这样来的。`module` 不是 `classLoader`，V1 放行；下一跳的当前类型变成 `Module`，`classLoader` 这个名字不再被特殊对待。

```text
seed:     class.classLoader.resources.context.parent.pipeline.first.pattern=<FLAG>
          → V1 在 Class 上丢掉 classLoader → 404

residual: class.module.classLoader.resources.context.parent.pipeline.first.pattern=<FLAG>
          → Class.module 放行 → Module.classLoader 放行 → AccessLogValve 被改
          → GET /pcb_decisive.txt 出现 PCBFLAG_...
```

官方博客的「Am I Impacted」把这条链的环境写死了：JDK 9+（才有 `Class.getModule()`）、独立 Tomcat WAR（valve 暴露在 classloader 的 `resources` 上）。本 case 的镜像按这个清单钉 Tomcat 9.0.60 / JDK 17，就是为了让 V1/V2 的差只来自 Spring 那几行内省，而不是 Tomcat 后来自己的缓解。

---

## 残余仍然走同一条 data-binding 写 valve 路径（CVE-2022-22965）

没有换控制器、没有换绑定入口、没有换 AccessLogValve。还是：

```http
GET /hello?class.module.classLoader.resources.context.parent.pipeline.first.pattern=<FLAG>&…directory=webapps/ROOT&prefix=pcb_decisive&suffix=.txt&fileDateFormat=
```

`HelloController` 仍然 `hello(Greeting)`。V1 那两行名字过滤照样执行；执行完之后 `module` 还在缓存里；`BeanWrapper` 继续走到 `Module.getClassLoader()`，再走到同一组 valve setter。写出的文件名换了，sink 没换。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：过滤按「类型 × 名字」而不是「属性类型」；写发生在检查之后；默认 binder 没有使用已经存在的 `disallowedFields`。seed 被挡住只说明「从 `Class` 直接取 `classLoader` 没了」，不说明「不能再从 data-binding 改到 AccessLogValve」。

---

## 后来又补了什么（CVE-2022-22965，5.3.18）

5.3.18 把「只在 `Class` 上按名字滤」换成两条更硬的规则。对着 tag `v5.3.18`：

```java
// CachedIntrospectionResults 构造器  (v5.3.18)
if (Class.class == beanClass &&
    (!"name".equals(pd.getName()) && !pd.getName().endsWith("Name"))) {
  // Only allow all name variants of Class properties
  continue;
}
if (pd.getPropertyType() != null &&
    (ClassLoader.class.isAssignableFrom(pd.getPropertyType())
     || ProtectionDomain.class.isAssignableFrom(pd.getPropertyType()))) {
  // Ignore ClassLoader and ProtectionDomain types
  // - nobody needs to bind to those
  continue;
}
```

对残余输入：

```text
class.module          → Class 上只留 *Name，module 被丢掉
即便走到 Module      → classLoader 的 PropertyType 是 ClassLoader，第二段丢掉
```

`class.module.classLoader.*` 在第一跳或第二跳断开，AccessLogValve 不再被改，`GET /pcb_decisive.txt` 404。公开建议是升级到 5.3.18 / 5.2.20；Tomcat 9.0.62+ 从容器侧也收了这条 valve 链，那是另一层。

即便如此，这仍然是「内省缓存里少暴露几个属性」，`BeanWrapper` 还是见描述符就写。对 `module` 这条已知链它够用；若还有其它不经过 ClassLoader 类型、仍能摸到容器可写对象的属性，需要另证。本 benchmark 的 v2 只关闭这一条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是 `Class` 的属性名表。真正改到磁盘的是 `AccessLogValve.setPattern`。V2 仍在内省层加码，但终于按**属性类型**滤，而不是赌 `Class` 以后不再长出新 getter。

**不是没有更好的谓词。**  
`setDisallowedFields("class.*")` 和「PropertyType 是 ClassLoader 就拒绝」都比 V1 那两行名字更接近「不要从用户参数走进 JVM 内部」。前者是公开 workaround，后者 2010 年就可以写。从 V1 的 diff 只能看到 `Class` 上少了两个名字；要判断补丁是否闭合，必须看到 JDK 9 的 `Class.getModule()` 和 `Module.getClassLoader()`。

**同一 binder、同一 `Greeting`，只换了中间一跳。**  
任何把用户 query 绑到任意 POJO 的 `@RequestMapping`，在 5.3.17 + JDK9 + 独立 Tomcat 上都吃这一份缓存。官方博客已指出 WebFlux 同样走 data binding。

**`class` 几乎没有白名单。**  
POJO 默认暴露 `Object.getClass()`。若 binder 默认丢掉 `class`，后面那两行名字过滤根本不会被逼去近似「ClassLoader 安全」。

**金丝雀在 webapp 目录外的「应用数据」里是有意的。**  
flag 不是 `Greeting.content`。能从 `GET /pcb_*.txt` 读到它，说明 setter 写到了 Tomcat 的阀，不是「页面上碰巧回显了参数」。

**官方应急博客把环境钉死了，补丁差才可读。**  
「Am I Impacted」要求 JDK 9+、独立 Tomcat WAR、`spring-webmvc`/`webflux`。本 case 钉 Tomcat 9.0.60 / JDK 17，是为了让 v1/v2 的差只来自 `CachedIntrospectionResults` 那几行，而不是 Tomcat 9.0.62 自己收的 valve 链。嵌入式 Spring Boot jar 不是这条 PoC 的场景，文章不把它写成「修了」。

---

## 版本、入口、参考

| | tag | `CachedIntrospectionResults` | `class.classLoader` seed | `class.module.classLoader` residual |
|---|---|---|---|---|
| V0 | 3.0.2.RELEASE | 无黑名单 | 写出 marker | （也能） |
| V1 | v5.3.17 | 仅 `Class` 上丢掉 `classLoader`/`protectionDomain` | 404 | 写出 marker |
| V2 | v5.3.18 | `Class` 只留 `*Name`；任何 `ClassLoader`/`ProtectionDomain` 类型都丢掉 | 挡 | 挡 |

- Web：`GET /hello?<nested property>=...`（`HelloController`，无鉴权）
- 认证语义：v0 seed 观察到 flag；v1 seed 未观察到；v1 residual 观察到。
- [CVE-2010-1622](https://nvd.nist.gov/vuln/detail/CVE-2010-1622)
- [CVE-2022-22965](https://nvd.nist.gov/vuln/detail/CVE-2022-22965)、[Spring RCE 早期公告](https://spring.io/blog/2022/03/31/spring-framework-rce-early-announcement)
- V1 blob：[`CachedIntrospectionResults.java` @ v5.3.17](https://github.com/spring-projects/spring-framework/blob/v5.3.17/spring-beans/src/main/java/org/springframework/beans/CachedIntrospectionResults.java)
- V2 blob：[`CachedIntrospectionResults.java` @ v5.3.18](https://github.com/spring-projects/spring-framework/blob/v5.3.18/spring-beans/src/main/java/org/springframework/beans/CachedIntrospectionResults.java)
