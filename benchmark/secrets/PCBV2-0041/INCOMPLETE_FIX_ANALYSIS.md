# fastjson 1.2.25：黑名单还没跑，mappings 里已经有这个类了

- Case：`PCBV2-0041`（`deser_fastjson_autotype`）
- 产品：Alibaba fastjson（Java JSON 库）。本 case 把已发布的 Maven 包放进真实 HTTP 服务 `com.pcb.DeserHttpService`，`POST /deser` 对 body 做 `JSON.parse`。
- 链：CVE-2017-18349（1.2.24 → 1.2.25，加上 `ParserConfig.checkAutoType` + 前缀 denylist）→ CVE-2025-70974 / GHSA-jm7w-5684-pvh8（1.2.48，`MiscCodec` 加载 `java.lang.Class` 时不再写入 `TypeUtils.mappings`）。NVD 写明后者 *exists because of an incomplete fix for CVE-2017-18349*。
- 源码对着官方 tag `1.2.25` 的 `ParserConfig.java`、`MiscCodec.java`、`TypeUtils.java`。本仓库 `patch.diff` 是 ROUND9 误同步的 `ObjectArrayCodec` / Issue1005 测试改动，**不是** CVE-2017-18349 的安全增量；下面按 1.2.24…1.2.25 真实 diff 写。

2017 年前后，fastjson 的 `@type` 可以点名任意类并实例化。1.2.25 加了 `checkAutoType`：默认关掉 autoType，再用一串前缀（`com.mchange`、`com.sun.`、`org.springframework` …）挡住危险类。字面写 `{"@type":"com.mchange.PcbFlagBean"}` 会在 denylist 上炸掉。同一份函数里，**denylist 之前**先问 `TypeUtils.getClassFromMapping`；而 `MiscCodec` 反序列化 `java.lang.Class` 时，两参数 `loadClass` 会无条件 `mappings.put`。于是可以先用 `{"@type":"java.lang.Class","val":"X"}` 把 X 放进缓存，再用 `{"@type":"X"}` 让 `checkAutoType` 在扫黑名单之前直接返回。下面按请求走进去、补丁加了哪一段、缓存怎么填、第二次解析为什么不再看 denylist，把这三层写完。

---

## 这块功能本来在干什么

fastjson 解析对象时，若 JSON 带 `"@type"`，就把值当 Java 类名，解析成那个类型的实例。这是 autoType。Web API / RPC 把整段 body 丢给 `JSON.parse` 时，类名来自调用方。

本 case 的入口：

```http
POST /deser
Content-Type: application/json

{"@type":"com.mchange.PcbFlagBean","probe":"x"}
```

服务用默认 `ParserConfig()`（`autoTypeSupport=false`），fresh 配置，每请求还清掉金丝雀在 `TypeUtils.mappings` 里的键，避免上次请求污染这次。`com.mchange.PcbFlagBean` 是挂在 denylist 前缀 `com.mchange` 下的影子 bean：无参构造读 `/canary/flag.txt`，放进 `CanaryHolder`；服务在同一线程把 `PCB_CANARY_FLAG=<token>` 写进响应。classpath 上没有真 c3p0。能读到 flag，说明 `checkAutoType` 放行了这个名字并且 bean 被 new 出来。

数据流：

```text
HTTP JSON body
    → JSON.parse / DefaultJSONParser
         看见 @type = typeName
    → ParserConfig.checkAutoType(typeName, expectClass)
         V0 1.2.24：没有这个函数，直接 TypeUtils.loadClass
         V1 1.2.25：见下一节
    → 得到 Class 后按 JavaBean 实例化
    → 构造器读 /canary/flag.txt
    → 响应 PCB_CANARY_FLAG=...
```

设计意图：未打开 `Feature.SupportAutoType` 时，除了少数内部类型，不该按用户给的名字去 load 任意类；打开时至少不该 load denylist 前缀下的类。成功穿越之后的效果是 **denylist 上的类被构造，树外金丝雀进 HTTP body**。

---

## 原始漏洞：没有 checkAutoType（CVE-2017-18349 之前，1.2.24）

1.2.24 的 `parseObject` 路径对 `@type` 直接 `TypeUtils.loadClass`。没有 denylist，没有 autoType 开关。任意能加载的类都能被点名构造。公开利用多用 `com.sun.rowset.JdbcRowSetImpl` 一类 JNDI gadget。本 case 的 seed 用影子 bean：

```text
{"@type":"com.mchange.PcbFlagBean","probe":"x"}
```

1.2.24 加载并 `new` 它，构造器读金丝雀，body 里出现 `PCBFLAG_...`。这就是 v0 + `--seed` 退出码 0。没有鉴权，body 即类名。

---

## 维护者改了什么（CVE-2017-18349，1.2.25）

1.2.25 在 `ParserConfig` 里加了 `autoTypeSupport`（默认 false）、前缀数组 `denyList`，以及 `checkAutoType`。`denyList` 字面包含 `com.mchange`：

```java
// ParserConfig.java  (fastjson 1.2.25, 约 L164–165)
private boolean  autoTypeSupport = AUTO_SUPPORT;
private String[] denyList = "bsh,com.mchange,com.sun.,java.lang.Thread,java.net.Socket,java.rmi,javax.xml,org.apache.bcel,org.apache.commons.beanutils,org.apache.commons.collections.Transformer,org.apache.commons.collections.functors,org.apache.commons.collections4.comparators,org.apache.commons.fileupload,org.apache.myfaces.context.servlet,org.apache.tomcat,org.apache.wicket.util,org.codehaus.groovy.runtime,org.hibernate,org.jboss,org.mozilla.javascript,org.python.core,org.springframework".split(",");
```

`checkAutoType` 的控制流（tag `1.2.25`，约 L804–890）按 `autoTypeSupport` 分叉。本 case 走默认关闭路径，相关片段按执行顺序是：

```java
// ParserConfig.checkAutoType  (1.2.25)
public Class<?> checkAutoType(String typeName, Class<?> expectClass) {
    if (typeName == null) return null;
    final String className = typeName.replace('$', '.');

    // 仅当 autoType 已打开、或调用方给了 expectClass 时，先扫 accept / deny
    if (autoTypeSupport || expectClass != null) {
        // acceptList 命中 → 直接 loadClass
        // denyList 前缀命中 → throw "autoType is not support. " + typeName
    }

    Class<?> clazz = TypeUtils.getClassFromMapping(typeName);   // ← 默认路径先到这里
    if (clazz == null) {
        clazz = deserializers.findClass(typeName);
    }
    if (clazz != null) {
        return clazz;   // 缓存命中则直接返回，后面的 denylist 不再执行
    }

    if (!autoTypeSupport) {
        for (int i = 0; i < denyList.length; ++i) {
            if (className.startsWith(denyList[i])) {
                throw new JSONException("autoType is not support. " + typeName);
            }
        }
        // acceptList 命中才 load；否则落到函数末尾再 throw
    }
    ...
    if (!autoTypeSupport) {
        throw new JSONException("autoType is not support. " + typeName);
    }
    return clazz;
}
```

对 seed 这种字面 `@type`，`getClassFromMapping` 是空的，于是走进 `!autoTypeSupport` 的 denylist 循环。`com.mchange.PcbFlagBean`.startsWith(`com.mchange`) 为真，抛 `autoType is not support. com.mchange.PcbFlagBean`。构造器不跑，body 没有金丝雀。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险类的名字会以 denylist 里某段前缀开头，而且每次解析都会走到那次 `startsWith`。
2. `getClassFromMapping` 里若已有这个名字，那它就是「已经安全解析过的类型」，可以跳过 denylist。

第二点把检查和类表当成同一套信任根。`mappings` 并不是只由 `checkAutoType` 自己写入的。

---

## 谁在往 mappings 里写

`TypeUtils.getClassFromMapping` 就是 `mappings.get(className)`。1.2.25 的两参数 `loadClass` **没有 cache 开关**，加载成功就 `put`：

```java
// TypeUtils.loadClass(String, ClassLoader)  (1.2.25, 约 L1073–1121)
public static Class<?> loadClass(String className, ClassLoader classLoader) {
    Class<?> clazz = mappings.get(className);
    if (clazz != null) return clazz;
    ...
    clazz = classLoader.loadClass(className);   // 或 contextClassLoader / Class.forName
    mappings.put(className, clazz);
    return clazz;
}
```

谁在 denylist 之外调用它？`MiscCodec.deserialze` 处理目标类型为 `java.lang.Class` 时：

```java
// MiscCodec.deserialze  (1.2.25, 约 L320–321)
if (clazz == Class.class) {
    return (T) TypeUtils.loadClass(strVal, parser.getConfig().getDefaultClassLoader());
}
```

`{"@type":"java.lang.Class","val":"com.mchange.PcbFlagBean"}` 这条路径：

1. `@type` 是 `java.lang.Class`。它不在 denylist 前缀上，fastjson 内置了 `Class` 的 codec，`checkAutoType("java.lang.Class")` 会放行（或走内置 deserializer，根本不按危险 bean 去 load）。
2. codec 读到 `val`，调用两参数 `loadClass("com.mchange.PcbFlagBean", cl)`。
3. 这里 **没有** 再进 `checkAutoType`。`loadClass` 用 `Class.forName` / `ClassLoader.loadClass` 把类装进来，并 `mappings.put("com.mchange.PcbFlagBean", PcbFlagBean.class)`。
4. 装类不等于实例化：这一步还没有跑影子 bean 的构造器，金丝雀还没被读。但名字已经躺在全局表里。

`checkAutoType` 只在「按 `@type` 决定要 new 哪个 JavaBean」时当门卫。`MiscCodec` 把同一个字符串当成 `Class` 的值去 load，走的是另一扇门，写的却是门卫下一步会先查的那张表。

---

## 这个补丁挡住了什么、没挡住什么

同一份 `checkAutoType`，默认 autoType-off：

- 字面 `@type=com.mchange.PcbFlagBean`：mapping 未命中 → denylist `startsWith("com.mchange")` → 抛异常。seed 被挡。
- mapping 已有这个名字：函数在 denylist 循环 **之前** `return clazz`。后面那串 `startsWith` 根本不跑。

所以只要在同一次 `JSON.parse`（或同一 JVM 里此前某次解析）里，先让 `MiscCodec` 把目标类放进 `mappings`，第二次 `@type` 就会拿到 Class 对象并实例化。本 case 把两步放进 **同一个 JSON 对象的两个键**，一次 POST：

```text
{
  "a": {"@type":"java.lang.Class","val":"com.mchange.PcbFlagBean"},
  "b": {"@type":"com.mchange.PcbFlagBean"}
}
```

解析顺序：先 `a`，`Class` + `val` 把 `PcbFlagBean` 写入 mappings（仍不 new bean）；再 `b`，`checkAutoType("com.mchange.PcbFlagBean")` 在 L827 命中缓存，返回 Class，JavaBean 反序列化调用无参构造，读 `/canary/flag.txt`。响应里出现 `PCB_CANARY_FLAG=`。过滤器认为自己已经按前缀拒绝了 `com.mchange`，实际上它只拒绝「mapping 为空时的第一次点名」。

注意：若打开 `Feature.SupportAutoType`，函数入口就会先跑 denylist，缓存绕过不成立。本 case 故意用默认配置，对应 1.2.25 上这条真实残差。`L...;` 描述符绕过是另一条链，1.2.42 已关，不是 1.2.25→1.2.48 的差。

---

## 残余仍然走同一条 autoType 解析路径（CVE-2025-70974）

没有换 endpoint、没有换 parser、没有换影子类。还是 `POST /deser`，还是默认 `ParserConfig`，还是 `com.mchange.PcbFlagBean`。唯一差别是 JSON 多了一个 `java.lang.Class` 条目，用来填 `TypeUtils.mappings`。

`verify.sh --residual` 把 candidate 写死为：

```text
{"a":{"@type":"java.lang.Class","val":"com.mchange.PcbFlagBean"},
 "b":{"@type":"com.mchange.PcbFlagBean"}}
```

认证：v1 + `--residual` 退出码 0，body 中观察到 `PCBFLAG_...`。所以残余不是新洞面，而是同一 sink 上三件事叠在一起：denylist 只在 mapping 未命中时执行；`MiscCodec` 能在 denylist 外把任意类名写入同一张表；实例化仍然信任 `checkAutoType` 的返回值。seed 被挡住只说明「字面类名第一次会被拒」，不说明「denylist 上的类不能再被构造」。

---

## 后来又补了什么（CVE-2025-70974，1.2.48）

1.2.48 把 `MiscCodec` 里那一行改成三参数、`cache=false`：

```java
// MiscCodec.deserialze  (1.2.48, 约 L334–335)
if (clazz == Class.class) {
    return (T) TypeUtils.loadClass(strVal, parser.getConfig().getDefaultClassLoader(), false);
}
```

`loadClass(..., false)` 仍可能 `Class.forName`，但不再 `mappings.put`。随后 `checkAutoType("com.mchange.PcbFlagBean")` 的 `getClassFromMapping` 是空的，denylist 抛异常。公开建议升级到 1.2.48+，或开 safeMode 彻底关掉 autoType。

即便如此，1.2.48 之后仍有 CVE-2022-25845 一类后续绕过；本 benchmark 的 v2 只关闭「Class 缓存进 mappings」这一条 reference residual。1.2.25 的 `checkAutoType` 也没有改成「无论 mapping 是否命中都扫 denylist」。

---

## autoType 打开时，同一条缓存链反而不成立

把 `checkAutoType` 再读一遍会发现：`autoTypeSupport || expectClass != null` 为真时，**denylist 循环在 mapping 查询之前**。那是「打开 autoType 的人至少先过前缀表」的路径。本 case 的服务显式用默认配置（`new ParserConfig()`，不设 `Feature.SupportAutoType`），走的是另一枝：先 mapping，再（仅当 miss 时）denylist。CVE-2025-70974 在 1.2.25 上能复现，靠的就是这枝。若有人在 1.2.25 上打开 autoType 再测同一份双条目 JSON，denylist 会先于 `getClassFromMapping` 扔掉 `com.mchange`，残余会失败——那不是补丁更完整，只是走了另一条控制流。写分析时必须把「默认 autoType-off」写进前提，否则会误判 1.2.25 已经挡住了缓存。

`TypeUtils.mappings` 是进程级静态表。本 case 每请求 eviction 金丝雀键，是为了让两次 POST 互不干扰；真实应用里第一次 `java.lang.Class` 解析会把名字留到后续完全无关的请求。residual 把两步放进同一 JSON，只是为了一次 HTTP 内完成 priming。

1.2.25 的 `loadClass` 还有 `L...;` 描述符递归：`Lcom.mchange.PcbFlagBean;` 先剥 L 和分号再 load。那是另一条绕过，1.2.42 关掉，不是本 case 的 1.2.25→1.2.48 差。不要把 descriptor 写进 residual。

`JavaBeanDeserializer` 在确认 Class 之后才会 `new`。mapping 命中返回的已经是 `Class<?>`，后面的实例化不再问 denylist。影子 bean 的无参构造读文件，发生在这一步，不发生在 `MiscCodec` 填缓存的那一步。所以单条 `{"@type":"java.lang.Class","val":"...PcbFlagBean"}` 不会让 flag 出现；必须有第二次 `@type` 指向同一个名字。

`ParserConfig` 构造函数会 `addItemsToDeny(DENYS)`，系统属性 `fastjson.parser.deny` 只能往表里加，不能把 `getClassFromMapping` 挪到 denylist 后面。1.2.25 把 `com.mchange` 写进默认表，是因为当时的 gadget 前缀；影子 bean 故意占用同一前缀，让 seed 与残余都在「表已经认识这个家族」的前提下差分。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们加的是 `@type` 点名时的前缀表。真正让危险 Class 对象出现在门卫之前的，是 `MiscCodec` 对 `java.lang.Class` 的 `loadClass` 以及 `checkAutoType` 把 `mappings` 当成已授权集合。V2 改的是写入端（cache=false），没有把「mapping 命中也必须再过 denylist」写进 `checkAutoType`。

**不是没有 denylist。**  
`com.mchange` 从 1.2.25 起就在表里。seed 能被挡，说明表对字面名字有效。要判断补丁是否闭合，必须看到 `getClassFromMapping` 相对 denylist 循环的位置，以及还有谁调用两参数 `loadClass`。

**同一函数、同一 typeName，只换了 JSON 形状。**  
任何把用户 JSON 交给默认 `JSON.parse` 的服务，在 1.2.25 上都吃这一段 `checkAutoType` 和同一次 `MiscCodec` 缓存。advisory 覆盖的是整个 autoType 面，不限于某个 HTTP 路由。

**金丝雀在 classpath / 应用目录之外是有意的。**  
`/canary/flag.txt` 不在源码和 JSON 里。能读到它，说明影子 bean 的构造器在 denylist 之后仍然跑了。

---

## 版本、入口、参考

| | 版本 | `checkAutoType` | `MiscCodec` 对 `Class` | 字面 `@type` seed | Class 缓存 residual |
|---|---|---|---|---|---|
| V0 | 1.2.24 | 无 | 两参数 loadClass | 读到金丝雀 | （不必） |
| V1 | 1.2.25 | mapping 先于 autoType-off denylist | `loadClass(strVal, cl)` 写入 mappings | `autoType is not support` | 读到金丝雀 |
| V2 | 1.2.48 | 同结构 | `loadClass(strVal, cl, false)` | 挡 | mapping 不写，denylist 挡 |

- Web：`POST /deser`，body 为 raw JSON。
- 认证（本平台）：v0 seed 观察到 flag；v1 seed 未观察到；v1 residual 观察到。
- [CVE-2017-18349](https://nvd.nist.gov/vuln/detail/CVE-2017-18349)、[CVE-2025-70974](https://nvd.nist.gov/vuln/detail/CVE-2025-70974)
- [GHSA-jm7w-5684-pvh8](https://github.com/advisories/GHSA-jm7w-5684-pvh8)
- 1.2.24…1.2.25：https://github.com/alibaba/fastjson/compare/1.2.24...1.2.25
- tag 源码：`ParserConfig.checkAutoType`、`MiscCodec.deserialze`、`TypeUtils.loadClass` / `getClassFromMapping`（1.2.25 / 1.2.48）
