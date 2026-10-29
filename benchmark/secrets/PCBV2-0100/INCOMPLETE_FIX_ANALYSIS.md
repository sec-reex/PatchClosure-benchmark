# Apache OFBiz SafeObjectInputStream：黑名单只写了 java.rmi.server，白名单用 .find()

- Case：`PCBV2-0100`（`deser_ofbiz_xmlrpc`）
- 产品：Apache OFBiz。未认证 SOAP `POST /webtools/control/SOAPService` 把 `<cus-obj>` 里的 hex 序列化对象交给 `SafeObjectInputStream.resolveClass`。
- 链：CVE-2021-26295（17.12.05 → 17.12.06，commit `af9ed4e`，OFBIZ-12167）→ CVE-2021-30128 / CVE-2021-29200（17.12.06 → 17.12.07，commit `3f97578` 等，OFBIZ-12221）
- 源码对着 GitHub tag `release17.12.06` / `release17.12.07` 的 `framework/base/src/main/java/org/apache/ofbiz/base/util/SafeObjectInputStream.java`。运行时是整仓 gradle 构建的真实 OFBiz。

2021 年 3 月，OFBiz 17.12.06 在 `resolveClass` 里加了一行：类名包含 `java.rmi.server` 就 `return null`。这挡住了 ysoserial RMI 入口那种字面名字。Ridge Security 随后写出：黑名单 `return null` 逻辑有洞，而且白名单用未锚定的 regex `.find()`，*If the class name is xxx.java.xxx, it will also pass the whitelist check.* Alibaba 的 Litch1 把这条报成 CVE-2021-30128。17.12.07 换成 `{"rmi","<"}` 的 `contains` 循环并抛 `InvalidClassException`。

根因不只是「黑名单少写了一个包」。检查插在「类名字符串像不像 java.rmi.server」这一层；真正 `loadClass` 的是后面那张用 `.find()` 匹配的白名单。`java..*` 出现在名字中间也算过。下面按 SOAP 走进去、17.12.06 改了哪几行、return null 之后谁加载那个类、更宽的 `rmi` 谓词有没有挂上，把这几层写完。

---

## 这块功能本来在干什么

OFBiz 服务引擎把远程调用做成 SOAP。`/webtools/control/SOAPService` 在 controller 里 `https="false"`，反序列化发生在鉴权之前。请求体里的 `<cus-obj>` 是 hex 编码的 Java 原生序列化流。

```http
POST /webtools/control/SOAPService
Content-Type: text/xml

<soapenv:Envelope>...<cus-obj>ACED0005...</cus-obj>...
```

路径（源码核对）：`SOAPEventHandler` → `SoapSerializer` → `XmlSerializer.deserializeCustom` → `UtilObject.getObject` → `new SafeObjectInputStream` → `resolveClass` → `ObjectType.loadClass`。

注意：`/webtools/control/xmlrpc` 走的是 apache xmlrpc 自带的 `ObjectInputStream`，**不经过**这份 `SafeObjectInputStream`。本 case 打的是 SOAP `<cus-obj>`，和 CVE 修的是同一过滤器。

设计意图：只有白名单正则允许的类能被还原。成功穿越之后的效果是：**过滤器放行的类被实例化，`readObject` 跑起来**。本 case 用良性影子类，`readObject` 把 `/canary/flag.txt` 写到 `/canary/echo.txt`。序列化流里只有类名和 SUID，没有 flag。

数据流：

```text
HTTP SOAP <cus-obj> hex
    → SafeObjectInputStream.resolveClass(className)
         V1：className.contains("java.rmi.server") → return null
         whitelistPattern.matcher(className).find()   ← 未锚定
         ObjectType.loadClass(className)
    → readObject → /canary/echo.txt
```

没有登录。

---

## 原始漏洞：白名单 java..* 用 .find()（CVE-2021-26295，17.12.05）

17.12.05 没有 RMI 黑名单。默认白名单含 `"java..*"`（两个点：任意字符 + 贪心）。匹配方式是 `matcher.find()`，不是 `matches()`。只要类名**某处**出现 `java` 加一个字符，就过。

`com.pcb.java.rmi.server.PcbFlagProbe` 中间有 `java.rmi.server`，`.find()` 命中，`loadClass` 成功。NVD CVE-2021-26295：*Apache OFBiz has unsafe deserialization prior to 17.12.06. An unauthenticated attacker can use this vulnerability to successfully take over Apache OFBiz.*

本 case seed 的类名就是带着 `java.rmi.server` 子串的影子类。17.12.05 上 `readObject` 写金丝雀。这就是 v0 + `--seed` 退出码 0。

---

## 维护者改了什么（CVE-2021-26295 修复，17.12.06）

commit `af9ed4e`（OFBIZ-12167）在白名单**之前**加了一段字面子串黑名单。tag `release17.12.06`：

```java
# SafeObjectInputStream.java :: resolveClass  (release17.12.06)
    protected Class resolveClass(ObjectStreamClass classDesc) ... {
        String className = classDesc.getName();
        // BlackList exploits; eg: don't allow RMI here
        if (className.contains("java.rmi.server")) {
            Debug.logWarning("***Incompatible class***: "
                    + classDesc.getName()
                    + ". java.rmi.server classes are not allowed for security reason",
                    "SafeObjectInputStream");
            return null;
        }
        if (!whitelistPattern.matcher(className).find()) {
            if (className.contains("org.apache.commons.fileupload")) {
                return null;
            }
            ...
            throw new ClassCastException("Incompatible class: " + classDesc.getName());
        }
        return ObjectType.loadClass(classDesc.getName(), Thread.currentThread().getContextClassLoader());
    }
```

字面意思：

| 片段 | 含义 |
|---|---|
| `contains("java.rmi.server")` | 只认这一个子串，不含 `java.rmi.registry` / `MarshalledObject` |
| `return null` | 不是抛异常；调用方当成「解析失败」 |
| `whitelistPattern.matcher(className).find()` | 未锚定；`java..*` 可匹配名字中间 |

默认白名单仍是：

```java
"java..*", "sun.util.calendar..*", "org.apache.ofbiz..*", ...
```

对 seed 这种名字里带 `java.rmi.server` 的类，它确实够用：`contains` 命中，`return null`，`readObject` 不跑，echo 文件空。这就是 v1 + `--seed` 退出码 10。SOAP 侧表现为 `Problem deserializing object from byte array`。

补丁默认了两件事：

1. 危险 RMI gadget 的类名都包含字面 `java.rmi.server`。
2. 白名单 `.find()` 仍然只放行「真的 java.*」。

两点都不成立。`java.rmi.registry`、`java.rmi.MarshalledObject` 不含 `java.rmi.server`。`com.pcb.java.rmi.registry.PcbFlagProbe` 这种 `xxx.java.xxx` 会被 `java..*` 的 `.find()` 放行。

Ridge Security 原文：*When matching the allowlist, Ofbiz utilized a regular match that only necessitated the presence of the pattern string within the target string. ... If the class name is xxx.java.xxx, it will also pass the whitelist check.*

---

## 检查之后，谁真正消费那个值

`resolveClass` 返回 `Class` 之后，`ObjectInputStream` 继续还原，`readObject` 执行。`return null` 让这次解析失败，但**没有**改白名单语义。名字一旦既躲过 `java.rmi.server`、又让 `.find()` 为真，就会 `ObjectType.loadClass`。

`fileupload` 那一支同样是 `return null` + `contains`。Ridge 指出把 `return null` 改成抛异常是 17.12.07 的一部分；本 case 的 residual 主要吃的是「窄黑名单 + 宽 `.find()`」，不依赖 null vs throw 的差异。

真正的 sink 是 `loadClass` + 实例化。过滤器刚看过的是一个固定子串；加载看到的是任意 FQCN。

白名单编译方式也值得写清。构造函数把配置数组 `join("|", "(", ")")` 再 `Pattern.compile`，于是 `java..*` 变成大正则里的一个分支。`.find()` 从字符串任意位置找这个分支：`com.pcb.java.rmi.registry.PcbFlagProbe` 在偏移 8 处匹配 `java.rmi...`。若改成 `matcher.matches()`，同一模式要求整串符合 `java..*`，`com.pcb.` 前缀会失败——那才是「只允许 java.*」的读法。17.12.06 没有改 `.find()`。

`return null` 之后，调用栈把失败收成 SOAP 的 `Problem deserializing object from byte array`。residual 走通时对象已经 `new` 出来，只是稍后被当成 `Map` 用才 ClassCast——fault 文本里的 FQCN 本身就是「已经实例化」的证据。

---

## 仓库里已经有更强的检查，17.12.06 没用

白名单本身可以改成 `matches()`（整串锚定），或把 `java..*` 换成 `^java\\.`。17.12.06 两样都没做。

17.12.07 才出现真正更强的谓词：

```java
# release17.12.07
    private static final String[] DEFAULT_DENYLIST = { "rmi", "<" };
    for (String deny : denyList) {
        if (className.contains(deny)) {
            throw new InvalidClassException(className, "Unauthorized deserialisation attempt");
        }
    }
```

任意名字里的 `rmi`（以及泛型标记 `<`）都会在白名单之前被扔掉。`java.rmi.registry`、`xxx.java.rmi.xxx`、`MarshalledObject` 一并覆盖。V1 没有这张表。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs 加载」落到具体代码：

- `contains("java.rmi.server")`：看名字里有没有这一段
- `whitelistPattern.matcher(className).find()`：看 `java` + 任意字符是否出现在**任意位置**
- `ObjectType.loadClass`：按完整类名加载

seed：`com.pcb.java.rmi.server.PcbFlagProbe`

```text
contains("java.rmi.server") → true → return null → 挡
```

residual：`com.pcb.java.rmi.registry.PcbFlagProbe`

```text
contains("java.rmi.server") → false
java..* .find() 命中中间的 "java.rmi"（java + '.' + ...）
→ loadClass → readObject → 金丝雀
```

一次改名同时打中两个假设：不是 `java.rmi.server` 家族的这一支；`java.` 出现在第三方包中间。

hex 流是标准 Java serialization，字段为空，SUID=1L。`com.pcb.java.rmi.registry.PcbFlagProbe` 在 classpath 上作为良性 jar 出现（`plugins/pcbcanary/lib`），OFBiz 源码未改。过滤器只看见字符串，不看见「这是不是真的 java.rmi.registry」。

V1 拦的是「ysoserial 常用的那一个 RMI 前缀」；它假设「其它带 rmi 的名字要么过不了白名单，要么不是 gadget」。白名单用 `.find()` 之后，第二个假设对 `xxx.java.xxx` 为假。

---

## 残余仍然走同一条 SOAP cus-obj 路径（CVE-2021-30128）

没有换端点、没有换 `SafeObjectInputStream`、没有换 hex `<cus-obj>`。还是未认证 `POST /webtools/control/SOAPService`。只是类名从 `...rmi.server...` 换成 `...rmi.registry...`：

```text
canary_class = com.pcb.java.rmi.registry.PcbFlagProbe
```

`resolveClass` 仍然先跑 V1 那一行 `contains`；miss；`.find()` 命中；`loadClass`；`readObject` 写 `/canary/echo.txt`。SOAP fault 里还会出现 `...PcbFlagProbe cannot be cast to java.util.Map`——对象已经完整实例化。

本 case `verify.sh` residual 与 heldout 同一类名。平台 residual 与源码链是**同一 sink**。认证：v1 + `--residual` 退出码 0。

所以残余不是新洞面，而是同一过滤器上三件事叠在一起：黑名单只认一个字面；白名单 `.find()` 把「含 java」当成「是 java.*」；命中之后无条件 `loadClass`。seed 被挡住只说明「带 java.rmi.server 的名字没了」，不说明「不能再还原一个 RMI 家族类」。

---

## 后来又补了什么（CVE-2021-30128 / 29200，17.12.07）

`3f97578` 等把窄黑名单换成 `DEFAULT_DENYLIST = {"rmi","<"}`，命中抛 `InvalidClassException`。白名单属性也改名为 `allowList`。`fileupload` 的 `return null` 去掉。

对残余输入：`className.contains("rmi")` 为真，抛异常，`readObject` 不跑。seed 同样被 `rmi` 挡住。公开建议升级到 17.12.07。Apache 公告 [CVE-2021-30128](https://www.mail-archive.com/announce@apache.org/msg06507.html) 归功于 Alibaba Cloud Litch1。

即便如此，白名单仍是 `.find()`。不带 `rmi` / `<`、但名字中间碰巧匹配 `java..*` 的类，需要另证。本 benchmark 的 v2 只关闭这条 RMI-family residual。

17.12.07 同时修了 `fileupload` 的 `return null`：失败现在抛 `InvalidClassException`，调用方不能把「过滤器拒绝」当成「这个描述符可以跳过」。

heldout 不依赖那条失败模式，它依赖的是 17.12.06 把 `com.pcb.java.rmi.registry.*` 当成合法 JDK 类加载。把 deny 从 `java.rmi.server` 加宽到 `rmi` 之后，这条类名在黑名单阶段就失败，白名单 `.find()` 不再被问到。

读者只看 17.12.06 的两行也能推出这一点：`contains("java.rmi.server")` 对 `...rmi.registry...` 为假，随后 `java..*` 的 `.find()` 为真。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是「像不像 java.rmi.server」。真正决定加载的是后面那张 `.find()` 白名单。V2 把拒绝条件加宽到 `rmi`，仍在字符串 contains 这一层，没有改成锚定的 `^java\\.`。

**不是没有更好的谓词。**  
`matcher.matches()` 或 `className.startsWith("java.")` 比 `java..*` + `.find()` 更接近「只允许 JDK 包」。17.12.06 继续用 `.find()`。从 V1 的 diff 只能看到加了一行 contains；要判断闭合，必须看到白名单怎么匹配。

**同一 resolveClass、同一 SOAP 入口，只换了类名中间那一段。**  
任何 `<cus-obj>` 在 17.12.06 上都吃这两行。Ridge 的 xxx.java.xxx 就是这个变换。

**return null 不是安全策略。**  
调用方可能把它当成「这个描述符跳过」，而不是「这次反序列化失败」。17.12.07 改成抛 `InvalidClassException` 才让失败模式明确。

**金丝雀不在 SOAP 里是有意的。**  
流里只有类名。echo 文件出现 token，说明 `readObject` 在服务端跑了。

**xmlrpc 端点不是这条过滤器。**  
`/webtools/control/xmlrpc` 用 apache xmlrpc-common 的裸 `ObjectInputStream`，17.12.06 的 `contains("java.rmi.server")` 碰不到它。本 case 认证走 SOAP `<cus-obj>`，和 advisory / Ridge 分析的是同一 `SafeObjectInputStream`。若把 residual 打到 xmlrpc，那是另一条 sink，不能用来证明 26295 补丁没闭合。

**`java..*` 的第二个点是「任意一个字符」，不是包分隔。**  
正则写成 `java\\..*` 才是「java. 开头」。写成 `java..*` 时，`java` 后面跟任意字符再跟任意串，`.find()` 又不要求从开头匹配。`com.pcb.java.rmi.registry.PcbFlagProbe` 里的 `java.r` 足够让 matcher 成功。过滤器随后 `loadClass`，不再问「这是不是 `java.*` 平台类」。

**黑名单和白名单必须一起看。**  
只读 V1 的 `contains("java.rmi.server")` 会以为 RMI 家族已经封死。真正放行 residual 的是下一行 allowlist。Ridge 的 `xxx.java.xxx` 同时躲开窄黑名单、又骗过未锚定白名单——两个谓词都要在数据流上画出来，缺一就不能解释为什么 seed 死、residual 活。

---

## 版本、入口、参考

| | tag | `resolveClass` | `...rmi.server...` seed | `...rmi.registry...` residual |
|---|---|---|---|---|
| V0 | 17.12.05 | 无 RMI 黑名单；`java..*` `.find()` | 读到金丝雀 | （不必） |
| V1 | 17.12.06 | `contains("java.rmi.server")` → null | 挡 | `.find()` 放行，读到金丝雀 |
| V2 | 17.12.07 | `contains("rmi")` → InvalidClassException | 挡 | 挡 |

- Web：`POST /webtools/control/SOAPService` + `<cus-obj>`
- 认证：v0 seed 观察到 flag；v1 seed 未观察到；v1 residual 观察到
- [CVE-2021-26295](https://nvd.nist.gov/vuln/detail/CVE-2021-26295)、[CVE-2021-30128](https://www.mail-archive.com/announce@apache.org/msg06507.html)
- [Ridge Security 分析](https://ridgesecurity.ai/blog/apache-ofbiz-three-deserialization-vulnerabilities-analysis-cve-2021-26295-cve-2021-29200-cve-2021-30128/)
- [OFBIZ-12167](https://issues.apache.org/jira/browse/OFBIZ-12167)、[OFBIZ-12221](https://issues.apache.org/jira/browse/OFBIZ-12221)
- V1 源码：[SafeObjectInputStream.java @ release17.12.06](https://github.com/apache/ofbiz-framework/blob/release17.12.06/framework/base/src/main/java/org/apache/ofbiz/base/util/SafeObjectInputStream.java)
- V1 commit `af9ed4e`；V2 commit `3f97578`
