# SOFA Hessian 黑名单：补上了 Qname，XString 的 S 写成了 s

- Case：`PCBV2-0101`（`deser_sofahessian_blacklist`）
- 产品：SOFA Hessian（`com.alipay.sofa:hessian`）。Hessian2 反序列化时用 `NameBlackListFilter` 按前缀拒绝类名。
- 链：CVE-2019-9212（3.3.13 → 3.4.0 起补条目，本 case V1=3.5.4）→ CVE-2024-46983（3.5.4 → 3.5.5，GHSA-c459-2m73-67hj）
- 源码对着 GitHub tag `v3.5.4` / `v3.5.5` 的 `src/main/resources/security/serialize.blacklist` 与 `src/main/java/com/alipay/hessian/NameBlackListFilter.java`。运行时装的是 Maven 整包。

2019 年，CVE-2019-9212 指出 sofa-hessian 的黑名单没拦住 Resin gadget：`com.caucho.naming.QName` 和 `com.sun.org.apache.xpath.internal.objects.XString`。3.x 线在 3.4.0 把这两行**按当时写下的大小写**追加进 `serialize.blacklist`：`Qname`、`Xstring`。`NameBlackListFilter.inBlackList` 用**大小写敏感**的 `className.startsWith(prefix)`。五年后 GHSA-c459-2m73-67hj / CVE-2024-46983：仍存在只依赖 JDK 的 gadget 链能绕过黑名单；3.5.5 把窄类名枚举换成宽包前缀（含 `com.sun.`）。

根因不只是「打错一个字母」。检查插在「类名是否以黑名单某一行开头」这一层；真正 `readObject` 的是 Hessian2 解析器。3.x 补丁写的是错误大小写，而且只枚举了少数 `com.sun.*` 全名。下面按 POST /deser 走进去、3.4.0/3.5.4 加了哪两行、startsWith 之后谁加载那个类、更宽的 `com.sun.` 有没有挂上，把这几层写完。

---

## 这块功能本来在干什么

SOFA Hessian 是 Ant Group 对 Hessian 3/4 的加固 fork，给 RPC 用。默认从 classpath 资源 `security/serialize.blacklist` 建 `NameBlackListFilter`，在 `SerializerFactory.getDeserializer(String)` → `ClassNameResolver.resolve()` 时过滤类名。命中则抛 `Class <name> is in blacklist.`

本 case 用 JDK `HttpServer` 起 `POST /deser`，请求体是 Hessian2 字节，走发布包自己的默认黑名单。这和 SOFA-RPC 服务反序列化请求是同一条库路径。

设计意图：名单上的前缀不能被还原。成功穿越之后的效果是：**类名过了过滤器，Hessian2 继续 decode**。服务在 decode 成功后读 `/canary/flag.txt` 写进 HTTP 响应。请求体只有类名和一个两字段 map，没有 flag。

数据流：

```text
HTTP POST /deser  Hessian2 body
    → Hessian2Input.readObject
         SerializerFactory.getDeserializer(className)
         ClassNameResolver.resolve
              NameBlackListFilter.resolve
                   inBlackList: className.startsWith(prefix)   ← 补丁改的是 prefix 列表
              命中且 LOGGER!=null → throw IOException
    → 放行则服务读 /canary/flag.txt → PCB_CANARY_FLAG=
```

没有登录。生产上若 sofa-common-tools 日志没配好，LOGGER 为 null 时命中**不抛**（静默放行）；本 case 拉了日志依赖，让守卫按生产那样 enforce。

---

## 原始漏洞：名单里没有 caucho / xpath 这两家（CVE-2019-9212，3.3.13）

3.3.13 的 `serialize.blacklist` 没有 `com.caucho.naming` 也没有 `...objects.XString`。NVD CVE-2019-9212：*SOFA-Hessian through 4.0.2 allows remote attackers to execute arbitrary commands via a crafted serialized Hessian object because blacklisting of com.caucho.naming.QName and com.sun.org.apache.xpath.internal.objects.XString is mishandled, related to Resin Gadget.* 厂商曾 disputed，说黑名单本就该用户自己维护；3.x 仍然把这两行加进了默认文件。

本 case seed 用 **3.x 补丁写下的那个拼写** `com.caucho.naming.Qname`（小写 n），保证 V1 上守卫真的开火：

```text
probe = com.caucho.naming.Qname
```

3.3.13 上 startsWith 全部 miss，decode 成功，响应里有金丝雀。这就是 v0 + `--seed` 退出码 0。

---

## 维护者改了什么（CVE-2019-9212 修复，3.4.0 起；本 case V1=3.5.4）

`v3.3.10...v3.4.0` 在 blacklist 文件末尾追加两行。tag `v3.5.4` 仍是这两行：

```text
# src/main/resources/security/serialize.blacklist  (v3.5.4 末尾)
org.apache.commons.beanutils.BeanMap
com.caucho.naming.Qname
com.sun.org.apache.xpath.internal.objects.Xstring
```

匹配代码在 3.5.4 没有改，仍是：

```java
# NameBlackListFilter.java :: inBlackList  (v3.5.4)
    protected boolean inBlackList(String className) {
        if (addBlackPrefixList != null && addBlackPrefixList.size() != 0) {
            for (String prefix : addBlackPrefixList) {
                if (className.startsWith(prefix)) {
                    return Boolean.TRUE;
                }
            }
        } else {
            for (String prefix : blackPrefixList) {
                if (className.startsWith(prefix)) {
                    return Boolean.TRUE;
                }
            }
        }
        return Boolean.FALSE;
    }
```

`resolve` 在 `result==true && LOGGER!=null` 时：

```java
        throw new IOException("Class " + className + " is in blacklist. ");
```

`startsWith` 大小写敏感。`QName` 不以 `Qname` 开头；`XString` 不以 `Xstring` 开头。

对 seed 这种**故意用错拼写**的 `Qname`，它确实够用：

```text
"com.caucho.naming.Qname".startsWith("com.caucho.naming.Qname") → true → 抛 blacklist
```

这就是 v1 + `--seed` 退出码 10。响应 `RESULT=BLOCKED`，无 flag。

补丁默认了两件事：

1. 黑名单里的字符串等于真实 gadget 的 FQCN（含大小写）。
2. 枚举几个 `com.sun.org.apache...` 全名就够挡住 JDK gadget。

第一点：3.x 写下的是 `Qname` / `Xstring`，真实类是 `QName` / `XString`。并行的 4.0.3 线反而加了正确的 `QName` 和更宽的 `com.sun.org.apache.xpath` 前缀。第二点：3.5.4 只有少数 `com.sun.*` 全名（`TemplatesImpl`、`JdbcRowSetImpl`、`Xstring` 等），没有 `com.sun.` 包前缀。

---

## 检查之后，谁真正消费那个值

`resolve` 返回原类名字符串（或抛 IOException）。Hessian 随后按这个名字找 deserializer、实例化。过滤器只看「名字是否以某一行为前缀」；加载看的是 JVM 里真实存在的类。`XString` 在 JDK `java.xml` 模块里，本 case 不必再塞一份影子类。

`inBlackList` 没有 `equalsIgnoreCase`，没有把前缀规范化成 canonical name。名单是资源文件里的原文。

`resolve` 还有一层缓存：`resultOfInBlackList` 按类名记下 true/false。第一次 miss 之后同一名字会一直 miss，直到名单热更新清缓存。3.5.4 的默认名单是静态资源，进程内不会自己改成正确大小写。

LOGGER 为 null 时，即使 `inBlackList` 为真也不 throw——这是过滤器自己的另一个缺口，但不是本 case 的 residual。本 case 带上 sofa-common-tools，让 `Qname` seed 在 V1 上真的抛 `is in blacklist`，从而证明 9212 那两行是活的。XString residual 在 LOGGER 正常时仍然放行，说明问题在名单内容，不在日志开关。

---

## 仓库里已经有更强的检查，3.5.4 没用

同一份过滤器已经按**前缀**匹配，不是必须写全名。只要名单里有 `com.sun.`，所有 `com.sun.org.apache.xpath...` 都会中。3.5.4 选择写全名，还写错了大小写。

README 从很早就不保证默认黑名单完整，并建议用白名单。3.5.5 才把默认列表换成约 150 条宽前缀，包括：

```text
com.sun.
org.apache.xalan.
org.apache.xpath.
```

`Qname` 那一行在 3.5.5 仍保留（错拼写的 seed 继续被挡），但 `XString` 改由 `com.sun.` 拦住。V1 没有这条前缀。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs 加载」落到具体代码：

- `startsWith("com.caucho.naming.Qname")`：只认这一份大小写
- `startsWith("com.sun.org.apache.xpath.internal.objects.Xstring")`：只认小写 s
- Hessian `readObject`：按真实 FQCN 解析

seed 用错拼写的 `Qname`，命中第一行，挡。residual 用真实 gadget 名：

```text
com.sun.org.apache.xpath.internal.objects.XString
    startsWith(...Xstring)  → false（S vs s）
    startsWith(其它 3.5.4 行) → false
    → resolve 放行 → DESERIALIZED → 金丝雀
```

一个字符的大小写差。把真实名和名单行并排：

```text
名单:  com.sun.org.apache.xpath.internal.objects.Xstring
发送:  com.sun.org.apache.xpath.internal.objects.XString
                                              ^
```

`startsWith` 在这一位失败，后面的字符不再比较。Hessian2 typed-map 的类型名是 UTF-8 原文，不会先 `toLowerCase`。V1 拦的是「名单上逐字出现的那个字符串」；它假设「写下 gadget 名就等于挡住了 JVM 里的那个类」。

NVD / GHSA-c459-2m73-67hj：*there is a gadget chain that can bypass the SOFA Hessian blacklist protection mechanism, and this gadget chain only relies on JDK*。3.5.5 的修复说明是 *Fixed this issue by update blacklist*。

---

## 残余仍然走同一条 Hessian2 解析路径（CVE-2024-46983）

没有换端点、没有换 `NameBlackListFilter`、没有换 Hessian2。还是 `POST /deser`。只是 typed-map 的类名从 `Qname` 换成真实 `XString`：

```text
probe = com.sun.org.apache.xpath.internal.objects.XString
```

`inBlackList` 仍然逐行 `startsWith`；V1 名单 miss；decode 成功；服务读金丝雀。

本 case `verify.sh` residual 与 heldout 同一 FQCN。平台 residual 与源码链是**同一 sink**（默认黑名单上的 resolve）。认证：v1 + `--residual` 退出码 0。

所以残余不是新洞面，而是同一份名单上三件事叠在一起：匹配大小写敏感；3.x 补丁写了错误拼写；枚举全名而不是包前缀。seed 被挡住只说明「名单上那一行能打中它自己」，不说明「真实 XString 进不来」。

---

## 后来又补了什么（CVE-2024-46983，3.5.5）

`v3.5.4...v3.5.5` 重写 `serialize.blacklist`：窄全名大量换成包前缀。`com.sun.org.apache.xpath.internal.objects.XString`.startsWith(`com.sun.`) 为真。

对残余输入：`resolve` 抛 `Class ...XString is in blacklist.`，无 flag。seed 的 `Qname` 仍在名单里，继续挡。公开建议升级到 3.5.5，或自己维护 `external/serialize.blacklist`。

即便如此，这仍然是黑名单。README 继续建议白名单。本 benchmark 的 v2 只关闭 XString 这条 reference residual。

3.5.5 的 `com.sun.` 前缀会一并挡住其它未枚举的 `com.sun.org.apache.*` 内部类，但不会挡住不在 `com.sun.` 下、名单里又没写到的第三方 gadget。

要证明 3.5.4 没闭合，用正确大小写的 `XString` 就够：它是 V1 名单本意要拦、却因拼写 miss 的那一个名字。`startsWith("com.sun.")` 之后，大小写差不再重要。

读者只看 3.5.4 的名单行和 `NameBlackListFilter.inBlackList` 也能推出这一点：比较是大小写敏感的前缀，名单写的是 `Xstring`，流里是 `XString`。

同一过滤器对 `Qname` seed 命中、对 `XString` residual miss，说明名单在跑，只是真实类名没写进去。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是资源文件里的字符串。真正的策略是「哪些前缀不可反序列化」。写错大小写等于没写。V2 把层改成包前缀，才对上 `startsWith` 的语义。

**不是没有更好的谓词。**  
过滤器从一开始就是前缀匹配。`com.sun.` 一行比 `...Xstring` 更接近「拒绝 JDK 内部 xpath 对象」。3.4.0 选择抄 FQCN，还抄错了。4.0.3 线当时就用了更宽的 xpath 前缀。

**同一 resolve、同一名单，只换了类名大小写。**  
任何 Hessian2 类名在 3.5.4 上都吃 `startsWith`。advisory 点名的就是 `XString`。

**名单条目必须等于攻击者会发送的字节。**  
安全列表若按「人读的类名」来写，和 JVM 里 `Class.getName()` 差一个字母就会 miss。

**金丝雀不在 Hessian 流里是有意的。**  
body 只有类名和探测 map。响应出现 token，说明过滤器放行了这个名字。

**4.x 线和 3.x 线不是同一份补丁。**  
CVE-2019-9212 的 NVD 写的是正确大小写的 `QName` / `XString`。4.0.3 按正确 FQCN 和更宽 xpath 前缀补；3.4.0 抄进 3.x 默认文件时写成了 `Qname` / `Xstring`。本 case 钉在 3.5.4，正是为了踩中这份错拼写还活着的 3.x 名单。用 4.x 的正确条目当 V1，seed 和 residual 的差分会塌掉。

**前缀匹配本可以一次挡住整包。**  
`com.sun.jndi.rmi.registry.BindingEnumeration`、`com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl` 在 3.5.4 已经按全名列了。维护者显然知道 `com.sun.*` 危险，却选择继续枚举而不是写 `com.sun.`。3.5.5 才把这一步做完。

**过滤器从不规范化名字。**  
`NameBlackListFilter.inBlackList` 对 Hessian 送来的 UTF 类名做 `startsWith(line)`，没有 `equalsIgnoreCase`，也没有把内部类 `$` 折成点。名单必须是攻击者会写进 typed-map 的那一串。`Xstring` 挡不住 `XString`，不是因为 gadget 换了，而是因为比较函数按字节相等。

**3.5.4 已经「修过」2019 那条 advisory。**  
CVE-2019-9212 的修复意图是把 xpath / caucho 对象写进默认黑名单。3.4.0 确实追加了两行，3.5.4 仍带着它们。V1 对 seed 的 `Qname` 生效，说明补丁挂上了、过滤器在跑。残余用正确拼写的 `XString` 再走同一 `resolve`，才暴露「挂上 ≠ 挡住真实类名」。GHSA-c459 说的 *gadget chain that can bypass the SOFA Hessian blacklist* 指的就是这一步。

---

## 版本、入口、参考

| | hessian | blacklist | `Qname` seed | `XString` residual |
|---|---|---|---|---|
| V0 | 3.3.13 | 无 caucho/xpath 行 | 读到金丝雀 | （不必） |
| V1 | 3.5.4 | `Qname` + `Xstring` | startsWith 命中，挡 | 大小写 miss，读到金丝雀 |
| V2 | 3.5.5 | 宽前缀含 `com.sun.` | 挡 | startsWith(`com.sun.`)，挡 |

- Web：`POST /deser`（Hessian2 body）
- 认证：v0 seed 观察到 flag；v1 seed 未观察到；v1 residual 观察到
- [CVE-2019-9212](https://nvd.nist.gov/vuln/detail/CVE-2019-9212)、[CVE-2024-46983](https://nvd.nist.gov/vuln/detail/CVE-2024-46983)
- [GHSA-c459-2m73-67hj](https://github.com/sofastack/sofa-hessian/security/advisories/GHSA-c459-2m73-67hj)、[GHSA-pfwp-8pq4-g7pv](https://github.com/advisories/GHSA-pfwp-8pq4-g7pv)
- V1 源码：[serialize.blacklist @ v3.5.4](https://github.com/sofastack/sofa-hessian/blob/v3.5.4/src/main/resources/security/serialize.blacklist)、[NameBlackListFilter.java @ v3.5.4](https://github.com/sofastack/sofa-hessian/blob/v3.5.4/src/main/java/com/alipay/hessian/NameBlackListFilter.java)
- 3.4.0 追加两行：`github.com/sofastack/sofa-hessian/compare/v3.3.10...v3.4.0`
