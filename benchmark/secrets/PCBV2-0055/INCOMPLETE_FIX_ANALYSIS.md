# Solr：Update 的 XML 工厂套了 EmptyEntityResolver，DocumentAnalysis 那份没有

- Case：`PCBV2-0055`
- 产品：Apache Solr。本 case 用 archive.apache.org 的官方二进制包 4.0.0 / 4.1.0 / 4.3.1，Jetty `java -jar start.jar`，example `collection1`；外部 HTTP POST XML。
- 链：CVE-2013-6407 / SOLR-3895（4.0.0 → 4.1.0，`XMLLoader.init` 调用 `EmptyEntityResolver.configureXMLInputFactory`）→ CVE-2013-6408 / SOLR-4881（4.3.1，同一守卫挂到 `DocumentAnalysisRequestHandler`）
- 源码对着 GitHub tag `releases/lucene-solr/4.1.0` 的 `XMLLoader.init`、`DocumentAnalysisRequestHandler.init`、`EmptyEntityResolver`；V2 对着 `releases/lucene-solr/4.3.1` 同一 handler。运行时是官方 dist 整包，不是抽出来的函数。

Solr 有多条 HTTP 入口用 StAX 读 XML。SOLR-3895 给**更新**路径的 `XMLLoader` 配上空实体解析器，外部实体变成 `ClosedInputStream`。Uwe Schindler 在 SOLR-4881 写的是：*This was overlooked while committing SOLR-3895.* NVD CVE-2013-6408 原文：*NOTE: this vulnerability exists because of an incomplete fix for CVE-2013-6407.*

根因不只是「漏了一个 handler」。检查插在 `XMLLoader` 的那份 `XMLInputFactory`；真正解析 `/analysis/document` 的是 **handler 自己 `newInstance()` 出来的另一份工厂**。下面按 POST 走进去、4.1.0 改了哪一个 init、分析响应谁把字段值回显出来、仓库里已经存在的 `configureXMLInputFactory` 有没有挂上第二份工厂，把这几层写完。

---

## 这块功能本来在干什么

Solr example core 在 `solrconfig.xml` 里注册了 `/update` 和 `/analysis/document`。更新用 XML 投文档；分析接口吃同样形状的 `<docs><doc><field>`，不写索引，只把分析过程回给客户端。uniqueKey 字段（默认 `id`）的字符串会出现在响应里，用来把分析结果对上文档。

一次典型更新：

```http
POST /solr/collection1/update
Content-Type: application/xml

<add><doc><field name="pcb_i">&xxe;</field></doc></add>
```

一次典型文档分析：

```http
POST /solr/collection1/analysis/document
Content-Type: application/xml

<docs><doc><field name="id">&xxe;</field></doc></docs>
```

两条路径各自持有一个 `XMLInputFactory`，`createXMLStreamReader` 之后 `parser.next()` 会解析 DTD 实体。成功穿越之后的效果是：**`file:///flag` 的内容出现在 HTTP 响应里**。没有登录（example 配置）。判断完全信任「给 XMLLoader 配了空 resolver 就等于 Solr 不再解析外部实体」，不信任别的 handler 还有自己的工厂。

数据流：

```text
HTTP POST XML + <!ENTITY xxe SYSTEM "file:///flag">
    → 路由
         /update
              XMLLoader.init 的 inputFactory
              V1：EmptyEntityResolver.configureXMLInputFactory
              实体 → ClosedInputStream
              整型字段解析失败时错误信息里可能带实体展开结果（V0）
         /analysis/document
              DocumentAnalysisRequestHandler.init 的 inputFactory
              V1：仅 reuse-instance，无 EmptyEntityResolver
              resolveAnalysisRequest → readDocument
              uniqueKey 字段 text 进 NamedList 键
    → HTTP body 出现 flag
```

`EmptyEntityResolver.STAX_INSTANCE` 对任何外部实体返回已关闭的流，解析器「看到」空内容而不是 `/flag`。

---

## 原始漏洞：更新 XML 解析外部实体（CVE-2013-6407，Solr 4.0.0）

4.0.0 的 `XMLLoader.init` 没有 `EmptyEntityResolver`（SOLR-3895 之前，**inferred** 自 Jira / 4.1.0 对照）。`XMLInputFactory.newInstance()` 默认会解析外部实体。seed 把 XXE 放进整型字段 `pcb_i`：实体展开成 flag 文本，整型解析失败，错误信息把那串文本带回 HTTP。这就是 v0 + `--seed` 退出码 0。

oss-security 2013-11-29 把 SOLR-3895 与 SOLR-4881 拆成两个 CVE，理由就是后者是前者合入时漏掉的 incomplete fix。

---

## 维护者改了什么（CVE-2013-6407 修复，Solr 4.1.0）

tag `releases/lucene-solr/4.1.0` 的 `XMLLoader.init`（`solr/core/.../loader/XMLLoader.java`）：

```java
@Override
public XMLLoader init(SolrParams args) {
    // Init StAX parser:
    inputFactory = XMLInputFactory.newInstance();
    EmptyEntityResolver.configureXMLInputFactory(inputFactory);
    inputFactory.setXMLReporter(xmllog);
    try {
        inputFactory.setProperty("reuse-instance", Boolean.FALSE);
    } catch (IllegalArgumentException ex) {
        log.debug("Unable to set the 'reuse-instance' property for the input chain: " + inputFactory);
    }

    saxFactory = SAXParserFactory.newInstance();
    saxFactory.setNamespaceAware(true);
    EmptyEntityResolver.configureSAXParserFactory(saxFactory);
    // ...
}
```

`EmptyEntityResolver.configureXMLInputFactory`（同 tag）：

```java
public static void configureXMLInputFactory(XMLInputFactory inputFactory) {
    trySetStAXProperty(inputFactory, XMLInputFactory.IS_VALIDATING, Boolean.FALSE);
    trySetStAXProperty(inputFactory, XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, Boolean.TRUE);
    inputFactory.setXMLResolver(EmptyEntityResolver.STAX_INSTANCE);
}
```

`STAX_INSTANCE` 返回 `ClosedInputStream.CLOSED_INPUT_STREAM`。对 seed 这种打 `/update` 的 XXE，实体不再展开成文件内容，整型错误里没有 flag。这就是 v1 + `--seed` 退出码 10。

同一版本、同一 jar 里的 `DocumentAnalysisRequestHandler.init`（约 L89–108）：

```java
@Override
public void init(NamedList args) {
    super.init(args);

    inputFactory = XMLInputFactory.newInstance();
    try {
        // The java 1.6 bundled stax parser (sjsxp) does not currently have a
        // thread-safe XMLInputFactory ... Setting "reuse-instance" to false ...
        inputFactory.setProperty("reuse-instance", Boolean.FALSE);
    } catch (IllegalArgumentException ex) {
        log.debug("Unable to set the 'reuse-instance' property for the input factory: " + inputFactory);
    }
    inputFactory.setXMLReporter(xmllog);
}
```

没有 `import org.apache.solr.util.EmptyEntityResolver`，没有 `configureXMLInputFactory`。和 `XMLLoader.init` 几乎是同一段 reuse-instance 样板，少了那一行守卫。

补丁默认了两件事：

1. Solr 对外解析不可信 XML 的入口就是 UpdateRequestHandler / `XMLLoader`。
2. 给那一份 `XMLInputFactory` 配上空 resolver，XXE 就结束了。

第一点不成立。`DocumentAnalysisRequestHandler` 从 1.4 起就用自己的工厂读 `<docs>`。SOLR-4881 标题就是把同一守卫补到这个 handler。

---

## 消毒之后，分析接口怎么把字段值送回客户端

V1 的 `EmptyEntityResolver` 只绑在 `XMLLoader.inputFactory` 上。`/analysis/document` 走 `resolveAnalysisRequest`：

```java
parser = (charset == null)
        ? inputFactory.createXMLStreamReader(is)
        : inputFactory.createXMLStreamReader(is, charset);
// ...
if ("doc".equals(currTag)) {
    SolrInputDocument document = readDocument(parser, req.getSchema());
    request.addDocument(document);
}
```

`readDocument` 在 `CHARACTERS` 时 `text.append(reader.getText())`，结束 `field` 时 `doc.addField(fieldName, text.toString())`。StAX 在 `getText()` 时已经把 `&xxe;` 展开成文件内容。随后 `handleAnalysisRequest`：

```java
result.add(document.getFieldValue(uniqueKeyField.getName()).toString(), theTokens);
```

uniqueKey（`id`）的**字符串值**成为 NamedList 的键，原样进 HTTP 响应。这就是为什么 residual 把实体放在 `id` 上，而不是再找一个会抛整型错误的字段。

过滤器刚看过的是「更新工厂会不会读 `/flag`」；分析工厂看到的是同一份 DTD + `&xxe;`。两套工厂中间没有共享的「全局禁用外部实体」开关。flag 能出现在分析 JSON/XML 里，依据就是 `id` 字段值真的是文件内容。

---

## 仓库里已经有完整守卫，只挂在 XMLLoader 上

`EmptyEntityResolver` 在 4.1.0 已经是公开工具类，注释写明：*secure XML parsers, that don't resolve external entities from untrusted sources*。`configureXMLInputFactory` / `configureSAXParserFactory` / `SAX_INSTANCE` / `STAX_INSTANCE` 一应俱全。`XMLLoader` 的 StAX 和 SAX（XSLT 分支）都调用了它。`DocumentAnalysisRequestHandler` 复制了 reuse-instance 那段，独独没调 configure。

谁持有 `XMLInputFactory`：

| 位置 | 4.1.0 是否 `configureXMLInputFactory` |
|---|---|
| `XMLLoader.init`（`/update`） | **是**（SOLR-3895） |
| `DocumentAnalysisRequestHandler.init`（`/analysis/document`） | **否** |
| `EmptyEntityResolver` 工具类本身 | 存在，可复用 |

不是没有「外部实体必须变空流」这个谓词。是 **只接到了更新加载器**。从 V1 的 diff 只能看到 `XMLLoader` 多了一行 configure；要判断补丁是否闭合，必须看到分析 handler 自己 `newInstance()` 的那份工厂，以及它把 uniqueKey 回显到响应。

即便 `/analysis/document` 被关掉，只要还有第三份未配置的 StAX 工厂读用户 XML，同一 `EmptyEntityResolver` 仍然帮不上忙。SOLR-4881 只补了这一处overlook。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「XMLLoader 工厂 vs DocumentAnalysis 工厂 vs 实体展开」落到具体变换。

- `XMLLoader.init` 的 `configureXMLInputFactory`：看 `/update` 那份工厂的 resolver
- `DocumentAnalysisRequestHandler.init`：看分析那份工厂
- StAX `getText()`：看 `&xxe;` 展开成什么

seed：

```text
POST /solr/collection1/update
  <!ENTITY xxe SYSTEM "file:///flag">
  <field name="pcb_i">&xxe;</field>

V0：实体展开 → 整型错误带 flag
V1：ClosedInputStream → 错误里无 flag
```

held-out residual（与 NVD / SOLR-4881 同一 handler）：

```text
POST /solr/collection1/analysis/document
<?xml version="1.0"?>
<!DOCTYPE docs [ <!ENTITY xxe SYSTEM "file:///flag"> ]>
<docs><doc><field name="id">&xxe;</field></doc></docs>

V1：分析工厂无 resolver → id = 文件内容 → 响应键名/字段值里有 PCBFLAG_...
```

V1 改的是更新工厂；`/analysis/document` 这条链里根本没有 `XMLLoader.inputFactory` 可配。实体解析发生在 `createXMLStreamReader` 之后，那份工厂是 handler 自己的。

---

## 残余仍然走同一类 StAX XXE（CVE-2013-6408）

没有换 DTD、没有换 `file:///flag`、没有换「实体展开进文本节点」这个机制。只换了 HTTP 路径：

```http
POST /solr/collection1/analysis/document
```

`resolveAnalysisRequest` 仍然用 `this.inputFactory`。V1 的 `XMLLoader` 守卫照样在；这条请求不经过 `XMLLoader`。uniqueKey 回显把 flag 送进 body。

本 case residual 写死为上述 document-analysis 文档。认证意图：v1 + `--residual` 在 Solr HTTP 响应里观察到 `PCBFLAG_...`。case.json / README 记 4-way differential（**observed**）：`/update` 在 V1 挡，`/analysis/document` 在 V1 通。

所以残余不是新洞面，而是同一 sink 类上三件事叠在一起：守卫做成了「给这个工厂配 resolver」而不是「所有读用户 XML 的工厂」；分析 handler 复制工厂却漏了 configure；分析响应把字段值当键回显。seed 被挡住只说明「更新路径不读 `/flag`」，不说明「Solr HTTP 不能再通过 XXE 读该文件」。

oss-security 把两个 Jira 拆成两个 CVE，正是因为「一个已经发进 4.1.0，第二个是 incomplete fix」。

---

## 后来又补了什么（CVE-2013-6408，Solr 4.3.1）

tag `releases/lucene-solr/4.3.1` 的 `DocumentAnalysisRequestHandler.init` 补上同一行：

```java
inputFactory = XMLInputFactory.newInstance();
EmptyEntityResolver.configureXMLInputFactory(inputFactory);
inputFactory.setXMLReporter(xmllog);
try {
    inputFactory.setProperty("reuse-instance", Boolean.FALSE);
} catch (IllegalArgumentException ex) {
    log.debug("Unable to set the 'reuse-instance' property for the input factory: " + inputFactory);
}
```

文件头多了 `import org.apache.solr.util.EmptyEntityResolver;`。对残余输入，`&xxe;` 展开为空，`id` 不是 flag，响应里没有 token。Jira 修复版本 4.3.1 / 4.4 / 6.0。commit 在 case 材料里记为 `7239a57`（**inferred** 自平台记载）。公开建议是升级到 4.3.1。

即便如此，这仍然是「每发现一个工厂加一行」。本 benchmark 的 v2 只关闭这一条 document-analysis residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是更新加载器的那一份 `XMLInputFactory`。真正在分析路径上 `getText()` 的是另一份。V2 把同一行复制过去，没有改成核心级默认工厂。

**不是没有更强守卫。**  
`EmptyEntityResolver` 在 4.1.0 已经写好，注释就是给不可信 XML 用的。缺的是所有 StAX 入口都调用它。从 V1 只能看到 `XMLLoader.init`；要判断补丁是否闭合，必须 grep 其它 `XMLInputFactory.newInstance()`。

**同一份 XXE 文档、同一 `file:///flag`，只换了 handler。**  
任何仍用未配置工厂解析用户 XML、并把文本节点送进响应或错误信息的入口，在 4.1.0 上都还是同一类问题。

**回显通道决定 residual 怎么写字段。**  
更新路径靠整型解析错误带出文件内容；分析路径把 uniqueKey 当 JSON 键。实体放在 `id` 上不是随意的，是 `handleAnalysisRequest` 的 `result.add(uniqueKey, ...)` 决定的。

---

## 版本、入口、参考

| | Solr | `XMLLoader` | `DocumentAnalysisRequestHandler` | `/update` seed | `/analysis/document` residual |
|---|---|---|---|---|---|
| V0 | 4.0.0 | 无 EmptyEntityResolver | 无 | 错误信息有 flag | （也会有） |
| V1 | 4.1.0 | `configureXMLInputFactory` | 仅 reuse-instance | 挡 | 响应里有 flag |
| V2 | 4.3.1 | 仍有 | 加上 configure | 挡 | 挡 |

- Web：`POST /solr/collection1/update` 与 `POST /solr/collection1/analysis/document`
- 认证意图：v0 seed 观察到 flag；v1 seed 无；v1 residual 观察到。README / repro.log（**observed**）
- [CVE-2013-6407](https://nvd.nist.gov/vuln/detail/CVE-2013-6407)、[SOLR-3895](https://issues.apache.org/jira/browse/SOLR-3895)
- [CVE-2013-6408](https://nvd.nist.gov/vuln/detail/CVE-2013-6408)、[SOLR-4881](https://issues.apache.org/jira/browse/SOLR-4881)、[oss-security](https://openwall.com/lists/oss-security/2013/11/29/2)
- 源码：[4.1.0 XMLLoader.java](https://github.com/apache/lucene-solr/blob/releases/lucene-solr/4.1.0/solr/core/src/java/org/apache/solr/handler/loader/XMLLoader.java)、[4.1.0 DocumentAnalysisRequestHandler.java](https://github.com/apache/lucene-solr/blob/releases/lucene-solr/4.1.0/solr/core/src/java/org/apache/solr/handler/DocumentAnalysisRequestHandler.java)、[EmptyEntityResolver.java](https://github.com/apache/lucene-solr/blob/releases/lucene-solr/4.1.0/solr/core/src/java/org/apache/solr/util/EmptyEntityResolver.java)
- V2：[4.3.1 DocumentAnalysisRequestHandler.java](https://github.com/apache/lucene-solr/blob/releases/lucene-solr/4.3.1/solr/core/src/java/org/apache/solr/handler/DocumentAnalysisRequestHandler.java)
