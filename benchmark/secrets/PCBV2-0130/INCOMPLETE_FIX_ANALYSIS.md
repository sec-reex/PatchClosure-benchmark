# Jenkins agent 密钥：读路径打码了，复制路径仍交出整份 XML

- Case：`PCBV2-0130`
- 产品：Jenkins core（官方镜像 `jenkins/jenkins` LTS）
- 链：CVE-2025-27622 / SECURITY-3495（LTS 2.492.1 → 2.492.2）→ CVE-2025-31721 / SECURITY-3513（2.492.2 → 2.492.3）
- 源码对着 GitHub tag `jenkins-2.492.2` / `jenkins-2.492.3` 的 `hudson.model.Computer.doConfigDotXml`、`hudson.model.ComputerSet.doCreateItem`，以及早已存在的 `jenkins.security.ExtendedReadRedaction.applyAll`。运行时是整台官方 LTS，agent 密钥是控制器自己用 `hudson.util.Secret` 加密后写入 node property 的。

2025 年 3 月 5 日，Jenkins 给 agent 的 `config.xml` **读**路径补上脱敏：没有 Agent/Configure 的人只能看到 `********`。四周后 2025-04-02 advisory 写明 SECURITY-3513 *is due to an incomplete fix of SECURITY-3495*：复制 agent 的 HTTP 入口只查 Agent/Create，把源节点整份 XStream XML（含可解密密文）写进攻击者自己的新 agent。NVD CVE-2025-31721：*copy an agent, gaining access to encrypted secrets in its configuration*。

根因不只是「漏了一个 permission check」。检查插在「GET config.xml 要不要打码」这一层；真正把密钥交给低权限用户的是 copy 分支的 `XSTREAM.toXML` → `fromXML` → `addNode`；同仓库里 `ExtendedReadRedaction` 已经能识别可解密 Secret，却只挂在读路径上。下面按请求走进去、2.492.2 改了哪几行、打码之后谁还在序列化那份 XML、更强的谓词有没有挂上复制，把这几层写完。

平台 `verify.sh` 的 residual 走 `POST /computer/createItem?mode=copy`，和 seed 的 `GET .../config.xml` 不是同一个 HTTP 动词/路径。这正是这条不完整修复链的 sibling sink，不是另起一条无关洞。heldout 与 V1 源码对得上：复制之后再读副本的 `config.xml`，解密得到同一枚 agent secret。

---

## 这块功能本来在干什么

Jenkins 把每个 agent（`Node`）的配置存在控制器上，环境变量、启动参数里可以放 `hudson.util.Secret`。有 Agent/Extended Read 的人允许**看**配置，但不该看到能拿去离线解密的密文；有 Agent/Configure 的人才该看到完整 XML。REST 入口是：

```http
GET /computer/agentA/config.xml
```

复制入口是「新建 agent」表格的 copy 模式：

```http
POST /computer/createItem?name=<new>&mode=copy&from=agentA
```

`ComputerSet.doCreateItem` 在 `mode=copy` 时取出源 `Node`，`Jenkins.XSTREAM.toXML(src)` 再 `fromXML`，`addNode` 成一份攻击者拥有的新节点。成功穿越之后的效果是：**低权限用户拿到源 agent 里那份可解密的 Secret 密文**（本 case 明文是 `PCBFLAG_...`，由 init hook 用当前控制器密钥加密后写入 `agentA` 的 `EnvironmentVariablesNodeProperty`）。

数据流：

```text
攻击者（Create + ExtendedRead，无 Configure）
    GET  /computer/agentA/config.xml
         Computer.doConfigDotXml
              checkPermission(EXTENDED_READ)
              xml = XSTREAM2.toXMLUTF8(node)
              V1：无 CONFIGURE → ExtendedReadRedaction.applyAll(xml)   ← 补丁插在这里
              返回打码或未打码的 XML
    POST /computer/createItem?mode=copy&from=agentA
         ComputerSet.doCreateItem
              checkPermission(Computer.CREATE)   ← V1 复制路径只查这一项
              xml = XSTREAM.toXML(src)           ← 完整密文，不打码
              fromXML → addNode(副本)
    GET  /computer/<副本>/config.xml            ← 攻击者现在「拥有」副本
```

设计意图：没有 Configure 就不能看到（也不能复制出）那些 Secret。V1 只落实了「不能看到」。

---

## 原始漏洞：读路径不打码（CVE-2025-27622，LTS 2.492.1）

2.492.1 的 `doConfigDotXml` GET 分支在 `EXTENDED_READ` 通过之后，直接把节点序列化进响应。没有「有没有 CONFIGURE」的分叉，也没有调用 `ExtendedReadRedaction`。2015–2016 年 SECURITY-266 已经给 **Job** 的 `config.xml` 做过同类打码；agent 这条 REST/CLI 读路径一直没接上。

2025-03-05 advisory（SECURITY-3495）：*does not redact encrypted values of secrets when accessing config.xml of agents via REST API or CLI*。本 case 的 seed：

```text
GET /computer/agentA/config.xml   （attacker，ExtendedRead，无 Configure）
```

V0 响应里是真实 `hudson.util.Secret` 密文。oracle 用管理员 script console、同一把控制器密钥解密，得到 `PCBFLAG_...`。这就是 v0 + `--seed` 退出码 0。

`ExtendedReadRedaction` / `ExtendedReadSecretRedaction` 当时已经在 core 里：用 `Secret.ENCRYPTED_VALUE_PATTERN` 找密文，`Secret.decrypt != null` 则换成 `********`。读 agent 配置的人没用它。

---

## 维护者改了什么（CVE-2025-27622 修复，LTS 2.492.2）

2.492.2 只改 GET `config.xml`。tag `jenkins-2.492.2` 的 `Computer.doConfigDotXml`：

```java
// hudson.model.Computer.doConfigDotXml  (jenkins-2.492.2)
@WebMethod(name = "config.xml")
public void doConfigDotXml(StaplerRequest2 req, StaplerResponse2 rsp)
        throws IOException, ServletException {
    if (req.getMethod().equals("GET")) {
        checkPermission(EXTENDED_READ);
        rsp.setContentType("application/xml");
        Node node = getNode();
        if (node == null) {
            throw HttpResponses.notFound();
        }
        if (hasPermission(CONFIGURE)) {
            Jenkins.XSTREAM2.toXMLUTF8(node, rsp.getOutputStream());
        } else {
            var baos = new ByteArrayOutputStream();
            Jenkins.XSTREAM2.toXMLUTF8(node, baos);
            String xml = baos.toString(StandardCharsets.UTF_8);
            xml = ExtendedReadRedaction.applyAll(xml);
            org.apache.commons.io.IOUtils.write(xml, rsp.getOutputStream(), StandardCharsets.UTF_8);
        }
        return;
    }
    ...
}
```

同一 tag 上，复制路径仍是：

```java
// hudson.model.ComputerSet.doCreateItem  (jenkins-2.492.2)
@RequirePOST
public synchronized void doCreateItem(...) {
    final Jenkins app = Jenkins.get();
    app.checkPermission(Computer.CREATE);

    if (mode != null && mode.equals("copy")) {
        name = checkName(name);
        Node src = app.getNode(from);
        ...
        // copy through XStream
        String xml = Jenkins.XSTREAM.toXML(src);
        Node result = (Node) Jenkins.XSTREAM.fromXML(xml);
        result.setNodeName(name);
        result.holdOffLaunchUntilSave = true;
        app.addNode(result);
        rsp.sendRedirect2(result.getNodeName() + "/configure");
    }
    ...
}
```

对 seed 这种 GET，V1 确实够用：没有 CONFIGURE 时密文变成 `********`，没有可解密材料，v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 密钥离开控制器的方式是「有人 GET/CLI 读 `config.xml`」。
2. 打码发生在**响应序列化**上，复制这种「序列化给自己新节点」不算读。

第二点不成立。`toXML(src)` 产生的字符串和 GET 那份是同一类 XStream 文档，里面仍是可 `Secret.decrypt` 的密文。复制完成后，攻击者作为副本的拥有者再 GET，走的是 `hasPermission(CONFIGURE)` 为真的分支，打码根本不会再跑。

（仓库里的 `patch.diff` 误采了 SECURITY-3498 的 `toggleCollapse` `@POST` 变更。判断 V1 是否闭合必须以 tag `jenkins-2.492.2` 的 `Computer` / `ComputerSet` 为准，不能以那份 diff 为准。）

---

## 消毒之后，谁真正消费那份 XML

读路径上，`applyAll` 的消费者是 HTTP 响应体。复制路径上，同一份 XML 的消费者是 `XSTREAM.fromXML` 和随后的 `addNode`：

```text
src (agentA，含 Secret)
    → toXML → 字符串（密文仍在）
    → fromXML → 新 Node（Secret 字段原样）
    → addNode → 磁盘上的新 agent config
    → 攻击者 GET 副本 /config.xml → 未打码密文
```

`ExtendedReadSecretRedaction.apply` 用的谓词是「这段像 Secret 并且当前控制器能解密」。复制路径在 V1 **完全不调用**它。内核不会在 `fromXML` 时自动打码；打码是一项显式的、按调用点挂上的策略。

所以：过滤器刚看过的是 GET 响应；open/copy 看到的是另一条把同一 `Node` 序列化进另一份配置的代码。两套语义中间没有第二次 `applyAll`。

本 case 的 flag 能从副本里解出来，依据就是这一步，而不是「读路径打码失败」。

---

## 仓库里已经有更强的检查，复制路径没用

`ExtendedReadRedaction.applyAll` 从 2.479 / SECURITY-266 起就是给「Extended Read 但没有 Configure」用的通用打码口。`ExtendedReadSecretRedaction` 会验证 `Secret.decrypt != null`，避免把碰巧长得像密文的普通字段抹掉。

谁调用它（2.492.2）：

| 函数 | 调用 `ExtendedReadRedaction.applyAll`？ |
|---|---|
| `Computer.doConfigDotXml` GET | **是**（V1 新加） |
| Job 的 `config.xml` 读 | 是（更早的 SECURITY-266） |
| `ComputerSet.doCreateItem` copy | **否**，裸 `toXML` / `fromXML` |

V1 等于在读路径接上了已经存在的谓词，复制路径继续信任 `Computer.CREATE` 这一项。不是仓库里没有更好的检查，是 **copy 没用**。

即便攻击者没有 ExtendedRead，只要有 Create，V1 的 copy 仍然能把源 XML 写进自己的节点（那是后来的 CVE-2025-31720 / SECURITY-3512：V2 额外加了 `src.checkPermission(EXTENDED_READ)`）。本 case residual 的攻击者两种权限都有，打的是「有密钥却没有 Configure」这一支，对应 CVE-2025-31721。

---

## 这个补丁挡住了什么、没挡住什么

- `doConfigDotXml`：看当前用户有没有 CONFIGURE；没有就把响应里的可解密 Secret 换成 `********`
- `doCreateItem(copy)`：只看有没有 CREATE；XML 原样克隆

只要走 copy，第一行的打码不会运行，第二行仍然交出完整密文。

```text
seed GET /computer/agentA/config.xml
  V1：applyAll → ******** → 解不出 flag

residual POST /computer/createItem?mode=copy&from=agentA&name=...
  V1：toXML(src) 含密文 → addNode
  再 GET /computer/<new>/config.xml
  攻击者对副本有 Configure → 不打码 → 密文 → 解密得 PCBFLAG_...
```

V1 挡的是「直接读别人的 config.xml」；它没挡「先变成这份配置的主人，再读」。seed 被挡住只说明读路径的响应里没有密文，不说明低权限用户拿不到那份 Secret。

---

## 残余仍然交出同一份 agent 密钥（CVE-2025-31721）

没有换密钥、没有换加密算法、没有换 agentA 上的 node property。还是那枚 `hudson.util.Secret`。换的是入口：

```http
POST /computer/createItem?name=<new>&mode=copy&from=agentA
GET  /computer/<new>/config.xml
```

`doCreateItem` 在 2.492.2 上仍然只 `checkPermission(CREATE)`。heldout 的 `probe: copy` 与平台 verify residual 的 inline candidate 是同一构造。认证：v1 + `--residual` 退出码 0，解密结果中观察到 `PCBFLAG_...`。

所以残余不是新资产，而是同一 Secret 上三件事叠在一起：打码只挂在 GET；copy 用另一套序列化且不调用 `applyAll`；副本的后续 GET 对拥有者不再打码。

---

## 后来又补了什么（CVE-2025-31721 / 31720，LTS 2.492.3）

2.492.3 的 copy 分支在 `toXML` 前后加上读权限和「含密钥则拒绝」：

```java
// hudson.model.ComputerSet.doCreateItem  (jenkins-2.492.3)
src.checkPermission(Computer.EXTENDED_READ);

String xml = Jenkins.XSTREAM.toXML(src);
if (!src.hasPermission(Computer.CONFIGURE)) {
    final String redactedConfigDotXml = ExtendedReadRedaction.applyAll(xml);
    if (!xml.equals(redactedConfigDotXml)) {
        throw new AccessDeniedException(
            Messages.ComputerSet_may_not_copy_as_it_contains_secrets_and_(
                src.getNodeName(),
                Jenkins.getAuthentication2().getName(),
                Computer.PERMISSIONS.title,
                Computer.EXTENDED_READ.name,
                Computer.CONFIGURE.name));
    }
}
Node result = (Node) Jenkins.XSTREAM.fromXML(xml);
```

对残余：`applyAll` 会改 XML（把 Secret 换成星号），`xml.equals(redacted)` 为假，抛 `AccessDeniedException`，HTTP 403，文案是 *May not copy agentA as it contains secrets*。公开建议升到 weekly 2.504 / LTS 2.492.3。

这仍然是「在 copy 调用点补上读路径已经用过的谓词」，没有改 XStream 本身。对这条「复制含密钥 agent」链它够用。本 benchmark 的 v2 只关闭这一条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是 GET 响应。真正让密钥换主人的是 copy 的 `toXML`/`fromXML`。V2 把同一套 `applyAll` 接到 copy，而不是在序列化层统一打码。

**不是没有更好的谓词。**  
`ExtendedReadRedaction` 比「只查 CREATE」更接近「没有 Configure 就不能碰 Secret」。它已经用在 Job 和（V1 之后的）agent 读路径上。从错误的 `toggleCollapse` diff 看不出这一点；必须对着 `ComputerSet.doCreateItem` 的 copy 分支。

**同一份 XML，只换了「读」还是「克隆」。**  
任何把 `Node` 经 XStream 交到低权限用户手里的入口，在 2.492.2 上都不受 GET 那行 `applyAll` 约束。SECURITY-3512 说明连 ExtendedRead 都没有的 Create 用户也能先拷到配置。

**打码发生在字符串上，所有权发生在 addNode 上。**  
一旦节点改了主人，后续 GET 的 CONFIGURE 检查对攻击者为真。残余利用的是所有权变化，不是打码正则的漏洞。

**金丝雀是控制器自己加密的 Secret。**  
明文从不进镜像。能解出 `PCBFLAG_...`，说明副本里仍是可 `Secret.decrypt` 的密文，而不是打码后的 `********`。

---

## 版本、入口、参考

| | LTS | GET `config.xml` | POST `createItem?mode=copy` | seed 读 | residual 复制 |
|---|---|---|---|---|---|
| V0 | 2.492.1 | 不打码 | 只查 CREATE，整份 XML | 解出 flag | （不必） |
| V1 | 2.492.2 | 无 Configure → `applyAll` | 同上，仍不调 `applyAll` | `********` | 解出 flag |
| V2 | 2.492.3 | 同 V1 | 先 EXTENDED_READ；无 Configure 且 XML 含 Secret → 403 | 挡 | 403 |

- 读：`GET /computer/agentA/config.xml`
- 复制：`POST /computer/createItem?mode=copy&from=agentA`
- [CVE-2025-27622](https://nvd.nist.gov/vuln/detail/CVE-2025-27622)、[CVE-2025-31721](https://nvd.nist.gov/vuln/detail/CVE-2025-31721)、[CVE-2025-31720](https://nvd.nist.gov/vuln/detail/CVE-2025-31720)
- [Jenkins advisory 2025-03-05 SECURITY-3495](https://www.jenkins.io/security/advisory/2025-03-05/#SECURITY-3495)
- [Jenkins advisory 2025-04-02 SECURITY-3513](https://www.jenkins.io/security/advisory/2025-04-02/#SECURITY-3513)
- [GHSA-wr6w-jxg7-qpfh](https://github.com/advisories/GHSA-wr6w-jxg7-qpfh)
- 源码：[`jenkins-2.492.2` Computer.java](https://github.com/jenkinsci/jenkins/blob/jenkins-2.492.2/core/src/main/java/hudson/model/Computer.java)、[同 tag ComputerSet.java](https://github.com/jenkinsci/jenkins/blob/jenkins-2.492.2/core/src/main/java/hudson/model/ComputerSet.java)、[`jenkins-2.492.3` ComputerSet.java](https://github.com/jenkinsci/jenkins/blob/jenkins-2.492.3/core/src/main/java/hudson/model/ComputerSet.java)
