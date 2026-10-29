# XStream：默认黑名单加了 `EventHandler`，没加下一条能调 `ProcessBuilder.start` 的类

- Case：`PCBV2-0005`
- 产品：XStream（本 case Maven `1.4.10` / `1.4.13` / `1.4.14`，真实 `POST /deser`，`new XStream().fromXML(body)`）
- 链：CVE-2013-7285（动态代理 + `java.beans.EventHandler` → `ProcessBuilder`）→ 1.4.10 引入 Security Framework、1.4.13 默认黑名单收 `EventHandler` → CVE-2020-26217（`javax.imageio.ImageIO$ContainsFilter` → 同一 `ProcessBuilder.start`，1.4.14）
- 源码对着 `XSTREAM_1_4_13` / `XSTREAM_1_4_14` 的 `XStream.setupSecurity`。运行时是整包 xstream。金丝雀是 benign：XML 里先写触发类型名，再写 `<pcb.PcbCanary/>`；deny 住第一个元素就不会走到 canary converter。

XStream 自己的 CVE-2020-26217 页写：*This issue is a variation of CVE-2013-7285, this time using a different set of classes of the Java runtime environment, none of which is part of the XStream default blacklist.* 并写明 *All versions until and including version 1.4.13 are affected, if using the version out of the box*。

根因不只是「又发现一个 gadget」。检查插在「类型名是否等于 deny 列表里某一串」上；真正 unmarshal 的是 Converter。同文件里已经有 `setupDefaultSecurity` 白名单助手，`new XStream()` 默认不用。下面按请求走进去。

---

## 这块功能本来在干什么

XStream 从 XML（或 JSON）重建对象。流里带类型名，`fromXML` 按名字 `Class.forName`、选 Converter、填字段。`new XStream()` 在 1.4.10 之后会调 `setupSecurity()`，装上 Security Framework；默认策略是 **AnyTypePermission.ANY 减去若干 deny**。

一次典型请求：

```xml
<list>
  <java.beans.EventHandler/>
  <pcb.PcbCanary/>
</list>
```

数据流（1.4.13，本 case 的 V1）：

```text
POST /deser  text/xml
    → new XStream()          // 构造器末尾 setupSecurity()
         addPermission(AnyTypePermission.ANY)
         denyTypes("java.beans.EventHandler")
         denyTypesByRegExp(LAZY_ITERATORS, JAVAX_CRYPTO)
    → xs.fromXML(body)
         读元素名 → 类型
         SecurityMapper 查 TypePermission
              deny 命中 → ForbiddenClassException，后面的元素不处理
              否则 Converter.unmarshal → new
         下一元素 <pcb.PcbCanary/> 同样过 mapper
    → 本 case：PcbCanary converter 读 /canary/flag.txt，响应带 flag
```

设计意图：开箱即用的 `new XStream()` 不能再走 2013 年那条 EventHandler RCE。成功穿越之后的效果是**命名的类型被 unmarshal**；本 case 用后续 benign 元素读金丝雀代替 `ProcessBuilder.start()`，观察的是同一道 deny 门。

---

## 原始漏洞：默认允许任意类型（CVE-2013-7285，1.4.10）

1.4.10 已有 Security Framework，但 `setupSecurity()` 在这一代实质上是 `AnyTypePermission.ANY`，**没有**把 `EventHandler` 放进默认 deny。CVE-2013-7285 的 gadget 是动态代理 + `java.beans.EventHandler` 调 `ProcessBuilder.start()`。advisory 写 1.4.10 *is affected if the security framework has not been initialized*；开箱 `new XStream()` 就是这种状态。

本 case seed 只送类型名（不搭完整代理链）：

```text
type = java.beans.EventHandler
XML  = <list><java.beans.EventHandler/><pcb.PcbCanary/></list>
```

1.4.10 上 EventHandler 被允许 → 继续处理 list 里下一个元素 → canary converter 跑 → 响应里有 `PCBFLAG_...`。

---

## 维护者改了什么（CVE-2013-7285 方向的默认黑名单，1.4.13）

1.4.13 changelog：*New predefined blacklist avoids vulnerability due to improper setup of the security framework*。`setupSecurity` 在 ANY 之上加了精确类型和两张正则：

```java
// com/thoughtworks/xstream/XStream.java :: setupSecurity  (XSTREAM_1_4_13)
    protected void setupSecurity() {
        if (securityMapper == null) {
            return;
        }

        addPermission(AnyTypePermission.ANY);
        denyTypes(new String[]{"java.beans.EventHandler"});
        denyTypesByRegExp(new Pattern[]{LAZY_ITERATORS, JAVAX_CRYPTO});
        allowTypeHierarchy(Exception.class);
        securityInitialized = false;
    }
```

`LAZY_ITERATORS` 配 `.*$LazyIterator`，`JAVAX_CRYPTO` 配 `javax.crypto.*`。`new XStream()` 的构造器在 `setupMappers()` 之后无条件调用它（1.4.13 约 L543–544），应用代码写 `new XStream(); xs.fromXML(untrusted)` 就会吃到这张表，不必自己 `setupSecurity`。

```java
        setupMappers();
        setupSecurity();
        setupAliases();
```

对 seed：元素名 `java.beans.EventHandler` 命中 `denyTypes` → `ForbiddenClassException` → 到不了 `<pcb.PcbCanary/>` → 没有 flag。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 2013 年那条链的触发类叫 `java.beans.EventHandler`（再加 LazyIterator / javax.crypto）。
2. 不在这几个名字/正则里的 JDK 类，开箱可以 unmarshal。

第二点是黑名单的结构：RCE sink 仍是 `ProcessBuilder.start()`，换一个能反射调这个方法的 JDK 类即可。1.4.13 **没有** deny `java.lang.ProcessBuilder` 本身，也没有 deny `javax.imageio.ImageIO$ContainsFilter`。

---

## 消毒之后，谁真正消费那个类型名

`SecurityMapper` 在 Converter 之前跑。命中 deny 就抛 `ForbiddenClassException`；否则 `HierarchicalStreamReader` 的元素名被交给对应 Converter，`unmarshal` 建对象、填字段、必要时调方法。

CVE-2020-26217 的完整链（advisory 给出的 XML）里，`ImageIO$ContainsFilter` 的 `method` 指向 `ProcessBuilder.start`，在 iterator 前进时触发。本 case 不跑这条链：只要求 1.4.13 的 mapper **允许**这个类型名，从而走到 list 里下一个 benign 元素。观察的是 deny 集合，不是 calc.exe。

过滤器刚看过的是类型名字段；open（这里是 Converter）看到的是任意 `Class`。中间没有第二道「这个类能不能调 `start()`」的谓词。

---

## 仓库里已经有更强的检查，`new XStream()` 没用

同一份 `XStream.java` 里，1.4.10 就加了白名单助手：

```java
    /**
     * Setup the security framework of a XStream instance.
     * This method is a pure helper method for XStream 1.4.x. It initializes an
     * XStream instance with a white list of well-known and simply types of the
     * Java runtime as it is done in XStream 1.5.x by default.
     * @since 1.4.10
     */
    public static void setupDefaultSecurity(XStream xstream) { ... }
```

changelog 和每条 CVE 页的第一句缓解都是：*use XStream's security framework to implement a whitelist*。`new XStream()` 的构造器调用的是 `setupSecurity()`（ANY + 短黑名单），**不是** `setupDefaultSecurity()`。

不是仓库里没有更好的谓词，是默认路径坚持黑名单。CVE-2020-26217 对 1.4.13 用户给的 workaround 仍然是再 `denyTypes` 两行，同时把白名单列为正道。1.4.18 起默认不再用黑名单。

构造器在 mapper 装配完之后无条件调用 `setupSecurity()`（1.4.13 约 L544）。`denyTypes(String[] names)` 只是往 `securityMapper` 里塞 `NoTypePermission` / 精确名：

```java
    public void denyTypes(String[] names) {
        for (int i = 0; i < names.length; i++) {
            denyType(names[i]);
        }
    }
```

没有「按包前缀拒绝 `javax.imageio.`」或「拒绝所有能拿到 Method 对象的 JDK 类」的默认规则。`denyTypesByRegExp` 已经用在 LazyIterator 和 `javax.crypto.*` 上——同一 API 完全可以再加 `javax\\.imageio\\..*`，V1 没加。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「deny 集合 vs Converter」落到具体名字：

- `setupSecurity`：精确拒绝 `java.beans.EventHandler`，正则拒绝 LazyIterator / javax.crypto.*
- `fromXML`：元素名 → Class → 未 deny 则 Converter

`javax.imageio.ImageIO$ContainsFilter` 不在 String 数组里，也不匹配那两张正则。XStream 默认把内部类写成 `ImageIO_-ContainsFilter`（`$` → `_-`）：

```text
seed:      <java.beans.EventHandler/>
residual:  <javax.imageio.ImageIO_-ContainsFilter/>
```

1.4.13 对前者 ForbiddenClassException，对后者放行，list 继续走到 `<pcb.PcbCanary/>`。

advisory 的完整 PoC 用 FilterIterator + ContainsFilter 调 `ProcessBuilder.start`；本 case 只需要「这个类型名不在 1.4.13 默认 deny 里」这一事实，和 advisory 写的 *none of which is part of the XStream default blacklist* 一致。

---

## 残余仍然走同一条 `fromXML` 路径（CVE-2020-26217）

没有换 API、没有自己配 permission、没有换观察通道。还是：

```http
POST /deser
Content-Type: text/xml

<list>
  <javax.imageio.ImageIO_-ContainsFilter/>
  <pcb.PcbCanary/>
</list>
```

`new XStream()` 照样 `setupSecurity`；1.4.13 那一行 `denyTypes(EventHandler)` 照样执行；ContainsFilter 不在列表里；canary converter 读 `/canary/flag.txt`；响应里出现 `PCBFLAG_...`。

本 case residual candidate：

```text
type = javax.imageio.ImageIO$ContainsFilter
```

认证：v1 residual 观察到 flag；1.4.14 上 `ForbiddenClassException: javax.imageio.ImageIO$ContainsFilter`。

seed 被挡住只说明「2013 年那个触发类名没了」，不说明「开箱 fromXML 不能再碰到 ProcessBuilder」。

advisory 给出的完整 XML 把 `ContainsFilter` 嵌进 `javax.imageio.spi.FilterIterator`，`method` 元素指名 `java.lang.ProcessBuilder` / `start`。1.4.13 的 `denyTypes` **也不含** `ProcessBuilder`。即便有人先 deny 了 EventHandler，iterator 前进时仍能反射调用 `start()`。本 case 不需要把这条链跑通：mapper 对 `ImageIO$ContainsFilter` 放行，就已经证明默认黑名单相对 2013 年那条 RCE sink 是不完整的。NSFOCUS 的通报把这写成「使用另一组类绕过黑名单」。

`denyTypes` 的实现按**字符串类名**精确匹配。内部类在 XML 里写成 `ImageIO_-ContainsFilter`，mapper 再折回 `ImageIO$ContainsFilter`。换元素写法（`$` / `_-` / 全限定 vs 短名）过不了这道门的唯一办法是名字根本不在数组里——残余走的就是这条。

---

## 后来又补了什么（CVE-2020-26217，1.4.14）

1.4.14 changelog：*The types java.lang.ProcessBuilder and javax.imageio.ImageIO$ContainsFilter are now part of the default blacklist*。

```java
// XStream.setupSecurity  (XSTREAM_1_4_14)
        addPermission(AnyTypePermission.ANY);
        denyTypes(new String[]{
            "java.beans.EventHandler",
            "java.lang.ProcessBuilder",
            "javax.imageio.ImageIO$ContainsFilter"
        });
        denyTypesByRegExp(new Pattern[]{LAZY_ITERATORS, JAVAX_CRYPTO});
```

同一 `fromXML`，ContainsFilter 现在 ForbiddenClassException。workaround 对停在 1.4.13 的用户就是把这两行手写上去。

这仍然是黑名单加行。CVE-2020-26258 马上又要 deny `NativeString` 和 `ReadAllStream$FileStream`。本 benchmark 的 v2 只关闭 -26217 这一条。

---

## 从这条链还能看出什么

**维护者改错了哪一层。**  
他们改的是默认 deny 数组。真正执行命令的是 Converter 调到的 `ProcessBuilder.start`。V2 仍在同一数组加名，没有把构造器默认切到已经存在的白名单助手。

**不是没有更好的谓词。**  
`setupDefaultSecurity` 从 1.4.10 就在。每条 XStream CVE 都把白名单写在第一段。`new XStream()` 不用它。从 V1 的 diff 只能看到 `denyTypes(EventHandler)`；要判断是否闭合，必须看到 ANY 仍然是底，以及 ContainsFilter 不在数组里。

**同一 `fromXML`、同一默认 mapper，只换了元素名。**  
任何未 deny、又能接到 `start()` 的 JDK 类，在 1.4.13 开箱都是这条残余。

**金丝雀不在 XML 里是有意的。**  
body 只有类型名。token 出现在响应里，说明 mapper 放行了触发类型，后续 converter 才跑。

---

## 版本、入口、参考

| | 版本 | `setupSecurity` | EventHandler seed | ContainsFilter residual |
|---|---|---|---|---|
| V0 | 1.4.10 | ANY，无 EventHandler deny | 读到金丝雀 | （不必） |
| V1 | 1.4.13 | ANY + deny EventHandler + 两正则 | ForbiddenClassException | 读到金丝雀 |
| V2 | 1.4.14 | 再 deny ProcessBuilder + ContainsFilter | 挡 | ForbiddenClassException |

- HTTP：`POST /deser`，XML `<list><TRIGGER/><pcb.PcbCanary/></list>`
- 认证（本平台）：v0 seed 观察到 flag；v1 seed BLOCKED；v1 residual 观察到。
- [CVE-2013-7285](https://x-stream.github.io/CVE-2013-7285.html)、[CVE-2020-26217](https://x-stream.github.io/CVE-2020-26217.html)（*variation of CVE-2013-7285*）
- [GHSA-mw36-7c6c-q4q2](https://github.com/x-stream/xstream/security/advisories/GHSA-mw36-7c6c-q4q2)
- [NVD CVE-2020-26217](https://nvd.nist.gov/vuln/detail/CVE-2020-26217)
- V1 源码：[`XStream.java` @ XSTREAM_1_4_13](https://github.com/x-stream/xstream/blob/XSTREAM_1_4_13/xstream/src/java/com/thoughtworks/xstream/XStream.java) `setupSecurity`
- V2 源码：[`XStream.java` @ XSTREAM_1_4_14](https://github.com/x-stream/xstream/blob/XSTREAM_1_4_14/xstream/src/java/com/thoughtworks/xstream/XStream.java)
