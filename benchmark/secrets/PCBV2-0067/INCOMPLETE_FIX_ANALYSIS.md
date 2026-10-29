# Jenkins remoting：外层黑名单看不见 SignedObject 里面的流

- Case：`PCBV2-0067`
- 产品：Jenkins remoting（`org.jenkins-ci.main:remoting`；master↔agent 通道和基于 remoting 的 CLI 都走它）
- 链：CVE-2015-8103 / SECURITY-218（2.52 → 2.53，commit `7c35ed9a`）→ CVE-2017-1000353 / SECURITY-429（Jenkins 2.57 / LTS 2.46.2 在 core 侧加黑名单；本 case 的 V2 钉 **remoting 自己的 jar 首次带 `SignedObject` 条目** 的 3.16）
- 源码对着 GitHub tag `remoting-2.52` / `remoting-2.53` / `remoting-3.16` 的 `ObjectInputStreamEx.resolveClass`、`ClassFilter.DEFAULT`。运行时是 Maven 整包 remoting + 真实 TCP `ServerSocket`，不是进程内 `readObject` harness。

2015 年 11 月 11 日，Jenkins 给 CLI 反序列化加了 `hudson.remoting.ClassFilter`：`ObjectInputStreamEx.resolveClass` 对**这一条流里点名的类**跑黑名单，挡住 CommonsCollections / Groovy / Xalan 家族。2017 年 4 月 26 日官方 advisory 原文：*an attacker can transfer a serialized java.security.SignedObject object to the remoting-based CLI, that would be deserialized using a new ObjectInputStream, bypassing the blacklist-based protection mechanism*。NVD CVE-2017-1000353 就是这条。后来进了 CISA KEV。

根因不只是「黑名单少写了一个类名」。检查插在外层 `ObjectInputStreamEx` 的 `resolveClass` 上；真正跑 `readObject` 的是 `SignedObject.getObject()` 自己 new 出来的、**没有** ClassFilter 的普通 `ObjectInputStream`。下面按 TCP 走进去、2.53 改了哪几行、外层 check 之后谁重建那个对象、JDK 里已经有的嵌套流为什么没挂上过滤器，把这几层写完。

---

## 这块功能本来在干什么

remoting 是两条 JVM 之间的对象通道。Jenkins CLI（2017 年以前的默认）和 agent 协议都在 socket 上写 Java 序列化。服务端读的时候用 `hudson.remoting.ObjectInputStreamEx(in, cl)`——和 `Command#readFrom` 同一形态。

本 case 的服务是真实 `ServerSocket:9009`。外部 client 容器跨 docker 网络连上来，写入一份序列化流。服务端用**未改过的** `new ObjectInputStreamEx(in, cl)`（2.53+ 默认 `ClassFilter.DEFAULT`）读对象；若外层是 `SignedObject`，再调 `getObject()`。

设计意图：通道上出现的类应该是 remoting 自己的 Command / 业务 DTO。成功穿越之后的效果是：**黑名单里的类在服务端被完整重建，`readObject` 跑起来**。金丝雀是 `/canary/flag.txt`（容器启动时从 `${PCB_FLAG}` 写入，在 app 目录外）。本 benchmark 用良性影子类 `org.apache.commons.collections.functors.PcbSeed`：包名命中 2.53 黑名单前缀，`readObject` 只读那份 flag 到 transient 字段，服务端再把 token 从同一条 TCP 连接 echo 回去。client **不**带 `/canary`，线上没有 flag 字节。没有 CommonsCollections gadget，没有 `Runtime.exec`。

数据流：

```text
TCP 序列化流
    → ObjectInputStreamEx.readObject
         resolveClass(desc.getName())
              V0：Class.forName(name, false, cl)          无过滤
              V1：filter.check(Class.forName(filter.check(name), false, cl))
                   ClassFilter.DEFAULT：groovy.runtime.* /
                       commons.collections.functors.* / *xalan*
                   没有 java.security.SignedObject
         若外层是 SignedObject：
              SignedObject.getObject()
                   new ObjectInputStream(contentBytes).readObject()
                   ← 普通 JDK 流，不再进 ClassFilter
                   → 内层 PcbSeed.readObject 读 /canary/flag.txt
    → 服务端把 flag echo 回 TCP
```

没有 HTTP、没有登录。判断完全信任「外层流点名的类不在黑名单 ⇒ 可以重建」；不信任 JDK 标准类在 `readObject` / `getObject` 里再开一条流。

---

## 原始漏洞：CLI 反序列化不过滤（CVE-2015-8103，remoting 2.52）

2.52 的 `ObjectInputStreamEx` 只有 classloader 覆盖：

```java
// hudson/remoting/ObjectInputStreamEx.java  (tag remoting-2.52，patch.diff "-" 侧)
    public ObjectInputStreamEx(InputStream in, ClassLoader cl) throws IOException {
        super(in);
        this.cl = cl;
    }

    protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
        String name = desc.getName();
        try {
            return Class.forName(name, false, cl);   // 无 filter
        } catch (ClassNotFoundException ex) {
            return super.resolveClass(desc);
        }
    }
```

[Jenkins 2015-11-11 advisory](https://www.jenkins.io/security/advisory/2015-11-11/) SECURITY-218 / CVE-2015-8103：未认证远程攻击者可经 remoting 反序列化在 controller 上跑任意代码。公开利用是 CommonsCollections 等 gadget。本 case 的 seed 不跑 gadget，只把 `PcbSeed` **直接**写进外层流（`mode=direct`）。

V0 上 `resolveClass("org.apache.commons.collections.functors.PcbSeed")` 就是 `Class.forName`，`readObject` 读 `/canary/flag.txt`，TCP 上回 `PCB_SEED_FLAG=PCBFLAG_...`。这是 case.json 记录的一次真实 TCP gate（**本分析未重新 compose**）。

---

## 维护者改了什么（CVE-2015-8103 修复，remoting 2.53）

commit `7c35ed9a` *be careful what we unmarshal from network*。对着 GitHub tag `remoting-2.53` 原文：

```java
// src/main/java/hudson/remoting/ObjectInputStreamEx.java  (tag remoting-2.53)
public class ObjectInputStreamEx extends ObjectInputStream {
    private final ClassLoader cl;
    private final ClassFilter filter;

    /** @deprecated as of 2.53 */
    public ObjectInputStreamEx(InputStream in, ClassLoader cl) throws IOException {
        this(in, cl, ClassFilter.DEFAULT);
    }
    public ObjectInputStreamEx(InputStream in, ClassLoader cl, ClassFilter filter) throws IOException {
        super(in);
        this.cl = cl;
        this.filter = filter;
    }

    protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
        String name = desc.getName();
        try {
            return filter.check(Class.forName(filter.check(name), false, cl));
        } catch (ClassNotFoundException ex) {
            return super.resolveClass(desc);
        }
    }
```

`ClassFilter.DEFAULT` 在同版本：

```java
// src/main/java/hudson/remoting/ClassFilter.java  (tag remoting-2.53)
    public static final ClassFilter DEFAULT = new ClassFilter() {
        @Override
        protected boolean isBlacklisted(String name) {
            if (name.startsWith("org.codehaus.groovy.runtime."))
                return true;
            if (name.startsWith("org.apache.commons.collections.functors."))
                return true;
            if (name.contains("org.apache.xalan"))
                return true;
            return false;
        }
    };
```

对 seed 这种外层直接点名 `...functors.PcbSeed` 的流，它确实够用：`filter.check(name)` 抛 `SecurityException: Rejected: org.apache.commons.collections.functors.PcbSeed`，构造函数 / `readObject` 都不跑，TCP 上回 `PCB_BLOCKED=...`，没有 flag。同一次 V1 上，不在黑名单里的 `PcbExpected` 仍能重建——黑名单是选择性的，不是 deny-all。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险类会以外层流里的 UTF 类名出现，而且名字落在那三个前缀/子串上。
2. 只要外层 `resolveClass` 拦了，就不会再有别的 `ObjectInputStream` 把同一个类读出来。

第二点不成立。JDK `java.security.SignedObject.getObject()` 的实现是对内部 `content` 字节数组 `new ObjectInputStream(...).readObject()`。那条流不是 `ObjectInputStreamEx`，没有 `ClassFilter`。2.53 的黑名单里也没有 `java.security.SignedObject` 自己。

---

## 检查之后，谁真正重建那个对象

外层 `readObject` 对 `SignedObject` 只做常规字段恢复：签名算法名、content 字节、签名字节。`resolveClass` 看见的名字是 `java.security.SignedObject`（以及 `String`、`byte[]` 等），**从不**看见内层 payload 的类名。

之后服务端（和 2017 年 CLI 一样）调用 `getObject()`。OpenJDK 的实现逻辑是：

```text
SignedObject.getObject():
    new ObjectInputStream(new ByteArrayInputStream(this.content)).readObject()
```

（推断自 JDK 源码与 SECURITY-429 advisory 原文 *deserialized using a new ObjectInputStream*；本分析未在本机反编译 rt.jar。）

内层流的 `resolveClass` 是 `ObjectInputStream` 默认实现：`Class.forName`，无 ClassFilter。于是 `PcbSeed` 被完整加载，`readObject` 读 `/canary/flag.txt`。flag 出现在 TCP echo 里，依据就是这次**嵌套、未过滤**的重建，而不是外层流里碰巧带了 flag 字符串——client 序列化的 PcbSeed 字段是空的。

签名不验证也能 `getObject()`：client 现场生成一次性 RSA 密钥对把 PcbSeed 包进去即可。过滤器刚看过的是外层类名；内层 open 看到的是另一条流。

---

## 仓库里已经有更强的检查，嵌套流没用上

`ClassFilter` 本身是可插的：三参数构造函数允许传入任意 filter。CLI 路径用的是 `ClassFilter.DEFAULT`。问题不在「没有过滤器类型」，而在 **只有 `ObjectInputStreamEx` 这一层会调用它**。

谁过 ClassFilter：

| 路径 | 调用 `ClassFilter.check`？ |
|---|---|
| `ObjectInputStreamEx.resolveClass`（外层 CLI 流） | 是 |
| `SignedObject.getObject()` 内部的 `new ObjectInputStream` | **否** |
| 任何其它自己 `new ObjectInputStream` 的 JDK 类 | **否** |

2.53 源码里已经把已知 gadget 家族按名字写死了。`java.security.SignedObject` 是 JDK 自己的类，不在那三个前缀里。维护者当时要拦的是「网上点名 InvokerTransformer」；没有把「能再开一条流的包装类」算进同一张表。

即便不用 SignedObject，任何 `readObject` 里自己构造 `ObjectInputStream` 的类都有同一形状。2017 年的修复选择是把 `SignedObject` 加进黑名单，而不是给所有嵌套流套上同一个 filter。JEP-200 后来改成 allowlist，那是再下一层。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「外层 check vs 内层 open」落到具体类名：

```text
seed 外层类名:
  org.apache.commons.collections.functors.PcbSeed
  V1 ClassFilter: startsWith("...functors.") → Rejected
  readObject 不跑

residual 外层类名:
  java.security.SignedObject
  V1 ClassFilter: 三个前缀都不中 → 放行
  然后 getObject() 内层类名:
    org.apache.commons.collections.functors.PcbSeed
    普通 ObjectInputStream → Class.forName → readObject 跑
```

token 变换：危险类名从「外层 UTF」挪到「SignedObject.content 里的嵌套流」。外层过滤器的匹配语言是 `desc.getName()`；内层根本不经过这段代码。seed 被挡住只说明「外层不能再点名 functors.*」，不说明「functors.* 不能再被重建」。

---

## 残余仍然走同一条 CLI ObjectInputStreamEx（CVE-2017-1000353）

没有换端口、没有换 `ObjectInputStreamEx`、没有换 PcbSeed。还是同一条 TCP：

```text
mode=signed  →  client 发送 SignedObject(PcbSeed)
服务端：ObjectInputStreamEx.readObject → SignedObject
       → getObject() → 内层 PcbSeed.readObject → echo PCB_SEED_FLAG
```

held-out 把 candidate 写死为 `mode=signed`。官方 PoC 形状与 FoxGlove / 2017 公开利用相同，本 case 把 gadget 换成良性读文件。认证记录：v1 + residual TCP 上回 `PCB_SEED_FLAG=... outer=java.security.SignedObject inner=...functors.PcbSeed`。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：黑名单只看外层类名；真正跑 gadget `readObject` 的是另一条未包装的流；包装类自己不在 2.53 表里。seed 被挡住只说明「直接点名 functors 没了」。

---

## 后来又补了什么（CVE-2017-1000353，remoting 3.16）

[2017-04-26 advisory](https://www.jenkins.io/security/advisory/2017-04-26/) SECURITY-429：*SignedObject has been added to the remoting blocklist*。Jenkins core commit `36b8285a` 先 `ClassFilter.appendDefaultFilter(Pattern.compile("java[.]security[.]SignedObject"))`。remoting jar **自己的** `ClassFilter.DEFAULT` 带上 `"^java[.]security[.]SignedObject$"` 是 3.16（JEP-200 整理），所以本 case V2 钉 3.16 而不是 2.53.x。

```text
// remoting-3.16 ClassFilter.DEFAULT（regex Matcher#matches）
    "^org[.]codehaus[.]groovy[.]runtime[.].*",
    "^org[.]apache[.]commons[.]collections[.]functors[.].*",   // 仍挡直接 PcbSeed
    ".*org[.]apache[.]xalan.*",
    ...
    "^java[.]security[.]SignedObject$"                         // 新增：挡包装
```

对残余输入：外层 `resolveClass` 在 `getObject()` 之前就 `Rejected: java.security.SignedObject`，内层流不创建。直接 seed 仍被 functors 规则挡住。公开建议还要求关掉 remoting-based CLI，改用 HTTP/SSH CLI。

即便如此，这仍然是「再加一个包装类名」，不是「嵌套 `ObjectInputStream` 必须带同一 filter」。对 SignedObject 这条已知链它够用。本 benchmark 的 v2 只关闭这一条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是外层 `resolveClass` 的名字表。真正执行危险 `readObject` 的是 JDK 包装类开的第二条流。V2 仍在同一张表加一行，没有把 filter 推进 `ObjectInputStream` 的构造。

**不是没有更好的谓词。**  
`ClassFilter.check` 已经能拒绝任意名字。它只挂在 `ObjectInputStreamEx` 上。从 V1 的 diff 只能看到「resolveClass 外包了 check」；要判断补丁是否闭合，必须看到哪些 JDK 类会再 `new ObjectInputStream`，以及 DEFAULT 表里有没有那些包装类。

**同一 sink、同一 PcbSeed，只换了线结构。**  
直接发送被拒、包进 SignedObject 就过——这是 case.json 在同一条 V1 TCP 服务上观察到的差分。

**黑名单按「网上已知 gadget 名字」写，不按「能再反序列化」的能力写。**  
functors / groovy / xalan 是 2015 年的公开 payload。SignedObject 是 JDK 里合法的签名容器，直到有人用它当隧道才进表。

**金丝雀在树外、且只在 readObject 时读是有意的。**  
线上没有 flag。能 echo 出 `PCBFLAG_...`，说明服务端真的重建了 PcbSeed。

---

## 版本、入口、参考

| | remoting | `resolveClass` | 直接 PcbSeed seed | SignedObject 包一层 residual |
|---|---|---|---|---|
| V0 | 2.52 | 裸 `Class.forName` | TCP echo flag | （不必） |
| V1 | 2.53 | `ClassFilter.DEFAULT`，无 SignedObject | `Rejected: ...functors.PcbSeed` | echo flag，outer=SignedObject |
| V2 | 3.16 | DEFAULT 含 `^java[.]security[.]SignedObject$` | 挡 | `Rejected: java.security.SignedObject` |

- 触发：外部 TCP client → 服务 `ObjectInputStreamEx(in, cl)`（CLI `Command#readFrom` 形态）
- 认证记录（case.json）：v0 seed 观察到 flag；v1 seed 未观察到；v1 residual 观察到；v2 residual 未观察到。
- [CVE-2015-8103](https://nvd.nist.gov/vuln/detail/CVE-2015-8103) / [SECURITY-218 2015-11-11](https://www.jenkins.io/security/advisory/2015-11-11/)
- [CVE-2017-1000353](https://nvd.nist.gov/vuln/detail/CVE-2017-1000353) / [SECURITY-429 2017-04-26](https://www.jenkins.io/security/advisory/2017-04-26/)
- V1 源码：[tag remoting-2.53 `ObjectInputStreamEx.java`](https://github.com/jenkinsci/remoting/blob/remoting-2.53/src/main/java/hudson/remoting/ObjectInputStreamEx.java)、[`ClassFilter.java`](https://github.com/jenkinsci/remoting/blob/remoting-2.53/src/main/java/hudson/remoting/ClassFilter.java)
- V2 core 侧：[commit `36b8285a`](https://github.com/jenkinsci/jenkins/commit/36b8285a41eb28333549e8d851f81fd80a184076) *Fixing by blacklisting SignedObject*
- JEP-200 后续把 denylist 换成 allowlist：https://github.com/jenkinsci/jep/tree/master/jep/200
