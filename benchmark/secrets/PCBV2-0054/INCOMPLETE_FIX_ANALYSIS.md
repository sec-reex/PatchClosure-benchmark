# Dubbo：Hessian2 白名单只罩住 id=2，帧头换成 native-hessian 就绕开

- Case：`PCBV2-0054`
- 产品：Apache Dubbo（Java RPC）。本 case 跑真实 Provider（`org.apache.dubbo:dubbo` 整包）监听 `dubbo://:20880`，独立 client 容器经 TCP 发帧；序列化 id 由 consumer URL 的 `serialization=` 写入帧头。
- 链：CVE-2020-1948（2.7.6 → 2.7.8，hessian-lite 3.2.8 `ClassFactory` 白名单，`-Ddubbo.application.hessian2.whitelist=true`）→ CVE-2021-25641 / GHSL-2021-035（2.7.12 + `-Dserialization.security.check=true`，`CodecSupport.checkSerialization`）
- 源码对着 GitHub tag `dubbo-2.7.8` 的 `CodecSupport.getSerialization`、`WhitelistHessian2FactoryInitializer`、`native-hession` 的 `Hessian2ObjectInput`；V2 对着 `dubbo-2.7.12` 的 `checkSerialization`。hessian-lite `ClassFactory.load` 引自 case `patch.diff` 对 3.2.8 jar 的摘录（raw blob 404，**quoted from case materials**）。

Dubbo 协议帧头里有一个 serialization id。Provider 默认 hessian2（id 2）。CVE-2020-1948 给 **hessian-lite** 加了类型白名单：不在名单里的类换成 `HashMap`，不实例化。GHSL-2021-034_043 原文：*`native-hessian` is similar to `hessian2` but does not support allowlists, so even in the case that the developers would set an allowlist for `hessian2`, attackers would still be able to change the protocol to `native-hessian` and evade it.*

根因不只是「漏了一个序列化实现」。检查插在 hessian2 的 `ClassFactory`；真正 `readObject` 的实现由**帧头那个字节**挑选。下面按 TCP 走进去、2.7.8 改了哪条 SPI、decode 之后谁实例化参数类、更强的「网络 id 必须等于服务配置 id」有没有挂上，把这几层写完。

---

## 这块功能本来在干什么

Dubbo Provider 导出一个服务，consumer 用 `dubbo://host:20880` 直连。帧格式以 magic `0xdabb` 开头，flags 里带着 serialization id。`DubboCodec.decodeBody` → `DecodeableRpcInvocation.decode` 按这个 id 取 `Serialization`，再反序列化参数。

本 case 的金丝雀是 benign 类 `com.pcb.PcbFlagProbe`：无参构造 / `readResolve` 读 `/canary/flag.txt`，把 `PCB_PROVIDER_FLAG=<token>` 打到 **Provider** 日志。它不在 `java.*` 里。成功穿越之后的效果是：**参数反序列化真的 new 了这个类**。没有登录。判断完全信任「hessian2 白名单开了就不能实例化任意类」，不信任客户端还能换一个没有 ClassFactory 的 Hessian 实现。

数据流：

```text
client TCP（serialization=hessian2 | native-hessian）
    → 帧头 serialization id = 2 或 10
    → CodecSupport.getSerialization(url, id)
         V1：只对 java/nativejava/compactedjava 核对 id 与配置
         id 10 直接放行
    → Serialization.deserialize → 参数 readObject
         id 2：hessian-lite ClassFactory
              whitelist=true → 非 java.* 变 HashMap
         id 10：com.caucho.hessian Hessian2Input
              Hessian2SerializerFactory.INSTANCE，无 ClassFactory
    → PcbFlagProbe 构造 → Provider 日志出现 flag
```

Provider 配置始终是默认 hessian2。攻击者不改服务端配置，只改自己发出去的那一个字节。

---

## 原始漏洞：hessian2 没有类型白名单（CVE-2020-1948，Dubbo 2.7.6）

2.7.6 带 hessian-lite 3.2.6。`patch.diff` 记：jar 里 **没有** `ClassFactory.class`。hessian2 参数流里写类名 `com.pcb.PcbFlagProbe`，`Class.forName` + 实例化，构造器读金丝雀。这就是 v0 + `--seed` 退出码 0。

公开讨论在 Dubbo #6364 / PR #6378。修法是给 hessian-lite 加 `ClassFactory`，并用系统属性选择 whitelist SPI。

---

## 维护者改了什么（CVE-2020-1948 修复，2.7.8）

hessian-lite 3.2.8 的 `ClassFactory.load`（case `patch.diff` 对 jar 的摘录）：

```java
// dubbo-hessian-lite v3.2.8  ClassFactory.java :: load
public Class<?> load(String className) throws ClassNotFoundException {
    if (isAllow(className)) { return Class.forName(className, false, _loader); }
    else { log.log(Level.SEVERE, className + " in blacklist or not in whitelist, "
                   + "deserialization  with type 'HashMap' instead."); return HashMap.class; }
}
```

默认 `allowList == null` 时 `isAllow` 返回 true（opt-in）。静态名单在 whitelist 模式下只放行 `java\\..+`。Dubbo 侧 tag `dubbo-2.7.8` 的选择器（`Hessian2FactoryInitializer`）：

```java
@SPI("default")
public interface Hessian2FactoryInitializer {
    String WHITELIST = "dubbo.application.hessian2.whitelist";
    String ALLOW = "dubbo.application.hessian2.allow";
    String DENY = "dubbo.application.hessian2.deny";

    static Hessian2FactoryInitializer getInstance() {
        String whitelist = ConfigurationUtils.getProperty(WHITELIST);
        if (StringUtils.isNotEmpty(whitelist)) {
            return loader.getExtension("whitelist");
        }
        return loader.getDefaultExtension();
    }
}
```

`WhitelistHessian2FactoryInitializer.createSerializerFactory`（同一 tag）：

```java
public SerializerFactory createSerializerFactory() {
    SerializerFactory serializerFactory = new Hessian2SerializerFactory();
    String whiteList = ConfigurationUtils.getProperty(WHITELIST);
    if ("true".equals(whiteList)) {
        serializerFactory.getClassFactory().setWhitelist(true);
        String allowPattern = ConfigurationUtils.getProperty(ALLOW);
        if (StringUtils.isNotEmpty(allowPattern)) {
            serializerFactory.getClassFactory().allow(allowPattern);
        }
    } else {
        serializerFactory.getClassFactory().setWhitelist(false);
        // deny pattern ...
    }
    return serializerFactory;
}
```

本 case V1 打开 `-Ddubbo.application.hessian2.whitelist=true`。seed 用 hessian2（id 2）送 `PcbFlagProbe`：`isAllow` 失败，变成 `HashMap`，构造器不跑，Provider 日志没有 flag。这就是 v1 + `--seed` 退出码 10。

同一版本的 `CodecSupport.getSerialization(URL, Byte id)`（`dubbo-remoting-api`，**observed** 于 tag `dubbo-2.7.8`）：

```java
public static Serialization getSerialization(URL url, Byte id) throws IOException {
    Serialization serialization = getSerializationById(id);
    String serializationName = url.getParameter(Constants.SERIALIZATION_KEY,
            Constants.DEFAULT_REMOTING_SERIALIZATION);
    // Check if "serialization id" passed from network matches the id on this side
    // (only take effect for JDK serialization), for security purpose.
    if (serialization == null
            || ((id == JAVA_SERIALIZATION_ID || id == NATIVE_JAVA_SERIALIZATION_ID
                    || id == COMPACTED_JAVA_SERIALIZATION_ID)
                && !(serializationName.equals(ID_SERIALIZATIONNAME_MAP.get(id))))) {
        throw new IOException("Unexpected serialization id:" + id
                + " received from network, please check if the peer send the right id.");
    }
    return serialization;
}
```

注释写得很清楚：**只对 JDK 序列化**核对网络 id。id 10（native-hessian）不在这三个常量里，有实现就直接返回。

补丁默认了两件事：

1. 危险反序列化走 hessian2，所以给 hessian2 加白名单就够。
2. 客户端不会（或不能）把帧头换成别的 Hessian。

第二点不成立。协议把选择权放在帧头；`getSerialization` 对非 JDK id 照单全收。

对照 advisory：NVD CVE-2021-25641 / GHSA-v2rg 把「客户端自选 serialization id」写成 *before 2.7.8*，并举例 Kryo/FST。2.7.8 实际只卡住了 java 三兄弟。native-hessian / Kryo / FST 在 2.7.8 上仍可切换。本 case 的 V1 是「hessian2 白名单已开」的 2.7.8；残余按 GHSL-2021-035 走 native-hessian。分析以 tag 源码为准。

---

## 消毒之后，参数对象在哪被 new 出来

V1 的 `ClassFactory` 只挂在 **com.alibaba.com.caucho.hessian**（hessian-lite）这条工厂上。native-hessian 模块的 `Hessian2ObjectInput`（tag `dubbo-2.7.8`，注意目录名拼写 `native-hession`）：

```java
package org.apache.dubbo.serialize.hessian;

import com.caucho.hessian.io.Hessian2Input;
// ...
public Hessian2ObjectInput(InputStream is) {
    input = new Hessian2Input(is);
    input.setSerializerFactory(Hessian2SerializerFactory.INSTANCE);
}
```

`com.caucho.hessian.io.Hessian2Input` 是另一份 Hessian，工厂是 `Hessian2SerializerFactory.INSTANCE`，**没有** hessian-lite 的 `ClassFactory`。`readObject` 按流里的类名直接加载、实例化。

过滤器刚看过的是「hessian2 路径上这个类名在不在白名单」；id 10 的消费者根本不问那张表。flag 能出现在 Provider 日志里，依据就是 `PcbFlagProbe` 的构造器在 Provider JVM 里跑了，而不是「日志碰巧有同类字符串」。

client 容器设 `-Dpcb.role=client`，本进程里即便也 new 了同类也保持沉默。oracle 只读 Provider 日志。

---

## 仓库里已经有「核对 serialization id」的想法，却只罩了 JDK

`getSerialization` 的注释和三个 `JAVA_*_SERIALIZATION_ID` 说明维护者知道：**网络 id 不能由客户端随便指定**。他们把这个谓词做成「仅 JDK」。GHSL 列出的 id 表里，hessian2=2、native-hessian=10、kryo=8、fst=9 都不走那三个分支。

谁在反序列化之前被问到：

| 位置 | 2.7.8 做什么 | id=10 过得去吗 |
|---|---|---|
| hessian-lite `ClassFactory` | whitelist 时非 java.* → HashMap | **不问，根本不在这条路上** |
| `WhitelistHessian2FactoryInitializer` | 只给 hessian2 SPI 用 | 否，native-hessian 不用它 |
| `CodecSupport.getSerialization` | 仅 JDK id 核对配置 | **是，直接 return** |
| `checkSerialization` | **不存在** | — |

不是没有「别让客户端换序列化器」这个想法。是 **谓词只挂在 JDK 三个 id 上，白名单只挂在 hessian-lite 上**。从 V1 的 diff 只能看到 `ClassFactory` + whitelist SPI；要判断补丁是否闭合，必须看到帧头仍由客户端选 id，以及 native-hessian 用的是 `com.caucho.hessian`。

即便没有 native-hessian 这个模块，只要 classpath 上还有 Kryo/FST 等弱实现，2.7.8 的 `getSerialization` 同样放行。本 case 显式带上 `dubbo-serialization-native-hession`，把 GHSL 那句「similar to hessian2 but does not support allowlists」落到可观测的构造器。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「hessian2 ClassFactory vs 帧头 id vs native Hessian」落到具体变换。

- `ClassFactory.load`：看 hessian-lite 要不要把类名换成 HashMap
- `getSerialization(url, id)`：看帧头字节选哪套 `ObjectInput`
- native-hessian `readObject`：看 `com.caucho.hessian` 是否实例化

seed（id 2）：

```text
serialization=hessian2，参数类型 com.pcb.PcbFlagProbe
V0 3.2.6：无 ClassFactory → new PcbFlagProbe → 日志有 flag
V1 3.2.8 + whitelist=true：变成 HashMap → 无 flag
```

held-out residual：

```text
serialization=native-hessian   # 帧头 id=10
同一 PcbFlagProbe 流

V1 getSerialization：id 10 不是 JAVA_* → 放行
Hessian2ObjectInput：无 ClassFactory → new PcbFlagProbe → 日志有 flag
```

V1 改的是 hessian2 工厂；id 10 这条链里根本没有 `ClassFactory.load` 可调用。白名单在 `readObject` 之前运行——如果根本没走进 hessian-lite，白名单等于没挂。

---

## 残余仍然走同一条 RPC 参数反序列化路径（CVE-2021-25641 / GHSL-2021-035）

没有换 magic、没有换 decode 入口、没有换 `PcbFlagProbe` 这个效果通道。还是：

```text
dubbo://provider:20880?serialization=native-hessian
```

`DecodeableRpcInvocation.decode` 仍然按帧头 id 取 Serialization，再读参数。V1 的 hessian2 白名单照样开着；这条帧根本不进 hessian-lite。构造器读 `/canary/flag.txt`，Provider 日志出现 token。

本 case residual 写死为 native-hessian id 10 + 同一 probe 类。和 GHSL 原文同一构造。认证意图：v1 + `--residual` 在 Provider 日志观察到 flag。`patch.diff` / repro.log 记 V2 抛 `Unexpected serialization id:10`（**observed**）。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：白名单绑死在一个实现上；协议把实现选择权留给帧头；2.7.8 的 id 核对故意不包括 Hessian。seed 被挡住只说明「hessian2 不再 new 非 java.*」，不说明「不能再让 Provider 实例化那个类」。

NVD 把 CVE-2021-25641 的 affected 写成 `< 2.7.8`，说的是「任意换弱反序列化器」那一层；2.7.8 只部分关上 JDK。完整的「网络 id 必须等于导出 URL 上配置的 id」要到 2.7.9+ 的 `checkSerialization`，本 case V2 钉在 2.7.12 并打开 `serialization.security.check`。

---

## 后来又补了什么（2.7.12，`checkSerialization`）

tag `dubbo-2.7.12` 的 `CodecSupport.checkSerialization`：

```java
public static void checkSerialization(String path, String version, Byte id) throws IOException {
    ServiceRepository repository = ApplicationModel.getServiceRepository();
    ProviderModel providerModel = repository.lookupExportedServiceWithoutGroup(path + ":" + version);
    if (providerModel == null) {
        logger.warn("Serialization security check is enabled but cannot work as expected because "
                + "there's no matched provider model for path " + path + ", version " + version);
    } else {
        List urls = providerModel.getServiceConfig().getExportedUrls();
        if (CollectionUtils.isNotEmpty(urls)) {
            URL url = urls.get(0);
            String serializationName = url.getParameter(
                    Constants.SERIALIZATION_KEY, Constants.DEFAULT_REMOTING_SERIALIZATION);
            Byte localId = SERIALIZATIONNAME_ID_MAP.get(serializationName);
            if (localId != null && !localId.equals(id)) {
                throw new IOException("Unexpected serialization id:" + id
                        + " received from network, please check if the peer send the right id.");
            }
        }
    }
}
```

`DecodeableRpcInvocation` 在 `readObject` 参数之前，若 `serialization.security.check=true` 就调用它（case `patch.diff`，**observed**）。id 10 ≠ 配置的 hessian2 id 2，抛 IOException，probe 不会被实例化。阿里云 MSE 文档同样要求升到 2.7.12 并打开该开关。

即便如此，这仍是 opt-in；provider model 找不到时只打 warn。本 benchmark 的 v2 打开开关并导出真实服务，关闭这一条 native-hessian residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是 hessian2 能加载哪些类。真正 new 对象的是「帧头选中的那套 ObjectInput」。V2 才回到「网络 id 必须等于服务声明」。2.7.8 的 `ClassFactory` 看不见 id 10。

**不是没有 id 核对。**  
`getSerialization` 已经在对 JDK 做这件事，注释写了 security purpose。缺的是对所有 id 做同一件事。从 V1 只能看到 whitelist SPI；要判断补丁是否闭合，必须看到 native-hessian 的 `com.caucho.hessian` 和三个 JAVA_* 常量的白名单。

**同一 decode、同一 probe 类，只换了帧头一个字节。**  
任何 classpath 上存在、且不走 hessian-lite ClassFactory 的 Serialization 扩展，在 2.7.8 上都能绕开 CVE-2020-1948 的白名单。

**白名单默认关闭。**  
`ClassFactory` 在 `allowList == null` 时全放行；Dubbo 还要 `-Ddubbo.application.hessian2.whitelist=true` 才切到 whitelist SPI。本 case 把开关打开，仍然被换协议打穿——说明问题不在「忘了开开关」，而在「开关绑错了实现」。

---

## 版本、入口、参考

| | Dubbo | hessian2 白名单 | 网络 id 核对 | hessian2 seed | native-hessian residual |
|---|---|---|---|---|---|
| V0 | 2.7.6 / lite 3.2.6 | 无 ClassFactory | 无 | 实例化，日志有 flag | （不必） |
| V1 | 2.7.8 / lite 3.2.8 | opt-in ClassFactory | 仅 JDK 三 id | HashMap，挡 | id 10 实例化，有 flag |
| V2 | 2.7.12 | 仍在 | `checkSerialization`（需打开） | 挡 | `Unexpected serialization id:10`，挡 |

- 入口：TCP `dubbo://`，client 容器选 `serialization=`
- 认证意图：v0 seed Provider 日志有 flag；v1 seed 无；v1 residual 有。repro.log（**observed**）
- [CVE-2020-1948](https://nvd.nist.gov/vuln/detail/CVE-2020-1948)、[PR #6378 Hessian2 whitelist](https://github.com/apache/dubbo/pull/6378)
- [CVE-2021-25641](https://nvd.nist.gov/vuln/detail/CVE-2021-25641)、[GHSL-2021-034_043](https://securitylab.github.com/advisories/GHSL-2021-034_043-apache-dubbo/)、[GHSA-v2rg-8cwr-75g8](https://github.com/advisories/ghsa-v2rg-8cwr-75g8)
- 源码：[dubbo-2.7.8 CodecSupport.java](https://github.com/apache/dubbo/blob/dubbo-2.7.8/dubbo-remoting/dubbo-remoting-api/src/main/java/org/apache/dubbo/remoting/transport/CodecSupport.java)、[WhitelistHessian2FactoryInitializer.java](https://github.com/apache/dubbo/blob/dubbo-2.7.8/dubbo-serialization/dubbo-serialization-hessian2/src/main/java/org/apache/dubbo/common/serialize/hessian2/dubbo/WhitelistHessian2FactoryInitializer.java)、[Hessian2ObjectInput.java](https://github.com/apache/dubbo/blob/dubbo-2.7.8/dubbo-serialization/dubbo-serialization-native-hession/src/main/java/org/apache/dubbo/serialize/hessian/Hessian2ObjectInput.java)
- V2：[dubbo-2.7.12 CodecSupport.checkSerialization](https://github.com/apache/dubbo/blob/dubbo-2.7.12/dubbo-remoting/dubbo-remoting-api/src/main/java/org/apache/dubbo/remoting/transport/CodecSupport.java)
