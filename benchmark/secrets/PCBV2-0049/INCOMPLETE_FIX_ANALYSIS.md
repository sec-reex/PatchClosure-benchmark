# Apache MINA：allowlist 写在 resolveClass，静态块已经跑过了

- Case：`PCBV2-0049`
- 产品：Apache MINA（`org.apache.mina:mina-core`）。本 case 跑真实 `NioSocketAcceptor` + `ObjectSerializationCodecFactory` TCP 服务，外部 client 写长度前缀的 MINA 序列化流。
- 链：CVE-2024-52046（2.2.3 → 2.2.4，`acceptMatchers` 加进 `resolveClass`）→ CVE-2026-42778（2.2.4…2.2.6 → 2.2.7，把同一张表提前到 `Class.forName` 之前）
- 源码对着 GitHub tag `2.2.4` / `2.2.7` 的 `mina-core/.../AbstractIoBuffer.java`：`getObject(ClassLoader)` 里的匿名 `ObjectInputStream`、`readClassDescriptor`、`resolveClass`。运行时装的是 Maven Central 整包，不是抽出来的函数。

2024 年 12 月，MINA 给 `IoBuffer.getObject()` 加了一张默认拒绝的类名 allowlist，想挡住任意 Java 反序列化。NVD / oss-security CVE-2024-52046 写明：升级不够，还要用 `accept(...)` 显式放行。2026 年 Apache 自己承认：*The fix for CVE-2024-52046 in Apache MINA AbstractIoBuffer.getObject() was incomplete. The classname allowlist … was applied too late after a static initializer in a class to be read might already have been executed.* 这就是 CVE-2026-42778。

根因不只是「少拦了一个类」。检查插在 `resolveClass`；真正加载类名的是更早的 `readClassDescriptor`，而且 `Class.forName(name, true, cl)` 会跑静态初始化。下面按 TCP 走进去、2.2.4 改了哪一层、`forName` 之后谁消费那个 Class、同函数里有没有更早的挂钩点，把这几层写完。

---

## 这块功能本来在干什么

MINA 是 Java 网络框架。应用把 `ProtocolCodecFilter(new ObjectSerializationCodecFactory())` 挂到 filter chain 上之后，对端发来的长度前缀二进制会被 `ObjectSerializationDecoder.doDecode` 交给 `IoBuffer.getObject(classLoader)`，还原成 Java 对象再交给 `IoHandler.messageReceived`。

一次典型的 type-1（Serializable）帧：

```text
[4-byte length][type=1][UTF className][字段数据…]
```

本 case 的服务端只愿意反序列化业务类 `PcbExpected`。金丝雀写在容器树外 `/canary/flag.txt`。成功穿越之后的效果是：**解码路径在拒绝这个类之前，已经执行了攻击者指定类的代码，并把 flag 读进共享 Beacon**。seed 走 `readObject`；残余走静态初始化。两条通道共用同一个 `getObject` sink。

数据流：

```text
TCP 长度前缀流
    → ObjectSerializationDecoder.doDecode
         in.setMatchers(acceptMatchers)
         in.getObject(classLoader)
              匿名 ObjectInputStream.readObject()
                   V1：readClassDescriptor()          ← 先 Class.forName(name, true)
                        type==1: 读 UTF 类名
                        Class.forName(className, true, cl)   ← 静态块在这里跑
                        ObjectStreamClass.lookup(clazz)
                   然后 resolveClass()                ← 补丁插在这里
                        acceptMatchers 匹配类名
                        不匹配则 ClassNotFoundException
                   匹配才 newInstance / readObject
    → messageReceived 或 exceptionCaught 回显
```

没有 HTTP、没有登录。客户端完全控制线上海的类名。

---

## 原始漏洞：没有任何类过滤（CVE-2024-52046，mina-core 2.2.3）

2.2.3 的 `resolveClass` 在 `desc.forClass()` 非空时直接返回，没有 `acceptMatchers`，也没有 `accept()` API。`readClassDescriptor` 的 type-1 路径同样是无条件 `Class.forName(name, true)`。任意 classpath 上的 Serializable 类都能被还原。

本 case 的 seed 类是 `PcbSeed`：它**没有**读 flag 的静态块，只在 `readObject()` 里读 `/canary/flag.txt`。2.2.3 会完整重建对象，`messageReceived` 回显 `PCB_READOBJECT=<flag>`。这就是 v0 + `--seed` 退出码 0。

官方范围：只有调用了 `IoBuffer.getObject()`、并且 filter chain 里有 `ObjectSerializationCodecFactory` 的应用才受影响。FtpServer / SSHd / Vysper 子项目不走这条解码器。

---

## 维护者改了什么（CVE-2024-52046 修复，2.2.4）

2.2.4 在 `AbstractIoBuffer` 上加了 `acceptMatchers` 和三套 `accept(...)`，默认空表 = 拒绝一切。`ObjectSerializationDecoder.doDecode` 在 `getObject` 之前 `in.setMatchers(acceptMatchers)`。真正执法的位置是内部 `ObjectInputStream.resolveClass`（GitHub tag `2.2.4`，约 L2199–2226）：

```java
// AbstractIoBuffer.java :: getObject(ClassLoader) 内匿名 ObjectInputStream
// tag 2.2.4，约 L2199–2226
protected Class<?> resolveClass(ObjectStreamClass desc)
        throws IOException, ClassNotFoundException {
    Class<?> clazz = desc.forClass();

    if (clazz == null) {
        String name = desc.getName();
        try {
            return Class.forName(name, false, classLoader);  // 这条分支也不查表
        } catch (ClassNotFoundException ex) {
            return super.resolveClass(desc);
        }
    } else {
        boolean found = false;
        String className = desc.getName();
        for (ClassNameMatcher matcher : acceptMatchers) {
            if (matcher.matches(className)) { found = true; break; }
        }
        if (found) { return clazz; }
        throw new ClassNotFoundException();
    }
}
```

对 seed 这种「效果在 `readObject`」的类，它确实够用：`PcbSeed` 不在 `PcbExpected` 这张表上，`resolveClass` 抛 `ClassNotFoundException`，对象建不出来，`readObject` 不跑，TCP 上回的是 `PCB_ERR ClassNotFoundException`，`PCB_READOBJECT` 为空。这就是 v1 + `--seed` 退出码 10。本 case 用反射调 `accept(Pattern)`，所以同一份 `Server.java` 也能在没有该 API 的 2.2.3 上编译。

补丁默认了两件事：

1. 危险发生在「类被实例化 / `readObject` 被调用」这一层。
2. 只要 `resolveClass` 拒绝，解码路径上就不会再跑攻击者的代码。

第二点不成立。`resolveClass` 能看到的 `ObjectStreamClass`，是 `readClassDescriptor` 已经 `forName(..., true)` 之后才 lookup 出来的。

---

## 检查之后，谁真正消费那个类名

`getObject` 里同一个匿名 `ObjectInputStream` 先覆盖 `readClassDescriptor`。type-1（MINA 自己的 Serializable 描述符）在 2.2.4 上是这样（约 L2176–2191）：

```java
// AbstractIoBuffer.java :: readClassDescriptor  （紧挨在 resolveClass 前面）
protected ObjectStreamClass readClassDescriptor()
        throws IOException, ClassNotFoundException {
    int type = read();
    if (type < 0) { throw new EOFException(); }
    switch (type) {
        case 0: // NON-Serializable / Primitive
            return super.readClassDescriptor();
        case 1: // Serializable class
            String className = readUTF();
            Class<?> clazz = Class.forName(className, true, classLoader);
            return ObjectStreamClass.lookup(clazz);
        default:
            throw new StreamCorruptedException(
                "Unexpected class descriptor type: " + type);
    }
}
```

`Class.forName(String, boolean, ClassLoader)` 的第二个参数是 `initialize`。`true` 表示：类解析成功后立刻跑 `<clinit>`。JVM 规范里静态初始化发生在「首次主动使用」；`forName(..., true)` 就是一次主动使用。

于是时间线是：

```text
读 UTF 类名
    → Class.forName(name, true)     ← 静态块执行，Beacon 被写入
    → ObjectStreamClass.lookup
    → readObject 内部再调 resolveClass
         acceptMatchers 不匹配
         throw ClassNotFoundException
    → 对象没建成，readObject 没跑
    → exceptionCaught 仍能读到 Beacon
```

过滤器刚看过的是「这个类名在不在表里」；表是在 lookup **之后** 才问的。真正跑用户代码的是 `forName` 的 `initialize=true`。两套语义中间没有第二次「加载前」谓词。金丝雀能出现在 `PCB_STATICINIT=` 里，依据就是这一步，而不是「allowlist 没配好」。

本 case `PcbCanary` 的静态块只读文件、写 `Beacon.staticInitFlag`，没有 gadget、没有 `Runtime.exec`。服务端 `exceptionCaught` 把 Beacon 回显到同一条 TCP 连接上，所以残余仍然是外部网络触发、同一 sink。

---

## 仓库里已经有更早的挂钩点，2.2.4 没用

同一份 `getObject` 里，`readClassDescriptor` 在读完 UTF 类名之后、调用 `forName` 之前，手里已经有完整的 `className` 字符串。`acceptMatchers` 也已经作为字段存在，`accept()` API 已经能往里面填。2.2.4 选择把匹配循环写在 `resolveClass` 的 else 分支，而不是写在 `forName` 前面。

谁在什么时候看这张表：

| 挂钩点 | 调用 `acceptMatchers`？ | 此时 `<clinit>` 是否已跑？ |
|---|---|---|
| `readClassDescriptor` type-1，`forName` 之前 | **否**（2.2.4） | 尚未 |
| `readClassDescriptor` type-1，`forName` 之后 | 否 | **已经跑过** |
| `resolveClass`，`forClass() != null` | 是 | 已经跑过 |
| `resolveClass`，`forClass() == null` | **否**（另一条 CVE-2026-41635 / 42779 分支） | `forName(..., false)` 仍可能加载 |

不是没有表。是 **表挂在第一个会执行用户代码的调用之后**。从 V1 的 diff 只能看到 `resolveClass` 多了一个循环；要判断补丁是否闭合，必须看到 `readClassDescriptor` 里 `initialize=true` 的那一行，以及 Java 对 `forName` 的语义。

顺带：`resolveClass` 的 `clazz == null` 分支在 2.2.4 上也不查表。那是另一条「allowlist 被跳过」的洞（CVE-2026-41635 / CVE-2026-42779）。本 case 的残余不走那条，走的是 type-1 + 静态块。同一张表、同一个函数，两处都没在加载前问。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「resolveClass vs forName」落到具体变换。

- `resolveClass` + `acceptMatchers`：看类名字符串在不在表里，决定**要不要返回 Class 给实例化**
- `readClassDescriptor` 的 `Class.forName(name, true)`：看能不能**解析并初始化**这个类
- `PcbSeed.readObject`：只有实例化成功才读 flag
- `PcbCanary.<clinit>`：只要 `forName(..., true)` 成功就读 flag

seed 输入（正常 MINA type-1，类名 `PcbSeed`）：

```text
className: PcbSeed
forName(true):  加载，无静态 flag
resolveClass:   不在表 → ClassNotFoundException
readObject:     不跑
回显:           PCB_READOBJECT=（空）  PCB_STATICINIT=（空）
```

残余只换类名，帧格式不变：

```text
className: PcbCanary
forName(true):  跑 static { read /canary/flag.txt → Beacon }
resolveClass:   不在表 → ClassNotFoundException（和 seed 同一个异常）
readObject:     不跑
回显:           PCB_READOBJECT=（空）  PCB_STATICINIT=<FLAG>
```

V1 改的是「实例化前的类名匹配」；`PcbCanary` 的效果根本不需要实例化。allowlist 认为自己挡住了这个类，实际上它刚让 JVM 把这个类初始化完，然后才拒绝。

Apache 新闻页原话：*An allow-list of classes was added … but it was applied too late for classes that have a static initializer which get executed even for not allowed classes.*

---

## 残余仍然走同一条 getObject 解码路径（CVE-2026-42778）

没有换 codec、没有换 TCP 口、没有换 `accept()` 配置。还是：

```text
client mode=canary  →  type-1 描述符，类名 PcbCanary
```

`doDecode` 仍然 `setMatchers` 再 `getObject`。V1 的 `resolveClass` 循环照样执行；执行完之后类已经被初始化，Beacon 非空，`exceptionCaught` 把 `PCB_STATICINIT=<flag>` 写回 TCP。

本 case residual 写死为：

```text
mode = "canary"     # 外部 client 发送 PcbCanary
```

和 advisory 描述的「静态初始化在 allowlist 之前」同一构造，只是把任意危险 `<clinit>` 换成读金丝雀。认证意图：v1 + `--residual` 在 client 收到的字节里观察到 `PCBFLAG_...`（通道名 `PCB_STATICINIT`）。dossier / case.json 记的是一次真实 Docker gate 上 `bypass@v1` 带 flag、`original@v1` 不带 flag——**observed**（平台 gate），不是推断。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：allowlist 插在 `resolveClass`；`readClassDescriptor` 用 `initialize=true` 加载线上海的类名；应用把拒绝异常当成「已经安全」，却仍能从静态副作用里读到效果。seed 被挡住只说明「`readObject` 不再跑」，不说明「解析类名不会执行代码」。

静态初始化对每个 ClassLoader 只跑一次。oracle 对每个 `(version, class)` 只探一次新鲜 JVM，这和 MINA 生产里「这个类第一次出现在流上」一致。

---

## 后来又补了什么（CVE-2026-42778，2.2.7）

2.2.7 把匹配循环挪到 `forName` **之前**，`resolveClass` 也改成无论 `forClass()` 是否为 null 都先查表（GitHub tag `2.2.7`）：

```java
// AbstractIoBuffer.java :: readClassDescriptor  type-1  （2.2.7）
String className = readUTF();

// Only accept classes that are listed as acceptable
// Apply class filter BEFORE calling Class.forName
if (!acceptMatchers.stream().anyMatch(m -> m.matches(className))) {
    throw new ClassNotFoundException("Class not in accept list " + className);
}

// 注释写 initialize=false，下一行实际仍是 true —— 但表已经先问过了
Class<?> clazz = Class.forName(className, true, classLoader);
return ObjectStreamClass.lookup(clazz);
```

对残余输入：

```text
className: PcbCanary
表匹配:    否 → ClassNotFoundException: Class not in accept list PcbCanary
forName:   不执行
静态块:    不跑
回显:      PCB_STATICINIT=（空）
```

公开建议是升级到 2.1.12 / 2.2.7。NVD 把 2.1.x/2.2.x 上这次补丁记成「CVE-2026-41409 没合到这两条分支」，描述正文仍是 52046 的不完整修复。即便 2.2.7 先查表，`forName` 仍传 `initialize=true`（注释和代码不一致，**observed**）。对「不在表上的类」这条已知链它够用；在表上的类仍会在 lookup 时初始化——那是 allowlist 的本意。

本 benchmark 的 v2 只关闭这一条 static-init residual。2.2.5 / 2.2.6 仍开放。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是 `resolveClass` 要不要把 Class 交给实例化。真正让残余生效的是 `readClassDescriptor` 里那次带初始化的加载。V2 才回到 `forName` 之前。2.2.4 的 diff 里看不到 `readClassDescriptor` 的变动。

**不是没有类名字符串。**  
`readUTF()` 之后立刻就有 `className`。缺的是「加载前问表」。从 V1 的 diff 只能看到 `acceptMatchers` 循环；要判断补丁是否闭合，必须看到 `Class.forName(..., true)` 和 Java 静态初始化时机。

**同一函数、同一帧格式，只换了类名。**  
任何把用户可控类名送进 MINA type-1 描述符的客户端，在 2.2.4 上都吃同一次 `forName(true)`。seed 用 `PcbSeed` 是因为要证明 `readObject` 通道已被挡住；残余用 `PcbCanary` 是因为效果提前到了 `<clinit>`。

**拒绝异常不等于没有副作用。**  
`ClassNotFoundException` 出现在静态块之后。应用若只看「解码失败」，会误以为 allowlist 已经工作。本 case 故意把两条通道拆开：同一 v1 进程上 `PcbSeed` 的 `PCB_READOBJECT` 为空，`PcbCanary` 的 `PCB_STATICINIT` 有 flag。

**`initialize=true` 是显式选择。**  
`resolveClass` 的 null 分支用的是 `forName(name, false, cl)`。type-1 路径却用 `true`。V2 注释想改成 `false`，代码没改；闭合靠的是「先查表」，不是「禁止初始化」。

---

## 版本、入口、参考

| | mina-core | `readClassDescriptor` type-1 | `resolveClass` | `PcbSeed` seed | `PcbCanary` residual |
|---|---|---|---|---|---|
| V0 | 2.2.3 | `forName(name, true)`，无表 | 无条件返回 | `PCB_READOBJECT=flag` | （不必） |
| V1 | 2.2.4 | 同上，仍不查表 | else 分支查 `acceptMatchers` | `ClassNotFoundException`，无 flag | 静态块先跑，`PCB_STATICINIT=flag` |
| V2 | 2.2.7 | **先**查表再 `forName` | 两条分支都先查表 | 挡 | 挡，静态块不跑 |

- TCP：外部 client → `NioSocketAcceptor` :9009，`ObjectSerializationCodecFactory`
- 认证意图：v0 seed 观察到 `PCB_READOBJECT` 中的 flag；v1 seed 无；v1 residual 观察到 `PCB_STATICINIT` 中的 flag。dossier 记一次 Docker gate 为 passed（**observed**）。
- [CVE-2024-52046](https://nvd.nist.gov/vuln/detail/CVE-2024-52046)、[oss-security 公告](https://www.openwall.com/lists/oss-security/2024/12/25/1)
- [CVE-2026-42778](https://nvd.nist.gov/vuln/detail/CVE-2026-42778)、[Apache MINA 新闻](https://mina.apache.org/mina-project/news)
- 源码：[2.2.4 AbstractIoBuffer.java](https://github.com/apache/mina/blob/2.2.4/mina-core/src/main/java/org/apache/mina/core/buffer/AbstractIoBuffer.java)、[2.2.7 同文件](https://github.com/apache/mina/blob/2.2.7/mina-core/src/main/java/org/apache/mina/core/buffer/AbstractIoBuffer.java)
- 后续同函数上的分支遗漏：[CVE-2026-41635](https://github.com/advisories/GHSA-8297-v2rf-2p32)（`forClass()==null` 不查表）
