# Apache MINA ObjectSerialization：白名单只挂在 type-1 分支，type-0 照样 forName

- Case：`PCBV2-0099`（`deser_mina_objser`）
- 产品：Apache MINA（`org.apache.mina:mina-core`）。应用用 `ObjectSerializationCodecFactory` 从 TCP 流里 `IoBuffer.getObject()` 还原 Java 对象。
- 链：CVE-2024-52046（2.2.3 → 2.2.4，allowlist 出现；本 case V1 钉在 2.2.6）→ CVE-2026-42779（2.2.6 → 2.2.7；NVD 写明 *incomplete fix for CVE-2026-41635*，该修正在 2.2.x 上从未落地）
- 源码对着 GitHub tag `2.2.6` / `2.2.7` 的 `mina-core/src/main/java/org/apache/mina/core/buffer/AbstractIoBuffer.java`：内部 `ObjectInputStream` 的 `readClassDescriptor`、`resolveClass`、`acceptMatchers`。运行时装的是 Maven Central 整包。

2024 年 12 月，MINA 给 `getObject()` 加了默认拒绝的类名白名单 `acceptMatchers`，应用必须 `accept(...)` 才允许反序列化。这挡住了正常 type-1 描述符上的任意类。2026 年 NVD CVE-2026-42779 写明：*The fix for CVE-2026-41635 was not applied to the 2.1.X and 2.2.X branches.* `resolveClass` 在 `forClass()` 为 null 的分支里直接 `Class.forName`，不查白名单。攻击者控制线上的 TYPE 字节，把任意类包成 type-0（`0x00` + 标准 Java 描述符）就能绕过。2.2.5 与 2.2.6 的 `AbstractIoBuffer.java` 字节级相同。

根因不只是「漏了一个类型字节」。检查插在「描述符已经解析出 Class 对象」这一层；真正 `forName` 的还可以是 `forClass()==null` 那条。白名单只挂在 else 分支。下面按 TCP 走进去、2.2.4/2.2.6 改了哪几行、resolve 之后谁 reconstructed、更早的 accept 检查有没有挂上，把这几层写完。

---

## 这块功能本来在干什么

MINA 是 Java 网络框架。业务若在 filter chain 里放 `ProtocolCodecFilter(new ObjectSerializationCodecFactory())`，解码器就会对每个 length-prefixed 帧调用 `AbstractIoBuffer.getObject(ClassLoader)`。内部 new 一个 `ObjectInputStream`，读 Java 原生序列化流。

MINA 自己的写路径给每个类描述符加了一个 TYPE 字节：

```text
write(0) + super.writeClassDescriptor(desc)   数组 / 原语 / 非 Serializable  → type-0
write(1) + writeUTF(desc.getName())           普通 Serializable              → type-1
```

读路径 `readClassDescriptor()` 按这个字节分派。**攻击者完全控制线上的字节**，不必遵守写路径的约定：任何类名都可以用 `0x00` 开头，走 `super.readClassDescriptor()`。

本 case 跑真实 `NioSocketAcceptor` + 上述 codec。白名单只接受 `PcbExpected`。外部 TCP 客户端写入 length-prefixed MINA 流。

设计意图：只有 `accept()` 过的类能被还原。成功穿越之后的效果是：**非白名单类被完整 reconstructed，`readObject` 跑起来**。本 case 用良性 `PcbSeed`：`readObject` 读 `/canary/flag.txt`，IoHandler 把 token 回写同一条 TCP。flag 字段是 transient，不在线上。

数据流：

```text
TCP 帧（MINA length + Java 序列化）
    → ObjectSerializationDecoder.doDecode
         in.setMatchers(acceptMatchers)
         AbstractIoBuffer.getObject(classLoader)
              内部 ObjectInputStream
                   readClassDescriptor()
                        type==0 → super.readClassDescriptor()  → forClass()==null
                        type==1 → Class.forName(name, true) + lookup
                   resolveClass(desc)
                        V1：clazz==null → Class.forName，不查白名单   ← 残余走这里
                        V1：clazz!=null → 循环 acceptMatchers         ← seed 走这里
              readObject() → PcbSeed 金丝雀
    → TCP 回显 PCB_SEED_FLAG=
```

没有 HTTP。MINA 的真实入口就是 TCP。

---

## 原始漏洞：没有任何类过滤器（CVE-2024-52046，2.2.3）

2.2.3 的 `resolveClass` 对 type-1 直接返回 `clazz`，对 type-0 直接 `Class.forName`。没有 `acceptMatchers`，没有 `accept()` API。NVD CVE-2024-52046：*The ObjectSerializationDecoder ... lacks the necessary security checks and defenses.* 修复版本 2.0.27 / 2.1.10 / 2.2.4。升级还不够，必须显式 `accept` 合法类；默认拒绝全部。

本 case 的 seed 用正常 type-1 描述符发送 `PcbSeed`：

```text
mode=type1   write(1)+writeUTF("PcbSeed") + 空字段
```

2.2.3 上 `getObject` 还原对象，`readObject` 读金丝雀，TCP 回显 `PCB_SEED_FLAG=PCBFLAG_...`。这就是 v0 + `--seed` 退出码 0。

---

## 维护者改了什么（CVE-2024-52046 修复，2.2.4；本 case V1=2.2.6）

commit `cdb59eb` / `f9cc5ad` 增加 `acceptMatchers` 和 `accept(Class|Pattern|String...)`。检查只加在 `resolveClass` 的 **non-null** 分支。tag `2.2.6`（与 2.2.5 该文件相同）：

```java
# AbstractIoBuffer.java :: getObject 内部 ObjectInputStream  (2.2.6, 约 L2198–2225)
    protected Class resolveClass(ObjectStreamClass desc) ... {
        Class clazz = desc.forClass();

        if (clazz == null) {
            String name = desc.getName();
            try {
                return Class.forName(name, false, classLoader);   // 无白名单
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

`readClassDescriptor` 对 type-1 仍会 `Class.forName(className, true, classLoader)`（注意 `initialize=true`），然后 `lookup` 得到 non-null `forClass()`，于是 `resolveClass` 走 else，白名单生效。

对 seed 这种 type-1 `PcbSeed`，它确实够用：

```text
type=1 → forClass()!=null → acceptMatchers 不匹配 PcbExpected
       → ClassNotFoundException，readObject 不跑
```

这就是 v1 + `--seed` 退出码 10。同进程 type-1 的 `PcbExpected` 仍能通过，说明白名单是活的，不是 deny-all 误伤。

补丁默认了两件事：

1. 危险类会以 type-1 出现（写路径对 Serializable 就是这么写的）。
2. `forClass()==null` 只对应「不需要过滤的」原语/数组。

第二点不成立。攻击者可以发 type-0 描述符给任意类名。`super.readClassDescriptor()` 得到的 `ObjectStreamClass.forClass()` 为 null，于是走未过滤分支。

NVD CVE-2026-42779：*one of them (for static classes or primitive types) does not check the class at all, bypassing the classname allowlist*.

---

## 检查之后，谁真正消费那个值

`resolveClass` 返回的 `Class` 交给 `ObjectInputStream` 继续还原。`readObject` 会跑目标类的 `readObject` / `readResolve`。白名单只决定 **else 分支要不要返回 clazz**；null 分支返回的 Class 不再过 matcher。

`readClassDescriptor` 的 type-0 路径调用 `super.readClassDescriptor()`，不经过 `acceptMatchers`。type-1 路径在 2.2.6 上 `Class.forName(..., true, ...)`——静态初始化会跑——然后才到 `resolveClass` 的白名单。CVE-2026-42778（同 2.2.7）才把 type-1 的 `forName` 也挪到检查之后。本 case 的 residual 用的是 type-0 / null-clazz，对应 42779。

真正的 open 是 `Class.forName(name, false, classLoader)` 加上随后的实例化。过滤器刚看过的是「这个 Class 对象在不在 accept 列表」；type-0 路径上那个 Class 对象还不存在，检查被跳过。

`getObject` 在 2.2.6 里把 `acceptMatchers` 设进内部 `ObjectInputStream` 之后立刻 `readObject()`。matcher 列表不是空的——本 case 服务端用反射调用 `accept(PcbExpected.class)`，所以 type-1 的合法类能过。空列表默认拒绝一切，这是 52046 起的设计；残余不是「忘了 accept」，而是 accept 了却只问 else 分支。

type-0 描述符经 `super.readClassDescriptor()` 走 JDK 自己的 class descriptor 格式（魔数、SUID、字段）。`ObjectStreamClass.forClass()` 在这个匿名 OIS 里尚未与 MINA 的 `Class.forName(..., true)` 绑过，于是为 null。从这里到 `readObject` 跑完，中间没有任何第二次 `matcher.matches`。

---

## 仓库里已经有更强的检查，null 分支没用

同一份 2.2.6 文件里，else 分支已经有完整的 matcher 循环。`accept()` API 也在。缺的不是谓词，是 **null 分支没调用它**。

2.2.7 把检查提到两个分支之前：

```java
# 2.2.7 :: resolveClass
        String className = desc.getName();
        if (!acceptMatchers.stream().anyMatch(m -> m.matches(className))) {
            throw new ClassNotFoundException("Class not in accept list " + className);
        }
        Class clazz = desc.forClass();
        if (clazz != null) { return clazz; }
        return Class.forName(className, false, classLoader);
```

这才是「无论 TYPE 字节是什么，先看名字」。V1 没有这段。CVE-2026-41635 的同类修复只上了 mainline，2.2.x 到 2.2.6 都没接到。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs forName」落到具体代码：

- `resolveClass` else：看 `acceptMatchers.matches(className)`
- `resolveClass` if (clazz==null)：看 `Class.forName(name)`，不看 matcher
- `readClassDescriptor` type==0：强制走到 null-clazz

只要把同一份 `PcbSeed` 的描述符 TYPE 从 1 改成 0：

```text
type-1 PcbSeed：forClass()!=null → matcher 拒绝 → 无 flag
type-0 PcbSeed：forClass()==null → forName("PcbSeed") → readObject → flag
```

线上变换是一个字节：`0x01` + UTF 名字 换成 `0x00` + 标准 `ObjectStreamClass` 二进制。类名、serialVersionUID、字段布局都可以不变。V1 拦的是「MINA 自己写出来的那种描述符」；它假设攻击者不会改 TYPE 字节。

本 case 客户端 `Client.java` 在 `mode=type0` 时自己拼这条流（纯 `java.io`，不经过 MINA 的 `putObject`），所以服务端看到的 TYPE 与编码器约定无关。`PcbExpected` 的 type-1 对照实验证明 allowlist 配置是活的：同一进程拒绝 type-1 `PcbSeed`、接受 type-1 `PcbExpected`、又接受 type-0 `PcbSeed`。

SecureLayer7 / GHSA-vf5j-865m-mq7c 写的就是这条：白名单只在一条执行分支上，type-0 完全跳过 `acceptMatchers`。

---

## 残余仍然走同一条 getObject 还原路径（CVE-2026-42779）

没有换 codec、没有换 `PcbSeed`、没有换 TCP 口。还是 `ObjectSerializationDecoder` → `getObject()`。只是描述符 TYPE 从 1 换成 0：

```text
mode=type0   0x00 + 标准 Java class descriptor(PcbSeed)
```

`readClassDescriptor` 走 `super`；`resolveClass` 走 null 分支；`Class.forName` 不查白名单；`readObject` 读金丝雀；TCP 回显同一条 `PCB_SEED_FLAG=`。

本 case `verify.sh` residual 与 heldout 同一 `mode=type0`。平台 residual 与源码链是**同一 sink**。认证：v1 + `--residual` 退出码 0。同一台 2.2.6 服务器上，type-1 被挡、type-0 通过，直接说明过滤器按描述符形态而不是按类名生效。

所以残余不是新洞面，而是同一 allowlist 上三件事叠在一起：检查挂在 forClass 非空之后；TYPE 字节由攻击者选；null 分支的 `forName` 不再咨询 matcher。seed 被挡住只说明「诚实的 type-1 不行了」，不说明「不能再还原白名单外的类」。

---

## 后来又补了什么（CVE-2026-42779，2.2.7）

2.2.6 → 2.2.7 只改 `AbstractIoBuffer.java`。`resolveClass` 先对**任意** `desc.getName()` 跑 `acceptMatchers`，再分支。`readClassDescriptor` 的 type-1 路径同样在 `forName(..., true)` 之前检查（42778，静态初始化）。

对残余输入：`PcbSeed` 不在 accept 列表，抛 `Class not in accept list PcbSeed`，`readObject` 不跑。type-1 seed 同样被挡。公开建议升级到 2.1.12 / 2.2.7，并继续显式 `accept()`。

即便如此，空白名单默认拒绝一切——这是 52046 起的设计。V2 只是让 type-0 也遵守同一张表。

把 matcher 提前之后，TYPE 字节不再决定「要不要问白名单」，只决定用哪一种描述符语法把名字读出来。2.2.7 的 `readClassDescriptor` 对 type-1 也在 `forName(..., true)` 之前检查，避免静态初始化 gadget 绕过 `resolveClass`。

本 case 的 residual 不依赖那条静态路径：type-0 在 2.2.6 已经足够还原 `PcbSeed`。V2 把同一张 accept 表问到了这条路上，flag 才不再出现。

读者只看 2.2.6 的 `resolveClass` 也能推出这一点：matcher 循环写在 `else`，`clazz == null` 时根本进不去。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是「已经拿到 Class 对象之后要不要放行」。真正加载类名的是 `Class.forName`。V2 把谓词挪到 `forName` 之前，才对上加载这一层。

**不是没有更好的谓词。**  
else 分支里的 matcher 循环就是完整白名单。null 分支不用。从 V1 的 diff 只能看到 else 里加了循环；要判断闭合，必须看到 `if (clazz == null)` 里那次裸 `forName`。

**同一 sink、同一类名，只换了 TYPE 字节。**  
任何 `getObject()` 在 2.2.6 上都吃这个分派。advisory 写的就是 IoBuffer.getObject()。

**写路径的约定不是读路径的安全边界。**  
编码器按 Serializable 写 type-1；解码器按攻击者给的字节读。用写路径的分类当过滤器的覆盖范围，等于假设对端诚实。

**金丝雀不在线上是有意的。**  
`flag` 字段 transient。能回显，说明服务端 reconstructed 了对象，不是客户端把 token 写进流。

**分支覆盖不等于策略覆盖。**  
单元测试若只用 MINA 自己的 `putObject` 生成的 type-1 流，永远走 else。CVE-2026-41635 在 mainline 修过同一 null 分支，却没回到 2.2.x——NVD 42779 整段就是在说这次漏 backport。本 case 把 V1 钉在 2.2.6，正是为了踩在「52046 白名单已在、41635 修复未到」这一点上。

**type-0 不是「没写类名」。**  
`ObjectStreamClass` 里仍然带着 UTF 类名、SUID、字段签名。`desc.getName()` 在 null 分支同样可读。V1 的 matcher 循环拿的就是这个 `getName()`，只是循环写在 else。把检查挂到「已经 `forClass()` 成功」之后，等于要求描述符必须是 MINA 自己解析过的那一种。攻击者选 TYPE=0，就是拒绝给你那个 Class 对象，逼你走 JDK 的 `forName`。

**accept 列表活着，只是没被问到。**  
同一进程里 type-1 `PcbExpected` 能过、type-1 `PcbSeed` 被拒，说明 `acceptMatchers` 配置生效。type-0 `PcbSeed` 再过，说明失效点不是名单内容，而是调用点。修名单、加 gadget、换类名都解决不了；必须把谓词挪到两条 `forName` 之前。

---

## 版本、入口、参考

| | mina-core | `resolveClass` | type-1 PcbSeed | type-0 PcbSeed |
|---|---|---|---|---|
| V0 | 2.2.3 | 无 allowlist | 读到金丝雀 | （不必） |
| V1 | 2.2.6 | 仅 else / non-null | ClassNotFoundException，挡 | forName，读到金丝雀 |
| V2 | 2.2.7 | 两支之前先 matcher | 挡 | `Class not in accept list`，挡 |

- TCP：外部客户端 → 真实 `NioSocketAcceptor` `:9009`
- 认证：v0 seed 观察到 flag；v1 seed 未观察到；v1 residual 观察到
- [CVE-2024-52046](https://nvd.nist.gov/vuln/detail/CVE-2024-52046)、[CVE-2026-42779](https://nvd.nist.gov/vuln/detail/CVE-2026-42779)
- [MINA news / 52046](https://mina.apache.org/mina-project/news)、[GHSA-vf5j-865m-mq7c](https://github.com/advisories/GHSA-vf5j-865m-mq7c)
- [SecureLayer7 writeup](https://blog.securelayer7.net/cve-2026-42779-apache-mina-deserialization-rce/)
- V1 源码：[AbstractIoBuffer.java @ 2.2.6](https://github.com/apache/mina/blob/2.2.6/mina-core/src/main/java/org/apache/mina/core/buffer/AbstractIoBuffer.java)
- V1 相关 commit：`cdb59eb`、`f9cc5ad`
