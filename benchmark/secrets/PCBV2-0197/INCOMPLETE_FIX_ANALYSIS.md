# Spring：22259 让 userinfo 吃掉 `@`，反斜杠仍能把 authority 在浏览器里截断

- Case：`PCBV2-0197`
- 产品：Spring Framework `spring-web`（Maven Central `org.springframework:spring-web`）。运行时是整包 JAR + 薄 `Driver.java` 调 `UriComponentsBuilder.fromUriString(url).build().getHost()`，再交给 Node WHATWG `URL` 做真实导航。不是抽出来的函数。
- 链：CVE-2024-22259（6.1.4 → 6.1.5）→ CVE-2024-22262（6.1.5 → 6.1.6）。再往前是 CVE-2024-22243（本仓库 PCBV2-0198 的 seed）。spring.io 对 22262 的原话：*This is the same as CVE-2024-22259 and CVE-2024-22243, but with different input.*
- 源码对着 tag `v6.1.5` 的 `spring-web/.../UriComponentsBuilder.java`（`USERINFO_PATTERN` / `HOST_IPV4_PATTERN` / `SCHEME_PATTERN` / `checkSchemeAndHost`）。金丝雀只活在内网 sidecar `sidecar.internal` 的响应体里。

根因不只是「又漏了一个字符」。检查插在「正则拆出来的 host 是不是 allow-list」上；真正发请求的是后面那次 WHATWG 导航。同一次 6.1.5 已经加了 `checkSchemeAndHost`，却只判断「http(s) 且 host 为空」，authority 字符类里仍然没有 `\`。下面按调用走进去。

---

## 这块功能本来在干什么

应用用 Spring 解析用户给的 URL，取出 host，和 `{trusted.internal}` 比对，通过才去拉这个 URL。这是 spring.io 三条 advisory 共同描述的模式。本 case 的 driver 只做前半段：

```java
// Driver.java —— 调的是未改过的库 API
host = UriComponentsBuilder.fromUriString(url).build().getHost();
```

后半段是 Node `new URL(input).hostname` + 真实 HTTP GET。flag 只在 `sidecar.internal` 上。设计意图：`getHost()` 报谁，导航就该去谁；allow-list 挡住 sidecar。成功穿越之后的效果是：**`getHost()` 报 `trusted.internal`，浏览器/WHATWG 却去 `sidecar.internal`，body 里出现 `PCBFLAG_...`**。

数据流：

```text
url = http://sidecar.internal\@trusted.internal
    → UriComponentsBuilder.fromUriString
         URI_PATTERN 吃 USERINFO / HOST
         V1：USERINFO = ([^/?#]*)   ← 已允许 @，仍允许 \
         checkSchemeAndHost         ← 只拦「http 且 host 空」
         build().getHost()
    → 应用：host == trusted.internal ? 放行
    → WHATWG：\ 当 /，authority 在 sidecar.internal 结束
    → GET http://sidecar.internal/  → PCBFLAG_...
```

这是库 API。没有 HTTP 路由、没有登录。消费方是「谁在 `getHost()` 之后用**原始字符串**去导航」。Driver 只打印 `SPRING_HOST=`；外层 `nav.js` 用 Node `new URL(input).hostname` 做 WHATWG 等价解析，再对解析出的主机发真实 GET。flag 只在 `sidecar.internal` 的响应体里，Driver / Spring 源码 / nav.js 都不含这个字符串。

---

## 原始漏洞：前导 `@` + `[` 截断 host（CVE-2024-22259，6.1.4）

6.1.4 的 userinfo 还不能跨 `@`，IPv4 host 还不能跨 `[`（22243 修过 userinfo 里的 `[`，但 5.3 线和 6.1 线的落点不同；6.1.4 已是 22243 之后、22259 之前）。seed 是 22259 自己的那条输入：

```text
http://@trusted.internal[@sidecar.internal
```

`(userinfo@)?` 吃掉开头那个空 userinfo（第一个 `@`），扫描停在 `trusted.internal[`。`HOST_IPV4 = [^\[/?#:]*` 在 `[` 处停，`getHost()` = `trusted.internal`。WHATWG 按最后一个 `@` 切 userinfo，导航去 `sidecar.internal`。guard 放行，sidecar 回 flag。这就是 v0 + `--seed` 观察到 flag。

---

## 维护者改了什么（CVE-2024-22259 修复，6.1.5）

6.1.5 让 userinfo 可以含 `@`，让 IPv4 host 可以含 `[`，并抽出 `checkSchemeAndHost`。对着 tag `v6.1.5`：

```java
// UriComponentsBuilder  (spring-framework v6.1.5)
private static final String SCHEME_PATTERN = "([^:/?#]+):";
private static final String USERINFO_PATTERN = "([^/?#]*)";
private static final String HOST_IPV4_PATTERN = "[^/?#:]*";
private static final String PORT_PATTERN = "(\\{[^}]+\\}?|[^/?#]*)";

public static UriComponentsBuilder fromUriString(String uri) {
  Matcher matcher = URI_PATTERN.matcher(uri);
  if (matcher.matches()) {
    // ...
    checkSchemeAndHost(uri, scheme, host);
    builder.userInfo(userInfo);
    builder.host(host);
  }
}

private static void checkSchemeAndHost(String uri, String scheme, String host) {
  if (StringUtils.hasLength(scheme) && scheme.startsWith("http")
      && !StringUtils.hasLength(host)) {
    throw new IllegalArgumentException("[" + uri + "] is not a valid HTTP URL");
  }
}
```

V1 谓词的字面意思：

| 片段 | 6.1.5 行为 |
|---|---|
| `USERINFO = ([^/?#]*)` | 一直吃到 `/` `?` `#`，**包括 `@` 和 `\`** |
| `HOST_IPV4 = [^/?#:]*` | 一直吃到 `/` `?` `#` `:`，**包括 `\`** |
| `SCHEME = ([^:/?#]+):` | scheme 里不能有 `/` `?` `#`，**可以有 `\`** |
| `checkSchemeAndHost` | 只拒绝「scheme 像 http 且 host 为空」 |

对 seed：userinfo 变成 `@trusted.internal[`（吃到最后一个 `@` 之前的全部），host 变成 `sidecar.internal`。allow-list 失败，不导航。这就是 v1 + `--seed` 退出码 10。

6.1.4 → 6.1.5 相对 5.3.32 → 5.3.33 是同一语义在 6.1 线上的落点：userinfo 不再以 `@` 为界，host 不再以 `[` 为界。本 case 的 V0 已经是 22243 之后，所以 seed 用的是 22259 那条「前导 `@` + `[`」，不是 0198 的 `trusted[@attacker`。字符类演进必须按 6.1.4/5/6 三份源码读，不能把 5.3.32 的常量抄过来当 V1。

补丁默认了两件事：

1. 危险分隔符是 `@` 和 `[`（22243/22259 已经见过的那两个）。
2. 正则拆出的 authority 和浏览器拆出的 authority 从此对齐。

第二点不成立。WHATWG 对 special scheme（http/https）把 `\` 当成 `/`，authority 在第一个 `\` 结束。Spring 的字符类把 `\` 当普通 userinfo/host 字符。

---

## 消毒之后，host 怎么接到导航上

`fromUriString` 一结束，`build().getHost()` 返回的就是正则捕获组。Driver 把它打印成 `SPRING_HOST=...`。外层脚本：**仅当**这个值 ∈ `{trusted.internal}` 才用**原始 url 字符串**做 WHATWG 导航。

没有第二次解析，没有 `java.net.URI`，没有「导航 host 必须等于 `getHost()`」。过滤器刚看过的是「`([^/?#]*)` 从最后一个 `@` 往左、host 类从那里往右」；消费者看到的是「浏览器把 `\` 当 `/` 之后的 hostname」。

```text
输入:  http://sidecar.internal\@trusted.internal

Spring 6.1.5:
  USERINFO 贪婪吃到最后一个 @  → sidecar.internal\
  HOST                        → trusted.internal
  getHost()                   → trusted.internal   （allow-list 过）

WHATWG:
  \ 视为 /  → 等价 http://sidecar.internal/@trusted.internal
  hostname  → sidecar.internal
  GET sidecar.internal → PCBFLAG_...
```

`(userinfo@)?` 绑的是**最后一个** `@`。反斜杠不结束 userinfo，所以 Spring 把 sidecar 整段当成 userinfo，把 allow-list 主机当成 host。浏览器正好相反：反斜杠先结束 authority，后面的 `@trusted.internal` 变成路径。

`fromUriString` 用的是整条 `URI_PATTERN`：

```text
^(SCHEME)? (// (USERINFO @)? HOST (:PORT)? )? PATH (?QUERY)? (#FRAG)?
```

6.1.5 的 `USERINFO` / `HOST` / `SCHEME` / `PORT` 四处都还能吃 `\`。residual 只打了 userinfo 这一处，但同一字符类漏洞在 host、甚至 scheme 上 theoretically 也能让捕获组和 WHATWG 再分叉。V2 四处一起排除，就是承认「漏一个类就够再出一条 CVE」。

`checkSchemeAndHost` 在 `fromUriString`、`fromHttpUrl`、`fromOriginHeader` 三处调用。V1 的实现只看「scheme 以 http 开头且 host 为空」。`http://sidecar.internal\@trusted.internal` 的 host 捕获组非空，这个钩子整段不进。它本可以成为「解析结果必须像导航结果」的第二道谓词，V1 写成了空 host 哨兵。

---

## 仓库里已经有更强的检查，字符类没用

同一份 `UriComponentsBuilder` 里刚加的 `checkSchemeAndHost` 本可以成为「解析结果必须像一个真的 HTTP URL」的钩子。V1 只写了空 host。

`java.net.URI` / `java.net.URL` 以及 JDK 的 WHATWG 实现（更高版本）都在 classpath 附近。应用自己也可以用导航侧的 parser 做 allow-list，而不是用 Spring 的 RFC 3986 近似正则。

谁在用哪种 host：

| 位置 | 用什么当 host |
|---|---|
| `getHost()`（应用 guard） | Spring 正则捕获组 |
| 浏览器 / `new URL()` / `fetch` | WHATWG，`\` = `/` |
| `checkSchemeAndHost`（V1） | 只看「空不空」，不看 `\` |

V1 等于在正则层修了 `@`/`[`，而「authority 终结符必须和浏览器一致」这个更强谓词要到 6.1.6 才写进字符类。不是没有第二道检查，是 **checkSchemeAndHost 没用上反斜杠**。

即便没有 `\`，只要字符类和 WHATWG 的 special-scheme 集合再差一个（例如以后的 Unicode 斜杠），`getHost()` 和导航还会再分叉。V2 只是把这一个已知差集补进排除表。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs 导航」落到具体代码：

- V1 `USERINFO = ([^/?#]*)` + 最后一次 `@`：看 Spring 眼里谁是 host
- WHATWG special scheme：看 `\` 会不会先切开 authority

只要构造一种输入，使「最后一个 `@` 右边」是 allow-list 主机，而「第一个 `\` 左边」是 sidecar，第一行会放行，第二行仍然打到 sidecar。

```text
seed (22259):     http://@trusted.internal[@sidecar.internal
                  V0 getHost=trusted.internal  → 导航 sidecar → flag
                  V1 getHost=sidecar.internal  → 挡

residual (22262): http://sidecar.internal\@trusted.internal
                  V1 getHost=trusted.internal  → 导航 sidecar → flag
                  V2 getHost=sidecar.internal（\ 进了排除类，匹配失败/host 翻面）→ 挡
```

两条输入的主机顺序相反、分隔符不同（`[` vs `\`）。V1 上 seed 已被挡住、residual 仍过，这是 runtime 可分开的两条链，不是同一 payload 换了个编码。

---

## 残余仍然走同一个 getHost() 再导航（CVE-2024-22262）

没有换 API、没有换 allow-list、没有换 sidecar。还是：

```text
UriComponentsBuilder.fromUriString(url).build().getHost()
  == "trusted.internal"
    → WHATWG GET(url)
```

V1 那几行字符类照样执行；执行完之后 `\` 仍在 userinfo 里；`getHost()` 仍报 `trusted.internal`；导航仍去 sidecar。flag 仍在 sidecar body 里出现。

spring.io CVE-2024-22262：*Applications that use UriComponentsBuilder to parse an externally provided URL and perform validation checks on the host of the parsed URL may be vulnerable to open redirect / SSRF. This is the same as CVE-2024-22259, but with different input.*

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：正则字符类比 WHATWG 窄；导航用的是检查之前的原始字符串；`checkSchemeAndHost` 没有把 `\` 当成非法 authority。seed 被挡住只说明「前导 `@`+`[` 没了」，不说明「不能再让 getHost() 和导航分叉」。

---

## 后来又补了什么（CVE-2024-22262，6.1.6）

6.1.6 把 `\` 加进 SCHEME / USERINFO / HOST_IPV4 / PORT 的排除类（construction 记录的唯一 getHost 相关改动）：

```text
SCHEME_PATTERN:    ([^:/?#]+):     → ([^:/?#\\]+):
USERINFO_PATTERN:  ([^/?#]*)       → ([^/?#\\]*)
HOST_IPV4_PATTERN: [^/?#:]*        → [^/?#:\\]*
```

对残余输入，`\` 不再待在 userinfo 里。匹配要么失败，要么 host 不再是 `trusted.internal`。allow-list 拒绝，sidecar 不会被 GET。公开建议是升级到 6.1.6 / 6.0.19 / 5.3.34。

即便如此，这仍然是「在同一套 RFC 近似正则上再减一个字符」，没有改成用 WHATWG 做 allow-list。对 `\` 这条已知链它够用；若还有其它 Spring 当 host、浏览器当路径的字符，需要另证。本 benchmark 的 v2 只关闭这一条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是 userinfo/host 的排除字符。真正走到 sidecar 的是 WHATWG 导航。V2 仍在同一层加码，没有把 guard 换成「用导航 parser 取 host」。

**不是没有更好的谓词。**  
`checkSchemeAndHost` 已经挂在 `fromUriString` 上。它可以拒绝 host 里的 `\`，或拒绝「解析 host ≠ 用同一字符串再 parse 一次的 host」。V1 只写了空 host。从 6.1.5 的 diff 只能看到 `@`/`[`；要判断补丁是否闭合，必须看到 WHATWG 对 `\` 的 special-scheme 规则。

**同一 `getHost()`，只换了分隔符和主机顺序。**  
任何「`fromUriString` + 检查 host + 用原串导航」的应用，在 6.1.5 上都吃这套字符类。advisory 已把 22243/22259/22262 写成同一模式的三次输入。

**allow-list 信任的是解析器，不是字节。**  
`trusted.internal` 出现在字符串里并不等于它是导航目标。金丝雀只活在 sidecar 上：能读到它，说明导航越过了 guard，不是「trusted.internal 自己回了 flag」。

**和 PCBV2-0198 的差必须写清。**  
0198 的 V2 是 5.3.33 = 22259 修复，也就是本 case 的 V0/V1 边界在 5.3 线上的对应物。本 case 跑 6.1.4/6.1.5/6.1.6，seed 是 22259、residual 是 22262。不要把 `@trusted[@sidecar` 和 `sidecar\@trusted` 写成同一条 payload 的两种编码。

---

## 版本、入口、参考

| | Maven | userinfo / host 字符类 | `http://@trusted[@sidecar` seed | `http://sidecar\@trusted` residual |
|---|---|---|---|---|
| V0 | 6.1.4 | userinfo 不含 `@`；host 遇 `[` 停 | getHost=trusted → flag | （也能分叉） |
| V1 | 6.1.5 | userinfo 含 `@`；host 含 `[`；仍含 `\` | getHost=sidecar → 挡 | getHost=trusted → flag |
| V2 | 6.1.6 | 上述类再排除 `\` | 挡 | 挡 |

- 库 API：`UriComponentsBuilder.fromUriString(url).build().getHost()`
- 消费：WHATWG 导航到 allow-list 通过的**原串**
- 认证语义：v0 seed 观察到 flag；v1 seed 未观察到；v1 residual 观察到。
- [CVE-2024-22259](https://spring.io/security/cve-2024-22259)、[NVD CVE-2024-22259](https://nvd.nist.gov/vuln/detail/CVE-2024-22259)
- [CVE-2024-22262](https://spring.io/security/cve-2024-22262)、[NVD CVE-2024-22262](https://nvd.nist.gov/vuln/detail/CVE-2024-22262)
- 前序：[CVE-2024-22243](https://spring.io/security/cve-2024-22243)（PCBV2-0198）
- V1 blob：[`UriComponentsBuilder.java` @ v6.1.5](https://github.com/spring-projects/spring-framework/blob/v6.1.5/spring-web/src/main/java/org/springframework/web/util/UriComponentsBuilder.java)
- V2 对照：tag `v6.1.6` 同一文件
