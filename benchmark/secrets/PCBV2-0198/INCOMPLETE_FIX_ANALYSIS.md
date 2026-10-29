# Spring：22243 只从 userinfo 拿掉 `[`，前导 `@` 仍能让 getHost 报错主机

- Case：`PCBV2-0198`
- 产品：Spring Framework `spring-web`（Maven Central）。运行时是整包 JAR + `Harness.java`：`GET /redirect?url=` → `fromUriString(url).build().getHost()` 对 `trusted.internal` allow-list → 302 `Location: <原串>`。不是抽出来的函数。
- 链：CVE-2024-22243（5.3.31 → 5.3.32，commit `7ec5c994`）→ CVE-2024-22259（5.3.32 → 5.3.33，commit `297cbae2`）。spring.io 对 22259 的原话：*This is the same as CVE-2024-22243, but with different input.*
- 源码对着 tag `v5.3.32` 的 `spring-web/.../UriComponentsBuilder.java`。金丝雀骑在 redirect URL 的 query 上：allow-list 通过才会进 `Location`。

根因不只是「正则少排除了一个字符」。检查插在「捕获组里的 host 是否等于 `trusted.internal`」上；真正让浏览器离开源站的是后面原样写出的 `Location`。V1 修了 userinfo 里的 `[`，却把 `@` 留在 userinfo 类里、把 `[` 留在 `HOST_IPV4` 类里。下面按请求走进去。

---

## 这块功能本来在干什么

应用校验用户提供的跳转 URL：用 Spring 解析，看 host，通过就把**同一条字符串**放进 `Location`。这是三条 UriComponentsBuilder advisory 共同针对的模式。本 case 写成一条 HTTP 面：

```http
GET /redirect?url=http://trusted.internal/
```

```java
// Harness.java :: approveRedirect
UriComponents uc = UriComponentsBuilder.fromUriString(url).build();
parsedHost = uc.getHost();
if (parsedHost != null && parsedHost.equals("trusted.internal")) {
  return url; // 302 Location: <url>
}
return null;  // 403，不回显 url
```

设计意图：只有跳到 `trusted.internal` 才 302。成功穿越之后的效果是：**`getHost()` 报 `trusted.internal`，浏览器按最后一个 `@` 把 userinfo 切掉，实际去 `attacker.test`，`Location` 的 query 里带着 `PCBFLAG_...`**。

数据流：

```text
GET /redirect?url=http://trusted.internal[@attacker.test/?<FLAG>
    → URLDecoder
    → fromUriString + build + getHost     ← V1 谓词是这里的正则
    → host==trusted.internal ?
         是 → 302 Location: <原串>
         否 → 403 blocked（body 不回显 url）
    → 浏览器：最后一个 @ 之前都是 userinfo → host=attacker.test
```

没有登录。flag 不进应用代码，只在被批准的 `Location` 里出现。`/host` 调试面只打印 `getHost=`，不发 `Location`，不带 flag；观测通道是 `/redirect` 的响应头。

Harness 依赖的 `UriComponentsBuilder` 来自 `spring-web:${SPRING_VER}`，三个镜像的 Java 源码字节级相同，唯一变量是 JAR。这是库 CVE 的产品用法：应用按 advisory 描述的模式消费 `getHost()`，不是把正则抽出来单测。

---

## 原始漏洞：`[` 截断 userinfo，host 停在 allow-list（CVE-2024-22243，5.3.31）

5.3.31 的 userinfo 类是 `([^@\[/?#]*)`：既不能跨 `@`，也不能跨 `[`。seed：

```text
http://trusted.internal[@attacker.test/?<FLAG>
```

userinfo 在 `[` 处停（还没看见 `@`），host 捕获 `trusted.internal`，`[` 后面整段被当成「别的东西」。浏览器按 RFC / WHATWG 把最后一个 `@` 之前当作 userinfo，host 是 `attacker.test`。Harness 302，`Location` 带着 flag，浏览器离开源站。这就是 v0 + `--seed` 观察到 flag。

---

## 维护者改了什么（CVE-2024-22243 修复，5.3.32）

commit `7ec5c994`（*Update user info pattern*）只从 userinfo 类里拿掉 `[`。对着 tag `v5.3.32`：

```java
// UriComponentsBuilder  (spring-framework v5.3.32)
private static final String USERINFO_PATTERN = "([^@/?#]*)";   // 不再排除 [
private static final String HOST_IPV4_PATTERN = "[^\\[/?#:]*"; // 仍排除 [
```

V1 谓词的字面意思：

| 片段 | 5.3.32 |
|---|---|
| `USERINFO = ([^@/?#]*)` | 吃到 `@` `/` `?` `#`，**可以含 `[`** |
| `HOST_IPV4 = [^\[/?#:]*` | 吃到 `[` `/` `?` `#` `:`，**`[` 仍是 host 终结符** |
| `(userinfo@)?` | userinfo 组仍以 `@` 结尾，**不能含 `@`** |

对 seed：userinfo 现在能跨过 `[`，吃到 `trusted.internal[`，`@` 触发组结束，host 变成 `attacker.test`。allow-list 失败，403，`Location` 里没有 flag。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险分隔符就是 userinfo 里的 `[`（Sean Pesce 报的那条）。
2. 只要 userinfo 能跨 `[`，`getHost()` 和浏览器就对齐了。

第二点不成立。host 类仍然在 `[` 处停；userinfo 仍然不能含 `@`。换一种「空 userinfo + `[` 截断 host」的写法，捕获组会再次把 allow-list 主机当成 host。

---

## 消毒之后，host 怎么接到 Location 上

`getHost()` 返回捕获组。Harness **不做**规范化、不换 parser、不比较「再 parse 一次」。通过则：

```java
ex.getResponseHeaders().add("Location", approved); // approved == 原始 url
```

过滤器刚看过的是「`([^@/?#]*)` 和 `[^\[/?#:]*` 切出来的 host」；消费者（浏览器）看到的是 `Location` 里那条**未改过的**字符串。两套语义中间没有第二次谓词。

5.3.32 还没有 6.1.5 那份 `checkSchemeAndHost`。authority 是否像一个真的 HTTP URL，没有额外钩子。`fromUriString` 对 `URI_PATTERN` 一次 `matcher.matches()`，捕获组直接进 `builder.userInfo` / `builder.host`。没有「再 parse 一遍比对」、没有把 host 丢给 `java.net.URI`。

把 seed 和 residual 的捕获组并排写出来（5.3.32）：

```text
URI_PATTERN:
  ^(SCHEME)? (// (USERINFO @)? HOST (:PORT)? )? PATH (?QUERY)? (#FRAG)?

seed    http://trusted.internal[@attacker.test/?FLAG
  USERINFO = ([^@/?#]*)  →  trusted.internal[     （能跨 [，停在 @）
  HOST     = [^\[/?#:]*  →  attacker.test
  getHost() = attacker.test     → 403

residual http://@trusted.internal[@attacker.test/?FLAG
  (USERINFO @)? 先吃掉开头的空 userinfo（第一个 @）
  扫描从 trusted.internal[ 重启
  USERINFO 不再匹配（下一个 @ 之前已经不是「userinfo@」的位置）
  HOST = [^\[/?#:]*  →  trusted.internal   （[ 仍是 host 终结符）
  getHost() = trusted.internal  → 302 Location 原串
```

同一条正则、同一次 `matches()`，只因输入多了一个前导 `@`，host 捕获组从 attacker 翻回 trusted。V1 修 userinfo 时没动 host 类，就是给这次翻面留的缝。

---

## 仓库里已经有更强的检查，host 类没用

同一文件里 `HOST_IPV4_PATTERN` 已经把 `[` 当作终结符——这正是 seed 能打 V0 的原因之一。V1 修 userinfo 时**故意**没动它。完整闭合需要两处一起改：userinfo 不再以 `@` 为界（让前导 `@` 被吃进 userinfo），并且 host 不再以 `[` 为界（让 `[` 不能截断 allow-list 主机）。

`java.net.URI` 就在 JDK 里。应用也可以用浏览器那套 parser 做 allow-list。Harness 故意不用它们：advisory 描述的脆弱模式就是「用 Spring 的 `getHost()` 做 allow-list，再用原串当 Location」。若 guard 改成 `new URL(url).getHost()` 或 WHATWG，seed 和 residual 在 V0 上就会一起失败，这条链不成立。

谁在用哪种 host：

| 位置 | 5.3.32 |
|---|---|
| `getHost()` | 正则；userinfo 遇 `@` 停，host 遇 `[` 停 |
| 浏览器对 `Location` | 最后一个 `@` 切 userinfo，`[` 不是 userinfo 终结符 |
| `HOST_IPV4` 排除 `[` | **仍在**，只是没被 seed 再用 |

V1 等于只修了「`[` 在 userinfo 里」这一个方向，更强的「`@` 不要当 userinfo 边界、`[` 不要当 host 边界」要到 5.3.33 才一起写上。不是没有这两个字符类，是 **只改了一半**。

`fromHttpUrl` 用另一份 `HTTP_URL_PATTERN`，但 userinfo/host 宏是同一组常量。只修 `fromUriString`、不改这两个 `private static final String`，两套入口会一起漏。V1/V2 都改的是常量，不是某一个 factory 方法——这是对的；漏的是常量里还剩哪些字符。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs Location」落到具体代码：

- V1 userinfo `([^@/?#]*)`：不能跨 `@`
- V1 host `[^\[/?#:]*`：不能跨 `[`
- 浏览器：最后一个 `@` 才结束 userinfo

只要构造一种输入，使「第一个能停 host 的 `[`」出现在 allow-list 主机后面，而「一个 `@`」出现在更前面（空 userinfo），Spring 会把 allow-list 当成 host，浏览器会把最后一个 `@` 之后当成 host。

```text
seed:     http://trusted.internal[@attacker.test/?<FLAG>
          V0: userinfo 遇 [ 停 → getHost=trusted.internal → 302 + flag
          V1: userinfo 跨 [ 吃到 @ → getHost=attacker.test → 403

residual: http://@trusted.internal[@attacker.test/?<FLAG>
          V1: 前导 @ 被 (userinfo@)? 吃成空 userinfo
              扫描从 trusted.internal[ 重启
              HOST 遇 [ 停 → getHost=trusted.internal → 302 + flag
          V2: userinfo 可含 @，host 不再遇 [ 停 → getHost=attacker.test → 403
```

residual 只是在 seed 前面加了一个 `@`。同一条 `/redirect`，同一个 `getHost()`，同一个 `Location` sink。

---

## 残余仍然走同一条 redirect allow-list（CVE-2024-22259）

没有换路由、没有换 allow-list、没有换 flag 放置。`/redirect` 仍是：

```java
String target = queryParam(rawQuery, "url");          // URLDecoder
String approved = approveRedirect(target);            // 只看 getHost()
if (approved != null) {
  ex.getResponseHeaders().add("Location", approved);  // 原串
  respond(ex, 302, "redirecting", ...);
} else {
  respond(ex, 403, "blocked", ...);                   // body 不含 url
}
```

还是：

```http
GET /redirect?url=http://@trusted.internal[@attacker.test/?<FLAG>
```

`approveRedirect` 仍然只看 `getHost()`。V1 那行 userinfo 正则照样执行；执行完之后前导 `@` 被当成「空 userinfo 结束符」，host 再次变成 `trusted.internal`；302 的 `Location` 仍是原串；浏览器仍去 `attacker.test`。flag 仍在 `Location` 的 query 里。

spring.io CVE-2024-22259：*This is the same as CVE-2024-22243, but with different input.* 受影响版本明确包括 5.3.32。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：只修了 userinfo 里的 `[`；`Location` 用的是检查之前的原串；host 类里的 `[` 和 userinfo 类里的 `@` 都还在。seed 被挡住只说明「`host[` 这一种截断没了」，不说明「不能再让 getHost() 和浏览器分叉」。

下一条链（PCBV2-0197 / CVE-2024-22262）会在 6.1.5（5.3 线上对应 5.3.33 = 本 case V2）上再用 `\` 打一次。那是**另一次**未写完，不是本 case 的 residual。本 case v2 挡住 `@trusted[@attacker` 即可，不必也不该把反斜杠写成这条链的 reference residual。

---

## 后来又补了什么（CVE-2024-22259，5.3.33）

commit `297cbae2`（*Extract reusable checkSchemeAndPort method*）同时改两处：

```java
// v5.3.32 → v5.3.33
USERINFO_PATTERN:  ([^@/?#]*)     → ([^/?#]*)      // 去掉 @
HOST_IPV4_PATTERN: [^\[/?#:]*     → [^/?#:]*       // 去掉 [
```

对残余输入：userinfo 可以吞掉 `@trusted.internal[`，host 变成 `attacker.test`。allow-list 失败，403，`Location` 不出现。公开建议是升级到 5.3.33。

即便如此，5.3.33 仍是同一套正则（6.1.6 才排除 `\`）。对前导 `@`+`[` 这条已知链它够用；`http://sidecar\@trusted` 要到 22262 才关。本 benchmark 的 v2 只关闭本 case 的 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是 userinfo 字符类里的一个符号。真正离开源站的是 `Location` 原串。V2 仍在同一层加码，只是把漏掉的 `@`/`[` 补完。

**不是没有更好的谓词。**  
`HOST_IPV4` 排除 `[` 已经在文件里，V1 没动它。完整修复需要「userinfo 边界」和「host 边界」一起改。从 `7ec5c994` 只能看到 userinfo；要判断补丁是否闭合，必须看到 host 类和 `(userinfo@)?` 对前导 `@` 的绑定。

**同一 `getHost()`，只在前面多了一个 `@`。**  
任何「解析 + 检查 host + 把原串当 Location」的应用，在 5.3.32 上都吃这套不对称字符类。advisory 已写明 same issue, different input。

**403 故意不回显 url。**  
flag 只在被批准的 `Location` 里。能看到它，说明 guard 放行了一次离站跳转，不是「错误页碰巧打印了参数」。

**5.3 线和 6.1 线的落点不要混。**  
22243 在 5.3.32 / 6.1.4 修复；22259 在 5.3.33 / 6.1.5 修复；22262 在 5.3.34 / 6.1.6 修复。本 case 钉 5.3.31/32/33，residual 是前导 `@`+`[`。PCBV2-0197 钉 6.1.4/5/6，residual 是 `\`。两条都是「same issue, different input」，但分隔符和主机顺序都不同。

---

## 版本、入口、参考

| | tag / commit | USERINFO | HOST_IPV4 | `trusted[@attacker` seed | `@trusted[@attacker` residual |
|---|---|---|---|---|---|
| V0 | v5.3.31 | `([^@\[/?#]*)` | `[^\[/?#:]*` | getHost=trusted → 302+flag | （也能） |
| V1 | v5.3.32 / `7ec5c994` | `([^@/?#]*)` | **未改** | getHost=attacker → 403 | getHost=trusted → 302+flag |
| V2 | v5.3.33 / `297cbae2` | `([^/?#]*)` | `[^/?#:]*` | 挡 | 挡 |

- Web：`GET /redirect?url=...`（`Harness.approveRedirect`）
- 认证语义：v0 seed 观察到 flag；v1 seed 未观察到；v1 residual 观察到。
- [CVE-2024-22243](https://spring.io/security/cve-2024-22243)、[NVD CVE-2024-22243](https://nvd.nist.gov/vuln/detail/CVE-2024-22243)
- [CVE-2024-22259](https://spring.io/security/cve-2024-22259)、[NVD CVE-2024-22259](https://nvd.nist.gov/vuln/detail/CVE-2024-22259)
- 后续：CVE-2024-22262（PCBV2-0197，6.1.5 → 6.1.6，反斜杠）
- V1 blob：[`UriComponentsBuilder.java` @ v5.3.32](https://github.com/spring-projects/spring-framework/blob/v5.3.32/spring-web/src/main/java/org/springframework/web/util/UriComponentsBuilder.java)
- V2 对照：tag `v5.3.33` 同一文件
