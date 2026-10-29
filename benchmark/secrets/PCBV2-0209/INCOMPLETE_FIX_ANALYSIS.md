# Undertow：CR/LF 按 char 比、按 byte 写，宽字符截断后仍是真正的换行

- Case：`PCBV2-0209`
- 产品：Undertow（`io.undertow:undertow-core`，JBoss / WildFly 内嵌的 HTTP 层）。运行时是 Maven Central 整包；本 case 用一小段 `ReflectServer` 把查询参数写进响应头，经**外部** raw TCP 观察线上的头。不是抽出来的 `writeString`。
- 链：CVE-2016-4993（1.4.2.Final → 1.4.3.Final）→ CVE-2018-1067（1.4.3.Final → 1.4.25.Final，commit `85d4478e`）。NVD 对 1067 写明 *the fix for CVE-2016-4993 was incomplete*。
- 源码对着 tag `1.4.3.Final` 的 `HttpResponseConduit.writeString`。金丝雀不跟 payload 走：只有线上真的出现独立的 CRLF 头 `X-Split` 时，host 侧检测才释放 `PCBFLAG_...`。

根因不只是「漏了一种换行写法」。检查插在 Java `char` 和 `'\r'`/`'\n'` 的相等上；真正进 TCP 的是 `(byte) c`。UTF-16 码元低字节可以是 0x0D，码元本身却不是 U+000D。下面按响应头走进去。

---

## 这块功能本来在干什么

Undertow 把 `HeaderMap` 里的响应头写成 HTTP/1.1 字节：`Name: value\r\n`。值来自应用调用 `exchange.getResponseHeaders().put(name, value)`。设计意图：即使用户字符串进了头值，也不能在值里插入 CR/LF 从而劈出新头或新响应。

库 API：

```java
exchange.getResponseHeaders().put(new HttpString("X-Reflect"), userControlled);
```

本 case 的 HTTP：

```http
GET /reflect?v=<payload> HTTP/1.1
```

`v` 经 Undertow 的 URL 解码（UTF-8）变成 Java String，原样放进 `X-Reflect`。没有应用层消毒；唯一防线是写管道里的 `writeString`。

数据流：

```text
GET /reflect?v=...
    → HttpHandler
         HeaderMap.put(X-Reflect, v)
    → HttpResponseConduit 写状态行后遍历 HeaderMap
         header.appendTo(buffer)
         buffer.put(':').put(' ')
         writeString(buffer, string)          ← V1 在这里比 char、写 byte
         buffer.put('\r').put('\n')
    → TCP
         若 value 里出现真正的 0x0D 0x0A，后面的 "X-Split: ..." 变成独立头
```

成功穿越 = **响应在字节上被劈开**（CWE-113），检测器看到独立的 `X-Split`。不需要登录。WildFly/JBoss 上任何把请求数据抄进响应头的 handler（Location、自定义头、错误回显）都走同一 `writeString`。

---

## 原始漏洞：头值原样窄化写入（CVE-2016-4993，1.4.2.Final）

1.4.2 的 `writeString` 没有 CR/LF 判断：

```java
private static void writeString(ByteBuffer buffer, String string) {
    int length = string.length();
    for (int charIndex = 0; charIndex < length; charIndex++) {
        buffer.put((byte) string.charAt(charIndex));
    }
}
```

明文 `%0d%0aX-Split:%20` 解码成 U+000D U+000A，窄化后仍是 0x0D 0x0A，响应劈开。这就是 v0 + seed。NVD CVE-2016-4993：WildFly 10 / EAP 7.x 上的 CRLF injection，修复随 Undertow 1.4.3 一类版本进入产品。

---

## 维护者改了什么（CVE-2016-4993 修复，1.4.3.Final）

1.4.3 在写入前用 **char** 和 `'\r'`/`'\n'` 比较，命中则改成空格：

```java
// HttpResponseConduit.writeString   1.4.3.Final  （CVE-2016-4993，本 case 的目标）
private static void writeString(ByteBuffer buffer, String string) {
    int length = string.length();
    for (int charIndex = 0; charIndex < length; charIndex++) {
        char c = string.charAt(charIndex);
        if(c != '\r' && c != '\n') {
            buffer.put((byte) c);
        } else {
            buffer.put((byte) ' ');
        }
    }
}
```

对 seed：`c == '\r'` / `'\n'` 为真，线上变成空格，`X-Split` 仍折在 `X-Reflect` 的值里，不是独立头。这就是 v1 + `--seed`。

补丁默认了两件事：

1. 能劈响应的字节只来自码元 U+000D / U+000A。
2. 比较用的值和写入用的值是同一个东西。

第二点不成立。比较的是 16 位 `char`，写入的是 `(byte) c`，即低 8 位。`(byte) 0x010D == 0x0D`，但 `0x010D != '\r'`。

---

## 检查通过之后，谁把这个 byte 送上线

`writeString` 是 `HttpResponseConduit` 写头值的快路径（状态行 reason-phrase 也走它）。循环一结束，周围代码立刻 `buffer.put('\r').put('\n')` 结束这一行，然后 `next.write(buffer)` 进连接。

没有「写入后再扫一遍 0x0D/0x0A」、没有按 RFC 7230 把 field-value 限制在可见 ASCII。过滤器看的是 `c != '\r' && c != '\n'`；socket 看的是 `ByteBuffer` 里的 octet。

U+010D（Latin capital letter D with caron）/ U+010A 经 UTF-8 查询串进来后，在 Java String 里各占一个 char。V1 认为它们不是 CR/LF，`(byte)` 之后线上就是 CR/LF。随后应用（或探测串）里的 `X-Split:` 变成新头。Red Hat Bugzilla / CVE-2018-1067：*insufficient sanitization and validation of user input before the input is used as part of an HTTP header value*。

慢路径 `processStatefulWrite` 同样按 char 写头值；V2 的 byte 收窄要两处一起改才闭合。本链的 reference residual 打的是快路径 `writeString`。

---

## 仓库里已经有「按即将写入的字节判断」的做法

V1 自己就在 `buffer.put((byte) c)`——手里已经有即将上线的 octet，却拿宽 char 去比。更强且零新 API 的谓词是：先 `byte b = (byte) c`，再 `if (b != '\r' && b != '\n')`。这就是 V2。

HTTP 头值在线上是 octet，不是 UTF-16。Undertow 的 `HttpString`（头**名**）走另一套 ASCII 约束；头**值**在 1.4.3 没有同等的 octet 白名单。维护者若按 RFC 只允许 VCHAR / SP / HTAB，U+010D 根本不会进缓冲区。V1 选了最窄的「只挡两个 char 字面量」。

---

## 这个补丁挡住了什么、没挡住什么

- V1：`char c` 是否等于 U+000D / U+000A
- TCP：`(byte) c` 是否为 0x0D / 0x0A

```text
明文 CR LF     c='\r'/'\n'     挡，写成空格
U+010D U+010A  c=0x010D/0x010A 放行，(byte)→0x0D/0x0A，响应劈开
```

seed 被挡住只说明「Unicode 换行码元被换成空格」，不说明「头值里不能再出现换行字节」。

---

## 残余仍然走同一条 writeString 头值路径（CVE-2018-1067）

没有换 HeaderMap、没有换 `X-Reflect`、没有换「值里的 CRLF 劈出 X-Split」这个观察通道。还是 `GET /reflect?v=...`。差别只是 payload：明文 CR/LF 换成低字节为 0x0D/0x0A 的 BMP 字符（如 `%C4%8D` = U+010D）。

平台 residual 若用截断字符打同一响应头 sink，和 NVD「incomplete fix of CVE-2016-4993」是同一条链。不是另打请求行走私或 HTTP/2。本 case 的 ReflectServer 只是把库的 `HeaderMap.put` 暴露成查询参数；产品里对应的是任意把用户输入抄进响应头的 handler。

把一个字符在 V1 循环里的两种身份拆开：

```text
明文 CR = U+000D = '\r' = 0x000D
    c != '\r' → 假 → put(' ')           线上 0x20

U+010D = 0x010D  （UTF-8 查询串 %C4%8D，URL 解码后一个 char）
    c != '\r' → 真（0x010D ≠ 0x000D）
    c != '\n' → 真
    (byte) 0x010D = (byte) 269 = 0x0D = '\r'
    buffer.put((byte) c)                线上 0x0D

U+010A 同理 → 线上 0x0A
```

探测串若是 `U+010D U+010A X-Split: 1`，快路径写出来的字节是：

```text
X-Reflect: <0x0D><0x0A>X-Split: 1\r\n
```

HTTP/1.1 解析器在头段遇到 CRLF 就结束当前字段。下一行 `X-Split: 1` 成为独立头。host 侧 raw socket 不走 HTTP 客户端的头折叠，才能把「真的劈开」和「值里有空格」分开。V0 明文 CRLF 与 V1 截断字符在线上是同一类 0x0D 0x0A；V1 只是把触发码元从 U+000D 换成了低字节碰巧为 0x0D 的别的码元。

`writeString` 还用于 reason-phrase。本 case 打的是头**值**，因为应用 API `HeaderMap.put` 把用户字符串放在值上；reason-phrase 通常不是用户可控。同一函数、同一窄化，两条消费者。V2 的 `byte b = (byte) c` 对两者一起生效。

---

## 后来又补了什么（CVE-2018-1067，1.4.25.Final）

commit `85d4478e` 先窄化再比较：

```java
// 1.4.25.Final
char c = string.charAt(charIndex);
byte b = (byte) c;
if(b != '\r' && b != '\n') {
    buffer.put(b);
} else {
    buffer.put((byte) ' ');
}
```

对残余：U+010D 的低字节是 `'\r'`，写成空格，线上不再劈头。NVD 记 EAP / Undertow 7.1.2 以及社区 1.4.25 / 2.0.5 一线。公开建议升到含该 commit 的版本。

即便按 byte 拦 CR/LF，头值仍可能含其它 CTL；那是更宽的 CWE-113。本 benchmark 的 v2 只关闭截断字符这一条 reference residual。

NVD 把 1067 记在 EAP 7.1.2 / Undertow 1.4.25 与 2.0.5 一线；社区 tag `1.4.25.Final` 的 `writeString` 与 commit `85d4478e` 一致。WildFly 把用户输入抄进 `Location`、错误页、CORS、自定义头时，值同样经过 `HttpResponseConduit`。本 case 用 `X-Reflect` 只是为了让 raw socket 上的劈头可判定：探测串里的 `X-Split` 在 V1 residual 下必须作为**独立头**出现，而不能只是 `X-Reflect` 值里的子串。明文 CRLF 在 V1 被换成空格后，检测器看到的是折叠后的 `X-Reflect: x  X-Split:`，不释放 flag——这保证 seed/residual 的差分落在 `writeString` 的 char vs byte 上，而不是检测器过宽。

---

## 从这条链还能看出什么

**维护者改错了哪一层。**  
他们改的是 UTF-16 码元是否等于 `'\r'`。真正劈 HTTP/1.1 的是 octet。V2 仍在同一循环里加码，只是让比较对象和 `put` 的对象一致。

**不是没有更好的谓词。**  
即将 `put` 的那个 byte 就是最强的本地谓词。V1 计算了它，用来写入，却不用来判断。

**同一 `writeString`、同一头值 String，只换了码元。**  
任何把用户字符串放进响应头的 Undertow 应用，在 1.4.3–1.4.24 上都吃这次 char 检查和同一次 `(byte)` 写入。

**URL 解码用 UTF-8，写入用 Latin-1 窄化。**  
两条编码不是同一个同态；检查若只认解码后的 char 字面量，就会和线上 octet 分叉。

任意 `char` 只要 `(c & 0xFF) == 0x0D` 且 `c != '\r'` 都能当 residual：U+010D、U+020D、U+560D 一类。本 case 用 U+010D/U+010A 是因为 UTF-8 编码短、Undertow 查询串解码后仍是单个 BMP char（不是 surrogate pair）。代理对会让 `charAt` 看到高/低代理而不是那个码点，不在这条 V1 谓词的典型残余里。V2 按 byte 比，这些码元一律当成 CR/LF 换成空格。

---

---

## 头名和头值不是同一套编码器

`HttpString.appendTo` 写的是头**名**，按 ASCII 字节逐个 put，不经过 `writeString`。用户可控的是头**值** `string = headerValues.get(valueIdx)`，只走 `writeString`。所以 residual 必须出现在值里：查询参数进 `X-Reflect` 的 value，再在 value 里注入 CR/LF 劈出下一头。把 U+010D 放进头名通常进不了 `HttpString` 的合法名。V1/V2 都只改值这一侧。快路径在 buffer 还够时走 `writeString`；值过长才进 `processStatefulWrite`。本 case 的探测串很短，走快路径，和 1.4.3 / 1.4.25 的 `writeString` 字节级对应。

写完所有头之后 conduit 再 `buffer.put('\r').put('\n')` 结束头段。residual 在值里注入的 CRLF 发生在**这一行结束之前**，所以解析器会提前结束 `X-Reflect`，把后续当成新头；头段结束的那组 CRLF 仍然在。检测器要的是「出现独立的 `X-Split` 行」，不是「响应变短」。V1 seed 把明文 CR/LF 换成空格后，`X-Split:` 仍在 `X-Reflect` 的同一行里，结构上不是独立头。

Undertow 的查询串解码按 UTF-8：`%C4%8D` → U+010D 一个 char。若客户端用 ISO-8859-1 把 0x0D 当 `%0D` 送来，那是明文 CR，走 V1 的 char 检查被挡。residual 依赖「解码后的 char 不是 CR，窄化后的 byte 是 CR」这一对。`HeaderMap.put` 接受 `String`，不在 put 时扫 CR/LF；消毒只发生在序列化到 `ByteBuffer` 的那一毫秒。应用层若自己先 `value.replace('\n',' ')` 也只挡得住 char 字面量，挡不住 U+010D——和 V1 同一层错误。

## 版本、入口、参考

| | 版本 | `writeString` | 明文 CRLF seed | U+010D/U+010A residual |
|---|---|---|---|---|
| V0 | 1.4.2.Final | `(byte) charAt`，无检查 | 线上独立 X-Split | （不必） |
| V1 | 1.4.3.Final | `char` 比 `'\r'`/`'\n'`，仍 `(byte)c` 写入 | 折成空格 | 线上独立 X-Split |
| V2 | 1.4.25.Final | 先 `(byte)c` 再比 | 挡 | 挡 |

- 库 API：`HeaderMap.put` → `HttpResponseConduit.writeString`
- 本 case HTTP：`GET /reflect?v=...`（外部 raw socket 读响应字节）
- [CVE-2016-4993](https://nvd.nist.gov/vuln/detail/CVE-2016-4993)、[Bugzilla 1344321](https://bugzilla.redhat.com/show_bug.cgi?id=1344321)
- [CVE-2018-1067](https://nvd.nist.gov/vuln/detail/CVE-2018-1067)（*fix for CVE-2016-4993 was incomplete*）、[Bugzilla CVE-2018-1067](https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2018-1067)
- V1 源码：[HttpResponseConduit.java @ 1.4.3.Final](https://github.com/undertow-io/undertow/blob/1.4.3.Final/core/src/main/java/io/undertow/server/protocol/http/HttpResponseConduit.java)（`writeString` 约 L287–L297）
- V2：同文件 @ [1.4.25.Final](https://github.com/undertow-io/undertow/blob/1.4.25.Final/core/src/main/java/io/undertow/server/protocol/http/HttpResponseConduit.java) commit `85d4478e598105fe94ac152d3e11e388374e8b86`
