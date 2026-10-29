# url-parse：斜杠改完了，控制字符还在 trimLeft 前面

- Case：`PCBV2-0009`
- 产品：npm `url-parse`（unshiftio）。应用侧是一个用它做「是否同站」判断的安全跳转接口。
- 链：CVE-2021-3664（1.5.1 → 1.5.2，commit `81ab967`）→ CVE-2022-0691（1.5.2…1.5.8 → 1.5.9，commit `0e3fb54`）
- 源码对着 GitHub tag `1.5.1` / `1.5.2` / `1.5.9` 的 `index.js`：`trimLeft`、`extractProtocol`、`isSpecial`、`sanitize`。运行时装的是发布包本身，不是抽出来的函数。

2021 年 7 月，url-parse 把 scheme 后面的斜杠规则从「`:` 后任意 `\` 或 `/`」改成必须 `://`，并给特殊 scheme 做全局反斜杠替换。这挡住了 `https:\evil` 这种「库说没有 host、浏览器当成绝对 URL」的跳转。四个月后 huntr 报告：同一个解析入口前面的 `trimLeft` 仍不剥 `\x00`–`\x08` 这类 C0 控制字符。WHATWG 会先剥再当绝对 URL 解析；url-parse 会把带 `\x08` 的串当成相对路径，解析到应用自己的 origin 上。NVD CVE-2022-0691 写的是 *Authorization Bypass Through User-Controlled Key in NPM url-parse prior to 1.5.9*；GHSA-jf5r-8hm2-f872 写明 *Leading control characters in a URL are not stripped*。

根因不只是「少剥了一个字符」。检查插在「scheme / 斜杠长什么样」这一层；真正拿去放行跳转的是解析后的 `hostname`；同文件里已经有一次 `trimLeft`，却用了一张从 `\x09` 才开始的空白表。下面按请求走进去、1.5.2 改了哪几行、trim 之后谁消费那个字符串、更宽的空白表有没有挂上，把这几层写完。

---

## 这块功能本来在干什么

`url-parse` 给 Node / 浏览器提供一份小体积 URL 解析。很多应用不用 WHATWG `new URL()`，而是拿它的 `.hostname` / `.protocol` 做白名单：相对地址或本站 host 才 302。一份典型的安全跳转：

```http
GET /redirect?to=/dashboard
```

应用把 `to` 交给解析器，并带上自己的 origin 当 base：

```javascript
// harness.mjs :: isSameOrigin  （本 case 的应用侧，调用的是真实 url-parse）
const parsed = new UrlParse(rawTarget, SELF_ORIGIN);  // SELF_ORIGIN = http://trusted.internal
const host   = parsed.hostname;
return host === "" || host === SELF_HOST;             // 空 host = 相对地址
```

设计意图：`to` 必须是本站路径，或 host 等于 `trusted.internal`。通过之后，应用把**客户端给的原始字符串**写进 `Location`（或控制字符无法进 HTTP 头时，写成 `<meta http-equiv=refresh>`）。成功穿越之后的效果是：**库认为这是同站，浏览器却导航到站外**，响应里出现攻击者选的 host 标签（本 case 用 `PCBFLAG_...` 当 host 前缀）。

数据流：

```text
HTTP ?to=
    → Url(address, location)          ← 入口先 trimLeft(address)
    → extractProtocol(address, loc)   ← 再 trimLeft 一次，再跑 protocolre
         V1：isSpecial + :// 斜杠计数   ← 补丁插在这里
         得到 protocol / slashes / rest
    → 相对则继承 location.hostname
    → isSameOrigin 只看 parsed.hostname
    → 放行则 302 Location = 原始 to（或 meta refresh）
```

没有登录。判断完全信任解析器对 host 的读法，不信任浏览器稍后怎么读同一串字节。

---

## 原始漏洞：scheme 后一个反斜杠（CVE-2021-3664，1.5.1）

1.5.1 的斜杠正则把 `\` 和 `/` 当成同类：

```javascript
// index.js  (url-parse@1.5.1)
, slashes = /^[A-Za-z][A-Za-z0-9+-.]*:[\\/]+/
, protocolre = /^([a-z][a-z0-9.+-]*:)?([\\/]{1,})?([\S\s]*)/i
```

`extractProtocol` 用第二组的**长度**判断有没有 authority：`slashes = !!(match[2] && match[2].length >= 2)`。`https:\evil` 的第二组是单个 `\`，长度 1，于是 `slashes=false`，整个余下部分折进 pathname。`sanitize` 只替换**第一个**反斜杠：

```javascript
function sanitize(address) {
  return address.replace('\\', '/');
}
```

Snyk SNYK-JS-URLPARSE-1533425 / GHSA-hh27-ffr2-f2jc 的问题是：应用按「没有 hostname = 相对 = 安全」放行，浏览器却把 `https:\host` 当成绝对 `https://host`。本 case 的 seed：

```text
to = https:\<FLAG>.evil.example
```

1.5.1 解析结果：`hostname === ''`，`isSameOrigin` 为真，发出 302，`Location` 里出现 `PCBFLAG_...`。

`trimLeft` 在 1.5.1 就已经存在，空白类从 `\x09`（TAB）起，不含 `\x00`–`\x08`。当时没人拿它当斜杠问题的一部分。

---

## 维护者改了什么（CVE-2021-3664 修复，1.5.2）

commit `81ab967` 动的是 scheme / 斜杠这一层，和 1.5.1 并排：

```javascript
// V0  1.5.1
, slashes = /^[A-Za-z][A-Za-z0-9+-.]*:[\\/]+/
, protocolre = /^([a-z][a-z0-9.+-]*:)?([\\/]{1,})?([\S\s]*)/i
function sanitize(address) {
  return address.replace('\\', '/');
}
function extractProtocol(address) {
  address = trimLeft(address);
  var match = protocolre.exec(address)
    , protocol = match[1] ? match[1].toLowerCase() : ''
    , slashes = !!(match[2] && match[2].length >= 2)
    , rest =  match[2] && match[2].length === 1 ? '/' + match[3] : match[3];
```

```javascript
// V1  1.5.2
, slashes = /^[A-Za-z][A-Za-z0-9+-.]*:\/\//
, protocolre = /^([a-z][a-z0-9.+-]*:)?(\/\/)?([\\/]+)?([\S\s]*)/i
function sanitize(address, url) {
  return isSpecial(url.protocol) ? address.replace(/\\/g, '/') : address;
}
function isSpecial(scheme) {
  return (
    scheme === 'file:' || scheme === 'ftp:' ||
    scheme === 'http:' || scheme === 'https:' ||
    scheme === 'ws:'   || scheme === 'wss:'
  );
}
function extractProtocol(address, location) {
  address = trimLeft(address);          // 空白表没改
  // 按 // 与其它斜杠分别计数；特殊 scheme 强制 slashes=true
  return { protocol, slashes: forwardSlashes || isSpecial(protocol),
           slashesCount, rest };
}
```

对 seed 这种明文 `https:\host`，它确实够用：`protocolre` 不再把单个 `\` 当成 authority，`isSpecial('https:')` 为真，`rest` 落到 host 解析，`hostname` 变成 `<FLAG>.evil.example`，和应用自己的 `trusted.internal` 对不上，接口回 403，body / Location 都没有金丝雀。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险形态长得像「scheme 后面用 `\` 冒充 `//`」。
2. 只要斜杠规则按 WHATWG 特殊 scheme 对齐，解析出的 `hostname` 就会和浏览器一致。

第二点不成立。斜杠规则之前还有一次 trim；那次 trim 的字符表比 WHATWG 的 C0 剥离窄。

`trimLeft` 在 1.5.2 **一字未改**：

```javascript
// index.js  (url-parse@1.5.2，与 1.5.1 相同)
, whitespace = '[\\x09\\x0A\\x0B\\x0C\\x0D\\x20\\xA0\\u1680\\u180E\\u2000\\u2001\\u2002\\u2003\\u2004\\u2005\\u2006\\u2007\\u2008\\u2009\\u200A\\u202F\\u205F\\u3000\\u2028\\u2029\\uFEFF]'
, left = new RegExp('^'+ whitespace +'+');

function trimLeft(str) {
  return (str ? str : '').toString().replace(left, '');
}
```

`\x08`（BACKSPACE）不在这张表里。`extractProtocol` 第一行仍是 `address = trimLeft(address)`，然后才跑新的 `protocolre`。

---

## 消毒之后，解析结果怎么接到跳转判断上

V1 的 `extractProtocol` 一结束，`Url` 构造函数用它的返回值决定这是不是相对 URL：

```javascript
// index.js :: Url  (url-parse@1.5.2)
extracted = extractProtocol(address || '', location);
relative = !extracted.protocol && !extracted.slashes;
url.slashes = extracted.slashes || relative && location.slashes;
url.protocol = extracted.protocol || location.protocol || '';
address = extracted.rest;
```

相对时，后面的 rule 会从 `location` 继承 `hostname`。应用的 `isSameOrigin` **只读** `parsed.hostname`：

| 解析器看到的 hostname | 应用决定 |
|---|---|
| `''`（认为相对、且 base 也没有 host） | 放行 |
| `trusted.internal`（相对解析到了自己的 origin） | 放行 |
| 其它（例如 `evil.example`） | 403 |

过滤器刚看过的是「`://` 在不在、反斜杠要不要换成正斜杠」；放行看到的是 trim 之后、相对解析之后的 host 字段。两套语义中间没有第二次「和浏览器解析是否一致」的谓词。金丝雀能出现在 Location / meta 里，依据就是这一步：应用把**原始** `to` 交给浏览器，而不是把 `parsed.href` 交给浏览器。

---

## 仓库里已经有一次 trim，字符表却比消费者窄

同一份 `index.js` 里，WHATWG 会剥掉的前导 C0 控制字符，本应在 `trimLeft` 里处理——函数名字和调用点都在。它已经挂在两个入口上：

| 调用点 | 调用 `trimLeft`？ | 空白表含 `\x00`–`\x08`？ |
|---|---|---|
| `Url()` 构造函数第一行 | 是 | 否（从 `\x09` 起） |
| `extractProtocol` 第一行 | 是 | 否 |
| `protocolre` / `isSpecial` | 否，假定输入已被 trim | — |

不是没有 trim。是 **trim 的谓词比后面的 scheme 解析、也比浏览器，都更弱**。V1 在 `extractProtocol` 里加了 `isSpecial` 和斜杠计数，等于在 trim **之后** 把斜杠语义对齐了；trim 自己仍按「Unicode 空白」而不是「WHATWG 会忽略的前导控制字符」来写。

即便没有 `\x08`，只要任何让 `protocolre` 认不出 `http:` 的前缀还能留下，相对解析仍会把 host 填成 `trusted.internal`。1.5.2 到 1.5.8 中间还有 CVE-2022-0512（`@` userinfo，1.5.6），同样没动这张空白表。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「斜杠规则 vs trim vs 浏览器」落到具体变换。

- `slashes` / `protocolre` / `isSpecial`：看 scheme 后面是不是 `://`，特殊 scheme 的 `\` 要不要换成 `/`
- `trimLeft`：看字符串是不是以 `\x09` 及以后的空白开头
- 浏览器（WHATWG）：先剥 C0 控制字符和空白，再按绝对 / 相对解析

只要构造一种输入，使 trim 之后**第一个可见字符不是** `http:` 的 `h`，`protocolre` 就拿不到 protocol，`relative` 为真，host 继承 `trusted.internal`。

huntr / Snyk 的 PoC 用的是 `\b`（`\x08`）：

```javascript
// Snyk SNYK-JS-URLPARSE-2407770 PoC（url-parse < 1.5.9）
url = parse('\bhttp://google.com')
// hostname: ''   protocol: ''   pathname: '\bhttp://google.com'
```

带上本 case 的 base origin：

```text
to:      \x08http://<FLAG>.evil.example
trimLeft(1.5.2):  不变（\x08 不在空白表）
protocolre:       第一个字符不是 [a-z]，protocol=''，slashes=false
relative:         true
继承 location:    hostname = trusted.internal
isSameOrigin:     true → 放行
```

浏览器剥掉 `\x08` 之后看到的是绝对 URL `http://<FLAG>.evil.example`。Node 的 `http` 层拒绝把 `\x08` 写进 `Location`（`ERR_INVALID_CHAR`），应用退回到客户端跳转页，body 里仍是原始 `to`，金丝雀 host 出现在 HTML 里。GHSA-jf5r-8hm2-f872 给的 XSS 例子是同一机制：`url.protocol !== "javascript:"` 放行，href 里却是浏览器会执行的 `javascript:`。

V1 改的是斜杠；`\x08http://...` 里根本没有「scheme 后的反斜杠」可改。斜杠规则在 trim 之后运行，trim 没把控制字符拿掉，新规则无事可做。

---

## 残余仍然走同一条安全跳转路径（CVE-2022-0691）

没有换接口、没有换字段、没有换身份。还是：

```http
GET /redirect?to=%08http://<FLAG>.evil.example
```

`Url()` 仍然先 `trimLeft`，再 `extractProtocol`。V1 的 `isSpecial` / `://` 照样执行；执行完之后因为没有识别到 protocol，相对解析把 host 填成应用自己的；`isSameOrigin` 放行；原始 `to` 进 meta refresh。

本 case residual 写死为：

```text
to = "\x08" + "http://" + FLAG + ".evil.example"
```

和 Snyk / huntr 的 `\bhttp://google.com` 同一构造，只是把 google.com 换成金丝雀 host。认证意图：v1 + `--residual` 在响应 body 中观察到 `PCBFLAG_...`。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：斜杠补丁插在 trim 之后；trim 的字符表比 WHATWG 窄；应用拿解析后的 hostname 做决定，却把**未解析的原始字符串**交给浏览器。seed 被挡住只说明「单个反斜杠不再能把 host 藏进 pathname」，不说明「库和浏览器会对同一串字节读出同一个 host」。

---

## 后来又补了什么（CVE-2022-0691，1.5.9）

commit `0e3fb54` 把空白表扩到 `\x00`–`\x20`，并在 trim 之后再剥 CR/LF/TAB：

```javascript
// V2  1.5.9
, CRHTLF = /[\n\r\t]/g
, whitespace = /^[\x00-\x20\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]+/;

function trimLeft(str) {
  return (str ? str : '').toString().replace(whitespace, '');
}

function extractProtocol(address, location) {
  address = trimLeft(address);
  address = address.replace(CRHTLF, '');
  ...
}
```

对残余输入：

```text
输入:     \x08http://<FLAG>.evil.example
trimLeft: http://<FLAG>.evil.example
protocol: http:   hostname: <FLAG>.evil.example
isSameOrigin: false → 403
```

公开建议是升级到 `url-parse@1.5.9`。即便如此，应用若继续把原始 `to` 写进 Location，而不是使用解析后的 `href`，其它「库和浏览器仍不一致」的写法需要另证。本 benchmark 的 v2 只关闭这一条 leading-control-char residual。中间的 1.5.6 / 1.5.8 仍开放这一条。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是 `extractProtocol` 里 scheme 后面长什么样。真正让跳转放行的是 trim 之后「有没有 protocol / slashes」以及相对解析填进去的 `hostname`。V2 才回到 `trimLeft` 的字符表。1.5.2 的 diff 里看不到 `whitespace`。

**不是没有 trim。**  
`trimLeft` 在 V0 就存在，并且构造函数和 `extractProtocol` 都调用。缺的是「WHATWG 会剥的那些字节」。从 V1 的 diff 只能看到 `isSpecial` 和 `://`；要判断补丁是否闭合，必须看到 `whitespace` 从 `\x09` 起、以及应用拿 `hostname` 做决定却重放原始字符串。

**同一函数、同一 `to`，只换了前缀字节。**  
任何把用户字符串传进 `new UrlParse(to, origin)` 再读 `.hostname` 的接口，在 1.5.2 上都吃同一张空白表。advisory 里的 `javascript:` XSS 是同一 trim。

**应用信任的是解析结果，发出去的是原始输入。**  
若 302 的 Location 用的是 `parsed.href` 而不是 `to`，`\x08` 这条链至少不会把控制字符交给浏览器。当前 sink 把两套 URL 语义并在一次判断里。

---

## 版本、入口、参考

| | npm | `trimLeft` 空白表 | `extractProtocol` 斜杠 | `https:\host` seed | `\x08http://host` residual |
|---|---|---|---|---|---|
| V0 | 1.5.1 | `\x09` 起 | `:[\\/]+`，单次 `replace('\\','/')` | hostname 空，放行 | （不必） |
| V1 | 1.5.2 | 同上 | `://` + `isSpecial`，全局 `\\`→`/` | hostname=evil，403 | 当相对 URL，放行 |
| V2 | 1.5.9 | `\x00`–`\x20` + CRHTLF | 斜杠规则保留 | 挡 | 剥掉 `\x08` 后 hostname=evil，403 |

- Web：`GET /redirect?to=...`
- 认证意图：v0 seed 在 Location 观察到 flag；v1 seed 403；v1 residual 在 meta/body 观察到 flag。
- [CVE-2021-3664](https://nvd.nist.gov/vuln/detail/CVE-2021-3664)、[GHSA-hh27-ffr2-f2jc](https://github.com/advisories/GHSA-hh27-ffr2-f2jc)
- [CVE-2022-0691](https://nvd.nist.gov/vuln/detail/CVE-2022-0691)、[GHSA-jf5r-8hm2-f872](https://github.com/advisories/GHSA-jf5r-8hm2-f872)
- [Snyk SNYK-JS-URLPARSE-1533425](https://security.snyk.io/vuln/SNYK-JS-URLPARSE-1533425)、[Snyk SNYK-JS-URLPARSE-2407770](https://security.snyk.io/vuln/SNYK-JS-URLPARSE-2407770)（含 `\bhttp://google.com` PoC）
- 修复提交：[81ab967](https://github.com/unshiftio/url-parse/commit/81ab967)（1.5.2）、[0e3fb54](https://github.com/unshiftio/url-parse/commit/0e3fb542d60ddbf6933f22eb9b1e06e25eaa5b63)（1.5.9）
