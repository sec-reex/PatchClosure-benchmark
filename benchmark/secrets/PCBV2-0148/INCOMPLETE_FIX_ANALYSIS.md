# netmask ip2long：八进制补上了，大写 `0X` 仍落到 parseInt 的八进制分支

- Case：`PCBV2-0148`
- 产品：npm `netmask`（`rs/node-netmask`）。库 API 是 `new Netmask(cidr).contains(host)`，常被应用拿来做 SSRF / IP-ACL。运行时是整包 `netmask@2.0.0`。
- 链：CVE-2021-28918（1.0.6 → 2.0.0）→ CVE-2021-29418（2.0.0 → 2.0.1）。NVD 写明后者 *exists because of an incomplete fix for CVE-2021-28918*。
- 源码对着 npm `netmask@2.0.0` 的 `lib/netmask.js`（`ip2long` / `Netmask.prototype.contains`）。金丝雀是 loopback sidecar 上的 `PCBFLAG_...`：ACL 放行之后，应用用 Node `fetch` 去拉 `?host=`。

根因不只是「写错一个字母」。检查插在「这个 octet 字符串怎么 `parseInt`」上；真正决定「是不是 127/8」的是后面那次 `contains` 的整数比较，而内核 / `fetch` 对同一字符串另有一套解析。同一次 `ip2long` 里已经写了十六进制分支，却用 `byte[1] === 'x' || byte[1] === 'x'` 去认 `0x`——`'X'` 永远走不到。下面按调用走进去。

---

## 这块功能本来在干什么

应用把用户给的 host 丢进私网拒绝表，命中则不发请求。一次典型调用：

```javascript
const { Netmask } = require('netmask')
const blocks = ['127.0.0.0/8', '10.0.0.0/8', '172.16.0.0/12',
                '192.168.0.0/16', '169.254.0.0/16']
function blocked(host) {
  return blocks.some((b) => new Netmask(b).contains(host))
}
// GET /fetch?host=...
if (blocked(host)) return 403
return fetch('http://' + host + '/')
```

`contains` 内部把 host 和网段都变成 32 位整数再按掩码比。**没有** `url.parse`、没有 `new URL`、没有 `os.networkInterfaces`。字符串原样进 `ip2long`。

设计意图：看起来像 loopback / RFC1918 / link-local 的地址不能出网。成功穿越之后的效果是：`contains` 认为「不是 127/8」，`fetch` 却连到 127.0.0.1，sidecar 把 flag 反射回 HTTP body。`0.0.0.0/8` 故意不在拒绝表里——这是真实 denylist 常漏的一块，残余正是把地址塌成 `0.0.0.1` 来用它。

数据流：

```text
GET /fetch?host=<用户字符串>
    → 原样 host
    → Netmask(block).contains(host)
         ip2long(host)                 ← V1 的 parseInt / 进制判断
         (long & mask) === netLong     ← 整数比较，不再看字符
    → 未命中拒绝表
    → fetch('http://' + host + '/')    ← Node / undici 按自己的 IPv4 规则解析
    → 127.0.0.1:80 sidecar → PCBFLAG_...
```

---

## 原始漏洞：前导 0 当十进制（CVE-2021-28918，1.0.6）

1.0.6 的 `ip2long` 对 octet 一律 `parseInt(byte, 10)`（或等价地忽略前导零）。`0177.0.0.1` 被读成 `177.0.0.1`。`177.0.0.1` 不在 `127.0.0.0/8` 里，`contains` 返回 false，ACL 放行。

Node 的 `fetch` / 多数 URL 栈把 `0177` 当八进制，`0177.0.0.1` 就是 `127.0.0.1`。拒绝表和出站解析各说各话。这就是 v0 + `--seed`：`host=0177.0.0.1` 打到 sidecar。

---

## 维护者改了什么（CVE-2021-28918 修复，2.0.0）

2.0.0 在 `ip2long` 里按「前导 0」分叉，想同时处理八进制和十六进制：

```javascript
// lib/netmask.js :: ip2long  （npm netmask@2.0.0）
ip2long = function(ip) {
  var b, byte, i, j, len;
  b = (ip + '').split('.');
  if (b.length === 0 || b.length > 4) {
    throw new Error('Invalid IP');
  }
  for (i = j = 0, len = b.length; j < len; i = ++j) {
    byte = b[i];
    if (byte && byte[0] === '0') {
      if (byte.length > 2 && (byte[1] === 'x' || byte[1] === 'x')) {
        byte = parseInt(byte, 16);
      } else {
        byte = parseInt(byte, 8);
      }
    } else {
      byte = parseInt(byte, 10);
    }
    if (isNaN(byte)) {
      throw new Error("Invalid byte: " + byte);
    }
    if (byte < 0 || byte > 255) {
      throw new Error("Invalid byte: " + byte);
    }
    b[i] = byte;
  }
  ...
};
```

`(byte[1] === 'x' || byte[1] === 'x')` 是把 `'X'` 写成了第二个 `'x'`。CoffeeScript 源里同样是两个小写。十六进制分支实际上只认 `0x`，不认 `0X`。

V1 谓词的字面意思：

| octet | 分支 | `parseInt` |
|---|---|---|
| `177` | 十进制 | 177 |
| `0177` | 八进制（前导 0，第二位不是 `x`） | 127 |
| `0x7f` | 十六进制 | 127 |
| `0X7f` | **本该十六进制，实际落到八进制** | `parseInt('0X7f', 8) === 0`（`X` 不是八进制数字，解析停在 0） |

对 seed 这种 `0177.0.0.1`，它确实够用：`0177` → 127，`contains(127.0.0.0/8)` 为真，拒绝。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 前导 0 只可能是八进制，或 `0x`/`0X` 十六进制。
2. `parseInt` 遇到非法数字会失败（`isNaN`），而不是静默截断。

第二点不成立。`parseInt('0X7f', 8)` 不是 NaN，是 `0`。

---

## 进制判断之后，谁拿这个整数去比网段

`ip2long` 一结束，`contains` 立刻用整数做掩码：

```javascript
// lib/netmask.js :: Netmask.prototype.contains  （2.0.0）
Netmask.prototype.contains = function(ip) {
  if (typeof ip === 'string' && (ip.indexOf('/') > 0 || ip.split('.').length !== 4)) {
    ip = new Netmask(ip);
  }
  if (ip instanceof Netmask) {
    return this.contains(ip.base) && this.contains(ip.broadcast || ip.last);
  } else {
    return (ip2long(ip) & this.maskLong) >>> 0 === (this.netLong & this.maskLong) >>> 0;
  }
};
```

过滤器刚看过的是每个 octet 的**字符**；比较器用的是已经塌掉的 32 位数。`0X7f.0.0.1` 变成 `0.0.0.1` 之后，对 `127.0.0.0/8` 为假，对 `10/8`、`172.16/12`、`192.168/16`、`169.254/16` 也都为假。若拒绝表没有 `0.0.0.0/8`，ACL 放行。

出站的 `fetch('http://0X7f.0.0.1/')` 不走 `ip2long`。Node / undici 按 WHATWG / 自己的 IPv4 解析把 `0X7f` 当十六进制 127，连到 loopback。两套语义中间没有第二次「这个 host 字符串解析成的地址必须两边一致」。

---

## 仓库里已经有更强的检查，大小写没对齐

V1 的十六进制分支**意图**就是处理 `0x`/`0X`，只是第二个比较数写错了。更强、当时就能用的谓词：

1. `byte[1] === 'x' || byte[1] === 'X'`（V1 注释里的本意）。
2. 拒绝一切前导 0，只接受十进制（很多现代栈的选择；八进制本身就是 SSRF 经典坑）。
3. 不用 `parseInt` 的静默截断：扫完整个 octet，遇到非法字符就 throw。这正是 2.0.1 的 `atob`。

谁在用这些（2.0.0）：

| 函数 | 对 `0X` 的行为 |
|---|---|
| `ip2long` 的 `=== 'x'` | 不匹配，落到 `parseInt(..., 8)` → 0 |
| `contains` | 只比整数，不再看字符 |
| 应用侧 `fetch` / `new URL` | 把 `0X7f` 当 127 |

不是仓库里没有「认大写 X」这个想法，是 **比较写成了两个 `'x'`**。即便修好大小写，`parseInt('0x9', 8)` 这类「进制声明和数字不符」仍会截断；那是 NVD 在 CVE-2021-29418 里提到的 *octal digit of 9* 另一面，2.0.1 的字符扫描一并收掉。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「parseInt 进制 vs fetch 解析」落到具体输入：

- V1 过滤器：前导 0 且第二位不是小写 `x` → 当八进制 `parseInt`
- Node `fetch`：`0X7f` 是十六进制 127

```text
seed:
  host = 0177.0.0.1
  ip2long → 127.0.0.1
  contains(127/8) === true → 拒绝
  （fetch 也会去 127.0.0.1，但请求到不了 fetch）

residual:
  host = 0X7f.0.0.1
  byte='0X7f'：byte[0]==='0'，byte[1]==='X' ≠ 'x'
  parseInt('0X7f', 8) → 0
  ip2long → 0.0.0.1
  contains(127/8) === false，contains(10/8) === false，…
  ACL 放行
  fetch('http://0X7f.0.0.1/') → 127.0.0.1 → sidecar flag
```

NVD 对 CVE-2021-29418 的概括是 *mishandles certain unexpected characters in an IP address string*，并点名 incomplete fix。大写 `0X` 是其中最干净的一条：只换了一个字母的大小写，sink 仍是 `contains` + 随后的 `fetch`。

---

## 残余仍然走同一条 contains → fetch 路径（CVE-2021-29418）

没有换 API、没有换拒绝表、没有换 sidecar。还是：

```text
GET /fetch?host=0X7f.0.0.1
```

`contains` 仍然调用同一个 `ip2long`。V1 那行 `=== 'x'` 照样不匹配；整数塌成 `0.0.0.1`；fetch 照样去 loopback。本 case residual 和公开 PoC 同一构造。平台 residual 打的就是这条 `contains` + 出站 fetch，和源码链同一 sink。不是另一条无关的 SSRF 通道。

seed 被挡住只说明「八进制 0177 现在会被认成 127」，不说明「ACL 用的整数和 fetch 用的地址是同一个」。

---

## 后来又补了什么（CVE-2021-29418，2.0.1）

2.0.1 扔掉 `split('.')` + `parseInt`，换成逐字符的 `atob`：显式认 `x` 和 `X`，八进制把 `dmax` 限制在 `'7'`，非法字符停止并要求至少消费一个数字，溢出 throw：

```javascript
// lib/netmask.js :: atob  （npm netmask@2.0.1）
if (s.length > 1 && s[i] === '0') {
  if (s[i + 1] === 'x' || s[i + 1] === 'X') {
    i += 2;
    base = 16;
  } else if ('0' <= s[i + 1] && s[i + 1] <= '7') {
    i++;
    base = 8;
    dmax = '7';
  }
}
```

对残余输入：`0X7f` 走 hex，值为 127，`contains(127/8)` 为真，拒绝。公开建议升级到 2.0.1。

即便如此，这仍然是「在 ACL 里把字符串变成整数」，没有强制「只接受十进制点分」。对本条 `0X7f.0.0.1` 够用。本 benchmark 的 v2 只关闭这一条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是 octet 的 `parseInt` 进制。真正逃出拒绝表的是「ACL 整数」和「fetch 解析」不一致。V2 仍在 `ip2long` 加码，但终于自己当严格扫描器，不再把非法数字交给 `parseInt` 截断。

**不是没有更好的谓词。**  
`'X'` 就在同一行的意图里。从 V1 的 diff 只能看到「前导 0 当八进制」；要判断是否闭合，必须看到那行重复的 `'x'`，以及 `parseInt(..., 8)` 对 `0X7f` 返回 0，以及 `contains` 之后的 `fetch` 仍用原始字符串。

**同一 `ip2long`、同一 `contains`，只换了字母大小写。**  
`0x7f.0.0.1` 在 V1 会被挡住；`0X7f.0.0.1` 不会。消费者从来不是「这个字符串像不像 IP」，而是「这个整数在不在网段里」。

**拒绝表漏 `0.0.0.0/8` 会放大塌缩。**  
任何把 octet 静默变成 0 的解析错误，都会把地址丢进「未列出的 0.0.0.0/8」。这不是另一个洞，是这道谓词失败后的默认落点。

**金丝雀在 loopback sidecar 上是有意的。**  
flag 不在 ACL 返回值里。能在 `/fetch` 的 body 里读到它，说明 `contains` 放行之后 `fetch` 真的连到了 127.0.0.1。

---

## 版本、入口、参考

| | 版本 | `ip2long` | `0177.0.0.1` seed | `0X7f.0.0.1` residual |
|---|---|---|---|---|
| V0 | 1.0.6 | 前导 0 当十进制 | 177.0.0.1，ACL 放行，fetch→127 | （不必） |
| V1 | 2.0.0 | 前导 0 当八进制；hex 只认小写 `x` | 127.0.0.1，ACL 拒绝 | 0.0.0.1，ACL 放行，fetch→127 |
| V2 | 2.0.1 | `atob` 认 `x`/`X`，拒绝非法数字 | 拒绝 | 127.0.0.1，ACL 拒绝 |

- 库 API：`new Netmask(cidr).contains(host)`；本 case HTTP 入口 `GET /fetch?host=`
- [CVE-2021-28918](https://nvd.nist.gov/vuln/detail/CVE-2021-28918)、[CVE-2021-29418](https://nvd.nist.gov/vuln/detail/CVE-2021-29418)
- npm：[`netmask@2.0.0` `lib/netmask.js`](https://cdn.jsdelivr.net/npm/netmask@2.0.0/lib/netmask.js)、[`netmask@2.0.1`](https://cdn.jsdelivr.net/npm/netmask@2.0.1/lib/netmask.js)
- 上游仓库：[rs/node-netmask](https://github.com/rs/node-netmask)
