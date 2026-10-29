# PostCSS：去掉了 `.*` 后面的 `\\s*`，贪婪 `.*` 还在 sourceMappingURL 上

- Case：`PCBV2-0015`
- 产品：npm `postcss`。解析 CSS 时 `lib/previous-map.js` 用正则从注释里抠 `/*# sourceMappingURL=... */`。
- 链：CVE-2021-23368（8.2.9 → 8.2.10，删掉 `.*` 与 `*/` 之间的 `\\s*`）→ CVE-2021-23382（8.2.10 → 8.2.13，把 `.*` 换成 tempered-greedy `(?:(?!sourceMappingURL=).)*`）
- 源码对着 GitHub tag `8.2.10` / `8.2.13` 的 `lib/previous-map.js`：`loadAnnotation`、`getAnnotationURL`。`postcss.parse(css, {map:{prev:true}})` 会构造 `PreviousMap`，构造函数第一件事就是 `this.loadAnnotation(css)`。

2021 年 4 月 26 日 Snyk 报 source map 注释正则灾难性回溯。8.2.10 的修复是把 `/\/\*\s*# sourceMappingURL=.*\s*\*\//gm` 里 `*/` 前的 `\\s*` 拿掉。四天后 CVE-2021-23382 / SNYK-JS-POSTCSS-1255640：*The vulnerable regexes are caused mainly by the sub-pattern `\/\*\s*# sourceMappingURL=(.*)`*，PoC 是重复前缀 `/*# sourceMappingURL=` 而不是空白填充。

根因不只是「少改了一个量词」。检查插在「注释正则能不能匹配」；真正占住 Node 事件循环的是 V8 对这条正则的回溯；同一次 `match` 仍用贪婪 `.*` 去找一个输入里**根本不存在**的 `*/`。下面按 parse 走进去、8.2.10 改了哪一段、匹配失败之后引擎还在干什么、禁止跨越第二个 `sourceMappingURL=` 的谓词有没有挂上，把这几层写完。

---

## 这块功能本来在干什么

PostCSS 解析带 inline / 外部 source map 的 CSS 时，要找到最后一处 `/*# sourceMappingURL=... */`。`PreviousMap` 构造函数：

```javascript
// lib/previous-map.js  (postcss@8.2.10)
constructor(css, opts) {
    if (opts.map === false) return
    this.loadAnnotation(css)
    ...
}
```

`postcss.parse(css, {from, map:{prev:true}})` 会走到这里。构建工具把用户 CSS 交给 parse 时，这条正则在事件循环上同步执行。一次典型请求：

```http
POST /process  {"css":"a{}/*# sourceMappingURL=data:... */"}
```

数据流：

```text
CSS 字符串
    → postcss.parse(..., {map:{prev:true}})
         new Input → new PreviousMap(css)
         loadAnnotation(css)
              css.match(/\/\*\s*# sourceMappingURL=.*\*\//gm)     ← V1 补丁后的形态
              取最后一处，getAnnotationURL 再 match 一次
         若匹配失败：注解不存在，parse 继续（但 match 可能已经耗尽 CPU）
    → HTTP 响应延迟 / 超时
```

设计意图：从合法注释里读 URL。成功穿越之后的效果不是读文件，而是 **match 在失败路径上超级线性回溯，卡住单线程事件循环**。本 case 用 HTTP 往返 >2s 或 10s 读超时当「打到了」。

没有鉴权。CSS 完全来自请求体。

---

## 原始漏洞：`.*` 后面紧跟 `\\s*`，空白可以两种切法（CVE-2021-23368，8.2.9）

8.2.9：

```javascript
loadAnnotation(css) {
  let annotations = css.match(/\/\*\s*# sourceMappingURL=.*\s*\*\//gm)
  ...
}
getAnnotationURL(sourceMapString) {
  return sourceMapString.match(/\/\*\s*# sourceMappingURL=(.*)\s*\*\//)[1].trim()
}
```

`.*` 是贪婪的，后面的 `\\s*` 也能吃空格。输入是一长串空格、**没有**结尾 `*/` 时，引擎要尝试「空格里多少归 `.*`、多少归 `\\s*`」的每一种划分，再因缺 `*/` 失败、回溯。Snyk SNYK-JS-POSTCSS-1090595 的 PoC：

```javascript
"a{}/*# sourceMappingURL=" + " ".repeat(n) + "!"
```

本 case seed 用 n=90000。8.2.9 上 HTTP 打满 10s 超时。

---

## 维护者改了什么（CVE-2021-23368 修复，8.2.10）

8.2.10 只拿掉 `*/` 前面那个 `\\s*`。GitHub tag `8.2.10`：

```javascript
// lib/previous-map.js  (postcss@8.2.10)
getAnnotationURL(sourceMapString) {
    return sourceMapString.match(/\/\*\s*# sourceMappingURL=(.*)\*\//)[1].trim()
}

loadAnnotation(css) {
    let annotations = css.match(/\/\*\s*# sourceMappingURL=.*\*\//gm)
    if (annotations && annotations.length > 0) {
        let lastAnnotation = annotations[annotations.length - 1]
        if (lastAnnotation) {
            this.annotation = this.getAnnotationURL(lastAnnotation)
        }
    }
}
```

和 8.2.9 并排：`.*\s*\*/` → `.*\*/`，`(.*)\s*\*/` → `(.*)\*/`。

对 seed 这种「一个前缀 + 九万空格 + `!`、没有 `*/`」：

```text
.* 可以一次吃掉空格和 ! 直到 EOL
后面要的是 */，没有
没有「空格归谁」的第二套划分
回溯次数从指数落到可忽略 → 数毫秒结束，match 失败，parse 正常返回
```

这就是 v1 + `--seed` 退出码 10（延迟低于阈值）。

补丁默认了两件事：

1. 灾难性回溯只来自 `.*` 与 `\\s*` 对同一段空白的划分。
2. 留下贪婪 `.*` 去找 `*/` 是安全的，因为「找不到就很快失败」。

第二点在「很多个相同前缀、仍然没有 `*/`」时不成立。`/g` 会在每一个 `/*` 起点再开一轮；每一轮 `.*` 先吞到行尾再一格格吐出找 `*/`。前缀重复 n 次，工作量大约 O(n²)。

---

## 消毒之后，失败的 match 怎么接到 CPU 上

`String.prototype.match` 在**失败**时也要跑完引擎。`loadAnnotation` 没有超时、没有长度上限、没有「先看有没有 `*/`」。`opts.map.prev === true` 时这条路径必走。

`getAnnotationURL` 只在 `loadAnnotation` 已经拿到一处匹配后才调用。残余输入没有 `*/`，`annotations` 为空，`getAnnotationURL` 不会跑——但 `loadAnnotation` 自己的 `/g` match 已经把 CPU 吃完了。Snyk 两个 advisory 都点名 `loadAnnotation()` 和 `getAnnotationURL()`，因为两处正则结构相同。

过滤器刚看过的是「有没有 `\\s*` 歧义」；事件循环看到的是整次 `match` 的步数。没有第二次「回溯是否有界」的谓词。

Node 单线程：正则跑完之前 HTTP 响应写不出去。本 case 用 10s 客户端读超时观察挂起，并在每次探测前重启进程，因为卡住的事件循环无法被应用层打断。

---

## 仓库里已经在找 sourceMappingURL，没有禁止它再出现一次

`loadAnnotation` 的注释写 *Locate the last sourceMappingURL to avoid picking up sourceMappingURLs from comments, strings, etc.* 它用 `/g` 找**所有**匹配再取最后一个。这默认了「匹配会成功结束」。当输入是 N 段前缀、没有任何一段能配到 `*/` 时，`/g` 变成 N 次失败的贪婪扫描。

谁限制了 `.*` 的跨度：

| 版本 | `loadAnnotation` 正则 |
|---|---|
| 8.2.9 | `/\/\*\s*# sourceMappingURL=.*\s*\*\//gm` |
| 8.2.10 | `/\/\*\s*# sourceMappingURL=.*\*\//gm` |
| 8.2.13 | `/\/\*\s*# sourceMappingURL=(?:(?!sourceMappingURL=).)*\*\//gm` |

8.2.13 的 `(?:(?!sourceMappingURL=).)*` 不能跨过下一个 `sourceMappingURL=`，重复前缀时每一轮在下一前缀处停，失败是线性的。这个 tempered-greedy 在 8.2.10 **不存在**。8.2.10 只删了空白量词。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「空白划分 vs 多前缀回溯」落到具体字符串。

seed（CVE-2021-23368）：

```text
a{}/*# sourceMappingURL=   +  90000 个空格  +  !
```

V1：没有 `.*`/`\\s*` 双量词，快速失败。

residual（CVE-2021-23382，Snyk PoC 原样，n=24000）：

```javascript
function build_attack(n) {
    var ret = "a{}"
    for (var i = 0; i < n; i++) {
        ret += "/*# sourceMappingURL="
    }
    return ret + "!"
}
```

```text
a{}/*# sourceMappingURL=/*# sourceMappingURL= ... (24000 次) ... !
```

V1 正则 `/\/\*\s*# sourceMappingURL=.*\*\//gm`：

```text
在第 1 个 /* 处：.* 吞到 EOL，找不到 */，回溯
在第 2 个 /* 处：同样再扫剩余 n-1 段
...
总步数随 n 平方增长 → HTTP 10s 超时
```

Snyk 写 *caused mainly by the sub-pattern `\/\*\s*# sourceMappingURL=(.*)`*。8.2.10 删的是这个子模式**后面**的 `\\s*`，子模式自己的 `(.*)` / `.*` 还在。

V1 挡住的是「空格两种切法」；没挡住「同一个前缀出现很多次、闭合符永不出现」。两者都是 source map 注释正则在失败路径上的回溯，输入都没有合法 `*/`。

---

## 残余仍然走同一条 loadAnnotation 正则（CVE-2021-23382）

没有换 API、没有换文件。还是：

```http
POST /process  {"css":"a{}" + "/*# sourceMappingURL="*24000 + "!"}
```

`PreviousMap` 构造函数仍然 `loadAnnotation(css)`。V1 那条去掉 `\\s*` 的正则照样 `match`；match 在 `/g` 下对每个 `/*` 做一次贪婪失败。事件循环卡住，客户端超时。

本 case residual 写死为 24000 次前缀。和 Snyk / GHSA-566m-qj78-rww5 的 `build_attack` 同一构造。认证意图：v1 + `--residual` 延迟超过阈值；同一 V1 上空白 seed 已是数毫秒。

所以残余不是新洞面，而是同一正则上两件事叠在一起：修了与 `\\s*` 的歧义，留下了失败时仍要回溯的贪婪 `.*`；`/g` 把失败乘上前缀个数。seed 被挡住只说明「空白填充不再指数爆炸」，不说明「sourceMappingURL 注解读取不会再把 CPU 打满」。

---

## 后来又补了什么（CVE-2021-23382，8.2.13）

8.2.13：

```javascript
getAnnotationURL(sourceMapString) {
    return sourceMapString.match(
        /\/\*\s*# sourceMappingURL=((?:(?!sourceMappingURL=).)*)\*\//
    )[1].trim()
}
loadAnnotation(css) {
    let annotations = css.match(
        /\/\*\s*# sourceMappingURL=(?:(?!sourceMappingURL=).)*\*\//gm
    )
    ...
}
```

对残余输入：每一轮在下一个 `sourceMappingURL=` 处负向预查失败，不能把后续前缀吞进 `.*`，n 段就是 O(n) 次短失败。公开修复：postcss 8.2.13 与 7.0.36。commit `2b1d04c` 等见 OSV CVE-2021-23382。

即便如此，这仍然是「用更刁钻的正则近似线性」。输入仍可很长；本 case 把残余长度钉在约 5e5 字符，V2 上约 8ms。若还有其它灾难性子模式，需要另证。本 benchmark 的 v2 只关闭重复前缀这一条。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是 `.*` 后面那个空白量词。真正耗 CPU 的是「贪婪任意字符 + 必须出现的闭合符 + 闭合符不存在」。V2 才限制 `.*` 不能跨第二个 `sourceMappingURL=`。8.2.10 的 diff 里 `.*` 还在。

**不是没有更好的谓词。**  
可以先 `indexOf('*/')`，没有就直接返回；可以把注解解析改成线性扫描。仓库选择改正则。从 V1 只能看到 `\\s*` 消失；要判断补丁是否闭合，必须对**同一条** `.*\*/` 再喂 Snyk 四天后那条重复前缀 PoC。

**同一 `loadAnnotation`，只换了填充物。**  
空白和重复前缀都是「没有 `*/` 的伪注释」。flag 通道都是事件循环卡住。内部从「双量词划分」换成「多起点贪婪失败」。

**失败路径也是安全边界。**  
匹配成功时 `.*` 很短；匹配失败时它扫描整行。安全补丁若只按「合法注释还能否读出 URL」来测，会测不出 ReDoS。

---

## 版本、入口、参考

| | postcss | `loadAnnotation` 正则 | 空白填充 seed | 重复前缀 residual |
|---|---|---|---|---|
| V0 | 8.2.9 | `.*\s*\*/` | 指数回溯，HTTP 超时 | （不必，同样会慢） |
| V1 | 8.2.10 | `.*\*/` | 数毫秒 | `/g` × 贪婪失败，HTTP 超时 |
| V2 | 8.2.13 | `(?:(?!sourceMappingURL=).)*\*/` | 挡 | 线性失败，数毫秒 |

- Web：`POST /process` `{css}` → `postcss.parse`
- 认证意图：v0 seed 超时；v1 seed 快；v1 residual 超时。
- [CVE-2021-23368](https://nvd.nist.gov/vuln/detail/CVE-2021-23368)、[Snyk SNYK-JS-POSTCSS-1090595](https://security.snyk.io/vuln/SNYK-JS-POSTCSS-1090595)
- [CVE-2021-23382](https://nvd.nist.gov/vuln/detail/CVE-2021-23382)、[Snyk SNYK-JS-POSTCSS-1255640](https://security.snyk.io/vuln/SNYK-JS-POSTCSS-1255640)、[GHSA-566m-qj78-rww5](https://github.com/advisories/GHSA-566m-qj78-rww5)
- 源码：[previous-map.js @ 8.2.10](https://github.com/postcss/postcss/blob/8.2.10/lib/previous-map.js)、[8.2.13](https://github.com/postcss/postcss/blob/8.2.13/lib/previous-map.js)
