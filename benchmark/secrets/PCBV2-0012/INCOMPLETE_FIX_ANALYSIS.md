# shell-quote：字符串分支改了 `[A-z]`，对象 op 仍用 `/(.)/g`

- Case：`PCBV2-0012`
- 产品：npm `shell-quote`（ljharb）。`quote(tokens)` 声称把每个 token 收成对 shell 无害的字面量，再交给 `child_process.exec('/bin/sh -c ...')`。
- 链：CVE-2021-42740（1.7.2 → 1.7.3，把 `[A-z]` 收成 `[A-Za-z]`）→ CVE-2026-9277（1.7.3 → 1.8.4，对象 op 从逐字符 `/(.)/g` 改成算符白名单 + 拒绝行终止符）
- 源码对着 GitHub tag `v1.7.3` 的 `index.js` `exports.quote`，以及 1.8.4 的 `quote.js`。运行时装的是发布包本身。

2021 年，shell-quote 修了字符串分支里 Windows 盘符正则：`[A-z]` 在 ASCII 上连着 `Z` 到 `a` 中间的 `` ` `` `[` `\` `]` `^` `_`，反引号会被第一组吃掉再原样吐出。1.7.3 把类改成 `[A-Za-z]`。GHSA-w7jw-789q-3m8p / CVE-2026-9277 写明：*The `.op` field was backslash-escaped character by character using `/(.)/g`, which in JavaScript does not match line terminators.* POSIX shell 把裸换行当命令分隔符。

根因不只是「正则又写窄了」。检查插在 `quote()` 的**字符串** `else` 分支；真正进 `/bin/sh` 的是整段拼接结果；同一函数里对象分支用另一套转义，1.7.3 的 diff 碰都没碰。下面按 token 走进去、1.7.3 改了哪一行、转义之后谁消费那串命令、更强的 op 白名单有没有挂上，把这几层写完。

---

## 这块功能本来在干什么

`quote()` 是 `parse()` 的逆操作：给定字符串或 `{op: '&&'}` 这类对象，吐出一行应当可以安全塞进 `sh -c` 的文本。应用侧一次典型用法：

```javascript
child_process.exec('/bin/sh -c ' + JSON.stringify('echo ok ' + quote(tokens)))
```

本 case 的 harness 把用户 JSON 数组交给真实 `quote()`，再 `exec`。金丝雀在 `/canary/flag.txt`，只有执行了种植的无参读文件命令才会出现在 stdout。

数据流：

```text
HTTP JSON tokens[]
    → quote(xs)
         若 typeof s === 'object' → s.op.replace(/(.)/g, '\\$1')   ← 1.7.3 没动
         否则按引号 / 空白走几个字符串分支
         最后一个 else：盘符正则 + 元字符转义                 ← CVE-2021-42740 只改这里
    → 空格 join
    → /bin/sh -c "echo ok " + 结果
    → stdout 里有没有 PCBFLAG
```

设计意图：无论 token 是字符串还是 parse() 吐出的 op 对象，进 shell 之后都不应再引入新的命令边界。成功穿越之后的效果是：**quote 以为转义过了，sh 却执行了第二段命令**，读出树外金丝雀。

---

## 原始漏洞：`[A-z]:` 把反引号留在输出里（CVE-2021-42740，1.7.2）

1.7.2 字符串 else 分支：

```javascript
return String(s).replace(/([A-z]:)?([#!"$&'()*,:;<=>?@\[\\\]^`{|}])/g, '$1\\$2');
```

`$1` 是「可选的盘符」，原样保留；`$2` 才加反斜杠。`[A-z]` 包含反引号（ASCII 96）。token `` `:;rf`:; `` 里，前导 `` `: `` 被第一组吃掉，反引号不进第二组，输出里留下命令替换：

```text
quote(["`:;rf`:;"])  →  `:;rf`:;     （反引号未转义）
/bin/sh 执行 `:;rf`  （以冒号粘在命令名上的 command substitution）
```

因为 `$1` 总是「某字符 + 冒号」，替换词以 `:` 开头，字符串分支里的其它分隔符仍会被 `$2` 转义，所以达不到任意多参数 RCE。本 case 在 PATH 里放了一个字面名为 `:;rf` 的脚本，内容是 `cat /canary/flag.txt`。OSV / NVD CVE-2021-42740：*the Windows drive letter regex character class is [A-z] instead of [A-Za-z]*。

---

## 维护者改了什么（CVE-2021-42740 修复，1.7.3）

1.7.3 只改字符串 else 那一个字符类。对象分支原样留下。GitHub `v1.7.3` 的 `quote`：

```javascript
// index.js  (shell-quote@1.7.3)
exports.quote = function (xs) {
    return xs.map(function (s) {
        if (s && typeof s === 'object') {
            return s.op.replace(/(.)/g, '\\$1');
        }
        else if (/["\s]/.test(s) && !/'/.test(s)) {
            return "'" + s.replace(/(['\\])/g, '\\$1') + "'";
        }
        else if (/["'\s]/.test(s)) {
            return '"' + s.replace(/(["\\$`!])/g, '\\$1') + '"';
        }
        else {
            return String(s).replace(/([A-Za-z]:)?([#!"$&'()*,:;<=>?@\[\\\]^`{|}])/g, '$1\\$2');
        }
    }).join(' ');
};
```

和 1.7.2 的唯一差：`[A-z]` → `[A-Za-z]`。

对 seed `` `:;rf`:; ``，它确实够用：反引号不再被盘符组吃掉，落入第二组，变成 `` \`\:\;rf\`\:\; ``，`echo ok` 只是打印字面量，PATH 里的 `:;rf` 不会作为命令替换跑起来。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险元字符只会从**字符串 token** 进来。
2. 对象分支的 `/(.)/g` 已经「每个字符都加了反斜杠」，等于中和完毕。

第二点不成立。JavaScript 的 `.` 默认不匹配行终止符（`\n` `\r` U+2028 U+2029），除非加 `s` 标志。`quote` 没有给这支正则加 `s`。

---

## 消毒之后，那串文本怎么接到 /bin/sh 上

对象分支一结束，结果直接 `join(' ')` 进 `exec`。没有第二轮「输出里是否还有未转义的换行 / 反引号」检查。

```javascript
// 1.7.3 对象分支，输入 {op: ';\n/canary/rf'}
s.op.replace(/(.)/g, '\\$1')
```

对每个**被 `.` 匹配到的**字符前面加 `\`：

```text
;  →  \;
\n →  （不匹配，原样留下）
/  →  \/
c  →  \c
...
```

拼进命令行：

```text
echo ok \;
/canary/rf
```

`\;` 是字面分号。裸换行是 POSIX 命令分隔符，第二行执行 `/canary/rf`。harness 种的 `/canary/rf` 无参数 `cat` 金丝雀——因为空格也会被 `/(.)/g` 转义，带参数的命令会被粘成一个词。

过滤器刚看过的是「每个 `.` 匹配的字符」；shell 看到的是整段文本里的换行。两套「什么叫一个字符」中间没有第二次谓词。

`parse()` 自己会把 `&&` `||` `;` 收成 `{op: s}`，文档允许调用方直接构造这种对象，也允许 `parse(cmd, envFn)` 的 `envFn` 返回对象 token。CVE 记录写明两条都是公开 API。

---

## 仓库里已经有更完整的转义，对象分支没用

同一份 `quote` 里：

- 双引号分支已经转义 `` ` $ ! \ " ``
- 字符串 else 分支有一张元字符表（含反引号）
- 对象分支却按「任意字符 + 反斜杠」的弱模式走，且 `.` 漏行终止符

谁用了「每个字符都转义」的完整点类：

| 分支 | 转义 |
|---|---|
| 字符串 else（1.7.3） | 元字符表 + 盘符组，不含换行（换行会走带空白的引号分支） |
| 对象 op（1.7.3） | `/(.)/g`，漏 `\n` `\r` U+2028 U+2029 |
| 对象 op（1.8.4） | op 必须在 `OPS` 白名单里，否则 TypeError；真正转义改用 `[\s\S]` |

1.7.3 修字符串时，对象那一行就在上面三行。diff 只动了 `[A-z]`。不是没有「把 op 限制成 parse 会吐出的那几个算符」这种更强谓词——`parse` 的 `CONTROL` 正则已经是那张名单。**quote 的对象分支没有复用它**。

字符串 token 里的裸换行会走 `/["\s]/` 分支被单引号包起来，所以「字符串换行」在 V1 上并不是这条残余。残余**专门**要对象 op 这条路。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「盘符类 vs `.` vs shell」落到具体变换：

- `[A-Za-z]:`：看是不是 Windows 盘符，决定反引号进不进 `$1`
- `/(.)/g`：看 BMP 里除行终止符以外的单个字符
- `/bin/sh`：看换行、反引号、`;`、`&&` 这些命令边界

seed `` `:;rf`:; `` 在 V1 上被挡住，只说明反引号不再能经盘符组漏出。换一条分支：

```text
tokens = [{op: ';\n/canary/rf'}]

quote 输出:  \; \n \/canary\/rf   （换行未加反斜杠）
sh -c:      echo ok \;
            /canary/rf
```

GHSA-w7jw-789q-3m8p：*A line terminator in `.op` therefore passed through unescaped into the output; POSIX shells treat a literal `\n` as a command separator.*

V1 改的是字符串 else；`{op: ...}` 根本不进那一支。`/(.)/g` 里的点不是两个点那种路径把戏，它就是 JS 正则「任意字符」的默认定义，文档写明不含行终止符。

---

## 残余仍然走同一个 quote() → exec 出口（CVE-2026-9277）

没有换 sink、没有换 flag 文件。还是：

```text
POST tokens=[{"op":";\n/canary/rf"}]
→ quote() → /bin/sh -c "echo ok ..." → stdout
```

`quote` 仍然先判断 `typeof s === 'object'`。V1 那一行 `s.op.replace(/(.)/g,'\\$1')` 照样执行；执行完之后输出里仍有裸 `\n`；sh 当命令分隔符。

本 case residual 写死为：

```text
tokens = [{"op": ";\n/canary/rf"}]
```

和 advisory 的 `{ op: '...\n...' }` 同一构造，第二段换成无参读金丝雀。认证意图：v1 + `--residual` 在 command output 中观察到 `PCBFLAG_...`。反引号 seed 在同一 V1 上不再注入。

所以残余不是新洞面，而是同一函数上两套转义叠在一起：修了字符串盘符类，没修对象分支的 `.`；join 之后立刻 `exec`，没有「输出必须是单一命令」的谓词。seed 被挡住只说明「这一条反引号写法没了」，不说明「quote 的输出不能再引入新的 sh 命令」。

---

## 后来又补了什么（CVE-2026-9277，1.8.4）

1.8.4 把对象分支换成形状校验。GHSA 列的行为：

- `{op}`：`op` 必须是 parse 会吐出的那张表（`||` `&&` `;` `|` …）。其它值 `TypeError`。
- `{op:'glob', pattern}`：`pattern` 不得含行终止符。
- `{comment}`：comment 不得含行终止符。
- 其它对象：`TypeError`。

Debian tracker 指向 commit `4378a6e`（tag v1.8.4）。对残余输入 `{op:';\n/canary/rf'}`：`';\n/canary/rf'` 不在 `OPS` 里，抛 TypeError，命令根本不会被拼出来。公开建议是升级到 `shell-quote@1.8.4`。

即便如此，这仍然依赖「调用方把 quote 的异常当失败」。本 benchmark 的 v2 在 TypeError 时视为挡住。白名单比「给 `.` 加上 `s` 标志」更宽：U+2028 / 注释换行 / 未知对象形状一并关掉。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是字符串 else 的盘符类。真正进 shell 的是所有分支 join 后的那一行。对象分支就在被改那一行上面，1.7.3 的 diff 把它当无关上下文。V2 才把 op 收到 parse 已经在用的算符表上。

**不是没有更好的谓词。**  
`parse` 的 `CONTROL` 已经是 op 白名单。字符串分支已经有元字符表。对象分支用 `.` 是「每个字符加反斜杠」的近似，近似在 JS 正则里不成立。从 V1 的 diff 只能看到 `[A-z]`→`[A-Za-z]`；要判断补丁是否闭合，必须看到 `typeof s === 'object'` 那一支，以及 `.` 与行终止符的关系。

**同一 `quote()`，只换了 token 的形状。**  
字符串反引号和对象换行都是「元字符没被中和 → exec 多跑一条命令」。flag 通道都是 stdout 里的金丝雀。内部走的不是同一条 `replace`。

**quote 的契约是「输出是惰性字面量」，不是「我们转义了看起来危险的字符」。**  
1.8.4 用允许的 op 集合，比继续打补丁正则更接近契约。1.7.3 仍在用逐字符反斜杠，所以漏掉 `.` 不匹配的那一类码点是结构性的。

---

## 版本、入口、参考

| | npm | 字符串 else | 对象 op | `` `:;rf`:; `` seed | `{op:';\\n/canary/rf'}` residual |
|---|---|---|---|---|---|
| V0 | 1.7.2 | `[A-z]:` 漏反引号 | `/(.)/g` | command substitution，金丝雀 | （不必） |
| V1 | 1.7.3 | `[A-Za-z]:` | 同上 | 反引号被转义 | 裸换行当命令分隔符，金丝雀 |
| V2 | 1.8.4 | 保留 | op 白名单 + 拒绝行终止符 | 挡 | TypeError，挡 |

- Web：JSON `tokens` → `quote()` → `sh -c`
- 认证意图：v0 seed 在 output 观察到 flag；v1 seed 无注入；v1 residual 观察到 flag。
- [CVE-2021-42740](https://nvd.nist.gov/vuln/detail/CVE-2021-42740)、[OSV](https://osv.dev/vulnerability/CVE-2021-42740)
- [CVE-2026-9277](https://www.cve.org/CVERecord?id=CVE-2026-9277)、[GHSA-w7jw-789q-3m8p](https://github.com/advisories/ghsa-w7jw-789q-3m8p)
- 源码：[index.js @ v1.7.3](https://github.com/ljharb/shell-quote/blob/v1.7.3/index.js)、修复提交 [4378a6e](https://github.com/ljharb/shell-quote/commit/4378a6e613db5948168684864e49b42b83134d2d)（v1.8.4）
