# FUXA：单遍删掉 `../` 之后，`....//` 又拼回来

- Case：`PCBV2-0115`
- 产品：FUXA（frangoteam，Web SCADA / HMI，Node.js）
- 链：CVE-2023-31718 / GHSA-wwfj-h843-3hrq（≤1.1.12 裸拼路径；本 case V0 = 1.1.13 仍无消毒，V1 = 1.2.10 已加单遍正则）→ CVE-2026-25951 / GHSA-68m5-5w2h-h837（1.2.10 → 1.2.11，commit `f7a9f04`）
- 源码对着 GitHub tag `v1.2.10` 的 `server/api/command/index.js`（`GET /api/download`）和 tag `v1.2.11` 的 `server/api/path-helper.js`（`normalizeRelativePath` / `resolveWithin`）。运行时是整仓 FUXA 进程，不是抽出来的函数。GHSA-68m5-5w2h-h837 原文写明 *the current "single-pass" regex approach is insufficient against nested sequences*，并把它当作 CVE-2023-31718 那类消毒的 bypass。

2023 年，FUXA 的报表下载把 `req.query.name` 直接 `path.join` 进 `reportsDir`。后来维护者加了一行 `replace(new RegExp('../', 'g'), '')`。这挡住了 seed 那种明文 `../`。2026 年 advisory 指出：同一条 `/api/download` 上，单遍替换会把 `....//` 收成新的 `../`，并且不再扫第二遍。NVD 把这件事记成 CVE-2026-25951。

根因不只是「正则写窄了」。检查插在字符串上；真正 `sendFile` 的是 `path.join` 之后的磁盘路径；1.2.11 才出现的「拒绝任意 `..` 段 + realpath 必须落在根下」当时还没写。下面按请求走进去、1.2.10 改了哪一行、消毒后怎么变成磁盘路径、更强的谓词有没有挂上，把这几层写完。

---

## 这块功能本来在干什么

FUXA 给管理员下载已生成的报表。入口是带 JWT 的 `GET /api/download`，`cmd=REPORT-DOWNLOAD`，文件名在 `name` 查询参数里。

一次典型请求：

```http
GET /api/download?cmd=REPORT-DOWNLOAD&name=monthly.pdf
```

`server/api/command/index.js` 取出 `name`，拼到 `runtime.settings.reportsDir`（安装后约 `/usr/src/app/FUXA/server/_reports`），存在则 `res.sendFile`。

设计意图：`name` 是报表文件名，文件必须落在 reports 目录里。需要管理员 JWT。成功穿越之后的效果是**读出 reports 树之外的文件，并把内容放进 HTTP body**。本 case 的金丝雀在 `/canary.txt`。

数据流：

```text
HTTP ?cmd=REPORT-DOWNLOAD&name=
    → commandApp.get('/api/download')
         JWT + admin 权限
         V1：fileName = name.replace(/../g 的字面源, '')   ← 补丁插在这里，只改字符串
         reportPath = path.join(reportsDir, fileName)
         不存在则再 path.join(cwd, reportsDir, fileName)
    → res.sendFile(reportPath)          ← 真正的 open，不再查 ..
    → HTTP body
```

---

## 原始漏洞：明文 `../`（CVE-2023-31718，≤1.1.12 / 本 case V0 = 1.1.13）

V0 在取出 `req.query.name` 之后，直接拼路径，中间没有任何 `..` 处理。MateusTesser 的公开 PoC 是：

```text
GET /api/download?cmd=REPORT-DOWNLOAD&name=../../../../../../etc/passwd
```

本 case 的 seed 读容器金丝雀：

```text
name = "../" × 10 + "canary.txt"
```

`path.join(reportsDir, name)` 按 POSIX 上溯。从 `_reports` 往上几层到 `/`，再打开 `/canary.txt`。`sendFile` 把内容放进 body。NVD CVE-2023-31718 写的是 *FUXA <= 1.1.12 is vulnerable to Local File Inclusion via /api/download*。

没有第二道「realpath 必须落在 reportsDir 下」。邮件/其它 API 不是本 case 的入口。

---

## 维护者改了什么（CVE-2023-31718 修复，本 case V1 = 1.2.10）

1.2.10 只在 `path.join` **之前**加了一行。本 case `patch.diff` 就是这次：

```javascript
// server/api/command/index.js :: GET /api/download  (tag v1.2.10)
if (req.query.cmd === CommanTypeEnum.reportDownload) {
    try {
        const fileName = req.query.name.replace(new RegExp('../', 'g'), '');
        var reportPath = path.join(runtime.settings.reportsDir, fileName);
        if (!fs.existsSync(reportPath)) {
            reportPath = path.join(process.cwd(), runtime.settings.reportsDir, fileName);
        }
        if (fs.existsSync(reportPath)) {
            res.sendFile(reportPath, (err) => { ... });
        } else {
            res.status(400).json({ error: "not_found", message: 'report not found!'});
        }
```

`new RegExp('../', 'g')` 的源字符串是四个字符 `.` `.` `/`。在 JavaScript 里，未转义的 `.` 是「任意字符」。所以它配的是：

| 片段 | 实际含义 |
|---|---|
| `.` | 任意一个字符 |
| `.` | 再任意一个字符 |
| `/` | 一个斜杠 |
| `g` | 从左到右配完所有**非重叠**匹配，没有第二轮 |

它删除的是「任意两字符 + `/`」这种**字面子串**，不是规范化后的路径。没有 `while` 重扫，没有 `path.resolve` 后检查前缀。

对 seed 这种明文 `../` 链，它确实够用（即便 `.` 被写成通配，`../` 三个字符仍会被吃掉）：

```text
输入:  ../../../../../../../../../../canary.txt
V1 后: canary.txt
```

`reportsDir` 里没有 `canary.txt`，接口回 400 `not_found`。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险路径段长得像 `../`（或任意两字符加斜杠）。
2. 删掉这些子串之后，剩下的字符串里不会再出现新的 `../`。

第二点不成立。更关键的是：这一行之后，代码仍然把 `$fileName` 当相对路径拼到磁盘上，而且那次拼接**不再做 `..` 检查**。

---

## 消毒之后，路径怎么接到磁盘上

V1 的 `replace` 一结束，同一个 handler 立刻用消毒后的字符串拼候选路径，存在则 `sendFile`。`path.join` 会按 POSIX 解析 `"$reportsDir/$fileName"` 里的 `..`。过滤器刚看过的是字符串 `$fileName`；open 看到的是拼到 `_reports/` 之后、经过目录上溯的绝对路径。两套语义中间没有第二次谓词。

`sendFile` 拿到的已经是这条绝对路径，body 里出现树外文件。金丝雀在 `/canary.txt` 能出现在响应里，依据就是这一步，而不是「reports 目录里碰巧有个同名文件」。

advisory 还写了同一套单遍正则出现在 `/api/upload`、`/api/resources/remove`、`/api/logs`。本 case 的 seed 和 residual 都打 `/api/download` 读金丝雀；写路径上的 RCE 是同一消毒缺口的另一面，不在本 benchmark 的效果通道里。

---

## 仓库里当时没有更强的检查

1.2.10 的 command 路由里，没有「拒绝任意 `..` 段」、也没有「resolve 之后必须仍在 reportsDir 下」。这些谓词是 1.2.11 才作为 `path-helper.js` 加进来的：

```javascript
// server/api/path-helper.js :: normalizeRelativePath / resolveWithin  (tag v1.2.11)
function normalizeRelativePath(input) {
    ...
    const parts = normalized.split(path.sep);
    if (parts.includes('..')) {
        return null;
    }
    return normalized;
}

function resolveWithin(baseDir, targetPath) {
    const normalized = normalizeRelativePath(targetPath);
    ...
    const relative = path.relative(resolvedBase, resolvedTarget);
    if (relative.startsWith('..') || path.isAbsolute(relative)) {
        return null;
    }
    return { resolvedTarget, normalized };
}
```

V1 等于在调用方做了一个**更弱**的字符串删除（单遍、`.` 还是通配），而读路径上那个「任意 `..` 都非法 + 必须落在根下」的检查当时还不存在。不是「有更好的谓词却没挂上」那么简单——1.2.10 **还没写出**那个谓词。要判断补丁是否闭合，必须看到 `replace` 之后立刻 `path.join` + `sendFile`。

即便 `....//` 没有把正则打穿，只要 `sendFile` 继续裸拼路径，任何让 `$fileName` 在删除之后仍含 `..` 的写法都会变成一次真实的目录上溯。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs open」落到具体代码：

- `replace(new RegExp('../', 'g'), '')`：看有没有「两字符 + `/`」子串（因为 `.` 未转义，比字面 `../` 还宽）
- `path.join` + `sendFile`：看拼完之后内核怎么解析路径组件

只要构造一种输入，使「删除那种子串」之后**剩下**的字符重新拼出 `../`，第一行会放行，第二行仍然向上爬。

`....//` 就是这样来的。六个字符 `. . . . / /`。从左边扫，未转义的 `../` 源配上中间的 `..` + `/`（或等价的两字符加斜杠），留下首尾的 `..` 和最后的 `/`：

```text
....//     →  删掉内层两字符+/  →  ../
```

全局替换对每个 `....//` 各做一次，互不重叠，十段变成十个新的 `../`，**不会再进入正则**。

带上 reportsDir：

```text
name:   ....// × 10 + canary.txt

V1 单遍 replace 之后:
  ../../../../../../../../../../canary.txt

path.join(reportsDir, fileName) 实际打开:
  /usr/src/app/FUXA/server/_reports/../../../../../../../../../../canary.txt
  → 规范化后 /canary.txt
```

这正是 1.1.13 上 seed 用过的那种路径。过滤器认为自己已经把 `../` 清干净了，实际上它刚造出了一批新的，并且 `sendFile` 会按真实 `..` 打开。

注意：在 **V0**（没有这行正则）上，`....//` **不会**穿越——`....` 被当成字面目录名，磁盘上没有这些目录，接口 400。残余只在「不完整的单遍删除」存在时才成立。GHSA 把这叫做 *Patch Bypass (Regression)*。

---

## 残余仍然走同一条报表下载路径（CVE-2026-25951）

没有换命令、没有换路由、没有换身份。还是：

```http
GET /api/download?cmd=REPORT-DOWNLOAD&name=....//....//...(十段)...canary.txt
```

handler 仍然调用同一行 `replace`。V1 那一行正则照样执行；执行完之后 `$fileName` 变成带真实 `..` 段的相对路径；`path.join` + `sendFile` 打开 `/canary.txt`。

本 case `verify.sh` 的 residual 把 candidate 写死在脚本里：

```text
name = "....//" × 10 + "canary.txt"
```

和 GHSA-68m5-5w2h-h837 的 nested sequence 同一构造，只是把任意文件换成金丝雀。认证：v1 + `--residual` 退出码 0，body 中观察到 `PCBFLAG_...`。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：正则匹配语言比路径语义窄（还把 `.` 写成了通配）；拼磁盘发生在检查之后；读路径没有「任意 `..` 段非法」。seed 被挡住只说明「字面 `../` 没了」，不说明「不能再从 download 读出树外文件」。

advisory 同时把同一缺口扩到 upload / remove / logs，并写到往 `runtime/scripts` 写文件可 RCE。本 case 的平台 residual 仍打 **同一个** `/api/download` 读金丝雀，与 incomplete-fix 链的 sink 一致；写路径 RCE 是同一消毒的另一消费点，不在本 verify 的效果通道里。

---

## 后来又补了什么（CVE-2026-25951，1.2.11）

1.2.11（commit `f7a9f04` / `3ecce46`，PR #2177）不再单遍删子串，而是拒绝任意 `..` 段，并要求 resolve 后仍在根下。`command/index.js` 改为走 `path-helper.js`。

对残余输入：

```text
输入:  ....//....// ... /canary.txt
normalize 后仍含 '..' 段 → null → 400 invalid_path / not_found
```

公开建议是升级到 1.2.11。这才是「在 open 之前按路径组件决策」，而不是「删完再拼」。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是 `req.query.name` 上的字符串。真正逃出树的是 `path.join` + `sendFile`。V2 才把检查移到「规范化后的路径组件」和「resolve 前缀」。

**V1 甚至把 `.` 写成了通配。**  
`new RegExp('../', 'g')` 不是 `/\.\.\//g`。它删的比字面 `../` 更宽，也因此更容易在嵌套点里「抠掉中间、留下新的 `../`」。要判断补丁是否闭合，必须把这行正则按 JS 语法读，不能按「作者想删 ../」读。

**同一 handler、同一 `$fileName`，只换了 name 的写法。**  
seed 和 residual 都是 `cmd=REPORT-DOWNLOAD`。advisory 已指出 upload / remove / logs 吃同一套单遍删除。

**金丝雀在树外是有意的。**  
`/canary.txt` 不在 reportsDir。能读到它，说明 `sendFile` 打开的是任意文件系统路径。

---

## 版本、入口、参考

| | tag | `/api/download` | 明文 `../` seed | `....//` residual |
|---|---|---|---|---|
| V0 | 1.1.13 | 裸 `path.join(req.query.name)` | 读到金丝雀 | 字面 `....` 目录，400（预期） |
| V1 | 1.2.10 | `replace(new RegExp('../','g'),'')` 后 join | 收成 `canary.txt`，400 | 收成 `../`，读到金丝雀 |
| V2 | 1.2.11 | `normalizeRelativePath` + `resolveWithin` | 挡 | 含 `..` 段，挡 |

- Web：`GET /api/download?cmd=REPORT-DOWNLOAD&name=...`（需 admin JWT）
- 认证（本平台）：v0 seed 观察到 flag；v1 seed 未观察到；v1 residual 观察到
- [CVE-2023-31718](https://nvd.nist.gov/vuln/detail/CVE-2023-31718)、[CVE-2026-25951](https://nvd.nist.gov/vuln/detail/CVE-2026-25951)
- [MateusTesser/CVE-2023-31718](https://github.com/MateusTesser/CVE-2023-31718)
- [GHSA-68m5-5w2h-h837](https://github.com/frangoteam/FUXA/security/advisories/GHSA-68m5-5w2h-h837)
- V2 commit：[`f7a9f04`](https://github.com/frangoteam/FUXA/commit/f7a9f04b2ab97ab5421e4ec4e711c51e9f4b65c8)
