# simple-git：锚定的 `-u` 挡不住 Git 的短选项簇

- Case：`PCBV2-0191`
- 产品：npm `simple-git`（Node 里拼 `git` 命令行）。运行时 `simple-git@3.15.1` / `@3.31.1` / `@3.32.0` 整包，经 `git.clone(remote, dest, [inject])` 调用真实 `git` 二进制。
- 链：CVE-2022-25860（3.15.1 → 3.16.0 起带 `/^\s*-u\b/`，本 case V1 钉在 3.31.1）→ CVE-2026-28291（3.31.1 → 3.32.0，短选项簇字符类）
- 源码对着 tag `simple-git@3.31.1` / `@3.32.0` 的 `simple-git/src/lib/plugins/block-unsafe-operations-plugin.ts`。金丝雀是 benign：注入的 upload-pack 只 `cat /canary/flag.txt>/canary/out.txt`，clone 源是本地 `file:///srv/repo.git`。

GHSA-jcxm-m3jx-f287 原话：*The vulnerability was introduced by an incorrect patch for CVE-2022-25860.* PoC 是 `git.clone(..., ['-vu sh -c "touch /tmp/pwned"'])`，即使 `allowUnsafePack: false`。advisory 还列出 `-4u` / `-nu` / `-qu` / `-su` 等「三个字符就能执行」的簇。

根因不只是「正则少写了几种」。检查插在「这个 argv 元素是不是以 `-u` 加词边界开头」上；真正去 exec 的是 Git 自己的短选项解析。插件里已经有对 `--upload-pack` 的整段匹配，短选项却用了锚定 `^\\s*-u\\b`。下面按调用走进去。

---

## 这块功能本来在干什么

`simple-git` 把用户给的 options 数组原样塞进 `git <task> ...`。`clone` 的 `-u` / `--upload-pack=<cmd>` 让 Git 在 fetch 时把「服务端」换成任意命令。库默认 `allowUnsafePack=false`，应在 spawn 前拒绝。一次典型调用：

```js
const git = require('simple-git')();
await git.clone('file:///srv/repo.git', dest, ['-u', 'cat /canary/flag.txt>/canary/out.txt #']);
```

`blockUnsafeOperationsPlugin` 的类型是 `spawn.args`：在真正 `child_process.spawn` 之前扫一遍 args。设计意图：没显式打开 unsafe 时，clone 不能带 upload-pack。成功穿越之后的效果是：**本机 Git 把注入的命令当 upload-pack 跑起来**，金丝雀文件被 cat 到 `/canary/out.txt`。

数据流：

```text
git.clone(url, dest, [inject...])
    → plugins['spawn.args']
         blockUnsafeOperationsPlugin.action(args, { method: 'clone' })
              preventUploadPack(arg, 'clone')
                   /^\s*--(upload|receive)-pack/
                   /^\s*-u\b/          ← V1 只认「单独的 -u」
         返回同一份 args
    → spawn('git', ['clone', ...args, url, dest])
    → git 把 -vu<cmd> 解析成 -v + -u=<cmd> → exec cmd
```

没有网络。`file://` 本地仓库时 Git 仍会调 upload-pack 助手。simple-git 把用户数组拼在 `git clone` 的 option 位置，不经 shell——注入靠的是 Git 自己把某个 option 当成要 exec 的命令路径，而不是 `sh -c` 拼进整条命令行。这和「参数注入进 git 的 upload-pack」是同一 sink。

---

## 原始漏洞：`--upload-pack` / `-u` 直接进 argv（CVE-2022-25860，3.15.1）

3.15.1 的 unsafe 插件主要拦 `-c protocol.allow`（CVE-2022-25912 那条），**没有** clone 的 `-u` 检查。seed 用分开的两个 argv 元素 `['-u', '<cmd>']` 或 `--upload-pack=<cmd>`，Git 执行 cmd。v0 上 `/canary/out.txt` 出现 flag。

---

## 维护者改了什么（CVE-2022-25860 修复，3.16.0 起 / 本 V1=3.31.1）

3.16.0 引入这条 clone 守卫之后，一直到 3.31.1 插件文件都是 1990 字节、同一份 `/^\s*-u\b/`（本 case 把 V1 钉在 3.31.1，避免和后续 3.32.0 字符类搅在一起）。`preventUploadPack`：

```ts
// simple-git/src/lib/plugins/block-unsafe-operations-plugin.ts  (simple-git@3.31.1)
function preventUploadPack(arg: string, method: string) {
   if (/^\s*--(upload|receive)-pack/.test(arg)) {
      throw new GitPluginError(..., `Use of --upload-pack or --receive-pack is not permitted...`);
   }
   if (method === 'clone' && /^\s*-u\b/.test(arg)) {
      throw new GitPluginError(..., `Use of clone with option -u is not permitted...`);
   }
   if (method === 'push' && /^\s*--exec\b/.test(arg)) {
      throw new GitPluginError(..., `Use of push with option --exec is not permitted...`);
   }
}

export function blockUnsafeOperationsPlugin({ allowUnsafePack = false, ... } = {}) {
   return {
      type: 'spawn.args',
      action(args, context) {
         args.forEach((current, index) => {
            const next = index < args.length ? args[index + 1] : '';
            allowUnsafeProtocolOverride || preventProtocolOverride(current, next);
            allowUnsafePack || preventUploadPack(current, context.method);
         });
         return args;
      },
   };
}
```

V1 谓词的字面意思（clone）：这个**单个 argv 字符串**以可选空白 + `-u` + 词边界开头。` -u` 能配；`-vu` 不能，因为 `^\\s*-u` 要求减号后面立刻是 `u`。没有把短选项簇拆开，没有问 Git「这里会不会被理解成 `--upload-pack`」。

对照：

```text
arg = "-u"           /^\s*-u\b/  → 命中
arg = "  -u"         命中（允许空白）
arg = "-u=cmd"       -u 后是 =，\b 在 u 与 = 之间仍可能命中；随后 Git 把 = 后当命令
arg = "-vu cat ..."  减号后是 v → 不命中
arg = "-4u..."       减号后是 4 → 不命中
arg = "--upload-pack=cmd"  走另一条正则，命中
```

对 seed 这种独立 token `-u`，它确实够用：`/^\\s*-u\\b/` 为真，抛 `GitPluginError`，`spawn` 不发生。这就是 v1 + `--seed` 退出码 10。`--upload-pack=` 同样被第一条正则挡住。

补丁默认了两件事：

1. 危险短选项长得像单独的 `-u`。
2. Git 不会把别的三个字符的 token 理解成「含 u 的 upload-pack」。

第二点不成立。Git 的短选项可以簇在一起：`-vu` = verbose + upload-pack。

---

## 检查之后谁真正去 exec

插件 `return args` 之后，simple-git 照样 spawn。Git 对 `-vu<cmd>` 的解析（POSIX 短选项簇 + 需要参数的 `u`）把 `u` 后面的内容当 upload-pack 命令。过滤器刚看过的是「这个字符串是不是以 `-u` 开头」；Git 看到的是「这个簇里有没有 `u`」。中间没有第二次按 Git 语法拆 flag。

`isConfigSwitch` 只认 trim 后小写等于 `-c`，和本条无关（那是 0192 的配置键链）。`allowUnsafePack` 默认 false，本应让 `preventUploadPack` 每次都跑——它跑了，只是正则认不出簇。GHSA 的 PoC 还显式传 `unsafe: { allowUnsafePack: false }`，说明即使用户把「安全模式」打开，簇仍然活。

Git 对需要参数的短选项：簇里一旦碰到 `u`，**后面剩下的字符都当成 `-u` 的参数**（不必再开一个 argv 元素）。所以 `-vu cat ...` 既可以是一个字符串，也可以被理解成 `-v` + `-u=cat ...`。插件按「一个 argv 元素 / 一条正则」扫，从来没有模拟这套吸收规则。`listRemote` 等 method 不进 `method === 'clone'` 分支，但本 case 只打 `clone`。

---

## 仓库里已经有更强的匹配，短选项没用

同一函数里，`--upload-pack` 用的是「出现这段长选项」而不是「整个 token 等于 `--upload-pack`」：`/^\\s*--(upload|receive)-pack/` 能配 `--upload-pack=cmd`。短选项却要求 token **从开头就是** `-u`。Git 自己把 `-u` 和 `--upload-pack` 当成同一件事；插件用了两套宽严不同的语言。

谁拦 upload-pack（3.31.1）：

| 形态 | 是否挡住 |
|---|---|
| `--upload-pack=cmd` / `--receive-pack` | 是 |
| 独立 `-u` / `-u cmd`（第二个元素） | 是（`^\\s*-u\\b`） |
| `-vu` / `-4u` / `-nu` / `--u` | **否** |
| `push --exec` | 是（另一分支） |

不是仓库里没有「这是 pack 助手」这个概念，是 **短选项那一支正则比 Git 的簇规则窄**。advisory 说完整模拟 Git 解析「几乎不可能」；3.32.0 退而求其次，用字符类覆盖 bruteforce 找到的那一组。插件对每个 arg **单独** `test`，不会把 `['-v','-u', cmd]` 这种拆开的合法写法漏掉——那是 seed 的形态，V1 能挡；漏的是「一个 token 里同时带 v 和 u」。

`push --exec` 那一支同样锚定 `/^\s*--exec\b/`，理论上也有长选项别名问题；本 case 不打 push。`preventProtocolOverride` 只在 `isConfigSwitch` 为真时看 **下一个** arg 是否像 `protocol.*.allow`，和 `-vu` 无关。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「锚定 -u」和「Git 短选项簇」落到具体 argv：

- V1 过滤器：`method==='clone' && /^\\s*-u\\b/.test(arg)`
- Git：`-vu<cmd>` → `-v` + `-u=<cmd>` → exec

```text
seed（['-u', '<cmd>'] 或 ['--upload-pack=<cmd>']）:
  /^\s*-u\b/ 或 --upload-pack 命中 → GitPluginError

residual（['-vu<cmd>']，一个 argv 元素）:
  字符串以 -v 开头，不是 -u
  → 正则失败 → spawn
  → git 执行 cmd → /canary/out.txt 出现 flag
```

GHSA 的 PoC 就是 `` `-vu sh -c "touch /tmp/pwned"` ``。本 case 把命令换成 cat 金丝雀，观察的是同一扇门。

---

## 残余仍然走同一条 git.clone spawn（CVE-2026-28291）

没有换 method、没有换 `file://` 仓库、没有换 `allowUnsafePack` 默认值。还是：

```js
await git.clone(REPO, dest, ['-vu cat /canary/flag.txt>/canary/out.txt #']);
```

插件仍然对每个 arg 调 `preventUploadPack(..., 'clone')`。V1 那一行 `^\\s*-u\\b` 照样配不上 `-vu...`；`spawn` 照样发生；Git 照样把簇里的 `u` 当 upload-pack。平台残余和 seed 都是 clone 的 pack 助手注入。不是 `filter.smudge` 或 `ext::` 另一条 Git 功能（那些是 0192 的配置键链）。

seed 被挡住只说明「单独的 `-u` token 没了」，不说明「Git 不会从短选项簇里读出 upload-pack」。

---

## 后来又补了什么（CVE-2026-28291，3.32.0）

3.32.0 把 clone 短选项改成「减号簇里是否含 `u`」：

```ts
// simple-git@3.32.0
const CLONE_OPTIONS = /^\s*(-|--|--no-)[\dlsqvnobucj]+/;

function isCloneSwitch(char: string, arg: string | unknown) {
   return Boolean(typeof arg === 'string' && CLONE_OPTIONS.test(arg) && arg.includes(char));
}

if (method === 'clone' && isCloneSwitch('u', arg)) {
   throw new GitPluginError(..., `Use of clone with option -u is not permitted...`);
}
```

对残余输入：`-vu...` 配上字符类（含 `v`、`u`），`includes('u')` 为真，抛错，金丝雀命令不跑。字符类 `[\dlsqvnobucj]` 来自 GHSA bruteforce 里出现过的簇字母（`4`/`6`/`l`/`n`/`q`/`s`/`v`/`o`/`b`/`u`/`c`/`j`），不是 Git 规范的完备集。公开建议升级到 3.32.0。advisory 自己也写：Git 合法变体近乎无穷，黑名单很难穷尽。

即便如此，这仍然是「在 spawn 前用正则近似 Git」。对本条 `-vu` 够用。本 benchmark 的 v2 只关闭这一条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是「argv 字符串长得像 `-u`」。真正 exec 的是 Git 的选项解析。V2 仍在同一插件加码，但按簇里是否出现危险字母来近似。

**不是没有更宽的匹配。**  
`--upload-pack` 已经按前缀配。从 V1 的 diff 只能看到加了 `^\\s*-u\\b`；要判断是否闭合，必须看到 Git 把 `-vu` 拆成 `-v` 和 `-u`。

**同一 `preventUploadPack`、同一 `clone`，只换了 token 写法。**  
独立 `-u` 死；簇里带 `u` 活。GHSA 用 bruteforce 扫出一串三个字符的活口。

**插件正则和 Git 语法不是一层。**  
词边界 `\\b` 在 `-u` 后面是对的，前提是 `u` 紧跟在第一个减号后。簇把这个前提打掉。

**金丝雀在 Git 子进程里是有意的。**  
flag 不在 clone 的 HTTP/stdout 里。能在 `/canary/out.txt` 读到它，说明 upload-pack 助手真的跑了——也就是插件把那串 args 原样交给了 `git`。clone 随后因无法协商 pack 而失败、harness 接到 `clone_error`，不影响已经写完的 out.txt。

**`--u` 也在 GHSA 的 bruteforce 列表里。**  
`/^\s*-u\b/` 要求第一个 `-` 后面立刻是 `u`；`--u` 是两个减号，同样配不上，Git 在部分版本里仍会把它当 upload-pack。V2 的 `CLONE_OPTIONS` 含 `--` 前缀和字符类，对 `--u` 也比 V1 宽。本 case 残余用 advisory PoC 同款 `-vu`。

spawn 前后对照：

```text
V1 preventUploadPack("-vu cat /canary/flag.txt>/canary/out.txt #", "clone")
    /^\s*-u\b/  → false
    return args 原样
    spawn git clone -vu cat ... file:///srv/repo.git <dest>
    git: -v + -u=cat ... → 助手跑起来 → out.txt 有 flag

V2 isCloneSwitch('u', "-vu cat ...")
    CLONE_OPTIONS 命中且 includes('u') → GitPluginError
    不 spawn
```

`context.method` 来自 simple-git 对 `clone()` 的任务名，不是用户伪造的 HTTP method。把 inject 丢给 `listRemote` 会走另一条 Git 命令，本 case 不这么打。

3.32.0 的 `CLONE_OPTIONS` 还允许 `--` / `--no-` 前缀，避免只扫单减号。`isCloneSwitch` 额外要求 `arg.includes(char)`，所以 `-v` 单独不会因为字符类里有别的字母而被误判成含 `u`。

`--upload-pack` 长选项在 V1/V2 都拦；残余只打短选项簇，不改长选项那一支。

插件 `return args` 从不改写 token，只选择抛不抛。

---

## 版本、入口、参考

| | 版本 | clone `-u` 谓词 | `--upload-pack` | 独立 `-u` seed | `-vu` residual |
|---|---|---|---|---|---|
| V0 | 3.15.1 | 无 | 无 | 执行，flag | （不必） |
| V1 | 3.31.1 | `/^\\s*-u\\b/` | 有 | `GitPluginError` | Git 拆簇执行，flag |
| V2 | 3.32.0 | `isCloneSwitch('u')` 字符类 | 有 | 挡 | `GitPluginError` |

- 库 API：`simpleGit().clone(url, dest, options)`；本 case HTTP：`GET /run?inject=`
- [CVE-2022-25860](https://nvd.nist.gov/vuln/detail/CVE-2022-25860)、[CVE-2026-28291](https://nvd.nist.gov/vuln/detail/CVE-2026-28291)
- [GHSA-jcxm-m3jx-f287](https://github.com/steveukx/git-js/security/advisories/GHSA-jcxm-m3jx-f287)
- V1 源码：[`simple-git@3.31.1` `block-unsafe-operations-plugin.ts`](https://github.com/steveukx/git-js/blob/simple-git@3.31.1/simple-git/src/lib/plugins/block-unsafe-operations-plugin.ts)
- V2 tag：[`simple-git@3.32.0` 同行](https://github.com/steveukx/git-js/blob/simple-git@3.32.0/simple-git/src/lib/plugins/block-unsafe-operations-plugin.ts)
