# simple-git argv-parser：六键配置黑名单里没有 `filter.smudge`

- Case：`PCBV2-0192`
- 产品：npm `simple-git` + 依赖 `@simple-git/argv-parser`。运行时 `simple-git@3.14.1`（无 parser）/ `@3.35.2` 钉死 `argv-parser@1.0.3` / `@3.36.0` + `argv-parser@1.1.1`，各在独立 `node_modules` 树里，经 `git.clone(remote, dest, inject)` 调真实 `git`。
- 链：CVE-2022-25912（3.14.1 → 3.15.0 起拦 `protocol.*.allow`）→ CVE-2026-6951（3.35.2+1.0.3 → 3.36.0+1.1.1，拓宽配置键黑名单）
- 源码对着 `simple-git@3.35.2` 的 `block-unsafe-operations-plugin.ts`（只转调 `parseArgv`），以及 jsDelivr 上的 [`@simple-git/argv-parser@1.0.3` `dist/index.cjs`](https://cdn.jsdelivr.net/npm/@simple-git/argv-parser@1.0.3/dist/index.cjs) 与 `1.1.1`。金丝雀是 benign：`cat /canary/flag.txt>/canary/out.txt`。

GHSA-hffm-xvc3-vprc / NVD 对 CVE-2026-6951 的摘要：*incomplete fix for CVE-2022-25912 that blocks the `-c` option but not the equivalent `--config` form … enabling `protocol.ext.allow=always` and using an `ext::` clone source.* 这是**同一条 ext:: 运输**上 `-c` vs `--config` 的写法差。

本 case 钉住的 V1 是 3.35.2 + **argv-parser 1.0.3**。1.0.3 的 `U()` 已经把 `-c` 和 `--config` 都标成 `inline` 配置，GHSA 写的那种 `--config protocol.ext.allow` 在这套字节上会走进同一份键黑名单。平台残余改用 `-c filter.pcb.smudge=<cmd>`：仍经过 `parseArgv` → `vulnerabilities` → `git.clone` spawn，但 Git 侧执行钩子是 **checkout 的 smudge filter**，不是 seed 的 `ext::` 运输。下面按 V1 源码把这两层分开写。

---

## 这块功能本来在干什么

`simple-git` 允许调用方把 `-c key=value` 塞进 `git clone`。若干 git config 会在 clone/checkout 时 exec 外部命令。3.35.2 把检测完全交给 argv-parser：

```ts
// simple-git/src/lib/plugins/block-unsafe-operations-plugin.ts  (simple-git@3.35.2)
import { parseArgv } from "@simple-git/argv-parser";

export function blockUnsafeOperationsPlugin(options = {}) {
   return {
      type: 'spawn.args',
      action(args) {
         const parsed = parseArgv(...args);
         for (const vulnerability of parsed.vulnerabilities.vulnerabilities) {
            if (options[vulnerability.category] !== true)
               throw new GitPluginError(undefined, "unsafe", vulnerability.message);
         }
         return args;
      },
   };
}
```

设计意图：没打开对应 `allowUnsafe*` 时，不能用 `-c` 打开危险配置。成功穿越之后的效果是：**Git 在 clone 过程中跑了注入的命令**，金丝雀被写到 `/canary/out.txt`。

数据流：

```text
git.clone(remote, dest, ['-c', 'protocol.ext.allow=always'])   // seed
git.clone(file:///repo.git, dest, ['-c', 'filter.pcb.smudge=<cmd>'])  // 平台残余
    → spawn.args 插件
         parseArgv(...args)
              认出 -c / --config 为 inline 配置（U()）
              对 write 配置键跑列表 j[]
         命中则 GitPluginError；否则原样 args
    → spawn('git', ['clone', '-c', key=val, remote, dest])
    → seed：ext:: 运输跑 helper
      残余：checkout 时跑 filter.<name>.smudge
```

3.35.2 的 `package.json` 写 `"@simple-git/argv-parser": "workspace:^"`；发布到 npm 后 caret 是 `^1.0.3`，**今天再 `npm install simple-git@3.35.2` 会漂到已修复的 1.1.x**，V1 环境会假阴性。本 case 用 overrides 把 V1 钉在发布当时的 1.0.3，分析也必须对着这份 dist，而不是仓库 `workspace:^` 解析出来的最新 parser。

---

## 原始漏洞：`-c protocol.ext.allow=always` + `ext::`（CVE-2022-25912，3.14.1）

3.14.1 没有 block-unsafe 的配置键检查。seed：

```text
remote = ext::sh -c 'cat /canary/flag.txt>/canary/out.txt' ignored-arg
inject = ['-c', 'protocol.ext.allow=always']
```

Git 允许 `ext::` 协议后，clone URL 里的命令在本机执行。v0 上 out.txt 出现 flag。

---

## 维护者改了什么（CVE-2022-25912 修复，落到 1.0.3 的键表）

argv-parser 1.0.3 把「会 exec 的配置」收成六条（压缩后的 `j` 数组）：

```js
// @simple-git/argv-parser@1.0.3 dist/index.cjs
function g(e, t, n = String(e)) { /* key 匹配 → { category, message } */ }

const j = [
  g(/^\s*protocol(.[a-z]+)?.allow/i, "allowUnsafeProtocolOverride", "protocol.allow"),
  g("core.sshCommand",  "allowUnsafeSshCommand"),
  g("core.fsmonitor",   "allowUnsafeFsMonitor"),
  g("core.gitProxy",    "allowUnsafeGitProxy"),
  g("core.hooksPath",   "allowUnsafeHooksPath"),
  g("diff.external",    "allowUnsafeDiffExternal"),
];
```

inline 配置的识别：

```js
function U({ name: e }) {
  if (e === "-c" || e === "--config") return "inline";
  if (e === "--config-env") return "env";
}
```

`A()` 在第一个 `=` 切开 key/value 并 `toLowerCase()`。所以 `-c Filter.PCB.Smudge=cmd` 也会变成 key `filter.pcb.smudge`。1.0.3 的 `g("core.sshCommand")` 是整串匹配，不会对 `filter.pcb.smudge` 做「中间段通配」；1.1.1 的 `i("filter.smudge")` 才会。

V1 谓词的字面意思：解析出来的配置 **key** 必须命中这六条之一才报 `allowUnsafe*`。`protocol(.[a-z]+)?.allow` 带 `/i`，`protocol.ext.allow` 和 `PROTOCOL.ALLOW` 都会中。`-c` 与 `--config` 在 1.0.3 已经等价。

对 seed 这种 `-c protocol.ext.allow=always`，它确实够用：正则命中 `allowUnsafeProtocolOverride`，插件抛错，`ext::` 不跑。这就是 v1 + `--seed` 退出码 10。同一份 1.0.3 里 clone 的短选项表 `E.clone.short` 仍把 `u` 标成 `needsNext: true`，pack 注入由另一个生成器 `$()` 用 `/^-\w*u/` 去拦——那是 0191 已经加宽过的簇规则，**不是**本条配置键缺口。

补丁默认了两件事：

1. 危险配置就是这六种名字（外加 pack 相关的 `-u`）。
2. 挡住 `protocol.*.allow` 之后，就不能再靠 `-c` 让 Git 在 clone 时 exec。

第二点不成立。Git 在 checkout 时还会跑 `filter.<driver>.smudge`。

---

## 检查之后谁真正去 exec

`parseArgv` 只返回漏洞列表，**不改 args**。插件要么抛错要么原样 `return args`。随后 `spawn('git', args)`。Git 读 `-c filter.pcb.smudge=...`，在检出 blob 时把 smudge 当过滤器命令执行（通常经 shell）。过滤器刚看过的是「key 在不在六元素数组」；Git 看到的是「这个 config 要不要 fork」。中间没有「凡是会 exec 的 config 都拒绝」的第二道谓词。

`parseArgv` 先用 `T()` 吃掉全局 flag（含 `-c`/`--config` 的 `needsNext`），再认 task 名 `clone`，再用 `W()` 吃 task 级 flag。`F()` 把所有 inline 配置收成 `config.write[]`，最后 `j[]` 对每个 write key 跑一遍。`filter.pcb.smudge` 会先被 `A()` 在 `=` 处切开、`toLowerCase()`，再拿去测那六条——字符串相等和 `protocol...allow` 正则都配不上，于是 `vulnerabilities` 为空。

seed 的消费者是 `ext::` 运输；平台残余的消费者是 smudge filter。都是同一次 `git clone` 进程里的外部命令，但不是同一个 Git 钩子。

---

## 仓库里已经有更强的「会 exec 的键」，filter 没用上

1.0.3 已经收了 `core.sshCommand`、`core.fsmonitor`、`core.hooksPath`、`diff.external`——都是「Git 跑外部程序」。`filter.*.smudge` / `filter.*.clean` 是同一类（gitattributes 过滤器），不在表里。1.1.1 用 `i("filter.smudge", "allowUnsafeFilter")` 补上，并一口气加了 `core.pager`、`credential.helper`、`gpg.program`、`merge.driver` 等。

谁在 1.0.3 会被标成漏洞：

| 配置键 | 1.0.3 |
|---|---|
| `protocol.ext.allow` / `protocol.allow` | 是（正则，含 `/i`） |
| `core.sshCommand` / `fsmonitor` / `hooksPath` / `gitProxy` | 是 |
| `diff.external` | 是 |
| `filter.<x>.smudge` / `filter.<x>.clean` | **否** |
| `--config` 形式的上述键 | 是（`U()` 已认 `--config`） |

不是仓库里没有「配置能 exec」这个类别，是 **表只抄了 2022 年那几条知名键**。GHSA 强调的 `--config` 别名，在这组 V1 字节里已经不是洞；洞在表的覆盖面。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「六键表 vs Git 会 exec 的 config」落到具体 argv：

- V1 过滤器：`j[]` 对 inline 配置 key 做正则/字符串匹配
- Git clone：任何漏网的 `-c` 都会进进程，按该键的语义执行

```text
seed（-c protocol.ext.allow=always + ext:: URL）:
  protocol...allow 命中 → GitPluginError
  （若改用 --config protocol.ext.allow：1.0.3 的 U() 同样标成 inline，仍命中）

平台残余（-c filter.pcb.smudge=<cmd> + file:// 仓库）:
  key 不在 j[] → spawn
  → checkout 跑 smudge → out.txt 出现 flag
```

**和 GHSA 摘要不是同一条 Git 钩子。** GHSA-hffm 写的 residual 是 `--config` + 仍然走 `protocol.ext.allow` + `ext::`。V1=argv-parser@1.0.3 已把 `--config` 映射到同一 walker，那条公开写法在本 V1 上应被挡住。平台残余改打 `filter.smudge`：同一 `parseArgv` 黑名单缺口，**不同的 Git 执行点**（smudge vs ext::）。若只复现 advisory 字面，会误以为 V1 仍能用 `--config` 打开 ext::。

---

## 残余仍然走 parseArgv，但 Git 侧换了钩子

没有换 `git.clone`、没有换 `spawn.args` 插件。换的是 `-c` 的 **key** 和 clone **URL 形态**：

```js
await git.clone('file:///srv/repo.git', dest, [
  '-c', 'filter.pcb.smudge=cat /canary/flag.txt>/canary/out.txt'
]);
```

（仓库侧还需 gitattributes 让某个路径走这个 filter；harness 在本地 bare repo 里备好。）`filter.pcb.smudge` 里的 `pcb` 是 driver 名，Git 匹配的是 `filter.<name>.smudge` 这种多段键；1.1.1 用 `i("filter.smudge", ...)` 做「任意中间段」匹配，1.0.3 没有对应条目。插件仍然 `parseArgv`；1.0.3 的 `j[]` 照样认不出；`spawn` 照样发生。seed 被挡住只说明「`protocol.*.allow` 没了」，不说明「所有会在 clone 时 exec 的 `-c` 都没了」。

---

## 后来又补了什么（CVE-2026-6951，argv-parser 1.1.1）

3.36.0 改调 `vulnerabilityCheck(args, env)`，依赖升到 argv-parser ^1.1。1.1.1 的表包括：

```text
filter.clean / filter.smudge  → allowUnsafeFilter
core.pager / core.editor / core.askPass / sequence.editor
credential.helper / gpg.program
merge.driver / mergetool.cmd / ...
protocol.allow 仍在，另筛 GIT_* 环境变量
```

对平台残余：`filter.smudge` 命中 `allowUnsafeFilter`，抛错，smudge 不跑。公开建议升级到 simple-git 3.36.0。GHSA 写的 `--config`+ext:: 在 1.0.3 已拦、在 1.1.1 也拦。

即便如此，这仍然是「再列一批键名」。对本条 smudge 够用。本 benchmark 的 v2 只关闭这一条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是「若干已知危险 config 的名字」。真正 exec 的是 Git 对每个 config 的语义。V2 把表加长，并开始扫环境变量，仍是名单而不是「禁止 clone 时的全部 hook」。

**不是没有同类键。**  
`core.hooksPath` / `core.fsmonitor` 已经在 1.0.3 里。`filter.smudge` 是同一类「路径上的外部命令」。从 3.35.2 插件的 diff 几乎看不出名单；要判断是否闭合，必须打开 **钉死版本的** `argv-parser` dist，而不是 caret 漂过的那份。

**同一 `parseArgv`、同一 `-c`，只换了 key。**  
`protocol.ext.allow` 死；`filter.*.smudge` 活。GHSA 还指出历史上 `-c` vs `--config` 的别名问题——在 1.0.3 源码里 `U()` 已经合并，和本平台残余不是一回事。

**插件名单和 Git 钩子不是一层。**  
挡住运输协议，挡不住过滤器；挡住 `-c`，在更老的插件里挡不住 `--config`。每一层都要单独对照 Git 文档里「会运行命令的配置」。

**金丝雀在 Git 子进程里是有意的。**  
能在 `/canary/out.txt` 读到 flag，说明 smudge（或 seed 的 ext:: helper）真的跑了——也就是 `j[]` 放行了那条 `-c`。file:// 仓库把残余限制在本地 checkout，避免再走一遍已挡住的 ext::。

**V2 换了插件入口。**  
3.36.0 不再 `parseArgv(...args).vulnerabilities`，而是 `vulnerabilityCheck(args, env)`，把 `GIT_EDITOR` / `GIT_PAGER` 一类环境变量也纳入。平台残余不靠环境变量，靠的是 1.1.1 新增的 `filter.smudge → allowUnsafeFilter`。

1.0.3 对 write 配置的扫描只有 `j[]` 这一圈：

```text
parseArgv('-c', 'filter.pcb.smudge=cat /canary/flag.txt>/canary/out.txt', ...)
    U("-c") → inline
    A("filter.pcb.smudge=...") → key=filter.pcb.smudge
    j[]：protocol.allow 正则否；五个 core/diff 字符串否
    vulnerabilities = []
    spawn git clone -c filter.pcb.smudge=... file:///srv/repo.git
    checkout → smudge → out.txt 有 flag
```

GHSA-hffm 若拿去打 1.0.3，`--config protocol.ext.allow=always` 会在 `U()` 之后仍进 `j[]` 的 protocol 正则，应被挡住。所以「官方摘要 residual」和「本平台 residual」必须分开写，不能从 `verify.sh` 反推 GHSA，也不能从 GHSA 字面覆盖掉 V1 dist 里已经合并的 `--config`。

smudge 要生效，clone 必须真的 checkout 带该 filter 的 blob；bare repo + 默认 checkout 满足这一点。`listRemote` 只读引用、不跑 smudge，所以残余必须走 `clone` 而不是 `ls-remote`。

`core.fsmonitor` 已在 1.0.3 黑名单里，不能当本条残余；漏的是 filter 这一类，不是「所有 hook」。

1.1.1 的 `i("filter.clean")` 与 `i("filter.smudge")` 成对出现，本条只打 smudge。

---

## 版本、入口、参考

| | 版本 | 配置键表 | `-c protocol.ext.allow` seed | `--config` + ext::（GHSA 字面） | `-c filter.smudge`（平台残余） |
|---|---|---|---|---|---|
| V0 | 3.14.1 | 无 | ext:: 执行，flag | （不必） | （不必） |
| V1 | 3.35.2 + argv-parser **1.0.3 钉死** | 六键，`U()` 已认 `--config` | `GitPluginError` | 应挡住（与 GHSA 针对的更老插件不同） | spawn，smudge 执行，flag |
| V2 | 3.36.0 + argv-parser 1.1.1 | 含 `filter.smudge` 等 | 挡 | 挡 | `allowUnsafeFilter` |

- 库 API：`simpleGit().clone(remote, dest, ['-c', 'key=val'])`
- [CVE-2022-25912](https://nvd.nist.gov/vuln/detail/CVE-2022-25912)、[CVE-2026-6951](https://nvd.nist.gov/vuln/detail/CVE-2026-6951)
- [GHSA-hffm-xvc3-vprc](https://github.com/advisories/GHSA-hffm-xvc3-vprc)（摘要是 `--config`+ext::；与平台 smudge 残余不是同一 Git 钩子）
- V1 源码：[`simple-git@3.35.2` 插件](https://github.com/steveukx/git-js/blob/simple-git@3.35.2/simple-git/src/lib/plugins/block-unsafe-operations-plugin.ts)、[`argv-parser@1.0.3` dist](https://cdn.jsdelivr.net/npm/@simple-git/argv-parser@1.0.3/dist/index.cjs)
- V2：[`argv-parser@1.1.1`](https://cdn.jsdelivr.net/npm/@simple-git/argv-parser@1.1.1/dist/index.cjs) 中 `i("filter.smudge","allowUnsafeFilter")`
