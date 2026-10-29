# Deno 2.7.1：有 `$VAR` 的参数走双引号，POSIX 双引号挡不住反引号

- Case：`PCBV2-0096`（`deno-cve-2026-32260`）
- 产品：Deno。本 case 并排安装官方 release 二进制 2.6.7 / 2.7.1 / 2.7.2；harness 用真实 `node:child_process` `spawnSync(cmd, {shell:true})`，cmd 以 `Deno.execPath()` 开头。
- 链：CVE-2026-27190（<2.6.8 → 2.6.8，进 2.7.1；GHSA-hmh4-3xvx-q5hr）→ CVE-2026-32260（2.7.0–2.7.1 → 2.7.2，GHSA-4c96-w8v2-p28j）
- 源码对着 tag `v2.7.1` 的 `ext/node/polyfills/internal/child_process.ts`：`transformDenoShellCommand` POSIX 分支。V0 对着 `v2.6.7` 的 blocklist + 无 quoting。V2 对着 `v2.7.2` 的 `unsafeInDoubleQuotes`。运行时是官方二进制里的 polyfill，不是抽出来的函数。

2.6.8 起，当 `shell:true` 的命令以 Deno 可执行文件开头时，`transformDenoShellCommand` 会重解析 CLI 参数并 **按参数加引号**，再交给 `/bin/sh -c`。POSIX 分支优先：若参数匹配 `/\$\{[^}]+\}|\$[A-Za-z_]/`，包进 **双引号**（为了保留变量展开）；否则若含元字符，包进 **单引号**。双引号在 POSIX sh 里 **不** 抑制 `` `cmd` `` 和 `$(cmd)`。于是同时带 `$X` 和反引号的参数会走第一支，反引号仍然执行。GHSA-4c96-w8v2-p28j：*This bypasses the fix for CVE-2026-27190*。

根因不只是「漏了一个元字符」。检查（加引号）按「像不像 `$VAR`」分流；真正解释命令替换的是 `/bin/sh` 的双引号语法。下面按 spawn 走进去、2.7.1 两段 `if` 的优先级、sh 如何消费加引号后的字符串、2.7.2 如何在进双引号之前再看一遍反引号，把这几层写完。

---

## 这块功能本来在干什么

Deno 的 Node 兼容层实现 `child_process.spawn/spawnSync`。`shell: true` 时会拼一条给系统 shell 的命令字符串。若这条命令是在调 Deno 自己（把 Node 的 `node script.js` 译成 `deno run ...`），还要改写 flag 并保证改写后的参数 **嵌进 shell 字符串时仍然只是参数**。

`transformDenoShellCommand` 就是这条边界：它认为自己输出的字符串对 `/bin/sh -c` 是安全的。应用侧典型用法：

```javascript
spawnSync(`${Deno.execPath()} ${userArg}`, { shell: true });
```

本 case harness：`GET /probe?arg=` → 上述 spawn。设计意图：`userArg` 即便含空格或元字符，也不该变成另一次命令。成功穿越之后的效果是 **`/bin/sh` 执行了参数里的命令替换**。金丝雀在 `/canary/flag.txt`，reader 是 `/canary/rf`（`cat` 该文件）。flag 出现在 Deno 的 `Module not found "<flag>"` 一类 stderr 里——替换结果被当成模块路径回显。被挡住时 stderr 里是字面 `` `%60` `` / 反引号，没有 flag。

数据流：

```text
userArg
    → command = execPath + " " + userArg
    → spawnSync(..., {shell:true})
         （polyfill 内）escape / parse
         transformDenoShellCommand(command)
              确认以 Deno 路径开头
              op_node_parse_shell_args
              op_node_translate_cli_args
              对每个 deno_args[i] 加引号     ← V1 补丁插在这里
         /bin/sh -c <transformed>
              若反引号仍活着：跑 /canary/rf
              输出插入后续 deno 参数 → stderr 含 flag
```

需要 `--allow-run`（本 harness 已开）。注入发生在 OS 进程层，不经过 Deno 的 JS 权限对「读 /canary」的细粒度拦截。

---

## 原始漏洞：命中 blocklist 就原样返回（CVE-2026-27190，2.6.7）

2.6.7 的 `transformDenoShellCommand` **不加引号**。翻译完参数后扫一张不完整的元字符表；命中则 `return command`（原始、未转义）；未命中则 `join(' ')` 仍然无引号：

```javascript
# child_process.ts :: transformDenoShellCommand  (v2.6.7 语义)
    for (let i = 0; i < result.deno_args.length; i++) {
      if (/[();&|<>`!]/.test(result.deno_args[i])) {
        return command;   // 原始命令，反引号到达 /bin/sh
      }
    }
    return prefix + " " + result.deno_args.join(" ");
```

seed：

```text
arg = run `/canary/rf`
```

反引号命中表，函数返回 **未改写的** `denoPath run `/canary/rf``。`/bin/sh` 做命令替换，`/canary/rf` 的 stdout（flag）插进 `run` 的参数，Deno 报模块找不到，stderr 含 `PCBFLAG_...`。v0 + `--seed` 退出码 0。

表里没有 `$()` 的完整形态、没有换行；即便有，命中后「返回原文」本身就是把元字符交给 shell。2.6.8 的修复方向是改成 **始终按参数 quoting**，而不是加长 blocklist。

---

## 维护者改了什么（CVE-2026-27190 修复，2.6.8 → 本 case V1=2.7.1）

quoting 写在 POSIX 的 `map` 里。tag `v2.7.1`：

```javascript
# ext/node/polyfills/internal/child_process.ts
# transformDenoShellCommand  (v2.7.1，约 L1286–1297)
        : result.deno_args.map((a) => {
          // POSIX: args with shell variable refs use double quotes to
          // preserve variable expansion. Other metacharacters use single
          // quotes.
          if (/\$\{[^}]+\}|\$[A-Za-z_]/.test(a)) {
            return '"' + a.replace(/"/g, '\\"') + '"';
          }
          if (/[();&|<>`!\n\r\s"'\\$]/.test(a)) {
            return "'" + a.replace(/'/g, "'\\''") + "'";
          }
          return a;
        });
```

注释写明优先级：先顾 `$VAR` 展开，再顾「其它元字符」。第二张表已经包含反引号 `` ` ``。

对 seed（`` run `/canary/rf` ``，无 `$` 变量形态）：

```text
arg 含 `  → 第二支
→ 单引号：'`/canary/rf`'
POSIX 单引号内反引号是字面量
→ /canary/rf 不执行
→ stderr 无 flag
```

v1 + `--seed` 退出码 10。

补丁默认：

1. 含 `$VAR` 的参数只需要保护双引号语义（转义内部 `"`），变量展开是特性。
2. 一张参数不会 **同时** 需要「展开变量」和「抑制命令替换」——或者说，若同时出现，展开优先。

第二点与 POSIX 双引号语法冲突：`"$X`/canary/rf`"` 里 `$X` 会展开，`` `...` `` **也会** 执行。

Windows 分支用 cmd 双引号和另一张元字符表（空格、`&|<>^`），不走 POSIX 这两支 `if`。本 case 镜像是 `debian:bookworm-slim`，`/bin/sh` 是 dash，遵守上表。GHSA 给的 CVSS 和固定版本（2.7.2）针对的也是这条 POSIX 路径。

---

## 检查之后谁真正消费那个值

`quotedArgs.join(" ")` 拼回 `prefix + " " + ...`，返回值成为 `spawn` 交给 `/bin/sh -c` 的命令。没有第二轮「再扫一遍反引号」。sh 按 POSIX 引号规则解析：

| 引号 | `$VAR` | `` `cmd` `` | `$(cmd)` |
|---|---|---|---|
| 单 `'...'` | 字面量 | 字面量 | 字面量 |
| 双 `"..."` | 展开 | **执行** | **执行** |
| 无 | 展开 | 执行 | 执行 |

过滤器选引号类型时看的是 JS 正则；shell 看的是已经加上的那一对引号字符。`$VAR` 检测为真就再也不会走到单引号分支，即使同一字符串里有 `` ` ``。

前面还有 `op_node_parse_shell_args` / `op_node_translate_cli_args`。advisory 把攻击链写成四步：

1. `escapeShellArg` 先用单引号包住参数（这一步本身是安全的）
2. `op_node_parse_shell_args` 分词时剥掉单引号定界符，载荷重新变成裸字符串
3. requote 看到 `$VAR` → 改套双引号
4. 双引号里的反引号由 `/bin/sh` 执行

无论是否经过这一剥/套，V1 POSIX 分支的最终形态对 residual 都是双引号。本 case 经验证：`$VAR`+反引号参数能活过 Rust ops，到达这段 `map`。harness 看到的 `output` 是 stdout+stderr 拼接；flag 出现在 Deno 把替换结果当成模块说明符回显的那一行，而不是 `/canary/rf` 自己把文件打到 stdout 再被 HTTP 原样转发——blocked 版本上同一位置出现的是字面反引号 / `%60`，所以「output 含 PCBFLAG」是在证明替换发生了。

---

## 仓库里已经有「单引号包元字符」的分支，只是排在后面

同一 `map` 的第二支已经把反引号列为必须单引号的字符。它不是缺失，是 **被第一支抢先**。把两支对调，或在第一支加「若含 `` ` `` / `$(` 则仍单引号」，就是 V2。

没有「永远单引号、用另一种方式保留 `$VAR`」的白名单路径。为了 Node 兼容（让 `shell:true` 下 `$PATH` 仍展开），维护者选择双引号，却没处理双引号里仍然活着的命令替换。

`isWindows` 分支不走这张 POSIX 表。更强的「unsafe in double quotes」谓词要到 2.7.2 才出现，且只挂在 POSIX 支。

---

## 这个补丁挡住了什么、没挡住什么

- 纯反引号、无 `$[A-Za-z_]` / `${...}`：单引号 → 字面量
- 带 `$X` 或 `${FOO}`：**无论是否还有反引号** → 双引号 → 反引号仍是命令替换

residual 的变换是加一个未定义变量前缀，把参数推进第一支：

```text
seed:      run `/canary/rf`
           V1 → run '`/canary/rf`'     （单引号）

residual:  run $X`/canary/rf`
           匹配 \$[A-Za-z_]  （$X）
           V1 → run "$X`/canary/rf`"
           sh： $X 展开为空； `/canary/rf` 仍执行
           flag 插入 deno 参数 → stderr
```

`$X` 不必存在。它的全部作用是让 JS 正则为真。没有换 sink、没有换 `shell:true`、没有换 `/canary/rf`。

seed 被挡住只说明「单独一个反引号会进单引号」，不说明「所有反引号都会进单引号」。

---

## 残余仍然走同一条 transformDenoShellCommand → /bin/sh（CVE-2026-32260）

平台 verify 的 residual 与 heldout 同一 probe：`arg` 不同，harness 相同，`spawnSync` + `transformDenoShellCommand` 相同。flag 通道相同（stderr 里的模块名）。不是另一个 API。

v1 + `--residual`：output 含 flag。v2：`unsafeInDoubleQuotes` 为真，改走单引号，`'$X`/canary/rf`'`，反引号字面量，无 flag。

GHSA 还提到 `$(...)` 与反斜杠在双引号里同样危险。本 case 固定用反引号，与 seed 同一替换语法，只多 `$X` 转向。

---

## 后来又补了什么（CVE-2026-32260，2.7.2）

POSIX 分支变成（V2 语义）：

```javascript
        const hasShellVarRef = /\$\{[^}]+\}|\$[A-Za-z_]/.test(a);
        const unsafeInDoubleQuotes = /`|\$\(|\\/.test(a);
        const hasShellMetachars = /[();&|<>`!\n\r\s"'\\$]/.test(a);

        if (hasShellMetachars) {
          if (hasShellVarRef && !unsafeInDoubleQuotes) {
            return '"' + a.replace(/"/g, '\\"') + '"';
          }
          return "'" + a.replace(/'/g, "'\\''") + "'";
        }
        return a;
```

对 residual 字符串逐步变成：

```text
输入 arg:     run $X`/canary/rf`
V1 输出片段:  "$X`/canary/rf`"
sh 展开:      `/canary/rf` 的 stdout（flag）替换进该位置
V2 输出片段:  '$X`/canary/rf`'
sh 展开:      五个字符 $ X ` / c ... 都是字面量，/canary/rf 不跑
```

`$X` 在 V2 里不再有「转向」作用：`unsafeInDoubleQuotes` 一旦为真，整段进单引号，变量也不再展开——这是故意用「少保留一点 Node 兼容」换「反引号不能活」。纯 `$HOME` 不含反引号，仍走双引号。

这仍是「按字符选引号」，不是禁止 `shell:true` 下的用户参数。对本 residual 足够。若还有 sh 在某种 locale/引号组合下把单引号解开的写法，需要另证。

---

## 从这条链还能看出什么

**维护者改错了哪一层。**  
他们按「参数像不像 shell 变量」选择引号类型，默认双引号能保住 `$VAR` 且同时能保住反引号。POSIX 不是这样。V2 承认双引号有一张自己的危险字符表。

**不是没有更强的 quoting。**  
第二支单引号已经能中和反引号。优先级把它放在 `$VAR` 后面。

**同一 sink 上元字符策略从 blocklist 进化到 quoting，quoting 仍按错误语法分流。**  
2.6.7：命中就放弃改写。2.7.1：改写了，但选错引号。两次都把活着的 `` ` `` 交给 `/bin/sh`。

**`$X` 是转向器，不是载荷。**  
载荷仍是 `/canary/rf`。读补丁时若只测「反引号还在不在表里」，会误判 2.7.1 已闭合。

**金丝雀只能靠执行读到。**  
`/canary/flag.txt` 不在参数原文里。output 出现 flag 证明命令替换跑了；出现 `%60` 证明反引号仍是字面量。

---

## 版本、入口、参考

| | 版本 | POSIX 改写 | seed `` run `/canary/rf` `` | residual `` run $X`/canary/rf` `` |
|---|---|---|---|---|
| V0 | 2.6.7 | blocklist 命中则返回原文，无 quoting | sh 执行反引号，stderr 含 flag | （不必） |
| V1 | 2.7.1 | `$VAR`→双引号，其它元字符→单引号 | 单引号，无 flag | 双引号，sh 仍执行反引号，含 flag |
| V2 | 2.7.2 | `$VAR` 且无 `` ` ``/`$(`/`\` 才双引号 | 单引号 | 单引号，无 flag |

- 入口：harness `GET /probe?arg=` → `spawnSync(execPath+" "+arg, {shell:true})`
- 认证：同一 sink；V1 关闭纯反引号；V1 `$VAR`+反引号仍执行；V2 关闭
- [CVE-2026-27190](https://nvd.nist.gov/vuln/detail/CVE-2026-27190)、[CVE-2026-32260](https://nvd.nist.gov/vuln/detail/CVE-2026-32260)
- [GHSA-hmh4-3xvx-q5hr](https://github.com/denoland/deno/security/advisories/GHSA-hmh4-3xvx-q5hr)、[GHSA-4c96-w8v2-p28j](https://github.com/denoland/deno/security/advisories/GHSA-4c96-w8v2-p28j)
- V1：[child_process.ts @ v2.7.1](https://github.com/denoland/deno/blob/v2.7.1/ext/node/polyfills/internal/child_process.ts) `transformDenoShellCommand`
- V0 对照：同文件 @ [v2.6.7](https://github.com/denoland/deno/blob/v2.6.7/ext/node/polyfills/internal/child_process.ts)
