# Git：ssh 主机名的 `-` 挡住了，子模块 url 的 `-` 还在

- Case：`PCBV2-0116`
- 产品：Git（`git clone --recurse-submodules`）
- 链：CVE-2017-1000117（2.13.4 → 2.14.1，commits `2491f77b` / `820d7650` / `3be4cf09` / `aeeb2d49`）→ CVE-2018-17456（2.14.1 → 2.19.1，commits `1a7fd1fb` / `a124133e`）
- 源码对着 GitHub tag `v2.14.1` 的 `connect.c`（`git_connect` / `git_proxy_connect`）、`path.c`（`looks_like_command_line_option`）和 tag `v2.19.1` 的 `builtin/submodule--helper.c`（`clone_submodule` 里的 `--`）。运行时是三个 tag 从源码编出来的真实 `git` 二进制，不是抽出来的函数。GitHub Blog 原文写明 *This vulnerability [CVE-2018-17456] is very similar to CVE-2017-1000117 ... except that the option-injection is against the child git clone itself*。

2017 年 8 月，Git 给交给 `ssh` / proxy 的 host、port、path 加了「以 `-` 开头就 `die`」。这挡住了 seed 那种 `ssh://-oProxyCommand=...`。14 个月后，同一条 `git clone --recurse-submodules` 上，`.gitmodules` 的 `url` 仍被原样放进子进程 `git clone` 的 argv。以 `-` 开头的 url 被当成 `--upload-pack`。NVD 把这件事记成 CVE-2018-17456。

根因不只是「少拦了一个字段」。检查插在 `connect.c` 的 SSH 传输层；真正把 `.gitmodules` 的 url 变成 argv 的是 `submodule--helper` 再 spawn 的 `git clone`；谓词 `looks_like_command_line_option` 已经写好，却只挂在 connect 一侧。下面按 clone 走进去、2.14.1 改了哪几行、检查之后谁消费那个字符串、更宽的挂载点有没有接上，把这几层写完。

---

## 这块功能本来在干什么

Git 允许仓库用 `.gitmodules` 声明子模块。受害者执行：

```text
git clone --recurse-submodules <superproject>
```

Git 读 `.gitmodules` 的 `url` 和 `path`，再 spawn 子进程去取子模块。SSH 形态会走到 `git_connect` → 子进程 `ssh`；本地/未知协议会走到 `git clone <url> <path>`。

设计意图：`url` 是远程地址，`path` 是工作区相对路径。成功穿越之后的效果是：**父进程认为自己在 clone 子模块，子进程却把以 `-` 开头的值当成选项执行**——本 case 用 `/pcb-probe.sh` 回显 `PCB_HIT <flag>` 证明执行。

数据流（两条兄弟消费点，同一份 `.gitmodules`）：

```text
.gitmodules  url / path
    → git clone --recurse-submodules
         读 url、path
         ├─ ssh://...  → connect.c :: git_connect
         │                 V1：looks_like_command_line_option(ssh_host)  ← 补丁只插在这里
         │                 spawn ssh <host> ...
         └─ 其它 / 再一层 clone
                           submodule--helper → git clone <url> <path>
                           V1：url 原样进 argv，没有 --，没有 looks_like_...
                           spawn git clone -u/pcb-probe.sh sm:sm
```

没有 HTTP 服务。本 case 的 SUT 是编出来的 `git`；SSH 侧的 seed 用环境里的旧 ssh stub（现代 OpenSSH ≥7.6 会自己拒 dash-host），差分仍完全由 git 的 `connect.c` 守卫决定。residual 不经过 ssh，不需要这层 stub。

`.gitmodules` 是普通 ini。父仓库可以是本地路径；`--recurse-submodules` 一读到 `url` / `path` 就按上面两条路 spawn。受害者不必 `git submodule add`，clone 超级工程就够。

---

## 原始漏洞：ssh 主机名以 `-` 开头（CVE-2017-1000117，2.13.4）

2.13.4 的 `git_connect` 把 URL 里解析出的 `ssh_host` 直接推进 `ssh` 的 argv。Brian Neel / Joern Schneeweisz / Jeff King 的问题是：`ssh://-oProxyCommand=...` 的 host 是 `-oProxyCommand=...`，ssh 把它当选项。NVD CVE-2017-1000117 写的是 *a crafted "ssh://..." URL ... can result in any program that exists on the victim's machine being executed*，并点名 `.gitmodules` + `git clone --recurse-submodules`。

本 case 的 seed：

```text
url  = ssh://-oProxyCommand=pcb-probe/x
path = sm
```

2.13.4 没有 dash 检查，ssh stub 执行 probe，输出 `PCB_HIT <flag>`。这就是 v0 + `--seed` 退出码 0。

`.gitmodules` 的 `url` 字段本身当时也没有「不能以 `-` 开头」的检查。当时没人拿它当 SSH host 问题的一部分。

---

## 维护者改了什么（CVE-2017-1000117 修复，2.14.1）

2.14.1 抽出一个谓词，只挂在 connect 一侧。`path.c`：

```c
// path.c :: looks_like_command_line_option  (tag v2.14.1)
int looks_like_command_line_option(const char *str)
{
	return str && str[0] == '-';
}
```

`cache.h` 的注释写明：*Returns true iff "str" could be confused as a command-line option when passed to a sub-program like "ssh". ... we're assuming here that the string makes it verbatim to the sub-program.*

然后只在三处调用：

```c
// connect.c :: git_proxy_connect  (tag v2.14.1, 约 L579–582)
if (looks_like_command_line_option(host))
    die("strange hostname '%s' blocked", host);
if (looks_like_command_line_option(port))
    die("strange port '%s' blocked", port);

// connect.c :: git_connect  (约 L830–831, L866–867)
if (looks_like_command_line_option(path))
    die("strange pathname '%s' blocked", path);
...
if (looks_like_command_line_option(ssh_host))
    die("strange hostname '%s' blocked", ssh_host);
```

对 seed 这种 SSH host，它确实够用：

```text
ssh_host = -oProxyCommand=pcb-probe
→ fatal: strange hostname '-oProxyCommand=pcb-probe' blocked
```

probe 不会跑。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险值是交给 **ssh / proxy** 的 host、port、path。
2. 其它把 `.gitmodules` 值推进子进程 argv 的路径，要么不会经过 connect，要么已经安全。

第二点不成立。谓词已经写成「任意可能被当成选项的字符串」，却只挂在 connect。

---

## 检查之后，谁真正消费那个值

V1 的 `die` 只发生在 `git_connect` 解析 SSH URL 之后。子模块更新的另一条路是：`submodule--helper` 自己再 `run_command` 一次 `git clone`，把 `.gitmodules` 的 `url` 当作**位置参数**推进 argv。2.14.1 的这条路上**没有** `looks_like_command_line_option`，也没有 `--` 分隔符。

2.19.1 才在 `clone_submodule` 里加上 `--`（对比用）：

```c
// builtin/submodule--helper.c :: clone_submodule  (tag v2.19.1, 约 L1234–1238)
if (gitdir && *gitdir)
    argv_array_pushl(&cp.args, "--separate-git-dir", gitdir, NULL);

argv_array_push(&cp.args, "--");
argv_array_push(&cp.args, url);
argv_array_push(&cp.args, path);
```

V1 没有这两行 `--`。于是：

```text
git clone --no-checkout ... -u/pcb-probe.sh sm:sm
```

`git clone` 把 `-u/pcb-probe.sh` 解析成 `--upload-pack=/pcb-probe.sh`。`path` 里的 `:`（`sm:sm`）让 `url_is_local_not_ssh` 为假，传输层走 smart options，`uploadpack` 覆盖生效，probe 被当成 upload-pack 程序执行。exploit-db 45631 / staaldraad 的 writeup 把这条 argv 写死了。

过滤器刚看过的是「交给 ssh 的 host」；真正执行的是「交给子 `git clone` 的 url」。两套 argv 中间没有第二次谓词。

---

## 仓库里已经有更强的检查，clone argv 没用

`looks_like_command_line_option` 的注释说的是 *sub-program like "ssh"*，语义其实是「原样进子进程 argv 的字符串」。谁调用它（2.14.1）：

| 调用点 | 调用了？ |
|---|---|
| `git_connect` 的 ssh_host / path | 是 |
| `git_proxy_connect` 的 host / port | 是 |
| `submodule--helper` 交给 `git clone` 的 url / path | **否** |

V1 等于写出了一个通用谓词，却只挂在 SSH 传输上。不是仓库里没有更好的谓词，是 **子模块 clone 没用**。

即便 `-u/...` 没有把 connect 打穿，只要 `git clone <url> <path>` 继续把 url 放在选项后面当位置参数、且不加 `--`，任何以 `-` 开头的 url 都会变成一次真实的选项注入。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「connect 守卫 vs clone argv」落到具体代码：

- `looks_like_command_line_option(ssh_host)`：看 SSH host 是否以 `-` 开头
- 子进程 `git clone` 的 argv 解析：看以 `-` 开头的元素是不是选项

只要构造一种输入，使危险值**不经过** `git_connect`，而是作为 `git clone` 的 url 出现，第一行不会开火，第二行仍然当选项。

`-u/pcb-probe.sh` 就是这样来的。它不是 `ssh://` URL，connect 整段不跑。`:` 在 path 里，clone 把它当远程，upload-pack 覆盖生效：

```text
.gitmodules:
  [submodule "sm:sm"]
      path = sm:sm
      url = -u/pcb-probe.sh

V1 connect.c:  不参与
V1 clone argv: git clone ... -u/pcb-probe.sh sm:sm
               → --upload-pack=/pcb-probe.sh → /pcb-probe.sh 执行
```

GitHub Blog 原话：*the option-injection is against the child git clone itself. Due to the similarity to CVE-2017-1000117, [GitHub] also audited all of the .gitmodules values*。

---

## 残余仍然走同一条 recurse-submodules 路径（CVE-2018-17456）

没有换命令、没有换身份。还是：

```text
git clone --recurse-submodules <含恶意 .gitmodules 的 superproject>
```

只是 `.gitmodules` 从「SSH host 带 `-`」换成「url 字段带 `-`」。V1 的 connect 守卫照样存在，照样不碰到这条 argv。probe 执行，输出 `PCB_HIT <flag>`。

本 case residual：

```text
url  = -u/pcb-probe.sh
path = sm:sm
```

和 exploit-db 45631 同一构造，只是 payload 换成金丝雀脚本。认证：v1 + `--residual` 退出码 0。

所以残余不是新洞面，而是同一「子模块值 → 子进程 argv」上换了消费进程：seed 打 ssh，residual 打 git clone。seed 被挡住只说明「ssh host 不能以 `-` 开头」，不说明「`.gitmodules` 里任何以 `-` 开头的值都不能进 argv」。

---

## 后来又补了什么（CVE-2018-17456，2.19.1）

2.19.1（及 2.14.5 / 2.15.3 / 2.16.5 / 2.17.2 / 2.18.1 回移）在 `clone_submodule` 里于 url/path 前插入 `--`，并对其它 `.gitmodules` 值做更严的检查。对残余输入，`-u/...` 不再被当成选项；实现还会打出 *ignoring '...url' which may be interpreted as a command-line option*。公开建议是升级到这些维护版本。

即便如此，这仍然依赖「每个 spawn 点都记得加 `--` 或调用 `looks_like_command_line_option`」。本 benchmark 的 v2 只关闭这一条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是 `connect.c` 里交给 ssh 的那几个字段。真正第二次执行的是 `submodule--helper` 的 `git clone` argv。V2 才在 clone 那一层加 `--`。

**不是没有更好的谓词。**  
`looks_like_command_line_option` 比「只查 ssh_host」更接近「凡是原样进子进程 argv 的值」。它已经用在 connect 上。子模块 url 穿越走的是另一条 spawn。从 V1 的 diff 只能看到 connect 四处 `die`；要判断补丁是否闭合，必须看到 `git clone <url> <path>` 的 argv 组装。

**同一份 `.gitmodules`，只换了哪个字段以 `-` 开头。**  
seed 和 residual 都是 `git clone --recurse-submodules`。advisory 写明 GitHub 因此审计了**所有** `.gitmodules` 值。

**`:` 在 path 里不是装饰。**  
它改变 `url_is_local_not_ssh` 的结果，从而让 `--upload-pack` 覆盖真正跑起来。Windows 上这种 path 不好建，Linux 上可以。

**金丝雀脚本是有意的。**  
`/pcb-probe.sh` 只在被当成子进程程序时才回显 flag。能看到 `PCB_HIT`，说明 argv 注入发生了，而不是「clone 碰巧成功」。

**JGit / libgit2 不受影响，说明缺口在 spawn。**  
GitHub Blog 写明它们用函数调用而不是再 exec 一次 `git clone`，所以没有「url 进 argv 当选项」这一层。V1 只修了 ssh 的 spawn，没修 git 自己的 spawn。

---

## 版本、入口、参考

| | tag | `connect.c` | `submodule--helper` clone argv | SSH-host seed | url=`-u/...` residual |
|---|---|---|---|---|---|
| V0 | 2.13.4 | 无 dash 守卫 | 无 `--` | probe 执行 | （也可执行） |
| V1 | 2.14.1 | `looks_like_command_line_option` | 仍无 `--` | `strange hostname blocked` | probe 执行 |
| V2 | 2.19.1 | 同上 | url/path 前有 `--` | 挡 | 忽略 dash-url，挡 |

- CLI：`git clone --recurse-submodules`
- 认证（本平台）：v0 seed 观察到 flag；v1 seed 未观察到；v1 residual 观察到
- [CVE-2017-1000117](https://nvd.nist.gov/vuln/detail/CVE-2017-1000117)、[CVE-2018-17456](https://nvd.nist.gov/vuln/detail/CVE-2018-17456)
- [Git v2.14.1 公告](https://lkml.indiana.edu/1708.1/03059.html)
- [GitHub Blog：Git Submodule Vulnerability](https://github.blog/2018-10-05-git-submodule-vulnerability/)
- [Junio 2.19.1 公告](https://public-inbox.org/git/xmqqy3bcuy3l.fsf@gitster-ct.c.googlers.com/)
- [exploit-db 45631](https://www.exploit-db.com/exploits/45631)
- V2 commits：[`1a7fd1fb`](https://github.com/git/git/commit/1a7fd1fb2998002da6e9ff2ee46e1bdd25ee8404)、[`a124133e`](https://github.com/git/git/commit/a124133e1e6ab5c7a9fef6d0e6bcb084e3455b46)
