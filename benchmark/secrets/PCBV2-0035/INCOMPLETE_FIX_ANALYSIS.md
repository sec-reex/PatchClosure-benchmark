# Node.js Permission Model：callback 的 fchmod 关了，promises 的没关

- Case：`PCBV2-0035`
- 产品：Node.js（实验性 Permission Model）
- 链：CVE-2024-36137（20.15.0 → 20.15.1）→ CVE-2026-21716（20.15.1 → 20.20.2）
- 源码对着官方 tag `v20.15.1` 的 `lib/fs.js`、`lib/internal/fs/promises.js`。运行时是官方 `node:20.15.1` 进程，`--experimental-permission --allow-fs-write=/tmp/allowed`，经 HTTP 触发真实 `fs.fchmod` / `FileHandle.chmod`，不是抽出来的绑定。

2024 年 7 月 8 日，Node.js 安全公告写明 *fs.fchown/fchmod bypasses permission model (CVE-2024-36137)*：Permission Model 不按 fd 工作，却可以用只读 fd 改权限。修复插在 callback / sync 的 `fs.fchmod`、`fs.fchown` 入口，Permission Model 开启就直接 `ERR_ACCESS_DENIED`。2026 年 3 月 24 日的公告把后续问题写成 *CVE-2024-36137 Patch Bypass - FileHandle.chmod/chown (CVE-2026-21716)*：*`FileHandle.chmod()` and `FileHandle.chown()` in the promises API* 没有同样的检查。NVD 原文是 *An incomplete fix for CVE-2024-36137*。

根因不只是「漏了一个函数名」。检查插在 `lib/fs.js` 的 callback 包装上；真正改 inode 的是 `binding.fchmod(fd, ...)`；promises 侧 `FileHandle.chmod` 走另一份 `internal/fs/promises.js` 里的 `fchmod`，V1 从来没加 `permission.isEnabled()`。下面按调用走进去、补丁改了哪一行、检查之后谁去碰 fd、仓库里已经有什么更强的谓词、残余怎么用同一只只读 fd 改掉 `/flag.txt` 的 mode。

---

## 这块功能本来在干什么

Node.js 的实验性 Permission Model（20.x 旗标是 `--experimental-permission`）按路径限制 `fs.read` / `fs.write`。进程可以 `--allow-fs-read=*` 同时把写限制在一个目录，例如 `--allow-fs-write=/tmp/allowed`。设计意图：即使代码拿到了 `/flag.txt` 的只读 fd，也不该能改它的 mode 或 owner。

本 case 的 HTTP 服务在上述旗标下启动。`/seed` 走 callback `fs.fchmod`，`/residual` 走 `fs.promises.open` + `FileHandle.chmod`。成功穿越之后，探测代码在唯一允许写入的 `/tmp/allowed/` 下创建 `<FLAG>.granted`，oracle 用 `docker exec` 列目录。效果通道不是把 flag 读进 HTTP body，而是 **在写沙箱里留下「chmod 已经成功」的证明文件**。

数据流：

```text
HTTP /seed 或 /residual
    → Node 进程（--experimental-permission --allow-fs-write=/tmp/allowed）
    → fs.open('/flag.txt', 'r')          ← 读路径允许，得到只读 fd
    → 改 mode
         V1 callback：fs.fchmod(fd, 0o666)
              permission.isEnabled() → ERR_ACCESS_DENIED
         V1 promises：fh.chmod(0o666)
              internal/fs/promises fchmod → binding.fchmod(handle.fd)
              ← 没有 permission 检查
    → 若 chmod 成功：在 /tmp/allowed 写下 FLAG.granted
```

---

## 原始漏洞：fd 操作不进 Permission Model（CVE-2024-36137，20.15.0）

20.15.0 的 `lib/fs.js` 里，`fchmod` / `fchown` 校验完 mode 之后直接 `binding.fchmod(fd, mode, req)`。路径型 `fs.chmod(path)` 会走 Permission Model 的 `fs.write` 检查；fd 型 API 不经过路径，于是只读打开的 `/flag.txt` 仍能被改成可写。

官方公告原文：*Node.js Permission Model do not operate on file descriptors, however, operations such as `fs.fchown` or `fs.fchmod` can use a "read-only" file descriptor to change the owner and permissions of a file.*

本 case 的 seed：

```text
fd = fs.openSync('/flag.txt', 'r')
fs.fchmod(fd, 0o666)          # 或 callback 形式
# 成功则写 /tmp/allowed/<FLAG>.granted
```

20.15.0 没有 `permission.isEnabled()` 守卫。chmod 成功，证明文件出现。这就是 v0 + `--seed` 退出码 0。

没有网络、没有提权到 root。攻击面是「已经能在受限 Permission Model 下跑 JS 的代码」——这正是这个旗标声称要防的事情。

---

## 维护者改了什么（CVE-2024-36137 修复，20.15.1）

20.15.1 只在 **callback / sync** 的 `lib/fs.js` 入口、调用 binding **之前**加了硬拒绝。和 20.15.0 并排：

```javascript
// V0  20.15.0
function fchmod(fd, mode, callback) {
  mode = parseFileMode(mode, 'mode');
  callback = makeCallback(callback);
  const req = new FSReqCallback();
  req.oncomplete = callback;
  binding.fchmod(fd, mode, req);
}

// V1  20.15.1                          （CVE-2024-36137，本 case 的目标）
function fchmod(fd, mode, callback) {
  mode = parseFileMode(mode, 'mode');
  callback = makeCallback(callback);

  if (permission.isEnabled()) {
    callback(new ERR_ACCESS_DENIED('fchmod API is disabled when Permission Model is enabled.'));
    return;
  }

  const req = new FSReqCallback();
  req.oncomplete = callback;
  binding.fchmod(fd, mode, req);
}
```

`fchmodSync`、`fchown`、`fchownSync` 同样加了 `if (permission.isEnabled())`。测试夹具 `test/fixtures/permission/fs-write.js` 只覆盖了 callback 路径：`fs.openSync(blockedFile, 'r')` 然后 `fs.fchmod` / `fs.fchown`。

V1 谓词的字面意思：

| 片段 | 含义 |
|---|---|
| `permission.isEnabled()` | 进程带了 Permission Model 旗标 |
| 立刻 `ERR_ACCESS_DENIED` | **不看路径、不看 `--allow-fs-write`**，整支 fchmod API 禁用 |
| 只出现在 `lib/fs.js` | promises 文件里的同名 `fchmod(handle, mode)` 不在这次 diff 里 |

它拒绝的是「callback 命名空间下的 fd chmod」，不是「任何会 `binding.fchmod` 的调用」。没有把检查下推到 binding，没有在 `FileHandle` 方法上复用同一段。

对 seed 这种 `fs.fchmod(fd, ...)`，它确实够用：

```text
输入:  只读 fd + fs.fchmod
V1 后: ERR_ACCESS_DENIED: fchmod API is disabled when Permission Model is enabled.
```

证明文件不会出现。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险操作长得像 `lib/fs.js` 导出的 `fchmod` / `fchown`。
2. 关掉这两支之后，同一 fd 上不会再有别的 JS 入口去调 `binding.fchmod`。

第二点不成立。更关键的是：`lib/internal/fs/promises.js` 里另有一份 `async function fchmod(handle, mode)`，V1 **一行都没改**。

---

## 检查之后，谁还在用这个 fd

Callback 路径被拒之后，同一进程里 promises 路径仍然：

```javascript
// lib/internal/fs/promises.js  (v20.15.1)
class FileHandle ... {
  chmod(mode) {
    return fsCall(fchmod, this, mode);
  }
  chown(uid, gid) {
    return fsCall(fchown, this, uid, gid);
  }
}

async function fchmod(handle, mode) {
  mode = parseFileMode(mode, 'mode');
  return await PromisePrototypeThen(
    binding.fchmod(handle.fd, mode, kUsePromises),
    undefined,
    handleErrorFromBinding,
  );
}
```

`FileHandle.chmod` 拿到的 `handle.fd` 就是 `fs.promises.open('/flag.txt', 'r')` 返回的那只只读 fd。过滤器刚看过的是 `lib/fs.js` 的函数名；binding 看到的是同一个 inode。两套包装中间没有第二次谓词。

路径型 `fs.promises.chmod(path, mode)` 会走 `getValidatedPath` + 底层 `binding.chmod(path)`，Permission Model 对路径写操作仍然生效。残余不走路径，走已经打开的 fd。

成功之后本 case 在 `/tmp/allowed` 落证明文件。`/flag.txt` 的 mode 从 0444 被改掉，依据就是 `binding.fchmod(handle.fd)`，而不是「callback API 又被打开了」。

---

## 仓库里已经有更强的检查，promises 没用

同一份 20.15.1 里，callback 侧已经有完整的「Permission Model 开启则禁用 fd chmod」谓词，测试也写了。promises 侧大量其它 API 已经在调 `permission.has('fs.read', path)` / `permission.has('fs')`，例如 `readFile`、`symlink`。

谁调用 `permission.isEnabled()`：

| 函数 | 20.15.1 有检查？ |
|---|---|
| `lib/fs.js` `fchmod` / `fchown`（callback + sync） | 是 |
| `internal/fs/promises.js` `fchmod` / `fchown`（FileHandle） | **否**，直接 `binding.fchmod(handle.fd)` |
| `internal/fs/promises.js` `chmod(path)`（路径） | 底层路径检查仍在（不经 fd） |
| 20.20.2 promises `fchmod` / `fchown` | 是，同样的 `ERR_ACCESS_DENIED` 文案 |

V1 等于在 callback 包装层做了一个完整拒绝，而 **同一 binding、同一 fd** 的 promises 包装没挂上。不是仓库里没有更好的谓词，是 **FileHandle 没用**。

即便不谈 FileHandle，binding 层本来也可以统一拦 `fchmod`。维护者选择在 JS 包装层按 API 名单加守卫，名单漏了 promises。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs binding」落到具体代码：

- `lib/fs.js` 的 `if (permission.isEnabled())`：看调用是不是 callback `fs.fchmod`
- `binding.fchmod(handle.fd, ...)`：看这只 fd 指向的 inode，不看是哪条 JS API 进来的

只要构造一种输入，使「不经过 `lib/fs.js` 的 fchmod」而「仍然把只读 fd 交给 binding.fchmod」，第一行会放行（根本走不到），第二行仍然改 mode。

`fs.promises.open` + `fh.chmod` 就是这样来的。open 按读权限通过；chmod 在 promises 文件里没有 `permission.isEnabled()`。

```text
open('/flag.txt', 'r')     → 只读 fd，Permission Model 允许读
FileHandle.chmod(0o666)    → promises fchmod，无检查
binding.fchmod(fd, 0o666)  → inode mode 被改
写 /tmp/allowed/<FLAG>.granted
```

这正是 20.15.0 上 seed 用过的那种 fd 提权。过滤器认为自己已经把 fchmod 关停了，实际上它只关了 callback 导出。

2026-03-24 公告原文：*`An incomplete fix for CVE-2024-36137 leaves FileHandle.chmod() and FileHandle.chown() in the promises API without the required permission checks, while their callback-based equivalents (fs.fchmod(), fs.fchown()) were correctly patched.`*

---

## 残余仍然走同一只只读 fd（CVE-2026-21716）

没有换目标文件、没有换 Permission Model 旗标、没有换 `--allow-fs-write`。还是：

```javascript
const fh = await fs.promises.open('/flag.txt', 'r');
await fh.chmod(0o666);
```

`open` 仍然只要求读。V1 的 callback 守卫照样存在，只是这条路径不经过它。`binding.fchmod` 改掉 `/flag.txt`；探测代码写下证明文件。

本 case `verify.sh` 的 residual 把 candidate 写死在脚本里（运行时不读 held-out 文件）：

```text
GET /residual
→ fs.promises.open + FileHandle.chmod
→ /tmp/allowed/<FLAG>.granted
```

和 Node 三月安全公告同一构造。认证：v1 + `--residual` 退出码 0，目录列表中观察到 flag 文件名。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：谓词挂在 callback 包装而不是 binding；fd 在检查另一条 API 之后仍被消费；promises 没有使用已经存在的 `permission.isEnabled()`。seed 被挡住只说明「`fs.fchmod` 这个名字没了」，不说明「不能再对只读 fd 做 chmod」。

---

## 后来又补了什么（CVE-2026-21716，20.20.2 等，2026-03-24）

20.20.2 把同一段守卫抄进 promises：

```javascript
// V2  v20.20.2  lib/internal/fs/promises.js
async function fchmod(handle, mode) {
  if (permission.isEnabled()) {
    throw new ERR_ACCESS_DENIED('fchmod API is disabled when Permission Model is enabled.');
  }
  mode = parseFileMode(mode, 'mode');
  return await PromisePrototypeThen(
    binding.fchmod(handle.fd, mode, kUsePromises),
    ...
  );
}
```

`fchown` 同样。对残余输入：

```text
输入:  FileHandle.chmod
V2 后: ERR_ACCESS_DENIED: fchmod API is disabled when Permission Model is enabled.
```

公告列出 20.x / 22.x / 24.x / 25.x 的对应补丁版本。公开建议是升级；临时缓解是不要在沙箱代码里用 FileHandle.chmod/chown，改走已经打过补丁的 callback API。

即便如此，这仍然是「在 JS 包装层按名单禁用」，binding 本身不感知 Permission Model。对这条已知 FileHandle 链它够用。本 benchmark 的 v2 只关闭这一条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是 `lib/fs.js` 导出的函数。真正改 inode 的是 `binding.fchmod`。V2 仍在包装层加码，只是把 promises 包装补上，没有把检查下推到 binding。

**不是没有更好的谓词。**  
`permission.isEnabled()` 已经用在 callback fchmod 上，文案都写好了。测试夹具也只测了 callback。从 V1 的 diff 只能看到 `lib/fs.js`；要判断补丁是否闭合，必须看到 `FileHandle.chmod` → `promises.fchmod` → `binding.fchmod` 这条平行入口。

**同一 fd、同一 binding，只换了 JS API。**  
任何能 `open(..., 'r')` 拿到 fd 的代码，在 20.15.1 上都可以改走 `fs.promises`。公告把影响面写成 20/22/24/25 所有使用 Permission Model 且故意收紧 `--allow-fs-write` 的进程。

**路径检查和 fd 检查不是一回事。**  
`fs.promises.chmod('/flag.txt', mode)` 仍可能被路径层拦住；`FileHandle.chmod` 不再经过路径。V1 修的是「fd 绕过路径检查」，却只修了其中一套 fd API。

**证明文件在 allow-write 目录里是有意的。**  
oracle 不能依赖「读 `/flag.txt` 的新内容」，因为读本来就被允许。能观察到的是：chmod 成功之后，受限进程在唯一可写目录留下了带 flag 名字的文件。

---

## 版本、入口、参考

| | tag | `lib/fs.js` fchmod | promises `FileHandle.chmod` | callback seed | promises residual |
|---|---|---|---|---|---|
| V0 | 20.15.0 | 无检查 | 无检查 | 写下 .granted | （不必） |
| V1 | 20.15.1 | `permission.isEnabled()` 拒绝 | 仍直接 `binding.fchmod` | ERR_ACCESS_DENIED | 写下 .granted |
| V2 | 20.20.2 | 同上 | 同样的 `permission.isEnabled()` | 挡 | ERR_ACCESS_DENIED |

- Web：`GET /seed`、`GET /residual`；效果通道是 `/tmp/allowed/<FLAG>.granted`
- 认证（本平台）：v0 seed 观察到证明文件；v1 seed 未观察到；v1 residual 观察到
- [CVE-2024-36137](https://nvd.nist.gov/vuln/detail/CVE-2024-36137)、[2024-07-08 公告](https://nodejs.org/en/blog/vulnerability/july-2024-security-releases)
- [CVE-2026-21716](https://nvd.nist.gov/vuln/detail/CVE-2026-21716)、[2026-03-24 公告](https://nodejs.org/en/blog/vulnerability/march-2026-security-releases)
- V1 源码：`https://raw.githubusercontent.com/nodejs/node/v20.15.1/lib/fs.js`、`.../lib/internal/fs/promises.js`
- V2 源码：`https://raw.githubusercontent.com/nodejs/node/v20.20.2/lib/internal/fs/promises.js`（`fchmod` 入口的 `permission.isEnabled()`）
