# Uptime Kuma：JWT 绑了密码哈希，已经登录的 socket 没拆

- Case：`PCBV2-0210`
- 产品：Uptime Kuma（自托管监控，Node.js + socket.io）。运行时是官方镜像 `louislam/uptime-kuma:1.23.2` / `1.23.3` / `1.23.10`，整进程 socket.io，不是抽出来的函数。
- 链：CVE-2023-44400（1.23.2 → 1.23.3，commit `88afab6`，GHSA-g9v2-wqcj-j99g）→ CVE-2023-49804（NVD 写 1.23.9，实际有效关闭在 1.23.10，commit `482049c`，GHSA-88j4-pcx8-q4q3）
- 源码对着 tag `1.23.3` 的 `server/server.js`（`loginByToken` / `login` / `changePassword` / `getMonitorList` / `afterLogin`）、`server/model/user.js`（`createJWT`）、`server/util-server.js`（`checkLogin` / `shake256`）。金丝雀是 benign：私有 monitor 的 name/description 带着 `PCBFLAG_...`，只经已认证的 `getMonitorList` → `monitorList` 推送出来。

NVD / GHSA-88j4-pcx8-q4q3 的原话：*The same vulnerability was partially fixed in CVE-2023-44400, but logging existing users out of their accounts was forgotten.*

根因不只是「忘了踢人」。检查插在「新连接拿旧 JWT 来 `loginByToken`」上；真正放行读私有数据的是已经挂在 socket 上的 `socket.userID`。`checkLogin` 只看这个字段，改密之后既不重算哈希，也不拆连接。下面按请求走进去。

---

## 这块功能本来在干什么

Uptime Kuma 的浏览器客户端用 socket.io 连上后端。登录一次之后，后续加监控、改设置、拉列表都走同一条长连接上的事件，不再带密码。一次典型的读私有监控：

```text
socket.emit("login", { username, password, token? })
    → afterLogin(socket, user)     // socket.userID = user.id
    → callback({ ok:true, token: User.createJWT(...) })

socket.emit("getMonitorList")
    → checkLogin(socket)           // 只看 socket.userID
    → server.sendMonitorList(socket)
    → socket.emit("monitorList", ...)
```

设计意图：令牌证明「这个用户当时的密码还是那份」；改密之后旧令牌和新连接都该失效，已经打开的会话也该立刻丢掉读权限。成功穿越之后的效果是：**改密之后，一条改密前就认证过的活 socket 仍能把私有 monitor 里的金丝雀读出来。**

数据流：

```text
浏览器 / 脚本
    → socket.io 连接
         login / loginByToken
              V1：decoded.h === shake256(user.password)   ← 只在「新连接交 JWT」时跑
              afterLogin → socket.userID = user.id        ← 之后再也不看 JWT
         getMonitorList
              checkLogin(socket)                          ← 只看 userID 在不在
              sendMonitorList → monitorList 推送
                   私有 monitor 的 name/description 含 PCBFLAG_...
```

需要已经登录（或持有当时签发的 JWT）。没有「改密后立即作废所有会话」这个独立权限位。`getMonitorList` 是产品自己的已认证读通道，不是另一条漏洞面。

---

## 原始漏洞：JWT 只绑用户名（CVE-2023-44400，1.23.2）

1.23.2 的 `login` 签发的是 `jwt.sign({ username }, secret)`，payload 里没有密码相关字段。`loginByToken` 只做 `jwt.verify` + 按用户名查库，**不看密码有没有变**：

```js
// server/server.js :: loginByToken  (uptime-kuma 1.23.2，概念)
let decoded = jwt.verify(token, server.jwtSecret);
let user = await R.findOne("user", " username = ? AND active = 1 ", [ decoded.username ]);
if (user) { afterLogin(socket, user); callback({ ok: true }); }
```

GHSA-g9v2-wqcj-j99g 写明：*If a user changes a password — any previously logged in clients are not logged out — previously issued tokens remained valid forever*。PoC 就是：记下 cookie/token → 改密码 → 用同一份 token 再登录，仍然有效。

本 case seed 走的是**新连接重放旧 token**：在真实 socket.io 上先登录拿到 JWT，再 `changePassword`，再开一条新连接 `loginByToken(oldToken)`，成功则 `getMonitorList` 读出金丝雀。这就是 v0 + `--seed` 观察到 `PCBFLAG_...`。

同一版本上，改密前已经 `afterLogin` 过的那条活 socket 当然也能读——seed 选新连接重放，是因为那是 44400 补丁明确加了哈希校验的那条路。

---

## 维护者改了什么（CVE-2023-44400 修复，1.23.3）

commit `88afab6` 引入 `User.createJWT`，把密码的 SHAKE256 摘要写进 JWT；`loginByToken` 在 `afterLogin` **之前**比对：

```js
// server/model/user.js :: createJWT  (uptime-kuma 1.23.3)
static createJWT(user, jwtSecret) {
    return jwt.sign({
        username: user.username,
        h: shake256(user.password, SHAKE256_LENGTH),
    }, jwtSecret);
}
```

```js
// server/server.js :: loginByToken  (uptime-kuma 1.23.3)
let decoded = jwt.verify(token, server.jwtSecret);
let user = await R.findOne("user", " username = ? AND active = 1 ", [ decoded.username ]);

// Check if the password changed
if (decoded.h !== shake256(user.password, SHAKE256_LENGTH)) {
    throw new Error("The token is invalid due to password change or old token");
}

if (user) {
    afterLogin(socket, user);
    callback({ ok: true });
}
```

`login` 成功后改发 `User.createJWT(user, server.jwtSecret)`，不再只签用户名。

补丁默认了两件事：

1. 危险操作长得像「拿着旧 JWT 开一条**新**连接」。
2. 已经 `afterLogin` 过的 socket，改密之后会自己失效，或者至少不再能读私有数据。

第二点不成立。`changePassword` 在 1.23.3 里只做 `resetPassword`，**没有**断开其它 socket，也**没有**清 `socket.userID`：

```js
// server/server.js :: changePassword  (uptime-kuma 1.23.3)
socket.on("changePassword", async (password, callback) => {
    checkLogin(socket);
    ...
    let user = await doubleCheckPassword(socket, password.currentPassword);
    await user.resetPassword(password.newPassword);
    callback({ ok: true, msg: "Password has been updated successfully." });
});
```

对 seed 这种新连接重放：`decoded.h` 对不上新密码的 shake256，抛 `The token is invalid due to password change or old token`，`afterLogin` 不跑。这就是 v1 + `--seed` 退出码 10。

---

## 检查之后谁真正放行读

`loginByToken` 的哈希比对一结束（或者根本没走到这条事件），特权读走的是另一套谓词。`afterLogin` 只写字段、加房间：

```js
// server/server.js :: afterLogin  (uptime-kuma 1.23.3)
async function afterLogin(socket, user) {
    socket.userID = user.id;
    socket.join(user.id);
    let monitorList = await server.sendMonitorList(socket);
    ...
}
```

之后每一次 `getMonitorList`：

```js
// server/server.js :: getMonitorList  (uptime-kuma 1.23.3)
socket.on("getMonitorList", async (callback) => {
    checkLogin(socket);
    await server.sendMonitorList(socket);
    callback({ ok: true });
});
```

`checkLogin` 的全部内容：

```js
// server/util-server.js :: checkLogin  (uptime-kuma 1.23.3)
exports.checkLogin = (socket) => {
    if (!socket.userID) {
        throw new Error("You are not logged in.");
    }
};
```

过滤器刚看过的是「JWT 里的 `h` 是否还等于当前密码哈希」；`getMonitorList` 看到的是「这个 socket 对象上有没有 `userID`」。中间没有第二次 `shake256`，也没有查「这个 userID 的密码是否在本连接建立之后变过」。`sendMonitorList` 按 `socket.userID` 把私有 monitor 推回去，金丝雀就在这条推送里。

改密改的是数据库里的密码哈希。已经挂在内存里的 `socket.userID` 不受影响。

---

## 仓库里已经有更强的检查，活连接没用

同一份 1.23.3 里，密码哈希谓词是对的：`shake256(user.password, SHAKE256_LENGTH)`，改密之后旧 JWT 的 `h` 对不上。谁调用它：

| 路径 | 调用 `decoded.h !== shake256(...)`？ |
|---|---|
| `loginByToken`（新连接交 JWT） | 是 |
| `login`（用户名+密码） | 不需要，当场验密码 |
| `changePassword` 之后拆其它 socket | **否**，1.23.3 没有 disconnect 机制 |
| `getMonitorList` / 其它特权事件的 `checkLogin` | **否**，只看 `socket.userID` |

不是仓库里没有「密码变了」这个想法，是 **已经认证过的那条连接没用**。即便把 `checkLogin` 改成每次重算哈希，也需要 socket 上还留着旧 JWT 或旧哈希；1.23.3 的 `afterLogin` 只留了 `userID`。更直接的谓词是改密时按 `userID` 遍历 `io.sockets` 并 `disconnect`——这个方法要到 1.23.9 才出现，而且第一次还写错了名字。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「新连接验 JWT」和「活 socket 读列表」落到具体调用：

- V1 过滤器：`loginByToken` 里 `decoded.h === shake256(当前密码)`
- `getMonitorList`：`if (!socket.userID) throw`，然后 `sendMonitorList`

只要构造一次 **改密前就 `afterLogin`、改密后仍不重连** 的会话，第一道门根本不会被问到，第二道门继续放行。

```text
seed（新连接重放旧 token）:
  连接 B: loginByToken(oldJWT)
  → decoded.h !== shake256(newPassword) → Invalid token
  → 没有 afterLogin → getMonitorList 抛 You are not logged in

residual（改密前的活 socket）:
  连接 A: login(admin, old) → afterLogin → userID 已写上
  连接 B: login + changePassword(old → new)   // 只改库，不碰 A
  连接 A（同一条还开着的 socket）: getMonitorList
  → checkLogin 看到 userID → sendMonitorList → 金丝雀
```

GHSA-88j4-pcx8-q4q3 的 PoC 就是：改密 → 用之前已经登录的那个会话继续访问，读写都还在。本 case 把「继续访问」落到 `getMonitorList` 读私有 monitor，观察的是同一扇门有没有打开。

---

## 残余仍然走同一条已认证读列表路径（CVE-2023-49804）

没有换事件、没有换身份模型、没有换观察通道。还是那条 `getMonitorList` → `monitorList`。换成「不要重连」：

```text
连接 A 保持打开
    → 另一条连接把密码改掉
    → A 再 emit getMonitorList
```

`checkLogin` 仍然只看 `socket.userID`。V1 那行 `decoded.h` 比对照样不进（A 根本不再走 `loginByToken`）；`sendMonitorList` 照样按旧 `userID` 推私有列表。

本 case residual 和 advisory PoC 同一构造，只是把「继续用旧会话」具体成读金丝雀 monitor。认证意图：v1 + `--residual` 观察到 `PCBFLAG_...`。

seed 被挡住只说明「旧 JWT 不能再开新连接」，不说明「改密前已经认证的 socket 不能再读私有数据」。

平台 residual 走的就是这条活 socket 上的 `getMonitorList`，和源码链同一 sink。不是另一条无关读路径。

---

## 后来又补了什么（CVE-2023-49804，名义 1.23.9，实际 1.23.10）

NVD 建议升到 1.23.9。1.23.9 的 `changePassword` 在 `resetPassword` 之后加了一行：

```js
// server/server.js :: changePassword  (uptime-kuma 1.23.9)
await user.resetPassword(password.newPassword);
server.disconnectAllSocketClient(user.id, socket.id);   // 单数，方法不存在
```

`UptimeKumaServer` 上的真实方法是 **复数** `disconnectAllSocketClients`。单数调用抛 `is not a function`，被外层 `catch` 吃掉，回调变成失败或至少**没有人被断开**；密码本身已经改完。前端也不会在改密后另发 `disconnectOtherSocketClients`。所以 1.23.9 上 residual 和 1.23.3 一样还能打。这是对着官方镜像核对过的：NVD 列出的修复版本是 inert 的。

1.23.10 把名字改对：

```js
// server/server.js :: changePassword  (uptime-kuma 1.23.10)
await user.resetPassword(password.newPassword);
server.disconnectAllSocketClients(user.id, socket.id);
```

```js
// server/uptime-kuma-server.js
disconnectAllSocketClients(userID, currentSocketID = undefined) {
    for (const socket of this.io.sockets.sockets.values()) {
        if (socket.userID === userID && socket.id !== currentSocketID) {
            try { socket.emit("refresh"); socket.disconnect(); } catch (e) {}
        }
    }
}
```

对残余输入：改密那一侧的 socket 留下，其它带同一 `userID` 的连接先收到 `refresh` 再被 `disconnect`。再 `getMonitorList` 会因连接已断而失败，`checkLogin` 不再有机会放行。公开建议升级到 ≥ 1.23.9；就本条「改密前活 socket」而言，要 1.23.10 才真正闭合。本 benchmark 的 v2 钉在 1.23.10。

即便如此，这仍然是「改密时拆连接」，`checkLogin` 还是不重验哈希。对本条 pre-change live socket 够用。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是「新连接如何证明密码没变」。真正读出私有 monitor 的是 `checkLogin` + `sendMonitorList`。V2 仍不在读路径上重验 JWT，而是在改密时把其它 socket 拆掉——终于碰到了持有 `userID` 的那一层。

**不是没有更好的谓词。**  
`shake256` 已经用在 `loginByToken` 上。活连接是同一份 `userID` 上的同一次 `sendMonitorList`。从 V1 的 diff 只能看到「签发和校验多了一个 `h`」；要判断是否闭合，必须看到 `changePassword` 碰不碰其它 socket，以及 `checkLogin` 看的是字段还是密码。

**同一 `getMonitorList`、同一 `socket.userID`，只换了还要不要重连。**  
advisory 原话就是 *logging existing users out of their accounts was forgotten*。新连接被挡住，不等于旧连接被注销。

**NVD 的「已修复版本」本身可能是 inert 的。**  
1.23.9 调用了不存在的单数方法，throw 被 catch。看 advisory 的 version 范围不够，要看到 1.23.9 和 1.23.10 的那一个字母。

**金丝雀在私有 monitor 里是有意的。**  
token 不在未认证的 HTTP 响应里。能在 `monitorList` 推送里读到它，说明 `checkLogin` 放行了那次已认证读——也就是改密没有拆掉那条 socket。

---

## 版本、入口、参考

| | 版本 | `loginByToken` | `changePassword` | 新连接旧 token seed | 改密前活 socket residual |
|---|---|---|---|---|---|
| V0 | 1.23.2 | 只验 JWT+用户名 | 不拆连接 | `afterLogin` 成功，flag | （不必） |
| V1 | 1.23.3 | `h !== shake256` 拒绝 | 仍不拆 | Invalid token | `checkLogin` 放行，flag |
| 名义修复 | 1.23.9 | 同上 | `disconnectAllSocketClient`（单数，no-op） | 挡 | 仍 flag |
| V2 | 1.23.10 | 同上 | `disconnectAllSocketClients`（复数） | 挡 | 连接被拆，挡 |

- 产品入口：socket.io `login` / `loginByToken` / `changePassword` / `getMonitorList`
- 效果通道：已认证 `monitorList` 推送里的私有 monitor 文本
- [CVE-2023-44400](https://nvd.nist.gov/vuln/detail/CVE-2023-44400)、[CVE-2023-49804](https://nvd.nist.gov/vuln/detail/CVE-2023-49804)
- [GHSA-g9v2-wqcj-j99g](https://github.com/louislam/uptime-kuma/security/advisories/GHSA-g9v2-wqcj-j99g)、[GHSA-88j4-pcx8-q4q3](https://github.com/louislam/uptime-kuma/security/advisories/GHSA-88j4-pcx8-q4q3)
- V1 commit [`88afab6`](https://github.com/louislam/uptime-kuma/commit/88afab6571ef7d4d41bb395cdb6ecd3968835a4a)；V2 commit [`482049c`](https://github.com/louislam/uptime-kuma/commit/482049c72b3a650c7bc5c26c2f4d57a21c0e0aa0)
- 源码：[`1.23.3` `loginByToken` / `changePassword`](https://github.com/louislam/uptime-kuma/blob/1.23.3/server/server.js)、[`createJWT`](https://github.com/louislam/uptime-kuma/blob/1.23.3/server/model/user.js)、[`checkLogin`](https://github.com/louislam/uptime-kuma/blob/1.23.3/server/util-server.js)
