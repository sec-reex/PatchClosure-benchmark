# LibreChat：fork 限速挂上了，同文件的 duplicate 没挂

- Case：`PCBV2-0137`
- 产品：LibreChat（自托管 ChatGPT 克隆，Express + MongoDB）
- 链：CVE-2025-7105（v0.7.8 → v0.7.9，commit `97a99985fa`）→ CVE-2026-54037（v0.7.9…v0.8.3 → v0.8.4-rc1，PR #12218 / merge `ca79a031`）
- 源码对着 GitHub tag `v0.7.9` 的 `api/server/routes/convos.js`、`api/server/middleware/limiters/forkLimiters.js`、`api/server/utils/import/fork.js`（`forkConversation` / `duplicateConversation`）。运行时是官方镜像 `ghcr.io/danny-avila/librechat`，不是抽出来的函数。

2026 年 2 月，LibreChat 给会话分叉加了 IP / 用户两道 `express-rate-limit`，想挡住「一分钟内狂 fork」把 Mongo 写满、重启时 Mermaid 图 OOM 的那条路。NVD CVE-2025-7105 写的是 unrestricted Fork Function in `/api/convos/fork`。半年后 GHSA-g445-9wq6-jf3v 指出：同一文件里的 `POST /api/convos/duplicate` 做的是同一套「读会话 + 读消息 + 克隆 + 批量写入」，限速器只挂在 `/fork` 上。NVD CVE-2026-54037 写明 *the POST /api/convos/duplicate endpoint — which is in the same file and performs the exact same expensive database operations — was not given any rate limiter*，并写 *This vulnerability is fixed in 0.8.4-rc1*。

根因不只是「少写了一行 middleware」。检查插在路由表上；真正耗资源的是 `fork.js` 里那次批量克隆；同文件里已经有一份 `createForkLimiters()`，却只接到一条路径。下面按请求走进去、0.7.9 改了哪几行、限速之后谁真正写库、更宽的限速器有没有挂上，把这几层写完。

---

## 这块功能本来在干什么

LibreChat 给已登录用户提供「从某条消息分叉出新会话」和「整段复制会话」。两条 HTTP 入口都在 `api/server/routes/convos.js`，路由器先过 `requireJwtAuth`，再分到两个 handler。一次典型分叉：

```http
POST /api/convos/fork
Authorization: Bearer <JWT>
Content-Type: application/json

{"conversationId":"<id>","messageId":"<mid>","option":"direct","splitAtTarget":false}
```

一次典型复制：

```http
POST /api/convos/duplicate
Authorization: Bearer <JWT>
Content-Type: application/json

{"conversationId":"<id>","title":"Dup-1"}
```

两条路最后都进 `api/server/utils/import/fork.js`。`forkConversation` 按 option 选出要克隆的消息子集；`duplicateConversation` 用 `getMessagesUpToTargetLevel` 把整棵消息树拿来。然后共用：

1. `getConvo(userId, conversationId)` — 读原会话
2. `getMessages(...)` — 读全部消息
3. `cloneMessagesWithTimestamps` — 每条消息新 UUID、重写 parent、校正时间戳
4. `importBatchBuilder.saveBatch()` — 批量写入 MongoDB

设计意图：用户复制的是**自己的**会话，身份已经过 JWT。成功穿越之后的效果不是读出金丝雀文件，而是**在限速预算之外反复做同一套昂贵写操作**。本 case 的 oracle 是 DoS 阈值：一分钟窗口内连打 60 次，看有没有 HTTP 429。没有种植 `PCBFLAG_`；judge 看的是 429 计数。

数据流：

```text
JWT + conversationId
    → convos.js
         /fork      ← V1 在这里插入 forkIpLimiter + forkUserLimiter
         /duplicate ← 同一文件，V1 不插
    → forkConversation / duplicateConversation
         getConvo + getMessages
         cloneMessagesWithTimestamps
         saveBatch()                 ← 真正的写库，不再看限速
    → 201 / 200 或（仅 /fork）429
```

---

## 原始漏洞：/fork 没有次数上限（CVE-2025-7105，v0.7.8）

v0.7.8 的 `convos.js` 里 `/fork` 是裸 handler。huntr `e44f0740-48bd-443b-8826-528e6afe9e34` / NVD CVE-2025-7105 的问题是：已认证用户可以对同一会话狂 fork。若内容里有节点很多的 Mermaid 图，服务重启渲染时 JavaScript heap OOM。即便没有 Mermaid，每次 fork 也是一次完整的消息树克隆 + Mongo 批量写。

本 case 的 seed 不依赖 Mermaid，只打速率：注册 / 登录拿到 JWT，先造一条会话，再对 `/api/convos/fork` 连打 60 次。v0.7.8 上 429 计数为 0，所有请求都被处理。这就是 v0 + `--seed` 退出码 0。

同一版本的 `/duplicate` 同样没有限速。seed 只打 `/fork`，因为那是 CVE-2025-7105 写明的入口。

---

## 维护者改了什么（CVE-2025-7105 修复，v0.7.9）

commit `97a99985fa339db0a21ad63604e0bb8db4442ffc` 做了两件事：新建 `forkLimiters.js`，以及只在 `/fork` 上挂中间件。tag `v0.7.9` 的路由是：

```javascript
// api/server/routes/convos.js  (LibreChat v0.7.9)
const { createImportLimiters, createForkLimiters } = require('~/server/middleware');
...
const { importIpLimiter, importUserLimiter } = createImportLimiters();
const { forkIpLimiter, forkUserLimiter } = createForkLimiters();

router.post('/fork', forkIpLimiter, forkUserLimiter, async (req, res) => {
  try {
    const { conversationId, messageId, option, splitAtTarget, latestMessageId } = req.body;
    const result = await forkConversation({
      requestUserId: req.user.id,
      originalConvoId: conversationId,
      targetMessageId: messageId,
      latestMessageId,
      records: true,
      splitAtTarget,
      option,
    });
    res.json(result);
  } catch (error) {
    ...
  }
});

router.post('/duplicate', async (req, res) => {
  const { conversationId, title } = req.body;
  try {
    const result = await duplicateConversation({
      userId: req.user.id,
      conversationId,
      title,
    });
    res.status(201).json(result);
  } catch (error) {
    ...
  }
});
```

限速器本身的数字来自环境变量，默认 IP 30/分钟、用户 7/分钟：

```javascript
// api/server/middleware/limiters/forkLimiters.js :: getEnvironmentVariables / createForkLimiters
// (LibreChat v0.7.9，约 L6–L88)
const getEnvironmentVariables = () => {
  const FORK_IP_MAX = parseInt(process.env.FORK_IP_MAX) || 30;
  const FORK_IP_WINDOW = parseInt(process.env.FORK_IP_WINDOW) || 1;
  const FORK_USER_MAX = parseInt(process.env.FORK_USER_MAX) || 7;
  ...
};

const createForkLimiters = () => {
  ...
  const forkIpLimiter = rateLimit(ipLimiterOptions);
  const forkUserLimiter = rateLimit(userLimiterOptions);
  return { forkIpLimiter, forkUserLimiter };
};
```

超限时 handler 写 429，body 是 `Too many conversation fork requests. Try again later`。本 case 把 `FORK_USER_MAX=3` / `FORK_IP_MAX=10` 灌进 V1/V2，让 60 次 burst 一定能撞到阈值。

对 seed 这种明文打 `/fork` 的流量，V1 够用：前几发 200，随后 429。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 昂贵的克隆只从 `/fork` 进来。
2. 只要 `/fork` 有次数上限，CVE-2025-7105 描述的「狂克隆把库写满 / 重启 OOM」就闭合了。

第二点不成立。`createForkLimiters()` 返回的两个函数是普通 Express middleware，谁都可以挂；V1 只把它们写进 `/fork` 那一行。

---

## 限速之后，谁真正写库

V1 的 `rateLimit` 一放行，`/fork` handler 立刻把同一份 `conversationId` 交给 `forkConversation`。`/duplicate` 连这一步都没有，直接进 `duplicateConversation`。两个函数在同一份 `fork.js` 里，后半段几乎同一套：

```javascript
// api/server/utils/import/fork.js :: duplicateConversation  (v0.7.9)
async function duplicateConversation({ userId, conversationId }) {
  const originalConvo = await getConvo(userId, conversationId);
  if (!originalConvo) {
    throw new Error('Conversation not found');
  }

  const originalMessages = await getMessages({
    user: userId,
    conversationId,
  });

  const messagesToClone = getMessagesUpToTargetLevel(
    originalMessages,
    originalMessages[originalMessages.length - 1].messageId,
  );

  const importBatchBuilder = createImportBatchBuilder(userId);
  importBatchBuilder.startConversation(originalConvo.endpoint ?? EModelEndpoint.openAI);

  cloneMessagesWithTimestamps(messagesToClone, importBatchBuilder);

  const result = importBatchBuilder.finishConversation(
    originalConvo.title,
    new Date(),
    originalConvo,
  );
  await importBatchBuilder.saveBatch();
  ...
}
```

`forkConversation` 只是在选消息子集时多几个 option，然后同样调用 `cloneMessagesWithTimestamps` + `saveBatch()`。限速器看的是「这一分钟这个 IP / 这个 user.id 打了几次 `/fork`」；Mongo 看到的是「又一批新 conversation + 新 message 文档」。两套语义中间没有第二次谓词。

GHSA-g445-9wq6-jf3v 把四步写死了：`getConvo` → `getMessages` → `cloneMessagesWithTimestamps` → `saveBatch`。`/duplicate` 四步全做。advisory 原话是 *both endpoints performing identical expensive write operations*。

---

## 仓库里已经有更强的检查，复制路径没用

同一份 `convos.js` 在 V1 里已经实例化了 fork 限速器，也已经给另一条「贵」的写路径挂了限速——导入：

```javascript
// api/server/routes/convos.js  (v0.7.9)
const { importIpLimiter, importUserLimiter } = createImportLimiters();
const { forkIpLimiter, forkUserLimiter } = createForkLimiters();

router.post(
  '/import',
  importIpLimiter,
  importUserLimiter,
  upload.single('file'),
  async (req, res) => { ... }
);

router.post('/fork', forkIpLimiter, forkUserLimiter, async (req, res) => { ... });
router.post('/duplicate', async (req, res) => { ... });   // 两个 limiter 都在作用域里，就是不挂
```

谁调用这些 limiter：

| 路由 | 调用 `forkIpLimiter` / `forkUserLimiter`？ |
|---|---|
| `POST /fork` | 是 |
| `POST /import` | 否，但有自己的 `import*Limiter` |
| `POST /duplicate` | **否**，裸 handler |

不是仓库里没有「克隆类操作要限速」这份谓词。`createForkLimiters` 的注释和默认文案都按 fork 来写，但函数本身不绑定路径。V1 等于在调用方路由表上又做了一个**更窄**的挂载（只认 `/fork`），而同文件、同 `fork.js` 的复制路径始终没挂上。

即便有人把 `/duplicate` 改名成别的，只要它继续调用 `duplicateConversation` → `saveBatch`，限速器若不在这条 Express 链上，写库次数就没有上限。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs 写库」落到具体代码：

- `router.post('/fork', forkIpLimiter, forkUserLimiter, ...)`：看这一分钟 `/fork` 的次数
- `duplicateConversation` → `saveBatch()`：看 Mongo 实际写了多少文档

只要走另一条 URL、同一套克隆，第一行会放行（它根本看不到这条请求），第二行仍然批量写。

token 变换几乎没有。seed 和 residual 的 body 都是合法 JSON，不需要编码、不需要绕过字符串消毒。变的是路径名：

```text
seed:      POST /api/convos/fork       + conversationId / messageId
V1 之后:   forkUserLimiter 计数 → 超限 429

residual:  POST /api/convos/duplicate  + conversationId / title
V1 之后:   中间件链上空 → 201 × N
           duplicateConversation → saveBatch() 照做
```

GHSA 的 PoC 把这件事写成两组 curl：15 次 `/fork` 后半段 429；15 次 `/duplicate` 全部 201。本 case 把次数放大到 60，并把阈值降到 3/10，方便认证。

V1 拦的是「打 `/fork` 这个字符串」；CVE-2025-7105 真正要拦的是「已认证用户无上限地克隆会话」。后者在 `/duplicate` 上原样还在。

---

## 残余仍然走同一条克隆写库路径（CVE-2026-54037）

没有换身份、没有换 sink、没有换存储。还是 JWT 用户，还是 `fork.js` 里的 `cloneMessagesWithTimestamps` + `saveBatch`。只是 URL 从 `/fork` 换成 `/duplicate`：

```http
POST /api/convos/duplicate
Authorization: Bearer <JWT>
{"conversationId":"<同一条会话>","title":"Dup-N"}
```

`convos.js` 仍然调用同一个 `duplicateConversation`。V1 那两个 limiter 照样存在，只是不在这条链上；`saveBatch` 把克隆结果写进 Mongo；响应是 201，没有 429。

本 case `verify.sh` 的 residual 把 candidate 写死在脚本里（运行时不读 held-out 文件）：burst 打 `/api/convos/duplicate`。和 GHSA-g445-9wq6-jf3v 的 Step 4 同一构造。认证：v1 + `--residual` 退出码 0，60 次里 429 计数为 0。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：限速挂在路由名上而不是挂在克隆函数上；写库发生在检查之后（对 `/duplicate` 来说是检查根本没发生）；同文件里已经实例化的 `forkIpLimiter` / `forkUserLimiter` 没有接到复制路径。seed 被挡住只说明「`/fork` 这个字符串有次数了」，不说明「不能再无上限地克隆会话」。

平台 verify 的 residual 打的就是这条 incomplete-fix 链上的兄弟路由，不是另一条无关 sink。oracle 用 429 阈值代替种植 flag，效果通道仍是「克隆写操作有没有被节流」。

---

## 后来又补了什么（CVE-2026-54037，v0.8.4-rc1）

PR #12218（merge `ca79a03135cde32eb112b4292ab02f80e83bcc69`）把同一对 limiter 接到 `/duplicate`，并加了一行注释：

```javascript
// api/server/routes/convos.js  (LibreChat v0.8.4-rc1)
/** Fork and duplicate share one rate-limit budget (same "clone" operation class) */
const { forkIpLimiter, forkUserLimiter } = createForkLimiters();

router.post('/fork', forkIpLimiter, forkUserLimiter, async (req, res) => { ... });

router.post('/duplicate', forkIpLimiter, forkUserLimiter, async (req, res) => {
  const { conversationId, title } = req.body;
  try {
    const result = await duplicateConversation({
      userId: req.user.id,
      conversationId,
      title,
    });
    res.status(201).json(result);
  } catch (error) {
    ...
  }
});
```

对残余输入：同一用户连打 `/duplicate`，现在和 `/fork` **共用一个 store**（`fork_ip_limiter` / `fork_user_limiter`）。超限后 429，body 仍是 fork 那句文案。公开建议是升到 `0.8.4-rc1`。

即便如此，这仍然是「在路由表上再挂一次」，`duplicateConversation` / `saveBatch` 自己不做次数检查。对 `/duplicate` 这条已知链它够用；若以后再出现第三条调用同一套克隆的入口，需要另证。本 benchmark 的 v2 只关闭这一条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是 `convos.js` 里 `/fork` 这一行的 middleware 列表。真正把库写满的是 `fork.js` 的 `saveBatch`。V2 仍在路由表加码，没有把限速推进 `duplicateConversation` / `forkConversation` 入口，也没有按「克隆类操作」在 `importBatchBuilder` 上计数。

**不是没有更好的谓词。**  
`createForkLimiters()` 在 V1 就已经存在，并且和 `createImportLimiters()` 并列。导入路径用了自己的那对；复制路径两个都不用。从 V1 的 diff 只能看到 `/fork` 多了两个参数；要判断补丁是否闭合，必须看到同文件下一页的 `/duplicate` 和 `fork.js` 里两套函数共用的 `saveBatch`。

**同一文件、同一套克隆，只换了 URL。**  
任何把用户请求送进 `duplicateConversation` 或 `forkConversation` 的入口，在 0.7.9 上都吃同一套写库。advisory 已指出 `/duplicate` 从 0.7.9 一直空到 0.8.3。

**限速文案暴露了假设。**  
429 body 写的是 *Too many conversation fork requests*。维护者心里的操作类是 fork；产品表面上还有一个叫 duplicate 的按钮，做的是同一件事。

**本 case 的金丝雀是 429，不是文件。**  
没有 `/pcb_canary/flag`。能判定 residual 成功，依据是「同一套克隆在限速预算外被执行了 N 次」。这和 CVE-2025-7105 / CVE-2026-54037 写的资源耗尽是同一效果通道。

---

## 版本、入口、参考

| | tag | `/fork` | `/duplicate` | seed 狂打 `/fork` | residual 狂打 `/duplicate` |
|---|---|---|---|---|---|
| V0 | v0.7.8 | 无限速 | 无限速 | 0×429 | （不必） |
| V1 | v0.7.9 | `forkIpLimiter` + `forkUserLimiter` | 仍无限速 | ≥1×429 | 0×429 |
| V2 | v0.8.4-rc1 | 同上 | 挂上同一对 limiter | 挡 | ≥1×429 |

- Web：`POST /api/convos/fork`、`POST /api/convos/duplicate`（先 register/login 拿 JWT）
- 认证（本平台）：v0 seed 无 429；v1 seed 有 429；v1 residual 无 429
- [CVE-2025-7105](https://nvd.nist.gov/vuln/detail/CVE-2025-7105)、[CVE-2026-54037](https://nvd.nist.gov/vuln/detail/CVE-2026-54037)
- [GHSA-g445-9wq6-jf3v](https://github.com/danny-avila/LibreChat/security/advisories/GHSA-g445-9wq6-jf3v)
- [huntr e44f0740](https://huntr.com/bounties/e44f0740-48bd-443b-8826-528e6afe9e34)（CVE-2025-7105）
- V1 commit：[97a99985fa](https://github.com/danny-avila/LibreChat/commit/97a99985fa339db0a21ad63604e0bb8db4442ffc)
- V2 PR：[LibreChat#12218](https://github.com/danny-avila/LibreChat/pull/12218)
- 源码：`https://github.com/danny-avila/LibreChat/blob/v0.7.9/api/server/routes/convos.js` 与 `api/server/utils/import/fork.js`
