# LibreChat 上传限额：主 multer 加了 `fileSize`，会话导入那份实例没加

- Case：`PCBV2-0136`
- 产品：LibreChat（自建 ChatGPT 前端，镜像 `ghcr.io/danny-avila/librechat`）
- 链：CVE-2024-11171 / GHSA-c2qr-w9p6-cxgr（v0.7.5 → v0.7.6，commit `bb58a2d0`）→ CVE-2026-54024 / GHSA-52f6-fqwv-jccf（v0.7.6 → v0.8.4-rc1）
- 源码对着 GitHub tag `v0.7.6` 的 `api/server/routes/files/avatar.js`、`api/server/routes/files/multer.js` 的 `createMulterInstance`、`api/server/routes/convos.js` 的导入 multer、`api/server/services/Files/process.js` 的 `filterFile`。运行时是整台官方应用 + Mongo，不是抽出来的 multer 调用。

2024–2025 年，0.7.6 修 Huntr 报告的无限制内存上传：头像路由不再 `multer()` 默认内存存储，改走磁盘文件 + `filterFile(..., isAvatar: true)` 的 `avatarSizeLimit`（默认 2MB）；主文件路由的 `createMulterInstance()` 加上 `limits: { fileSize: fileConfig.serverFileSizeLimit }`。GHSA-52f6-fqwv-jccf 标题就是 *Incomplete Fix for CVE-2024-11171*：`POST /api/convos/import` 自己 `multer({ storage, fileFilter })`，**没有** `limits`。应用层 `fs.stat` 比较 `CONVERSATION_IMPORT_MAX_FILE_SIZE_BYTES`，但该环境变量在 `.env.example` 里是注释掉的，`size > undefined` 为假；即便设置了，检查也发生在 multer **已经把整文件写到磁盘之后**。

根因不只是「漏了一个数字」。检查插在「主上传工厂 / 头像 filterFile」这一层；真正接 multipart 的还有另一份 multer 实例；限额配置已经存在，却没挂到导入路由。下面按登录后的两次 POST 走进去、0.7.6 改了哪几行、限额之后谁消费 `req.file`、更强的 `limits.fileSize` 有没有挂上 sibling，把这几层写完。

平台 residual 走 `/api/convos/import`，seed 走 `/api/files/images/avatar`。HTTP 入口不同。这正是 advisory 写明的 sibling multer，不是另起的洞。heldout 与 V1 `convos.js` 对得上。平台把 6MB JSON 写进导入，并在会话列表里找 `RUN_FLAG`（效果通道从「头像 200 vs 500」换成「导入 201 + 列表含 flag」）；源码层残余仍是「这份 multer 不限大小」。

---

## 这块功能本来在干什么

LibreChat 用 multer 接 multipart。两条相关路由：

```http
POST /api/files/images/avatar     multipart field input   （头像）
POST /api/convos/import           multipart field file    （会话 JSON 导入）
```

头像在 0.7.5 上是 `const upload = multer(); router.post('/', upload.single('input'), ...)`：默认 **MemoryStorage**，没有 `limits`，整个文件进进程堆。导入在 0.7.6 上已经用磁盘 `storage`，但仍不限大小，随后 `importConversations` `fs.readFile` + `JSON.parse` 整文件进内存。

成功穿越之后的效果是：**超默认限额的上传被接受**。本 case 用 6MB（头像默认限额 2MB；导入在 v2 上被设成 5MB）当阈值。seed：头像 200 且 JSON 含 `url`。residual：导入 201 *Conversation(s) imported successfully*，会话里能看到嵌入的 flag。被挡住：头像 500；导入 413。

数据流：

```text
multipart body
    → 某条路由上的 multer 实例
         V0 头像：MemoryStorage，无 fileSize
         V1 头像：上游已落盘的 req.file + filterFile avatarSizeLimit   ← 补丁插在这里
         V1 导入：multer({ storage, fileFilter }) 无 limits            ← 残余走这里
    → 业务：resizeAvatar / importConversations
```

设计意图：上传不能无界占内存或磁盘。V1 只落实在文件/头像那条工厂上。

---

## 原始漏洞：头像 multer 无上限（CVE-2024-11171，v0.7.5）

NVD：*When using in-memory storage (the default setting for multer), there is no limit on the upload file size ... server crash due to out-of-memory*。固定版本 0.7.6。Huntr / GHSA-c2qr-w9p6-cxgr。

0.7.5 头像路由：

```javascript
const upload = multer();
router.post('/', upload.single('input'), async (req, res) => {
  const input = req.file.buffer;
  ...
});
```

`multer()` 无参数 → MemoryStorage，无 `limits.fileSize`。6MB PNG 进 `req.file.buffer`，业务跑完返回 `{ url }`。v0 + `--seed` 退出码 0。未认证即可打这条（NVD PR:N）；本 case 仍先注册登录，与 residual 共用会话。

---

## 维护者改了什么（CVE-2024-11171 修复，v0.7.6）

commit `bb58a2d0662ef86dc75a9d2f6560125c018e3836`。tag `v0.7.6` 头像路由不再自己 `multer()`，假定上游已经把文件落到磁盘：

```javascript
// api/server/routes/files/avatar.js  (tag v0.7.6)
router.post('/', async (req, res) => {
  try {
    filterFile({ req, file: req.file, image: true, isAvatar: true });
    const userId = req.user.id;
    const { manual } = req.body;
    const input = await fs.readFile(req.file.path);
    ...
    res.json({ url });
  } catch (error) {
    const message = 'An error occurred while uploading the profile picture';
    logger.error(message, error);
    res.status(500).json({ message });
  }
  ...
});
```

`filterFile` 对头像改走 `fileConfig.avatarSizeLimit`：

```javascript
// api/server/services/Files/process.js :: filterFile  (v0.7.6 相关片段)
const fileSizeLimit = isAvatar === true ? fileConfig.avatarSizeLimit : sizeLimit;
if (file.size > fileSizeLimit) {
  throw new Error(`File size limit of ${fileSizeLimit / megabyte} MB exceeded for ${
    isAvatar ? 'avatar upload' : `${endpoint} endpoint`
  }`);
}
```

主文件工厂：

```javascript
// api/server/routes/files/multer.js :: createMulterInstance  (v0.7.6)
return multer({
  storage,
  fileFilter,
  limits: { fileSize: fileConfig.serverFileSizeLimit },
});
```

对 6MB 头像，`filterFile` 抛错，路由 catch 成 500 *An error occurred while uploading the profile picture*。v1 + `--seed` 退出码 10。

同一 tag 上，导入路由：

```javascript
// api/server/routes/convos.js  (tag v0.7.6)
const { storage, importFileFilter } = require('~/server/routes/files/multer');
...
const upload = multer({ storage: storage, fileFilter: importFileFilter });

router.post(
  '/import',
  importIpLimiter,
  importUserLimiter,
  upload.single('file'),
  async (req, res) => {
    await importConversations({ filepath: req.file.path, requestUserId: req.user.id });
    res.status(201).json({ message: 'Conversation(s) imported successfully' });
  },
);
```

补丁默认了两件事：

1. 危险的无限制上传就是头像（以及主 `createMulterInstance` 覆盖的那些文件路由）。
2. 导入要么会复用那份工厂，要么应用层 `CONVERSATION_IMPORT_MAX_FILE_SIZE_BYTES` 会在读盘前拦住。

两件事都不成立。导入 **new 了一份自己的 multer**，只复用 `storage` 和 `importFileFilter`（按 JSON MIME 过滤），不复用 `limits`。GHSA 指出应用层检查：环境变量默认未设置；比较发生在 multer 写完盘之后；通过之后还 `readFile` + `JSON.parse` 整包进堆。

---

## 消毒之后，谁真正消费那个文件

头像路径上，`filterFile` 消费 `req.file.size`，超限则抛错，`resizeAvatar` 看不到大 buffer。导入路径上，multer 先把字节写到 `uploads/temp/<userId>/`，再把路径交给 `importConversations`。**没有**第二道与 `serverFileSizeLimit` / `avatarSizeLimit` 对齐的闸门（默认情况下）。

`importIpLimiter` / `importUserLimiter` 是速率限制，不是字节数。`importFileFilter` 只问是不是 JSON。6MB 的会话导出是合法 JSON，filter 放行。

所以：过滤器刚看过的是头像/主工厂的 size；导入实例看到的是「磁盘上能写多大写多大」。两套 multer 中间没有共享的 `limits.fileSize`。

---

## 仓库里已经有更强的检查，导入实例没用

`createMulterInstance` 在同一文件 `multer.js` 里已经写出 `limits: { fileSize: fileConfig.serverFileSizeLimit }`。`convos.js` 从该文件 import 了 `storage` 和 `importFileFilter`，唯独不调用 `createMulterInstance`。

应用层本有 `CONVERSATION_IMPORT_MAX_FILE_SIZE_BYTES`，但：

| 谓词 | v0.7.6 导入路径 |
|---|---|
| multer `limits.fileSize` | **未设置** |
| `createMulterInstance()` | **未调用** |
| env `CONVERSATION_IMPORT_MAX_FILE_SIZE_BYTES` | 默认 undefined，比较恒假 |
| 速率限制 | 只限次数 |

不是没有更好的谓词，是 **第二份 multer 没挂 limits，应用层闸门默认关闭且时机太晚**。V2 才把 `resolveImportMaxFileSize()`（默认 250MiB）塞进 `limits.fileSize`，并在 `LIMIT_FILE_SIZE` 时回 413。

---

## 这个补丁挡住了什么、没挡住什么

- `filterFile(..., isAvatar: true)`：看 `file.size` 是否大于 `avatarSizeLimit`（2MB）
- `createMulterInstance` 的 `limits.fileSize`：主文件路由
- 导入 `multer({ storage, fileFilter })`：不看大小

```text
seed  6MB PNG → POST /api/files/images/avatar
      V1：filterFile 抛错 → 500，无 url

residual 6MB JSON → POST /api/convos/import
      V1：multer 收完整文件 → 201 imported
      会话列表 / JSON 里出现嵌入的 RUN_FLAG
```

V1 挡的是头像（以及走工厂的文件上传）；它没挡会话导入。seed 被挡住只说明那一条路由的 size 比较生效了。

---

## 残余仍然是「multer 接受过大文件」（CVE-2026-54024）

没有换认证、没有换 multipart、没有换成另一类资源耗尽。还是登录后的一次 upload。heldout / 平台 verify 把候选写在导入路由上。认证目标：v1 201 且效果通道里出现 flag。NVD / GHSA 描述的是磁盘+内存耗尽（CWE-770）；本 case 用阈值 oracle 代替真 OOM，避免把 runner 打挂。

所以残余不是新洞面，而是同一「无限制 multipart」问题上三件事叠在一起：修复按实例而不是按「所有 multer()」；导入自己 new 实例；事后 `stat` 默认不生效。平台观察导入成功与否，与 advisory 的 sink 一致，只是检测从崩溃改成 201/413 + flag 反射。

---

## 后来又补了什么（CVE-2026-54024，v0.8.4-rc1）

PR #12221 一类变更：`resolveImportMaxFileSize()` +

```javascript
const importMaxFileSize = resolveImportMaxFileSize();
const upload = multer({
  storage,
  fileFilter: importFileFilter,
  limits: { fileSize: importMaxFileSize },
});
function handleUpload(req, res, next) {
  uploadSingle(req, res, (err) => {
    if (err && err.code === 'LIMIT_FILE_SIZE') {
      return res.status(413).json({ message: 'File exceeds the maximum allowed size' });
    }
    ...
  });
}
router.post('/import', ..., handleUpload, ...);
```

对残余：6MB > 测试环境的 5MB 上限，multer 在落盘完成前拒绝，413。公开建议升到 0.8.4-rc1，并配置 `CONVERSATION_IMPORT_MAX_FILE_SIZE_BYTES`。本 benchmark 的 v2 只关闭这条导入阈值 residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是头像路由和主工厂。真正还能无界写盘/读进内存的是另一份 `multer({...})`。V2 仍在导入调用点加 `limits`，没有强制「仓库里每一处 multer 必须经过 createMulterInstance」。

**不是没有更好的谓词。**  
`limits: { fileSize }` 已经写在 `multer.js`。`convos.js` 同文件 import 了 storage，却手写了一份无 limits 的实例。从 bb58a2d0 只能看到头像/工厂；要判断是否闭合，必须看到 `const upload = multer({ storage, fileFilter })`。

**同一类 multipart，只换了 URL。**  
任何 `multer()` 默认实例在 0.7.6 上只要没抄到 `limits`，都还是 CVE-2024-11171 的亲戚。导入只是审计时还活着的那条。

**应用层检查在 multer 之后等于没挡磁盘。**  
env 未设时连比较都不会触发。即便设了，大文件已经占用 inode 和块设备。

**阈值 oracle 不是另一种漏洞。**  
flag 出现在导入的会话内容里，只为了让平台在不打挂进程的情况下观察「过大文件被接受」。源码层的不完整修复仍是 missing `fileSize`。

---

## 版本、入口、参考

| | LibreChat | 头像 | `POST /api/convos/import` multer | 6MB 头像 seed | 6MB 导入 residual |
|---|---|---|---|---|---|
| V0 | v0.7.5 | 内存 multer，无限制 | （不必） | 200 `{url}` | （不必） |
| V1 | v0.7.6 | `filterFile` 2MB | 无 `limits.fileSize` | 500 | 201 |
| V2 | v0.8.4-rc1 | 同 V1 | `limits.fileSize` + 413 | 挡 | 413 |

- seed：`POST /api/files/images/avatar`
- residual：`POST /api/convos/import`
- [CVE-2024-11171](https://nvd.nist.gov/vuln/detail/CVE-2024-11171)、[CVE-2026-54024](https://nvd.nist.gov/vuln/detail/CVE-2026-54024)
- [GHSA-c2qr-w9p6-cxgr](https://github.com/advisories/ghsa-c2qr-w9p6-cxgr)、[GHSA-52f6-fqwv-jccf](https://github.com/danny-avila/LibreChat/security/advisories/GHSA-52f6-fqwv-jccf)
- V1 commit [`bb58a2d0`](https://github.com/danny-avila/LibreChat/commit/bb58a2d0662ef86dc75a9d2f6560125c018e3836)；V2 [PR #12221](https://github.com/danny-avila/LibreChat/pull/12221)
- 源码：[`v0.7.6` avatar.js](https://github.com/danny-avila/LibreChat/blob/v0.7.6/api/server/routes/files/avatar.js)、[multer.js](https://github.com/danny-avila/LibreChat/blob/v0.7.6/api/server/routes/files/multer.js)、[convos.js](https://github.com/danny-avila/LibreChat/blob/v0.7.6/api/server/routes/convos.js)
