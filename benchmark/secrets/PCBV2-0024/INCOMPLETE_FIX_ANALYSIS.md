# ComfyUI `/view`：扩展名黑名单漏了浏览器会当文档执行的类型

- Case：`PCBV2-0024`
- 产品：ComfyUI（图像工作流 UI，aiohttp）
- 链：CVE-2024-10099（PR #6034，commit `59d58b11`）→ CVE-2025-6092（PR #8384，commit `4f4f1c64` / GHSA-495g-pwwr-x2vf）
- 源码对着 PR #6034 合并点 `59d58b1158141ed5de65adabf4ef42bcbb3ee3da` 的 `server.py :: view_image`。运行时是整包 ComfyUI + 真实 `/upload/image` 与 `/view`，不是抽出来的 `mimetypes.guess_type`。

PR #6034 在 `/view` 把 `{'.html','.htm','.js','.css'}` 强制成 `application/octet-stream`，想挡住「上传一段带脚本的 HTML，再让别人打开 `/view` 当页面执行」。公开 gist（CVE-2025-6092）指出：现代浏览器还会把 `application/xhtml+xml` 当顶层文档执行内联脚本，而 `.xhtml` **不在**那四个扩展名里。`mimetypes.guess_type('payload.xhtml')` 得到 `application/xhtml+xml`，`FileResponse` 原样发出，Chromium 执行 `<script>`。VulDB 把这件事记成 CVE-2025-6092，并写明 *Incomplete Fix CVE-2024-10099*。

根因不是「忘了 escape HTML」。检查插在**扩展名集合**上；真正决定浏览器是否渲染的是 `Content-Type` 头，它消费的是 `guess_type` 的结果，只有命中那四个扩展时才被覆盖。下面按请求走进去、补丁改了哪一段、消毒后 MIME 怎么进响应、已经算出来的 content_type 为什么不直接拿来做黑名单，把这三层写完。

---

## 这块功能本来在干什么

ComfyUI 允许把文件传到 input/output 目录（`POST /upload/image`，字段 `image`），再通过 `GET /view?filename=...&type=input` 取回。`view_image` 对图片走特殊处理；其它扩展走 `web.FileResponse`。设计意图：工作流预览自己的输出文件。没有登录。成功穿越之后的效果是**受害者浏览器把该文件当文档执行内联脚本**，读 `document.cookie` 打到内部 callback。本 case 的 flag 只在 headless Chromium 对应用 origin 的 cookie 里，不在文件 HTML 中；能在 callback 看到它，说明脚本真的跑了，不是反射。

数据流：

```text
POST /upload/image  (filename=payload.html 或 payload.xhtml)
    → 存入 input 目录
GET /view?filename=...&type=input
    → view_image
         content_type = mimetypes.guess_type(filename)[0] or octet-stream
         V1：if suffix in {'.html','.htm','.js','.css'}:
                 content_type = octet-stream
         FileResponse(..., Content-Type: content_type)
    → 浏览器按 MIME 决定：下载 vs 渲染执行
```

---

## 原始漏洞：`/view` 当 HTML 发出（CVE-2024-10099，#6034 之前）

`563291ee`（#6034 的 parent）里，非图片分支是：

```python
                        return web.FileResponse(file, headers={"Content-Disposition": f"filename=\"{filename}\""})
```

aiohttp 按文件猜测或默认类型发出；`.html` 变成 `text/html`，浏览器当页面打开，内联 `<script>` 执行。seed 上传 `payload.html`，受害者访问 `/view?filename=payload.html&type=input`，脚本把 cookie 里的 flag POST 到 callback。

没有扩展名或 MIME 黑名单。`Content-Disposition` 只有 `filename=`，没有 `attachment`，挡不住顶层导航渲染。

---

## 维护者改了什么（CVE-2024-10099 修复，`59d58b11`）

#6034 在 `FileResponse` 前加上 guess + 扩展名覆盖：

```python
# server.py :: view_image  (59d58b11, 约 L460–475)
                    else:
                        # Get content type from mimetype, defaulting to 'application/octet-stream'
                        content_type = mimetypes.guess_type(filename)[0] or 'application/octet-stream'

                        # For security, force certain extensions to download instead of display
                        file_extension = os.path.splitext(filename)[1].lower()
                        if file_extension in {'.html', '.htm', '.js', '.css'}:
                            content_type = 'application/octet-stream'  # Forces download

                        return web.FileResponse(
                            file,
                            headers={
                                "Content-Disposition": f"filename=\"{filename}\"",
                                "Content-Type": content_type
                            }
                        )
```

对 seed 的 `.html`：`file_extension` 命中集合，`Content-Type` 变成 `application/octet-stream`，Chromium 当下载/不执行，callback 无 flag。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 会当文档执行脚本的文件，扩展名就是那四个。
2. 安全决策应该看扩展名，而不是已经算出来的 `content_type`。

第二点与浏览器的实际行为相反：浏览器看 MIME，不看你磁盘上叫什么。更关键的是：`guess_type` 的结果已经在手里，却只用扩展名集合决定要不要覆盖。

---

## 消毒之后，类型怎么接到浏览器上

`guess_type` 对 `.xhtml` 返回 `application/xhtml+xml`（标准 MIME 映射）。扩展名不在 `{.html,.htm,.js,.css}` 里，`if` 不进，`FileResponse` 发出：

```text
Content-Type: application/xhtml+xml
Content-Disposition: filename="payload.xhtml"
```

没有 `attachment`。顶层导航时，Chromium 把 XHTML 当文档解析，执行 `<script type="application/javascript">`。gist PoC 用的就是这种文件。过滤器刚看过的是四个扩展名；浏览器看到的是 MIME。两套语义中间没有「可执行的 MIME 一律 octet-stream」的谓词。

`view_image` 从 query 取 `filename` / `type` / `subfolder`，拼出 input 目录下的路径再 `os.path.exists`。没有「只允许 png/jpg」的白名单；扩展名只用于 guess 和那四个强制下载。上传侧 `image` 字段的客户端 MIME（gist 里写成 `image/jpeg`）不参与 `/view` 的 Content-Type。展示类型完全由**文件名后缀 + guess_type + 四件套**决定。

`Content-Disposition` 仍是 `filename="..."`，没有 `attachment`。对 `text/html` 这种类型，缺少 attachment 时顶层导航会渲染；V1 靠把类型改成 octet-stream 让浏览器「不知道怎么打开」。`.xhtml` 保持 xhtml+xml 时，这条 Disposition 帮不上忙。

`view_image` 前面的图片分支按 Pillow 打开失败才落到 else；`.xhtml` 不是位图，走 else。上传接口 `/upload/image` 并不按 MIME 拒绝非图片：字段名叫 image，gist 里 `Content-Type: image/jpeg` 也能存一个 xhtml 文件。存储侧不消毒，展示侧的扩展名集合是唯一门。

---

## 仓库里已经有更强的检查，黑名单没用 MIME

同一段代码先算了 `content_type`，再按扩展名决定是否丢掉它：

```python
                        content_type = mimetypes.guess_type(filename)[0] or 'application/octet-stream'
                        file_extension = os.path.splitext(filename)[1].lower()
                        if file_extension in {'.html', '.htm', '.js', '.css'}:
                            content_type = 'application/octet-stream'
```

把 `if` 改成 `if content_type in {..., 'application/xhtml+xml', ...}` 就是 #8384。V1 已经调用了 `guess_type`——这正是「浏览器会怎么看待这个文件」的近似——却用更弱的扩展名集合覆盖策略。不是仓库里没有更好的谓词，是 **强制下载没用 MIME**。

Python `mimetypes` 还可能把 `.svg` 映射成 `image/svg+xml`（部分环境会执行脚本）；gist 也提到 svg。本 case 的 reference residual 是公开 PoC 的 `.xhtml`。#8384 的 MIME 集合含 `application/xhtml+xml`，不含 SVG；那是另一条链。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs 渲染」落到具体代码：

- `file_extension in {'.html','.htm','.js','.css'}`：看后缀是不是这四个
- 浏览器：看 `Content-Type` 是否为可执行文档类型

只要构造一种输入，使后缀不在集合里、但 `guess_type` 仍给出可执行 MIME，第一行会放行，第二行仍然跑脚本。

```text
filename = payload.xhtml
guess_type → application/xhtml+xml
扩展名 .xhtml ∉ V1 集合
FileResponse Content-Type: application/xhtml+xml
Chromium 执行 inline script → document.cookie → callback 含 FLAG
```

PR #8384 的复现步骤就是把 `test.xhtml` 放进 output，打开 `/api/view?filename=test.xhtml&type=output`：主分支当页面加载，补丁后变成下载。

---

## 残余仍然走同一条 `/view` 读文件路径（CVE-2025-6092）

没有换路由、没有换上传字段。还是：

```http
POST /upload/image   filename=payload.xhtml
GET  /view?filename=payload.xhtml&type=input
```

`view_image` 仍然走 else。V1 的四扩展名检查照样执行，`.xhtml` 不命中；`guess_type` 给出 `application/xhtml+xml`；受害者导航后脚本读 cookie。payload 是良构 XHTML，内联 script 把 `document.cookie` 拼到 callback URL。

payload 是带 XHTML 命名空间的良构文档，内联 script 把 cookie 拼到 callback。gist 还演示过 SVG；本 case 只认证 `.xhtml`，因为那是 #8384 明确加进 MIME 集合、且 `guess_type` 稳定给出 `application/xhtml+xml` 的那条。`.svg` 在 V2 是否仍可执行取决于系统 MIME 映射是否把 svg 标成 `image/svg+xml` 以及浏览器是否对带脚本的 SVG 导航执行——那是另一条链，不能从本 residual 自动推出。

本 case `verify.sh` 的 residual 把文件名和 body 写死为 `payload.xhtml` + 带 callback 的 script（语义来自 held-out / gist）。认证：v1 + `--residual` 退出码 0，callback 记录中观察到 flag。

所以残余不是新洞面，而是同一 `FileResponse` 上三件事叠在一起：检查语言是扩展名；浏览器消费的是 MIME；已经算出来的 `content_type` 没有用来做强制下载。seed 被挡住只说明「`.html` 不会再当页面发」，不说明「不能再通过 `/view` 让浏览器执行上传文件里的脚本」。

---

## 后来又补了什么（CVE-2025-6092，v0.3.40 / #8384）

`4f4f1c64` 把扩展名集合换成 MIME 集合：

```python
# server.py :: view_image  (4f4f1c64)
                        content_type = mimetypes.guess_type(filename)[0] or 'application/octet-stream'

                        # For security, force certain mimetypes to download instead of display
                        if content_type in {'text/html', 'text/html-sandboxed', 'application/xhtml+xml', 'text/javascript', 'text/css'}:
                            content_type = 'application/octet-stream'  # Forces download
```

对残余输入：`application/xhtml+xml` 命中集合，发出 octet-stream，Chromium 不执行，callback 无 flag。PR 说明写明 *uses mimetypes to add more restricted filetypes ... since mimetypes are what browsers use*，并 *adds XHTML documents to the list*。公开建议是升级到含 #8384 的版本（v0.3.40）。

即便如此，SVG、XML 其它可执行类型、以及 `Content-Disposition` 仍无 `attachment`，若 `guess_type` 给出未列入的可执行 MIME，需要另证。本 benchmark 的 v2 只关闭 `.xhtml` 这条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是后缀字符串。真正执行脚本的是浏览器按 `Content-Type` 的文档策略。V2 把黑名单接到已经算出来的 MIME 上，这才对准 sink。

**不是没有更好的谓词。**  
`content_type = guess_type(...)` 在 V1 已经存在。从 V1 的 diff 只能看到四个扩展名；要判断补丁是否闭合，必须看到 `guess_type('.xhtml')` 仍是 `application/xhtml+xml`，以及 `if` 根本不读这个变量（除非扩展命中）。

**同一 `view_image` else，只换了文件名。**  
`.html` 和 `.xhtml` 都是「带脚本的标记文档」。V1 只枚举了前者的常见后缀。

**Disposition 仍是 inline 友好的。**  
只有 `filename=`，没有 `attachment`。黑名单漏一项，顶层导航就会渲染。V2 仍靠把 MIME 改成 octet-stream 来「假装下载」。给 `FileResponse` 加上 `Content-Disposition: attachment` 会让漏网 MIME 也倾向下载，V1/V2 都没做这一步。

**金丝雀在受害者 cookie 里是有意的。**  
flag 不在上传文件里。callback 出现 flag，说明是文档里的 JS 读了 `document.cookie`，而不是服务端把 cookie 写进了 HTML。

**`mimetypes.guess_type` 依赖系统映射。**  
V1/V2 都信任标准库。`.xhtml` → `application/xhtml+xml` 是常见映射（#8384 的复现依赖它）。若某环境把 `.xhtml` 映射成 octet-stream，residual 会「碰巧」被挡，那不是补丁闭合，是映射帮了忙。本 case 与 PR 复现都假定映射给出 xhtml+xml。

**脚本类型属性不是扩展名检查的一部分。**  
payload 用 `type="application/javascript"`。V1 的 `.js` 只看**文件**后缀，不看文档内部的 script type。XHTML 里的脚本能不能跑，由文档 MIME 决定。

V1 与 V2 对已经算出来的 `content_type` 的差别：

```python
# V1 59d58b11 — 算了 MIME，决策看后缀
content_type = mimetypes.guess_type(filename)[0] or 'application/octet-stream'
file_extension = os.path.splitext(filename)[1].lower()
if file_extension in {'.html', '.htm', '.js', '.css'}:
    content_type = 'application/octet-stream'

# V2 4f4f1c64 — 决策看 MIME
content_type = mimetypes.guess_type(filename)[0] or 'application/octet-stream'
if content_type in {'text/html', 'text/html-sandboxed',
                    'application/xhtml+xml', 'text/javascript', 'text/css'}:
    content_type = 'application/octet-stream'
```

`.xhtml` 在两版里 `guess_type` 都是 `application/xhtml+xml`。V1 的 `if` 不读这个值；V2 读了。这就是 residual 只在 V1 上执行脚本的全部差别。

`view_image` 用 `os.path.splitext(filename)[1].lower()`，只取最后一个点。`payload.html.xhtml` 的扩展是 `.xhtml`，仍不在四件套里。双扩展名帮不了 V1，因为决策从不看「是不是 HTML 家族」，只看精确后缀集合。

响应头在 `FileResponse` 里按 `content_type` 写出 `Content-Type`。V1 对 `.xhtml` 把 `application/xhtml+xml` 原样交给浏览器；Chromium 把该 MIME 当 XML 文档处理，内嵌 `<script>` 在顶层导航里执行。V1 已经算过 MIME，却只用它当「没命中扩展名时的默认 Content-Type」，没有用它当「要不要强制 octet-stream」的谓词。

上传侧 `POST /upload/image` 不按 MIME 拒绝 `.xhtml`：文件落到 input 目录后，`GET /view?filename=...&type=input` 才是真正的 sink。补丁插在 `view_image` 的 Content-Type 赋值处，不插在上传校验处；残余因此仍走同一 GET，只换扩展名。

V2 的 MIME 集合仍是黑名单：`text/html`、`text/html-sandboxed`、`application/xhtml+xml`、`text/javascript`、`text/css`。`image/svg+xml` 等未列入。本 case 的 residual 只证明 V1 漏了 xhtml+xml 这一项已经算出来的值；不声称 V2 对所有可执行 MIME 闭合。

seed 的 `.html` 在 V1 因扩展名命中而被改成 octet-stream；residual 的 `.xhtml` 走同一 `else` 分支、同一 `FileResponse`，只是 `file_extension` 不在集合里，于是 `content_type` 保持 `guess_type` 的结果。闭合条件因此不是「再加几个后缀」，而是「决策读取已经存在的 MIME」。

---

## 版本、入口、参考

| | commit | `.html` seed | `.xhtml` residual | 强制下载依据 |
|---|---|---|---|---|
| V0 | `563291ee` | text/html，执行，FLAG | （亦可） | 无 |
| V1 | `59d58b11` | octet-stream，不执行 | xhtml+xml，执行，FLAG | 扩展名四件套 |
| V2 | `4f4f1c64` | 挡 | octet-stream，不执行 | MIME 集合含 xhtml+xml |

- Web：`POST /upload/image` + `GET /view?filename=...&type=input`，端口 8188；callback 收 cookie
- 认证（本平台）：v0 seed 观察到 flag；v1 seed 未观察到；v1 residual 观察到。
- 受害者：headless Chromium，cookie `session=<PCB_FLAG>` 种在应用 origin；flag 不在文件 HTML 里。
- [CVE-2025-6092](https://nvd.nist.gov/vuln/detail/CVE-2025-6092) / [gist PoC](https://gist.github.com/superboy-zjc/96f0d56da584d840ba18355cbea96ac4)
- 前置：CVE-2024-10099 / [PR #6034](https://github.com/comfyanonymous/ComfyUI/pull/6034)
- 闭合：[PR #8384](https://github.com/comfyanonymous/ComfyUI/pull/8384)（merge `4f4f1c64`）
- 源码函数：`server.py` 的 `view_image`；上传入口 `POST /upload/image`
- V1 源：ComfyUI `59d58b11` 的 `server.py`；V2 源：`4f4f1c64` 同文件 MIME 集合
- NVD：https://nvd.nist.gov/vuln/detail/CVE-2025-6092
- Huntr / gist 复现依赖 `.xhtml` → `application/xhtml+xml` 的系统 MIME 映射
