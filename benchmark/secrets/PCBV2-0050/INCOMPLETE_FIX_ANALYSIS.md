# Gotenberg：ExifTool 的 `-key=value` 只消毒了等号左边

- Case：`PCBV2-0050`
- 产品：Gotenberg（Docker 无状态 PDF API）。本 case 用官方镜像 `gotenberg/gotenberg:8.29.1` / `8.30.1` / `8.31.0`，打未鉴权的 `POST /forms/pdfengines/metadata/write`。
- 链：CVE-2026-42589（8.29.1 → 8.30.1，危险伪标签 KEY 改成 `EqualFold`）→ CVE-2026-40281（8.30.1 → 8.31.0，VALUE 拒绝 `\n\r\x00`）
- 源码对着 GitHub tag `v8.30.1` / `v8.31.0` 的 `pkg/modules/exiftool/exiftool.go`：`WriteMetadata`、`dangerousTags`、`validateMetadataValue`。运行时是官方镜像整包，不是抽出来的函数。

Gotenberg 把用户 JSON 元数据交给 `go-exiftool`，后者按行写成 `-<key>=<value>` 喂给常驻 `exiftool -stay_open True -@ -`。ExifTool 把 `FileName` / `Directory` / `SymLink` / `HardLink` 当成文件系统伪标签，写它们等于 rename / move / 建链接。8.30.1 把 KEY 侧的精确删除改成大小写不敏感，并补上 SymLink/HardLink。GHSA-q7r4-hc83-hf2q 写明：*This is a complete bypass of the key-sanitization fix introduced in v8.30.1 … The fix validated the wrong side of the `=` sign.*

根因不只是「漏了一个危险标签」。检查插在 map 的 **key**；真正进 ExifTool stdin 的是 `fmt.Fprintln(stdin, "-"+k+"="+v)` 整行。下面按 POST 走进去、8.30.1 改了哪一段、`SetString` 之后谁消费那个字符串、更宽的字符表有没有挂上 VALUE，把这几层写完。

---

## 这块功能本来在干什么

Gotenberg 对外提供文档转换 HTTP API。PDF engines 模块有读写元数据的接口，不鉴权。一次典型写入：

```http
POST /forms/pdfengines/metadata/write
Content-Type: multipart/form-data

files:     <一份合法 PDF>
metadata:  {"Author":"alice","Title":"report"}
```

`WriteMetadata` 先 `ExtractMetadata` 读现有标签，再按用户 map 调 `fileMetadata[0].SetString(key, val)`，最后 `exifTool.WriteMetadata`。`barasher/go-exiftool` 对每个 pair 做：

```text
fmt.Fprintln(e.stdin, "-"+k+"="+str)
```

ExifTool 的 `-stay_open` 协议按**行**切参数。成功穿越之后的效果是：**处理中的临时 PDF 被伪标签改名到攻击者选的路径**。本 case 用 `/tmp/pcb_{key,val}_${PCB_FLAG}` 当 sentinel；文件存在且仍是 `%PDF` 头，就是一次良性 state-write，不是 `-if` Perl eval。

数据流：

```text
multipart metadata JSON
    → json.Unmarshal → map[string]any     ← Go 会保留 JSON 字符串里的真实 \n
    → ExifTool.WriteMetadata
         V1：按 key EqualFold 删除 FileName/Directory/HardLink/SymLink
         不看 value
         SetString(key, val)              ← val 原样
    → go-exiftool Fprintln("-"+k+"="+v)   ← 行协议，\n 切成第二参数
    → ExifTool 执行 -FileName=<path>      ← 真正的 rename
```

没有登录。判断完全信任「key 不是那四个名字」，不信任 value 里会不会再长出一行 `-FileName=`。

---

## 原始漏洞：精确、大小写敏感的 key 删除（CVE-2026-42589 形态，8.29.1）

8.29.1 的守卫是一张短名单、精确删除（case.json / original_poc 对照源码，**observed** 于 8.30.1 注释所描述的「改之前」行为）：

```go
// pkg/modules/exiftool/exiftool.go  （8.29.1，精确匹配）
dangerousTags := []string{"FileName", "Directory"}
for _, tag := range dangerousTags {
    delete(metadata, tag)   // 只删字面 "FileName"，不删 "filename"
}
```

ExifTool 自己对标签名大小写不敏感。`{"filename":"/tmp/pcb_key_<flag>"}` 过得了 `delete`，stdin 上变成 `-filename=/tmp/pcb_key_...`，PDF 被 rename。这就是 v0 + `--seed` 退出码 0。

公开 GHSA-rqgh-gxv4-6657 / NVD CVE-2026-42589 把同一接口说成「JSON **key** 里嵌 `\n`，切开后注入 `-if` Perl」。那是更重的 RCE 写法。8.30.1 实际合入的是危险标签的 `EqualFold`，**不是** key 的控制字符白名单（见下一节）。本 case 的 seed 按 **tag 源码真正挡住的那条** 来写：大小写变体的 `filename` key。advisory 文案和 8.30.1 源码不对齐，分析以 GitHub tag `v8.30.1` 为准。

---

## 维护者改了什么（CVE-2026-42589 修复，8.30.1）

tag `v8.30.1` 的 `WriteMetadata` 在把用户 map 交给 `SetString` **之前**，只扫 key（`pkg/modules/exiftool/exiftool.go`，函数 `WriteMetadata`）：

```go
// pkg/modules/exiftool/exiftool.go :: WriteMetadata  （v8.30.1）
// Filter user-supplied metadata to prevent ExifTool pseudo-tags from
// triggering dangerous side effects like file renames, moves, or link
// creation. Comparison is case-insensitive because ExifTool processes
// tag names case-insensitively.
// See https://exiftool.org/TagNames/Extra.html.
dangerousTags := []string{
    "FileName",  // Writing this triggers a file rename in ExifTool
    "Directory", // Writing this triggers a file move in ExifTool
    "HardLink",  // Writing this creates a hard link in ExifTool
    "SymLink",   // Writing this creates a symbolic link in ExifTool
}
for key := range metadata {
    for _, tag := range dangerousTags {
        if strings.EqualFold(key, tag) {
            delete(metadata, key)
        }
    }
}

for key, value := range metadata {
    switch val := value.(type) {
    case string:
        fileMetadata[0].SetString(key, val)  // val 原样，无校验
```

对 seed 这种明文 `filename` key，它确实够用：`EqualFold("filename","FileName")` 为真，key 被删，stdin 上没有 `-filename=`，sentinel `/tmp/pcb_key_*` 不出现。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险形态长得像「元数据 **key** 等于那四个伪标签（忽略大小写）」。
2. 只要 key 侧干净，写到 ExifTool stdin 的那一行就不会再变成文件系统操作。

第二点不成立。`SetString` 之后的消费者按行解析 `key=value`；value 里的换行会造出**新的 key**。

对照：GHSA-q7r4 把 commit `405f106`（加 `safeKeyPattern`）记成「8.30.1 的 key 消毒」。我拉了 `405f106.diff`：它是在**已经有** `EqualFold` 的文件上再加 `safeKeyPattern`。GitHub tag `v8.30.1` 的 `exiftool.go` **没有** `safeKeyPattern`，也没有 `regexp` import。`safeKeyPattern` 出现在 tag `v8.31.0`。**observed**：8.30.1 = EqualFold 黑名单；405f106 / 8.31.0 才是 key 字符白名单。advisory 把两次 key 加固叠在一个版本号上了。

---

## 消毒之后，元数据怎么接到 ExifTool stdin 上

V1 的 `EqualFold` 循环一结束，同一个函数立刻把剩下的 pair 原样 `SetString`。`go-exiftool`（GHSA-q7r4 引用的实现）写的是：

```text
fmt.Fprintln(e.stdin, "-"+k+"="+str)
```

`Fprintln` 在末尾加 `\n`，但 **str 内部的 `\n` 不会被转义**。ExifTool `-@ -` 把 stdin 每一行当成一个参数。于是：

```text
k="Title", str="x\n-FileName=/tmp/pcb_val_FLAG"

stdin 实际两行:
  -Title=x
  -FileName=/tmp/pcb_val_FLAG
```

第二行的 key 是 `FileName`。它从未经过上面那个 `for key := range metadata` 循环——那个循环看的是 JSON 对象的 key `Title`，`Title` 不在危险名单里。

过滤器刚看过的是 Go map 的 key 字符串；ExifTool 看到的是按行切开之后的伪标签。两套语义中间没有第二次「value 里不许出现参数分隔符」的谓词。sentinel 能出现在 `/tmp/pcb_val_*`，依据就是这一步。

JSON 这一层帮了忙：`json.Unmarshal` 会把 JSON 字符串里的 `\n` 还原成真实 LF 字节，Go `string` 带着它走进 `SetString`。multipart 的 `metadata` 字段是一段 JSON 文本，不是已经切开的 ExifTool 行。

---

## 仓库里已经有一张危险标签表，只问了 key

同一份 `WriteMetadata` 里，维护者很清楚 ExifTool 伪标签会 rename / move / 建链接——注释把 Extra Tags 手册都写上了。`systemTags` 还从**读**路径里删 `FileName`/`Directory`，避免把内部临时路径泄漏给客户端。写路径上这张表却只用来 `delete(metadata, key)`。

谁调用它：

| 位置 | 看 key？ | 看 value？ | 看 stdin 行？ |
|---|---|---|---|
| `systemTags` 删除（读出后再写回） | 是（现有文件字段） | 否 | 否 |
| `dangerousTags` EqualFold（V1 新增） | 是（用户 JSON key） | **否** | 否 |
| `SetString` / `Fprintln` | 否，假定 pair 已安全 | 原样拼接 | **这里才按行切开** |

不是没有「FileName 危险」这个谓词。是 **谓词挂在 JSON key 上，消费者却在 value 里再切参数**。即便没有换行，只要任何让 stdin 多出一行 `-FileName=` 的写法还能留下（CR、NUL、将来的其它分隔），EqualFold 都看不见。

8.31.0 才出现的 `safeKeyPattern`（`^[a-zA-Z0-9\-_.:]+$`）会拒绝 key 里的 `\n`，这是 GHSA-rqgh 那种「key 里嵌换行」的闭合；它仍然不问 value。所以就算把 405f106 提前到 V1，本 case 的 VALUE 残余也还活着。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「key 黑名单 vs 行协议」落到具体变换。

- `EqualFold(key, "FileName"|…)`：看 JSON 对象的 **key** 是不是那四个名字
- `Fprintln("-"+k+"="+v)`：看拼出来的那一行 ExifTool 怎么切
- ExifTool：看每一行是不是一个伪标签

只要构造一种输入，使 JSON key 看起来无害，而 value 里带一个 LF + `-FileName=`，第一层会放行，第二层仍然 rename。

held-out residual：

```text
metadata JSON:  {"Title":"x\n-FileName=/tmp/pcb_val_<FLAG>"}

V1 EqualFold:   key=Title，不是 FileName/Directory/HardLink/SymLink → 保留
SetString:      Title = "x\n-FileName=/tmp/pcb_val_<FLAG>"
stdin:          -Title=x
                -FileName=/tmp/pcb_val_<FLAG>
ExifTool:       把正在处理的 PDF rename 到 sentinel
HTTP:           常见 404（临时路径上的文件已经不在了）
```

V1 改的是 key；`Title` 这条链里根本没有「叫 FileName 的 key」可删。黑名单在 `SetString` 之前运行，value 里的第二行从未作为 map key 出现过。

seed 的变换作为对照：

```text
{"filename":"/tmp/pcb_key_<FLAG>"}
V0:  "filename" != "FileName" → 保留 → rename
V1:  EqualFold → delete → 无 sentinel
```

---

## 残余仍然走同一条 metadata/write 路径（CVE-2026-40281）

没有换接口、没有换字段、没有换身份。还是：

```http
POST /forms/pdfengines/metadata/write
metadata={"Title":"x\n-FileName=/tmp/pcb_val_<FLAG>"}
```

`WriteMetadata` 仍然先 EqualFold 再 `SetString`。V1 的危险标签循环照样执行；执行完之后因为 key 是 `Title`，value 带着 LF 进 stdin；ExifTool 执行注入的 `-FileName=`。

本 case residual 写死为：

```text
{"Title": "x\n-FileName=/tmp/pcb_val_<flag>"}
```

和 GHSA-q7r4 的 PoC `{"Title":"test\n-FileName=/tmp/inject_proof"}` 同一构造，只是路径带上 per-run flag。认证意图：v1 + `--residual` 在容器内观察到 sentinel 文件。case.json 记一次真实 Docker gate：VALUE 注入 reaches@V1、blocked@V2（**observed**）。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：补丁只问 JSON key；消费者按行解析 `k=v`；ExifTool 把任意一行 `-FileName=` 当成 rename。seed 被挡住只说明「叫 filename 的 key 没了」，不说明「stdin 上不能再出现 `-FileName=`」。

---

## 后来又补了什么（CVE-2026-40281，8.31.0）

tag `v8.31.0` 在同一函数里加了两层。一层是 key 白名单（也就是 405f106 那次），一层才是 VALUE：

```go
// pkg/modules/exiftool/exiftool.go  （v8.31.0）
var safeKeyPattern = regexp.MustCompile(`^[a-zA-Z0-9\-_.:]+$`)

func validateMetadataValue(key, value string) error {
    if strings.ContainsAny(value, "\n\r\x00") {
        return fmt.Errorf(
            "write PDF metadata with ExifTool: invalid metadata value for key %q (contains control character): %w",
            key, gotenberg.ErrPdfEngineMetadataValueNotSupported)
    }
    return nil
}
```

`WriteMetadata` 对 `string` / `[]string` / `[]any` 在 `SetString` 之前调 `validateMetadataValue`。对残余输入：

```text
value 含 \n → HTTP 400（ErrPdfEngineMetadataValueNotSupported）
sentinel 不出现
```

8.31.0 还把 `EqualFold` 改成先剥 `System:FileName` 这种 group 前缀再比，并加上 `FilePermissions`。公开建议是升级到 8.31.0。即便如此，若还有其它让 stdin 多出参数、却不含 `\n\r\x00` 的写法，需要另证。本 benchmark 的 v2 只关闭这一条 VALUE-newline residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是 JSON map 的 key 是否叫 FileName。真正 rename 的是 ExifTool 行协议上的 `-FileName=`。V2 才回到 value 里的参数分隔符。8.30.1 的 diff 里看不到对 `SetString` 参数的检查。

**不是没有危险标签表。**  
`dangerousTags` 在 V1 就存在，注释写明 rename/move/symlink。缺的是「拼进 stdin 之前，等号两边都不能引入新行」。从 V1 只能看到 `EqualFold`；要判断补丁是否闭合，必须看到 `Fprintln("-"+k+"="+v)` 和 ExifTool `-@ -` 按行切参数。

**同一函数、同一 `metadata` 字段，只换了哪一侧带注入。**  
任何把用户 JSON 交给 `WriteMetadata` 的接口，在 8.30.1 上都吃同一套「只扫 key」的逻辑。GHSA-rqgh 的 key-newline RCE 和本残余的 value-newline 是同一行协议的两侧。

**advisory 版本号和 tag 源码不一致。**  
NVD CVE-2026-42589 把 newline-in-key 说成「fixed in 8.31.0」；GHSA-q7r4 把 `safeKeyPattern` 说成 8.30.1。tag `v8.30.1` 实际只有 EqualFold。本 case 的 seed 按源码真正闭合的那条（大小写变体 key）来选，而不是按 advisory 字面。

---

## 版本、入口、参考

| | 镜像 | key 侧 | value 侧 | `filename` seed | `Title`+`\n-FileName=` residual |
|---|---|---|---|---|---|
| V0 | 8.29.1 | 精确 `delete("FileName")` | 无 | rename `/tmp/pcb_key_*` | （不必） |
| V1 | 8.30.1 | `EqualFold` + SymLink/HardLink | 无 | key 被删，挡 | stdin 切两行，rename `/tmp/pcb_val_*` |
| V2 | 8.31.0 | `safeKeyPattern` + 去 group 前缀的 EqualFold | `validateMetadataValue` 拒 `\n\r\x00` | 挡 | HTTP 400，挡 |

- Web：`POST /forms/pdfengines/metadata/write`
- 认证意图：v0 seed sentinel 存在；v1 seed 不存在；v1 residual sentinel 存在。case.json 记 Docker gate passed（**observed**）。
- [CVE-2026-42589](https://nvd.nist.gov/vuln/detail/CVE-2026-42589)、[GHSA-rqgh-gxv4-6657](https://github.com/gotenberg/gotenberg/security/advisories/GHSA-rqgh-gxv4-6657)
- [CVE-2026-40281](https://nvd.nist.gov/vuln/detail/CVE-2026-40281)、[GHSA-q7r4-hc83-hf2q](https://github.com/gotenberg/gotenberg/security/advisories/GHSA-q7r4-hc83-hf2q)
- 源码：[v8.30.1 exiftool.go](https://github.com/gotenberg/gotenberg/blob/v8.30.1/pkg/modules/exiftool/exiftool.go)、[v8.31.0 同文件](https://github.com/gotenberg/gotenberg/blob/v8.31.0/pkg/modules/exiftool/exiftool.go)
- commit `405f106`（`safeKeyPattern`，在 EqualFold 之后，随 8.31.0 出现在 tag 上）
