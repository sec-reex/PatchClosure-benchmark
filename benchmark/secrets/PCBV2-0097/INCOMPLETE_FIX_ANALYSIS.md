# Concrete CMS Express Entry List：写路径加了布尔门，unserialize 从来没人动

- Case：`PCBV2-0097`（`deser_concretecms_unserialize`）
- 产品：Concrete CMS（`concretecms/concretecms`）。Express Entry List 块把列配置和过滤字段存成 PHP 序列化字符串，渲染/编辑时再 `unserialize`。
- 链：CVE-2026-3452（9.4.7 → 9.4.8，PR `#12826`）→ CVE-2026-8135（9.4.8…9.5.0 → 9.5.1）
- 源码对着 GitHub tag `9.4.8` / `9.5.1` 的 `concrete/blocks/express_entry_list/controller.php`：`save`、`view` / `edit`、`doGetImportData`。运行时是整仓 clone + `c5:install`，不是抽出来的函数。

2026 年 3 月，Concrete CMS 9.4.8 给 Express Entry List 的 `save()` 加了一道写保护：除非 `$data['_fromCIF'] === true`，否则把 `columns` / `filterFields` 清空。这挡住了浏览器表单 POST——表单只能送来字符串 `"true"`，严格比较失败，恶意序列化串进不了库。三个月后 Nguyễn Văn Thiện 指出：REST API 用 `json_decode()` 解析 body，JSON `"_fromCIF": true` 会变成真正的 PHP boolean，门就开了。NVD CVE-2026-8135 写明 rogue administrator 可以 *bypass the intended protection mechanism (`_fromCIF === true`) ... by leveraging the REST API functionality*。9.5.1 的 `unserialize()` 调用仍然是裸的。

根因不只是「少拦了一种输入」。检查插在「要不要把客户端给的序列化串写进块记录」这一层；真正把任意类实例化出来的是渲染路径上的 `unserialize($this->columns)`。CIF 导入本来就有一条内部通道，9.4.8 却把那条通道的令牌放进了**不可信的 `$data` 数组**。下面按请求走进去、9.4.8 改了哪几行、blank 之后谁消费那个值、`allowed_classes` 有没有挂上，把这几层写完。

---

## 这块功能本来在干什么

Express 是 Concrete CMS 的自定义对象系统。Express Entry List 块让编辑者选一个 Express 实体、挑要显示的列、配搜索过滤。这些配置存在块记录的 `columns` 和 `filterFields` 两列里，类型是 PHP `serialize()` 之后的字符串。

一次典型的块保存（仪表盘、已登录管理员）：

```http
POST /index.php/ccm/system/block/action/add ...
Content-Type: application/x-www-form-urlencoded

columns=O%3A12%3A%22PcbFlagProbe%22%3A0%3A%7B%7D&filterFields=...
```

控制器 `save($data)` 把 `$data` 交给 `parent::save`，写进 `btExpressEntryList`。之后管理员打开页面或再点编辑，`view` / `edit` 把库里的串喂给 `unserialize`：

```php
# concrete/blocks/express_entry_list/controller.php  (tag 9.4.8, 约 L123–132)
        if ($this->filterFields) {
            $filterFields = unserialize($this->filterFields);
            $query->setFields($filterFields);
        }

        $columns = unserialize($this->columns);
        if ($columns) {
            $query->setColumns($columns);
        }
```

设计意图：`columns` / `filterFields` 必须是本块自己 `serialize()` 出来的 `ColumnSet` / 搜索字段对象。没有完整性签名，没有 `allowed_classes`。成功穿越之后的效果是：**任意 PHP 类在渲染时被实例化，魔术方法跑起来**。本 case 用良性影子类 `PcbFlagProbe`：`__wakeup` 读 `/canary/flag.txt`，响应 JSON 的 `flag_line` 里出现 `PCBFLAG_...`。

数据流：

```text
HTTP body（表单 POST 或 REST JSON）
    → 块 save($data)
         V1：($data['_fromCIF'] ?? null) === true ? 保留 : 清空 columns/filterFields
         若 !$fromCIF：再从 request 重建 serialize($set)
         parent::save($data)          ← 写库
    → 稍后 view() / edit()
         unserialize($this->columns)
         unserialize($this->filterFields)   ← 真正的 sink，V1/V2 都没改
    → 对象魔术方法 → /canary/flag.txt
```

CIF（Content Import Format）导入是另一条写路径：XML 站点包里的块节点要原样还原序列化字段。那条路径**应当**跳过 blank。问题是 9.4.8 用什么当「这是导入」的证据。

---

## 原始漏洞：表单把序列化串写进块记录（CVE-2026-3452，9.4.7）

9.4.7 的 `save()` 取出 `$fromCIF`，但**没有**随后的 blank。`$data['columns']` 和 `$data['filterFields']` 原样进 `parent::save`。表单字段是字符串，管理员（或被 XSS/CSRF 借用的会话）可以直接塞 `O:12:"PcbFlagProbe":0:{}`。

NVD CVE-2026-3452：*Concrete CMS below version 9.4.8 is vulnerable to Remote Code Execution by stored PHP object injection into the Express Entry List block via the columns parameter. An authenticated administrator can store attacker-controlled serialized data in block configuration fields that are later passed to unserialize() without class restrictions or integrity checks.* 报告者 YJK / ZUSO ART。

本 case 的 seed 走表单通道：

```text
columns = O:12:"PcbFlagProbe":0:{}
filterFields = 同上
_fromCIF = "true"     ← 字符串，即使有人带上这个字段
```

9.4.7 没有 blank，串进库。下一次 `view()` 调 `unserialize($this->columns)`，`PcbFlagProbe::__wakeup` 读金丝雀。这就是 v0 + `--seed` 退出码 0。

`$fromCIF` 在 9.4.7 已经存在：`doGetImportData` 会设 `$args['_fromCIF'] = true`。当时它只影响「要不要从 HTTP request 重建列集合」，并不挡住客户端直接提交的序列化串。

---

## 维护者改了什么（CVE-2026-3452 修复，9.4.8）

PR `#12826` / tag `9.4.8` 在 `save()` 入口、`parent::save` **之前**加了四行。GitHub blob `concretecms/concretecms` tag `9.4.8`：

```php
# concrete/blocks/express_entry_list/controller.php :: save  (9.4.8, 约 L320–327)
    public function save($data)
    {
        $this->on_start();
        $fromCIF = ($data['_fromCIF'] ?? null) === true;
        if (!$fromCIF) {
            $data['columns'] = '';
            $data['filterFields'] = '';
        }
```

字面意思：

| 片段 | 含义 |
|---|---|
| `$data['_fromCIF']` | 令牌住在**同一份** `$data` 里，和 payload 一起到 |
| `=== true` | 只要 PHP boolean `true`，字符串 `"true"`、整数 `1` 都不算 |
| `if (!$fromCIF) { blank }` | 非导入就把两个字段清掉 |

随后，若 `!$fromCIF`，函数会从 `$this->request->request` 重建列集合和过滤字段，再 `serialize` 写回去。所以表单 POST 的正常编辑仍然能保存**自己选的列**，只是不能再把客户端给的序列化 blob 原样入库。

对 seed 这种表单通道，它确实够用：

```text
表单 _fromCIF="true"  →  PHP 字符串 "true"
"true" === true       →  false
blank                 →  columns='', filterFields=''
重建自 request        →  没有合法 column[] 时仍是空串
view() unserialize('') →  不实例化 PcbFlagProbe
```

这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 只有 CIF 导入会把 `_fromCIF` 设成 boolean `true`。
2. 其它写入口（表单、REST、CLI）要么送不出 boolean，要么根本不经过这份 `$data`。

第一点在 9.4.8 的 `doGetImportData` 里确实成立：

```php
# 同文件 :: doGetImportData  (9.4.8, 约 L407–410)
        $args = parent::getImportData($blockNode, $page);
        $args['_fromCIF'] = true;
```

第二点不成立。REST API 把 JSON 解成 PHP 数组，JSON 的 `true` 就是 boolean。

---

## 检查之后，谁真正消费那个值

V1 的 `=== true` 一结束，同一个 `save()` 仍把 `$data['columns']` / `$data['filterFields']` 交给 `parent::save`。blank 只决定**库里存什么**。读路径完全不管 `_fromCIF`：

```php
# 同文件，edit/view 路径（9.4.8 与 9.4.7、9.5.1 字节级相同）
        $filterFields = unserialize($this->filterFields);
        $columns = unserialize($this->columns);
```

PHP 的 `unserialize` 没有 `allowed_classes`。任意 `O:<n>:"ClassName"` 都会 `new ClassName`，再跑 `__wakeup` / `__destruct`。过滤器刚看过的是「写的时候 `$data` 里有没有 boolean 令牌」；open 看到的是库里那串字节。两套语义中间没有第二次谓词。

本 case 的 `pcb_driver.php` 用 `json_decode` 解析 POST body，再调用**真实**控制器的 `save($data)` 和 `view()`。这对应 REST 通道：JSON 对象进 PHP 数组，类型得以保留。表单 `application/x-www-form-urlencoded` 则所有值都是字符串。

`parent::save` 把字段写进块记录。之后任何一次渲染都会走到上面那两行 `unserialize`。金丝雀在 `/canary/flag.txt`（应用目录外），能读到它，依据就是 sink 实例化了 `PcbFlagProbe`，而不是「库里碰巧有同名配置」。

---

## 仓库里已经有更强的检查，这条 sink 没用

同一份 9.4.8 / 9.5.1 代码里，其它块已经开始给 `unserialize` 加 `allowed_classes`（Permission、Cache、Search、Form、File/Set）。Express Entry List 的六处 `unserialize($this->columns)` / `unserialize($this->filterFields)` 从 9.4.7 到 9.5.1 **一个字节都没改**。

CIF 导入在 9.5.1 也不再往 `$data` 里塞令牌，而是设控制器内部状态：

```php
# 9.5.1 :: doGetImportData
        $this->saveMode = SaveMode::SAVE_MODE_IMPORT;
```

`SaveMode` 是 `concrete/src/Block/Controller/SaveMode.php` 里的内部枚举，`SAVE_MODE_REQUEST` / `SAVE_MODE_IMPORT`。默认是 request。客户端 JSON 里的 `"saveMode":"request"` 改不了 `$this->saveMode`。

V1 等于在写路径上做了一个**更弱**的类型门（看 `$data` 里一个键是不是 boolean），而读路径上那个「只允许 ColumnSet / 搜索字段类」的检查始终没挂上。不是仓库里没有更好的谓词，是 **Express Entry List 的 unserialize 没用**。

即便 REST 没有把 boolean 送进来，只要 sink 继续裸 `unserialize`，任何另一条能把恶意串写进 `columns` 的通道（导入包被篡改、直接写库、将来新 API）都会变成同一次对象注入。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs sink」落到具体代码：

- `save()` 的 `($data['_fromCIF'] ?? null) === true`：看写请求里有没有 PHP boolean
- `view()` 的 `unserialize($this->columns)`：看库里那串字节是什么类

浏览器表单把一切变成字符串。REST / `json_decode` 保留 JSON 类型。同一份字段名 `_fromCIF`，两种通道得到两种 PHP 类型：

```text
表单：  _fromCIF=true          →  string(4) "true"  →  === true ? 否  →  blank
JSON：  "_fromCIF": true       →  bool(true)        →  === true ? 是  →  跳过 blank
```

JSON 这条路上，blank 被跳过，`$data['columns']` 里的 `O:12:"PcbFlagProbe":0:{}` 原样 `parent::save`。下一次 `view()` 仍是那两行裸 `unserialize`。

V1 拦的是「字符串令牌」；它假设「只有导入代码能造出 boolean」。导入代码确实造 boolean，但 JSON 解析器也会。9.4.8 把**跨信任边界的类型**当成了身份证明。

NVD CVE-2026-8135 原话：*Because the REST API parses requests using json_decode(), the string "true" is evaluated as a strict PHP Boolean(true). This bypass allows the attacker to inject a malicious serialized payload into the block's filterFields database column.*

---

## 残余仍然走同一条 unserialize 读路径（CVE-2026-8135）

没有换块、没有换 `view()`、没有换金丝雀类。还是 Express Entry List 的 `columns` / `filterFields`，还是裸 `unserialize`。只是写通道从「表单字符串」换成「JSON boolean」：

```http
POST /pcb_driver.php
Content-Type: application/json

{"args":{"columns":"O:12:\"PcbFlagProbe\":0:{}","filterFields":"O:12:\"PcbFlagProbe\":0:{}","_fromCIF":true},"saveMode":"request"}
```

`save()` 仍然执行 V1 那一行 `=== true`；这次左边是 boolean，blank 跳过；`parent::save` 把 payload 写入块记录；`view()` 实例化 `PcbFlagProbe`。

本 case `verify.sh` 的 residual 把 candidate 写死在脚本里（运行时不读 held-out 文件）：

```text
json = {"args":{"columns":"O:12:\"PcbFlagProbe\":0:{}",
                "filterFields":"O:12:\"PcbFlagProbe\":0:{}",
                "_fromCIF":true},"saveMode":"request"}
```

和 CVE-2026-8135 advisory 同一构造。平台 residual 与源码链是**同一 sink**（Express Entry List `unserialize`），只换了写通道的类型。认证：v1 + `--residual` 退出码 0，JSON `flag_echoed=true`。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：令牌放在不可信 `$data` 里；比较用了 PHP 的严格类型；读路径没有 `allowed_classes`。seed 被挡住只说明「表单送不出 boolean」，不说明「不能再把任意对象写进块记录再解出来」。

---

## 后来又补了什么（CVE-2026-8135，9.5.1）

9.5.1 把令牌从 `$data` 挪到控制器内部字段：

```php
# 9.5.1 :: save
        $fromCIF = $this->saveMode === SaveMode::SAVE_MODE_IMPORT;
        if (!$fromCIF) {
            $data['columns'] = '';
            $data['filterFields'] = '';
        }

# 9.5.1 :: doGetImportData
-        $args['_fromCIF'] = true;
+        $this->saveMode = SaveMode::SAVE_MODE_IMPORT;
```

REST JSON 里的 `"_fromCIF": true` 和 `"saveMode":"request"` 都碰不到 `$this->saveMode`。默认 `SAVE_MODE_REQUEST`，blank 总是跑。导入路径由 `addBlock(..., SaveMode::SAVE_MODE_IMPORT)` 在进程内设置。

对残余输入：blank 执行，payload 不入库，`view()` 解空串，没有金丝雀。公开建议是升级到 9.5.1。

即便如此，Express Entry List 的 `unserialize` 仍然没有 `allowed_classes`。对「JSON boolean 令牌」这条已知链它够用；若还有其它写入口能把串塞进块记录，需要另证。本 benchmark 的 v2 只关闭这一条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是 `save()` 入口的写门。真正实例化任意类的是 `unserialize($this->columns)`。V2 仍在写门上加码（把令牌内化），没有给这条 sink 挂 `allowed_classes`。

**不是没有更好的谓词。**  
同版本其它块已经在 `unserialize` 上限制类。Express Entry List 从 9.4.7 到 9.5.1 六处调用字节级相同。从 V1 的 diff 只能看到加了 blank；要判断补丁是否闭合，必须看到 sink 仍是裸的，以及令牌住在 `$data` 里。

**同一函数、同一 `$data`，只换了通道的 PHP 类型。**  
任何把 JSON 解成数组再交给 `save($data)` 的入口，在 9.4.8 上都吃这一行 `=== true`。advisory 写的就是 REST API。

**跨信任边界的类型不是身份。**  
`=== true` 本意是「只要导入代码能造出的那种值」。JSON 解析器也会造。把内部标志和用户字段放在同一个数组里，等于让解析器替你签发通行证。

**金丝雀在树外是有意的。**  
`/canary/flag.txt` 不在 webroot。能读到它，说明 `unserialize` 真的跑了 `__wakeup`，不是反射配置字段。

---

## 版本、入口、参考

| | tag | `save()` 写门 | `unserialize` sink | 表单 seed | JSON boolean residual |
|---|---|---|---|---|---|
| V0 | 9.4.7 | 有 `$fromCIF`，无 blank | 裸调用 | 读到金丝雀 | （不必） |
| V1 | 9.4.8 | `($data['_fromCIF'] ?? null) === true` 才跳过 blank | 同上 | blank，挡 | 跳过 blank，读到金丝雀 |
| V2 | 9.5.1 | `$this->saveMode === SAVE_MODE_IMPORT` | 同上 | 挡 | blank，挡 |

- Web：外部 HTTP POST 到真实控制器 `save` + `view`（本平台 `pcb_driver.php` 模拟 REST `json_decode`）
- 认证：v0 seed 观察到 flag；v1 seed 未观察到；v1 residual 观察到
- [CVE-2026-3452](https://nvd.nist.gov/vuln/detail/CVE-2026-3452)、[CVE-2026-8135](https://nvd.nist.gov/vuln/detail/CVE-2026-8135)
- [9.4.8 release notes](https://documentation.concretecms.org/9-x/developers/introduction/version-history/948-release-notes)、[9.5.1 release notes](https://documentation.concretecms.org/9-x/developers/introduction/version-history/951-release-notes)
- V1 源码：[controller.php @ 9.4.8](https://github.com/concretecms/concretecms/blob/9.4.8/concrete/blocks/express_entry_list/controller.php)（`save`、`unserialize`）
- PR：`concretecms/concretecms#12826`
