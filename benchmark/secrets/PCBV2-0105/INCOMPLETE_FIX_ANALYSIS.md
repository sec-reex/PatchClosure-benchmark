# Rack `get_byte_ranges`：总覆盖量拦住了，段数没拦住

- Case：`PCBV2-0105`（legacy `dos_rack_byte_ranges`）
- 产品：RubyGems `rack`。本 case 跑真实 `rackup` + WEBrick，用发布包 `Rack::Files` 提供 `GET /file`。
- 链：CVE-2024-26141（3.0.9 → 3.1.20，`sum > size`）→ CVE-2026-34826（3.1.20 → 3.1.21，`max_ranges: 100`）
- 源码对着 GitHub tag `v3.1.20` 的 `lib/rack/utils.rb`（`get_byte_ranges` / `byte_ranges`）和 `lib/rack/files.rb`（`Files#serving`、`BaseIterator#each` / `#bytesize`）。运行时装的是发布包本身。

2024 年 2 月，Rack 给 `Range` 头加了一道「所有区间加起来不能超过文件长度」的闸。这挡住了「把整文件重复几千遍」那种把响应撑到数 GB 的内存耗尽。2026 年 4 月 GHSA-x8cg-fq8g-mxfx 写明：*Although the existing fix for CVE-2024-26141 rejects ranges whose total byte coverage exceeds the file size, it does not restrict the count of ranges.* NVD CVE-2026-34826 把同一句话写进了描述。

根因不只是「少写了一个上限」。检查插在「区间长度之和」这一层；真正按段拼 multipart 的是 `Rack::Files::BaseIterator`，它按 **数组长度** 循环，不看总和。同文件里 multipart 上传已经有 `multipart_total_part_limit`，字节区间这条路径没用。下面按请求走进去、3.1.20 改了哪一行、谁消费那个数组、仓库里有没有更强的计数谓词，把这几层写完。

---

## 这块功能本来在干什么

HTTP `Range` 让客户端只要文件的一段。单个区间返回 206 + `Content-Range`；多个区间返回 `multipart/byteranges`，每个区间一块。Rails / 静态中间件普遍走 `Rack::Files`。一次典型请求：

```http
GET /file
Range: bytes=0-99
```

本 case 的应用把一个约 900000 字节的文件交给真实 `Rack::Files`。`Files#get` 用 `Utils.unescape_path` / `clean_path_info` 拼磁盘路径，确认 `-f` 可读后进 `serving`。`serving` 取出 `HTTP_RANGE`，交给 `get_byte_ranges`，再按返回值决定 200 / 206 / 416。

设计意图：`Range` 是客户端声明的字节窗口，服务端按窗口 seek/read，避免传整文件。成功穿越之后的效果是：**解析出的区间个数没有上限，multipart 装配的 CPU / 内存 / I/O 与段数成正比**，请求挂住或把 worker 打满。本 case 的 oracle 是延迟阈值，没有 `PCBFLAG_` 金丝雀。

数据流：

```text
HTTP Range
    → Rack::Request HTTP_RANGE
    → Files#serving
         size = File.size?(path)
         ranges = Utils.get_byte_ranges(http_range, size)   ← V1 补丁插在这里
              nil  → 当「没有 Range」，整文件 200
              []   → 416 Range Not Satisfiable
              [r0, r1, ...] 且 length>1 → 206 multipart
    → BaseIterator#each
         每个 range：multipart heading + seek + read     ← 真正的消耗
    → bytesize 先按 ranges.size 预计算 Content-Length
```

没有登录。判断完全信任解析器返回的数组；不限制「这个数组可以有多长」。

---

## 原始漏洞：无聚合检查（CVE-2024-26141，rack 3.0.9）

3.0.9 的 `get_byte_ranges` 把 `bytes=` 后面按逗号切开，每个 `r0-r1` 变成一个 Range，直接返回：

```ruby
# lib/rack/utils.rb :: get_byte_ranges  (rack 3.0.9，概念；3.1.20 在同一位置多了 sum 检查)
def get_byte_ranges(http_range, size)
  return nil if size.zero?
  return nil unless http_range && http_range =~ /bytes=([^;]+)/
  ranges = []
  $1.split(/,\s*/).each do |range_spec|
    # ... 解析 r0, r1 ...
    ranges << (r0..r1) if r0 <= r1
  end
  ranges   # 无总和、无个数
end
```

GHSA-xj5v-6v4g-jfw6 / NVD CVE-2024-26141 的问题是：精心构造的 Range 会让服务器吐出「意外巨大」的响应。本 case 的 seed 把**整文件区间**重复 6000 次：

```text
Range: bytes=0-899999,0-899999,...   （6000 段，头约 54 KB）
总和 = 6000 × 900000 = 5.4 GB  >>  文件 900000
```

3.0.9 原样返回 6000 个 `0..899999`。`Files#serving` 看到 `ranges.size > 1`，把 `CONTENT_TYPE` 改成 multipart，把数组交给 `BaseIterator`。`#each` 对每一段写 heading、seek 到 0、读 900000 字节。512m 容器在装配多 GB body 时 OOM。这就是 v0 + `--seed` 的 DoS 阳性。

同一函数里当时没有任何「聚合」谓词。`byte_ranges(env, size)` 只是把 `HTTP_RANGE` 转交给 `get_byte_ranges`。

---

## 维护者改了什么（CVE-2024-26141 修复，rack 3.1.20）

tag `v3.1.20` 只在解析循环**之后**加了一行。签名仍是 `get_byte_ranges(http_range, size)`，没有 `max_ranges`：

```ruby
# lib/rack/utils.rb :: get_byte_ranges  (github.com/rack/rack tag v3.1.20)
def get_byte_ranges(http_range, size)
  # See <http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.35>
  # Ignore Range when file size is 0 to avoid a 416 error.
  return nil if size.zero?
  return nil unless http_range && http_range =~ /bytes=([^;]+)/
  ranges = []
  $1.split(/,\s*/).each do |range_spec|
    return nil unless range_spec.include?('-')
    range = range_spec.split('-')
    r0, r1 = range[0], range[1]
    # ... suffix / open-ended / clip to size ...
    ranges << (r0..r1) if r0 <= r1
  end

  return [] if ranges.map(&:size).sum > size

  ranges
end
```

`Range#size` 对 `0..899999` 是 900000。注释原话：*Removes ranges that are too large, to avoid a denial of service by requesting ranges whose total coverage exceeds the file size.*（本 case `patch.diff` 里保留了这句。）

对 seed 这种「总和远大于文件」的输入，它确实够用：

```text
sum = 5.4e9  >  900000  →  return []
Files#serving: ranges.empty?  →  416，毫秒级返回
```

这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险的 Range 集合长得像「覆盖的字节总数超过文件」。
2. 只要总和不超过 `size`，后面的 multipart 装配就是安全的。

第二点不成立。更关键的是：这一行之后，代码仍然把 `$file` 对应的 **ranges 数组原样**交给 `BaseIterator`，装配路径**不再看个数**。

commit 侧：NVD 记的 3.0 线是 `4849132` / `62457686`（2.2.8.1 / 3.0.9.1）。本 case 的 V1 钉在 3.1.20，语义相同：只有总和，没有 count。

---

## 检查之后，谁真正消费那个数组

V1 的 `sum > size` 一结束，`get_byte_ranges` 把数组交还给 `Files#serving`（tag `v3.1.20`，`lib/rack/files.rb`）：

```ruby
# lib/rack/files.rb :: Files#serving  (v3.1.20)
ranges = Rack::Utils.get_byte_ranges(request.get_header('HTTP_RANGE'), size)
if ranges.nil?
  ranges = [0..size - 1]
elsif ranges.empty?
  response = fail(416, "Byte range unsatisfiable")
  response[1]["content-range"] = "bytes */#{size}"
  return response
else
  partial_content = true
  if ranges.size == 1
    range = ranges[0]
    headers["content-range"] = "bytes #{range.begin}-#{range.end}/#{size}"
  else
    headers[CONTENT_TYPE] = "multipart/byteranges; boundary=#{MULTIPART_BOUNDARY}"
  end
  status = 206
  body = BaseIterator.new(path, ranges, mime_type: mime_type, size: size)
  size = body.bytesize
end
```

`nil` 和 `[]` 在这里语义不同：`nil` = 当没要 Range（整文件）；`[]` = 不可满足（416）。V1 用 `[]` 挡 seed，所以是 416。V2 后来用 `nil` 挡残余，所以是 200 整文件——两条失败路径都「快」，但 HTTP 状态不同。

真正的消耗在 `BaseIterator`：

```ruby
# lib/rack/files.rb :: BaseIterator#each / #bytesize  (v3.1.20)
def each
  ::File.open(path, "rb") do |file|
    ranges.each do |range|
      yield multipart_heading(range) if multipart?
      each_range_part(file, range) do |part|
        yield part
      end
    end
    yield "\r\n--#{MULTIPART_BOUNDARY}--\r\n" if multipart?
  end
end

def bytesize
  size = ranges.inject(0) do |sum, range|
    sum += multipart_heading(range).bytesize if multipart?
    sum += range.size
  end
  size += "\r\n--#{MULTIPART_BOUNDARY}--\r\n".bytesize if multipart?
  size
end
```

`multipart?` 是 `ranges.size > 1`。每个区间：一块 heading（约几十字节）+ `seek` + `read`。700000 个 `0-0` 就是 700000 次 heading + 700000 次 1 字节读，body 大约 52 MB，CPU 在秒级。过滤器刚看过的是「长度之和」；open/装配看到的是「数组有多长」。两套语义中间没有第二次谓词。

`bytesize` 在写 body 之前就要走一遍所有 heading 字符串，单这一步已经和 count 成正比。

---

## 仓库里已经有更强的计数，字节区间没用

同一份 `utils.rb` 顶部已经有 multipart **上传** 的个数上限：

```ruby
# lib/rack/utils.rb  (v3.1.20)
self.multipart_file_limit = (ENV['RACK_MULTIPART_PART_LIMIT'] || ENV['RACK_MULTIPART_FILE_LIMIT'] || 128).to_i
self.multipart_total_part_limit = (ENV['RACK_MULTIPART_TOTAL_PART_LIMIT'] || 4096).to_i
```

注释写明 *Accepting too many can lead to excessive memory use and parsing time*。这是「部分个数」谓词，默认 4096。它挂在请求体解析上，**不挂**在 `get_byte_ranges` 上。

V1 等于在调用方又做了一个**更弱**的聚合（只认「覆盖字节总和」），而读文件路径上那个「部分太多就拒绝」的思路始终没挂上。不是仓库里没有更好的谓词，是 **Range 解析没用**。

即便没有 `0-0` 这种 1 字节重叠，只要 `get_byte_ranges` 继续返回无界数组，任何「每段很小、段数很多」的写法都会变成一次真实的 multipart 膨胀。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs 装配」落到具体代码：

- `get_byte_ranges` 的 `ranges.map(&:size).sum > size`：看区间长度**加起来**有没有超过文件
- `BaseIterator#each`：看数组里有**多少个**区间，每个都 heading + seek + read

只要构造一种输入，使「长度之和 ≤ 文件」但「个数极大」，第一行会放行，第二行仍然按段数干活。

`0-0` 重复 700000 次就是这样来的：

```text
每个 Range#size = 1
sum = 700000  ≤  900000   →  V1 的 if 为假，返回 700000 个 0..0
Files#serving：ranges.size > 1  →  206 multipart
BaseIterator：700000 块  →  约 52 MB body，数秒
```

字符串层面几乎没有变换。逗号分隔的 `0-0` 解析成 Range 对象之后，过滤器只读 `.size` 的和，不读 `.length`。token 还是那些 `0-0`；变的是「哪一个聚合量被当成安全」。

GHSA-x8cg-fq8g-mxfx 原话：*a request such as `Range: bytes=0-0,0-0,0-0,...` can contain thousands of overlapping one-byte ranges while still satisfying the total-size check added for CVE-2024-26141.*

注意 WEBrick 默认请求头上限约 112 KiB，2.8 MB 的残余头会被 413 挡在 Rack 之外。本 case 把服务器头限制调到 8 MiB（类似 nginx `large_client_header_buffers`），**没有改 Rack**。这只说明：前面的 HTTP 栈碰巧能挡住超长头；Rack 自己在 3.1.20 仍然接受无界 count。

---

## 残余仍然走同一条 Files 读文件路径（CVE-2026-34826）

没有换中间件、没有换入口、没有换身份。还是：

```http
GET /file
Range: bytes=0-0,0-0,...（700000 段）
```

`Files#serving` 仍然调用同一个 `get_byte_ranges`。V1 那一行 `sum > size` 照样执行；执行完之后数组里仍是 700000 个 `0..0`；`BaseIterator` 按段装配；客户端看到 206 和数秒延迟。

本 case `verify.sh` / heldout 把 candidate 写死为：

```text
HEADER = "bytes=" + ",".join(["0-0"] * 700000)
```

和 advisory 同一构造，只是把「成千上万」具体成 700000，使总和 700000 ≤ 900000。认证：v1 + `--residual` 延迟超过阈值（legacy 门上约 2.8 s / 206）。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：检查的聚合量比装配的复杂度窄；拼 multipart 发生在检查之后；Range 路径没有使用已经存在的 part-count 思路。seed 被挡住只说明「总覆盖量没了」，不说明「不能再强迫 Files 按段数干活」。

---

## 后来又补了什么（CVE-2026-34826，rack 3.1.21）

3.1.21（commit `345a4cfa`，标题 *Use a default limit of 100 byte ranges*；3.2 线是 `9138756`）给同一函数加了关键字参数，并在 **split 之前**按逗号个数短路：

```ruby
# lib/rack/utils.rb :: get_byte_ranges  (v3.1.21，概念)
def get_byte_ranges(http_range, size, max_ranges: 100)
  return nil if size.zero?
  return nil unless http_range && http_range =~ /bytes=([^;]+)/
  byte_range = $1
  return nil if byte_range.count(',') >= max_ranges
  ranges = []
  byte_range.split(/,\s*/).each do |range_spec|
    # ...
  end
  return [] if ranges.map(&:size).sum > size
  ranges
end
```

对残余输入：逗号个数 699999 ≥ 100 → 返回 `nil` → `serving` 当成「没有 Range」→ 整份 900 KB 一次 200，毫秒到百毫秒级。V1 的总和检查仍保留，seed 继续 416。

`nil` 而不是 `[]`：超过个数时不当 416（那会承认「这是一条 Range 请求」），而是忽略 Range。公开建议升到 2.2.23 / 3.1.21 / 3.2.6。

即便如此，这仍然是「在解析层加一个 count」，`BaseIterator` 还是信任上游数组。对 `0-0`×N 这条已知链它够用。本 benchmark 的 v2 只关闭这一条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是 `get_byte_ranges` 出口的标量总和。真正按段数耗资源的是 `BaseIterator#each` / `#bytesize`。V2 仍在同一层加码（解析前数逗号），没有把 Files 接到一个独立的 `max_ranges` 装配闸。

**不是没有更好的谓词。**  
`multipart_total_part_limit` 已经用「部分个数」防解析 DoS。Range 这条对称的「区间个数」在 3.1.20 不存在。从 V1 的 diff 只能看到加了一行 `sum > size`；要判断补丁是否闭合，必须看到 `BaseIterator` 对 `ranges.size` 的线性工作。

**同一函数、同一 `$file` 对应的 ranges，只换了每个区间的宽度。**  
任何把用户 `Range` 头传进 `get_byte_ranges` 的文件服务，在 3.1.20 上都吃这一行总和和同一次 multipart 装配。advisory 已指出这与 CVE-2024-26141「不同」。

**返回值的三态被用成了安全策略。**  
`nil` / `[]` / 非空数组在 `serving` 里是三种完全不同的 HTTP 结果。V1 用 `[]`（承认 Range、声明不可满足），V2 用 `nil`（假装没看到 Range）。残余能过 V1，正是因为总和合法，函数不愿意返回这两种「快失败」里的任何一种。

**金丝雀不在树外是有意的。**  
这是延迟 oracle。能观察到数秒 206，说明装配真的跑完了 700000 段，而不是「过滤器拒绝后的空响应」。

---

## 版本、入口、参考

| | gem | `get_byte_ranges` | `Files#serving` / `BaseIterator` | 6000×整文件 seed | 700000×`0-0` residual |
|---|---|---|---|---|---|
| V0 | 3.0.9 | 无聚合 | 按数组装配 | OOM / 超时 | （不必；同样慢） |
| V1 | 3.1.20 | `sum > size → []` | 同上，仍无 count | 416 快 | 206 慢（~52 MB） |
| V2 | 3.1.21 | `count(',') >= 100 → nil`，总和保留 | 同上 | 快（nil 或 416） | 200 整文件，快 |

- Web：`GET /file` + `Range`
- 认证（本平台）：v0 seed 慢/崩；v1 seed 快；v1 residual 慢。
- [CVE-2024-26141](https://nvd.nist.gov/vuln/detail/CVE-2024-26141)、[GHSA-xj5v-6v4g-jfw6](https://github.com/rack/rack/security/advisories/GHSA-xj5v-6v4g-jfw6)
- [CVE-2026-34826](https://nvd.nist.gov/vuln/detail/CVE-2026-34826)、[GHSA-x8cg-fq8g-mxfx](https://github.com/rack/rack/security/advisories/GHSA-x8cg-fq8g-mxfx)
- V1 语义提交：[4849132](https://github.com/rack/rack/commit/4849132bef471adb21131980df745f4bb84de2d9)、[62457686](https://github.com/rack/rack/commit/62457686b26d33a15a254c7768c2076e8e02b48b)
- V2：[345a4cfa](https://github.com/rack/rack/commit/345a4cfa51f451e58b2931322998e04f3cf6dc0d)（3.1.21）、[9138756](https://github.com/rack/rack/commit/9138756fb0bcfb500abbb0b8ed90bc24911ff6a3)（3.2.6）
- 源码：`https://github.com/rack/rack/blob/v3.1.20/lib/rack/utils.rb`、`.../lib/rack/files.rb`
