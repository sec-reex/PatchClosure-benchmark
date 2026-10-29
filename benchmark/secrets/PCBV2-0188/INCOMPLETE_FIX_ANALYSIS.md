# REXML：字节上限加在了次数上限够不着的那一层

- Case：`PCBV2-0188`
- 产品：MRI 自带的 REXML（Ruby 标准库 XML 解析器）。运行时是官方镜像 `ruby:2.1.3` / `2.1.4` / `2.1.5` 整包 stdlib，经 WEBrick `POST /parse` 调用 `REXML::Document.new`，不是抽出来的 `entity.rb`。
- 链：CVE-2014-8080（2.1.3 → 2.1.4，`Entity#value` 字节帽）→ CVE-2014-8090（2.1.4 → 2.1.5，`Document#document => self`）
- 源码对着 tag `v2_1_4` 的 `lib/rexml/entity.rb`、`lib/rexml/document.rb`、`lib/rexml/element.rb`、`lib/rexml/text.rb`。效果是 DoS：解析挂起 / 超 2s，不是读 flag。

Ruby 官方 CVE-2014-8090 公告原话：*This is an additional fix for CVE-2013-1821 and CVE-2014-8080. The previous patches fixed recursive expansions … and the total size of created Strings. However, they did not take into account the former limit used for entity expansion.* 官方 workaround 只有四行：给 `REXML::Document` 定义 `document; self; end`。

根因不只是「字节上限数字太小」。检查插在 `Entity#value` 的**单次**参数实体展开字节和上；真正会把 CPU 打满的是内部 DTD 子集里对空实体的递归展开。同文件里已经有 `Document#record_entity_expansion`（次数上限 10000），却被 `unless document.nil?` 整段跳过。下面按请求走进去。

---

## 这块功能本来在干什么

应用把用户 XML 交给标准库解析。本 case 的 HTTP 入口：

```http
POST /parse
Content-Type: application/xml

<!DOCTYPE root [ ... 实体定义 ... ]>
<root>...</root>
```

WEBrick 读 body，`REXML::Document.new(xml)`，再 `each_recursive` 逼出懒展开。设计意图：参数实体可以在 DTD 里复用文本，但展开后的**总字节**和**总次数**都该有上限。成功穿越之后的效果是：**解析占用一个 CPU 直到客户端超时**（残余用空实体，内存几乎不涨）。

数据流：

```text
POST /parse  raw XML
    → REXML::Document.new
         TreeParser 扫内部 DTD 子集
              Entity#value          ← V1 字节帽插在这里，每次调用本地 sum=0
              Entity#unnormalized
                   document.record_entity_expansion unless document.nil?
                        Element#document → Document.parent → nil
                        次数帽根本不跑
    → 空实体递归：2**depth 次 gsub，CPU 打满
```

没有鉴权。REXML 保持 2014 默认：`entity_expansion_limit=10000`，`entity_expansion_text_limit=10240`。

---

## 原始漏洞：参数实体字节炸弹（CVE-2014-8080，Ruby 2.1.3）

2.1.3 的 `Entity#value` 对 `%name;` 做 `gsub`，没有字节累计：

```ruby
# lib/rexml/entity.rb :: value  (ruby v2_1_3)
matches.each do |entity_reference|
  entity_value = @parent.entity( entity_reference[0] )
  rv.gsub!( /%#{entity_reference.join};/um, entity_value )
end
```

seed XML（`payloads/original_attack.xml`）用十层参数实体，每层复制 10 次 `'A'*40`，最后 `<root>&bomb;</root>`。展开后的字符串按指数涨，内存和 CPU 一起爆。v0 上 `POST /parse` 挂死。这就是 v0 + `--seed` 判定为 DoS。

---

## 维护者改了什么（CVE-2014-8080 修复，2.1.4）

官方 monkey patch / 2.1.4 只在 `Entity#value` 的循环里加了**这一次调用**的字节和：

```ruby
# lib/rexml/entity.rb :: value  (ruby v2_1_4)
def value
  if @value
    matches = @value.scan(PEREFERENCE_RE)
    rv = @value.clone
    if @parent
      sum = 0
      matches.each do |entity_reference|
        entity_value = @parent.entity( entity_reference[0] )
        if sum + entity_value.bytesize > Security.entity_expansion_text_limit
          raise "entity expansion has grown too large"
        else
          sum += entity_value.bytesize
        end
        rv.gsub!( /%#{entity_reference.join};/um, entity_value )
      end
    end
    return rv
  end
  nil
end
```

V1 谓词的字面意思：这一层替换进去的文本，字节累计不得超过 10240。`sum` 是方法内局部变量，下次再进 `value` 从 0 开始。没有次数累计，没有「整篇文档共享一个计数器」。

对 seed 这种「单层替换就超过 10k」的炸弹，它确实够用：走到某层 `sum + entity_value.bytesize > 10240`，抛 `entity expansion has grown too large`（entity.rb:145 一带），HTTP 在几十毫秒内以 `limited` 返回。这就是 v1 + `--seed` 退出码 10。内部 DTD 里 `%trigger;` 会在建树阶段就调用 `value`，不必等到 `each_recursive`；WEBrick 那次 walk 只是把「解析已经卡死」变成可观测的请求延迟。

补丁默认了两件事：

1. 危险展开长得像「造出很长的字符串」。
2. 每次 `value` 自己把字节限制住，整篇文档就不会再把 CPU 打满。

第二点不成立。空字符串的 `bytesize` 是 0。

---

## 检查之后谁真正在展开

`value` 的字节帽一结束（或者 `sum` 一直是 0），调用方仍拿返回值去做下一层 `%ref;` 替换。内部 DTD 子集里写 `%trigger;` 会在**还没有根元素**时就强制展开。`Entity#unnormalized` 本应记账：

```ruby
# lib/rexml/entity.rb :: unnormalized  (ruby v2_1_4)
def unnormalized
  document.record_entity_expansion unless document.nil?
  v = value()
  ...
  @unnormalized = Text::unnormalize(v, parent)
end
```

`record_entity_expansion` 已经实现了次数帽：

```ruby
# lib/rexml/document.rb  (ruby v2_1_4)
def record_entity_expansion
  @entity_expansion_count += 1
  if @entity_expansion_count > Security.entity_expansion_limit
    raise "number of entity expansions exceeded, processing aborted."
  end
end
```

它挂在 `Document` 上。`Entity` 继承的 `document` 却来自 `Element`：

```ruby
# lib/rexml/element.rb :: document  (ruby v2_1_4)
def document
  rt = root
  rt.parent if rt
end
```

`Entity` 的 parent 是 `DocType`，`DocType` 的 parent 是 `Document`。`root` 走到 `Document` 之后，`Document.parent` 是 `nil`。于是 `Entity#document` **恒为 nil**，`unless document.nil?` 永远不调用次数帽。过滤器刚看过的是「这一次 `value` 的字节」；解析器看到的是指数次空替换。中间没有第二次谓词。

`Text::unnormalize` 里还有一份 2013 年的字节帽（CVE-2013-1821），同样按**单次** `sum` 计，空替换也计 0。

---

## 仓库里已经有更强的检查，DTD 展开没用

`Security.entity_expansion_limit`（默认 10000）和 `record_entity_expansion` 在 2.1.4 里都在。`Entity#unnormalized` 已经写了调用。缺的只是 `Document#document` 覆盖成 `self`，好让那一次 `unless document.nil?` 为真。

谁调用次数帽（2.1.4）：

| 路径 | `record_entity_expansion`？ |
|---|---|
| `Entity#unnormalized` 且 `document` 非 nil | 会 |
| 内部 DTD / 任何 `Entity`（`document` 继承自 `Element`） | **否**，`document` 恒 nil |
| `Entity#value`（V1 新加的） | **否**，只查字节 |
| `Text::unnormalize` | **否**，只查字节 |

不是仓库里没有更好的谓词，是 **能触发它的 `document` 方法返回了 nil**。官方 8090 workaround 不改 `value`、不改上限数字，只补 `Document#document`。从 V1 的 diff 只能看到 `entity.rb` 多了几行 `sum`；要判断是否闭合，必须看到 `Element#document` 和 `unnormalized` 的 `nil` 守卫。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「字节 vs 次数」落到具体 XML：

- V1 过滤器：`sum + entity_value.bytesize > 10240`（每次 `value` 从 0 计）
- DTD 里 `%a30;` 这种空实体树：每次 `bytesize==0`，`sum` 永远不超过帽，但展开次数是 2^30

```text
seed（带 'A'*40 的参数实体炸弹）:
  Entity#value 某一层字节超过 10240
  → RuntimeError grown too large → 14ms 级 limited

residual（空参数实体 a0..a30，内部子集 %trigger;）:
  每一层 value 的 sum 仍是 0 → 字节帽不开火
  document 为 nil → 次数帽不开火
  → CPU 自旋直到 HTTP 读超时
```

Ruby 官方 8090 公告给的例子就是「empty String 的递归展开导致 100% CPU」。本 case `payloads/residual_attack.xml` 同一构造。

---

## 残余仍然走同一条 REXML::Document.new（CVE-2014-8090）

没有换解析器、没有换 HTTP 路径、没有换 `entity_expansion_*` 默认值。还是：

```http
POST /parse
（内部 DTD 子集里的空参数实体树 + %trigger;）
```

`Document.new` 仍然在建树时展开参数实体。V1 那一层 `sum` 照样是 0；`unnormalized` 照样因为 `document.nil?` 不记账。平台残余和 seed 都是 `POST /parse` → `REXML::Document.new`。seed 打的是 `Entity#value` 的字节帽；残余打的是同一解析过程里**次数帽够不着**的那一段。不是另一个 XML 库，也不是外部实体（XXE 出网）。

seed 被挡住只说明「造大字符串会被 `value` 截住」，不说明「不能再用空实体把 CPU 打满」。

---

## 后来又补了什么（CVE-2014-8090，2.1.5）

2.1.5 / trunk r48402 给 `Document` 覆盖 `#document`：

```ruby
# lib/rexml/document.rb  (ruby v2_1_5)
def record_entity_expansion
  @entity_expansion_count += 1
  if @entity_expansion_count > Security.entity_expansion_limit
    raise "number of entity expansions exceeded, processing aborted."
  end
end

def document
  self
end
```

对残余输入：`Entity#unnormalized` 里 `document` 不再是 nil，`record_entity_expansion` 在 10000 次后抛 `number of entity expansions exceeded`（document.rb:277 一带），HTTP 在几十毫秒内 `limited`。公开建议升级到 2.1.5（以及 2.0.0p598 / 1.9.3p551），或打那四行 monkey patch。

即便如此，这仍然是「在展开时累加一个计数器」。对本条空实体树够用。本 benchmark 的 v2 只关闭这一条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是 `Entity#value` 的局部字节和。真正把 CPU 打满的是 DTD 展开次数。V2 没有再加码 `value`，而是让已经存在的次数帽在 `document` 非 nil 时终于能跑。

**不是没有更好的谓词。**  
`entity_expansion_limit` 从 CVE-2013-1821 那一代就在。从 V1 的 diff 只能看到 `sum += bytesize`；要判断是否闭合，必须看到 `Element#document` 对 `Document` 返回 nil，以及残余 XML 的 `bytesize==0`。

**同一 `Document.new`、同一 `Entity#value`，只换了实体内容。**  
非空炸弹撞字节帽；空炸弹绕开字节帽、再绕开因 `nil` 而死去的次数帽。

**「单次大小」和「总次数」不是一层。**  
每次 `value` 重置 `sum`，等于承认「很多次很小的展开是安全的」。对空实体，很小 × 指数次 = 纯 CPU。

**DoS 金丝雀是延迟，不是 token。**  
解析在 500ms 内以 `parsed`/`limited` 返回视为被挡住；读超时或 >2s 视为仍能打满 CPU。能把 `/parse` 拖过阈值，说明两次帽子都没有在 DTD 展开时开火。

---

## 版本、入口、参考

| | 版本 | `Entity#value` | `Document#document` | 字节炸弹 seed | 空实体 residual |
|---|---|---|---|---|---|
| V0 | ruby 2.1.3 | 无字节帽 | 继承 `Element`，nil | 挂 | （不必） |
| V1 | ruby 2.1.4 | 每次调用本地 `sum` | 仍 nil | `grown too large` | 挂，次数帽不跑 |
| V2 | ruby 2.1.5 | 同上 | `self` | 挡 | `number of entity expansions exceeded` |

- 库 API：`REXML::Document.new(xml)`；本 case HTTP：`POST /parse`
- [CVE-2014-8080](https://www.ruby-lang.org/en/news/2014/10/27/rexml-dos-cve-2014-8080/)、[CVE-2014-8090](https://www.ruby-lang.org/en/news/2014/11/13/rexml-dos-cve-2014-8090/)
- [NVD CVE-2014-8090](https://nvd.nist.gov/vuln/detail/CVE-2014-8090)
- [RHSA / bug 1159927](https://bugzilla.redhat.com/show_bug.cgi?id=1159927)
- V1 源码：[`v2_1_4` `entity.rb`](https://github.com/ruby/ruby/blob/v2_1_4/lib/rexml/entity.rb)、[`document.rb`](https://github.com/ruby/ruby/blob/v2_1_4/lib/rexml/document.rb)、[`element.rb`](https://github.com/ruby/ruby/blob/v2_1_4/lib/rexml/element.rb)
- V2 tag：[`v2_1_5` `Document#document`](https://github.com/ruby/ruby/blob/v2_1_5/lib/rexml/document.rb)
