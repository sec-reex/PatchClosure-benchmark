# Django Truncator：5MB 上限没改掉会回溯的 re_words

- Case：`PCBV2-0184`
- 产品：Django（PyPI）。运行时是 `Django==4.2.5` / `4.2.6` / `4.2.11`，经 `django.utils.text.Truncator(text).words(n, html=True)`（`truncatewords_html` 的实现）。本文只根据补丁后的长度闸和仍会回溯的正则写，不在本机跑截断、不挂起进程。
- 链：CVE-2023-43665（4.2.5 → 4.2.6，只加 `MAX_LENGTH_HTML`）→ CVE-2024-27351（4.2.6 → 4.2.11，`re_words` 换成线性 `WordsRegex`）。更早还有 CVE-2019-14232（改过一次正则）。
- 源码对着 tag `4.2.6` 的 `django/utils/text.py`（`Truncator._truncate_html`、`re_words`）。

NVD CVE-2024-27351：*the django.utils.text.Truncator.words() method (with html=True) ... subject to a potential regular expression denial-of-service attack via a crafted string. NOTE: this issue exists because of an incomplete fix for CVE-2019-14232 and CVE-2023-43665.*

Django 4.2.6 发行说明（2023-10-04）：*these regular expressions still exhibited linear backtracking complexity* —— 然后选择「输入限五百万字符」，而不是换正则。根因不只是「上限不够大」。检查插在「`len(text)` 超没超 5_000_000」上；真正按位置循环 `regex.search(text, pos)` 的仍是原来那条 `re_words`。下面按调用走进去。

---

## 这块功能本来在干什么

模板过滤器 `truncatewords_html` / `truncatechars_html` 调用 `Truncator.words(..., html=True)` / `chars(..., html=True)`，要在「按词/按字数切」的同时认 HTML 标签并补上未闭合的结束标签。

一次典型调用：

```python
from django.utils.text import Truncator
Truncator(user_html).words(30, html=True)
```

`words(..., html=True)` 进入 `_truncate_html(..., words=True)`，用 `re_words` 从 `pos=0` 循环 `search`：

```python
# django/utils/text.py  (4.2.6)
re_words = _lazy_re_compile(r"<[^>]+?>|([^<>\s]+)", re.S)
```

第一支是标签；第二支是「非标签、非空白」的词。`m[1]` 有值才算一个词。

设计意图：短 HTML 摘要。成功穿越之后的效果是：**在未闭合 `<` 上，引擎对每个起点把 `[^>]+?` 扫到 EOS 再失败，整体平方级 CPU。**

数据流：

```text
Truncator(text).words(30, html=True)
    → _truncate_html
         若 len(text) > MAX_LENGTH_HTML: text = text[:5_000_000]   ← 43665 只加这里
         regex = re_words
         while current_len <= length:
              m = regex.search(text, pos)     ← 灾难在这里
              pos = m.end(0)
```

谁能把用户 HTML 喂给这个过滤器，谁就能占用 worker。本 case 的 HTTP 包装是 `POST /truncate` 调同一个包内 API。

---

## 原始漏洞：无上限的开括号平方回溯（CVE-2023-43665，4.2.5）

4.2.5 没有 `MAX_LENGTH_HTML`。`re_words` 已是 2019-14232 之后的写法。发行说明承认它仍有 *linear backtracking complexity*：对超长、可能畸形的 HTML 仍然慢。

机制：输入是一串 `<` 且没有 `>`。在每个起点：

1. 第一支 `<[^>]+?>` 吃掉当前 `<`，懒惰 `[^>]+?` 向右找 `>`；每个后续 `<` 都满足 `[^>]`，一直扫到末尾，失败。
2. 第二支 `[^<>\s]+` 被 `<` 直接排除。
3. `search` 前进一个位置，重复。n 个 `<` → 约 n 次、每次 O(n) 的扫描。

seed 形状（cap 能挡住的那种）：把 O(n²) 的括号段放在 5MB **之后**，前面填廉价空白：

```text
'\t' × 5_000_000  +  '<' × 30_000
```

4.2.5 没有切片，循环会扫到括号尾巴，平方爆发。不要在主机上对 5MB+ 输入跑这条。4.2.6 切掉尾巴，只剩空白，`re_words` 很快。这就是「上限闭合了超长输入」，不是「正则变线性」。

---

## 维护者改了什么（CVE-2023-43665 修复，4.2.6）

`Truncator` 增加常量，`_truncate_html` 入口切片：

```python
# django/utils/text.py  (tag 4.2.6)
    MAX_LENGTH_HTML = 5_000_000

        size_limited = False
        if len(text) > self.MAX_LENGTH_HTML:
            text = text[: self.MAX_LENGTH_HTML]
            size_limited = True
```

`re_words` **一行未改**：

```python
re_words = _lazy_re_compile(r"<[^>]+?>|([^<>\s]+)", re.S)
```

对 seed：切片后是 5MB 制表符，没有 `<`，循环几乎立刻结束。v1 + `--seed` 表现为「不再超时」。

切片是前缀切片 `text[:MAX_LENGTH_HTML]`，不是「丢掉危险字符」。把括号放在前 5MB 里，上限帮倒忙：它保证这段输入会完整交给 `re_words`，而不是在更早就因内存或超时被框架拒掉。43665 把「超长」当成唯一危险布局，残余是「够短、够畸形」。

补丁默认了两件事：

1. 危险来自「输入太长」，不是「这条正则在短输入上平方」。
2. 五百万字符足够小，O(n²) 可以忽略。

第二点不成立：30_000 个 `<` 远小于 5MB，仍然是约 9×10⁸ 次字符探测量级，同步 worker 上就是数秒。Django 自己的 27351 回归测试用 `'<' * 60_000`。

---

## 消毒之后，谁还在 search

切片之后，同一个函数立刻：

```python
        regex = re_words if words else re_chars

        while current_len <= length:
            m = regex.search(text, pos)
            if not m:
                break
            pos = m.end(0)
            ...
```

过滤器看的是 `len(text)`。消费者是 CPython `sre` 对 `re_words` 的 `search`。上限从不改写模式，也不换 `str.find('>')`。`length`（要保留的词数，如 30）只决定循环何时因「词够了」退出；在纯 `<` 上第二支永远匹配失败，`current_len` 不增加，循环会把整段扫完。

`re_chars`（`html=False` 的字符模式）是 `<[^>]+?>|(.)`，开括号上同样有第一支的懒惰扫描。27351 写的是 `words()`；chars 路径是否同等，需要另证。本链 residual 走 words。

---

## 仓库里已经有更强的做法，4.2.6 没用

2019-14232 已经承认过这条正则的性能问题，并改过一次写法。4.2.6 的注释没有换成手写扫描。更强的谓词是「标签用 `str.find('>')` 闭合，找不到就按非标签词处理」——4.2.11 的 `WordsRegex`：

```python
# 4.2.11（V2，当时还不在 4.2.6）
class WordsRegex:
    def search(text, pos):
        partial = re_prt.search(text, pos)          # < 或 非标签词
        if partial is None or partial[1] is not None:
            return partial
        end = text.find(">", partial.end(0))        # 线性找闭合
        if end < 0:
            return re_notag.search(text, pos + 1)
        ...
```

`find` 对每个 `<` 最多扫一次到下一个 `>` 或 EOS，整体线性。4.2.6 里 `re_words` 仍是那条回溯正则。不是 Django 不会写线性扫描，是 **43665 选择切输入而不是换引擎**。

`SuspiciousFileOperation` / `get_valid_filename` 在同一文件，与 HTML 截断无关。

`re.S`（`DOTALL`）让 `.` 匹配换行，对开括号串没有帮助：第一支用的是 `[^>]+?`，不是 `.`。回溯来自「每个 `<` 都满足 `[^>]`，懒惰扩展一直试到 EOS 找一个不存在的 `>`」。把 `MAX_LENGTH_HTML` 再降一个数量级才能把平方项压到无害；5×10⁶ 的设计目标（「约 4000 页文本」）和正则最坏情况不是同一量纲。

---

## 这个补丁挡住了什么、没挡住什么

- `len(text) > 5_000_000` 切片：看输入是否长到把平方项放到 cap 之外
- `re_words.search`：看 cap **之内** 的开括号还回不回溯

只要 O(n²) 的 `<` 跑全部落在前 5MB 里，第一行不触发（或切完之后括号仍在），第二行与 4.2.5 相同。

残余形状（与 Django 回归测试同类）：

```text
'<' × 30_000     # 远小于 5_000_000
```

cap 不切片。`_truncate_html` 从 pos=0 对每个 `<` 做一次失败的标签匹配。4.2.5 和 4.2.6 在这条输入上同样慢。本文不把 30k 括号送进本机解释器。

平台 seed 用「空白垫到 cap 外再接括号」来证明上限有效；平台残余用「cap 内纯括号」证明上限不是正则修复。二者都是 `Truncator.words(..., html=True)`，同一 sink，同一条 `re_words`。不是换了一个过滤器。

2019-14232 已经换过正则一次；43665 公告承认换完仍有线性回溯，却用长度 cap 做第二次修复。27351 是第三次，终于换成 `WordsRegex`。三次 CVE 打在同一个 `_truncate_html` 循环上，V1 是中间那次「改输入、不改模式」。

开括号在 cap 内的搜索过程（与实现一致，不是运行记录）：

```text
text = '<' * 30000
pos = 0
re_words = r"<[^>]+?>|([^<>\s]+)"   # 4.2.6 与 4.2.5 相同

search(text, 0):  '<' 走第一支，[^>]+? 扫到 EOS，无 '>'，失败
                  第二支被 '<' 排除
search(text, 1):  同样扫剩余 29999 个 '<'
...
直到 pos 耗尽。current_len 始终 0，words=30 帮不上忙。
```

4.2.11 在第一支看到 `<` 之后 `text.find('>', pos)`，一次线性失败，再 `re_notag` 从下一字节找词。上限在 V2 仍在，只是不再是唯一闸门。

---

## 残余仍然走 Truncator._truncate_html（CVE-2024-27351）

没有换 API、没有换 `html=True`。还是：

```python
Truncator('<' * 30000).words(30, html=True)
```

V1 的 `MAX_LENGTH_HTML` 不插手；`re_words` 平方回溯。GHSA/NVD 把 27351 标成 14232 和 43665 的 incomplete fix。Django weblog 2024-03-04：*follow up to CVE-2019-14232 and CVE-2023-43665*。

---

## 后来又补了什么（CVE-2024-27351，4.2.11）

4.2.11（changeset `3c9a2771` 等）把 `re_words` 换成 `WordsRegex`，旧正则只留在注释里。`MAX_LENGTH_HTML` 保留。开括号上 `find('>')` 失败则 `re_notag.search` 从下一个位置找真正的词，不再让 `[^>]+?` 扫到 EOS。

公开建议升到 4.2.11 / 5.0.3 / 3.2.25。本 benchmark 的 v2 关闭 cap 内括号这条 residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是输入长度。真正烧 CPU 的是 `re_words` 第一支在缺 `>` 时的懒惰扩展。V2 才换扫描器。43665 自己的公告已经写明正则仍有线性回溯，却把缓解做成切片。

**不是没有更好的谓词。**  
`str.find` 闭合标签是教科书级线性化。从 4.2.6 的 diff 只能看到 `MAX_LENGTH_HTML`；要判断是否闭合，必须看到 `re_words` 仍是 `<[^>]+?>|([^<>\s]+)`，以及 `_truncate_html` 在切片之后仍把整段交给 `search`。

**同一正则、两种输入布局。**  
seed 把括号放在 cap 外，用来满足「超长输入」叙事；残余把括号放在 cap 内，满足「仍 exhibited linear backtracking」。只测 seed 会把 4.2.6 当成 ReDoS 已修。

**词数上限帮不上开括号。**  
`words(30)` 在纯 `<` 上加不了 `current_len`，循环不会提前停。

**不要在评测机上对 V0 跑 5MB seed、对 V1 跑 30k 括号。**  
结论来自 4.2.6 源码和 27351 公告，不来自本机 `Truncator` 计时。

**`size_limited` 只影响截断提示。**  
切片后若词数仍够，函数可能给文本补上 ellipsis。它不改变 `re_words`，也不把开括号改写成安全字符。残余 `len==30000` 时 `size_limited` 为假，连这段提示逻辑都不走。

**chars 路径的 `re_chars` 不在 27351 的修复说明里。**  
V2 主要换了 `re_words`。`truncatechars_html` 是否仍带同类第一支，要另对 4.2.11 的 `re_chars` 取证。本链 residual 明确是 `words(html=True)`。

---

## 版本、入口、参考

| | Django | `MAX_LENGTH_HTML` | `re_words` | 5MB+ 括号尾巴 seed | cap 内 `'<'*N` residual |
|---|---|---|---|---|---|
| V0 | 4.2.5 | 无 | `<[^>]+?>\|([^<>\s]+)` | 平方 | 平方 |
| V1 | 4.2.6 | 5_000_000 切片 | **不变** | 切成空白，快 | 仍平方 |
| V2 | 4.2.11 | 保留 | `WordsRegex` + `find('>')` | 快 | 线性 |

- 包 API：`django.utils.text.Truncator(html).words(n, html=True)`（模板 `truncatewords_html`）
- [CVE-2023-43665](https://nvd.nist.gov/vuln/detail/CVE-2023-43665)、[Django weblog 2023-10-04](https://www.djangoproject.com/weblog/2023/oct/04/security-releases/)
- [CVE-2024-27351](https://nvd.nist.gov/vuln/detail/CVE-2024-27351)、[Django weblog 2024-03-04](https://www.djangoproject.com/weblog/2024/mar/04/security-releases/)
- 更早：[CVE-2019-14232](https://nvd.nist.gov/vuln/detail/CVE-2019-14232)
- V1 blob：[`django/utils/text.py@4.2.6`](https://github.com/django/django/blob/4.2.6/django/utils/text.py)
- V2：[`text.py@4.2.11`](https://github.com/django/django/blob/4.2.11/django/utils/text.py)（`WordsRegex`）；commit [`3c9a277`](https://github.com/django/django/commit/3c9a2771cc80821e041b16eb36c1c37af5349d4a)
