# Django is_safe_url：控制字符拦了，反斜杠规范化只验证一遍

- Case：`PCBV2-0103`（`django-openredirect-2015-2317-2017-7233`）
- 产品：Django。登录成功后的 `?next=` 是否放行，由 `django.utils.http.is_safe_url(url, host)` 决定。
- 链：CVE-2015-2317（1.7.5 → 1.8.0）→ CVE-2017-7233（1.8.0…1.8.17 → 1.8.18）
- 源码对着 GitHub branch/tag `1.8` / `1.8.18` 的 `django/utils/http.py`：`is_safe_url`、`_is_safe_url`、`url.replace('\\','/')`、`unicodedata.category`。运行时装的是 pip 发布包（Django==1.7.5 / 1.8.0 / 1.8.18）。

2015 年 3 月，Django 给 `is_safe_url` 加上「首字符不能是 Unicode 控制类」：Chrome 会忽略 URL 开头的控制字符，把 `\x08javascript:` 或 `\x7f//evil` 当成相对或 scheme-relative。这挡住了 seed 的 `DEL + //host`。2017 年 4 月安全公告 CVE-2017-7233 的标题写的是 numeric URL（`http:999999999`），同一份 1.8.18 补丁把验证拆成 **raw 与把 `\` 换成 `/` 之后各跑一次**。注释写明：*Chrome treats \ completely as / in paths but it could be part of some basic auth credentials so we need to check both URLs.* 本 case 的 residual 是后一条：`http://app.local\@flag.evil.example`。

根因不只是「少拦一种 URL」。检查插在「规范化之后的 netloc 像不像本站」这一层；真正写进 `Location` 的是**原始** `next` 字符串。V1 只对替换反斜杠之后的那一版做 `urlparse`。下面按 GET /login 走进去、1.8.0 改了哪几行、替换之后谁消费那个 URL、双边验证有没有挂上，把这几层写完。

---

## 这块功能本来在干什么

Django 的 `login` / i18n 等视图用 `is_safe_url(redirect_to, host=request.get_host())` 决定 302 的 Location 是否可用用户指定的 `next`。本意：只允许相对路径或 host 等于当前站点。

本 case 的 `go` 视图同样调用**已安装 Django 包自己的** `is_safe_url`，通过则 302 到原始 `next`，否则 302 到 `/`：

```http
GET /login?next=...
Host: app.local
```

设计意图：`next` 不能把浏览器带到站外。成功穿越之后的效果是：**库认为安全，Location 里出现攻击者选的 host 标签**（本 case 用 `PCBFLAG_...` 当 host 前缀）。

数据流：

```text
HTTP ?next=
    → is_safe_url(next, host="app.local")
         strip
         V1：url.replace('\\','/')          ← 只这一版拿去 parse
         urlparse
         首字符 category[0]=='C' → False     ← CVE-2015-2317
         netloc=='' 或 netloc==host
    → True 则 302 Location = 原始 next（未再规范化）
```

没有登录墙。判断完全信任 `is_safe_url` 对「会跳到哪」的读法，不信任浏览器稍后怎么解析同一串字节。

诚实说明：真实 Django 的 `fix_location_header` 会把**相对** Location 绝对化。seed `\x7f//flag.evil.example` 在 V0 被当成相对路径批准，线上看起来是 `http://app.local/%7F//flag...`，flag 出现在 path。residual `http://app.local\@flag...` 已经是绝对 URL，V1 上 Location 原样发出，浏览器把 `@` 前当 userinfo。gate 用的是「Location 里有没有 FLAG」，seed 的角色是证明控制字符检查在 V1 开火。

---

## 原始漏洞：开头控制字符（CVE-2015-2317，1.7.5）

1.7.5 的 `is_safe_url` 没有控制字符检查。`urlparse('\x7f//evil.example')` 的 netloc 为空（控制字符让它不像 scheme-relative），函数当成相对路径返回 True。Django 2015-03-18 公告：*accepted URLs with leading control characters and so considered URLs like `\x08javascript:...` safe.* 若开发者把返回值放进 `<a href>`，Chrome 忽略开头控制字符，变成 XSS；放进 Location 时浏览器表现因实现而异。CVE-2015-2317。

本 case seed（URL 编码后发送，Django 解码回 DEL）：

```text
next = \x7f//<FLAG>.evil.example
```

1.7.5 上 `is_safe_url` 为 True，Location 含 FLAG。这就是 v0 + `--seed` 退出码 0。

1.7.5 已经有 `url = url.replace('\\', '/')` 和「三个斜杠算绝对、有 scheme 无 netloc 则拒绝」。当时没人拿反斜杠当控制字符问题的一部分。

---

## 维护者改了什么（CVE-2015-2317 修复，1.8.0）

1.8 的 `is_safe_url`（GitHub `django/django` `1.8` 分支，与 1.8.0 一致）在 parse 之后加上控制字符检查，并把 `strip` 挪到空串判断之前：

```python
# django/utils/http.py :: is_safe_url  (1.8 / 1.8.0)
def is_safe_url(url, host=None):
    if url is not None:
        url = url.strip()
    if not url:
        return False
    # Chrome treats \ completely as /
    url = url.replace('\\', '/')
    if url.startswith('///'):
        return False
    url_info = urlparse(url)
    if not url_info.netloc and url_info.scheme:
        return False
    # Forbid URLs that start with control characters. Some browsers (like
    # Chrome) ignore quite a few control characters at the start of a
    # URL and might consider the URL as scheme relative.
    if unicodedata.category(url[0])[0] == 'C':
        return False
    return ((not url_info.netloc or url_info.netloc == host) and
            (not url_info.scheme or url_info.scheme in ['http', 'https']))
```

字面意思：

| 片段 | 含义 |
|---|---|
| `unicodedata.category(url[0])[0] == 'C'` | 首字符是 Unicode 控制类（含 DEL `\x7f` 的 Cc） |
| `url.replace('\\', '/')` | **先**把反斜杠换成正斜杠，**再** parse **一次** |
| 返回值用的 `url_info` | 只来自规范化后的串 |

对 seed 这种开头 DEL，它确实够用：

```text
url[0] = \x7f → category Cc → 'C' → return False
```

这就是 v1 + `--seed` 退出码 10。Location 回落到 `/`，无 FLAG。

补丁默认了两件事：

1. 危险的「库和浏览器看法不同」主要来自首字符控制类。
2. 先按 Chrome 把 `\` 当成 `/` 再判断 netloc，得到的 host 就是浏览器会连的 host。

第二点不成立。`http://app.local\@evil.example` 规范化后变成 `http://app.local/@evil.example`，`urlparse` 的 netloc 是 `app.local`，path 是 `/@evil.example`。浏览器对**原始**串把 `\` 留在 userinfo 里，`@` 后面才是真正的 host。

---

## 检查之后，谁真正消费那个值

`is_safe_url` 返回 True 之后，视图把**调用前的原始字符串**放进 `HttpResponseRedirect`。`replace('\\','/')` 的结果只用于判断，不写回 Location。

过滤器刚看过的是：

```text
http://app.local/@FLAG.evil.example     netloc=app.local == host
```

浏览器（和多数客户端）看到的 Location 仍是：

```text
http://app.local\@FLAG.evil.example     userinfo=app.local\  host=FLAG.evil.example
```

两套 URL 语法中间没有第二次 `is_safe_url(原始串)`。

`urlparse` / Python 2 的 `urlsplit` 也不把 `\` 当 authority 分隔符，所以**若不**先 replace，原始串的 netloc 会是 `app.local\@FLAG.evil.example`，不等于 `app.local`。V1 的 replace 把这个不相等抹掉了。

`HttpResponseRedirect` 随后还可能经过 `iri_to_uri`。反斜杠会按 ISO-8859-1 进 Location，浏览器仍按 userinfo 规则拆 `@`。控制字符 seed 在真实 Django 上还会被 `fix_location_header` 绝对化——这是相对 URL 的诚实行为，不改变「V1 用 category==C 拒绝它」这一事实。

---

## 仓库里已经有更强的检查，1.8.0 没用

同一函数已经知道 Chrome 把 `\` 当 `/`（注释写了）。完整策略是：**既要拒绝浏览器当成 `/` 时危险的串，也要拒绝原始串本身 netloc 不等于 host 的串。** 这需要两次验证。1.8.0 只做了前一半。

1.8.18：

```python
# django/utils/http.py :: is_safe_url  (1.8.18)
    # Chrome treats \ completely as / in paths but it could be part of some
    # basic auth credentials so we need to check both URLs.
    return _is_safe_url(url, host) and _is_safe_url(url.replace('\\', '/'), host)
```

`_is_safe_url` 仍含控制字符检查和 `urlparse`（1.8.18 还换成内部 `_urlparse` 以修 numeric URL）。双边 AND：原始串 netloc 对不上就整次拒绝。V1 没有这行 AND。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs Location」落到具体代码：

- `unicodedata.category(url[0])`：看首字节是不是控制字符
- `url.replace('\\','/'); urlparse`：看规范化后 netloc
- 302 Location：原始 next

seed：

```text
\x7f//FLAG.evil.example → 首字符 C → False → 挡
```

residual：

```text
输入:     http://app.local\@FLAG.evil.example
replace:  http://app.local/@FLAG.evil.example
urlparse: scheme=http netloc=app.local path=/@FLAG.evil.example
host:     app.local
→ True，Location 仍是带反斜杠的原始串
```

V1 拦的是「Chrome 会剥掉的开头控制字符」；它假设「按 Chrome 把反斜杠换成斜杠再 parse，得到的 host 就是跳转目标」。basic-auth 的 `@` 让 replace 改变的是 path/userinfo 边界，不是「同一个 host 的两种写法」。

NVD CVE-2017-7233 摘要强调 numeric URL；1.8.18 源码注释和 heldout 对应的是同一函数里的反斜杠双边检查。本 case 的 residual 走的是后一条，仍是 `is_safe_url` 这一个 sink。

---

## 残余仍然走同一条 login next 路径（CVE-2017-7233）

没有换视图、没有换 `is_safe_url`、没有换 Host。还是 `GET /login?next=`。只是 payload 从开头 DEL 换成反斜杠 + `@`：

```text
next = http://app.local\@<FLAG>.evil.example
```

`is_safe_url` 仍然先 replace 再 parse 一次；netloc 等于 host；302 Location 带 FLAG。

本 case `verify.sh` residual 与 heldout 同一构造。平台 residual 与源码链是**同一 sink**。认证：v1 + `--residual` 退出码 0。

所以残余不是新洞面，而是同一判断函数上三件事叠在一起：只验证规范化后的串；Location 发射原始串；`\` 在 Chrome 路径语义和 basic-auth 语义下不是同一个变换。seed 被挡住只说明「开头控制字符不行了」，不说明「不能再让 is_safe_url 批准一个浏览器会打到站外的 URL」。

---

## 后来又补了什么（CVE-2017-7233，1.8.18）

2017-04-04 公告同时修 numeric URL 和（代码里的）双边验证。1.8.18 / 1.9.13 / 1.10.7。

对残余输入：`_is_safe_url(原始)` 的 netloc 为 `app.local\@FLAG.evil.example` ≠ `app.local`，AND 为 False，302 到 `/`。seed 仍被控制字符检查挡住。公开建议升级到 1.8.18+。

即便如此，这仍然是「对两种规范化各 parse 一次」。其它让 Python `urlparse` 和浏览器权威解析不一致的写法，需要另证。本 benchmark 的 v2 只关闭 `\@` 这条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是「parse 之前先按 Chrome 把 `\` 换成 `/`」。真正决定跳到哪的是 Location 里的原始字节。V2 仍在 `is_safe_url` 里加码，但要求原始串自己也安全。

**不是没有更好的谓词。**  
「对 raw 和 normalized 都 True」就是完整策略，1.8.18 注释写得很清楚。1.8.0 已经知道 Chrome 的 `\` 规则，却只验证了一种形态。

**同一函数、同一 next 参数，只换了 URL 写法。**  
任何调用 `is_safe_url` 的跳转在 1.8.0 上都吃这一次 replace。heldout 的 `\@` 就是这个变换。

**规范化必须覆盖将要发射的那一串。**  
检查 A 的变换结果、发射未变换的 A，等于给「检查过的 URL」和「浏览器看到的 URL」两套语法。

**FLAG 只当 host 标签是有意的。**  
没有服务端文件。Location 里出现 token，说明 `is_safe_url` 批准了攻击者控制的跳转目标。

**NVD 摘要和代码补丁不是同一句话。**  
CVE-2017-7233 的 NVD 描述强调 `http:999999999` 这种 numeric URL；1.8.18 的 `is_safe_url` 同时引入内部 `_urlsplit`（修 numeric）和 raw∧normalized 双边检查（修 `\@`）。heldout / 本平台 residual 走的是反斜杠 basic-auth，与函数注释一致。两者共用同一个 V2 发布，但证明 V1 不闭合时必须把 `\@` 变换写清，不能只复述 NVD 的 numeric 那句。

**seed 的 Location 可能被绝对化，residual 不会。**  
控制字符相对 URL 被拒之后，Django 的 `fix_location_header` 仍可能把合法相对路径做成绝对 Location，flag 出现在 path 上——那是相对跳转的诚实行为，不是跨站。`\@` residual 的 Location 则把 token 放进另一 origin 的 userinfo/host。平台若只扫响应里有没有 `PCBFLAG_`，两种都会亮；要说明 V1 没闭合，必须看 Location 的 authority 是否离开了 `app.local`。

---

## 版本、入口、参考

| | Django | `is_safe_url` | `\x7f//` seed | `\@` residual |
|---|---|---|---|---|
| V0 | 1.7.5 | 无控制字符检查 | Location 含 FLAG | （不必） |
| V1 | 1.8.0 | 控制字符检查；replace 后只 parse 一次 | 挡 | 规范化 netloc=本站，Location 含 FLAG |
| V2 | 1.8.18 | raw AND replace 各验证一次 | 挡 | raw netloc ≠ host，挡 |

- Web：`GET /login?next=...`（Host: `app.local`）
- 认证：v0 seed 观察到 flag；v1 seed 未观察到；v1 residual 观察到
- [CVE-2015-2317](https://nvd.nist.gov/vuln/detail/CVE-2015-2317)、[CVE-2017-7233](https://nvd.nist.gov/vuln/detail/CVE-2017-7233)
- [Django 2015-03-18](https://www.djangoproject.com/weblog/2015/mar/18/security-releases/)、[Django 2017-04-04](https://www.djangoproject.com/weblog/2017/apr/04/security-releases/)
- V1 源码：[http.py @ 1.8](https://github.com/django/django/blob/1.8/django/utils/http.py)
- V2 源码：[http.py @ 1.8.18](https://github.com/django/django/blob/1.8.18/django/utils/http.py)
