# Drupal 8.5.1：RequestSanitizer 扫了数组键，没拆 destination 字符串

- Case：`PCBV2-0011`
- 产品：Drupal core 8.5.x。Web 入口经 `DrupalKernel::preHandle` 进入 Form API / Renderer。
- 链：CVE-2018-7600 / SA-CORE-2018-002（8.5.0 → 8.5.1，引入 `RequestSanitizer`）→ CVE-2018-7602 / SA-CORE-2018-004（8.5.1 → 8.5.3，给 sanitizer 加 `checkDestination`）。8.5.2 的 `RequestSanitizer.php` 与 8.5.1 相同。
- 源码对着 GitHub tag `8.5.1` / `8.5.3` 的 `core/lib/Drupal/Core/Security/RequestSanitizer.php`、`DrupalKernel.php`。官方镜像 `drupal:8.5.0/8.5.1/8.5.3` 带的就是这份 core。

2018 年 3 月 28 日，Drupal 给每次请求加了 `RequestSanitizer::sanitize()`，递归删掉 GET/POST/COOKIE 参数袋里以 `#` 开头的键，想挡住把 render 数组属性直接塞进请求的 RCE（Drupalgeddon2）。四周后 SA-CORE-2018-004 写明：*This vulnerability is related to ... SA-CORE-2018-002 (CVE-2018-7600)*。Qualys / F5 的分析指出：8.5.1 的 `stripDangerousValues` 只看数组键，`destination` 是一个还要再被 `UrlHelper::parse` 拆开的**字符串**。NVD CVE-2018-7602 对应 Drupal 7.59 / 8.4.8 / 8.5.3。

根因不只是「少扫了一个参数名」。检查插在 ParameterBag 的键上；真正执行 `#post_render` 的是 Renderer；同一次请求里 `destination` 稍后会被拆成 query 数组，那次拆分在 8.5.1 **没有**再跑一遍 `#` 键检查。下面按请求走进去、8.5.1 加了哪一层、消毒后谁消费那个字符串、更强的 `checkDestination` 有没有挂上，把这几层写完。

---

## 这块功能本来在干什么

Drupal 用 render 数组描述页面和表单。以 `#` 开头的键是元素属性，不是用户字段名：`#markup` 是内容，`#post_render` 是渲染后要调用的 PHP callable。Form API 和 AJAX 会把请求参数合并进这些数组。`destination` 是 Drupal 自己的查询参数，表示「做完这件事跳到哪」，例如注销确认、删节点之后的回跳。

一次典型的未登录可触达路径（公开 Drupalgeddon3 写起来用过 `user/<uid>/cancel`；F5 还提到删节点时带的 destination）：

```http
GET /user/1/cancel?destination=/node/1
```

`DrupalKernel::preHandle` 在装遗留 include 之前先消毒请求（8.5.1 起才有）：

```php
// core/lib/Drupal/Core/DrupalKernel.php :: preHandle  (8.5.1)
public function preHandle(Request $request) {
    $request = RequestSanitizer::sanitize(
      $request,
      (array) Settings::get(RequestSanitizer::SANITIZE_WHITELIST, []),
      (bool) Settings::get(RequestSanitizer::SANITIZE_LOG, FALSE)
    );
    $this->loadLegacyIncludes();
    ...
}
```

设计意图：用户不得通过请求参数注入 `#` 属性；`destination` 应当只是站内路径。成功穿越之后的效果是：**攻击者指定的 PHP callable 在渲染时被调用**。本 case 用良性 `file_get_contents('/flag/pcb_flag.txt')` 当 callable，把树外金丝雀读进响应；公开利用则是 `exec` / `passthru`。

数据流：

```text
HTTP 查询 / POST / Cookie
    → DrupalKernel::preHandle
         V1：RequestSanitizer::sanitize
              stripDangerousValues(query/request/cookies)   ← 只扫数组键
         （8.5.1 没有 checkDestination）
    → 路由 / Form API / Renderer
         若某处把 destination 再 parse 成 query 数组
         则 #post_render / #markup 进入 render 数组
    → Renderer 调用 #post_render($#markup)
```

`access.default` 对许多表单确认页在已登录或带 token 时更宽；Drupalgeddon2 的原始利用甚至可以走 `user/register` 的 AJAX。本分析只盯 sanitizer 这一层：它是 CVE 对里唯一改变的门。

---

## 原始漏洞：请求里直接放 `#` 键（CVE-2018-7600，8.5.0）

8.5.0 没有 `RequestSanitizer` 这个类。`preHandle` 不扫 `#`。Unit42 对 Drupalgeddon2 的描述是：Form API 的 renderable array 把 `#` 前缀属性当成可执行结构，攻击者在 AJAX / 表单请求里塞 `#post_render` 就能让 Renderer 调用任意 PHP 函数。

本 case 的 seed 把键放在查询袋顶层（正是 8.5.1 sanitizer 会扫的那一层）：

```text
#post_render[] = file_get_contents
#markup        = /flag/pcb_flag.txt
```

8.5.0 上这些键原样进入 render 结构，callable 执行，响应里出现 `PCBFLAG_...`。没有这层检查。

---

## 维护者改了什么（CVE-2018-7600 修复，8.5.1）

8.5.1 新增整个 `RequestSanitizer` 类，并在 `preHandle` 入口调用。和 8.5.0 并排：V0 没有这个文件；V1 的核心是 `stripDangerousValues`：

```php
// core/lib/Drupal/Core/Security/RequestSanitizer.php  (8.5.1)
public static function sanitize(Request $request, $whitelist, $log_sanitized_keys = FALSE) {
    if (!$request->attributes->get(self::SANITIZED, FALSE)) {
      $get_sanitized_keys = [];
      $request->query->replace(static::stripDangerousValues(
          $request->query->all(), $whitelist, $get_sanitized_keys));
      // 同样处理 $request->request（POST）和 $request->cookies
      ...
      $request->attributes->set(self::SANITIZED, TRUE);
    }
    return $request;
}

protected static function stripDangerousValues($input, array $whitelist, array &$sanitized_keys) {
    if (is_array($input)) {
      foreach ($input as $key => $value) {
        if ($key !== '' && $key[0] === '#' && !in_array($key, $whitelist, TRUE)) {
          unset($input[$key]);
          $sanitized_keys[] = $key;
        }
        else {
          $input[$key] = static::stripDangerousValues($input[$key], $whitelist, $sanitized_keys);
        }
      }
    }
    return $input;
}
```

对 seed 这种顶层 `#` 键，它确实够用：`query->all()` 是数组，`#post_render` / `#markup` 被 `unset`，Renderer 看不到 callable，body 里没有金丝雀。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险属性只会作为 ParameterBag 的**键**出现。
2. 袋里的字符串值不会在稍后被重新解析成带 `#` 键的数组。

第二点不成立。`destination` 的值是 URL 字符串；Drupal 自己稍后会用 `UrlHelper::parse` 拆 query。`stripDangerousValues` 遇到非数组直接原样返回，根本不看字符串内容。

8.5.1 的 `sanitize` **没有** `checkDestination`。把 8.5.1 和 8.5.3 并排时，8.5.3 才在扫完袋之后对名为 `destination` 的值再 parse 一次。

---

## 消毒之后，destination 怎么接到渲染上

V1 的 `stripDangerousValues` 一结束，查询袋里仍可能有：

```text
destination = "user/1/cancel?q[%23post_render][]=file_get_contents&q[%23markup]=/flag/pcb_flag.txt"
```

或者 Drupalgeddon3 常见的写法：destination 的 query 里直接带 `#post_render`（URL 编码成 `%23`）。对 sanitizer 来说这是一个普通字符串，键名是 `destination`，不以 `#` 开头，值也不是数组，递归到此停止。

Drupal 随后在多处消费这个字符串：

- 确认表单 / 注销 / 删内容结束后的跳转
- `RedirectResponseSubscriber` 把 destination 收成 RedirectResponse
- 某些 Form API / AJAX 路径会把 destination 的 query **再解码** 合并进请求或 render 数组

F5 对 CVE-2018-7602 的描述是：*the sanitation function ... is not covering the case where a parameter contains a path that may be parsed by Drupal's Forms API. ... Drupal passes a "destination" parameter with a URL ... this is where an attacker can inject his payload.* 例子形态：`?destination=URL?param[#]=`。

Qualys 写得更直接：*`destination` is one of the accepted GET query parameters that can hold a URL with its own custom GET parameters. The fix for CVE-2018-7600 does not address this use case.*

也就是说：过滤器看的是袋的键；Renderer 看的是 destination 被 parse 之后的内层 query。两套结构中间，8.5.1 没有第二次 `#` 谓词。金丝雀能出现在渲染结果里，依据就是内层 `#post_render` 真的被当成 render 属性执行，而不是「destination 字符串碰巧打印出来」。

`UrlHelper::parse` 正是 8.5.3 后来拿来检查 destination 的那个函数。8.5.1 里它已经存在，只是 sanitizer 没调用。

---

## 仓库里已经有拆 URL 的工具，消毒没用

同一份 Drupal 8.5.1 里：

- `Drupal\Component\Utility\UrlHelper::parse($url)` 能把 querystring 拆成数组
- `stripDangerousValues` 已经能递归扫数组里的 `#` 键
- `sanitize` 已经拿到完整 `Request`

谁调用了「parse + strip」：

| 时机 | 对 destination 做 `UrlHelper::parse` + `stripDangerousValues`？ |
|---|---|
| 8.5.1 `RequestSanitizer::sanitize` | 否，只 `stripDangerousValues($bag->all())` |
| 8.5.3 `processParameterBag` | 是，`checkDestination($bag->get('destination'))` |
| 业务侧稍后 parse destination | 是，但那次 parse 的目的是跳转 / 合并参数，不是删 `#` |

不是仓库里没有「把 destination 当 URL 再扫一遍」的零件。是 **sanitize 入口没用**。即便没有 `%23post_render` 这种编码，只要字符串值稍后被 `parse_str` / `UrlHelper::parse` 变成数组，V1 的键扫描都看不见。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「袋的键 vs 字符串里的 query」落到具体变换：

- `stripDangerousValues`：看当前层 `$key[0] === '#'`
- Renderer：看 render 数组里有没有 `#post_render` 这个属性

只要 `#` 键不出现在袋的键上，而出现在某个字符串值的内层 query 里，第一层放行，渲染仍会调用 callable。

本 case residual：

```text
destination_path  = user/1/cancel
destination_query = {
  #post_render[] = file_get_contents
  #markup        = /flag/pcb_flag.txt
}
```

拼进请求后，顶层只有键 `destination`。V1 扫完 GET 袋：没有 `#` 键可删。稍后 `UrlHelper::parse(destination)` 得到的 query 里重新出现 `#post_render` / `#markup`，Renderer 调用 `file_get_contents('/flag/pcb_flag.txt')`。

这正是 8.5.0 上 seed 用过的那种 render 属性，只是藏进了 Drupal 自己约定要再 parse 的那个参数。SA-CORE-2018-004 要求站点**已经打过** SA-CORE-2018-002，补丁才有意义——它承认 8.5.1 那一层还在，只是不够。

V1 删的是「现在就是数组键」的 `#`；`destination` 里三个字符 `#` `p` `o` 在消毒时还是字符串的一部分（常常还是 `%23`），整段不会被当成一次键匹配。

---

## 残余仍然走同一条 render callable 路径（CVE-2018-7602）

没有换 callable、没有换 `#markup` 金丝雀、没有换 Renderer。还是：

```http
GET /...?destination=user/1/cancel%3F%23post_render%5B%5D=file_get_contents%26%23markup=%2Fflag%2Fpcb_flag.txt
```

（具体编码随 Form API 路径而异；机制是 destination 字符串携带内层 `#` 键。）

`preHandle` 仍然只跑 8.5.1 的 `sanitize`。`stripDangerousValues` 照样执行；执行完之后 destination 原样留在袋里；稍后 parse 把 `#post_render` 交回 Renderer。

认证意图：v1 + `--residual` 在渲染结果中观察到 `PCBFLAG_...`。顶层 `#` 键的 seed 在同一 V1 上被剥掉。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：消毒只认数组键；`destination` 的契约就是「里面还藏着一份 query」；那份 query 进入的是同一个 `#` 属性执行器。seed 被挡住只说明「顶层袋里不能再直接放 `#post_render`」，不说明「不能再让 Renderer 执行攻击者指定的 callable」。

公开 Drupalgeddon3 利用同样走 destination，payload 往往是 `exec`/`passthru`；本 case 把命令换成读金丝雀，不改变 sanitizer 与 Renderer 之间的那层缝。

---

## 后来又补了什么（CVE-2018-7602，8.5.3）

8.5.3 把袋处理抽成 `processParameterBag`，扫完键之后若存在 `destination` 就 `checkDestination`：

```php
// RequestSanitizer.php  (8.5.3)
protected static function processParameterBag(ParameterBag $bag, $whitelist, ...) {
    $bag->replace(static::stripDangerousValues($bag->all(), $whitelist, $sanitized_keys));
    ...
    if ($bag->has('destination')) {
      $destination_dangerous_keys = static::checkDestination($bag->get('destination'), $whitelist);
      if (!empty($destination_dangerous_keys)) {
        // The destination is removed rather than sanitized because the URL
        // generator service is not available and this method is called very
        // early in the bootstrap.
        $bag->remove('destination');
        ...
      }
    }
}

protected static function checkDestination($destination, array $whitelist) {
    $dangerous_keys = [];
    $parts = UrlHelper::parse($destination);
    if (!empty($parts['query'])) {
      static::stripDangerousValues($parts['query'], $whitelist, $dangerous_keys);
    }
    return $dangerous_keys;
}
```

对残余输入：`UrlHelper::parse` 拆出 `#post_render` / `#markup`，`stripDangerousValues` 把它们记进 `$dangerous_keys`，整个 `destination` 从袋里删除。后续既跳不过去带毒 URL，也无法把内层键合并进 render 数组。公开建议是升级到 Drupal 8.5.3（8.4.x 给了 8.4.8，7.x 给了 7.59）。

即便如此，这仍然是「对名为 destination 的字符串再 parse 一次」。其它也会被二次解析成 render 数组的字符串参数，若 8.5.3 没点名，需要另证。本 benchmark 的 v2 只关闭这一条 destination residual。SA-CORE-2018-004 写双方都在野利用。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是 ParameterBag 的键。真正执行代码的是 Renderer 对 `#post_render` 的调用。destination 是 Drupal 自己的二次解析通道，8.5.1 的 diff 里完全没有这个词。V2 仍在 sanitizer 里补，只是终于调用了已有的 `UrlHelper::parse`。

**不是没有更好的谓词。**  
`stripDangerousValues` 已经能扫任意数组。`UrlHelper::parse` 已经能把 destination 变成数组。缺的是在 `preHandle` 这么早的阶段把两者接上。从 V1 的 diff 只能看到「新增一个类、扫三个袋」；要判断补丁是否闭合，必须看到 destination 稍后仍会被 parse，以及 `is_array` 之外的值原样返回。

**同一 sanitizer、同一 Renderer，只换了 `#` 键的放置位置。**  
顶层 query 和 destination 内层 query 最终都要变成同一类 render 属性。advisory 说 *multiple attack vectors*，destination 是 8.5.1 明确没盖住的那一个。

**`#` 是框架的控制平面，不是用户字段。**  
若 Form API 从不把请求参数合并进 `#` 属性，sanitizer 根本不必近似「删所有井号键」。补丁选择在请求入口做黑名单，就要覆盖所有随后会被当成数组再解析的字符串。

---

## 版本、入口、参考

| | Drupal | `RequestSanitizer` | 顶层 `#` 键 seed | destination 内层 `#` 键 residual |
|---|---|---|---|---|
| V0 | 8.5.0 | 不存在 | callable 执行，金丝雀 | （不必） |
| V1 | 8.5.1 | 只 `stripDangerousValues` 三个袋 | 键被剥掉 | destination 原样留下，parse 后仍执行 |
| V2 | 8.5.3 | 加上 `checkDestination` + `UrlHelper::parse` | 挡 | 整段 destination 被 remove |

- Web：Drupal 表单 / 确认页带 `destination=`；seed 也可把 `#` 键放在查询袋顶层
- 认证意图：v0 seed 观察到 flag；v1 seed 未观察到；v1 residual 观察到 flag。
- [SA-CORE-2018-002](https://www.drupal.org/sa-core-2018-002)（CVE-2018-7600）、[SA-CORE-2018-004](https://www.drupal.org/sa-core-2018-004)（CVE-2018-7602）
- [NVD CVE-2018-7602](https://nvd.nist.gov/vuln/detail/CVE-2018-7602)
- [Qualys：destination 未消毒](https://threatprotect.qualys.com/2018/04/26/drupal-critical-rce-patch-release-cve-2018-7602/)
- [F5：删节点 / destination 注入](https://community.f5.com/kb/technicalarticles/drupal-core-remote-code-execution-cve-2018-7602/283401)
- [Unit42：Drupalgeddon2 与 stripDangerousValues](https://unit42.paloaltonetworks.com/unit42-exploit-wild-drupalgeddon2-analysis-cve-2018-7600/)
- 源码：[RequestSanitizer.php @ 8.5.1](https://github.com/drupal/drupal/blob/8.5.1/core/lib/Drupal/Core/Security/RequestSanitizer.php)、[8.5.3](https://github.com/drupal/drupal/blob/8.5.3/core/lib/Drupal/Core/Security/RequestSanitizer.php)
