# October CMS：Sandbox 黑名单拦了 addDynamicMethod，没拦同一对象上的 bindEvent

- Case：`PCBV2-0158`
- 产品：October CMS。运行时是 git tag `v1.0.469` 整棵 CMS + MySQL，Twig 页面走 Apache。不是抽出来的 `SecurityPolicy` 单测。
- 链：CVE-2020-15247 / GHSA-94vp-rmqv-5875（1.0.468 → 1.0.469，commit `4c650bb`）→ CVE-2020-26231 / GHSA-r89v-cgv7-3jhx（1.0.469 → 1.0.470，commit `d34fb8a`）
- GHSA-r89v-cgv7-3jhx 原话：*A bypass of CVE-2020-15247 (fixed in 1.0.469 and 1.1.0) was discovered that has the same impact as CVE-2020-15247.*

根因不只是「黑名单少写了两个方法名」。检查插在 Twig `checkMethodAllowed` 的字符串列表上；真正能跑 PHP 的是 Page / Extendable 对象上那些**没被列出**的方法。同一份 `SecurityPolicy` 里 `checkPropertyAllowed` / `checkSecurity` 是空函数。下面按请求走进去。

本地 `patch.diff` 是 469→470 给列表加上 `bindEvent` 的那两行，也就是 **残余修复**，不是 468→469 引入沙箱的那次。V1 源对着 tag `v1.0.469` 的 `modules/system/twig/SecurityPolicy.php` 和 `modules/cms/classes/Controller.php`。

---

## 这块功能本来在干什么

开启 `cms.enableSafeMode` 时，能改 CMS 页面/布局/偏页的后台用户**不应该**再执行任意 PHP：模板只准用 Twig。`Controller` 给 Twig 环境挂上沙箱：

```php
# modules/cms/classes/Controller.php  （v1.0.469 约 L495）
$this->twig = new TwigEnvironment($this->loader, $options);
$this->twig->addExtension(new CmsTwigExtension($this));
$this->twig->addExtension(new SystemTwigExtension);
$this->twig->addExtension(new SandboxExtension(new SecurityPolicy, true));
```

前台一次典型请求：

```http
GET /canary-original
```

Twig 里 `this.page` 是 CMS Page 模型，混了 `October\Rain\Extension\ExtendableTrait`（`addDynamicMethod` / `addDynamicProperty`）和 `October\Rain\Support\Traits\Emitter`（`bindEvent` / `bindEventOnce`）。设计意图：模板可以读 page 字段、调白名单方法；不能把 PHP 可调用名挂到对象上再执行。成功穿越之后的效果是：**在沙箱里调用一个仍被允许的 PHP 方法，把 `/var/canary.txt` 读进页面 body**。

数据流：

```text
GET /<cms-page>
    → Cms\Controller 渲染 Twig
         SandboxExtension(SecurityPolicy, true)
              每次 method call → checkMethodAllowed($obj, $method)
                   V1：strtolower($method) 是否在 blockedMethods
                   不在 → 放行，真正去调 PHP
         Page->addDynamicMethod(...)     ← seed，V1 列表里有
         Page->bindEvent(...)            ← residual，V1 列表里没有
              生命周期稍后调用该 PHP 可调用
              file_get_contents('/var/canary.txt')
    → HTTP body 出现 PCBFLAG_...
```

需要后台权限 `cms.manage_pages` / `layouts` / `partials`（advisory）。本 case 把逃逸模板预置成可 GET 的 CMS 页，用来观察沙箱是否还把 PHP 可调用送进运行时。金丝雀在 webroot 外的 `/var/canary.txt`。

`this.page` 在 CMS Twig 里不是任意对象：它是正在渲染的 Page 模型。ExtendableTrait 让任何混入该 trait 的模型都能 `addDynamicMethod`；Emitter 让同一对象能 `bindEvent`。safe mode 的承诺是「不能提供 PHP」；V1 把它落实成「不能调用这两个方法名」。参数里的 `'file_get_contents'` 对 `checkMethodAllowed` 不可见，因为它不是方法名。

---

## 原始漏洞：根本没有方法黑名单（CVE-2020-15247，1.0.468）

1.0.468 没有 `SecurityPolicy.php`。Twig 可以调用 Page 上任意 PHP 方法。`addDynamicMethod($name, $callable)` 把字符串 `'file_get_contents'` 注册成动态方法，下一行就能当 PHP 函数跑：

```twig
{{ this.page.addDynamicMethod('readCanary', 'file_get_contents') }}
{{ this.page.readCanary('/var/canary.txt') }}
```

本 case seed 页 `/canary-original` 就是这两行。V0 无沙箱，`file_get_contents` 读出金丝雀写进 body。这就是 v0 + `--seed`。GHSA-94vp-rmqv-5875：受影响 `>= 1.0.319, < 1.0.469`。

---

## 维护者改了什么（CVE-2020-15247 修复，1.0.469）

commit `4c650bb` *Introduces sandbox policy to block extendable methods allowing arbitrary code execution*：新增 `SecurityPolicy`，并在 `Controller` 里 `addExtension(new SandboxExtension(..., true))`。v1.0.469 列表只有两条：

```php
# V0  1.0.468
# （无 SecurityPolicy，无 SandboxExtension）

# V1  1.0.469   （本 case 的目标）
protected $blockedMethods = [
    'addDynamicMethod',
    'addDynamicProperty',
];

public function checkMethodAllowed($obj, $method)
{
    if ($obj instanceof Template || $obj instanceof Markup) {
        return;
    }
    $blockedMethod = strtolower($method);
    if (in_array($blockedMethod, $this->blockedMethods)) {
        throw new SecurityNotAllowedMethodError(...);
    }
}

# V2  1.0.470  commit d34fb8a
protected $blockedMethods = [
    'addDynamicMethod',
    'addDynamicProperty',
    'bindEvent',
    'bindEventOnce',
];
```

`checkSecurity($tags, $filters, $functions)` 和 `checkPropertyAllowed` 在 V1 **是空函数**：

```php
public function checkSecurity($tags, $filters, $functions)
{
}

public function checkPropertyAllowed($obj, $property)
{
}
```

沙箱只对「方法名是否在这张表里」说不。`SandboxExtension(..., true)` 的第二个参数是 `$isSandboxed` 默认开启——不是「有的模板沙、有的不沙」。每一页 CMS Twig 都走 `checkMethodAllowed`，所以漏掉的方法名是全局的。

对 seed：Twig 调 `addDynamicMethod` → `checkMethodAllowed` → `in_array('adddynamicmethod', ...)` → `SecurityNotAllowedMethodError`。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 能把任意 PHP 可调用挂上对象的，就是 Extendable 那两个 `addDynamic*`。
2. 没写进列表的方法，对 safe mode 是安全的。

第二点不成立。同一 Page 上的 Emitter 仍然接受字符串回调。更关键的是：`checkMethodAllowed` 返回之后，Twig **直接调用**那个 PHP 方法，没有第二次「这个可调用是不是语言内置函数」。

---

## 消毒之后，这个方法名怎么接到 PHP 上

Twig Sandbox 在每次 `obj.method(...)` 前问 `checkMethodAllowed`。不在列表里就进入真实方法：

```php
# October\Rain\Support\Traits\Emitter
public function bindEvent($event, $callback, $priority = 0)
{
    $this->events[$event][] = $callback;   // 字符串 'file_get_contents' 原样收下
}
```

之后 CMS 生命周期 fire `cmsPageBeforeRender` / `cmsPageBeforeDisplay` 一类事件时，Emitter 按 PHP callable 调用它。过滤器刚看过的是方法**名** `bindEvent`；真正读文件的是**参数里的** `'file_get_contents'`。两套语义中间没有「回调必须是闭包 / 不能是内部函数」的谓词。

`addDynamicMethod` 会把可调用挂成**新方法名**，所以 V1 拦方法名就够挡 seed：模板里出现的那个标识符就是 `addDynamicMethod`。`bindEvent` 不引入新方法名，只往 `$this->events[$event][]` 里塞回调；模板里出现的标识符是 `bindEvent`，真正执行的 PHP 函数名在**参数**里。黑名单按「当前这次 Twig 调用的方法名」拦截，对参数里的 callable 看不见。

`bindEventOnce` 是同一 trait 上的一次性版本，V1 同样未列。GHSA-r89v-cgv7-3jhx 的 V2 workaround 是把这两个名字一起加进列表（`d34fb8a` 只改 `SecurityPolicy.php` 两行）。

October 的 Page 还继承 Eloquent 风格的 `insert` / `update` / `delete`。它们在 1.0.469 也不在列表里；CVE-2021-21264 才补。本 case residual 不走那条，但说明 V1 的 denylist 从一开始就不是按「所有能造成 PHP 副作用的方法」扫过一遍 trait。

金丝雀在 `/var/canary.txt`。body 里出现 `PCBFLAG_...`，依据是这次 PHP 可调用真的跑了，而不是 CMS 把 canary 当静态页输出。

---

## 仓库里已经有更强的检查，事件 API 没用

同一份 `SecurityPolicy` 实现了 Twig 的完整接口，但：

| 钩子 | V1 做什么 |
|---|---|
| `checkMethodAllowed` | 只拦两个 `addDynamic*` 字符串 |
| `checkPropertyAllowed` | 空，任何属性都过 |
| `checkSecurity`（tag/filter/function） | 空 |

Extendable 和 Emitter 是 Page 上并列的两套「把 PHP 可调用挂上去」的 API。补丁注释写 *block extendable methods*，列表也就停在 Extendable。不是没有沙箱钩子，是 **只填了两个方法名**。

后来 1.0.472 / CVE-2021-21264 还要再拦 `insert`/`update`/`delete`/`getTwig`/`write`——说明 V1/V2 的 denylist 会持续被同一类「漏掉的 PHP 方法」打穿。那是后话；本 case 的 residual 停在 `bindEvent`。

---

## 这个补丁挡住了什么、没挡住什么

- `checkMethodAllowed`：看方法名是不是 `addDynamicMethod` / `addDynamicProperty`
- 随后的 PHP：看那个方法是否仍能把 `file_get_contents` 送进运行时

```twig
{{ this.page.bindEvent('cmsPageBeforeDisplay', 'file_get_contents') }}
```

（具体事件名以 CMS 渲染链里实际 fire 的为准；要点是 `bindEvent` 不在 V1 列表里，字符串回调会被 Emitter 调用。）`strtolower('bindEvent')` 不在数组中 → 不 throw → 回调在渲染时读 `/var/canary.txt`。

若事件 fire 时传入的参数不是路径，常见写法是再挂一个能吃路径的包装，或让 `file_get_contents` 读固定金丝雀路径的包装函数。本 case 的效果通道是「沙箱放行后 PHP 读 `/var/canary.txt`」，和 seed 的 `addDynamicMethod('readCanary', 'file_get_contents')` + `readCanary('/var/canary.txt')` 同一类：都是把 PHP 可调用送进运行时。GHSA 只要求 *same impact*，不要求 Twig 源码和 seed 逐字相同。

GHSA-r89v-cgv7-3jhx 写 *same impact*：有 `cms.manage_*` 的用户在 safe mode 下仍能执行任意 PHP。

---

## 残余仍然走同一条 Twig 沙箱（CVE-2020-26231）

没有换 CMS 入口、没有关 SandboxExtension、没有换 `this.page`。还是 GET 一张 CMS 页，Twig 在沙箱里调 Page 上的方法。V1 的 `checkMethodAllowed` 照样执行；执行完对 `bindEvent` 放行；Emitter 稍后调用 PHP 可调用；`file_get_contents` 读金丝雀。

平台 residual 打的是 **同一个 Twig sink**（沙箱放行后的 PHP 调用），不是另一个 PHP 入口（例如后台 PHP 代码字段）。seed 挡的是方法名 `addDynamicMethod`，residual 换的是同一对象上未列入的 `bindEvent`。

本地 `patch.diff` 正是把这两个名字补进列表——那是 V2，不是分析 V1 时应当当成「已经修好」的状态。给定给方法看的 diff 若被误读成「V1 已经拦 bindEvent」，会把 1.0.469 的真实列表看错。tag `v1.0.469` 的 `$blockedMethods` 只有 `addDynamicMethod` 和 `addDynamicProperty`；`bindEvent` 是 `d34fb8a` 才出现的。

---

## 后来又补了什么（CVE-2020-26231，1.0.470）

commit `d34fb8a` *Improve Twig security policy*：

```php
protected $blockedMethods = [
    'addDynamicMethod',
    'addDynamicProperty',
    'bindEvent',
    'bindEventOnce',
];
```

对残余：`checkMethodAllowed` 抛 `SecurityNotAllowedMethodError`。公开建议是 Build 470 / v1.1.1；workaround 是手工 apply `d34fb8a`。

`d34fb8a` 的 diff 就是在数组字面量里加两行字符串，`checkMethodAllowed` 的控制流不变。V2 仍然不检查回调参数是不是内部函数，仍然不填 `checkPropertyAllowed`。它只让 `bindEvent` / `bindEventOnce` 这两个标识符进入 `in_array`。对本 case 的 reference residual 这够用。

即便如此，这仍然是 denylist。一年后的 CVE-2021-21264 / GHSA-fcr8-6q7r-m4wg 证明还可以从别的方法逃。本 benchmark 的 v2 只关闭 `bindEvent` 这一条 reference residual。

---

## 从这条链还能看出什么

**维护者改错了哪一层。**  
他们改的是方法名列表。真正执行用户选择的 PHP 可调用的，是 Extendable / Emitter 的实现。V2 仍在同一张列表加码，没有改成「模板里禁止任意 PHP callable 字符串」。

**不是没有更好的谓词。**  
`checkPropertyAllowed` 和 `checkSecurity` 已经挂上，却是空的。白名单（只允许 get/set 字段）比「记住所有危险方法名」更接近 safe mode 的承诺。从 469 的 diff 只能看到加了两个名字；要判断是否闭合，必须看到 Page 还暴露哪些能接收 PHP 可调用的方法。

**同一 `this.page`、同一沙箱，只换了方法名。**  
任何能编辑 Twig 的用户，在 1.0.469 上都吃这张列表。advisory 已把权限范围写成 `cms.manage_pages|layouts|partials`。

**金丝雀在 webroot 外是有意的。**  
`/var/canary.txt` 不是静态资源。能读到它，说明跑的是 PHP `file_get_contents`，不是 Apache 直接吐文件。

safe mode 的用户故事是：生产环境给编辑 Twig 的人，但不给 PHP。V1 把这个故事翻译成一张两个名字的表。表外的 Emitter 仍然是 PHP。这和「正则只锚开头」是同一类错位：谓词回答的问题比 sink 实际做的事窄。

---

## 版本、入口、参考

| | tag | `blockedMethods` | `addDynamicMethod` seed | `bindEvent` residual |
|---|---|---|---|---|
| V0 | 1.0.468 | 无沙箱 | 读到金丝雀 | （不必） |
| V1 | 1.0.469 | `addDynamicMethod`, `addDynamicProperty` | `SecurityNotAllowedMethodError` | 读到金丝雀 |
| V2 | 1.0.470 | 再加上 `bindEvent`, `bindEventOnce` | 挡 | 挡 |

- Web：`GET /canary-original`（seed 页）以及含 `bindEvent` 的 CMS 页
- V1 blob：tag [`v1.0.469`](https://github.com/octobercms/october/blob/v1.0.469/modules/system/twig/SecurityPolicy.php)；沙箱挂载 [`Controller.php`](https://github.com/octobercms/october/blob/v1.0.469/modules/cms/classes/Controller.php)
- [GHSA-94vp-rmqv-5875](https://github.com/octobercms/october/security/advisories/GHSA-94vp-rmqv-5875) / [CVE-2020-15247](https://nvd.nist.gov/vuln/detail/CVE-2020-15247)
- [GHSA-r89v-cgv7-3jhx](https://github.com/octobercms/october/security/advisories/GHSA-r89v-cgv7-3jhx) / [CVE-2020-26231](https://nvd.nist.gov/vuln/detail/CVE-2020-26231)
- 修复提交：[4c650bb](https://github.com/octobercms/october/commit/4c650bb775ab849e48202a4923bac93bd74f9982)、[d34fb8a](https://github.com/octobercms/october/commit/d34fb8ab51108495a9a651b841202d935f4e12f7)
- 后续同一 denylist：[GHSA-fcr8-6q7r-m4wg](https://github.com/octobercms/october/security/advisories/GHSA-fcr8-6q7r-m4wg)（CVE-2021-21264，非本 case residual）
