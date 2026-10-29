# Twig：include() 函数补了 checkSecurity，沙箱标签编译路径没补

- Case：`PCBV2-0206`
- 产品：Twig（`twig/twig`）。运行时是 Composer 整包；本 case 用 PHP 内置服务器把 `Environment::render` 暴露成 `POST /run`，驱动的是已发布库的 sandbox API，不是抽出来的 `checkSecurity`。
- 链：CVE-2024-45411（3.13.0 → 3.14.0，GHSA-6j75-5wfj-gh66）→ CVE-2026-46638（3.14.0 → 3.26.0，GHSA-7fxw-r6jv-74c8）
- 源码对着 tag `v3.14.0` 的 `CoreExtension::include`、`Node/IncludeNode::compile`、`TokenParser/SandboxTokenParser`。金丝雀是 benign：`pcb_flag()` 不在 allow-list 里，被调用则把 `${PCB_FLAG}` 写进渲染输出。

GHSA-7fxw-r6jv-74c8 标题即 *incomplete fix for CVE-2024-45411*。原文：函数路径加了 `$loaded->unwrap()->checkSecurity()`，*the deprecated but still functional `{% sandbox %}{% include %}` tag path was not updated*。根因不只是「漏了一个语法」。检查插在「这次 include 会不会再调一次 checkSecurity」上；真正执行标签/过滤器/函数的是模板的 `yield`。构造期那一次 checkSecurity 被 `isSandboxed()` 关掉之后，结论会粘在 `Environment::$loadedTemplates` 里。下面按库 API 走进去。

---

## 这块功能本来在干什么

Twig 的沙箱给不可信模板套 `SecurityPolicy` 白名单：只允许列出的 tag / filter / function。全局可以关沙箱，只在某次 `include(..., sandboxed=true)` 或 `{% sandbox %}...{% endsandbox %}` 里打开。设计意图：被 include 的那份模板也必须过白名单。

`checkSecurity()` 编译进每个 Template 的构造函数，受 `SandboxExtension::isSandboxed()` 门控。模板实例缓存在 `Environment::$loadedTemplates`。因此：**在非沙箱里 load 过一次的模板，构造期那次检查是空跑，缓存命中后不会自动再跑。** include 要重新套白名单，必须在 include 现场再调一次 `checkSecurity()`。

本 case 的 HTTP 是对这套 API 的薄包装：

```http
POST /run
{"template": "{{ include('evil.twig', sandboxed=true) }}"}
```

harness 先 `$env->load('evil.twig')`（沙箱关），再 `render('probe.twig')`。`evil.twig` 是 `{{ pcb_flag() }}`，`pcb_flag` 不在 allow-list。

数据流：

```text
Environment::load('evil.twig')          ← 非沙箱，构造期 checkSecurity 空跑
    实例进入 $loadedTemplates            ← 结论粘住
probe 渲染
    路径 A：CoreExtension::include(..., sandboxed=true)
         resolveTemplate
         V1：unwrap()->checkSecurity()   ← CVE-2024-45411 补在这里
         render / yield
    路径 B：{% sandbox %}{% include %}
         SandboxTokenParser → SandboxNode
         IncludeNode.compile
              V1：yield from load()->unwrap()->yield()   ← 没有 checkSecurity
         enableSandbox / disableSandbox 只包住 yield
    pcb_flag() 若未再检查 → 输出 PCBFLAG_...
```

需要「同一 Environment 里先在沙箱外 load 过」这一条件，和 GHSA-6j75-5wfj-gh66 写的三条一致。成功穿越 = **白名单被跳过，disallowed 函数照跑**。

---

## 原始漏洞：按名字 include 不重查（CVE-2024-45411，3.13.0）

3.13.0 的 `CoreExtension::include` 在沙箱打开后，只对传入的 `Template` / `TemplateWrapper` **实例**再查一遍；经 `resolveTemplate` 得到的**名字**不查。缓存里的 `evil.twig` 正好是名字。seed：

```twig
{{ include('evil.twig', sandboxed=true) }}
```

`checkSecurity` 不跑，`pcb_flag()` 执行。这就是 v0 + seed。GHSA 写修复是 *security checks are always run at runtime*；落地 commit 是在 `include()` 里补上那一次调用。

---

## 维护者改了什么（CVE-2024-45411 修复，3.14.0）

3.14.0 在 `resolveTemplate` 之后、`render` 之前加上：

```php
// CoreExtension::include   tag v3.14.0
$loaded = $env->resolveTemplate($template);
...
if ($isSandboxed) {
    $loaded->unwrap()->checkSecurity();
}
return $loaded->render($variables);
```

对 seed：缓存模板也会再走 `SecurityPolicy::checkSecurity()`，`pcb_flag` 不在 functions 白名单 → `SecurityNotAllowedFunctionError`。这就是 v1 + `--seed`。

补丁默认了两件事：

1. 运行时 include 的入口是 `CoreExtension::include()` 这个 PHP 函数。
2. 加上这一次调用，所有「沙箱内 include 已缓存模板」的路径就闭合了。

第二点不成立。`{% include %}` 不经过这个函数。它编译成 `IncludeNode` 生成的 PHP，V1 的 `compile()` **没有** `checkSecurity()`。`SandboxTokenParser` 也不给 IncludeNode 打 `sandboxed` 标记。

---

## 编译产物怎么接到 yield 上

V1 `IncludeNode::compile`（非 `ignore_missing` 分支）就是：

```php
yield from $this->loadTemplate(...)->unwrap()->yield(...);
```

`{% sandbox %}` 编译成 `enableSandbox(); <body>; disableSandbox();`。body 几乎必须是 include（parser 限制）。于是运行时顺序是：

```text
enableSandbox()
yield from cachedEvil->unwrap()->yield(...)    ← 不调用 checkSecurity
disableSandbox()
```

`yield` 执行模板体时沙箱是开的，但 **allow-list 那一次检查已经在构造期以 isSandboxed=false 跑过了**，不会因为现在 sandbox 开着就自动重跑。`pcb_flag()` 作为普通函数调用执行。

过滤器（V1 真正加上的那次 `checkSecurity`）挂在函数 `include()` 上；标签路径的消费者是 `yield`。同一缓存实例、同一 `SecurityPolicy`，只是调用约定换了。

---

## 仓库里已经有同一谓词，标签路径没挂

V1 刚加的 `$loaded->unwrap()->checkSecurity()` 就是正确的那一层：对**已经构造完的**模板再执行一遍编译进去的检查，此时 `isSandboxed()` 为真，白名单生效。它已经出现在 `CoreExtension::include` 里。`IncludeNode` 在同一版本里继续只 `yield`。

`SandboxTokenParser`（v3.14.0）解析后只 `return new SandboxNode($body, ...)`，不 `setAttribute('sandboxed', true)`。所以即便有人想在 `IncludeNode::compile` 里读这个属性，V1 也读不到。V2 两处一起改：parser 打标，compile 读标并 emit `checkSecurity()`。

模板类上的 `checkSecurity()` 不是「没有这个函数」，是 **include 的一条语法没调用它**。

---

## 这个补丁挡住了什么、没挡住什么

- V1 `CoreExtension::include`：沙箱函数 include 在 render 前重查
- V1 `IncludeNode::compile`：标签 include 直接 yield

seed 走函数，被挡住。residual 走标签：

```twig
{% sandbox %}
{% include 'evil.twig' %}
{% endsandbox %}
```

预条件相同：`evil.twig` 已在非沙箱 load 过。V1 编译路径不重查，`pcb_flag()` 输出 flag。GHSA-7fxw-r6jv-74c8 把这条编译结果写进 advisory 正文，和源码一致。

---

## 残余仍然走同一条「缓存模板 + 沙箱 include」路径（CVE-2026-46638）

没有换 `SecurityPolicy`、没有换 `pcb_flag`、没有换「先 load 再 include」的预条件。还是对已缓存模板做沙箱 include，还是靠跳过 `checkSecurity` 让 disallowed 函数跑起来。差别只是 API：`include()` 函数换成 `{% sandbox %}{% include %}` 标签。

平台 residual 若用标签打 `POST /run`，和 advisory 是同一 sink。不是另起一个 SSTI 面（例如未沙箱的 `{{ }}` 或动态 `template_from_string`）。要注意：本 case 的 HTTP 是库 harness，产品侧对应的是 CMS/应用里「对用户模板做 sandbox include」的那次 `Environment::render`；sink 仍是 Twig 自己的 allow-list。

V1 `SandboxTokenParser::parse` 的全部安全相关动作是：要求 `{% sandbox %}` 体里实质上只有 `IncludeNode`（夹杂空白 `TextNode` 可以），然后 `return new SandboxNode($body)`。没有 `setAttribute('sandboxed', true)`。`SandboxNode` 编译出来是：

```text
$sandbox = $this->sandbox;
if (!$alreadySandboxed = $sandbox->isSandboxed()) {
    $sandbox->enableSandbox();
}
try {
    yield from <IncludeNode 的产物>;
} finally {
    if (!$alreadySandboxed) $sandbox->disableSandbox();
}
```

IncludeNode 的产物在 V1 是 `yield from $this->loadTemplate('evil.twig', ...)->unwrap()->yield(...)`。`loadTemplate` / `$env->load` 命中 `$loadedTemplates['evil.twig']`，**不会再 new**，构造期 `checkSecurity` 不会重跑。`enableSandbox()` 只把标志位打开，供**尚未执行**的检查去读；已经执行过的那次空跑不会因为标志后来变了而补做。

函数路径之所以在 V1 闭合，是因为它在 `render` 之前**显式**又调了一次：

```php
$loaded = $env->resolveTemplate($template);  // 缓存命中同一实例
if ($isSandboxed) {
    $loaded->unwrap()->checkSecurity();      // 此时 isSandboxed()==true
}
return $loaded->render($variables);
```

标签路径缺的就是这一行。`pcb_flag` 作为普通 `{{ }}` 函数调用走进 CoreExtension 的 function 调用点；沙箱扩展在调用前问 policy「functions 白名单有没有 pcb_flag」。因为 `checkSecurity` 没跑，这次调用前的 tag/filter/function 集合检查被整段跳过，policy 根本没有机会拒绝。

---

## 后来又补了什么（CVE-2026-46638，3.26.0）

3.26.0 让 `{% sandbox %}` 内的 IncludeNode 带 `sandboxed=true`，`compile()` 在 yield 前 emit：

```php
$t->unwrap()->checkSecurity();
yield from $t->unwrap()->yield(...);
```

这与 3.14.0 给函数路径加的那一行对齐。对残余：缓存模板在沙箱打开后被再查一次，`pcb_flag` 拒绝。公开建议升到 3.26.0。（3.27 之后又把显式 `checkSecurity` 收进 `yield()`，超出本链。）

即便标签路径补上了，构造期门控 + 实例缓存这个设计还在：任何**新的** include 编译路径若忘记 emit 检查，仍会粘住旧结论。本 benchmark 的 v2 只关闭标签这一条 reference residual。

3.26.0 的 `SandboxTokenParser` 在确认 body 是 IncludeNode（或其中的 IncludeNode）之后调用 `$node->setAttribute('sandboxed', true)`。`IncludeNode::compile` 读这个属性：普通 include 仍只 yield；带标记的才先 `checkSecurity`。`ignore_missing` 分支同样要在 `if ($t)` 之后、`yield` 之前插入同一调用，否则缺失文件的 catch 路径会漏。GHSA-7fxw-r6jv-74c8 写 *matching the behaviour of CoreExtension::include() with sandboxed = true*——V2 的目标是两条语法在「缓存模板 + 沙箱」下调用同一谓词，而不是改 `SecurityPolicy` 本身。`pcb_flag` 仍然不在 allow-list 里；闭合靠的是检查被重新执行，不是函数被改名。

---

## 从这条链还能看出什么

**维护者改错了哪一层。**  
他们改的是 `include()` 这一个 PHP 入口。真正跳过白名单的是「缓存实例不再跑构造期检查」加上「某条 include 编译路径不重查」。V2 仍在编译层补同一调用，没有取消粘性缓存。

**不是没有更好的谓词。**  
`checkSecurity()` 在 3.14.0 已经存在，并且刚被函数路径用上。标签路径没用。

**同一缓存模板、同一 allow-list，只换了 include 语法。**  
任何在非沙箱 load 之后再沙箱 include 的应用，在 3.14.0 上都吃函数路径的新检查和标签路径的旧编译。

**`{% sandbox %}` 在 3.14 已标 deprecated，但仍功能完整。**  
不完全修复常常落在「旧语法没跟着新检查走」。advisory 把这一点写进标题。

`Environment::$loadedTemplates` 的键是模板名。`cache => false` 只关掉文件系统编译缓存，**不**关掉这次请求里的实例表。harness 每请求 new 一个 Environment，所以必须在同一次 `render` 之前先 `load('evil.twig')` 才能种下粘性结论——这正好是 GHSA-6j75 写的第三条。若应用把 Environment 做成进程级单例，一次非沙箱渲染就会让后续所有沙箱 include 吃到同一份未检查实例，条件比 harness 更宽。

---

---

## 函数路径和标签路径的编译结果并排

V1 函数 `include('evil.twig', sandboxed=true)` 运行时等价于：开沙箱（若尚未开）→ `resolveTemplate`（缓存命中）→ `checkSecurity()` → `render`。V1 标签 `{% sandbox %}{% include 'evil.twig' %}` 等价于：开沙箱 → `loadTemplate`（缓存命中）→ **直接 yield** → 关沙箱。中间少的那一次 `checkSecurity()` 就是 45411 补丁没有覆盖的语法。`SecurityPolicy` 的 `$allowedFunctions` 在两条路径上是同一份；residual 不是「白名单里多写了 pcb_flag」，是检查没跑。harness 每请求 new Environment，必须先 `$env->load('evil.twig')` 才能种下粘性实例，对应 advisory 的第三条预条件。

若把 `include` 写成传入 Template 实例而不是名字，3.13.0 的函数路径其实会重查（V0 只漏「名字」）。本 case seed 用名字，与 GHSA-6j75 描述一致。标签路径即使在 3.14.0 也始终不重查，不论名字还是已经 load 过的缓存。

`Template` 构造函数里编译进去的检查形态是：

```php
public function __construct(...) {
    ...
    if ($this->env->hasExtension(SandboxExtension::class)
            && $this->env->getExtension(SandboxExtension::class)->isSandboxed()) {
        $this->checkSecurity();
    }
}
```

`isSandboxed()` 在非沙箱 load 时为 false，`checkSecurity` 整段不执行，实例却已经进 `$loadedTemplates`。之后无论函数路径还是标签路径，拿到的都是这个实例。函数路径靠显式再调一次补上；标签路径在 V1 没有对应的再调。`SecurityNotAllowedFunctionError` 只在检查实际执行且 `pcb_flag` 不在名单时出现——residual 在 V1 上连异常都没有，输出里直接是 flag。

`{% include %}` 还有 `ignore missing` 修饰。V1 的 `ignore_missing` 分支同样只 `yield`，没有 `checkSecurity`。V2 在 `if ($t)` 里对 sandboxed include 补了这一行，避免「文件存在时跳过检查、缺失时才进 catch」。本 case residual 不用 ignore missing，走的是普通 include 分支；两条分支在 V1 都不重查，V2 都要重查。

## 版本、入口、参考

| | 版本 | `CoreExtension::include` | `IncludeNode::compile` | 函数 include seed | 标签 include residual |
|---|---|---|---|---|---|
| V0 | 3.13.0 | 只对实例重查，名字不查 | 无 checkSecurity | pcb_flag 执行 | （不必） |
| V1 | 3.14.0 | `unwrap()->checkSecurity()` | 仍无 | SecurityNotAllowedFunctionError | pcb_flag 执行 |
| V2 | 3.26.0 | 同 V1 | 沙箱 include 先 checkSecurity | 挡 | 挡 |

- 库 API：`Twig\Environment::render` / `include(..., sandboxed=true)` / `{% sandbox %}{% include %}`
- 本 case HTTP：`POST /run` JSON `template`（真实 twig/twig，未改引擎）
- [GHSA-6j75-5wfj-gh66](https://github.com/twigphp/Twig/security/advisories/GHSA-6j75-5wfj-gh66)（CVE-2024-45411）
- [GHSA-7fxw-r6jv-74c8](https://github.com/twigphp/Twig/security/advisories/GHSA-7fxw-r6jv-74c8)（CVE-2026-46638，*incomplete fix for CVE-2024-45411*）
- [NVD CVE-2024-45411](https://nvd.nist.gov/vuln/detail/CVE-2024-45411)、[NVD CVE-2026-46638](https://nvd.nist.gov/vuln/detail/CVE-2026-46638)
- V1 源码：[CoreExtension.php @ v3.14.0](https://github.com/twigphp/Twig/blob/v3.14.0/src/Extension/CoreExtension.php)（`include()` 约 L567–L604）、[IncludeNode.php](https://github.com/twigphp/Twig/blob/v3.14.0/src/Node/IncludeNode.php)、[SandboxTokenParser.php](https://github.com/twigphp/Twig/blob/v3.14.0/src/TokenParser/SandboxTokenParser.php)
- V2：commit `819c6a89` / tag `v3.26.0` 的 `IncludeNode::compile`
