# Grav CMS：cleanDangerousTwig 只扫了一遍字面量

- Case：`PCBV2-0026`
- 产品：Grav（扁平文件 PHP CMS；页面/字段里的 Twig 经 `Twig::processString()` 渲染）
- 链：CVE-2024-28116（1.7.44 → 1.7.45）→ CVE-2025-66294（1.7.45 → 1.8.0-beta.27）
- 源码对着官方 tag `1.7.45` 的 `system/src/Grav/Common/Security.php`、`system/src/Grav/Common/Twig/Twig.php`、`system/src/Grav/Common/Twig/Extension/GravExtension.php`。运行时是整仓 Grav + Apache，探针走真实的 `processString()`，不是抽出来的正则。

2024 年 Grav 1.7.45 给不可信 Twig 加了一个 `Security::cleanDangerousTwig()`，想在渲染前把带危险名字的 `{{ }}` / `{% %}` 块改成注释。一年多后 GHSA-662m-56v4-3r8f 指出：这是弱正则，而且 `evaluate` / `evaluate_twig` 不在名单里——内层可以在全新的 Twig 环境里再跑一遍，外层消毒根本看不到拼出来的名字。NVD 把这件事记成 CVE-2025-66294，根因写的就是 *weak regex validation in the cleanDangerousTwig method*。

根因不只是「黑名单少了两个词」。检查插在字符串上；真正执行用户拼出来的模板的是另一个 `Environment`；同一次渲染里已经有主引擎的 undefined-function 回调，内层却不走 `processString`。下面按请求走进去、补丁加了哪一段、消毒后怎么进引擎、`evaluateTwigFunc` 为什么不拦，把这三层写完。

---

## 这块功能本来在干什么

Grav 允许页面内容和若干字段里写 Twig。入口是 `Twig::processString()`：先消毒，再把字符串当成模板渲染。本 case 的探针 `POST /pcb-probe` 把 payload 交给这条真实路径。

一次典型调用：

```php
// system/src/Grav/Common/Twig/Twig.php :: processString  (grav 1.7.45, 约 L392–410)
public function processString($string, array $vars = [])
{
    $this->grav->fireEvent('onTwigStringVariables');
    $vars += $this->twig_vars;

    $string = Security::cleanDangerousTwig($string);

    $name = '@Var:' . $string;
    $this->setTemplate($name, $string);
    $output = $this->twig->render($name, $vars);
    ...
}
```

`processPage` / `processSite` 同样在把内容交给 Twig 之前调一次 `cleanDangerousTwig`。设计意图：编辑者写的 Twig 可以出页面，但不能去碰 `registerUndefinedFunctionCallback`、`twig.getFunction` 这类能改引擎或直接调 PHP 的名字。

成功穿越之后的效果，本 case 用的是良性金丝雀：在**主** Grav Twig 环境上把 undefined-function 回调改成 PHP 的 `getenv`，再 `getFunction('PCB_FLAG')`，从而读出进程环境里的 `PCBFLAG_...`。`grav.twig.twig` 就是单例里那份真实的 `Twig\Environment`。

数据流：

```text
POST /pcb-probe  {payload: <twig string>}
    → Twig::processString($payload)
         V1：cleanDangerousTwig($payload)     ← 单遍正则，只看字面量
         $this->twig->render(...)             ← 主环境，带 GravExtension
              若 payload 调用 evaluate_twig(inner)
                  → GravExtension::evaluateTwigFunc
                       new Environment          ← 新环境，不再调 cleanDangerousTwig
                       $template->render(inner)
                           内层可改 grav.twig.twig 上的回调
    → 响应 output 字段
```

---

## 原始漏洞：没有消毒器（CVE-2024-28116，1.7.44）

1.7.44 的 `Security.php` 里没有 `cleanDangerousTwig`（grep 计数为 0）。`processString` 把用户字符串直接 `render`。页面里写

```twig
{{ grav.twig.twig.registerUndefinedFunctionCallback('getenv') }}
{{ grav.twig.twig.getFunction('PCB_FLAG') }}
```

就会在主环境上挂上 `getenv`，再按函数名去解析 `PCB_FLAG`。本 case 的 seed 就是这种**字面连续**的危险名。没有登录墙挡在探针前面（真实站点上通常要编辑者权限；advisory 也写了特定条件下未认证可打）。

1.7.45 的 CHANGELOG 把这次修复记成 GHSA-2m7x-c7px-hp58 / GHSA-r6vw-8v8r-pmp4 / GHSA-qfv4-q44r-g7rv：*Fixed a security issue with insecure Twig functions be processed*。

---

## 维护者改了什么（CVE-2024-28116 修复，1.7.45）

V1 在 `Security` 末尾加了一个静态方法，并在 `processString` / `processPage` / `processSite` 三处调用。方法本体：

```php
// system/src/Grav/Common/Security.php :: cleanDangerousTwig  (1.7.45)
public static function cleanDangerousTwig(string $string): string
{
    if ($string === '') {
        return $string;
    }

    $bad_twig = [
        'twig_array_map',
        'twig_array_filter',
        'call_user_func',
        'registerUndefinedFunctionCallback',
        'undefined_functions',
        'twig.getFunction',
        'core.setEscaper',
        'twig.safe_functions',
    ];
    $string = preg_replace(
        '/(({{\s*|{%\s*)[^}]*?(' . implode('|', $bad_twig) . ')[^}]*?(\s*}}|\s*%}))/i',
        '{# $1 #}',
        $string
    );
    return $string;
}
```

正则的字面意思：

| 片段 | 含义 |
|---|---|
| `({{` 或 `{%` | 一个 Twig 块的开头 |
| `[^}]*?` | 块内、遇到 `}` 之前的任意字符（非贪婪） |
| 黑名单之一 | 必须**连续出现**在这一块里 |
| `}}` 或 `%}` | 同一块的结尾 |
| 无第二遍、无 `while` | `preg_replace` 单次扫描 |

它注释掉的是「单个块里字面含有黑名单词」的整段，不是语义上的沙箱。没有 Twig AST，没有「内层再渲染也必须再消毒」，名单里也没有 `evaluate` / `evaluate_twig`。

对 seed 这种明文连续名字，它确实够用：

```text
输入:  {{ grav.twig.twig.registerUndefinedFunctionCallback('getenv') }}
V1 后: {# {{ grav.twig.twig.registerUndefinedFunctionCallback('getenv') }} #}
```

`registerUndefinedFunctionCallback` 落在同一对 `{{ }}` 里，整块变成注释，主引擎看不到这次回调注册。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险能力长得像名单里那些连续子串，而且出现在**一个** `{{ }}` / `{% %}` 里。
2. 外层消毒过一次之后，渲染过程中不会再出现一份**没消过毒**的模板源。

两点都不成立。更关键的是：名单挡住的是「出现在当前字符串里的名字」；真正执行内层模板的那次 `render`，根本不会再走进 `cleanDangerousTwig`。

---

## 消毒之后，内层模板怎么接到引擎上

V1 的 `preg_replace` 一结束，`processString` 用**同一份**（可能原样留下的）字符串去 `render`。Grav 把 `evaluate_twig` 注册成 Twig 函数，指向 `GravExtension::evaluateTwigFunc`：

```php
// GravExtension.php  (1.7.45, 约 L906–916)
public function evaluateTwigFunc($context, $twig)
{
    $loader = new FilesystemLoader('.');
    $env = new Environment($loader);
    $env->addExtension($this);

    $template = $env->createTemplate($twig);

    return $template->render($context);
}
```

注意它做了什么、没做什么：

- **做了**：新建一个 `Twig\Environment`，只挂上当前这份 `GravExtension`（所以内层仍能调用 `evaluate_twig`、仍能通过上下文碰到 `grav`）。
- **没做**：不调用 `Security::cleanDangerousTwig($twig)`；不复用主环境上已经打过的沙箱/SourcePolicy；不走 `Twig::processString()`。

GHSA 把第二点说成：*the evaluate and evaluate_twig functions which are allowed, and since we can call Twig syntax from inside them, it will lead to nested function calls*。外层正则再严，也只看见外层源码。内层字符串是 Twig 运行时用 `~` 拼出来的，消毒器在拼之前就已经返回了。

主环境上 `grav.twig.twig` 仍是那份单例 `Environment`。内层模板只要写 `grav.twig.twig.registerUndefinedFunctionCallback(...)`，改的就是外层引擎的回调表——内层自己那份空环境反而不重要。

---

## 仓库里名单挡住了名字，没挡住拼名字的通道

同一份 `Security.php` 把 `registerUndefinedFunctionCallback` 和 `twig.getFunction` 都写进了 `$bad_twig`。seed 正是靠这两项被注释掉的。

谁调用消毒器：

| 函数 | 调用 `cleanDangerousTwig`？ |
|---|---|
| `Twig::processString` / `processPage` / `processSite` | 是，渲染前扫一遍源码 |
| `GravExtension::evaluateTwigFunc` | **否**，`createTemplate($twig)` 直接 render |
| 内层 `Environment` | **否**，连 Grav 的主 loader / 回调策略都没有 |

V1 等于在调用方入口做了一个**更弱**的字符串过滤（必须连续、必须在一对花括号里、单遍），而真正会二次编译用户字符串的那条 API 始终没挂上。不是仓库里没有「危险名字」的概念，是 **evaluate 这条路径没用**。

即便不靠 `~` 拆开名字，只要 `evaluate_twig('{{ grav.twig.twig.registerUndefinedFunctionCallback(...) }}')` 这种内层字面量能进 `evaluateTwigFunc`，内层也不会再被扫一遍。拆开名字只是为了让**外层**正则也看不见这两个词——因为外层源码里它们不再连续。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs 引擎」落到具体代码：

- `cleanDangerousTwig` 的 `preg_replace`：看当前字符串的某一个 `{{ }}` 里有没有连续的黑名单词
- `evaluateTwigFunc` 的 `createTemplate($twig)->render`：看拼出来的内层源码在新环境里怎么执行

只要构造一种输入，使「外层单个块里」没有连续黑名单词，但运行时拼出的内层模板里有，第一行会放行，第二行仍然改主引擎。

`~` 拼接就是这样来的。Twig 的 `'a' ~ 'b'` 在**源码**里是两段字面量，运行时才变成 `'ab'`。外层正则看的是源码：

```text
'{{ grav.twig.' ~ 'twig.regist' ~ 'erUndefinedFunctionCallback("getenv") }}'
```

这里没有任何连续的 `registerUndefinedFunctionCallback`，也没有连续的 `twig.getFunction`（`get` 和 `Function` 被拆在 `~` 两侧）。`evaluate_twig` 本身不在 1.7.45 名单里。整段外层原样留下。

运行时 `evaluate_twig` 收到的 inner 是：

```text
{{ grav.twig.twig.registerUndefinedFunctionCallback("getenv") }}
{{ grav.twig.twig.getFunction("PCB_FLAG") }}
```

新环境不消毒，按这段源码渲染：主环境挂上 `getenv`，再按名字取出 `PCB_FLAG`。

GHSA 给的另一条示例是 `{{ evaluate("read_file('/etc/passwd')") }}`——`evaluate` 同样不在 V1 名单里，危险名字藏在字符串参数里，外层 `[^}]*?` 看的是整块，但 `read_file` 在 1.7.45 的 `$bad_twig` 里也没有（advisory 贴出的稍新名单才加上）。本 case 的 residual 用的是拆开的 `registerUndefinedFunctionCallback` + `evaluate_twig` 嵌套，两条漏洞叠加：名单不含二次求值入口，正则又不认被拆开的词。

---

## 残余仍然走同一条 processString 路径（CVE-2025-66294）

没有换 CMS、没有换渲染入口。还是：

```http
POST /pcb-probe
{"payload":"{{ evaluate_twig('{{ grav.twig.' ~ 'twig.regist' ~ 'erUndefinedFunctionCallback(\"getenv\") }}{{ grav.twig.twig.get' ~ 'Function(\"PCB_FLAG\") }}') }}"}
```

`processString` 仍然先 `cleanDangerousTwig`。V1 那一遍正则照样执行；执行完之后字符串几乎没变；主引擎调用 `evaluate_twig`；`evaluateTwigFunc` 用新环境渲染拼好的 inner；金丝雀出现在 `output` 里。

本 case residual 把 payload 写死（运行时不读 held-out 文件），与 GHSA 描述的 nested `evaluate_twig` 同一构造，只是把 `system` / `read_file` 换成 `getenv('PCB_FLAG')`。认证：v1 + `--residual` 退出码 0，响应中观察到 flag。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：正则匹配语言比 Twig 求值语义窄；二次编译发生在检查之后；二次编译没有使用已经存在的 `cleanDangerousTwig`。seed 被挡住只说明「字面连续的危险名没了」，不说明「不能再从 processString 改主引擎回调」。

---

## 后来又补了什么（CVE-2025-66294，1.8.0-beta.27 / e372595）

1.8.0-beta.27 把 `cleanDangerousTwig` 改成四遍过滤，并把 `evaluate_twig` / `evaluate` 写进函数名单。Pass 3 不再要求名字落在一对 `{{ }}` 里：

```php
// Security.php :: cleanDangerousTwig  (1.8.0-beta.27，节选)
// Pass 1: 块内危险函数（含 evaluate_twig / evaluate / getenv / ...）
$string = preg_replace($patterns['functions'], '{# BLOCKED: $1 #}', $string);
// Pass 2: 块内危险属性（twig.twig、config.set、...）
$string = preg_replace($patterns['properties'], '{# BLOCKED: $1 #}', $string);
// Pass 3: 任意位置的 `名字(` —— 为 nested eval bypass
$string = preg_replace($patterns['calls'], '{# BLOCKED: $0 #}', $string);
// Pass 4: join 拼接绕过
$string = preg_replace($patterns['join'], '{# BLOCKED: $1 #}', $string);
```

对残余输入，Pass 3 的 `/\b(evaluate_twig)\s*\(/i` 在外层就能把调用挖掉，inner 根本进不了 `evaluateTwigFunc`。公开建议是升级到 1.8.0-beta.27。

即便如此，这仍然主要是「在入口加厚字符串过滤」。`evaluateTwigFunc` 在 1.7.45 上新建裸 `Environment` 的结构，要到后续版本才改成回调用 `processString`（从而内层也会再走消毒器）。本 benchmark 的 v2 关闭的是 reference residual 这一条：外层出现 `evaluate_twig(` 即被挡。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是 `processString` 入口的字符串。真正二次编译用户模板的是 `evaluateTwigFunc` 的 `createTemplate`。V2 仍在同一层加码（把 `evaluate_twig(` 从源码里挖掉），没有在 1.7.45 就把内层接到已有的 `cleanDangerousTwig`。

**不是没有更好的挂钩点。**  
`processString` 已经是「字符串 → 消毒 → 渲染」的唯一正路。`evaluateTwigFunc` 另起炉灶。从 V1 的 diff 只能看到加了一个黑名单 `preg_replace`；要判断补丁是否闭合，必须看到 `evaluateTwigFunc` 建了新环境、以及正则要求名字落在单个块内。

**同一函数、同一 `$string`，只换了 Twig 的写法。**  
任何把用户字符串传进 `processString` 的插件/字段，在 1.7.45 上都吃这一遍正则和同一次 `evaluate_twig`。advisory 已指出其它间接调用 `processString` 的类同样受影响。

**黑名单是源码形态，不是 AST。**  
`[^}]*?` 让「块内出现 `}`」或「用 `~` 切开标识符」都能让连续词消失。若消毒器走 Twig lexer、或禁止 `evaluate*` 作为函数名，后面那次裸 `Environment` 根本不会被逼去近似沙箱。

**金丝雀是 `getenv`，不是 shell。**  
`PCB_FLAG` 在进程环境里。能读到它，说明主引擎的 undefined-function 回调被改成了真实 PHP 函数。这和 advisory 里的 `system` / `read_file` 是同一条原语，只是效果换成可观测的 flag。

---

## 版本、入口、参考

| | tag | `cleanDangerousTwig` | `evaluateTwigFunc` | 字面 seed | 嵌套 residual |
|---|---|---|---|---|---|
| V0 | 1.7.44 | 无 | 新 Environment，不消毒 | 读到 flag | （不必） |
| V1 | 1.7.45 | 单遍 8 词正则 | 同上 | 块被注释 | 拼出 inner，读到 flag |
| V2 | 1.8.0-beta.27 | 四遍，含 `evaluate_twig` + Pass 3 | 本 case 不依赖其改动 | 挡 | 外层 `evaluate_twig(` 被挖掉 |

- 探针：`POST /pcb-probe`（真实 `Twig::processString()`）
- 认证（本平台）：v0 seed 观察到 flag；v1 seed 未观察到；v1 residual 观察到。
- [CVE-2024-28116](https://nvd.nist.gov/vuln/detail/CVE-2024-28116)、[CVE-2025-66294](https://nvd.nist.gov/vuln/detail/CVE-2025-66294)
- [GHSA-662m-56v4-3r8f](https://github.com/getgrav/grav/security/advisories/GHSA-662m-56v4-3r8f)（含 V1 正则原文与 nested eval 说明）
- 修复提交：[de1ccfa](https://github.com/getgrav/grav/commit/de1ccfa12dbcbf526104d68c1a6bc202a98698fe)（引入 `cleanDangerousTwig`）、[e372595](https://github.com/getgrav/grav/commit/e37259527d9c1deb6200f8967197a9fa587c6458)（1.8.0-beta.27 四遍过滤）
