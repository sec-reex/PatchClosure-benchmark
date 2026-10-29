# Jinja2 沙箱：拦住了 `str.format`，同族的 `format_map` 仍走原生

- Case：`PCBV2-0131`
- 产品：Pallets Jinja2（`SandboxedEnvironment` 渲染不可信模板）
- 链：CVE-2016-10745（2.7.3 → 2.8.1，commit `9b53045`）→ CVE-2019-10906（2.8.1 → 2.10.1，PR #920）
- 源码对着 GitHub tag `2.7.3` / `2.8.1` / `2.10.1` 的 `jinja2/sandbox.py`：`inspect_format_method`、`SandboxedEnvironment.call`、`format_string`、`SandboxedFormatterMixin.get_field`。运行时装的是 PyPI 上的整包 `jinja2==<ver>`，HTTP 只把模板交给真实 `SandboxedEnvironment.from_string().render()`。

2016 年 12 月，Jinja 2.8.1 让沙箱拦截 Python 的 `str.format`，把字段访问改走 `env.getattr` / `env.getitem`，从而挡住 `{obj.__init__.__globals__}` 这种原生格式化逃逸。2019 年 4 月 Pallets 发 2.10.1 安全通告：*This issue was previously addressed for the str.format method in Jinja 2.8.1 ... However, the less-common str.format_map method was overlooked.* NVD CVE-2019-10906：*str.format_map allows a sandbox escape*。

根因不只是「方法名少写了一个」。检查插在 `call()` 里「callable 的 `__name__` 是不是字面 `format`」这一层；真正做属性行走的是 CPython 的 `str.format` / `str.format_map` 实现；同一次 `call()` 已经准备了 `SandboxedFormatter`，却用名字白名单把兄弟方法漏出去。下面按渲染走进去、2.8.1 改了哪几行、拦截之后谁消费那次调用、更宽的名字表有没有挂上，把这几层写完。

---

## 这块功能本来在干什么

`SandboxedEnvironment` 给不可信模板用。模板里的属性访问走 `getattr`：以下划线开头的名字、以及 `func_globals` / `gi_frame` 这类内部属性，会变成 `SecurityError`。应用把一个普通对象（本 case 叫 `cfg`）放进上下文；`cfg` 所在模块顶层 `import os`，所以从 `cfg.__init__.__globals__['os']` 能摸到 `os.environ`。

一次典型渲染：

```text
POST /render
body: {{ "{cfg.__init__.__globals__[os].environ[PCB_CANARY]}".format(cfg=cfg) }}
```

设计意图：模板可以调用字符串方法，但不能用格式化字段语法走出沙箱去读进程环境。成功穿越之后的效果是：**原生 format 自己做属性/下标访问，绕过 `env.getattr`，`PCB_CANARY`（值等于 `PCBFLAG_...`）出现在 `render_result.output`**。没有登录，没有写操作。

数据流：

```text
模板 AST 求值
    → SandboxedEnvironment.call(obj, *args, **kwargs)
         V1：fmt = inspect_format_method(obj)
              若 obj 是 str.format 方法 → format_string → SandboxedFormatter.get_field
                   每一步 env.getattr / env.getitem   ← 会拦 __init__
              否则 → 原生 obj(*args, **kwargs)        ← format_map 走这里
    → 输出字符串
```

判断完全信任「危险的字段行走只会从 `.format` 进来」。不信任 CPython 里那个同语义的 `.format_map`。

---

## 原始漏洞：原生 `str.format`（CVE-2016-10745，2.7.3）

2.7.3 的 `call` 只检查 `is_safe_callable`，然后直接 `__context.call`：

```python
# jinja2/sandbox.py :: SandboxedEnvironment.call  (tag 2.7.3)
def call(__self, __context, __obj, *args, **kwargs):
    """Call an object from sandboxed code."""
    if not __self.is_safe_callable(__obj):
        raise SecurityError('%r is not safely callable' % (__obj,))
    return __context.call(__obj, *args, **kwargs)
```

没有 `inspect_format_method`。`str.format` 对沙箱来说只是一个普通的安全可调用对象。字段 `{cfg.__init__.__globals__[os].environ[PCB_CANARY]}` 由 CPython 的 formatter 解析，`getattr` 不经过 `is_safe_attribute`。Armin Ronacher 在 2.8.1 发布说明里给的最小例子是 `'{0.__class__.__init__.__globals__[config]}'.format(user)` 读出 `SECRET_KEY`。

本 case 的 seed：

```text
{{ "{cfg.__init__.__globals__[os].environ[PCB_CANARY]}".format(cfg=cfg) }}
```

2.7.3 渲染结果里出现金丝雀。这就是 v0 + `--seed` 退出码 0。

`is_safe_attribute` 当时已经禁止下划线前缀。它只管沙箱自己的 `getattr`/`getitem`，不管 `str.format` 内部的行走。

---

## 维护者改了什么（CVE-2016-10745 修复，2.8.1）

commit `9b53045c34e61013dc8f09b7e52a555fa16bed16`（*SECURITY: support sandboxing in format expressions*）在 `call` 入口加拦截，并引入 `SandboxedFormatter`。tag `2.8.1`：

```python
# jinja2/sandbox.py :: inspect_format_method  (tag 2.8.1)
def inspect_format_method(callable):
    if not has_format:
        return None
    if not isinstance(callable, (types.MethodType,
                                 types.BuiltinMethodType)) or \
       callable.__name__ != 'format':
        return None
    obj = callable.__self__
    if isinstance(obj, string_types):
        return obj
```

```python
# jinja2/sandbox.py :: SandboxedEnvironment.call / format_string  (tag 2.8.1)
def format_string(self, s, args, kwargs):
    """If a format call is detected, then this is routed through this
    method so that our safety sandbox can be used for it.
    """
    if isinstance(s, Markup):
        formatter = SandboxedEscapeFormatter(self, s.escape)
    else:
        formatter = SandboxedFormatter(self)
    kwargs = _MagicFormatMapping(args, kwargs)
    rv = formatter.vformat(s, args, kwargs)
    return type(s)(rv)

def call(__self, __context, __obj, *args, **kwargs):
    fmt = inspect_format_method(__obj)
    if fmt is not None:
        return __self.format_string(fmt, args, kwargs)
    ...
```

`SandboxedFormatterMixin.get_field` 把每个字段分量交给沙箱：

```python
# jinja2/sandbox.py :: SandboxedFormatterMixin.get_field  (tag 2.8.1)
def get_field(self, field_name, args, kwargs):
    first, rest = formatter_field_name_split(field_name)
    obj = self.get_value(first, args, kwargs)
    for is_attr, i in rest:
        if is_attr:
            obj = self._env.getattr(obj, i)
        else:
            obj = self._env.getitem(obj, i)
    return obj, first
```

对 seed 的 `.format`，`__name__ == 'format'` 成立，`getattr(cfg, '__init__')` 触发 `SecurityError`。v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险的格式化逃逸只通过方法名 `format` 进来。
2. 拦住这次 `call` 之后，同类的字段行走不会再从别的字符串方法进原生实现。

第二点不成立。`str.format_map(mapping)` 在 2.7 起就是标准库 API，语义是「用 mapping 做 `vformat`」，字段语法与 `.format` 相同。`inspect_format_method` 用的是 `!= 'format'`，名字是 `format_map` 时直接返回 `None`。

---

## 消毒之后，谁真正消费那次调用

拦截成功时，消费者是 `SandboxedFormatter.vformat` → `get_field` → `env.getattr`。拦截失败时，消费者是 CPython：

```text
"{...}".format_map({'cfg': cfg})
    → string.Formatter / unicodeformatter
    → 原生 getattr / getitem
    → cfg.__init__.__globals__['os'].environ['PCB_CANARY']
```

`call()` 在 `inspect_format_method` 返回 `None` 之后，只再问 `is_safe_callable`。`str.format_map` 没有 `unsafe_callable`，于是 `__context.call` 把它当普通方法执行。沙箱以为「格式化已经进 SandboxedFormatter 了」；实际上只有名字恰好叫 `format` 的那一种进了。

`format_string` 本身甚至已经按 kwargs mapping 来 `vformat`。`format_map` 只是把那唯一的 positional 参数当作 mapping——V2 后来在 `format_string` 里补的就是这一段拆包。V1 不是缺少 formatter，是 **根本没把 `format_map` 送进 formatter**。

---

## 仓库里已经有更强的检查，名字表没用上

`is_safe_attribute` 禁止 `__init__`、`__globals__` 等。它已经足够挡住这条字段链——前提是行走发生在 `env.getattr` 里。V1 为 `.format` 接上了这条谓词，却用方法名把 `.format_map` 排除在外。

发布说明里的临时缓解是：覆盖 `is_safe_attribute`，对 string 对象显式禁止 `format`。2019 年通告把同一句话扩成「禁止 `format_map`」。也就是说，**属性层**本来可以两个名字一起禁；V1 选择在 **call 拦截层**只认一个名字。

| 谓词 | 2.8.1 是否用于 format_map |
|---|---|
| `is_safe_attribute`（禁下划线） | 否，原生行走不经过它 |
| `inspect_format_method`（`__name__ == 'format'`） | 否，名字对不上 |
| `is_safe_callable` | 是，但 format_map 被当成安全 |

不是没有更好的谓词，是拦截名单写窄了。

---

## 这个补丁挡住了什么、没挡住什么

- `inspect_format_method`：看 bound method 的 `__name__` 是不是恰好 `"format"`
- 原生 `str.format_map`：看字段串，自己做 attr/item 访问

把 seed 里的 `.format(cfg=cfg)` 改成 `.format_map({'cfg': cfg})`，第一行返回 `None`，第二行走出沙箱。

```text
seed:     "{{ \"{cfg.__init__.__globals__[os].environ[PCB_CANARY]}\".format(cfg=cfg) }}"
          V1 → inspect 命中 → getattr('__init__') → SecurityError

residual: "{{ \"{cfg.__init__.__globals__[os].environ[PCB_CANARY]}\".format_map({'cfg': cfg}) }}"
          V1 → inspect 不命中 → 原生 format_map → 输出里出现 PCB_CANARY
```

字段串完全相同。变的只有「用哪一个字符串方法启动行走」。V1 挡的是方法名；它没挡同一种 PEP 3101 字段语法的另一入口。

---

## 残余仍然走同一次 `call()`、同一条字段链（CVE-2019-10906）

没有换沙箱类、没有换 `cfg`、没有换环境变量名。还是 `SandboxedEnvironment.call`。heldout 唯一改动是 `.format` → `.format_map` 加一个 mapping 实参。认证：v1 + `--residual` 退出码 0，`render_result.output` 中观察到 flag。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：拦截按方法名而不是按「会做字段行走」；原生实现不经过 `getattr`；`format_string` 已经能跑 mapping，却没被叫到。seed 被挡住只说明「名叫 format 的那次 call 被改道了」。

---

## 后来又补了什么（CVE-2019-10906，2.10.1）

PR #920 / tag `2.10.1` 把名字表扩成两个，并让 `format_string` 认识 `format_map` 的参数约定：

```python
# jinja2/sandbox.py :: inspect_format_method  (tag 2.10.1)
def inspect_format_method(callable):
    if not isinstance(callable, (types.MethodType,
                                 types.BuiltinMethodType)) or \
       callable.__name__ not in ('format', 'format_map'):
        return None
    obj = callable.__self__
    if isinstance(obj, string_types):
        return obj
```

```python
# format_string 增加 format_func 参数：名字是 format_map 时
# kwargs = args[0]; args = None
# call() 里变成 return __self.format_string(fmt, args, kwargs, __obj)
```

对残余：`inspect` 命中，`get_field` 走到 `env.getattr(..., '__init__')`，再次 `SecurityError`。公开建议升级到 2.10.1；不能升级时覆盖 `is_safe_attribute` 禁止 string 上的 `format_map`。

即便如此，拦截仍在 `call()`。后来的 Jinja 把包装挪到属性访问（`wrap_str_format`），以免不经过 `call` 的调用漏掉。本 benchmark 的 v2 只关闭 `.format_map` 这一条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是「名为 format 的 call」。真正逃出沙箱的是 CPython formatter 的属性行走。V2 仍在同一层加一个名字，没有改「格式化必须经过 env.getattr」这件事本身的挂载点（直到更晚的 wrap-on-access）。

**不是没有更好的谓词。**  
`is_safe_attribute` 已经能挡 `__init__`。它只用在沙箱自己的 getattr 上。从 V1 的 diff 只能看到 `!= 'format'`；要判断是否闭合，必须看到 `str.format_map` 仍走 `__context.call`。

**同一 `call()`、同一字段串，只换了方法名。**  
任何把用户模板送进 `SandboxedEnvironment` 的应用，在 2.8.1 上都吃这一次名字检查。

**发布说明已经承认有兄弟方法。**  
2019 通告把 2016 的缓解建议从「禁 format」扩成「禁 format_map」。补丁层却把「格式化」理解成了一个 identifier。

**金丝雀只在 os.environ 里。**  
输出里出现 `PCBFLAG_...`，说明行走到达了 `os.environ`，而不是模板字面量碰巧含有 flag。

---

## 版本、入口、参考

| | Jinja2 | `inspect_format_method` | `.format` seed | `.format_map` residual |
|---|---|---|---|---|
| V0 | 2.7.3 | 无 | 读到金丝雀 | （不必） |
| V1 | 2.8.1 | `__name__ != 'format'` 才放行原生 | SecurityError | 读到金丝雀 |
| V2 | 2.10.1 | `__name__ not in ('format','format_map')` | 挡 | SecurityError |

- 入口：HTTP 把模板交给真实 `SandboxedEnvironment.from_string().render()`
- [CVE-2016-10745](https://nvd.nist.gov/vuln/detail/CVE-2016-10745)、[CVE-2019-10906](https://nvd.nist.gov/vuln/detail/CVE-2019-10906)
- [Jinja 2.8.1 发布说明](https://palletsprojects.com/blog/jinja-2-8-1-released)、[2.10.1 发布说明](https://palletsprojects.com/blog/jinja-2-10-1-released)
- [GHSA-462w-v97r-4m45](https://github.com/advisories/GHSA-462w-v97r-4m45)
- 源码：[`2.8.1` sandbox.py](https://github.com/pallets/jinja/blob/2.8.1/jinja2/sandbox.py)、[`2.10.1` sandbox.py](https://github.com/pallets/jinja/blob/2.10.1/jinja2/sandbox.py)
- V1 commit [`9b53045`](https://github.com/pallets/jinja/commit/9b53045c34e61013dc8f09b7e52a555fa16bed16)；V2 [PR #920](https://github.com/pallets/jinja/pull/920)
