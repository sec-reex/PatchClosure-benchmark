# Keras safe_mode：包名过了白名单，get_file 照样被 Lambda 调起来

- Case：`PCBV2-0098`（`deser_keras_safe_mode`）
- 产品：Keras（`keras-team/keras`）。本 case 用官方 PyPI `keras==3.8.0` / `3.9.0` / `3.11.0`，Flask `POST /load` 把 JSON 配置交给 `keras.saving.load_model(..., safe_mode=True)`。
- 链：CVE-2025-1550（3.8.0 → 3.9.0，PR `#20751` / commit `bb340d6`）→ CVE-2025-8747（3.9.0…3.10.0 → 3.11.0，PR `#21429`，GHSA-c9rc-mg46-23w3）
- 源码对着 GitHub tag `v3.9.0` / `v3.11.0` 的 `keras/src/saving/serialization_lib.py`：`_retrieve_class_or_fn`、`api_export.get_symbol_from_name`、`LOADING_APIS`。运行时装的是发布包本身。

2025 年 3 月，Keras 3.9.0 给 `safe_mode` 下的类/函数解析加了一张**包名**白名单：`module` 的第一段必须是 `keras` / `keras_hub` / `keras_cv` / `keras_nlp`。这挡住了 `pcb_leak.leak` 这种树外可调用对象。五个月后 JFrog 的 Andrey Polkovnichenko 在 GHSA-c9rc-mg46-23w3 写出：*It is possible to bypass the mitigation introduced in response to CVE-2025-1550 ... by crafting malicious arguments to built-in Keras modules.* 同一条 Lambda 原语，把 `function` 指到 `keras.utils.get_file`，带上攻击者控制的 `origin` / `cache_dir`。NVD CVE-2025-8747 写的是 *safe mode bypass ... even when safe_mode is enabled*。

根因不只是「白名单漏了一个函数」。检查插在「模块属于哪个包」这一层；真正被调用的是解析出来的任意可调用对象。白名单上面还有一条 **keras.* API 路径**，根本不经过那张包集合，直接 `get_symbol_from_name` 返回。下面按 `load_model` 走进去、3.9.0 改了哪几行、解析之后谁调用那个函数、更强的 `LOADING_APIS` 有没有挂上，把这几层写完。

---

## 这块功能本来在干什么

Keras v3 把模型图存成 `.keras` 档案（zip + `config.json`）。`load_model` 按配置重建层。`Lambda` 层的 `function` 节点可以命名一个 Python 可调用对象：`{"module": "...", "class_name": "function", "config": "name"}`。解析成功后，一次前向就会调用它，并把 `arguments` 当关键字参数传进去。

`safe_mode=True`（3.x 默认）本来是为了拦住配置里的 `__lambda__` 字节码。CVE-2025-1550 证明：不必嵌 Python 源码，只要能 `import` 任意模块并 `getattr` 出函数，一样能在 load 期间执行代码。

本 case 的服务就是这种用法：

```http
POST /load
Content-Type: application/json

<Keras Functional config.json>
```

```python
# app.py
keras.saving.load_model(path_or_config, safe_mode=True)
# 再做一次 zeros 输入的前向
```

设计意图：配置是层图，不是代码。成功穿越之后的效果是：**Lambda 在 load/forward 期间调用了配置指定的函数**。本 case 把这次调用收成一次良性读：`get_file` 把 `file:///canary/flag.txt` 拷到 `/out`，`/load` 把 `/out` 读进响应。真实 CVE-2025-8747 用远程 `origin` 做任意文件覆盖；这里只用本地 `file://`。

数据流：

```text
HTTP JSON config
    → load_model(safe_mode=True)
         deserialize_keras_object
         Lambda.from_config
              function = _retrieve_class_or_fn(module, name)
                   V1：keras.* → get_symbol_from_name     ← 补丁没动这条
                   V1：其它包 → package in {keras,...}    ← 补丁插在这里
              Lambda.call(inputs, **arguments)           ← 真正的 sink
    → /out 出现金丝雀 → JSON body
```

没有登录。判断完全信任 `safe_mode`「不会跑任意可调用对象」。

---

## 原始漏洞：任意模块都能 import（CVE-2025-1550，3.8.0）

3.8.0 的 `_retrieve_class_or_fn` 在自定义对象表未命中之后，对任意 `module` 做 `importlib.import_module`：

```python
# keras/src/saving/serialization_lib.py :: _retrieve_class_or_fn  （3.8.0）
        try:
            mod = importlib.import_module(module)          # 任意攻击者模块
        except ModuleNotFoundError:
            raise TypeError(...)
        obj = vars(mod).get(name, None)
        if obj is not None:
            return obj
```

`safe_mode` 只拦 `class_name == "__lambda__"`。`class_name: "function"` 不走那条。NVD CVE-2025-1550：*By altering the config.json file within the archive, an attacker can specify arbitrary Python modules and functions, along with their arguments, to be loaded and executed during model loading.* 修复在 PR `#20751`。

本 case 的 seed 指向树外模块 `pcb_leak.leak`（拷金丝雀、忽略 tensor 第一参）：

```text
Lambda.function  = {module: "pcb_leak", class_name: "function", config: "leak"}
Lambda.arguments = {flag_path: "/canary/flag.txt", out_path: "/out/orig_leak.txt"}
```

3.8.0 上 `import pcb_leak` 成功，前向调用 `leak`，响应里出现 `PCBFLAG_...`。这就是 v0 + `--seed` 退出码 0。

---

## 维护者改了什么（CVE-2025-1550 修复，3.9.0）

PR `#20751` / commit `bb340d6780fdd6e115f2f4f78d8dbe374971c930` 没有拿掉 Lambda，也没有限制「可以调用哪些函数」。它只在 **import 之前**加了包名白名单。tag `v3.9.0`：

```python
# keras/src/saving/serialization_lib.py :: _retrieve_class_or_fn  (v3.9.0, 约 L728–792)
    if module:
        if module == "keras" or module.startswith("keras."):
            api_name = module + "." + name
            obj = api_export.get_symbol_from_name(api_name)
            if obj is not None:
                return obj
        ...
        package = module.split(".", maxsplit=1)[0]
        if package in {"keras", "keras_hub", "keras_cv", "keras_nlp"}:
            try:
                mod = importlib.import_module(module)
                obj = vars(mod).get(name, None)
                if obj is not None:
                    return obj                             # 包内任意对象，含函数
            except ModuleNotFoundError:
                raise TypeError(...)
        raise TypeError(f"Could not locate {obj_type} '{name}'. ...")
```

字面意思：

| 片段 | 含义 |
|---|---|
| `module == "keras" or startswith("keras.")` | 走导出 API 表，**不看**下面那张四包集合 |
| `get_symbol_from_name(api_name)` | 按 `keras.utils.get_file` 这种公开名取符号 |
| `package in {keras, keras_hub, ...}` | 只约束**第一段包名** |
| `return obj` | 类、函数、随便什么，只要 `vars(mod)` 里有 |

对 seed 这种树外模块，它确实够用：

```text
module="pcb_leak" → package="pcb_leak" 不在集合 → TypeError
load 在 Lambda 构建期失败，前向不跑，/out 没有金丝雀
```

这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险可调用对象都住在 keras 树外（`os`、`subprocess`、攻击者模块）。
2. keras 包内的函数拿去给 Lambda 调是安全的。

第二点不成立。`keras.utils.get_file` 的工作就是按 `origin` 取文件写到 `cache_dir`。

更关键的是：残余甚至不必走下面那个 `package in {...}` 分支。`module="keras.utils"` 命中**上面**那条 API 路径，`get_symbol_from_name("keras.utils.get_file")` 直接返回函数对象。白名单对这条路径是旁路。

---

## 检查之后，谁真正消费那个值

`_retrieve_class_or_fn` 返回的是可调用对象，不是「已经验证过安全的层」。`Lambda.from_config` 把它存进层；一次 `model(zeros)` 就会：

```text
Lambda.call(inputs, **arguments)
    → get_file(tensor, origin="file:///canary/flag.txt",
               cache_dir="/out", cache_subdir="", force_download=True)
```

`get_file` 的 `fname` 在第一参假值时从 `origin` 派生。前向传入的 `zeros` 张量在布尔上下文里假，于是本地 `file://` 被拷进 `/out`。过滤器刚看过的是模块名的第一段；调用看到的是函数和攻击者关键字参数。两套语义中间没有「这个符号是不是加载 API」的第二次谓词。

GHSA 给的截断 `config.json` 用远程 URL 覆盖 `/tmp`；本 case 把 `origin` 换成金丝雀路径，效果通道仍是「函数被调用了」。

---

## 仓库里已经有更强的检查，解析路径没用

同一份 3.9.0 文件里，`safe_mode` 已经拒绝 `__lambda__` 字节码。那是「配置里嵌了 Python 源码」这一层。Lambda 的 `class_name: "function"` 走的是另一条。

3.11.0 才出现的 `LOADING_APIS` 才是对「包内危险函数」的谓词：

```python
# v3.11.0
LOADING_APIS = frozenset({
    "keras.config.enable_unsafe_deserialization",
    "keras.models.load_model",
    "keras.preprocessing.image.load_img",
    "keras.saving.load_model",
    "keras.saving.load_weights",
    "keras.utils.get_file",
    "keras.utils.load_img",
})
```

V1 没有这张表。API 路径在 `get_symbol_from_name` 之前不查函数名。包导入分支对函数和类一视同仁。不是仓库后来没有更好的谓词，是 **3.9.0 没挂**。

即便不用 `get_file`，任何仍在 `keras.*` 导出表里、接受攻击者参数的函数（`load_img`、`load_model`、`enable_unsafe_deserialization`）在 3.9.0 上同样能被 Lambda 解析出来。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs 调用」落到具体代码：

- `_retrieve_class_or_fn` 的 `package in {keras,...}`：看模块第一段是不是批准的包
- 同一函数更早的 `get_symbol_from_name("keras.utils.get_file")`：看导出表里有没有这个名字
- `Lambda.call(..., **arguments)`：看解析出来的对象能不能被调用

seed 走第一条，被挡。residual 走第二条，根本不到第一条：

```text
module="keras.utils", name="get_file"
    → api_name="keras.utils.get_file"
    → get_symbol_from_name 命中
    → return <function get_file>
    → 包白名单未执行
    → Lambda 前向调用，origin/cache_dir 由配置决定
```

V1 拦的是「树外 import」；它假设「keras 树内的符号给 Lambda 用是安全的」。`get_file` 是官方下载/缓存工具，参数完全由配置控制。GHSA 原话：*it will bypass the latest fix since it uses a function from one of the approved modules (`keras`)*.

---

## 残余仍然走同一条 Lambda 调用路径（CVE-2025-8747）

没有换入口、没有关 `safe_mode`、没有换 sink。还是 `POST /load` → `load_model(safe_mode=True)` → Lambda。只是 `function` 从树外模块换成包内函数：

```text
Lambda.function  = {module: "keras.utils", class_name: "function", config: "get_file"}
Lambda.arguments = {origin: "file:///canary/flag.txt", cache_dir: "/out",
                    cache_subdir: "", force_download: True}
```

`_retrieve_class_or_fn` 仍然执行；这次走 keras.* API 分支，返回 `get_file`；前向把它调起来，金丝雀出现在 `/out`。

本 case `verify.sh` 的 residual 与 heldout 同一构造（本地 `file://`，不是远程覆盖）。平台 residual 与源码链是**同一 sink**（Lambda 调用解析出的函数）。认证：v1 + `--residual` 退出码 0。

所以残余不是新洞面，而是同一解析器上三件事叠在一起：白名单只看包名；keras.* 导出路径在白名单之前放行任意符号；Lambda 无条件调用返回值。seed 被挡住只说明「树外模块进不来」，不说明「不能再让 load 去调一个带副作用的官方函数」。

---

## 后来又补了什么（CVE-2025-8747，3.11.0）

PR `#21429` / tag `v3.11.0` 做了两处。keras 3.10.0 的本函数与 3.9.0 字节级相同，所以 3.11.0 才是闭合版本。

第一，API 路径在 `get_symbol_from_name` **之前**查 `LOADING_APIS`：

```python
# v3.11.0 :: _retrieve_class_or_fn
        if module == "keras" or module.startswith("keras."):
            api_name = module + "." + name
            if api_name in LOADING_APIS:
                raise ValueError(
                    f"Cannot deserialize `{api_name}`, loading functions are "
                    "not allowed during deserialization"
                )
            obj = api_export.get_symbol_from_name(api_name)
```

第二，包导入分支只返回 `KerasSaveable` 子类，函数不再放行。

对残余输入：`api_name="keras.utils.get_file"` 命中 `LOADING_APIS`，load 抛 `ValueError`，前向不跑。树外 seed 仍被包白名单挡住。公开建议是升级到 3.11.0+。

即便如此，这仍然是「再列一张危险函数名」。不在 `LOADING_APIS` 里、又不是 `KerasSaveable`、却仍能从 `keras.*` 导出表拿到的可调用对象，需要另证。本 benchmark 的 v2 只关闭 `get_file` 这条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是 import 前的包名。真正产生效果的是 Lambda 调用解析结果。V2 仍在解析器里加码（函数黑名单 + 只允许 Saveable 类），没有禁止 Lambda 在 safe_mode 下解析任意 `function` 节点。

**不是没有更好的谓词。**  
`safe_mode` 已经知道 `__lambda__` 危险。3.11.0 的 `LOADING_APIS` 更接近「加载 API 不能当 gadget」。它在 3.9.0 不存在。从 V1 的 diff 只能看到四包集合；要判断闭合，必须看到上面那条 `get_symbol_from_name` 提前返回。

**同一函数、同一 Lambda，只换了 module/name。**  
任何 `class_name: "function"` 的配置在 3.9.0 上都吃同一套解析。advisory 的 PoC 就是 `keras.utils.get_file`。

**白名单「属于 keras」不等于「可以调用」。**  
包名回答的是「从哪 import」；安全问题是「调了会干什么」。`get_file` 的副作用就是它的功能。

**金丝雀在模型目录外是有意的。**  
`/canary/flag.txt` 不在 `.keras` 档案里。能出现在 `/out`，说明官方函数带着攻击者参数真的跑了。

---

## 版本、入口、参考

| | 版本 | `_retrieve_class_or_fn` | 树外 seed | `keras.utils.get_file` residual |
|---|---|---|---|---|
| V0 | 3.8.0 | 任意 `import_module` | 调用，读到金丝雀 | （不必） |
| V1 | 3.9.0 | 四包白名单；keras.* API 仍直通 | TypeError，挡 | `get_symbol_from_name` 命中，读到金丝雀 |
| V2 | 3.11.0 | `LOADING_APIS` + 只返回 KerasSaveable | 挡 | ValueError，挡 |

- Web：`POST /load`（application/json，真实 `load_model(safe_mode=True)`）
- 认证：v0 seed 观察到 flag；v1 seed 未观察到；v1 residual 观察到
- [CVE-2025-1550](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)、[CVE-2025-8747](https://nvd.nist.gov/vuln/detail/CVE-2025-8747)
- [GHSA-c9rc-mg46-23w3](https://github.com/keras-team/keras/security/advisories/GHSA-c9rc-mg46-23w3)
- V1 源码：[serialization_lib.py @ v3.9.0](https://github.com/keras-team/keras/blob/v3.9.0/keras/src/saving/serialization_lib.py)
- PR：`keras-team/keras#20751`（V1）、`#21429`（V2）；V1 commit `bb340d6`
