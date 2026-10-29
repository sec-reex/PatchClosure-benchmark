# PyYAML：FullConstructor 只拒绝函数 apply，类仍然会构造

- Case：`PCBV2-0180`
- 产品：PyYAML（Python YAML 库）。运行时是 PyPI 整包 `pyyaml==3.13` / `5.1` / `5.2`，经 `yaml.load(..., Loader=...)` 消费文档，不是抽出来的 constructor。
- 链：CVE-2017-18342（&lt;5.1 → 5.1，引入 `FullLoader`）→ CVE-2019-20477（5.1 → 5.2，PR #347）
- 源码对着 tag `5.1` 的 `lib3/yaml/constructor.py`（`FullConstructor.make_python_instance` / `construct_python_object_apply` / `add_multi_constructor`）。金丝雀是 `/canary/flag.txt` 上的 `PCBFLAG_...`：payload 只**读**这个文件，不 `os.system`。

NVD CVE-2019-20477 的原话：*PyYAML 5.1 through 5.1.2 has insufficient restrictions on the load and load_all functions because of a class deserialization issue, e.g., Popen is a class in the subprocess module. NOTE: this issue exists because of an incomplete fix for CVE-2017-18342.*

根因不只是「忘了禁 Popen」。检查插在「`python/object/apply` 的目标是不是 `type`」上；真正执行的是后面的 `cls(*args, **kwds)`。`SafeConstructor` 根本不注册这个 tag，但 `FullLoader` 把 FullConstructor 当成「比 Unsafe 安全」的默认推荐，却把 apply 整条 multi-constructor 留着。下面按 `yaml.load` 走进去。

---

## 这块功能本来在干什么

很多应用用 `yaml.load` 读配置或 POST 过来的文档。5.1 之前默认 `yaml.Loader` 等于后来的 Unsafe：任意 `!!python/object/apply:os.system` 都会跑。5.1 把 `load()` 标成 deprecated，推荐 `FullLoader`，并引入 `UnsafeLoader` 给需要旧行为的人。

一次典型调用：

```python
yaml.load(document, Loader=yaml.FullLoader)
```

短格式 apply：

```yaml
!!python/object/apply:builtins.eval
- "open('/canary/flag.txt').read()"
```

解析器按 tag 前缀找 `yaml_multi_constructors`，落到 `construct_python_object_apply`，再进 `make_python_instance`。

设计意图（5.1 文档 / changelog）：FullLoader 可以还原 Python 类型，但不应再把**函数**当构造器调用。成功穿越之后的效果是：**任意 class 被实例化，副作用发生在构造函数里**（本 case 用 `io.FileIO` 读金丝雀，再包进 `list`，`repr` 反射到 HTTP 响应）。

数据流：

```text
YAML 文档
    → yaml.load(..., Loader=FullLoader)
         FullConstructor 匹配 tag:yaml.org,2002:python/object/apply:
         construct_python_object_apply
              抽出 args / kwds
              make_python_instance(suffix, node, args, kwds)
                   find_python_name(suffix)     ← 任意可 import 的名字
                   isinstance(cls, type)?      ← V1 唯一闸门
                   return cls(*args, **kwds)   ← 真正的调用
    → 返回 Python 对象（副作用已发生）
```

不需要鉴权。谁能把 YAML 喂给 `load`，谁就能驱动这条链。`yaml.safe_load` / `SafeLoader` 不注册 apply，不在这条 incomplete-fix 链上。

---

## 原始漏洞：函数也能 apply（CVE-2017-18342，3.13）

3.13 没有 `FullConstructor`。默认 `Loader` 的 `make_python_instance` 不要求目标是 class。`!!python/object/apply:builtins.eval` 或 `os.system` 直接执行。

NVD CVE-2017-18342：*In PyYAML before 5.1, the yaml.load() API could execute arbitrary code if used with untrusted data.* 5.1 把 `load` 标 deprecated，并引入 UnsafeLoader。

本 case seed：

```yaml
!!python/object/apply:builtins.eval
- "open('/canary/flag.txt').read()"
```

`eval` 是 builtin function，不是 class。3.13 上它被调用，返回文件内容，响应里出现 `PCBFLAG_...`。

---

## 维护者改了什么（CVE-2017-18342 修复，5.1）

5.1 增加 `FullConstructor`，在 `make_python_instance` 里加了一道类型门：

```python
# lib3/yaml/constructor.py :: FullConstructor.make_python_instance  (tag 5.1)
    def make_python_instance(self, suffix, node,
            args=None, kwds=None, newobj=False, unsafe=False):
        if not args:
            args = []
        if not kwds:
            kwds = {}
        cls = self.find_python_name(suffix, node.start_mark)
        if not (unsafe or isinstance(cls, type)):
            raise ConstructorError("while constructing a Python instance", node.start_mark,
                    "expected a class, but found %r" % type(cls),
                    node.start_mark)
        if newobj and isinstance(cls, type):
            return cls.__new__(cls, *args, **kwds)
        else:
            return cls(*args, **kwds)
```

`unsafe=False` 是 FullConstructor 的默认。函数、方法的 `isinstance(..., type)` 为假，抛 `expected a class, but found builtin_function_or_method`。seed 在 5.1 上被挡住。这就是 v1 + `--seed` 退出码 10。

同一文件仍然注册：

```python
FullConstructor.add_multi_constructor(
    'tag:yaml.org,2002:python/object/apply:',
    FullConstructor.construct_python_object_apply)
```

`construct_python_object_apply` 在通过那道门之后，无条件 `cls(*args, **kwds)`。没有类名白名单，没有禁止带副作用的 `__init__`。

补丁默认了两件事：

1. 危险的 apply 目标长得像函数（`eval` / `os.system` / `subprocess.call`）。
2. 目标是 `type` 就安全，因为「构造一个对象」不像「调用一个函数」。

第二点不成立：`subprocess.Popen`、`io.FileIO`、`os.fdopen` 都是 class，构造即带副作用。

---

## 检查之后，谁消费这个值

`make_python_instance` 的返回值就是 apply 节点的构造结果。调用方 `construct_python_object_apply` 还可能 `extend` / `update` 实例，但 RCE/读文件发生在 `cls(*args)` 那一行，不发生在检查里。

`find_python_name` 按 `module.attr` 做 import，FullConstructor 允许的模块范围很宽（不是 SafeConstructor 那套白名单）。谓词只问 `isinstance(cls, type)`，不问 `cls` 是不是 `int`/`str`/`datetime` 这种无副作用类型。

检查通过后没有任何第二次闸门。`FullLoader` 的公开语义是「完整 Python 对象还原」，不是「无代码执行」。5.1 把这条 API 标成 `load()` 的替代，等于把「任意 class 构造」交给了以为自己离开 Unsafe 的调用方。

`find_python_name` 在 Full 上可 `import` 的模块没有 Safe 那种白名单。`io.FileIO`、`subprocess.Popen`、`os.fdopen` 都只是「一个 type + 攻击者给的 args」。谓词在 `cls` 已经解析完之后才问 `isinstance`，问的是元类关系，不是「这个构造会不会碰文件系统」。

---

## 仓库里已经有更强的检查，FullLoader 没用

同一份 `constructor.py` 里，`SafeConstructor` **从不**注册 `python/object/apply`。`yaml.safe_load` 遇到这个 tag 会报 *could not determine a constructor*。这才是「不允许任意 Python 构造」的谓词。

| Loader | 注册 `python/object/apply`？ | `make_python_instance` 的门 |
|---|---|---|
| SafeLoader / SafeConstructor | 否 | 用不上 |
| FullLoader / FullConstructor（5.1） | **是** | 必须是 `type` |
| UnsafeLoader / UnsafeConstructor | 是 | `unsafe=True`，函数也行 |

V1 等于在 Full 这条「推荐替代 load()」的路径上，加了一道比 Safe 弱、比 Unsafe 强的门：挡住函数，放行任意类。不是仓库里没有更强的默认（SafeLoader 就在旁边），是 **FullLoader 被当成安全默认却仍挂着 apply**。

5.1 的 `UnsafeConstructor.make_python_instance` 只是把 `unsafe=True` 传给父类——函数 apply 被明确留给 Unsafe。残留的问题是 apply **tag 还在 Full 上**。

---

## 这个补丁挡住了什么、没挡住什么

- `isinstance(cls, type)`：看 apply 目标是不是类对象
- `cls(*args, **kwds)`：看这个类的构造函数做什么

只要目标是 class，第一行放行，第二行照跑。NVD 举的例子是 `subprocess.Popen`。本 case 残余不 spawn 进程，用两个 class 把文件读进 `repr`：

```yaml
!!python/object/apply:builtins.list
- !!python/object/apply:io.FileIO
  - /canary/flag.txt
  - r
```

`io.FileIO` 是 class → 打开 `/canary/flag.txt`。`list` 是 class → 把文件对象当 iterable 读成 `[b'PCBFLAG_...\n']`。没有函数 apply，V1 那道门两处都过。

`!!python/object/new:` 在 5.1 的 FullConstructor 上同样注册，走 `__new__`。残余不必用它。

---

## 残余仍然走 FullLoader 的 apply（CVE-2019-20477）

没有换 API、没有换 Loader。还是：

```python
yaml.load(document, Loader=yaml.FullLoader)
```

只是把 suffix 从 `builtins.eval` 换成 `io.FileIO` / `builtins.list`。`construct_python_object_apply` 照样执行；`make_python_instance` 看到 `type` 就 `cls(*args)`；金丝雀出现在对象的 `repr` 里。

平台残余和 NVD 是同一 sink：`FullConstructor` 上仍然注册的 `python/object/apply`。Exploit-DB 47655 / 公开讨论用 `Popen`；本 case 用 `FileIO` 只读金丝雀，语义相同（任意 class 构造）。

`make_python_instance` 在 `unsafe=False` 时唯一的 `raise` 就是那句 expected a class。没有 `cls.__module__ in ALLOWED`，没有禁止 `io` / `subprocess` / `os`。5.1 changelog 把 FullLoader 描述成 load 的安全一些的替代，调用方若据此从 `yaml.load(doc)` 改成 `yaml.load(doc, Loader=FullLoader)`，函数 RCE 没了，class 构造还在。

对 seed `builtins.eval`：`type(eval)` 是 `builtin_function_or_method`，门关上。对残余 `io.FileIO`：`type(FileIO)` 是 `type`，门打开，`FileIO('/canary/flag.txt', 'r')` 立刻读盘。两份文档都带 `tag:yaml.org,2002:python/object/apply:`，差别只在 suffix 解析出来的对象是不是 class。

`FullLoader` 在 5.1 的 `yaml/__init__.py` 里绑的是 `FullConstructor`。应用代码写 `Loader=yaml.FullLoader` 就吃到 apply 注册。`safe_load` 不在这条链上，也不该被当成 V1 的修复。

5.1 同时引入 `UnsafeLoader`，把旧 `Loader` 的函数 apply 明确标成 unsafe。Full 却仍注册同一 tag。产品叙事是「三条 Loader 分档」； incomplete-fix 出在中档仍能 `cls(*args)`。

---

## 后来又补了什么（CVE-2019-20477，5.2）

PR #347 / PyYAML 5.2 把 apply 从 FullConstructor **挪到** UnsafeConstructor：

```python
# lib3/yaml/constructor.py  (tag 5.2)
FullConstructor.add_multi_constructor(
    'tag:yaml.org,2002:python/object/new:',
    FullConstructor.construct_python_object_new)

class UnsafeConstructor(FullConstructor):
    ...

UnsafeConstructor.add_multi_constructor(
    'tag:yaml.org,2002:python/object/apply:',
    UnsafeConstructor.construct_python_object_apply)
```

5.2 的 FullLoader 遇到残余文档：*could not determine a constructor for the tag 'tag:yaml.org,2002:python/object/apply:io.FileIO'*。公开建议升到 5.2；`safe_load` 仍然是处理不可信输入的正确默认。

即便如此，Full 上还留着 `python/object:` 和 `python/object/new:`。本 benchmark 的 v2 只关闭 apply 这条 reference residual。`new` 是否仍能构造带副作用的类，需要另证。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是「目标是不是 class」。真正产生副作用的是 `cls(*args)`。V2 把 tag 从 Full 上摘掉，等于承认 Full 不该提供任意 apply，而不是把 class 再分一遍白名单。

**不是没有更好的谓词。**  
SafeConstructor 从不注册 apply。5.1 若把 Full 的 apply 也拿掉（或只允许无参、无副作用的内置不可变类型），CVE-2019-20477 不会以「incomplete fix」的形式出现。从 5.1 的 diff 只能看到「expected a class」；要判断是否闭合，必须看到 `add_multi_constructor` 仍把 apply 挂在 Full 上，以及 `return cls(*args)` 没有白名单。

**同一 tag、同一 `make_python_instance`，只换了 suffix 的种类。**  
任何 `!!python/object/apply:module.Class` 在 5.1 的 FullLoader 上都吃这道门。

**「推荐替代 load()」比「Unsafe」更容易被当成安全默认。**  
调用方从 3.13 迁到 `FullLoader` 是为了修 18342。残留把「函数 RCE」收成「类 RCE」，表面上 seed 死了。

**金丝雀在应用目录外是有意的。**  
`/canary/flag.txt` 不在 YAML 文档里。能读到它，说明构造函数真的打开了任意路径，不是 harness 把 flag 写进了返回值。

**`python/object/new:` 在 5.1 的 Full 上同样活着。**  
它走 `cls.__new__(cls, *args)`。残余不必用它；5.2 只把 apply 挪到 Unsafe，`new` 仍注册在 Full。本 benchmark 不把 `new` 当 reference residual。

**短格式和长格式走同一道门。**  
`!!python/object/apply:io.FileIO [path, r]` 与带 `args:` 映射的写法都进 `construct_python_object_apply`，最后都是 `make_python_instance`。换 YAML 形状绕不开 `isinstance(cls, type)`。

---

## 版本、入口、参考

| | 版本 | Loader | apply 注册在 | 函数 apply seed | class apply residual |
|---|---|---|---|---|---|
| V0 | 3.13 | `yaml.Loader`（Unsafe） | Constructor | eval 读到金丝雀 | （不必） |
| V1 | 5.1 | `yaml.FullLoader` | **FullConstructor** | `expected a class` | FileIO/list 读到金丝雀 |
| V2 | 5.2 | `yaml.FullLoader` | 仅 UnsafeConstructor | 挡 | 无 constructor，挡 |

- 包 API：`yaml.load(doc, Loader=yaml.FullLoader)`（V0 为默认 `yaml.Loader`）
- [CVE-2017-18342](https://nvd.nist.gov/vuln/detail/CVE-2017-18342)、[PyYAML #193](https://github.com/yaml/pyyaml/issues/193)、[PR #74](https://github.com/yaml/pyyaml/pull/74)
- [CVE-2019-20477](https://nvd.nist.gov/vuln/detail/CVE-2019-20477)、[CHANGES](https://github.com/yaml/pyyaml/blob/master/CHANGES)、[PR #347](https://github.com/yaml/pyyaml/pull/347)
- V1 blob：[`lib3/yaml/constructor.py@5.1`](https://github.com/yaml/pyyaml/blob/5.1/lib3/yaml/constructor.py)
- V2：[`constructor.py@5.2`](https://github.com/yaml/pyyaml/blob/5.2/lib3/yaml/constructor.py)（apply 仅 `UnsafeConstructor.add_multi_constructor`）
