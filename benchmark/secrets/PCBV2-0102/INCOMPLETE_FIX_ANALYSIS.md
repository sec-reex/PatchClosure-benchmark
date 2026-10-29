# Yii2 Behavior 类型检查：看的是 class，createObject 用的是 __class

- Case：`PCBV2-0102`（`deser_yii2_behavior_typecheck`）
- 产品：Yii 2（`yiisoft/yii2`）。`Component::__set` 把 `as <name>` 配置交给 `Yii::createObject` 去挂 Behavior。
- 链：CVE-2024-4990（2.0.49 → 2.0.50）→ CVE-2024-58136（2.0.50 → 2.0.52，GHSA-ggwg-cmwp-46r5，CISA KEV）
- 源码对着 GitHub tag `2.0.50` / `2.0.52` 的 `framework/base/Component.php`（`__set`）和 `framework/BaseYii.php`（`createObject`）。运行时装的是 Packagist 整包。

2024 年 5 月，Yii 2.0.50 给 `as <name>` 加了类型门：数组必须 `isset($value['class']) && is_subclass_of($value['class'], Behavior::class)`，否则抛 `InvalidConfigException`。这挡住了直接 `{class: 任意类}`。NVD CVE-2024-58136 写明：*Yii 2 before 2.0.52 mishandles the attaching of behavior that is defined by an `__class` array key, a CVE-2024-4990 regression, as exploited in the wild in February through April 2025.* Rapid7：2.0.50 的检查只读 `class`，而 `createObject` **先看 `__class`**。

根因不只是「少检查一个键」。检查插在「配置数组里那个叫 class 的键像不像 Behavior」这一层；真正 `new` 的是 `createObject` 按 `__class` 解析出的名字。`createObject` 从 2.0.49 到 2.0.52 字节级相同。下面按 POST /trigger 走进去、2.0.50 改了哪几行、检查通过之后谁实例化、更早读 `__class` 的谓词有没有挂上，把这几层写完。

---

## 这块功能本来在干什么

Yii 组件用魔术 `__set` 支持配置数组。键名 `as foo` 表示挂一个名叫 foo 的 Behavior。文档示例：

```php
'as tree' => [
    'class' => 'yii\behaviors\... ',
    ...
]
```

`Yii::configure` / Gii / 部分 REST 配置会把用户数组 foreach 赋到 Component 上，于是走到 `__set('as ...', $value)`。

本 case 是真实 `yii\web\Application`，`POST /trigger` JSON body 被 `TriggerController` mass-assign 到一个普通 Component：

```php
foreach ($body as $k => $v) { $c->$k = $v; }
```

设计意图：`as` 的值必须是 Behavior 实例、Behavior 类名、或「class 指向 Behavior 子类」的配置数组。成功穿越之后的效果是：**非 Behavior 类被 `createObject` 实例化，构造函数跑起来**。本 case 用良性 `app\PcbFlagProbe`：构造函数读 `/canary/flag.txt`，token 进 HTTP body。构造发生在后续 `attachBehaviorInternal` 报「Unsupported configuration type: object」之前，所以响应里能先看到泄漏。

数据流：

```text
HTTP POST /trigger  JSON
    → $c->{'as pcb'} = $value
         Component::__set
              V1：is_subclass_of($value['class'], Behavior::class)  ← 补丁插在这里
              Yii::createObject($value)
                   if isset __class → 用 __class     ← 真正选类，V1 没改
                   elseif isset class → 用 class
                   container->get($class)
    → PcbFlagProbe::__construct → body PCB_LEAKED
```

没有登录（本 harness 的 trigger 路由）。真实应用取决于谁能 mass-assign。

---

## 原始漏洞：as 配置直接 createObject（CVE-2024-4990，2.0.49）

2.0.49 的 `__set` 对 `as ` 前缀：

```php
            $this->attachBehavior($name, $value instanceof Behavior ? $value : Yii::createObject($value));
```

数组直接进 `createObject`。`{class: app\PcbFlagProbe}` 就会 `new PcbFlagProbe`。CVE-2024-4990 修的就是这个不安全反射。

本 case seed：

```json
{"as pcb": {"class": "app\\PcbFlagProbe"}}
```

2.0.49 上构造函数跑，body 含 `PCB_LEAKED` + flag。这就是 v0 + `--seed` 退出码 0。

---

## 维护者改了什么（CVE-2024-4990 修复，2.0.50）

tag `2.0.50` 的 `__set` 把三元运算换成显式分支。GitHub blob：

```php
# framework/base/Component.php :: __set  (2.0.50, 约 L156–167)
        } elseif (strncmp($name, 'as ', 3) === 0) {
            $name = trim(substr($name, 3));
            if ($value instanceof Behavior) {
                $this->attachBehavior($name, $value);
            } elseif (isset($value['class']) && is_subclass_of($value['class'], Behavior::class, true)) {
                $this->attachBehavior($name, Yii::createObject($value));
            } elseif (is_string($value) && is_subclass_of($value, Behavior::class, true)) {
                $this->attachBehavior($name, Yii::createObject($value));
            } else {
                throw new InvalidConfigException('Class is not of type ' . Behavior::class . ' or its subclasses');
            }
            return;
        }
```

字面意思：

| 片段 | 含义 |
|---|---|
| `isset($value['class'])` | 只承认 `class` 这个键存在 |
| `is_subclass_of($value['class'], Behavior::class, true)` | **检查**用这个键 |
| `Yii::createObject($value)` | **整份数组**交给工厂，含其它键 |

`createObject`（`BaseYii.php`，2.0.50，与 2.0.49/2.0.52 相同）的优先级是：

```php
# framework/BaseYii.php :: createObject
        if (isset($type['__class'])) {
            $class = $type['__class'];
            unset($type['__class'], $type['class']);
            return static::$container->get($class, $params, $type);
        }
        if (isset($type['class'])) {
            $class = $type['class'];
            unset($type['class']);
            return static::$container->get($class, $params, $type);
        }
```

对 seed 这种只有 `class => PcbFlagProbe` 的数组，它确实够用：`is_subclass_of(PcbFlagProbe, Behavior)` 为假，抛 InvalidConfigException，无 flag。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 要实例化的类名就是 `$value['class']`。
2. 通过类型检查之后，把同一份数组交给 `createObject` 是安全的。

第二点不成立：工厂先看 `__class`，并在选中后把 `class` 键删掉。检查过的那个名字根本不会被实例化。

---

## 检查之后，谁真正消费那个值

`is_subclass_of` 通过后，`createObject($value)` 拿到**同一个**数组。若同时有 `class` 和 `__class`：

```text
检查：  class = app\PcbLegitBehavior   → 是 Behavior → 通过
工厂：  __class = app\PcbFlagProbe     → new PcbFlagProbe
        unset(__class, class)          → Behavior 那个名字被扔掉
```

`attachBehaviorInternal` 稍后发现拿到的不是 Behavior 配置，可能再抛错；但构造函数已经跑过，金丝雀已经进响应。Rapid7 的野生利用用 `GuzzleHttp\Psr7\FnStream` + `__construct()` + `_fn_close`，同一套键分裂。

过滤器刚看过的是 `class` 字符串；`container->get` 看到的是 `__class` 字符串。两套键中间没有第二次 `is_subclass_of`。

---

## 仓库里已经有更强的检查，2.0.50 没用

`createObject` 自己已经规定 `__class` 优先于 `class`。类型门只要先读同一个键，就能和工厂对齐。2.0.50 选择只读 `class`。

2.0.52 / commit `40fe496` / PR `#20232`：

```php
# 2.0.52 :: __set
            } elseif (isset($value['__class']) && is_subclass_of($value['__class'], Behavior::class)) {
                $this->attachBehavior($name, Yii::createObject($value));
            } elseif (!isset($value['__class']) && isset($value['class']) && is_subclass_of($value['class'], Behavior::class)) {
                $this->attachBehavior($name, Yii::createObject($value));
```

`__class` 存在时**只**检查 `__class`；不再允许「class 是 Behavior、__class 是别的」。这就是工厂已经在用的谓词。V1 没有这段。`attachBehaviorInternal` 和 `createObject` 三标签字节级相同——整条修复都在 `__set`。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs 工厂」落到具体代码：

- `__set`：看 `$value['class']` 是不是 Behavior
- `createObject`：看 `$value['__class']`，没有才看 `class`

seed：

```text
{class: PcbFlagProbe}
    isset class → 是；is_subclass_of → 否 → throw → 挡
```

residual：

```text
{class: PcbLegitBehavior, __class: PcbFlagProbe}
    isset class → 是；is_subclass_of(PcbLegitBehavior) → 是
    createObject → new PcbFlagProbe → 金丝雀
```

V1 拦的是「class 键直接指向危险类」；它假设「class 就是将要 new 的那个名字」。Yii 配置方言里 `__class` 才是第一公民。NVD 把这叫做 CVE-2024-4990 regression。

---

## 残余仍然走同一条 as 挂载路径（CVE-2024-58136）

没有换 `__set`、没有换 `createObject`、没有换 POST /trigger。还是 mass-assign `as pcb`。只是数组多了一个合法 Behavior 的 `class`，真正的类放进 `__class`：

```json
{"as pcb": {"class": "app\\PcbLegitBehavior", "__class": "app\\PcbFlagProbe"}}
```

`__set` 仍然跑 V1 那一行 `is_subclass_of($value['class']...)`；通过；`createObject` 仍先读 `__class`；构造函数读金丝雀。

本 case `verify.sh` residual 与 heldout 同一 JSON。平台 residual 与源码链是**同一 sink**。认证：v1 + `--residual` 退出码 0。CISA KEV：2025 年 2–4 月野外利用（CraftCMS 等把 Yii 当依赖）。

所以残余不是新洞面，而是同一类型门上三件事叠在一起：检查读 class；工厂读 __class；通过后把未再验证的数组交给工厂。seed 被挡住只说明「单键 class 不行了」，不说明「不能再实例化任意类」。

---

## 后来又补了什么（CVE-2024-58136，2.0.52）

`__set` 改成 `__class` 优先，且 `__class` 存在时不再用 `class` 去过门。2.0.51 仍不够，必须 2.0.52。厂商：[Please upgrade to Yii 2.0.52](https://www.yiiframework.com/news/709/please-upgrade-to-yii-2-0-52)。

对残余输入：`is_subclass_of(PcbFlagProbe, Behavior)` 为假，抛 InvalidConfigException，无 flag。seed 仍被挡。Rapid7 的 FnStream payload 同样在这一层被拒。

即便如此，这仍然是「检查的键要和工厂的键一致」。`createObject` 自己始终不限制目标必须是 Behavior——限制只在 `__set` 的 as 分支。其它调用 `createObject` 的入口需要另证。本 benchmark 的 v2 只关闭这条 as/__class residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是 `__set` 里对 `class` 键的类型判断。真正选类的是 `createObject` 的 `__class` 优先。V2 仍在 `__set` 加码，但把键对齐到工厂。

**不是没有更好的谓词。**  
`createObject` 源码里 `__class` 就在 `class` 上面十几行。类型门只要抄那两行的顺序。从 V1 的 diff 只能看到加了 `is_subclass_of($value['class'])`；要判断闭合，必须打开 `BaseYii::createObject`。

**同一 __set、同一数组，只是多写了一个键。**  
任何 mass-assign `as ...` 在 2.0.50 上都吃这个分裂。Rapid7 PoC 就是这个形状。

**检查过的字段和将要使用的字段必须是同一个。**  
「配置数组通过了类型门」不等于「即将 new 的类通过了类型门」。

**金丝雀不在 JSON 里是有意的。**  
body 只有类名。响应出现 token，说明构造函数在服务端跑了。

---

## 版本、入口、参考

| | yii2 | `__set` as 分支 | 直接 class seed | class+__class residual |
|---|---|---|---|---|
| V0 | 2.0.49 | 无类型门，直接 createObject | 读到金丝雀 | （不必） |
| V1 | 2.0.50 | 检查 `class` 是否 Behavior | throw，挡 | 检查过、工厂 new __class，读到金丝雀 |
| V2 | 2.0.52 | 先检查 `__class` | 挡 | throw，挡 |

- Web：`POST /trigger`（JSON mass-assign 到 Component）
- 认证：v0 seed 观察到 flag；v1 seed 未观察到；v1 residual 观察到
- [CVE-2024-4990](https://nvd.nist.gov/vuln/detail/CVE-2024-4990)、[CVE-2024-58136](https://nvd.nist.gov/vuln/detail/CVE-2024-58136)
- [GHSA-ggwg-cmwp-46r5](https://github.com/advisories/GHSA-ggwg-cmwp-46r5)
- [Rapid7 分析](https://www.rapid7.com/blog/post/ra-cve-2024-58136-analysis/)
- V1 源码：[Component.php @ 2.0.50](https://github.com/yiisoft/yii2/blob/2.0.50/framework/base/Component.php)、[BaseYii.php @ 2.0.50](https://github.com/yiisoft/yii2/blob/2.0.50/framework/BaseYii.php)
- V2 commit `40fe496` / PR `#20232`
