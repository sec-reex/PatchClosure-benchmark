# n8n XML 节点：禁名单查的是拷贝，parser 用的是原值

- Case：`PCBV2-0020`
- 产品：n8n（工作流自动化，官方镜像 `n8nio/n8n`）
- 链：CVE-2026-42232（2.17.3 → 2.20.6）→ CVE-2026-44791（2.20.6 → 2.20.7 / GHSA-wrwr-h859-xh2r）
- 源码对着官方 tag `n8n@2.20.6` 的 `packages/nodes-base/nodes/Xml/Xml.node.ts :: execute`。运行时是整包 n8n 进程 + 真实 XML 节点 + xml2js 0.6.2，不是抽出来的 `sanitizeXmlName`。

2026 年 2.17.4 / 2.x 给 XML 节点加了 `sanitizeXmlName` 处理器，并在 `execute` 里用 `forbiddenKeys.includes(String(options.attrkey ?? ''))` 拒绝 `__proto__`。advisory 随后指出：校验读的是 **`String(...)` 得到的拷贝**，`Object.assign(..., options, ...)` 仍把**原始** `options.attrkey` 交给 `new Parser(...)`。一个 `toString()` 第一次返回 `'safe'`、之后返回 `'__proto__'` 的对象能过禁名单，然后在 xml2js 里被再次强制成字符串，写成 `Object.prototype`。NVD 把这件事记成 CVE-2026-44791，并写明 bypass of the patch for CVE-2026-42232。

根因不是「禁名单漏了某个拼写」。`forbiddenKeys` 已经包含 `__proto__` / `constructor` / `prototype`；`sanitizeXmlName` 已经改写危险**标签名**。检查插在局部变量 `attrkey` 上；真正当对象键用的是 parser 选项里那份未经稳定化的值。下面按工作流走进去、补丁改了哪两行、消毒后谁还在 `obj[attrkey] = {}`、为什么不把 `options.attrkey = String(...)` 写回去，把这三层写完。

---

## 这块功能本来在干什么

n8n 的 XML 节点把一段 XML 转成 JSON（`xmlToJson`）。用户可配置 Attribute Key（`attrkey`，默认 `$`）：xml2js 用这个字符串作为「属性对象」在结果里的键。工作流作者通过节点参数、或表达式 `={{ $json.evil }}` 提供该值。表达式在宿主进程里求值，得到的可以是任意 JS 对象，不一定是字符串。

一次典型执行：Webhook 收到 XML → XML 节点 `parseStringPromise` → 后续 HTTP 节点用 `$json.某个键` 发 sidecar。本 case 的 flag 只存在于 sidecar 的 `/ingest?seed=` / `/ingest?res=` 记录里；能打到 sidecar 说明原型污染已经让后续节点从 `Object.prototype` 上读到了攻击者写入的属性。

数据流：

```text
Webhook / Function 节点输出
    → Xml.execute
         options = getNodeParameter('options')     ← 仍可能是对象
         V1：const attrkey = String(options.attrkey ?? '')
             forbiddenKeys.includes(attrkey)        ← 只看拷贝
         parserOptions = Object.assign({mergeAttrs, explicitArray}, options, {processors})
              ← options.attrkey 原值进入 Parser
         new Parser(parserOptions).parseStringPromise(xml)
              xml2js: obj[attrkey] = {}; defineProperty(obj[attrkey], attrName, value)
    → deepCopy(json) → 后续节点
```

---

## 原始漏洞：标签名直接当键（CVE-2026-42232，2.17.3）

2.17.3 没有 `sanitizeXmlName`，也没有 `forbiddenKeys`。XML `<__proto__><pcb_seed_flag>FLAG</pcb_seed_flag></__proto__>` 被 xml2js 解析成普通对象之后，n8n-workflow 的 `deepCopy` 在复制带 `__proto__` 的结构时走到危险键，污染后续数据。seed 工作流：Webhook → XML（默认选项）→ HTTP GET sidecar，`url` 表达式读 `$json.pcb_seed_flag`。2.17.3 上 sidecar 记录 `seed=PCBFLAG_...`。

认证用户需要能创建工作流（advisory 前置）。本 case 用 owner 登录后 `POST /rest/workflows`。

---

## 维护者改了什么（CVE-2026-42232 修复，2.20.6）

2.17.4 起，`packages/workflow/src/utils.ts` 增加：

```ts
const DANGEROUS_XML_NAMES = new Set(['__proto__', 'constructor', 'prototype']);
export function sanitizeXmlName(name: string) {
  if (DANGEROUS_XML_NAMES.has(name)) return `sanitized_${name}`;
  return name;
}
```

XML 节点把它们挂到 parser 的 `tagNameProcessors` / `attrNameProcessors`。2.x 另外在 `execute` 开头校验 attrkey/charkey。**2.20.6 的原文**是：

```ts
# packages/nodes-base/nodes/Xml/Xml.node.ts :: execute  (n8n@2.20.6)
		const options = this.getNodeParameter('options', 0, {});

		const forbiddenKeys = ['__proto__', 'constructor', 'prototype'];
		const attrkey = String(options.attrkey ?? '');
		const charkey = String(options.charkey ?? '');
		if (forbiddenKeys.includes(attrkey)) {
			throw new NodeOperationError(
				this.getNode(),
				`The "Attribute Key" option value "${attrkey}" is not allowed`,
			);
		}
		if (forbiddenKeys.includes(charkey)) { ... }

		const parserOptions = Object.assign(
			{ mergeAttrs: true, explicitArray: false },
			options,
			{ tagNameProcessors: [sanitizeXmlName], attrNameProcessors: [sanitizeXmlName] },
		);
		const parser = new Parser(parserOptions);
```

`String(options.attrkey ?? '')` 会立刻调用一次 `toString`（或 valueOf 链）。禁名单看的是这次调用的结果。`options` 本身**没有被赋值回去**。随后 `Object.assign` 把仍是对象的 `attrkey` 拷进 `parserOptions`。

对 seed 这种字面标签 `<__proto__>`，`sanitizeXmlName` 把它改成 `sanitized___proto__`，`deepCopy` 不再沿原型链污染，sidecar 收不到 `seed=FLAG`。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险名字只出现在 XML **标签/属性名**里（processors 管得住）。
2. 校验 `String(x)` 等价于 parser 稍后再次把 `x` 当键用——即 `x` 是稳定字符串。

第二点不成立。更关键的是：校验之后代码仍然把原始 `options` spread 进 Parser，而 Parser **不再做** `forbiddenKeys` 检查。

---

## 消毒之后，键怎么接到 defineProperty 上

xml2js 0.6.2 在处理属性时（`mergeAttrs` 为 false 时尤其清楚）会：

```js
if (!(attrkey in obj) && !mergeAttrs) obj[attrkey] = {};
defineProperty(obj[attrkey], processedKey, newValue);
```

`attrkey in obj` 和 `obj[attrkey]` 都会把非字符串键 ToString。若此时 `toString()` 返回 `'__proto__'`：

- `'__proto__' in obj` 为 true（继承自 Object.prototype）时，有的分支会跳过「新建 {}」；
- 本 case residual 显式设 `mergeAttrs: False`，走 `obj[attrkey] = {}` 仍可能被解释成给 `obj['__proto__']` 赋值；
- `defineProperty(obj[attrkey], name, value)` 在 `obj[attrkey] === Object.prototype` 时，等于在**全局原型**上定义 `pcb_res_flag`。

V1 的 `sanitizeXmlName` 只改 **XML 里的名字**（标签、属性名），不改 parser 选项里的 `attrkey`。属性名 `pcb_res_flag` 不在 `DANGEROUS_XML_NAMES` 里，会原样成为 `Object.prototype.pcb_res_flag`。

后续 HTTP 节点的表达式 `$json.pcb_res_flag` 在宿主数据代理上读取，沿着原型链拿到 flag，打到 sidecar `/ingest?res=`。过滤器刚看过的是第一次 `String()`；open/defineProperty 看到的是第二次强制转换。两套语义中间没有把校验结果写回 `options`。

---

## 仓库里已经有更强的检查，写回没用上

谁在 2.20.6 碰危险键：

| 位置 | 是否稳定化 / 是否拒绝 |
|---|---|
| `sanitizeXmlName`（标签、属性**名**） | 是，改写成 `sanitized_*` |
| `const attrkey = String(options.attrkey)` + `forbiddenKeys.includes` | 是，但只针对**拷贝** |
| `options.attrkey` 本身 / `parserOptions.attrkey` | **否**，仍是调用方给的对象 |
| `new Parser(parserOptions)` | 不再查禁名单 |

把 `options.attrkey = String(options.attrkey)` 写回去，parser 拿到的就是校验过的稳定字符串——这正是 2.20.7 多出来的那一行。2.20.6 已经**算出了**这个字符串，只是存在局部变量里，没有替代即将被消费的值。不是仓库里没有更好的谓词，是 **赋值回 options 没用**。

Function 节点（`n8n-nodes-base.function`，vm2，主进程）能构造带自定义 `toString` 的对象，再经表达式交给 XML 节点。这是官方仍注册的节点，不是外部插件。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs parser」落到具体代码：

- `forbiddenKeys.includes(String(options.attrkey ?? ''))`：看**第一次** ToString 是不是 `__proto__`
- xml2js 的 `obj[attrkey]`：看**之后**每一次 ToString 是什么

只要构造一种输入，使第一次 ToString 为 `'safe'`、后续为 `'__proto__'`，第一行会放行，第二行仍然污染原型。

```text
let calls = 0;
const evil = { toString: () => (++calls === 1 ? 'safe' : '__proto__') };

V1 校验: String(evil) → 'safe'  → includes? false → 放行
Parser:  attrkey 仍是 evil
         解析 <root pcb_res_flag='FLAG'>x</root>
         ToString(evil) → '__proto__'
         defineProperty(Object.prototype, 'pcb_res_flag', FLAG)
```

seed 的 `<__proto__>` 标签被 processors 改名，走不通；residual 不依赖危险标签名，依赖危险 **attrkey**。

---

## 残余仍然走同一条 xmlToJson 路径（CVE-2026-44791）

没有换节点类型、没有换 xml2js。还是 XML 节点的 `execute`：

工作流：Webhook → Function（产出 `{data: xml, evil}`）→ XML（`attrkey: ={{ $json.evil }}`，`mergeAttrs: false`）→ HTTP（`/ingest?res=` + `$json.pcb_res_flag`）。

`sanitizeXmlName` 照样执行；`forbiddenKeys` 照样执行；执行完之后 `Parser` 拿到的 `attrkey` 仍是那个对象。污染发生后，本 case 还能观察到 TypeORM 「Property pcb_res_flag was not found in User」一类实例级副作用（原型上多出来的键干扰实体）。oracle 在探测之间重启容器，避免残留污染干扰下一轮。

本 case `verify.sh` 的 residual 把 Function 源码和 XML 选项写死在脚本里（运行时不读 held-out 文件）。认证：v1 + `--residual` 退出码 0，sidecar 记录 `res=PCBFLAG_...`。

所以残余不是新洞面，而是同一 `options.attrkey` 上三件事叠在一起：校验语言是「当前 ToString」；消费发生在校验之后且再次 ToString；已经算出来的安全字符串没有写回即将被 spread 的对象。seed 被挡住只说明「XML 里的字面 `__proto__` 标签没了」，不说明「不能再通过 XML 节点污染 `Object.prototype`」。

---

## 后来又补了什么（CVE-2026-44791，2.20.7）

2.20.7 把局部拷贝改成**原地强制转换**，再检查同一份值：

```ts
# Xml.node.ts :: execute  (n8n@2.20.7)
		if (options.attrkey !== undefined) {
			options.attrkey = String(options.attrkey);
			if (forbiddenKeys.includes(options.attrkey)) {
				throw new NodeOperationError(...);
			}
		}
		if (options.charkey !== undefined) {
			options.charkey = String(options.charkey);
			...
		}
```

`charkey` 走同一模式：V1 也是 `const charkey = String(options.charkey ?? '')` 后仍 spread 原值。xml2js 用 charkey 作为文本节点在对象上的键，`obj[charkey] = text` 同样能打到 `__proto__`。本 case residual 用 attrkey + 属性 `pcb_res_flag` 就够；闭合修复对两个键都做了原地 `String`。

对残余输入：第一次 `String(evil)` 得到 `'safe'`，写回 `options.attrkey`；对象被扔掉；Parser 拿到稳定的 `'safe'`，`obj['safe'] = { pcb_res_flag: FLAG }`，**不是** `Object.prototype`。后续 `$json.pcb_res_flag` 读不到原型上的值（除非结果对象自己带这个键，本 case 的 XML 在 mergeAttrs false 时键在 `safe` 下面）。sidecar 无 `res=FLAG`。测试断言 parser 收到的是强制转换后的字符串。公开建议是升级到 2.20.7 / 1.123.43 / 2.22.1。

`deepCopy(json)` 在 XML 节点返回前还会走一遍 n8n-workflow 的拷贝。seed 靠的是拷贝时碰到 `__proto__` 键；V1 的 processors 把标签改名后，拷贝看不到危险键。residual 的污染发生在 parser **内部**的 `defineProperty(Object.prototype, ...)`，不依赖 deepCopy 是否复制 `__proto__`。所以同一函数里「标签消毒 + 返回值拷贝」挡不住「选项键污染全局原型」。

表达式 `={{ $json.evil }}` 在 n8n 里不是先 `String()` 再进节点参数的：数据代理把 Function 输出的对象引用交出去。这就是「校验看到 string、parser 看到 object」能在真实 HTTP 工作流里发生的原因，而不需要改 Xml.node.ts 以外的引擎。

Function 节点跑在 vm2 的主进程沙箱里，`toString` 是普通 JS 属性，跨过表达式边界时对象身份保留。若 XML 的 attrkey 只能从节点编辑器填字符串字面量，状态对象送不进去；表达式是官方支持的参数源，V1 没把它当成「会得到非字符串」。

即便如此，gadget（Git 节点环境变量、task runner）仍可能在其它污染源下被利用；本 benchmark 的 v2 只关闭这条 attrkey 强制转换链。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是「当前字符串是否在禁名单里」。真正写成原型的是 xml2js 对 `attrkey` 的属性访问。V2 把校验结果写回即将被 Parser 消费的那份值，这才对准了消费层。

**不是没有更好的谓词。**  
`forbiddenKeys` 和 `String(...)` 在 2.20.6 已经存在。从 V1 的 diff 只能看到多了两行 `const attrkey = String(...)`；要判断补丁是否闭合，必须看到 `Object.assign(..., options)` 仍然传入原始对象，以及 xml2js 稍后会再次 ToString。

**同一 `execute`、同一 `options.attrkey`，只换了值的写法。**  
字面量 `'__proto__'` 被挡住；带状态的 `toString` 第一次不是 `'__proto__'`。Function 节点是把非字符串送进表达式的官方通道。

**processors 管名不管键。**  
`sanitizeXmlName` 让人以为「危险名字都处理了」。它的输入是 XML 里扫到的名字，不是 parser 选项。

**金丝雀只在 sidecar 上是有意的。**  
n8n 进程不持有 flag。能在 `/ingest?res=` 里看到它，说明后续节点从被污染的原型上读到了攻击者写入的属性，而不是 XML 节点 JSON 里碰巧有同名字段。

**`Object.assign` 的后写 processors 救不了 attrkey。**  
`Object.assign({mergeAttrs, explicitArray}, options, {tagNameProcessors, attrNameProcessors})` 第三参覆盖的是处理器，不是 `attrkey`。`options.attrkey` 若存在，会覆盖默认，并保留到 Parser。V1 把安全字符串放在 `const attrkey` 里，从未放进这个 assign 链。

V1 与 V2 对同一份 `options` 的差别只有「写不写回去」：

```ts
# V1 n8n@2.20.6
const attrkey = String(options.attrkey ?? '');
if (forbiddenKeys.includes(attrkey)) throw ...
# options.attrkey 未改；随后 Object.assign(..., options, ...)

# V2 n8n@2.20.7
if (options.attrkey !== undefined) {
  options.attrkey = String(options.attrkey);
  if (forbiddenKeys.includes(options.attrkey)) throw ...
}
```

`new Parser(parserOptions)` 在两版里都在校验之后立刻构造。闭合性不取决于禁名单内容，取决于 Parser 拿到的是不是那次 `String()` 的结果。

---

## 版本、入口、参考

| | 版本 | 标签 `__proto__` | `options.attrkey` 校验 | Parser 收到的 attrkey | seed | residual |
|---|---|---|---|---|---|---|
| V0 | 2.17.3 | 不改名 | 无 | 原值 | sidecar 有 seed=FLAG | （不必） |
| V1 | 2.20.6 | `sanitizeXmlName` | 查 **拷贝** | **原值** | 挡 | 原型污染，res=FLAG |
| V2 | 2.20.7 | 同 V1 | `options.attrkey = String(...)` 再查 | 稳定字符串 | 挡 | 挡 |

- HTTP：owner 登录 + `POST /rest/workflows` + 激活 + `POST /webhook/{path}`；sidecar `:8000/ingest`
- 认证（本平台）：v0 seed 观察到 flag；v1 seed 未观察到；v1 residual 观察到。
- [CVE-2026-44791](https://nvd.nist.gov/vuln/detail/CVE-2026-44791) / [GHSA-wrwr-h859-xh2r](https://github.com/n8n-io/n8n/security/advisories/GHSA-wrwr-h859-xh2r)
- 前置：CVE-2026-42232 / GHSA-hqr4-h3xv-9m3r
- 官方 tag：`https://github.com/n8n-io/n8n/tree/n8n%402.20.6` 与 `n8n@2.20.7`
