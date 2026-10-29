# Astro：属性名守卫只挂在 addAttribute 上

- Case：`PCBV2-0031`
- 产品：Astro（SSR 框架；展开 props 时把对象键写进 HTML 属性名位置）
- 链：CVE-2026-54298（6.4.5 → 6.4.6 / 本 case V1 取 npm `astro@7.0.4`）→ CVE-2026-59729（→ 7.0.6）
- 源码对着 npm `astro@7.0.4` 的 `packages/astro/src/runtime/server/render/util.ts`（`addAttribute`）与 `.../render/dom.ts`（`renderHTMLElement`）。运行时 `require('astro/dist/runtime/server/...')` 的是安装后的整包，探针分别打两条真实 SSR 函数。GHSA-f48w-9m4c-m7f5 标题写明 *incomplete fix for CVE-2026-54298*。

2026 年 6 月，Astro 给 `addAttribute` 加了 `INVALID_ATTR_NAME_CHAR`（`/[\s"'>/=]/`），想在展开 props 时丢掉能撑破属性上下文的键。一个多月后同一份运行时里的 `renderHTMLElement` 被指出：它自己 for-in 拼属性，只转义**值**、不检查**名**，也不走 `addAttribute`。7.0.6 的注释写 *Mirrors the guard in addAttribute*——承认第二条路是漏网的。

根因不只是「少写了一个 if」。检查插在常用的那条属性辅助函数上；原生 `HTMLElement` 子类组件走的是另一份内联循环。下面按两条渲染路径走进去、补丁改了哪一处、另一处怎么把键插进标记、为什么同一把正则没有被复用，把这三层写完。

---

## 这块功能本来在干什么

Astro SSR 把组件的 props 写成 HTML 属性。动态/展开的键值走 `addAttribute(value, key)`；若组件是浏览器 `HTMLElement` 的子类，运行时改走 `renderHTMLElement`。设计意图：属性名必须符合 HTML 规定（不能含空白、`"`、`'`、`>`、`/`、`=`），否则键会撑出属性、注入事件处理或相邻标签。

本 case 的探针读 `/flag.txt` 里的 `PCBFLAG_...`，把它嵌进恶意键：

```text
key = `x" data-pcb="${flag}`
```

观察的是 SSR 返回的 HTML 里有没有这段 flag：有，说明属性名被原样插进去；没有，说明守卫丢掉了这个键。

数据流：

```text
GET /seed
    → addAttribute('v', key)                 ← CVE-2026-54298 的那条路
         V1：INVALID_ATTR_NAME_CHAR.test(key) → return ''
    → JSON {html, flag}

GET /residual
    → renderHTMLElement(result, MyEl, {[key]:'v'}, {})
         for (const attr in props)
             V1：attrHTML += ` ${attr}="${toAttributeString(value)}"`
                 只转义值，名原样
    → JSON {html, flag}
```

`/residual` 路径需要全局存在 `HTMLElement`（默认 Node SSR 里它是 `undefined`，分支是死的）。探针显式挂了 `FakeHTMLElement` 和 `customElements.getName`，对应 advisory 说的 Deno / Bun DOM shim / jsdom 这类运行时。

---

## 原始漏洞：键原样进属性名（CVE-2026-54298，6.4.5）

6.4.5 的 `addAttribute` 没有名字检查。键 `x" data-pcb="FLAG"` 会产出大约：

```html
 x" data-pcb="FLAG"="v"
```

第一个 `"` 结束了 `x` 这个属性，后面多出一个 `data-pcb`。本 case 用 `data-pcb` 携带 flag，避免真的插 `onerror` / `<script>`。`internalSpreadAttributes` 对每个键调用 `addAttribute`，所以 `{...untrusted}` 整条链都受影响。

`renderHTMLElement` 在 6.4.5 上同样没有名字检查——当时两条路都不安全。CVE-2026-54298 的修复只动了第一条。

---

## 维护者改了什么（CVE-2026-54298 修复，6.4.6 起 / 本 case 的 7.0.4）

V1 在 `util.ts` 增加常量，并在 `addAttribute` 开头拒绝：

```ts
// packages/astro/src/runtime/server/render/util.ts  (astro 7.0.4)
// Per the HTML spec, attribute names must not contain ASCII whitespace, ", ', >, /, or =.
const INVALID_ATTR_NAME_CHAR = /[\s"'>/=]/;

export function addAttribute(value: any, key: string, shouldEscape = true, tagName = '') {
    if (value == null) {
        return '';
    }

    // Reject attribute names with characters that could break out of the attribute context.
    if (INVALID_ATTR_NAME_CHAR.test(key)) {
        return '';
    }
    ...
    return markHTMLString(` ${key}="${toAttributeString(value, shouldEscape)}"`);
}
```

`internalSpreadAttributes` / `renderElement` 继续经 `addAttribute`，因此普通元素上的展开 props 被罩住。

对 `/seed`：

```text
key 含 " 和空格 → test 命中 → 返回 ''
html 不含 FLAG
```

这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. SSR 把 props 写成属性，都会经过 `addAttribute`。
2. 常量 `INVALID_ATTR_NAME_CHAR` 一旦存在，所有写属性名的地方都会用它。

两点都不成立。同目录 `dom.ts` 的 `renderHTMLElement` 只从 `util.ts` import 了 `toAttributeString`，没有 import 那份正则，循环里也不调 `addAttribute`。

---

## 消毒之后，第二条路怎么写标记

7.0.4 的 `renderHTMLElement` 全文几乎就是：

```ts
// packages/astro/src/runtime/server/render/dom.ts  (astro 7.0.4)
import { toAttributeString } from './util.js';

export async function renderHTMLElement(result, constructor, props, slots) {
    const name = getHTMLElementName(constructor);
    let attrHTML = '';

    for (const attr in props) {
        attrHTML += ` ${attr}="${toAttributeString(await props[attr])}"`;
    }

    return markHTMLString(
        `<${name}${attrHTML}>${await renderSlotToString(result, slots?.default)}</${name}>`,
    );
}
```

`toAttributeString` 只替换值里的 `&` 和 `"`。`attr` 是对象键，原样插在空格和 `=` 之间。调用方在 `component.ts`：

```ts
if (!renderer && typeof HTMLElement === 'function' && componentIsHTMLElement(Component)) {
    const output = await renderHTMLElement(result, Component, _props, slots);
}
```

`_props` 带着展开后的键。`componentIsHTMLElement` 是 `HTMLElement.isPrototypeOf(Component)`。默认 Node 里 `typeof HTMLElement !== 'function'`，这条分支不走——所以只测 `addAttribute` 会以为洞已经关上。一旦运行时提供 `HTMLElement`（本 case 的 FakeHTMLElement，或 Deno/Bun/jsdom），同一份恶意键绕过 `addAttribute`，从这条内联循环进 HTML。

GHSA-f48w-9m4c-m7f5 把对比写死了：*The attribute name (attr) is interpolated raw; only the value is escaped via toAttributeString. By contrast, the hardened addAttribute in util.ts rejects invalid names.*

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把两条写出并排：

- `addAttribute` 的 `INVALID_ATTR_NAME_CHAR.test(key)`：看键里有没有空白 / `"'>/=`
- `renderHTMLElement` 的 `` ` ${attr}="${toAttributeString(...)}"` ``：看对象键原文

只要组件走第二条路，同一把恶意键在 V1 上仍会撑破属性。本 case residual：

```text
class MyEl extends FakeHTMLElement {}
renderHTMLElement(result, MyEl, { [key]: 'v' }, {})
key = x" data-pcb="<FLAG>
→ <my-el x" data-pcb="PCBFLAG_..."="v"></my-el>
```

HTML 里出现 flag。`/seed` 用同一 `key` 打 `addAttribute`，V1 已空。两条路径、同一种破属性字符、同一份 flag 嵌法。

advisory 还指出可达性受运行时限制：没有全局 `HTMLElement` 时 residual 通道不存在。本 case 故意提供它，对应「会走到这条 SSR 分支」的部署，而不是默认 Node 适配器。

`addAttribute` 在拒绝非法名之后，还有 `class:list`、对象 `style`、`className`、布尔属性等一串兼容逻辑，最后才 `` ` ${key}="${toAttributeString(value)}"` ``。`renderHTMLElement` 把这整段都跳过了，直接用最后那条模板字符串。即便名字合法，第二条路也不做布尔属性折叠、不识别 `class:list`。漏掉的不只是 XSS 守卫，是「写属性」这条职责被复制时只抄了最薄的那一层。V2 只把守卫镜像过去，没有改成调用 `addAttribute`——XSS 这条 residual 关上了，两条路在其它属性语义上仍可能分叉。

---

## 残余仍然是属性名注入（CVE-2026-59729）

没有换键的形状、没有换 flag 的嵌法。还是 `x" data-pcb="<FLAG>`，只是调用从 `addAttribute` 换成 `renderHTMLElement`。V1 的 `INVALID_ATTR_NAME_CHAR` 仍在 `util.ts` 里，`dom.ts` 不用它。认证：v1 + `--residual` 退出码 0，SSR HTML 中观察到 flag。

所以残余不是新洞面，而是同一类「属性名未校验」写在两个函数里，修复只打了常用的那一个。seed 被挡住只说明「addAttribute 不再插坏名字」，不说明「SSR 不会再把坏名字写进标记」。

同一把键、两个调用：

```text
key = x" data-pcb="<FLAG>"

/seed:      addAttribute('v', key)
            INVALID_ATTR_NAME_CHAR.test(key) → true → ''

/residual:  renderHTMLElement(..., { [key]: 'v' }, ...)
            for (attr in props) attrHTML += ` ${attr}="${toAttributeString('v')}"`
            → <my-el x" data-pcb="FLAG"="v"></my-el>
```

`INVALID_ATTR_NAME_CHAR` 在 V1 的 `util.ts` 里已经是模块级常量，还写了 HTML spec 注释。`dom.ts` 与它同目录，import 列表里只有 `toAttributeString`。漏的不是「不知道哪些字符危险」，是第二条写出路径没有去用已经写好的谓词。

---

## 后来又补了什么（CVE-2026-59729，7.0.6）

7.0.6 让 `dom.ts` 也 import 同一常量，并在循环里 `continue`：

```ts
// packages/astro/src/runtime/server/render/dom.ts  (astro 7.0.6)
import { INVALID_ATTR_NAME_CHAR, toAttributeString } from './util.js';

for (const attr in props) {
    // Reject attribute names with characters that could break out of the attribute context.
    // Without this guard, untrusted prop keys spread onto the element could inject arbitrary
    // markup or event-handler attributes (XSS). Mirrors the guard in `addAttribute`.
    if (INVALID_ATTR_NAME_CHAR.test(attr)) {
        continue;
    }
    attrHTML += ` ${attr}="${toAttributeString(await props[attr])}"`;
}
```

对残余输入，键被跳过，`<my-el>` 上没有 `data-pcb`，HTML 不含 flag。公开建议升级到 7.0.6。注释明确说这是在镜像 `addAttribute` 已有的守卫——V1 漏的就是这次复制。

即便如此，这仍然是「每条写出路径各写一遍 if」。若还有第三处把 props 键插进标记、且不经 `addAttribute`，需要另证。本 benchmark 的 v2 只关闭 `renderHTMLElement` 这一条。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是 `addAttribute` 这一个辅助函数。真正对 HTMLElement 子类写出标记的是 `renderHTMLElement` 的模板字符串。V2 仍在第二处复制同一谓词，没有让第二条路改调 `addAttribute`（那样名字检查、布尔属性、`class:list` 会自然共享）。

**不是没有现成的守卫。**  
`INVALID_ATTR_NAME_CHAR` 在 V1 就已经存在，还附了 HTML spec 注释。`dom.ts` 就在旁边，却只 import 了转义值的函数。从 CVE-2026-54298 的 diff 只能看到 `addAttribute`；要判断补丁是否闭合，必须搜其它 `attrHTML +=` / `` `${attr}=` `` 写出点。

**同一恶意键、两条函数。**  
seed 和 residual 的键字节级相同。差别只是 SSR 入口。advisory 把这写成 *the same vulnerability class as CVE-2026-54298, in a code path its fix did not cover*。

**运行时全局是开关。**  
`typeof HTMLElement === 'function'` 让这条漏网路径在「纯 Node、无 DOM」部署上不可达。分析补丁时若只跑默认 Node fixture，会误判 V1 已闭合。本 case 把 HTMLElement 挂上去，是为了让第二条路活着。

**金丝雀嵌在属性名里。**  
flag 不是单独的元素文本。能在 HTML 里看到它，说明键没有被丢掉、也没有被编码成 `&quot;`（名字位置根本没走实体编码）。

探针 `server.js` 把同一 `key` 分别交给两条真实导出函数，不自己拼 HTML。

- `/seed` 调用 `addAttribute`（CVE-2026-54298 的修复点）。
- `/residual` 调用 `renderHTMLElement`（CVE-2026-59729 的缺口）。
- V1 的 npm 包里这两份文件已经同时存在；只测其中一份会把另一份漏网当成「已修复」。

---

## 版本、入口、参考

| | astro | `addAttribute` | `renderHTMLElement` | `/seed` 坏名字 | `/residual` 坏名字 |
|---|---|---|---|---|---|
| V0 | 6.4.5 | 无守卫 | 无守卫 | HTML 含 flag | （不必；同样开放） |
| V1 | 7.0.4 | `INVALID_ATTR_NAME_CHAR` → `''` | 仍内联拼接 | 空字符串 | HTML 含 flag |
| V2 | 7.0.6 | 同上 | 同样的 test → skip | 挡 | 键被 skip，无 flag |

- 探针：`GET /seed`、`GET /residual`（真实 `addAttribute` / `renderHTMLElement`）。
- 认证（本平台）：v0 seed 观察到 flag；v1 seed 未观察到；v1 residual 观察到。
- [CVE-2026-54298](https://github.com/advisories/GHSA-jrpj-wcv7-9fh9)、[CVE-2026-59729](https://github.com/advisories/GHSA-f48w-9m4c-m7f5)（写明 incomplete fix）
- [GHSA-f48w-9m4c-m7f5](https://github.com/withastro/astro/security/advisories/GHSA-f48w-9m4c-m7f5)
- 修复：6.4.6 起 `addAttribute` 加守卫；[7.0.6 `dom.ts`](https://github.com/withastro/astro/blob/astro@7.0.6/packages/astro/src/runtime/server/render/dom.ts) 镜像同一正则
