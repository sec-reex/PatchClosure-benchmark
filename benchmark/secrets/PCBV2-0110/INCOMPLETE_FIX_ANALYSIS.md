# fast-xml-parser 实体限额：DOCTYPE 开始计数了，`&lt;` 循环还没有

- Case：`PCBV2-0110`（legacy `fastxmlparser_entity_expansion_limit`）
- 产品：npm `fast-xml-parser`（NaturalIntelligence）。本 case 用 Express `POST /parse` 同步跑 `new XMLParser({processEntities:true}).parse(req.body)`。
- 链：CVE-2026-26278（5.3.5 → 5.3.6，DOCTYPE 循环加 `maxTotalExpansions` / `maxExpandedLength`）→ CVE-2026-33036 / GHSA-8gc5-j5rx-235r（5.3.6 → 5.5.6，同样的计数接到 `lastEntities` / `htmlEntities`）
- 源码对着 GitHub tag `v5.3.6` 的 `src/xmlparser/OrderedObjParser.js`：`replaceEntitiesValue`、`this.lastEntities`、`this.docTypeEntities`。运行时装的是发布包本身。

2026 年初，5.3.6 给「亿笑」式 DOCTYPE 实体加了默认 1000 次 / 100000 字符的账本。GHSA-8gc5-j5rx-235r 标题直接写 *incomplete fix for CVE-2026-26278*：限额**只**在 DOCTYPE 循环上执行。NVD CVE-2026-33036：*`replaceEntitiesValue()` ... only enforces expansion counting on DOCTYPE-defined entities while the lastEntities loop handling numeric/standard entities performs no counting at all.*

根因不只是「少写了一个循环」。检查插在「自定义实体展开了几次」这一层；真正替换文本的还有紧跟着的标准实体循环，它用的是同一份 `val`、同一份 `String#replace`，复杂度随引用次数二次增长。账本对象已经在构造函数里，标准循环不用。下面按请求走进去、5.3.6 改了哪一段、谁消费 `val`、计数谓词挂在哪，把这几层写完。

---

## 这块功能本来在干什么

解析器在读元素文本和属性时，把 `&name;` / `&#NNN;` 换成对应字符。`processEntities: true`（默认）时，`parseTextData` 调用 `replaceEntitiesValue`。一次典型请求：

```http
POST /parse
Content-Type: text/xml

<note>hello &amp; world</note>
```

设计意图：DOCTYPE 里的内部实体和内置 `&lt;` `&amp;` 都展开成文本，供 JS 对象使用。成功穿越之后的效果是：**展开次数或替换工作量不受配置限额约束，同步 parse 卡住 Node 事件循环**。本 case 的 oracle 是延迟阈值（T_SLOW=2000ms，读超时 10s），没有金丝雀 token。

数据流：

```text
HTTP body XML
    → XMLParser.parse
    → OrderedObjParser.parseTextData
    → replaceEntitiesValue(val, tagName, jPath)
         若 val 不含 '&' 则返回
         循环 this.docTypeEntities     ← V1 在这里计数、throw
         循环 this.lastEntities        ← 仍是 val.replace，不计数
         可选 htmlEntities
         最后 ampEntity
    → 解析结果 JSON 回给 /parse
```

没有登录。判断完全信任「限额已经罩住所有实体替换」。

---

## 原始漏洞：三圈都不计数（CVE-2026-26278，5.3.5）

5.3.5 的 `replaceEntitiesValue(val)` 对三张表都是裸 `replace`：

```javascript
// OrderedObjParser.js  (5.3.5，概念)
for (let entityName in this.docTypeEntities) {
  val = val.replace(entity.regx, entity.val);
}
for (let entityName in this.lastEntities) {
  val = val.replace(entity.regex, entity.val);
}
```

一个小 DOCTYPE 实体被引用几千次，每次 replace 扫整串，展开后的文本再进入下一轮，CPU / 内存无界。本 case 的 seed：

```xml
<!DOCTYPE r [ <!ENTITY a "AAAA...(5000 A)"> ]>
<r>&a;&a;...(2000 次)</r>
```

5.3.5 在 DOCTYPE 循环里把 `&a;`×2000 换成约 10 MB，事件循环卡住，HTTP 读超时。这就是 v0 + `--seed` 的 DoS 阳性。

---

## 维护者改了什么（CVE-2026-26278 修复，5.3.6）

tag `v5.3.6` 给函数加了 `tagName, jPath`，并**只**在 DOCTYPE 循环里记账。GitHub blob：

```javascript
// src/xmlparser/OrderedObjParser.js :: replaceEntitiesValue  (tag v5.3.6)
const replaceEntitiesValue = function (val, tagName, jPath) {
  if (val.indexOf('&') === -1) {
    return val;
  }
  const entityConfig = this.options.processEntities;
  if (!entityConfig.enabled) {
    return val;
  }
  // ... allowedTags / tagFilter ...

  // Replace DOCTYPE entities
  for (let entityName in this.docTypeEntities) {
    const entity = this.docTypeEntities[entityName];
    const matches = val.match(entity.regx);
    if (matches) {
      this.entityExpansionCount += matches.length;
      if (entityConfig.maxTotalExpansions &&
          this.entityExpansionCount > entityConfig.maxTotalExpansions) {
        throw new Error(
          `Entity expansion limit exceeded: ${this.entityExpansionCount} > ${entityConfig.maxTotalExpansions}`
        );
      }
      const lengthBefore = val.length;
      val = val.replace(entity.regx, entity.val);
      if (entityConfig.maxExpandedLength) {
        this.currentExpandedLength += (val.length - lengthBefore);
        if (this.currentExpandedLength > entityConfig.maxExpandedLength) {
          throw new Error(
            `Total expanded content size exceeded: ${this.currentExpandedLength} > ${entityConfig.maxExpandedLength}`
          );
        }
      }
    }
  }
  if (val.indexOf('&') === -1) return val;

  // Replace standard entities
  for (let entityName in this.lastEntities) {
    const entity = this.lastEntities[entityName];
    val = val.replace(entity.regex, entity.val);
  }
  // htmlEntities 同样 uncounted ...
```

构造函数里账本已经就位：

```javascript
this.entityExpansionCount = 0;
this.currentExpandedLength = 0;
this.lastEntities = {
  "apos": { regex: /&(apos|#39|#x27);/g, val: "'" },
  "gt":   { regex: /&(gt|#62|#x3E);/g, val: ">" },
  "lt":   { regex: /&(lt|#60|#x3C);/g, val: "<" },
  "quot": { regex: /&(quot|#34|#x22);/g, val: "\"" },
};
```

对 seed：2000 次 `&a;` 在 DOCTYPE 循环里 `matches.length` 累加，超过默认 1000 就 throw，`/parse` 在数毫秒内返回错误 JSON。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险展开来自 `docTypeEntities`（用户在 DOCTYPE 里声明的名字）。
2. 内置实体「只是短名字换成一个字符」，次数再多也不可怕。

第二点不成立：`String#replace` 对全局正则在长串上是 O(N×M) 量级；12 万次 `&lt;` 足够把单线程卡过 10 秒，即使每次只变成一个 `<`。

---

## 检查之后，谁真正消费那个 val

DOCTYPE 循环之后，**同一份 `val`** 进入 `lastEntities`。对 seed，`&a;` 已经被换成 AAAA，串里可能不再有 `&`，函数会 `indexOf('&') === -1` 早退。对残余，根本没有 DOCTYPE，`docTypeEntities` 为空，计数保持 0，限额一次都没问，全部工作在：

```javascript
val = val.replace(entity.regex, entity.val);
```

`lt` 的正则是 `/&(lt|#60|#x3C);/g`。120000 个 `&lt;` 在一次 `replace` 里被找齐并换成 `<`。V8 的全局替换对这种「模式短、命中极多、输出几乎等长」的输入会走二次扫描。过滤器刚看过的是「DOCTYPE 展开次数」；CPU 看到的是标准实体循环的 replace。两套语义中间没有第二次谓词。

`htmlEntities` 里的 `num_dec` / `num_hex` 在 `htmlEntities: true` 时同样不计数。advisory 用 1M 个 `&#65;` 估约 147MB。本 case residual 选标准 `&lt;`，不依赖 htmlEntities 选项。

---

## 仓库里已经有更强的检查，标准循环没用

`entityExpansionCount` / `maxTotalExpansions` / throw 文案在 5.3.6 已经完整。它只被 DOCTYPE 循环调用。标准循环就在下面十几行，结构几乎可以复制粘贴。

`addExternalEntities` 甚至已经对名字做 `.replace(/[.\-+*:]/g, '\\.')` 再编译正则——说明维护者知道实体替换是危险面。限额却没有同样铺到 `lastEntities`。不是仓库里没有更好的谓词，是 **第二、第三个 for 没用**。

即便 `&lt;` 每次只变一个字符、`maxExpandedLength` 也几乎不涨，`maxTotalExpansions` 按「引用次数」本应在 1000 次时切断。V1 从未把这些引用算进去。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs replace」落到具体代码：

- DOCTYPE 循环：`match` → 加 `matches.length` → 超限 throw → 再 `replace`
- `lastEntities` 循环：直接 `replace`，不读账本

只要构造一种输入，使「没有（或很少）DOCTYPE 实体引用」但「标准 / 数字实体引用极多」，第一圈放行，第二圈仍按次数干活。

`<r>&lt;` × 120000 `</r>` 就是这样来的：

```text
无 <!ENTITY>，docTypeEntities 为空
entityExpansionCount 保持 0
lastEntities['lt'].regex 命中 120000 次
uncounted replace → O(N²) → HTTP 超时
```

字符串层面没有编码把戏。token 还是 XML 预定义实体；变的是「走哪一个 for」。seed 用自定义名字 `a` 走第一圈；残余用语言内置名字 `lt` 走第二圈。

GHSA 建议：把同一套 `entityExpansionCount` 接到 lastEntities 和 htmlEntities，与 DOCTYPE 循环类似。那正是 5.5.6 做的事。

---

## 残余仍然走同一条 replaceEntitiesValue（CVE-2026-33036）

没有换入口、没有换 `processEntities`、没有换 `/parse`。还是：

```http
POST /parse
<r>&lt;&lt;...（120000 次）...</r>
```

`replaceEntitiesValue` 仍然先跑已计数的 DOCTYPE 圈（空），再跑未计数的 `lastEntities`。V1 那套 maxTotalExpansions 照样在对象上；它从不被这条路径碰到。认证：v1 + `--residual` 超时 / 延迟超过阈值。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：限额只挂在一张表上；真正的 replace 还有另外两张表；账本对象已经存在却不更新。seed 被挡住只说明「自定义实体次数没了」，不说明「不能再强迫解析器做无界替换」。

平台 verify 与 heldout 都是 POST `/parse` 的同步 parse，同一 `replaceEntitiesValue`；残余只是换了实体种类。

---

## 后来又补了什么（CVE-2026-33036，5.5.6）

5.5.6（commit `bd26122`）把同样的 `val.match` + `entityExpansionCount += matches.length` + throw 接到 `lastEntities` 和 `htmlEntities` 上。对残余：1000 次之后 throw `Entity expansion limit exceeded: 120000 > 1000`，响应约几十毫秒。公开建议升级到 5.5.6；也可 `processEntities: false`（功能损失）或关掉 `htmlEntities`（挡不住 `&lt;` 这条标准路径）。

即便如此，这仍然是「在 replace 前数 match」；若某条替换路径以后再加第四张表，需要另证。本 benchmark 的 v2 只关闭标准实体 run 这条 residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是「用户声明的实体」。真正能卡住事件循环的是「所有 `val.replace`」。V2 仍在同一函数加码，没有把限额收到一个统一的 `replaceAndCount` 辅助函数里——但至少三张表都问了账本。

**不是没有更好的谓词。**  
`maxTotalExpansions` 已经是次数谓词。从 V1 的 diff 只能看到 DOCTYPE 圈变厚了；要判断补丁是否闭合，必须看到紧跟着的两个 for 还是不是裸 replace。

**同一函数、同一 `val`，只换了实体名字空间。**  
`&lt;`、`&#60;`、`&#x3C;` 在 `lastEntities['lt']` 的正则里是同一条。htmlEntities 的纯数字引用是平行缺口。

**「内置」不等于「便宜」。**  
限额设计常假设预定义实体是 O(1) 翻译。实现是全局正则替换，代价跟自定义实体同一量级。

**没有金丝雀是有意的。**  
信号是延迟和是否抛限额错误。V1 对 seed 抛错（快），对残余不抛（慢）——同一函数、同一默认 1000，只因走了不同的 for。

---

## 版本、入口、参考

| | npm | DOCTYPE 循环 | `lastEntities` / `htmlEntities` | `&a;`×2000 seed | `&lt;`×120000 residual |
|---|---|---|---|---|---|
| V0 | 5.3.5 | 裸 replace | 裸 replace | 超时 | 超时 |
| V1 | 5.3.6 | 计数 + throw | 仍裸 replace | 抛 2000>1000，快 | 超时 |
| V2 | 5.5.6 | 计数 | 同样计数 + throw | 快 | 抛 120000>1000，快 |

- Web：`POST /parse`，body 为 XML
- 认证（本平台）：v0 seed 慢；v1 seed 快；v1 residual 慢。
- [CVE-2026-26278](https://www.miggo.io/vulnerability-database/cve/CVE-2026-26278)
- [CVE-2026-33036](https://nvd.nist.gov/vuln/detail/CVE-2026-33036)、[GHSA-8gc5-j5rx-235r](https://github.com/advisories/GHSA-8gc5-j5rx-235r)
- V2 commit：[bd26122](https://github.com/NaturalIntelligence/fast-xml-parser/commit/bd26122c838e6a55e7d7ac49b4ccc01a49999a01)
- 源码：`https://github.com/NaturalIntelligence/fast-xml-parser/blob/v5.3.6/src/xmlparser/OrderedObjParser.js`
