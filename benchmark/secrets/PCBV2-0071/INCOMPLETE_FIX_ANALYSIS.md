# Open WebUI：ACL 把未知集合名当遗留，Milvus 把它当未转义的 resource_id

- Case：`PCBV2-0071`
- 产品：Open WebUI（自托管 LLM / RAG；知识库 chunk 存在向量库）
- 链：CVE-2026-44560 / GHSA-h36f-rqpx-j5wx（0.8.12 → 0.9.0，`filter_accessible_collections`）→ CVE-2026-54019 / GHSA-p5cp-r7rg-qpxc（→ 0.9.6，名字白名单 + Milvus 转义）
- 源码对着 GitHub tag `v0.9.0` 的 `backend/open_webui/retrieval/utils.py::filter_accessible_collections`、`retrieval/vector/dbs/milvus_multitenancy.py::search`。运行时是官方 `ghcr.io/open-webui/open-webui:0.9.0` + 真实 Milvus standalone（`ENABLE_MILVUS_MULTITENANCY_MODE=true`），攻击走 `POST /api/v1/retrieval/query/collection` + 真实 JWT。

2026 年 5 月，0.9.0 给 RAG 查询加了集合级 ACL：知识库 UUID 走 `Knowledges.check_access_by_user_id`，`file-*` / `user-memory-*` 走各自的权限。这挡住了「直接把受害者 KB uuid 当 collection_name」的越权读。GHSA-p5cp-r7rg-qpxc / NVD CVE-2026-54019 写明 *This is a bypass of the earlier fix for GHSA-h36f-rqpx-j5wx / CVE-2026-44560*：未知、非 KB 的名字被当成 legacy/ephemeral **放行**；Milvus 多租户模式下这个用户字符串变成 `resource_id`，插进 `expr=f"resource_id == '{resource_id}'"`，**不转义**。

根因不只是「表达式注入」。检查插在「这个名字是不是某类已知集合」这一层；真正返回 chunk 的是 Milvus 对那条 expr 的检索。同一份 0.9.0 里 ACL 已经会拒绝已知 KB，sink 却把「ACL 放行的任意字符串」当 SQL 风格字面量。下面按请求走进去、0.9.0 改了哪几行、放行之后谁消费那个名字、字符白名单为什么当时没挂上，把这几层写完。

---

## 这块功能本来在干什么

Open WebUI 把用户文档切块、嵌入、写入向量库，聊天时按 collection 检索。HTTP 入口之一：

```http
POST /api/v1/retrieval/query/collection
Authorization: Bearer <JWT>
{"collection_names":["<kb-uuid>"],"query":"anything","k":10}
```

设计意图：非管理员只能搜自己有权的知识库 / 自己的 file / 自己的 memory。多租户 Milvus 把很多逻辑集合挤进少数物理 collection（`*_knowledge` 等），用字段 `resource_id` 区分租户。

本 case：受害者非管理员建私有 KB，上传带 `${PCBFLAG_...}` 的文档，chunk 进真实 Milvus，`resource_id` = 该 KB id。攻击者是另一个非管理员，JWT 不含该 KB。成功穿越之后的效果是：**检索结果里出现受害者私有 chunk 的 flag 文本**。

数据流：

```text
POST /api/v1/retrieval/query/collection  {collection_names, query}
    → filter_accessible_collections(names, user)     ← CVE-2026-44560 补丁插在这里
         admin：全放行
         file-* / user-memory-* / web-search-*：各规则
         否则：若是 KB → check_access；若根本不是 KB → 当遗留集合放行
    → 对每个放行的 name：向量检索
         milvus_multitenancy._get_collection_and_resource_id(name)
              非 file/memory/web-search/hash → 物理库 *_knowledge，resource_id = name 原样
         search(..., expr=f"resource_id == '{resource_id}'")   ← 无转义
    → 返回 documents
```

需要登录（低权限用户即可）。判断完全信任「不是已知 KB ⇒ 遗留集合无敏感数据」；不信任 Milvus expr 把同一字符串当过滤条件。

---

## 原始漏洞：RAG 路径不查 ACL（CVE-2026-44560，0.8.12）

0.8.12 的 `get_sources_from_items` 有多条路径把用户给的 collection 名直接交给 `query_collection()`，**没有** `has_access_to_file` / KB ACL。GHSA-h36f-rqpx-j5wx 列了五条路径，其中三条（默认 file、text+collection_name、裸 collection_names）无检查。集合名可预测：`file-<id>` 或知识库 UUID。

seed：攻击者 JWT + `collection_names: [<受害者 KB uuid>]`。V0 上检索返回受害者 chunk，body 含 `PCBFLAG_...`。这是 case.json 记录的一次真实官方镜像 gate（**本分析未重新 compose**）。修复版本 0.9.0。

---

## 维护者改了什么（CVE-2026-44560 修复，0.9.0）

对着 GitHub tag `v0.9.0` 原文：

```python
# backend/open_webui/retrieval/utils.py :: filter_accessible_collections  (tag v0.9.0)
async def filter_accessible_collections(
    collection_names: set[str],
    user: UserModel,
    access_type: str = 'read',
) -> set[str]:
    """
    ...
      - everything else → if the name matches a knowledge base, validated
                          via Knowledges.check_access_by_user_id; if no
                          such KB exists, the name is treated as an
                          ephemeral/legacy collection and allowed
    """
    if user.role == 'admin':
        return collection_names

    validated = set()
    for name in collection_names:
        if name == 'knowledge-bases':
            continue
        elif name.startswith('file-'):
            ...
        elif name.startswith('user-memory-'):
            ...
        elif name.startswith('web-search-'):
            validated.add(name)
        else:
            # May be a knowledge-base ID or a legacy/ephemeral collection.
            # If it IS a KB, enforce access control.  If no such KB
            # exists, treat it as a non-sensitive collection ... and allow.
            if await Knowledges.check_access_by_user_id(name, user.id, permission=access_type):
                validated.add(name)
            elif not await Knowledges.get_knowledge_by_id(name):
                # Not a KB at all — legacy/ephemeral collection, allow
                validated.add(name)
    return validated
```

对 seed 这种**确实存在、且攻击者无权限**的 KB uuid，它确实够用：`check_access_by_user_id` 为假，`get_knowledge_by_id` 找得到该 KB，两个分支都不 `add`，名字被丢掉，接口 403 或空结果，body 没有金丝雀。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险读长得像「用别人的 KB uuid / file-id 当 collection 名」。
2. 不是已知 KB 的名字只是遗留/临时集合，放行也无妨；后面的向量库会按这个名字做隔离。

第二点在 **Milvus 多租户**下不成立。未知名字不会被丢掉，原样成为 `resource_id`。sink 用 f-string 插进 Milvus 表达式，单引号可以提前闭合字面量。

0.9.0 **没有** `_is_safe_collection_name`，也没有 `_escape_milvus_string`。那两样是 0.9.6 才加的。

---

## 检查之后，谁真正用那个名字去查

ACL 返回的集合名进入 `MilvusClient.search`。对着同一 tag：

```python
# backend/open_webui/retrieval/vector/dbs/milvus_multitenancy.py
# :: _get_collection_and_resource_id / search  (tag v0.9.0)
    def _get_collection_and_resource_id(self, collection_name: str) -> Tuple[str, str]:
        resource_id = collection_name
        if collection_name.startswith('user-memory-'):
            return self.MEMORY_COLLECTION, resource_id
        elif collection_name.startswith('file-'):
            return self.FILE_COLLECTION, resource_id
        elif collection_name.startswith('web-search-'):
            return self.WEB_SEARCH_COLLECTION, resource_id
        elif len(collection_name) == 63 and all(c in '0123456789abcdef' for c in collection_name):
            return self.HASH_BASED_COLLECTION, resource_id
        else:
            return self.KNOWLEDGE_COLLECTION, resource_id   # 默认：共享 knowledge 物理库

    def search(self, collection_name, vectors, filter=None, limit=10):
        mt_collection, resource_id = self._get_collection_and_resource_id(collection_name)
        ...
        results = collection.search(
            ...
            expr=f"{RESOURCE_ID_FIELD} == '{resource_id}'",
            ...
        )
```

`query` / `has_collection` / `delete` 同样是 `f"... == '{resource_id}'"`。Milvus 表达式没有参数化 API（0.9.6 注释后来写明这一点）。

residual 名字：

```text
x' or resource_id != '' or resource_id == 'x
```

ACL：不是 `file-`/`user-memory-`/`web-search-`；`get_knowledge_by_id("x' or ...")` 找不到 KB → **放行**。

映射：进 `KNOWLEDGE_COLLECTION`，`resource_id` 原样。expr 变成：

```text
resource_id == 'x' or resource_id != '' or resource_id == 'x'
```

这是永真（中间一项对任意非空 resource_id 为真）。共享 knowledge 库里**所有租户**的 chunk 都回来，包括受害者的 flag。过滤器刚看过的是「像不像 KB uuid」；Milvus 看的是布尔表达式。两套语义中间没有字符白名单。

GHSA-p5cp-r7rg-qpxc 的 curl 就是这条 payload，端点就是 `POST /api/v1/retrieval/query/collection`。本 case 与之同一构造，只是结果里认 `PCBFLAG_...`。

---

## 仓库里已经有更强的检查，未知名字和 sink 都没用上

0.9.0 已经：

| 谓词 | 用在哪 |
|---|---|
| `Knowledges.check_access_by_user_id` | **仅当**名字对应得到一个 KB |
| `has_access_to_file` | 仅 `file-*` |
| 拒绝系统元集合 `knowledge-bases` | 是 |
| 未知名字必须匹配 `[A-Za-z0-9_-]+` | **否**（0.9.6 `_is_safe_collection_name`） |
| 未知名字默认拒绝 | **否**（0.9.6 起 `ENABLE_RETRIEVAL_UNSCOPED_COLLECTIONS` 默认 False） |
| `resource_id` 进 expr 前校验/转义 | **否**（0.9.6 `_validate_resource_id` / `_escape_milvus_string`） |

不是产品里没有 ACL 原语——已知 KB 已经在用。缺口是 **else 分支把「不是 KB」当成允许**，而多租户 sink 把任意允许的字符串插进共享库的过滤表达式。即便不用 tautology，单引号截断也可以改写比较。advisory 建议三条：不要放行任意未知名、转义或参数化、拒绝引号/控制字符。0.9.6 三条都做了。

---

## 这个补丁挡住了什么、没挡住什么

```text
seed collection_names:  [<victim-kb-uuid>]
  0.9.0 ACL: 是 KB，攻击者无权限 → 丢掉
  检索不发生 → 无 flag

residual collection_names:  ["x' or resource_id != '' or resource_id == 'x"]
  0.9.0 ACL: 不是 KB → 当遗留放行
  resource_id 原样进 expr → 永真
  共享 knowledge 库全表 → 含受害者 chunk → flag
```

token 变换：不再用受害者的 uuid（那是 ACL 认识的），改用 ACL **故意不认识**、但 sink 当字面量插入的字符串。中间的 `'` 关掉 f-string 的引号，`or resource_id != ''` 放行所有行。seed 被挡住只说明「别人的 KB id 没了」，不说明「不能再从共享 knowledge 物理库读出别人的 chunk」。

多租户是前置条件：`ENABLE_MILVUS_MULTITENANCY_MODE=true`。非多租户时每个逻辑集合可能是独立物理库，这条 tautology 打不到「别人的 resource_id」。advisory 写明 *when Milvus multitenancy mode is enabled*。本 case 的 compose 打开了该开关（观察到的产品行为以 GHSA + tag 源码为准）。

---

## 残余仍然走同一条 query/collection → filter → search（CVE-2026-54019）

没有换端点、没有换 JWT 角色。还是：

```http
POST /api/v1/retrieval/query/collection
{"collection_names":["x' or resource_id != '' or resource_id == 'x"],"query":"anything","k":10}
```

`filter_accessible_collections` 仍然放行；`search` 仍然用未转义 f-string；返回文档里出现受害者 flag。held-out 把 `INJECTION` 写死为 GHSA 那条。认证记录：v1 + residual HTTP 200，documents 含 flag；v2 因不安全字符 403。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：ACL 的 else 放行未知名；该名字在多租户下就是 resource_id；expr 插值发生在 ACL 之后且不转义。

---

## 后来又补了什么（CVE-2026-54019，0.9.6）

0.9.6 两处一起改（仓库 `patch.diff` 是 V1→V2 摘要）：

1. `filter_accessible_collections`：先 `_is_safe_collection_name`（`^[A-Za-z0-9_-]{1,255}$`），未知 KB 默认拒绝，除非 `ENABLE_RETRIEVAL_UNSCOPED_COLLECTIONS`。
2. `milvus_multitenancy.py`：`_validate_resource_id` 同一正则；`_escape_milvus_string` 转义 `\` 和 `'`；search/query/delete 在拼 expr 前调用。

对残余输入：名字含 `'` 和空格，ACL 入口就丢掉；即便绕过，sink 的 `_validate_resource_id` 也会 `ValueError`。公开建议升级到 0.9.6。GHSA 测试写的是 0.9.5 commit `3660bc00f` 仍受影响。

即便如此，expr 仍是 f-string，靠白名单+转义而不是参数化。对这条 tautology 它够用。本 benchmark 的 v2 只关闭这一条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是「哪些 collection 名可以往下传」。真正读出别人 chunk 的是 Milvus expr。V2 两边都加码：ACL 不再默认放行未知名，sink 不再信任任意字符。

**不是没有更好的谓词。**  
`check_access_by_user_id` 已经存在。else 分支选择「找不到 KB 就允许」。从 V1 的 diff 只能看到 ACL 函数；要判断补丁是否闭合，必须看到多租户映射把任意 name 当成 `resource_id`，以及 `expr=f"... '{resource_id}'"`。

**同一端点、同一 JWT，只换了 collection 字符串。**  
seed 用受害者 uuid（ACL 认识）；residual 用 ACL 不认识、sink 当代码的字符串。

**「遗留集合」兼容性和多租户共享物理库不能同时信用户字符串。**  
兼容分支假设未知名无敏感数据；共享 `*_knowledge` 里全是敏感数据，只靠 resource_id 切开。

**金丝雀在受害者私有 KB chunk 里是有意的。**  
攻击者自己的集合没有 flag。能检索到它，说明跨租户读发生了。

---

## 版本、入口、参考

| | Open WebUI | ACL else | Milvus expr | 受害者 KB uuid seed | tautology 名 residual |
|---|---|---|---|---|---|
| V0 | 0.8.12 | 无 ACL | （无隔离检查） | 读到 flag | （不必） |
| V1 | 0.9.0 | 未知非 KB → 放行 | `f"resource_id == '{id}'"` 未转义 | 403 / 无 flag | 读到 flag |
| V2 | 0.9.6 | 字符白名单 + 未知默认拒绝 | `_validate_resource_id` + escape | 挡 | 挡 |

- Web：`POST /api/v1/retrieval/query/collection`（真实 JWT）
- 认证记录（case.json）：v0 seed 观察到 flag；v1 seed 未观察到；v1 residual 观察到；v2 residual 未观察到。
- [CVE-2026-44560](https://github.com/open-webui/open-webui/security/advisories/GHSA-h36f-rqpx-j5wx) / [GHSA-h36f-rqpx-j5wx](https://github.com/advisories/GHSA-h36f-rqpx-j5wx)
- [CVE-2026-54019](https://nvd.nist.gov/vuln/detail/CVE-2026-54019) / [GHSA-p5cp-r7rg-qpxc](https://github.com/advisories/GHSA-p5cp-r7rg-qpxc)
- V1 源码：[tag v0.9.0 `utils.py`](https://github.com/open-webui/open-webui/blob/v0.9.0/backend/open_webui/retrieval/utils.py) `filter_accessible_collections`；[同 tag `milvus_multitenancy.py`](https://github.com/open-webui/open-webui/blob/v0.9.0/backend/open_webui/retrieval/vector/dbs/milvus_multitenancy.py) `search`
