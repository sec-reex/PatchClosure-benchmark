# Loki：TenantID 不许 `..` 了，namespace 仍只做一次 PathUnescape

- Case：`PCBV2-0125`
- 产品：Grafana Loki（日志聚合）。运行时是官方镜像 `grafana/loki:2.2.1` / `3.6.3` / `3.6.4`，ruler 开本地规则存储。
- 链：CVE-2021-36156（2.2.1 → 2.3.0，PR #4020 / `ValidTenantID`）→ CVE-2026-21726（3.6.3 → 3.6.4，`filepath.IsLocal` on namespace）
- 源码对着 tag `v3.6.3` 的 `pkg/ruler/base/api.go`（`parseNamespace` / `parseRequest`）以及 vendored `github.com/grafana/dskit/tenant` 的 `ValidTenantID`。金丝雀是 `/loki/pcb_flag.yaml`（store 上一层），一份合法 ruler group，**group 名**是 `$PCB_FLAG`。

CVE-2021-36156：*`X-Scope-OrgID` is used to construct file paths for rules files*，`../../sensitive/path` 会让 Loki 去解析那份文件并把部分内容送进错误信息。Grafana 对 CVE-2026-21726 的 advisory 标题就是 *CVE-2021-36156 Bypass*，正文：*The CVE-2021-36156 fix validates the namespace parameter for path traversal sequences after a single URL decode, by double encoding, an attacker can read files at `/loki/api/v1/rules/{namespace}`*。

这里有一处需要按源码对齐的地方：36156 的修复（PR #4020）实际限制的是 **TenantID / `X-Scope-OrgID`**，不是 namespace。3.6.3 的 `parseNamespace` 只有一次 `url.PathUnescape`，**没有**穿越检查。vendor 把「单次 decode 之后才验证」写在 namespace 头上，和 3.6.3 代码不完全一致；真正没挂上的是 `filepath.Join(store, tenant, namespace)` 的**第二个用户输入**。双重编码是为了穿过 `net/http` 的单次解码和 301 规范化，把 `../` 送进这个未守卫的参数。下面按请求走进去。

---

## 这块功能本来在干什么

Loki ruler 的本地存储把规则文件放在：

```text
filepath.Join(ruler.storage.local.directory, <tenant-id>, <namespace>)
```

本 case store 是 `/loki/rules-src`。列出某个 namespace：

```http
GET /loki/api/v1/rules/my-ns
X-Scope-OrgID: fake
```

`parseRequest` 取出 tenant（来自 context / 头）和 URL 里的 `{namespace}`，交给 `store.ListRuleGroupsForUserAndNamespace`。本地实现按上面那条 Join 去读 YAML，再写进响应。

设计意图：tenant 和 namespace 都是路径的一段，文件必须落在 store 目录里。成功穿越之后的效果是：**读到 store 上一层的 `pcb_flag.yaml`，group 名（flag）出现在 API body**。

数据流（V1 = 3.6.3）：

```text
GET /loki/api/v1/rules/{namespace}   + X-Scope-OrgID
    → parseRequest
         tenant.TenantID(ctx)              ← V1：ValidTenantID，拒绝 ".." 和 '/'
         parseNamespace(mux vars)
              url.PathUnescape 一次        ← 无 IsLocal
         return {UserID, Namespace, ...}
    → store.ListRuleGroupsForUserAndNamespace
         Join("/loki/rules-src", tenant, namespace)
    → 解析 YAML → HTTP body
```

本 case 未开多租户鉴权代理（advisory 说「前面有校验 OrgID 的代理就不受影响」）。请求可以直接带 `X-Scope-OrgID`。

---

## 原始漏洞：OrgID 就是路径段（CVE-2021-36156，2.2.1）

2.2.1 把 `X-Scope-OrgID` 原样拼进规则文件路径。NVD：*if crafted to conduct directory traversal such as `../../sensitive/path/in/deployment`, then Loki will attempt to parse a rules file at that location and include some of the contents in the error message*。

本 case seed 把穿越用在读成功路径上，不只是错误信息：

```text
GET /loki/api/v1/rules/pcb_flag.yaml
X-Scope-OrgID: ..
→ Join("/loki/rules-src", "..", "pcb_flag.yaml")
→ /loki/pcb_flag.yaml
```

V0 上 200，body 里 group 名是 `PCBFLAG_...`。PR #4020 把 cortex/dskit 的 TenantID 限制引进来，这就是 2.3.0 起的修复；本 case V1 已经远在其后（3.6.3）。

---

## 维护者改了什么（CVE-2021-36156 修复，保留到 3.6.3）

3.6.3 每次取 tenant 都走 `tenant.TenantID` → `ValidTenantID`：

```go
// vendor/github.com/grafana/dskit/tenant/tenant.go :: ValidTenantID  (loki v3.6.3)
func ValidTenantID(s string) error {
  for pos, r := range s {
    if !isSupported(r) {
      return &errTenantIDUnsupportedCharacter{tenantID: s, pos: pos}
    }
  }
  if len(s) > MaxTenantIDLength {
    return errTenantIDTooLong
  }
  if containsUnsafePathSegments(s) {
    return errUnsafeTenantID
  }
  return nil
}

func containsUnsafePathSegments(id string) bool {
  return id == "." || id == ".."
}

func isSupported(c rune) bool {
  // a-z A-Z 0-9 以及 ! - _ . * ' ( )
  ...
}
```

`'/'` 不在允许字符里，所以 `../` 也会在第一段循环失败。`".."` 被 `containsUnsafePathSegments` 点名。`parseRequest` 失败时 ruler API 走到 `respondServerError` / `user.ErrNoOrgID` 一类，实测是 HTTP 500 `"no org id"`。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 会进 `filepath.Join` 的危险输入是 tenant id。
2. namespace 要么不是路径段，要么 `net/http` 已经把 `../` 规范化掉了。

第一点只覆盖了 Join 的一个参数。第二点对**明文或单次编码**的 namespace 成立（Go 的 ServeMux 会 301 到干净路径，handler 根本看不到 `../`），对**双重编码**不成立。

同一份 `api.go` 里，namespace 在 V1 仍是：

```go
// pkg/ruler/base/api.go :: parseNamespace  (loki v3.6.3)
func parseNamespace(params map[string]string) (string, error) {
  namespace, exists := params["namespace"]
  if !exists {
    return "", ErrNoNamespace
  }

  namespace, err := url.PathUnescape(namespace)
  if err != nil {
    return "", err
  }

  return namespace, nil
}
```

没有 `ValidTenantID`，没有 `filepath.IsLocal`，没有「禁止 `..`」。

---

## 检查之后谁真正拼磁盘路径

`parseRequest` 把两个字段放进同一个结构：

```go
func parseRequest(req *http.Request, requireNamespace, requireGroup bool) (*Request, error) {
  userID, err := tenant.TenantID(req.Context())
  if err != nil {
    return nil, user.ErrNoOrgID
  }
  ...
  namespace, err := parseNamespace(vars)
  ...
  return &Request{
    UserID:    userID,
    Namespace: namespace,
    ...
  }, nil
}
```

随后 `ListRuleGroupsForUserAndNamespace(ctx, pr.UserID, pr.Namespace)` 本地存储做：

```text
Join(storeDir, userID, namespace)
```

过滤器刚看过的是 tenant 字符集；open 看到的是三段拼完、内核解析 `..` 之后的绝对路径。namespace 上没有第二次谓词。

双重编码怎么活过 HTTP 层：

```text
请求路径:  /loki/api/v1/rules/..%252f..%252fpcb_flag.yaml

net/http 解码一次 %25 → %
  仍是单个 path segment: ..%2f..%2fpcb_flag.yaml
  没有真正的 '/'，不会 301

parseNamespace 再 PathUnescape 一次
  ../../pcb_flag.yaml

Join("/loki/rules-src", "fake", "../../pcb_flag.yaml")
  /loki/pcb_flag.yaml
```

`X-Scope-OrgID: fake` 是合法 tenant，`ValidTenantID` 放行。穿越完全在 namespace 里完成。

---

## 仓库里已经有更强的检查，namespace 没用

`ValidTenantID` 已经禁止 `.` / `..` 以及 `/`。把它套在 namespace 上就能挡住解码后的 `../../pcb_flag.yaml`。Go 1.20+ 的 `filepath.IsLocal` 更直接：非本地（含 `..`、绝对路径）返回 false。

3.6.3 **两种都没挂到 `parseNamespace`**。`parseGroupName` 同样只有一次 Unescape——同一类洞，V2 一并加了 `IsLocal`。不是仓库里没有更好的谓词，是 **Join 的第二、第三个参数没用 tenant 那套规则**。

vendor advisory 说「36156 在单次 decode 之后验证 namespace」。对照 3.6.3 源码，namespace 上连这层验证都没有；单次 decode 的 `../` 其实被 `net/http` 挡在 handler 之外。能打到 `parseNamespace` 的，必须是双重编码。所以「单次 decode 后验证」更像是对「HTTP 已经 decode 一次」的描述，而不是 `parseNamespace` 里真有一个穿越检查。

---

## 这个补丁挡住了什么、没挡住什么

- V1 `ValidTenantID`：OrgID 不能是 `..`，不能含 `/`
- `parseNamespace`：Unescape 一次，原样返回
- 本地 store：`Join(dir, tenant, namespace)`，内核解析 `..`

```text
seed:
  X-Scope-OrgID: ..
  namespace: pcb_flag.yaml
  → TenantID 失败 → 500 "no org id"

residual:
  X-Scope-OrgID: fake
  namespace（线上）: ..%252f..%252fpcb_flag.yaml
  → Unescape → ../../pcb_flag.yaml
  → Join(rules-src, fake, ../../pcb_flag.yaml) → /loki/pcb_flag.yaml
```

明文 `GET /loki/api/v1/rules/../pcb_flag.yaml` 在所有版本上都 301，到不了这个 handler。residual 必须双重编码，这是 HTTP 规范化逼出来的，不是 V1 多加了一层 namespace 检查。

---

## 残余仍然走同一条 ruler Join（CVE-2026-21726）

没有换 API、没有换 store 目录。还是 `GET /loki/api/v1/rules/{namespace}`：

```http
GET /loki/api/v1/rules/..%252f..%252fpcb_flag.yaml
X-Scope-OrgID: fake
```

`parseRequest` 仍调用同一个 `parseNamespace`。V1 没有 `IsLocal`。Join 仍把解码后的 `../` 送进文件系统。YAML 被读回来，group 名是 flag。

本 case residual 与 Grafana advisory 的双重编码描述一致。认证：v1 + `--residual` 观察到 `PCBFLAG_...`。V2 上 500 `invalid namespace: path traversal not allowed`。

seed 被挡住只说明「不能再把 tenant 设成 `..`」，不说明「不能从 namespace 段爬出 store」。

平台 verify 与这条链是同一 sink：`filepath.Join(store, tenant, namespace)` 读 YAML。seed 打 tenant，residual 打 namespace，两个输入进同一次 Join。

---

## 后来又补了什么（CVE-2026-21726，3.6.4）

tag `v3.6.4` 的 `parseNamespace` 在 Unescape 之后加 `filepath.IsLocal`：

```go
// pkg/ruler/base/api.go :: parseNamespace  (loki v3.6.4)
  namespace, err := url.PathUnescape(namespace)
  if err != nil {
    return "", err
  }

  if !filepath.IsLocal(namespace) {
    return "", errors.New("invalid namespace: path traversal not allowed")
  }

  return namespace, nil
```

`parseGroupName` 同样加了 `IsLocal`（错误文案 `invalid groupname: ...`）。对残余：Unescape 得到 `../../pcb_flag.yaml`，`IsLocal` 为假，handler 在 Join 之前返回。公开建议升级到 ≥ 3.6.4。缓解：Ruler API 不要暴露给未校验租户的网络。

这仍然是「在字符串进 Join 之前拒绝非本地路径」。本 benchmark 的 v2 关闭这条双重编码 namespace residual。

---

## 从这条链还能看出什么

**维护者改错了哪一层。**  
他们改的是 tenant 字符集（36156 真正的输入）。真正出树的是 Join 的**整条**相对路径。V2 才把同样的「是不是本地路径」问到 namespace / groupName 上。

**不是没有更好的谓词。**  
`ValidTenantID` 和后来的 `filepath.IsLocal` 都现成。3.6.3 只把前者接到 OrgID。从 2.3.0 的 diff 只能看到 tenant；要判断是否闭合，必须看到 `parseNamespace` 的 return 和本地 store 的 Join 参数列表。

**同一 Join、两个用户输入。**  
消毒一个参数，另一个参数仍是相对路径，门就是开的。vendor 把 21726 写成 36156 的 bypass，指的就是这件事——即便他们把「被验证的那个参数」说成了 namespace。

**HTTP 规范化会逼出双重编码。**  
单次 `../` 到不了 handler 不等于 handler 安全。多一次 Unescape 就和 `net/http` 错开一层。

**金丝雀在 store 上一层是有意的。**  
`/loki/pcb_flag.yaml` 不是某个合法 namespace 里的文件。body 里出现 group 名，说明 Join 解析到了树外，Loki 把它当规则文件读了回来。

---

## 版本、入口、参考

| | 版本 | TenantID | `parseNamespace` | seed `OrgID=..` | residual `..%252f` |
|---|---|---|---|---|---|
| V0 | 2.2.1 | 无限制 | 一次 Unescape | 200，flag | （不必） |
| V1 | 3.6.3 | `ValidTenantID` | 一次 Unescape，无 IsLocal | 500 no org id | 200，flag |
| V2 | 3.6.4 | 同上 | Unescape + `filepath.IsLocal` | 挡 | 500 invalid namespace |

- seed：`GET /loki/api/v1/rules/pcb_flag.yaml` + `X-Scope-OrgID: ..`
- residual：`GET /loki/api/v1/rules/..%252f..%252fpcb_flag.yaml` + `X-Scope-OrgID: fake`
- [CVE-2021-36156](https://nvd.nist.gov/vuln/detail/CVE-2021-36156)、[CVE-2026-21726](https://grafana.com/security/security-advisories/cve-2026-21726/)
- [Loki PR #4020](https://github.com/grafana/loki/pull/4020)（Restrict path segments in TenantIDs）
- 源码：[`v3.6.3` `parseNamespace`](https://github.com/grafana/loki/blob/v3.6.3/pkg/ruler/base/api.go)、[`v3.6.4` `IsLocal`](https://github.com/grafana/loki/blob/v3.6.4/pkg/ruler/base/api.go)
