# MLflow artifact_location：query 里的 `..` 查了，fragment 里的没查

- Case：`PCBV2-0145`
- 产品：MLflow Tracking Server（`mlflow server --serve-artifacts`）
- 链：CVE-2023-6909（2.9.1 → 2.11.0 窗口；修复始于 2.9.2，commit `1da75dfcec` / `0f416e170d`）→ CVE-2024-3848（2.11.0 → 2.12.1，commit `f8d51e2152`）
- 源码对着 GitHub tag `v2.11.0` 的 `mlflow/utils/uri.py`（`validate_query_string`、`validate_path_is_safe`、`append_to_uri_path`）以及 V1 的 `_create_experiment`（commit `0f416e17` 挂上的 `urlparse` + `validate_query_string`）。运行时是整包 `pip install mlflow==2.11.0`，不是抽出来的函数。

2023 年末，MLflow 给实验的 `artifact_location` 加了 query 检查：`urlparse` 之后只把 `parsed.query` 交给 `validate_query_string`，里面有 `..` 就 400。这挡住了 `http://host?/../../../../` 这种「`..` 藏在 `?` 后面、拼 run 路径时插到 query 之前、再被当成本地路径 resolve 到 `/`」的读文件链。NVD CVE-2023-6909 写的是 *Path Traversal: '\..\filename' ... prior to 2.9.2*。半年后 huntr `8d5aadaa` / CVE-2024-3848 指出：同一处 `urlparse` 已经把 `#` 后面拆进 `fragment`，V1 **不看** `parsed.fragment`。NVD 写明 *identified as a bypass for the previously addressed CVE-2023-6909*，*a '#' character can be used to insert a path into the fragment, effectively skipping validation*。

根因不只是「少写了一个 `if fragment`」。检查插在「query 字符串里有没有 `..`」这一层；真正打开文件的是稍后 `_validate_source` 把整段 URI 当本地路径 `Path.resolve()`；同文件里已经有 `validate_path_is_safe` 会拒绝 `#`，却只挂在 artifact **相对路径**上，不挂在 `artifact_location` 整 URL 上。下面按 API 走进去、2.11.0 改了哪几行、校验之后谁真正 resolve、更宽的 `#` 检查有没有挂上，把这几层写完。

---

## 这块功能本来在干什么

MLflow 跟踪服务让调用方在创建实验时指定 artifact 根：`POST /api/2.0/mlflow/experiments/create` 的 `artifact_location`。之后每个 run 会在这个根后面拼 `/<run_id>/artifacts`。模型版本注册时 `_validate_source` 要求 `source` 落在该 run 的 artifact 目录里（或被当成合法远程）。`GET /model-versions/get-artifact` 再按版本去读文件。

一次典型（也是本 case 的）链：

```http
POST /api/2.0/mlflow/experiments/create
{"name":"pcb","artifact_location":"http://host?/../../../../../../../../../"}

POST /api/2.0/mlflow/runs/create
{"experiment_id":"..."}

POST /api/2.0/mlflow/registered-models/create
{"name":"pcb_model"}

POST /api/2.0/mlflow/model-versions/create
{"name":"pcb_model","source":"/","run_id":"..."}

GET /model-versions/get-artifact?path=canary.txt&name=pcb_model&version=1
```

设计意图：`artifact_location` 可以是 `s3://` / `http://` / 本地目录，但拼完、resolve 完之后，模型版本不能用它读到 artifact 根**外面**的文件。成功穿越之后的效果是读出 `/canary.txt`（entrypoint 写入的 `PCB_FLAG`，在 `/mlartifacts` 树外）。

数据流：

```text
artifact_location 字符串
    → _create_experiment
         parsed = urlparse(artifact_location)
         V1：validate_query_string(parsed.query)     ← 补丁插在这里，只看 query
         原样存进 store
    → 创建 run：append_to_uri_path(root, run_id, 'artifacts')
         路径插在 query/fragment **之前**
    → _validate_source(source='/', run_id)
         local_file_uri_to_path(run.artifact_uri)
         Path(...).resolve()                         ← 真正的上溯，不再看 query 检查
         若 resolve 到 '/'，source '/' 算「在目录内」
    → get-artifact path=canary.txt
         打开 /canary.txt → HTTP body
```

没有鉴权（本 case 的 tracking server 默认开放）。判断完全信任「危险的 `..` 只会出现在 query 里」，不信任稍后整段 URI 被当成文件系统路径时 `#` 只是普通字符。

---

## 原始漏洞：artifact_location 完全不查（CVE-2023-6909，2.9.1）

2.9.1 的 `_create_experiment` 在取完 `request_message.artifact_location` 之后直接 `create_experiment`，中间没有 `urlparse`、没有 `..` 检查。PR #10653 把问题说清楚：拼 run 路径时，`/<run_id>/artifacts` 插在 `?` **前面**，query 里的 `../` 在「把整段当本地路径」时变成真正的上溯：

```text
artifact_location = http://host?/../../../../../../../../../
存下来的 run URI ≈ http://host/<run_id>/artifacts?/../../../../../../../../../
当本地路径 resolve → /
```

`?` 变成目录名里的一个字符（`artifacts?`），后面的 `../` 照样往上走。`_validate_source` 看到 `run_artifact_dir == PosixPath('/')`，于是 `source='/'` 合法。`get-artifact?path=canary.txt` 读到 `/canary.txt`。

本 case 的 seed 就是这条 `?` 链。2.9.1 上 body 里出现 `PCBFLAG_...`。这就是 v0 + `--seed` 退出码 0。

---

## 维护者改了什么（CVE-2023-6909 修复，进入 2.11.0 的形态）

commit `0f416e170d105a70df255600c5e5fef0181e48de`（PR #10653，*Disable '..' in query string for artifact URI*）在 `_create_experiment` 入口、写入 store **之前**加了：

```python
# mlflow/server/handlers.py :: _create_experiment
# (commit 0f416e17，v2.11.0 仍是这一形态)
# Validate query string in artifact location to prevent attacks
parsed_artifact_locaion = urllib.parse.urlparse(request_message.artifact_location)
validate_query_string(parsed_artifact_locaion.query)

experiment_id = _get_tracking_store().create_experiment(
    request_message.name, request_message.artifact_location, tags
)
```

`validate_query_string` 在 tag `v2.11.0` 的 `mlflow/utils/uri.py`：

```python
# mlflow/utils/uri.py :: validate_query_string / _decode  (mlflow v2.11.0)
def validate_query_string(query):
    query = _decode(query)
    # Block query strings contain any traveral path (../) because they
    # could be resolved as part of the path and allow path traversal.
    if ".." in query:
        raise MlflowException("Invalid query string", error_code=INVALID_PARAMETER_VALUE)

def _decode(url):
    # Keep decoding until the url stops changing (with a max of 10 iterations)
    for _ in range(10):
        decoded = urllib.parse.unquote(url)
        if decoded == url:
            return url
        url = decoded
    raise ValueError("Failed to decode url")
```

`append_to_uri_path` 里也对 `parsed_uri.query` 调了一次同一函数，防止拼路径时再把 `..` 带进 query。

V1 的字面意思：只检查 URL **query**（`?` 后面、`#` 前面）解码后有没有子串 `..`。`urlparse` 已经把 `#` 后面放进 `.fragment`，那一段根本不进 `validate_query_string`。

对 seed 这种明文 `?../..`，它确实够用：

```text
artifact_location = http://host?/../../../../../../../../../
urlparse.query = /../../../../../../../../../
".." in query → MlflowException Invalid query string
HTTP 400 INVALID_PARAMETER_VALUE
到不了 create run / get-artifact
```

这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 能让后续 `Path.resolve` 上溯的 `..` 只会出现在 query 里。
2. 看过 query 之后，整段 URI 当本地路径时不会再从**别的 URL 部件**里长出 `..`。

第二点不成立。`urlparse` 的 `fragment` 和 `query` 是对称的两个部件；拼路径同样插在它们前面；当本地路径时 `#` 和 `?` 一样是普通字符。

---

## 校验之后，谁真正 resolve 到 /

V1 的 `validate_query_string` 一通过，`artifact_location` **原样**进 store，包括 `#` 和后面的字符。创建 run 时 `append_to_uri_path` 只再查一次 query（此时为空），把 `run_id/artifacts` 插进 path。得到类似：

```text
http://host/<run_id>/artifacts#/../../../../../../../../
```

`_validate_source` 在 V1 上把 `run.info.artifact_uri` 交给 `local_file_uri_to_path`。这不是 `file:` URI，函数按原始字符串当路径处理。`#` 变成 `artifacts#` 这种目录名字符，后面的 `/../` 被 `Path.resolve()` 按 POSIX 上溯到 `/`。

于是 `source='/'` 通过「必须落在 run artifact 目录内」的检查——因为那个目录已经被 resolve 成了 `/`。`get-artifact?path=canary.txt` 打开的是 `/canary.txt`。

过滤器刚看过的是 `parsed.query`（空字符串）；open 看到的是拼完、把 `#` 当字面量之后的文件系统路径。两套语义中间没有第二次「整段里还有没有 `..` / 还有没有 fragment」的谓词。

---

## 仓库里已经有更强的 `#` 检查，artifact_location 没用

同一份 `uri.py` 里，`validate_path_is_safe` 在 V1 就已经拒绝 `#`：

```python
# mlflow/utils/uri.py :: validate_path_is_safe  (mlflow v2.11.0)
def validate_path_is_safe(path):
    """
    Validates that the specified path is safe to join with a trusted prefix.
    ...
    """
    path = _decode(path)

    exc = MlflowException("Invalid path", error_code=INVALID_PARAMETER_VALUE)
    if "#" in path:
        raise exc
    ...
    if (
        any((s in path) for s in _OS_ALT_SEPS)
        or ".." in path.split("/")
        ...
    ):
        raise exc
    return path
```

谁调用它：

| 值 | 调用 `validate_path_is_safe`？ |
|---|---|
| artifact **相对** path（下载参数等） | 是，含 `#` 或 `..` 直接 400 |
| `artifact_location` 整 URL | **否**，只把 `.query` 交给 `validate_query_string` |

不是仓库里没有「`#` 不能出现在路径里」这份谓词。V1 等于在 `_create_experiment` 又做了一个**更窄**的检查（只认 query 里的 `..`），而 path 安全函数那张同时管 `#` 和 `..` 的表始终没挂到 artifact 根 URL 上。

`urlparse` 自己就有 `.fragment`。V2 后来写的就是 `if parsed.fragment: raise ...`。这不是 2.12 才发明的 API。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs resolve」落到具体代码：

- `validate_query_string(parsed.query)`：看 `?` 和 `#` 之间有没有 `..`
- `Path(local_file_uri_to_path(run.artifact_uri)).resolve()`：看整段字符串当路径时内核怎么上溯

只要把 `..` 从 `?` 挪到 `#` 后面，第一行看到的是空 query，第二行仍然爬到 `/`。

token 变换：

```text
seed:     http://host?/../../../../../../../../../
          urlparse.query    = /../../../../../../../../../
          urlparse.fragment = ""
V1:       ".." in query → 400

residual: http://host#/../../../../../../../../
          urlparse.query    = ""
          urlparse.fragment = /../../../../../../../../
V1:       validate_query_string("") 通过
          存下带 # 的 URI
          run URI ≈ http://host/<run_id>/artifacts#/../../../../../../../../
          resolve → /
          get-artifact canary.txt → /canary.txt
```

`?` 换成 `#` 是唯一的变换。`..` 段、后面的模型注册、`source='/'`、`path=canary.txt` 与 seed 相同。huntr / NVD 原话就是 *a '#' character can be used to insert a path into the fragment*。

V1 拦的是「query 部件里的 `..` 子串」；CVE-2023-6909 真正要拦的是「不能靠 artifact_location 让 resolve 逃出 artifact 根」。后者在 fragment 上原样还在。

---

## 残余仍然走同一条实验投毒 + get-artifact 读文件路径（CVE-2024-3848）

没有换 API、没有换 sink、没有换金丝雀文件。还是 create experiment → create run → 注册模型版本 `source=/` → `get-artifact`：

```text
artifact_location = http://host#/../../../../../../../../
```

`_create_experiment` 仍然先 `urlparse`；`.query` 为空，`.fragment` 不查；store 收下带 `#` 的根；`_validate_source` 把 URI 当本地路径 resolve 到 `/`；`get-artifact` 读出 `/canary.txt`。

本 case `verify.sh` 的 residual 把 candidate 写死在脚本里。和 heldout / huntr 描述的 fragment 链同一构造。认证：v1 + `--residual` 退出码 0，body 中观察到 `PCBFLAG_...`。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：检查只看 `urlparse.query`；拼路径和 resolve 发生在检查之后，且把 `#` 当字面量；`validate_path_is_safe` 已经拒绝 `#` 却没挂到 artifact_location 上。seed 被挡住只说明「`?` 后面不能再放 `..`」，不说明「不能再从 get-artifact 读出树外文件」。

平台 verify 的 residual 打的就是这条 incomplete-fix 链上的同一 `get-artifact` 读，不是另一条无关 sink。V2 上 create_experiment 会因 fragment 直接 400（heldout 打印 `BLOCKED:create_experiment`）。

---

## 后来又补了什么（CVE-2024-3848，2.12.1）

commit `f8d51e21523238280ebcfdb378612afd7844eca8` 在同一处 `urlparse` 之后先拒 fragment，并收紧 `_validate_source`：只有 `is_local_uri(run.info.artifact_uri)` 为真时才信任 resolve 出来的本地目录：

```python
# mlflow/server/handlers.py  (commit f8d51e21)
parsed_artifact_locaion = urllib.parse.urlparse(request_message.artifact_location)
if parsed_artifact_locaion.fragment:
    raise MlflowException(
        "'artifact_location' URL can't include fragment part.",
        error_code=INVALID_PARAMETER_VALUE,
    )
validate_query_string(parsed_artifact_locaion.query)
```

对残余输入：`.fragment` 非空 → 400，到不了 create run。Snyk 写的修复版本是 2.11.2 / 2.12.1；本 case 负对照用 2.12.1。公开建议是升级到含 `f8d51e21` 的版本。

即便如此，这仍然是「在存 store 之前再多看一个 URL 部件」。`_validate_source` 的 `is_local_uri` 是第二道闸，避免把 `http://...#/../` 这种非本地 URI 的 resolve 结果当成可信根。对 `#` 这条已知链，入口那道 fragment 检查就够用。本 benchmark 的 v2 只关闭这一条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是 `urlparse.query` 这一部件。真正逃出树的是把整段 URI 当路径的 `Path.resolve()`。V2 仍在入口加码（多看 `.fragment`），同时也开始在 `_validate_source` 问「这是不是本地 URI」——后者更接近 sink。

**不是没有更好的谓词。**  
`validate_path_is_safe` 同时拒绝 `#` 和 `..`，比「只扫 query」更接近「这段字符串稍后会被当路径」。它已经用在下载 path 上。从 V1 的 diff 只能看到 `validate_query_string(parsed.query)`；要判断补丁是否闭合，必须看到 `urlparse.fragment` 和 `_validate_source` 的 resolve。

**同一条 create-experiment → get-artifact 链，只换了分隔符。**  
任何把用户 `artifact_location` 存下来再当本地路径 resolve 的调用，在 2.11.0 上都吃这次 query-only 检查。advisory 写的就是用 `#` 代替校验过的那一段。

**`urlparse` 的拆法就是绕过。**  
维护者用 `urlparse` 是为了「只查 query、保留合法 query（例如 S3 region）」。PR #10653 讨论过「丢掉 `?` 后面」和「忽略 query」的替代，选了窄检查。`#` 是同一拆法下没被选中的部件。

**金丝雀在树外是有意的。**  
`/canary.txt` 不在 `/mlartifacts` 里。能读到它，说明 `get-artifact` 打开的是任意文件系统路径，而不是实验目录里碰巧有个同名文件。

---

## 版本、入口、参考

| | pip | `_create_experiment` | `_validate_source` | seed `http://host?/../..` | residual `http://host#/../..` |
|---|---|---|---|---|---|
| V0 | 2.9.1 | 不查 artifact_location | resolve 整段当路径 | 读到 canary | （不必） |
| V1 | 2.11.0 | 只 `validate_query_string(query)` | 同上 | 400 Invalid query string | fragment 不查，读到 canary |
| V2 | 2.12.1 | 拒 fragment + 仍查 query | 先 `is_local_uri` 才信 resolve | 挡 | 400 can't include fragment |

- Web：`POST /api/2.0/mlflow/experiments/create` → run → model-version → `GET /model-versions/get-artifact`
- 认证（本平台）：v0 seed 观察到 flag；v1 seed 未观察到；v1 residual 观察到
- [CVE-2023-6909](https://nvd.nist.gov/vuln/detail/CVE-2023-6909)、[CVE-2024-3848](https://nvd.nist.gov/vuln/detail/CVE-2024-3848)
- [GHSA-rfqq-wq6w-72jm](https://github.com/advisories/GHSA-rfqq-wq6w-72jm)
- [huntr 8d5aadaa](https://huntr.com/bounties/8d5aadaa-522f-4839-b41b-d7da362dd610)（CVE-2024-3848）
- [huntr 11209efb](https://huntr.com/bounties/11209efb-0f84-482f-add0-587ea6b7e850)（CVE-2023-6909）
- V1 相关 commit：[0f416e170d](https://github.com/mlflow/mlflow/commit/0f416e170d105a70df255600c5e5fef0181e48de)、[1da75dfcec](https://github.com/mlflow/mlflow/commit/1da75dfcecd4d169e34809ade55748384e8af6c1)
- V2 commit：[f8d51e2152](https://github.com/mlflow/mlflow/commit/f8d51e21523238280ebcfdb378612afd7844eca8)
- 源码：`https://github.com/mlflow/mlflow/blob/v2.11.0/mlflow/utils/uri.py`
