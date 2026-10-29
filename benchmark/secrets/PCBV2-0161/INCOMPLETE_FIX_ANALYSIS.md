# Glance：validate_external_location 丢掉了 file，没丢掉 glance_store 的另一个 scheme 名 filesystem

- Case：`PCBV2-0161`
- 产品：OpenStack Glance（镜像服务）。**产品面**是 v2 Image API 的 location 属性：认证用户把 URI 写进镜像，Glance 用 `glance_store` 去 get/delete。本平台 case 用 Python 2.7 harness 加载 pinned commit 的 `glance/common/store_utils.py`，再调用真实 `glance_store==2.0.1` 的 filesystem backend——同一条谓词和同一读盘 sink，但不是完整 `glance-api` 进程。incomplete-fix 链仍是 `validate_external_location` → `get_size_from_backend` / `get_from_backend`，不是另一个库。
- 链：CVE-2014-9493 / OSSA-2014-041（commit `4afdb017`）→ CVE-2015-1195 / OSSA-2015-002（commit `a2d986b9`）
- `a2d986b9` 提交说明原话：*A previous fix to CVE-2014-9493 attempted to address this issue but did not include 'filesystem', a URI scheme allowed by the glance_store.* NVD：*this vulnerability exists because of an incomplete fix for CVE-2014-9493.*

根因不只是「黑名单少写了一个单词」。检查插在「URI 的 scheme 字符串是不是 `file` / `swift+config`」上；真正打开主机文件的是 `glance_store` 按 scheme **注册表**选中的 filesystem store。那个 store 同时应答 `file` 和 `filesystem`。下面按 API 走进去。

---

## 这块功能本来在干什么

Glance v2 允许镜像带一组 location URI（Swift、S3、HTTP，以及错误配置下的本地文件）。管理员或有权用户：

```http
PATCH /v2/images/{id}
X-Auth-Token: ...
{"locations":[{"url":"file:///var/lib/glance/images/xxx","metadata":{}}]}
```

或创建镜像时带 `locations`。`glance.location` 里的 `StoreLocations.insert` / `ImageFactoryProxy.new_image` / `ImageProxy` 的 locations setter 都会先 `_check_image_location`，再把 URI 交给 store。设计意图：外部 location 只能是**远程**对象存储；Glance 进程用户能读到的 `/etc/passwd`、本 case 的 `/canary/secret.txt` **不能**当镜像数据源。成功穿越之后的效果是：**get_size / get_from_backend 按 URI 打开任意主机路径，把文件字节当镜像内容返回**。

数据流：

```text
v2 API 写入 image.locations[].url
    → StoreLocations.insert / set_attr / new_image
         _check_image_location(..., uri)
              V1：store_utils.validate_external_location(uri)
                   urlparse(uri).scheme 是否在 known_schemes 减去 {file, swift+config}
              且 store_api.get_size_from_backend(uri) > 0
         通过则写入 locations
    → 稍后 GET 镜像数据
         ImageProxy.get_data → store_api.get_from_backend(url)
              filesystem store 打开 URI 路径   ← 真正的 open，不再查 scheme 黑名单
    → body 出现 PCBFLAG_...
```

需要认证用户（NVD：*remote authenticated users*）。只影响 **v2** location（OSSA-2015-002）。v1 上传走另一套路径。金丝雀在 `filesystem_store_datadir` **之外**的 `/canary/secret.txt`。

`urlparse('filesystem:///canary/secret.txt')` 的 `scheme` 是 `filesystem`，`path` 是 `/canary/secret.txt`。`urlparse('file:///canary/secret.txt')` 的 scheme 是 `file`。Glance 把整段 URI 交给 store；store 再按 scheme 拆路径。两个 URI 在磁盘上打开**同一个文件**，差别只在 scheme 字符串。V1 的减法列表按字符串相等过滤，所以换名字就能换命运。

本平台 harness：`validate_external_location(uri)` 通过后立刻 `glance_store.get_from_backend`，跳过 WSGI。谓词和读盘与产品路径相同；没有完整 Keystone + glance-api。下文按产品 API 写调用关系，用 harness 只说明如何观察 flag。

---

## 原始漏洞：location 可以是 file:// 主机路径（CVE-2014-9493，`81b3c04e`）

`4afdb017` 之前，`_check_location_uri` 只问 store 能不能 `get_size`：

```python
# glance/location.py  补丁前
size = store_api.get_size_from_backend(uri, context=context)
is_ok = size > 0
```

filesystem backend 对 `file:///canary/secret.txt` 返回非零 size，location 被接受，随后 `get_from_backend` 读出文件。LP 1400966 / OSSA-2014-041。seed：

```text
file:///canary/secret.txt
```

V0 无 scheme 黑名单，读到金丝雀。这就是 v0 + `--seed`。`filesystem://` 在 V0 同样通，seed 只打 `file`，因为那是 9493 补丁明确从列表里抠掉的名字。

---

## 维护者改了什么（CVE-2014-9493 修复，`4afdb017`）

commit `4afdb017` *To prevent client use v2 patch api to handle file and swift location*。tag 即该 commit 的 `glance/common/store_utils.py`：

```python
# V1  4afdb017   （本 case 的目标）
def validate_external_location(uri):
    """
    Only over non-local store types are OK, i.e. S3, Swift, HTTP.
    Note the absence of 'file://' for security reasons,
    see LP bug #942118, 1400966, 'swift+config://' is also
    absent for security reasons, see LP bug #1334196.
    """
    pieces = urlparse.urlparse(uri)
    valid_schemes = [scheme for scheme in store_api.get_known_schemes()
                     if scheme != 'file' and scheme != 'swift+config']
    return pieces.scheme in valid_schemes
```

`_check_location_uri` 变成：

```python
is_ok = (store_utils.validate_external_location(uri) and
         store_api.get_size_from_backend(uri, context=context) > 0)
```

对 seed `file:///canary/secret.txt`：`pieces.scheme == 'file'`，不在 `valid_schemes`，返回 False，抛 `BadStoreUri`，不会 `get_from_backend`。这就是 v1 + `--seed` 退出码 10。

`valid_schemes` 是现场从 `get_known_schemes()` 滤出来的列表，不是写死的 HTTP/Swift/S3 白名单。只要 store 注册了一个 V1 没写进减法的本地别名，它就会留在 `valid_schemes` 里。`filesystem` 正好是这个别名。`swift+config` 被扣掉是因为 LP 1334196（配置里的凭据）；它和本地文件不是同一类，却和 `file` 写在同一行 `if` 里——说明这张表是「出过事的名字」而不是「本地 store 的全部 scheme」。

补丁默认了两件事：

1. 本地文件 store 的 scheme 名叫 `file`。
2. 从 `get_known_schemes()` 里扣掉几个字符串，剩下的都是「非本地」。

第二点不成立。`glance_store` 给**同一个** filesystem backend 注册了两个名字。更关键的是：检查只看 scheme **字符串**；通过之后 `get_size_from_backend` 仍按注册表选 backend，**不再**问「这是不是本地盘」。

注释里的 TODO 写着 *This function could be moved to glance_store*——作者知道真正懂 scheme 的是 store 库，却在 Glance 侧维护了一份不完整的减法列表。

---

## 消毒之后，这个 URI 怎么接到读盘上

`StoreLocations.insert` 在 V1 的顺序是固定的（`glance/location.py` 同 commit）：

```python
def insert(self, i, location):
    _check_image_location(self.image_proxy.context,
                          self.image_proxy.store_api,
                          self.image_proxy.store_utils,
                          location)
    location['status'] = 'active'
    ...
    self.value.insert(i, location)
    _set_image_size(..., [location])   # 再一次 get_size_from_backend
```

`validate_external_location` 为真之后，同一 `_check_location_uri` 立刻 `get_size_from_backend`。`__setitem__`、`new_image`、locations 的 `set_attr` 都走同一对函数。v2 下载走 `ImageProxy.get_data`：对每个 location 调 `get_from_backend`，第一个成功的就返回 iterator。harness 把「guard 通过 ⇒ 立刻 get_from_backend」压成一步，观察的仍是这次读盘。

`glance_store` 用 `urlparse` 取出 scheme，查 backend 注册表。filesystem store 对 `file` **和** `filesystem` 都注册了自己（store 入口的 `get_known_schemes()` / `_STORE_TYPES`）。`filesystem:///canary/secret.txt` 的 scheme 是 `filesystem`：

```text
'filesystem' != 'file'
'filesystem' != 'swift+config'
'filesystem' in get_known_schemes()   → True
validate_external_location            → True
get_size_from_backend                 → 打开 /canary/secret.txt，size>0
```

过滤器刚看过的是「名字是不是 `file`」；open 看到的是同一套本地路径解析。两套语义中间没有「realpath 必须落在 `filesystem_store_datadir` 下」，也没有「scheme 对应的 store 类是不是 FileStore」。

随后 `ImageProxy.get_data` 对每个 location 调 `get_from_backend`，把文件块当镜像流返回。harness 在 guard 通过后直接 `get_from_backend`，观察同一读盘。金丝雀在 datadir 外。body 里出现 `PCBFLAG_...`，依据是这次 **filesystem store 打开了任意路径**，不是 Glance 把 canary 存进了镜像库。

---

## 仓库里已经有更强的检查，减法列表没用全

`store_api.get_known_schemes()` **已经返回** `filesystem`。V1 从这份列表里只减去两个字符串。更强的做法在 V2 才出现，而且就在同函数：

```python
# V2 a2d986b9
RESTRICTED_URI_SCHEMAS = frozenset(['file', 'filesystem', 'swift+config'])
scheme = urlparse.urlparse(uri).scheme
return (scheme in store_api.get_known_schemes() and
        scheme not in RESTRICTED_URI_SCHEMAS)
```

V2 注释还加了 *TODO: Use a whitelist of allowed schemes*——连作者都认为减法不如白名单。V1 已经在遍历 `get_known_schemes()`，却不按 **backend 类型**（本地 vs 远程）过滤，只按三个魔法字符串。不是没有「这个 scheme 是不是本地文件」的信息，是 **validate_external_location 没用 store 的类型，只用了两个名字**。

v1 images API 里对 file location 另有检查（commit message 引用 `glance/api/v1/images.py#L429`）；v2 想复用同一逻辑，复制时漏了 `filesystem`。OSSA-2015-002 写明 *Only setups using the Glance V2 API are affected*——v1 那条旧检查反而让 Icehouse/Juno 的 v1-only 部署逃过 1195。本 case 盯的是 v2 locations 谓词。

`get_size_from_backend` 在 guard **之后**仍会打开 URI：它既是「这个 location 有没有数据」的健康检查，也是一次真实读盘。即便有人只 add location 不 download，size 检查本身已经碰了 `/canary/secret.txt`。harness 用 `get_from_backend` 把字节读进响应，好让 flag 出现在 HTTP body。

---

## 这个补丁挡住了什么、没挡住什么

- `validate_external_location`：看 `urlparse(uri).scheme` 是否等于 `file` 或 `swift+config`
- `get_from_backend`：看 glance_store 把这个 scheme 派给哪个 backend

```text
file:///canary/secret.txt         → scheme=file        → V1 拦
filesystem:///canary/secret.txt   → scheme=filesystem  → V1 放行 → 同一 FileStore 读盘
```

`get_known_schemes()` 在装了 filesystem store 的配置下至少包含 `file`、`filesystem`、`http` 等。V1 的列表推导是：

```python
valid_schemes = [s for s in store_api.get_known_schemes()
                 if s != 'file' and s != 'swift+config']
# filesystem 仍在
```

Jin Liu（OSSA-2015-002 / LP 1408663）报的就是：OSSA-2014-041 只修了 `swift:` 和 `file:`，漏了 `filesystem:`。Red Hat：*the fix for CVE-2014-9493 was incomplete*。删除和下载是同一 guard：location 一旦被接受，`delete_from_backend` 也能打到那条主机路径；NVD 写 *read or delete arbitrary files*。本 case 只观察读。

---

## 残余仍然走同一条 location 读盘（CVE-2015-1195）

没有换 API 版本、没有换 backend。还是 v2 locations → `_check_location_uri` → `validate_external_location` → `get_size_from_backend` / `get_from_backend`。V1 那两行 `scheme != 'file'` 照样执行；`filesystem` 不匹配；FileStore 打开 `/canary/secret.txt`。

平台 residual candidate 是 `scheme=filesystem, path=/canary/secret.txt`。它打的是 **同一个 filesystem store 读盘 sink**，只换了 scheme 字符串。不是 Swift 删除、不是 v1 上传。harness 与产品 API 相比少了 HTTP/鉴权层，**没有**换到另一个 sink。

seed 被挡住只说明「字面 `file` 没了」，不说明「不能再让 Glance 进程读 datadir 外的文件」。

`swift+config` 在 V1 已经被减掉，本 case residual 不走它。`http://` 指向 sidecar 会是另一类 SSRF，也不是这条 incomplete-fix：9493/1195 的闭合条件是「本地 filesystem store 的全部 scheme」。`filesystem` 是那个集合里漏掉的名字。

---

## 后来又补了什么（CVE-2015-1195，`a2d986b9`）

`RESTRICTED_URI_SCHEMAS` 含 `file`、`filesystem`、`swift+config`。`filesystem:///canary/secret.txt` 的 scheme 在集合里，guard 返回 False。公开建议：kilo-1 / 2014.2.2 (Juno) / 2014.1.4 (Icehouse)。OSSA-2015-002 还建议轮换 Glance 能读到的凭据文件。

即便如此，这仍然是 scheme 字符串减法。白名单 TODO 没做。对本 benchmark 的 `filesystem://` residual 它够用。

---

## 从这条链还能看出什么

**维护者改错了哪一层。**  
他们改的是 Glance 侧的 scheme 名字列表。真正打开文件的是 glance_store 的 FileStore。V2 仍在同一列表加码，没有在 open 之后强制路径前缀，也没有按 store 类拦截。

**不是没有更好的谓词。**  
`get_known_schemes()` 已经列出 `filesystem`。把「该 backend 是否本地」放进 glance_store（commit message 自己也说还要在 store 里修）比在调用方减两个字符串更接近「禁止本地 location」。从 `4afdb017` 只能看到扣掉 `file`；要判断是否闭合，必须看 store 注册了哪些别名。

**同一 `validate_external_location`、同一 FileStore，只换了 scheme 写法。**  
任何把用户 URI 送进 v2 locations 的调用，在 `4afdb017` 上都吃这张减法表和同一次 `get_from_backend`。

**金丝雀在 datadir 外是有意的。**  
`/canary/secret.txt` 不是 Glance 镜像。能读到它，说明 store 打开了任意主机路径。

平台 harness 用 stub 填 `glance.db` 等 import，**没有改** `validate_external_location` 的字节。flag 只在 guard 放行且 `get_from_backend` 读到 canary 时出现。这和完整 glance-api 上 PATCH locations 再 GET 数据是同一谓词、同一 FileStore；差别只在有没有 WSGI。不能把 harness 当成「另一个 sink」。

---

## 版本、入口、参考

| | commit | `validate_external_location` | FileStore | `file://` seed | `filesystem://` residual |
|---|---|---|---|---|---|
| V0 | `81b3c04e` | 无此函数；只 `get_size>0` | 两种 scheme 都读盘 | 读到金丝雀 | （不必） |
| V1 | `4afdb017` | 减去 `file`、`swift+config` | 同上 | `BadStoreUri` | 读到金丝雀 |
| V2 | `a2d986b9` | `RESTRICTED_URI_SCHEMAS` 含 `filesystem` | 同上 | 挡 | 挡 |

- 产品 API：Glance v2 `PATCH /v2/images/{id}` 的 `locations`（以及 create 时带 locations）；随后 GET 镜像数据
- 本平台：harness 调同一 `validate_external_location` + `glance_store.get_from_backend`（非完整 glance-api）
- V1 blob：[`4afdb017` store_utils.py](https://github.com/openstack/glance/blob/4afdb017aa1ccef01482f117cb8d0736a6da38ed/glance/common/store_utils.py) `validate_external_location`；同 commit [`location.py`](https://github.com/openstack/glance/blob/4afdb017aa1ccef01482f117cb8d0736a6da38ed/glance/location.py) `_check_location_uri`
- V2 blob：[`a2d986b9` store_utils.py](https://github.com/openstack/glance/blob/a2d986b976e9325a272e2d422465165315d19fe6/glance/common/store_utils.py)
- [OSSA-2014-041](https://security.openstack.org/ossa/OSSA-2014-041.html) / [CVE-2014-9493](https://nvd.nist.gov/vuln/detail/CVE-2014-9493)
- [OSSA-2015-002](https://security.openstack.org/ossa/OSSA-2015-002.html) / [CVE-2015-1195](https://nvd.nist.gov/vuln/detail/CVE-2015-1195)
- [LP 1408663](https://launchpad.net/bugs/1408663)、[commit a2d986b9](https://github.com/openstack/glance/commit/a2d986b976e9325a272e2d422465165315d19fe6)
