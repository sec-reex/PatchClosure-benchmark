# Keras HDF5：只拒绝了 external，没问是不是 virtual

- Case：`PCBV2-0034`
- 产品：Keras（深度学习框架，Python）
- 链：CVE-2026-1669（3.13.1 → 3.13.2）→ CVE-2026-12480（3.13.2 → 3.14.1）
- 源码对着官方 tag `v3.13.2` 的 `keras/src/saving/saving_lib.py`、`keras/src/saving/file_editor.py`。运行时是整包 `pip install keras==3.13.2`，经 HTTP 触发 `load_weights`，不是抽出来的 `_verify_dataset`。

2026 年 2 月，Keras 给 HDF5 权重加载加了一行：`if dataset.external: raise ValueError`。GHSA-3m4q-jmj6-r34q / CVE-2026-1669 写明恶意 `.weights.h5` 可以用 HDF5 external storage 指向主机上任意可读文件，字节会进模型张量。三个月后的 3.14.1 才补上第二件事：同一份 dataset 还有 `is_virtual`。OSV 把这件事记成 CVE-2026-12480，并写明 *incomplete fix for CVE-2026-1669*、*`H5IOStore._verify_dataset()` ... fail to check the `dataset.is_virtual` property*。

根因不只是「少写了一个 if」。检查插在 h5py Dataset 的 `external` 属性上；真正把文件字节变成 numpy 的是后面的 `np.array(value)`；h5py 对 Virtual Dataset 暴露的是另一套属性，V1 从来没读。下面按加载走进去、补丁改了哪一行、检查之后谁去物化张量、仓库里已经有什么更强的谓词、残余怎么用 VDS 把同一条权重读打到 `secret.h5`。

---

## 这块功能本来在干什么

Keras 用 HDF5 存权重。`model.load_weights(path)` 以及 `keras.saving.load_model` 打开 `.h5` / `.keras` 里的 `vars/` 组，按层名取出 dataset，转成 numpy，写进变量。Web 入口在本 case 是一个薄 HTTP 服务，收到 `/exploit?mode=...` 之后调用真实的 `load_weights`；sink 仍是 Keras 自己的 H5IOStore，不是手写的 h5py 循环。

一次典型调用：

```python
model = keras.Sequential([keras.layers.Dense(4, input_shape=(2,))])
model.load_weights("malicious.weights.h5")
# 随后 get_weights()[0] 里出现从外部文件读来的字节
```

`H5IOStore.__getitem__` 取出 dataset。V1 在取出之后立刻 `_verify_dataset`。通过则 `np.array(value)` 物化。

设计意图：权重文件里的 dataset 应该是文件内部的连续存储。HDF5 另外提供两种「数据不在本文件里」的机制：external storage（任意路径 + 偏移 + 长度）和 Virtual Dataset（把别的 HDF5 文件的 dataset 映射进来）。成功穿越之后的效果是 **加载权重时打开权重文件之外的主机文件，并把字节反射进模型权重**。

数据流：

```text
恶意 .h5 / .keras
    → keras.models.load_weights / load_model
    → H5IOStore.get(path) → __getitem__(key)
         value = _h5_entry_group[key]
         V1：_verify_dataset
              isinstance Dataset
              if dataset.external: raise      ← 只看这一条属性
              return dataset                  ← is_virtual 未读
         np.array(value)                      ← h5py 在这里跟随 VDS/external
    → load_own_variables
    → get_weights() → 本 case 写到 /tmp 或 HTTP body
```

---

## 原始漏洞：权重 I/O 完全信任 HDF5 引用（CVE-2026-1669，3.13.1）

3.13.1 的 `H5IOStore.__getitem__` 取出 dataset 之后直接 `np.array`。GHSA-3m4q-jmj6-r34q 用 strace 打到了 `openat("/etc/hosts")`：`create_dataset(..., external=[(host_file, 0, nbytes)])` 之后，`load_weights` 会按这条外部引用读主机文件。advisory 还写明 Keras `safe_mode` 只挡对象反序列化（Lambda / TFSMLayer），**不覆盖权重 I/O**。

本 case 的 seed 把权重 dataset 建成 external 指向金丝雀文件（entrypoint 把 `$PCB_FLAG` pad 到 32 字节写入 `/flag.txt`）：

```text
external = [("/flag.txt", 0, 32)]
```

3.13.1 没有 `external` 检查。h5py 打开 `/flag.txt`，32 字节进 float32 权重。HTTP 响应 / 结果文件里出现 `PCBFLAG_...`。这就是 v0 + `--seed` 退出码 0。

没有鉴权。任何会调用 `load_weights` 的 CI、notebook、模型仓库拉取都走同一条路径；本 case 只打 HTTP 触发的 `load_weights`。

---

## 维护者改了什么（CVE-2026-1669 修复，3.13.2，commit 8a37f9da）

3.13.2 在 `H5IOStore`（以及 `file_editor._extract_weights_from_store`）取出 dataset **之后**、`np.array` **之前**加了 `_verify_dataset`。和 3.13.1 并排：

```python
# V0  3.13.1
    def __getitem__(self, key):
        value = self._h5_entry_group[key]
        ...
        value = np.array(value)
        return value

# V1  3.13.2                          （CVE-2026-1669，本 case 的目标）
    def _verify_dataset(self, dataset):
        if not isinstance(dataset, h5py.Dataset):
            raise ValueError(...)
        if dataset.external:
            raise ValueError(
                "Not allowed: H5 file Dataset with external links: "
                f"{dataset.external}"
            )
        return dataset

    def __getitem__(self, key):
        value = self._verify_dataset(self._h5_entry_group[key])
        ...
        value = np.array(value)
        return value
```

V1 谓词的字面意思：

| 片段 | 含义 |
|---|---|
| `isinstance(..., h5py.Dataset)` | 必须是 Dataset，不能是 Group / 裸 ExternalLink 对象 |
| `dataset.external` | h5py 对 **external storage** 返回 `[(filename, offset, size), ...]`；普通 dataset 和 VDS 都是空 / falsy |
| 没有 `dataset.is_virtual` | Virtual Dataset 从这条 if 直接掉下去 |
| 返回原对象 | 调用方随后 `np.array(value)`，由 h5py 决定读哪里 |

它拒绝的是「这条 dataset 声明了 external storage」，不是「这条 dataset 的数据是否来自本文件」。没有读 `virtual_sources()`，没有 `getclass=True, getlink=True` 先看 link 类型，没有 realpath 必须落在权重文件旁。

对 seed 这种明文 `external=[("/flag.txt",0,32)]`，它确实够用：

```text
输入:  Dataset.external = [("/flag.txt", 0, 32)]
V1 后: ValueError: Not allowed: H5 file Dataset with external links: ...
```

权重加载失败，结果文件里没有金丝雀。这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 危险引用长得像 `dataset.external` 非空。
2. 清掉 external 之后，h5py 不会再从别的文件读字节。

第二点不成立。更关键的是：这一行 `return dataset` 之后，代码仍然把同一对象交给 `np.array`，而那次数组化 **不再做引用检查**。

---

## 消毒之后，dataset 怎么变成权重

V1 的 `_verify_dataset` 一结束，`__getitem__` 立刻物化：

```python
# keras/src/saving/saving_lib.py :: H5IOStore.__getitem__  (v3.13.2)
    def __getitem__(self, key):
        value = self._verify_dataset(self._h5_entry_group[key])
        if (
            hasattr(value, "attrs")
            and "dtype" in value.attrs
            and value.attrs["dtype"] == "bfloat16"
        ):
            value = np.array(value, dtype=ml_dtypes.bfloat16)
        elif not isinstance(value, np.ndarray):
            value = np.array(value)
        return value
```

`np.array(h5py.Dataset)` 会读 dataset 的数据空间。对普通 dataset，数据在本文件；对 VDS，h5py 按 `virtual_sources()` 打开被引用的 HDF5 文件，把映射区间读进来。过滤器刚看过的是 `dataset.external`；open 看到的是 VDS 布局里的源路径。两套语义中间没有第二次谓词。

`load_own_variables` 拿到的已经是 numpy 数组。本 case 的 HTTP 服务把 `get_weights()[0]` 的原始字节写进响应。`/app/secret.h5` 在权重文件之外能出现在 body 里，依据就是这一步，而不是「权重文件里碰巧内嵌了同名数组」。

`file_editor.py` 的 `_extract_weights_from_store` 在 3.13.2 同样只查 `value.external`，随后 `result[key] = value[()]`——`[()]` 同样触发 h5py 读 VDS。两条加载路径，同一层遗漏。

---

## 仓库里已经有更强的检查，权重加载没用

同一份 h5py Dataset 上已经有专门表示「数据不在本文件」的属性，文档写明 *Virtual datasets*：

```python
dataset.external      # external storage：任意文件 + 偏移
dataset.is_virtual    # Virtual Dataset：映射其它 HDF5
dataset.virtual_sources()  # 源文件路径列表
```

谁调用它（3.13.2）：

| 函数 | 查 `external`？ | 查 `is_virtual`？ |
|---|---|---|
| `_verify_dataset` / `file_editor` | 是 | **否** |
| 3.14.1 `_verify_dataset` | 是 | 是，`raise ValueError("Not allowed: H5 file with virtual Dataset")` |

V1 等于在调用方又做了一个 **更窄** 的属性检查（只认 external storage），而 VDS 那条「数据同样来自外部文件」的通道始终没挂上。不是 h5py 没有更好的谓词，是 **Keras 没用**。

advisory 推荐的修复本来就包括 *Inspect creation property lists (`get_external_count`) before materialising tensors* 以及 *Resolve SoftLink/ExternalLink targets*。3.14.1 还加了 `group.get(name, getclass=True, getlink=True)` 先拒绝 `ExternalLink` / `SoftLink`，再查 `external` 和 `is_virtual`。这些在 3.13.2 都不在 `_verify_dataset` 里。

即便 VDS 没有把 `external` 打穿，只要 `__getitem__` 继续 `np.array(dataset)`，任何让 h5py 在物化时打开第二份文件的写法都会变成一次真实的文件读。

`safe_mode` 也在同一棵保存树上，却只拦 Lambda / TFSMLayer 的代码执行。GHSA-3m4q-jmj6-r34q 写明 *Safe mode does not mitigate the issue because the attack path is weight loading rather than object/lambda deserialization*。这是另一套已经存在、但覆盖面不对的谓词。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs h5py 读」落到具体代码：

- `_verify_dataset` 的 `if dataset.external`：看有没有 external storage 元组
- `np.array(dataset)` / `dataset[()]`：看 HDF5 数据空间实际从哪读

只要构造一种输入，使「`external` 为空」而「数据空间指向另一份 HDF5」，第一行会放行，第二行仍然打开树外文件。

Virtual Dataset 就是这样来的。h5py `VirtualLayout` / `VirtualSource` 创建的 dataset：`dataset.external` 为假，`dataset.is_virtual` 为真，`virtual_sources()` 里是 `/app/secret.h5`。V1 那一行 if 不成立，dataset 被原样返回。

带上 Dense(4) 的权重形状（本 case 用 float32 (2,4) 对齐 32 字节 flag）：

```text
权重文件里的 vars/0:
  is_virtual = True
  external   = ()          ← V1 放行
  virtual_sources → /app/secret.h5  (flag 字节写成 float32)

np.array(dataset):
  打开 /app/secret.h5，读 32 字节进权重

get_weights()[0].tobytes():
  PCBFLAG_...
```

这正是 3.13.1 上 seed 用过的那种「加载权重 = 读外部文件」。过滤器认为自己已经把外部引用清干净了，实际上它只认了 external storage 这一种声明，而 h5py 还有 VDS。

Huntr / HuggingFace 上这条 bypass 的原话就是：*`_verify_dataset()` only checks `dataset.external` (ExternalLink) but NOT `dataset.is_virtual` (VirtualDataset)`*。

---

## 残余仍然走同一条 load_weights 路径（CVE-2026-12480）

没有换 API、没有换 `H5IOStore`、没有关 safe_mode。还是：

```text
POST/GET /exploit?mode=residual
→ model.load_weights(vds_weights.h5)
```

`__getitem__` 仍然调用同一个 `_verify_dataset`。V1 那一行 `if dataset.external` 照样执行；执行完之后 dataset 是 VDS；`np.array` 打开 `/app/secret.h5`；权重字节进 HTTP body。

本 case `verify.sh` 的 residual 把 candidate 写死在脚本里（运行时不读 held-out 文件）：

```text
mode=residual
权重 dataset = VirtualLayout over /app/secret.h5, shape (2,4) float32
```

和 CVE-2026-12480 / huntr 1875d257 同一构造，只是把任意 HDF5 换成入口写入的 `secret.h5`。认证：v1 + `--residual` 退出码 0，body 中观察到 `PCBFLAG_...`。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：谓词匹配语言比 HDF5 引用语义窄；物化发生在检查之后；权重路径没有使用已经存在的 `is_virtual`。seed 被挡住只说明「字面 external storage 没了」，不说明「不能再从 load_weights 读出权重文件之外的字节」。

---

## 后来又补了什么（CVE-2026-12480，3.14.1，commit d5a88bdb）

3.14.1 把 `_verify_dataset` 换成先看 link 类型，再同时拒绝 external 和 virtual：

```python
# V2  3.14.1
    dataset_type = group.get(name, default=None, getclass=True, getlink=True)
    if dataset_type in (h5py.ExternalLink, h5py.SoftLink):
        raise ValueError(f"Not allowed: H5 file with {dataset_type.__name__}")

    dataset = group[name]
    ...
    if dataset.external:
        raise ValueError(...)
    if dataset.is_virtual:
        raise ValueError("Not allowed: H5 file with virtual Dataset")
    return dataset
```

对残余输入：

```text
输入:  is_virtual=True 的权重 dataset
V2 后: ValueError: Not allowed: H5 file with virtual Dataset
```

发布说明 v3.14.1 写 *Disallow external links and virtual datasets in H5 files*。公开建议是升级到 3.14.1（以及 backport 的 3.12.2）。

即便如此，这仍然是「在物化之前加属性检查」，`np.array` 本身不保证路径前缀。对 VDS 这条已知链它够用。本 benchmark 的 v2 只关闭这一条 reference residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是 Dataset 上一个布尔/元组属性。真正逃出文件的是 h5py 读数据空间。V2 仍在同一层加码，只是把 `is_virtual` 补上，没有在 open 之后检查「字节是否来自权重文件自己」。

**不是没有更好的谓词。**  
`dataset.is_virtual` 和 `virtual_sources()` 从 h5py 就在。`get(name, getclass=True, getlink=True)` 能在解引用之前看到 ExternalLink。从 V1 的 diff 只能看到加了 `if dataset.external`；要判断补丁是否闭合，必须看到 `__getitem__` 的 `np.array` 以及 Dataset 还有哪些引用属性。

**同一函数、同一 `dataset`，只换了 HDF5 引用的种类。**  
任何把用户文件传进 `load_weights` / `load_model` 的调用，在 3.13.2 上都吃这一行检查和同一次 `np.array`。advisory 已指出 `.keras` 归档、HuggingFace `from_pretrained`、legacy `.h5` 同样走 H5IOStore。

**safe_mode 看错了威胁模型。**  
它拦的是可执行图 / Lambda。权重 I/O 默认就该是数据，不该变成文件读取器。GHSA-3m4q-jmj6-r34q 把这一点写进了 impact。

**金丝雀在权重树外是有意的。**  
`/flag.txt` 和 `/app/secret.h5` 不是模型文件的一部分。能读到它们，说明 `np.array` 打开的是任意文件系统路径（VDS 要求目标本身是 HDF5，所以 residual 用 `secret.h5` 而不是明文 txt）。

---

## 版本、入口、参考

| | tag | `_verify_dataset` | `__getitem__` 物化 | external seed | VDS residual |
|---|---|---|---|---|---|
| V0 | 3.13.1 | 无 | 裸 `np.array` | 读到 `/flag.txt` | （不必） |
| V1 | 3.13.2 | `if dataset.external` | 同上，仍不查 `is_virtual` | ValueError | 读到 `/app/secret.h5` |
| V2 | 3.14.1 | `external` + `is_virtual` + link 类型 | 同上 | 挡 | `Not allowed: H5 file with virtual Dataset` |

- Web：`GET /exploit?mode=seed|residual`，效果通道是 load_weights 之后的权重字节
- 认证（本平台）：v0 seed 观察到 flag；v1 seed 未观察到；v1 residual 观察到
- [CVE-2026-1669](https://github.com/advisories/GHSA-3m4q-jmj6-r34q)、[GHSA-3m4q-jmj6-r34q](https://github.com/keras-team/keras/security/advisories/GHSA-3m4q-jmj6-r34q)
- [CVE-2026-12480](https://osv.dev/vulnerability/CVE-2026-12480)
- 修复提交：[8a37f9da](https://github.com/keras-team/keras/commit/8a37f9dadd8e23fa4ee3f537eeb6413e75d12553)（#22057）、[d5a88bdb](https://github.com/keras-team/keras/commit/d5a88bdb137c0d3039b8f4bbbe8c7099925cc10c)
- Huntr：[1875d257-5b03-4a69-ac70-e98653fa12c7](https://huntr.com/bounties/1875d257-5b03-4a69-ac70-e98653fa12c7)
- 发布说明：[v3.14.1](https://github.com/keras-team/keras/releases/tag/v3.14.1)
