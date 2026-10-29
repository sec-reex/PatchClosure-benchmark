# Nova：安全检查按 Glance 声称的 disk_format 选路，qemu-img 被强迫相信这个声称

- Case：`PCBV2-0162`
- 产品：OpenStack Nova（计算服务）。镜像从 Glance 下载之后，计算节点用 `nova/virt/images.py::fetch_to_raw` 做安全检查再交给 qemu-img。本 case 把同一份 pinned 的 `images.py` / `format_inspector.py` 接到 HTTP `/read`，sink 仍是真实的 `qemu-img`。
- 链：CVE-2022-47951（OSSA-2023-002，`check_vmdk_image` create-type 白名单）+ CVE-2024-32498（OSSA-2024-001，`format_inspector` 深检）→ CVE-2024-40767（OSSA-2024-002）。NVD 原文：*this issue exists because of an incomplete fix for CVE-2022-47951 and CVE-2024-32498*。
- 源码对着 master `1191a49a65dce694b12df26bb5316b0a816b278e` 的 `nova/virt/images.py`、`nova/image/format_inspector.py`。V0 是 `a90bd50887c45de1e1ee3cb4f0901ae62fcf9bfd`（OSSA-2023-002 之前）。V2 是 `8b4c522f6699514e7d1f20ac25cf426af6ea588f`。

2023 年 Nova 给 VMDK 加了 create-type 白名单，拦住 `monolithicFlat` 这种能指向宿主机任意文件的描述符。2024 年 OSSA-2024-001 又加了 `format_inspector` 深检，并且把随后的 `qemu-img info` 强迫成 Glance 声称的格式。Arnaud Morin 指出：上传者只要把同一份 VMDK **声称成 `raw`**，深检会走 Raw 检查器，qemu-img 也被强迫当 raw 看，VMDK 那条白名单根本不会跑。NVD 把这件事记成 CVE-2024-40767。

根因不只是「又漏了一种镜像格式」。检查插在「调用方声称这是什么格式」上；真正打开 extent / backing file 的是后面那次 qemu-img。同一份 `format_inspector.py` 里已经有按文件内容探测格式的 `detect_file_format`，V1 的 `do_image_deep_inspection` 没用。下面按 Glance 元数据走进去。

---

## 这块功能本来在干什么

Nova 从 Glance 拉镜像，转换成计算节点能用的 raw 盘。入口是 `fetch_to_raw(context, image_href, path)`：先 `IMAGE_API.download` 落到 `path.part`，再深检，再 `qemu-img info`，必要时 `convert_image`。Glance 里每张镜像带 `disk_format`（`raw` / `qcow2` / `vmdk` …），这是**上传者填写的元数据**，不是文件头。

一次典型计算路径（本 case 用 HTTP 把同一扇门露出来）：

```http
GET /read?claim=vmdk&extent=/canary/secret.txt
```

`claim` 相当于 Glance 的 `disk_format`。`extent` 写进一份 `monolithicFlat` VMDK 描述符，FLAT 段指向容器里、镜像仓库之外的金丝雀。`fetch_to_raw` 若放行，后续 `qemu-img` 按 VMDK 语义去打开那个 extent，金丝雀字节出现在响应 body。

数据流：

```text
Glance disk_format（用户声称） + 镜像字节
    → fetch_to_raw
         IMAGE_API.get → img['disk_format']
         do_image_deep_inspection(img, path)
              V1：inspector = get_inspector(disk_format)   ← 按声称选检查器
                  inspector.from_file(path).safety_check()
              返回 force_format = disk_format（或 ami→raw）
         qemu_img_info(path, format=force_format)          ← V1 把声称喂给 qemu
         若 fmt=='vmdk'：check_vmdk_image（create-type 白名单）
         若有 backing_file / data-file：拒绝
         必要时 convert_image(..., in_format=fmt, out_format='raw')
    → 计算节点使用转换后的盘
```

设计意图：无论上传者怎么写 `disk_format`，有外部引用的 QCOW2 / VMDK 都不能把宿主机文件读进实例盘。成功穿越之后的效果是 **qemu-img 打开描述符里的 FLAT extent，把 `/canary/secret.txt` 的内容吐出来**。需要能向 Glance 上传镜像的身份；本 case 把声称和 extent 做成查询参数，检查函数仍是 Nova 那一份。

---

## 原始漏洞：明文 VMDK Flat 描述符（CVE-2022-47951，commit a90bd508）

OSSA-2023-002 之前，`fetch_to_raw` 对 VMDK 没有 create-type 限制。一份标准的 `monolithicFlat` 描述符长这样：

```text
# Disk DescriptorFile
version=1
createType="monolithicFlat"
...
RW 1 FLAT "/canary/secret.txt" 0
```

qemu-img 按 VMware 语义打开 FLAT 段，读的是描述符里写的**宿主机路径**，不是镜像仓库里的某个 blob。本 case seed 诚实声称 `disk_format=vmdk`，extent 指向 `/canary/secret.txt`。V0 没有 `format_inspector`，也没有 `check_vmdk_image`，`qemu-img info` 识别成 vmdk 之后照样转换，body 里出现 `PCBFLAG_...`。

这就是 v0 + `--seed` 观察到金丝雀。攻击者不需要谎报格式——当时诚实的 `vmdk` 就已经够用。

---

## 维护者改了什么（CVE-2022-47951 + OSSA-2024-001，commit 1191a49a）

V1 叠了两层，都还挂在「Glance 声称的格式」上。

第一层是 47951 的 `check_vmdk_image`：从 **qemu-img 已经识别为 vmdk** 的 `format_specific['data']['create-type']` 里取出类型，不在 `vmdk_allowed_types` 里就拒绝。`monolithicFlat` 默认不在白名单。

第二层是 OSSA-2024-001 的深检。V1 的 `do_image_deep_inspection` 原文：

```python
# nova/virt/images.py :: do_image_deep_inspection  (1191a49a)
def do_image_deep_inspection(img, image_href, path):
    disk_format = img['disk_format']
    try:
        inspector_cls = format_inspector.get_inspector(disk_format)
        if not inspector_cls.from_file(path).safety_check():
            raise exception.ImageUnacceptable(
                image_id=image_href,
                reason=_('Image does not pass safety check'))
    except format_inspector.ImageFormatError:
        raise exception.ImageUnacceptable(
            image_id=image_href,
            reason=_('Image content does not match disk_format'))
    ...
    return disk_format
```

`get_inspector` 是一张名字表：

```python
# nova/image/format_inspector.py  (同一 commit)
def get_inspector(format_name):
    return ALL_FORMATS.get(format_name)
```

声称 `vmdk` 就构造 `VMDKInspector`；声称 `raw` 就构造 Raw 检查器。`from_file(path).safety_check()` 跑的是**这个声称对应的**检查器，不是「文件到底是什么」。

`fetch_to_raw` 紧接着把深检返回值当成 qemu 的强制格式：

```python
# nova/virt/images.py :: fetch_to_raw  (1191a49a)
        force_format = do_image_deep_inspection(img, image_href, path_tmp)
        ...
        data = qemu_img_info(path_tmp, format=force_format)
        fmt = data.file_format
        ...
        if fmt == 'vmdk':
            check_vmdk_image(image_href, data)
```

补丁默认了两件事：

1. Glance 的 `disk_format` 和文件内容一致；不一致时，对应检查器会抛 `ImageFormatError`。
2. 把这个声称传给 `qemu-img info -f <force_format>` 之后，qemu 看到的格式就是「该做安全检查的那种」。

第一点对「声称 vmdk、内容也是 vmdk」成立：`VMDKInspector` 认描述符，`safety_check` / 随后的 `check_vmdk_image` 会拦 `monolithicFlat`。seed 的明文 `claim=vmdk` 在 V1 被挡住，这就是 v1 + `--seed` 退出码 10。

第二点不成立。`qemu-img info -f raw` 不会去解析 VMDK 描述符，也就不会填 `create-type`，`if fmt == 'vmdk'` 整段不执行。

---

## 深检之后，声称怎么接到 qemu-img 上

V1 谓词一结束，同一个 `fetch_to_raw` 立刻用返回的 `force_format` 调 `qemu_img_info`。`qemu_img_info` 把 `format=` 原样传给 privsep 里的 `qemu-img info`。强制格式的语义是：**不要探测，按我说的解析**。

对 seed（声称 vmdk）：

```text
get_inspector('vmdk') → VMDKInspector
safety_check / ImageFormatError / 随后 check_vmdk_image
→ ImageUnacceptable（create-type 不在白名单，或描述符过不了深检）
```

对同一份描述符、声称 raw：

```text
get_inspector('raw') → Raw 检查器
safety_check：raw 没有「不许有外部 extent」这条规则 → 通过
force_format = 'raw'
qemu_img_info(path, format='raw') → file_format == 'raw'
backing_file is None（-f raw 看不见 VMDK backing）
fmt == 'vmdk' 为假 → check_vmdk_image 不调用
force_raw_images 下 fmt 已是 raw → os.rename，描述符当 raw 盘留下
```

真正读金丝雀的是后面 qemu-img 再消费这份文件时，按内容识别成 VMDK、打开 FLAT extent。过滤器刚看过的是「声称 raw 的 safety_check」；open 看到的是描述符里的绝对路径。两套语义中间没有「探测结果必须等于声称」的第二次谓词。

---

## 仓库里已经有更强的检查，深检没用

同一份 `format_inspector.py` 在 V1 就已经实现了按**文件内容**并行探测：

```python
# nova/image/format_inspector.py :: detect_file_format  (1191a49a, 约 L985)
def detect_file_format(filename):
    """Attempts to detect the format of a file.
    This runs through a file one time, running all the known inspectors in
    parallel.
    """
    inspectors = {k: v() for k, v in ALL_FORMATS.items()}
    ...
```

谁调用它：

| 函数 | 调用 `detect_file_format`？ |
|---|---|
| V2 `do_image_deep_inspection` | 是，再用 `str(inspector) != disk_format` 对声称 |
| V1 `do_image_deep_inspection` | **否**，只 `get_inspector(disk_format)` |
| `check_vmdk_image` | 否，它看的是 qemu 已经当成 vmdk 之后的 create-type |

不是仓库里没有「先看文件再比对声称」的谓词，是 **V1 深检按名字选检查器，探测函数闲置**。即便没有 `./.../` 这种字符串把戏，只要 `get_inspector` 继续信任 Glance，谎报 `raw` 就会跳过 VMDK 检查器。

另外 `qemu_img_info` 自己本来就会探测格式（`format=None`）。V1 为了「深检过了就别让 qemu 再猜」把探测关掉，等于把 47951 那条 `if fmt == 'vmdk'` 的钥匙交给了上传者。

---

## 这个补丁挡住了什么、没挡住什么

到这里可以把「过滤器 vs qemu」落到具体代码：

- `get_inspector(disk_format)`：看 Glance 字符串是不是已支持的格式名
- `VMDKInspector.safety_check` / `check_vmdk_image`：看**被当成 VMDK 之后**的 create-type
- `qemu_img_info(..., format=force_format)`：看 qemu 在被强迫的格式下报什么

只要构造一种输入，使「声称的格式」没有 VMDK 检查、强迫 qemu 也看不见 VMDK 元数据，而文件内容仍是 `monolithicFlat` 描述符，第一层放行，后面 qemu 仍会按 VMDK 打开 extent。

本 case residual 就是把 seed 的 `claim` 从 `vmdk` 改成 `raw`，extent 仍是 `/canary/secret.txt`。OSSA-2024-002 的原话：*By supplying a raw format image which is actually a specially crafted … VMDK flat image with a descriptor file path*。advisory 还写了对称的 QCOW2 backing-file 变体（`use_cow_images=false` 时）；本 case 打的是 VMDK 这条，和 47951 seed 同一 sink。

---

## 残余仍然走同一条 fetch_to_raw（CVE-2024-40767）

没有换 API、没有换 qemu、没有换金丝雀位置。还是：

```http
GET /read?claim=raw&extent=/canary/secret.txt
```

`do_image_deep_inspection` 仍按 `disk_format` 取检查器；Raw 检查器放行；`qemu_img_info` 带着 `format='raw'` 跑；`check_vmdk_image` 不执行；qemu-img 随后按内容打开 FLAT extent，body 中出现 `PCBFLAG_...`。

所以残余不是新洞面，而是同一 sink 上三件事叠在一起：深检按声称选路；qemu 被强迫相信声称；内容探测函数已经存在却没挂上。seed 被挡住只说明「诚实的 vmdk 没了」，不说明「不能再让 qemu 读出树外文件」。

---

## 后来又补了什么（CVE-2024-40767，commit 8b4c522f）

V2 把深检改成：**先探测内容，再和 Glance 声称比对**；并且 `qemu-img info` 不再带 `format=`。

```python
# V2 do_image_deep_inspection
        inspector = format_inspector.detect_file_format(path)
        if not inspector.safety_check():
            raise exception.ImageUnacceptable(...)
        if disk_format not in ami_formats and str(inspector) != disk_format:
            raise exception.ImageUnacceptable(
                image_id=image_href,
                reason=_('Image content does not match disk_format'))
```

```python
# V2 fetch_to_raw
-        data = qemu_img_info(path_tmp, format=force_format)
+        data = qemu_img_info(path_tmp)
         fmt = data.file_format
+        elif force_format is not None and fmt != force_format:
+            raise exception.ImageUnacceptable(...)
```

对残余输入：内容探测得到 vmdk，声称是 raw，`str(inspector) != disk_format` 直接拒绝。即便深检被绕过，未强迫的 qemu-img 也会报 vmdk，和 `force_format=raw` 对不上，第二道门也会关。公开建议是升到 Nova 27.4.1 / 28.2.1 / 29.1.1。

即便如此，AMI/AKI/ARI 仍被排除在格式比对之外；那是另一条链，本 benchmark 的 v2 只关闭这条 raw-claim VMDK residual。

---

## 从这条链还能看出什么

这些不是分类标签，只是顺着代码继续看时比较自然的问题。

**维护者改错了哪一层。**  
他们改的是「按 Glance 名字选哪个检查器」以及「把这个名字喂给 qemu」。真正读宿主机文件的是 qemu 对 VMDK/QCOW2 外部引用的解析。V2 把内容探测接到深检上，才对准了这一层。

**不是没有更好的谓词。**  
`detect_file_format` 在 V1 的 `format_inspector.py` 里已经写好。V1 的 `do_image_deep_inspection` 只调了更弱的 `get_inspector(disk_format)`。从 V0→V1 的 diff 只能看到「加了深检」；要判断是否闭合，必须看到深检的键是声称而不是内容，以及 `qemu_img_info` 的 `format=` 参数。

**同一函数、同一份描述符，只换了 disk_format 字符串。**  
任何把用户可控的 Glance `disk_format` 传进 `fetch_to_raw` 的启动/导入路径，在 1191a49a 上都吃这一套。advisory 写明 QCOW2 backing file 在 `use_cow_images=false` 时是对称变体。

**金丝雀在镜像仓库之外是有意的。**  
`/canary/secret.txt` 不是 Glance 对象。能读到它，说明 qemu 打开的是描述符里的任意路径，而不是「raw 镜像碰巧包含这段字节」。

---

## 版本、入口、参考

| | commit | 深检键 | qemu-img | 声称 vmdk 的 Flat seed | 声称 raw 的同一描述符 |
|---|---|---|---|---|---|
| V0 | `a90bd508` | 无 | 自由探测 | 读到金丝雀 | （不必） |
| V1 | `1191a49a` | `get_inspector(声称)` | `format=force_format` | `check_vmdk_image` / 深检拒绝 | 读到金丝雀 |
| V2 | `8b4c522f` | `detect_file_format` + 比对声称 | 不强迫格式，探测结果必须一致 | 挡 | 格式不匹配，挡 |

- 产品路径：Glance 上传 → Nova `fetch_to_raw` → qemu-img。本 case HTTP：`GET /read?claim=...&extent=...`
- [CVE-2022-47951](https://nvd.nist.gov/vuln/detail/CVE-2022-47951)、[CVE-2024-32498](https://nvd.nist.gov/vuln/detail/CVE-2024-32498)、[CVE-2024-40767](https://nvd.nist.gov/vuln/detail/CVE-2024-40767)
- [OSSA-2023-002](https://security.openstack.org/ossa/OSSA-2023-002.html)、[OSSA-2024-001](https://security.openstack.org/ossa/OSSA-2024-001.html)、[OSSA-2024-002](https://security.openstack.org/ossa/OSSA-2024-002.html)
- [Launchpad 2071734](https://bugs.launchpad.net/ossa/+bug/2071734)
- V1 源码：[images.py @ 1191a49a](https://github.com/openstack/nova/blob/1191a49a65dce694b12df26bb5316b0a816b278e/nova/virt/images.py)、[format_inspector.py @ 1191a49a](https://github.com/openstack/nova/blob/1191a49a65dce694b12df26bb5316b0a816b278e/nova/image/format_inspector.py)
- V2：[8b4c522f](https://github.com/openstack/nova/commit/8b4c522f6699514e7d1f20ac25cf426af6ea588f)
