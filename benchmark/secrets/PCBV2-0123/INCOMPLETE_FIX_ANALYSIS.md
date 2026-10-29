# Gradio：`".." in rel` 改完了，abspath 仍然不解析 symlink

- Case：`PCBV2-0123`
- 产品：Gradio（ML demo Web UI）。运行时是 PyPI `gradio==4.10.0` / `4.11.0` / `5.0.0` 整包，真实 `/file=` 路由。
- 链：CVE-2023-51449（4.10.0 → 4.11.0，`".." in str(relative)`）→ CVE-2024-47164（4.11.0 → 5.0.0，`.resolve()`，GHSA-77xq-6g77-h274）
- 源码对着 tag `gradio@4.11.0` 的 `gradio/utils.py`：`abspath`、`is_in_or_equal`。应用 `allowed_paths=["/gradio_tmp"]`。金丝雀在树外 `/flag`。

Horizon3 写 CVE-2023-51449：containment *doesn't account for subdirectories inside the temp folder*——相对路径是 `sub/../../flag`，`startswith("..")` 为假。GHSA-77xq-6g77-h274：*`is_in_or_equal` may be bypassed*；workaround 原话 *Ensuring that all file paths are properly resolved and absolute*。NVD CVE-2024-47164 把这记成对同一函数的目录穿越检查绕过。

根因不只是「少写了一个 `in`」。检查插在「相对路径字符串里有没有 `..`」上；真正 `open` 的是 `FileResponse` 拿到的那条路径。同文件里 `abspath` 的 docstring 已经写 *does not resolve symlinks*。下面按请求走进去。

---

## 这块功能本来在干什么

Gradio 的 `/file=`（4.x）把磁盘文件发给浏览器，但只允许落在临时目录或 `allowed_paths` 里。一次典型请求：

```http
GET /file=/gradio_tmp/some_upload.bin
```

路由把等号后面的路径交给 `is_in_or_equal(requested, allowed)`。为真才 `FileResponse`。

设计意图：调用者不能读 `/flag`、`/etc/passwd` 这种允许目录之外的文件。成功穿越之后的效果是：**HTTP 200 body 里出现树外金丝雀**。

数据流（V1 = 4.11.0）：

```text
GET /file=<path>
    → 路由取出 path
    → is_in_or_equal(path, "/gradio_tmp")
         path_1, path_2 = abspath(path_1), abspath(path_2)
              已是绝对路径 → 原样返回，不 resolve、不跟 symlink
         rel = path_1.relative_to(path_2)
         if ".." in str(rel): return False     ← V1 补丁
         ValueError → False
         否则 True
    → FileResponse(path)   ← 内核跟随 symlink
    → body
```

没有登录。判断完全信任「相对路径字符串里有没有两个点」，不信任稍后 `open` 怎么解析同一条路径。

---

## 原始漏洞：子目录 + `../`（CVE-2023-51449，4.10.0）

4.10.0 的守卫是**前缀**：

```python
if str(path_1.relative_to(path_2)).startswith(".."):
    return False
```

`Path.relative_to` 在 4.10 这条实现里并不先把 `..` 消掉。请求经过允许目录里的子目录：

```text
path = /gradio_tmp/sub/../../flag
allowed = /gradio_tmp
rel = sub/../../flag
rel.startswith("..") == False     # 开头是 "sub"
```

Horizon3：先用 upload 在 temp 里造个子目录，再 `../` 爬出去。本 case seed：

```text
GET /file=/gradio_tmp/sub/../../flag
```

`/gradio_tmp/sub` 由 compose 入口准备好。V0 上 `is_in_or_equal` 为真，`FileResponse` 打开 `/flag`，body 里 `PCBFLAG_...`。需要 `--path-as-is` 一类客户端，浏览器自己会先规范化。

---

## 维护者改了什么（CVE-2023-51449 修复，4.11.0）

4.11.0 只改了一处比较。tag `gradio@4.11.0` 的函数是：

```python
# gradio/utils.py :: is_in_or_equal  (gradio@4.11.0)
def is_in_or_equal(path_1: str | Path, path_2: str | Path):
    """
    True if path_1 is a descendant (i.e. located within) path_2 or if the paths
    are the same, returns False otherwise.
    """
    path_1, path_2 = abspath(path_1), abspath(path_2)
    try:
        if ".." in str(path_1.relative_to(path_2)):  # prevent path traversal
            return False
    except ValueError:
        return False
    return True
```

`startswith("..")` 变成 `".." in str(...)`。对 seed：

```text
rel = "sub/../../flag"
".." in rel == True → return False → 路由 403
```

这就是 v1 + `--seed` 退出码 10。

补丁默认了两件事：

1. 逃出允许目录的路径，相对字符串里一定会出现字面 `..`。
2. `abspath` 之后拿到的 `path_1` 已经是「真正要打开的那条路径」。

第二点被同文件里的 `abspath` 直接否定。

---

## 消毒之后谁真正打开那个路径

`is_in_or_equal` 返回 True 之后，路由把**用户给的那条路径**（或 `abspath` 后仍未 resolve 的 Path）交给 `FileResponse`。Starlette / 内核 `open` 会跟随 symlink。

V1 的 `abspath`：

```python
# gradio/utils.py :: abspath  (gradio@4.11.0)
def abspath(path: str | Path) -> Path:
    """Returns absolute path of a str or Path path, but does not resolve symlinks."""
    path = Path(path)

    if path.is_absolute():
        return path

    # recursively check if there is a symlink within the path
    is_symlink = path.is_symlink() or any(
        parent.is_symlink() for parent in path.parents
    )

    if is_symlink or path == path.resolve():
        return Path.cwd() / path
    else:
        return path.resolve()
```

`/file=` 进来的几乎都是绝对路径（`/gradio_tmp/...`）。第一句 `if path.is_absolute(): return path` **直接返回，后面的 symlink 探测根本不跑**。docstring 写明不 resolve symlink；对已经绝对的输入，它连规范化都不做。

于是过滤器看的是：

```text
path_1 = Path("/gradio_tmp/escape/flag")     # 字面，未跟随
path_2 = Path("/gradio_tmp")
rel = "escape/flag"                          # 没有 ".."
".." in "escape/flag" == False
→ True
```

`FileResponse` 打开 `/gradio_tmp/escape/flag` 时，`escape` 是指向 `/` 的 symlink，内核读到 `/flag`。两套语义：字符串相对关系 vs 跟随后的 inode。

---

## 仓库里已经有更强的检查，绝对路径没用上

`abspath` 对**相对**路径会 `path.resolve()`（跟 symlink）。对绝对路径选择不跟，注释还把这当特性。containment 真正需要的是「打开之前的真实路径必须落在允许根下」，也就是 `Path.resolve()` 之后再 `relative_to`。

Python 标准库里这就是：

```python
path_1.resolve().relative_to(path_2.resolve())
```

越界会 `ValueError`。4.11.0 **没有**这步。GHSA-77xq-6g77-h274 的 workaround 几乎把答案写在脸上：*manually sanitize and normalize*；*properly resolved and absolute*。V2（5.0.0，commit `02369b3`）做的就是 `abspath(p).resolve()`。

不是没有更好的谓词，是 **`is_in_or_equal` 调用 `abspath` 之后没有 `resolve`**。字面 `..` 扫描永远看不到「名字叫 `escape`、实际指向 `/`」这种情况。

---

## 这个补丁挡住了什么、没挡住什么

- V1 过滤器：`str(relative_to)` 里有没有子串 `..`
- `FileResponse` / 内核：按 symlink 打开

```text
seed:
  /gradio_tmp/sub/../../flag
  abspath 原样（已绝对）
  rel = "sub/../../flag"
  ".." in rel → False（拒绝）

residual:
  /gradio_tmp/escape/flag          # escape -> /
  abspath 原样
  rel = "escape/flag"
  ".." in rel → 没有
  FileResponse 跟随 → /flag
```

字面 `..` 的其它写法（`....//` 之类）多数也会被 `".." in` 打到。能在 V1 活下来的，是**相对字符串里根本没有两个点**的逃逸——允许目录内的 symlink。

---

## 残余仍然走同一条 `/file=` + `is_in_or_equal`（CVE-2024-47164）

没有换路由、没有换 `allowed_paths`。还是：

```http
GET /file=/gradio_tmp/escape/flag
```

`escape` 由 compose 入口在允许目录里建好，指向 `/`。`is_in_or_equal` 照样跑 V1 那一行 `".." in`；`rel` 是 `escape/flag`；放行；`FileResponse` 读 `/flag`。

本 case residual 与 GHSA「把路径 resolve 成绝对」所描述的缺口一致。认证：v1 + `--residual` body 里观察到 `PCBFLAG_...`。V2 上同一请求 403。

seed 被挡住只说明「带字面 `..` 的相对路径没了」，不说明「不能再从 `/file=` 读出允许目录外的文件」。

平台 verify 与这条 incomplete-fix 链是同一 sink：`is_in_or_equal` → `FileResponse`。不是换了一个无关的文件接口。

---

## 后来又补了什么（CVE-2024-47164，5.0.0）

commit `02369b3`（*Improve is_in_or_equal and fuzzer*）把比较建立在 resolve 之后的路径上。5.0.0 形态：

```python
path_1, path_2 = abspath(path_1).resolve(), abspath(path_2).resolve()
try:
    path_1.relative_to(path_2)
    return True
except ValueError:
    return False
```

对残余：

```text
/gradio_tmp/escape/flag  .resolve() → /flag
/gradio_tmp              .resolve() → /gradio_tmp
/flag.relative_to(/gradio_tmp) → ValueError → False → 403
```

symlink 被折叠，相对路径不再是「看起来在里面」。公开建议 `gradio>=5.0`。5.x 路由前缀变成 `/gradio_api/file=`，containment 函数仍是这一处。

即便如此，若允许目录本身和敏感文件在同一解析后的树上（例如允许了 `/`），这道门帮不上。本 benchmark 的允许根是 `/gradio_tmp`，金丝雀在 `/flag`，V2 关掉的就是这条 symlink residual。

---

## 从这条链还能看出什么

**维护者改错了哪一层。**  
他们改的是相对路径字符串怎么判断「看起来像穿越」。真正逃出树的是 `open` 跟随 symlink。V2 把检查移到 resolve 之后，才和 open 的语义对齐。

**不是没有更好的谓词。**  
`Path.resolve()` + `relative_to` 在标准库里现成。`abspath` 自己对相对路径也会 `resolve`。绝对路径那条捷径把这关掉了。从 V1 的 diff 只能看到 `startswith` → `in`；要判断是否闭合，必须读 `abspath` 的 docstring 和 `is_absolute` 早退。

**同一函数、同一路由，只换了路径形状。**  
`sub/../../flag` 和 `escape/flag` 都进 `is_in_or_equal`。一个在相对字符串里留 `..`，一个把 `..` 藏进 inode。

**字符串 containment 不是路径 containment。**  
`".." in rel` 问的是字符。symlink 问的是打开之后在哪。GHSA 的 workaround 已经把层说破了。

**金丝雀在允许目录外是有意的。**  
`/flag` 不在 `/gradio_tmp`。body 里出现 token，说明 `FileResponse` 打开的是任意文件系统路径，不是 temp 里碰巧有个同名文件。

---

## 版本、入口、参考

| | 版本 | `is_in_or_equal` | `abspath` | seed `sub/../../flag` | residual `escape/flag` |
|---|---|---|---|---|---|
| V0 | 4.10.0 | `startswith("..")` | 绝对路径原样 | 200，flag | （不必） |
| V1 | 4.11.0 | `".." in str(rel)` | 同上，不 resolve | 403 | 200，flag |
| V2 | 5.0.0 | `abspath().resolve()` 再 `relative_to` | 跟随 symlink | 403 | 403 |

- HTTP：`GET /file=...`（V2：`/gradio_api/file=...`）
- [CVE-2023-51449](https://nvd.nist.gov/vuln/detail/CVE-2023-51449)、[CVE-2024-47164](https://nvd.nist.gov/vuln/detail/CVE-2024-47164)
- [GHSA-6qm2-wpxq-7qh2](https://github.com/gradio-app/gradio/security/advisories/GHSA-6qm2-wpxq-7qh2)、[GHSA-77xq-6g77-h274](https://github.com/gradio-app/gradio/security/advisories/GHSA-77xq-6g77-h274)
- [Horizon3：Exploiting File Read Vulnerabilities in Gradio](https://horizon3.ai/attack-research/disclosures/exploiting-file-read-vulnerabilities-in-gradio-to-steal-secrets-from-hugging-face-spaces/)
- V2 commit [`02369b3`](https://github.com/gradio-app/gradio/commit/02369b3159df72b2f4a36ce5684574eb65065731)
- 源码：[`gradio@4.11.0` `utils.py`](https://github.com/gradio-app/gradio/blob/gradio@4.11.0/gradio/utils.py)
