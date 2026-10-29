# Manual extraction of `patch_real.diff`

论文用：每条 case 的 `patch_real.diff` 是**人工**对着官方首次修复抽出来的 unified diff，不是脚本按 tag 整包倒、也不是 residual / V2 补丁。下面按可直接改写成 Related Work / Dataset Construction 的口径写。

---

## What the file is

Each case directory contains `patch_real.diff`: the **official first-fix** that closed the **seed / original CVE** (the `v0 → v1` transition). It is **not**

- the residual / incomplete-fix bypass that still works on `v1` (that lives in `verify.sh --residual` and, when present, in `patch.diff` or held-out analysis);
- a later complete fix (`v2`);
- a whole minor-version dump (`git diff v0 v1` with no file filter).

Optional two–three header lines record the seed CVE, the official upstream, and the pin (tag, commit, or release artifact). The body is a unified diff (`diff --git` / `---` / `+++` / `@@`).

## Who extracted it

All 215 first-fix diffs were **extracted by hand**. An analyst read the public advisory for that case, identified the first official change that blocked the original issue, fetched that official artifact, and copied out only the files that implement the fix. No batch script was used to generate the corpus (a script cannot decide “this release merge is fat, keep only `Xml.node.ts`”).

## Three source classes

人工提取时按官方产物能不能 checkout 分成三类。**不因为范围肥 / 没有单独安全 SHA 就跳过**，而是对着官方发行物做文件级首次修复；也**不把「没有 git tag」说成已经钉到可 checkout 的 commit**。

### 1. 能钉到 git tag / 安全 commit / 发布包版本（绝大多数）

官方仓库有修前、修后 tag（或 GHSA/NVD 给出的 first-fix commit），或 registry 上有对应版本的整包。做法是：

```text
git diff TAG0 TAG1 -- <advisory 点名的文件>
```

fat release 也只抽 advisory 文件，不整包倒。例如：

| Case | Pin | Slice |
|---|---|---|
| 0020 n8n | `n8n@2.17.3..2.17.4` | `Xml.node.ts` + `sanitizeXmlName` |
| 0061 Keystone | `45d156b6b..b59946fa2` | mutations / resolvers（丢掉 Version Packages merge） |
| 0071 Open WebUI | `v0.8.12..v0.9.0` | `filter_accessible_collections` only |
| 0106 EazyDocs | `v2.3.5..v2.3.6` | Create/Delete + nopriv |
| 0113 FreeScout | `1.8.179..1.8.180` | `stripDangerousTags` unclosed |
| 0115 FUXA | `v1.1.13..v1.2.10` | `/api/download` `../` strip |
| 0130 Jenkins | `jenkins-2.492.1..2.492.2` | SECURITY-3495 / CVE-2025-27622（不是后面的 31721） |
| 0204 SuiteCRM | `v7.14.5..v7.14.6` | `ModuleScanner.php` |
| 0051 ASE | wordpress.org zip 7.6.2→7.6.3 | View Admin as Role + `profile_update` |
| 0176 json-ptr | `json-ptr@1.3.0..2.0.0` npm 整包 | `dist/util.js`（git 404，钉的是 npm） |

其余 case 同属这一类：NVD/GHSA/changelog 钉首次修复版本，再 `git diff` 或对 PyPI/npm/Maven/wordpress.org 整包做文件级 diff。

### 2. 只有官方 SourceForge / vendor tarball，没有可 checkout 的 git tag

上游历史上就不发这两个版本的 git tag。diff 仍然是「修前 vs 修后」的官方文件，只是源是发行包，不是 commit：

| Case | Official artifacts | File |
|---|---|---|
| 0007 Vtiger | `vtigercrm6.3.0.tar.gz` → `vtigercrm6.4.0.tar.gz` | `CompanyDetailsSave.php`（`mime_content_type`） |
| 0154 NukeSentinel | `NukeSentinel_2505_70-80.tar.gz` → `2506` | `html/includes/nukesentinel.php`（`ereg` 加 `^` 锚） |

这两份不能写成 “git first-fix SHA”。header 里写 SF URL + 包名。

### 3. 官方版本之间没有 first-fix delta

| Case | What the official zips contain | What `patch_real.diff` records |
|---|---|---|
| 0181 qdPM / CVE-2015-3884 | `qdPM_8.0.zip` … `qdPM_9.1.zip` 的 `uploads/.htaccess` **字节级相同**（`FilesMatch` 禁 PHP） | 9.1 zip 里那两份官方 `.htaccess`；**注明没有 8.x→9.1 htaccess delta**。case 的 v0 是把这份官方文件剥掉，v1 是 stock 9.1 |

这一条**不能**和 1、2 并列叫「钉到版本间首次修复」。header 必须写明 no version delta，以免被当成 git first-fix。

## How each diff was found

For every case the same loop:

1. **Read the incomplete-fix chain.** `INCOMPLETE_FIX_ANALYSIS.md` and the case pin (`case.yaml` `source.v0` / `v1`) name the seed CVE and the later residual CVE. `patch_real.diff` is always the **seed** side.

2. **Pin the first patched official version.** NVD, GHSA, vendor security pages, oss-security, and the project changelog. The first version that ships the seed fix is not always the case’s `v1` tag (example: n8n seed first-fix is `2.17.4`, while the case `v1` image is `2.20.6`). When they diverge, the diff is taken from the **first patched release**, not from the whole `v0…v1` range.

3. **Fetch the official artifact** (never a reconstructed snippet or `raw.githubusercontent.com` slice):

   | Kind | Where the bytes come from |
   |---|---|
   | Application with git | Official repo tags / the security commit (`git diff TAG0 TAG1 -- <advisory files>`) |
   | Library on a registry | Published package as a whole (PyPI / npm / Maven Central), then file-scoped diff of the installed / packed tree |
   | WordPress plugin | wordpress.org version zips (or upstream git tags if the zip is 404) |
   | No public git tag | Official SourceForge / vendor tarball or zip (same files the product historically shipped) |

4. **File-scope.** Keep only files named in the advisory or that implement the first-fix (e.g. `CompanyDetailsSave.php`, `sanitizeXmlName`, `filter_accessible_collections`). Drop changelog, docs, lockfiles, `composer.phar`, unrelated API refactors in the same minor bump, and **residual-only** hunks.

5. **Check against the seed, not the public name.** `public_name` sometimes carries the residual CVE (Jenkins `CVE-2025-31721`, PHPMailer `CVE-2016-10045`). The header and the hunks are the earlier first-fix (SECURITY-3495 / `CVE-2025-27622`, `CVE-2016-10033`).

## Typical commands (manual, per case)

Once the analyst has chosen the pin and the file list:

```bash
# git / tag pair
git diff TAG0 TAG1 -- path/to/advisory_file.c path/to/other.c

# published npm package
npm pack pkg@V0 && npm pack pkg@V1
diff -u package-V0/dist/util.js package-V1/dist/util.js

# official release tarball (no tag)
tar xf product-V0.tar.gz && tar xf product-V1.tar.gz
diff -u V0/path/File.php V1/path/File.php
```

The resulting unified diff is copied into `cases/PCBV2-XXXX/patch_real.diff`. Existing `patch.diff` is left untouched (it may still be the residual slice).

## What we explicitly did not do

- Dump `git diff v0 v1` for a fat minor (Open WebUI `0.8.12→0.9.0` whole `utils.py`, FUXA `1.1.13→1.2.10` report-API rewrite).
- Treat a Version Packages / release-merge SHA as the first-fix (Keystone).
- Write residual / V2 / “why still bypassable” into `patch_real.diff`.
- Reconstruct a package from a handful of raw GitHub files.

## Quality bar

A `patch_real.diff` is accepted only if an analyst can point to (i) the seed CVE, (ii) the official artifact, and (iii) the hunk that is the first incomplete fix — the same change that makes `v1 + --seed` fail (exit 10) while leaving the residual path open.
