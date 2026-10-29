# PatchClosure-Bench 统一基准库（工作区说明）

本目录是 NDSS 论文 PatchClosure-Bench（不完全修复链 benchmark）的**唯一权威本体**：
学术元数据（case.json / 四向 gate 底稿）+ 平台运行时（case.yaml / 生命周期脚本 / FastAPI 控制器）
同处一树。合并过程、冲突策略与验证记录见 [`SUMMARY.md`](SUMMARY.md)。

> **⚠️ 2026-10-12 工程化重构（四职分离）— 本 README 部分旧描述已过时，以下为新布局权威**：
> - **答案已迁出 `cases/`**：`oracle.py`、`_heldout/`、`bypass_poc.py`、`residual_poc.py`、
>   `gate_result.json`、`INCOMPLETE_FIX_ANALYSIS.md`、`repro.log` 现位于 **`secrets/<id>/`**
>   （永不部署、永不进选手包）。`cases/<id>/` 只留公开定义 + 环境定义。
> - **冻结 schema**：权威为 **`schemas/case.schema.json`**（v2）；根下旧 `case_schema*.json`
>   迁入 `schemas/legacy_*` 并留 `*.MOVED.md` 指针。
> - **入库 CI**：`ci/validate.py`（四条机检）。**唯一实验入口**：仓库根 `runner/`（见其 README/脚本）。
> - 案数 213，编号区间 0001-0215，**缺号 0027/0085**（`mapping.jsonl` 的 215 条含此二已删号，属历史漂移）。
> - 详见 `reports/REFACTOR_2026-10-12.md` 与 `reports/REFACTOR_INVENTORY_2026-10-12.md`。

- **唯一数字口径**：`freeze_gold.py` 从 `cases/*/case.json` 聚合 → `gold_frozen.json`（零硬编码，复算即得）。
- **唯一命名**：案例目录 = `PCBV2-XXXX`；slug（`public_name`）保存在 `case.json.case_id` 与
  `case.yaml.public_name`，全局对照表 `mapping.jsonl`。

## 0. 快速健康检查

```bash
python3 tools/audit_benchmark_integrity.py --json   # 8 项一致性/泄漏/语法审计（stdlib，无需依赖）
python3 tools/audit_case_protocol.py                # 平台协议审计（需 PyYAML）
python3 tools/verify_no_hidden_leak.py              # 运行/会话工作区无答案物料
python3 tools/verify_source_immutability.py         # 语料相对基线未变（--snapshot 重基线）
python3 freeze_gold.py && git diff --stat 2>/dev/null || true   # 重算论文数字口径
```

## 1. 目录规范（顶层）

| 路径 | 作用 |
|---|---|
| `cases/<eval_id>/` | **215 个 strict_gold case**（规范见 §2） |
| `controller/` | FastAPI 控制器：枚举 / run 生命周期 / 动态端口 / fresh flag / 暴露 profile |
| `hidden/` | 7-family hidden scorer（绝不挂给方法） |
| `schemas/` `openapi.json` `static/` | API 与 case/run/submission schema、UI、OpenAPI |
| `migrations/overrides/` | family 推导的显式覆盖（不改写学术元数据） |
| `v2_harness/` | V2 held-out 评测物料：`inputs/<id>/{input_manifest.json,seed.py,seed_exec.py,v0_to_v1.diff}`、`evaluator/<id>/{evaluator_manifest.json,reference_witness.py}`、协议文档 / schemas / splits / ledger / provenance。`certify --deep`、`controllerservices.case_catalog` 读这里 |
| `tools/` | CLI + 认证 + 质量闸门 + 学术工具（索引见 [`tools/README.md`](tools/README.md)） |
| `docs/` | `API.md`、`CASE_PROTOCOL.md`、`PATCH_REAL_EXTRACTION.md` |
| `reports/` `work/` | 平台/学术报告（认证快照等）与运行时账本（`work/audit.jsonl`、`work/state/`） |
| `mapping.jsonl` | `real_case_id`(slug) ↔ `eval_id`(PCBV2-XXXX)，215 条速查表 |
| `case.json schema` | `case_schema.json` / `case_schema_strict.json` |
| `flag_oracle.py` | 四向 gate 框架（FlagOracle / validate_case / contains_flag），被全部 case 的 `oracle.py` 复用 |
| `freeze_gold.py` → `gold_frozen.json` | **唯一数字生成器**（聚合计数 + 交叉校验 strict_gold 四向全 True）与冻结快照 |
| `gen_audit_html.py` | 生成 `../docs/benchmark_build_audit.html`（读冻结快照 + `archive_phase/ledgers/BUILD_LEDGER.jsonl`） |
| `archive_non_gold/` | 18 个非 gold case 的完整证据留档（9 needs_review / 5 gate_passed / 2 duplicate / 1 positive_only / 1 excluded），论文筛选漏斗的审计链；另有 3 个判死记录目录（无 case.json） |
| `archive_phase/` `new_build/` `strict_audit/` `provenance/` | 建设期历史证据与台账（一次性脚本、候选池、审计快照；结论已固化进 case.json，仅留复现性） |
| `_merge_manifest.jsonl` | 合并留档：逐条记录并集补入 / 同名冲突 / 语义动作（1706 行） |
| `_merge_conflicts/`（顶层及各 case） | 同名冲突时的落败侧变体 |

## 2. 案例目录规范（`cases/PCBV2-XXXX/`）

```text
case.yaml                    平台声明式清单（scripts / source / service / readiness）
case.json                    学术元数据（case_id=slug、mechanism_family、cve_pair、oracle.checks、
                             status.classification、证据；含 eval_id 映射字段）
.source.env                  fetch_source 的 source 身份（TYPE/REPO/V0/V1/IMAGE…）
docker-compose.yml           端口变量化 compose（协议 §1）
scripts/{prepare,fetch_source,start,verify,reset,stop}.sh
poc/original_poc.py          seed PoC（verify.sh --seed 入口）—— 留 cases/（给选手）
poc/seed_exec.py             候选执行器（存在时）—— 留 cases/
overlays/                    v0/v1 差异化覆盖（多数为空）
patch_real.diff              官方 first-fix unified diff（v0→v1）
patch.diff                   4 行规范头 + patch_real.diff 正文逐字节子串（2026-10-11 统一重写）

# —— 以下为答案物料，2026-10-12 起迁至 benchmark/secrets/<id>/，不再在 cases/ ——
secrets/<id>/bypass_poc.py           held-out residual 答案（与 _heldout/bypass_poc.py 同源）
secrets/<id>/residual_poc.py         可运行 residual 利用（9 案曾在 poc/，已迁出）
secrets/<id>/_heldout/               held-out 物料（含 bypass_poc.py）
secrets/<id>/INCOMPLETE_FIX_ANALYSIS.md  人工分析底稿（为何 V1 修复不完整）
secrets/<id>/oracle.py               四向 gate（seed@V0 / seed@V1 / residual@V1 / residual@V2）
secrets/<id>/{gate_result.json,repro.log}
repro.log                    构建期复现日志
_heldout/{bypass_poc.py,evidence.json,flag_spec.json}
_merge_conflicts/            合并留档（该 case 的同名冲突变体）
```

**答案物料边界**：`_heldout/`、`oracle.py`、`poc/bypass_poc.py` 等只允许留在 case 目录内；
平台运行/方法工作区（`work/runs/*/visible`、`work/sessions/*/exp`）只暂存 seed 路径物料
（`controller/app.py:ANSWER_MATERIAL_MARKERS`），held-out/residual/oracle/flag_spec 一律不得进入。

## 3. 四向 gate 与复算

- gate 语义：seed@V0 到达 / seed@V1 阻断 / residual@V1 到达 / residual@V2 阻断；`strict_gold` = 四向全 True。
- 判据由人工写入 `case.json.status.classification` 与 `oracle.checks`；`freeze_gold.py` **只计数、绝不覆盖**。
- 平台侧端到端认证（真实容器 + fresh flag）：`tools/certify.py --mvp|--all`，见 `docs/CASE_PROTOCOL.md`。

```bash
python3 freeze_gold.py        # 任何 case.json 变更后重算 → gold_frozen.json
python3 gen_audit_html.py     # 重新生成 ../docs/benchmark_build_audit.html
```

## 4. 已知问题（如实记录）

- `v2_harness/` 内有 **17 个文件语法损坏**（中性化脚本留下的结构性截断：括号/f-string 断行），
  其中仅 `inputs/PCBV2-0070/seed.py`、`inputs/PCBV2-0211/seed.py` 会被 `certify --deep` 加载；
  其余 15 个是无用的 `seed_exec.py`/`oracle.py` 旧副本（平台实际使用 `cases/<id>/poc/` 下的副本）。
  另有 15 个同类文件已修（删除孤立 `r` 行）。
- 6 个 case 无 `poc/seed_exec.py`（非必需，仅影响方法侧便利执行器）。
- `v2_harness/*/evaluator_manifest.json` 内的 `effect_oracle.implementation` 仍指向旧工作区绝对路径
  （历史数据，未改写以免破坏既有哈希）。
- 仓库其它目录（`notes/`、`.cursor/rules/*.mdc`、`docs/`）中按旧 `benchmark_platform/...` 书写的
  说明仍是待同步项。

## 5. 历史清理记录

- 2026-08-03：清理 `__pycache__/`、`.DS_Store` 等，根目录 61 → 13 项（当时布局）。
- 2026-09-29：与原 `benchmark_platform/` 合并为单一树（见 `SUMMARY.md` §1–§9）。
