# tools/ 工具索引

本目录 = 平台运行 + 认证 + 质量闸门 + 学术数字工具。除注明外均为 stdlib 脚本（可直接 `python3` 跑）。

## 质量闸门（每次改动语料后跑）

| 工具 | 作用 | 依赖 |
|---|---|---|
| `audit_benchmark_integrity.py` | 8 项审计：案例集合/必需文件/六向身份对齐/语法/悬空引用/答案物料边界/主机路径/held-out 同源；输出 `reports/benchmark_integrity.json` | stdlib |
| `audit_case_protocol.py` | 平台协议静态审计（case.yaml 字段、6 脚本可执行、source 完整、poc 存在、答案物料不入运行可见面）→ `reports/case_protocol_audit.jsonl` | PyYAML |
| `verify_no_hidden_leak.py` | 方法可见面泄漏闸门：API 视图 + `work/runs/*/visible` + `work/sessions/*/exp` | stdlib + 控制器在线 |
| `verify_source_immutability.py` | 语料不变性：与 `reports/source_tree_baseline.sha256` 比对（`--snapshot` 重基线；`work/`、`reports/` 不参与） | stdlib |
| `audit_certification.py` / `verify_certification.py` | 认证结果审计与门槛校验（trial 数、cleanup、flag 拒绝等） | stdlib |

## 平台运行

| 工具 | 作用 |
|---|---|
| `platform_cli.py` | API 客户端：`cases` / `case <id>` / `start` / `status` / `submit-flag` / `submit-cand` / `stop` |
| `run_mvp.py` | 7 family 代表 case × N trials 的 MVP 认证编排（调用控制器 API） |
| `certify.py` | 全量/子集认证：`--mvp` / `--all --trials 2` / `--deep`（深门读 `../v2_harness/`） |
| `batch_cases.py` / `rerun_batch.py` / `sync_live_failures.py` | 批量启动、失败重跑、线上失败同步 |
| `session_smoke.py` | 会话 API（v0+v1 同时起）冒烟 |
| `cleanup_case_images.py` / `disk_guard.py` / `disk_watchdog.py` | 镜像清理（按 project 标签）与磁盘水位守护 |
| `adapt_verify.py` | 把老式 verify.sh 适配到当前协议 |

## 学术数字与构建

| 工具 | 作用 |
|---|---|
| `freeze_gold.py` | **唯一数字口径**：聚合 `../cases/*/case.json` + `../archive_non_gold/` → `../gold_frozen.json`（只计数、不覆盖判断） |
| `gen_audit_html.py` | 生成 `../../docs/benchmark_build_audit.html`（冻结快照 + 历史 ledger） |
| `flag_oracle.py` | 四向 gate 框架（被所有 case 的 `oracle.py` 以 `sys.path` 复用；根目录同名文件是权威副本） |
| `migrate_case.py` | **[历史]** pre-merge 迁移工具（旧 `benchmark/cases/<slug>` → 平台布局），保留作 provenance |
| `fetch_src.sh` / `parse_source_manifest.py` / `real_diff_extract.py` / `backfill_a14.py` / `backfill_b.py` | 源码抓取、source manifest 解析、官方 diff 抽取、历史回填工具 |

## 运行前置

```bash
# 控制器（容器）：在 benchmark/ 下
docker compose build && docker compose up -d controller
curl -fsS http://127.0.0.1:8787/healthz

# 质量闸门（一条龙）
python3 tools/audit_benchmark_integrity.py && python3 tools/verify_no_hidden_leak.py
```
