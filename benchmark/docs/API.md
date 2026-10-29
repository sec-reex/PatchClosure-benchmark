# Platform API (r24-v2-agent)

认证编排 (`tools/run_mvp.py`) 仍走单版本 `POST /api/v1/runs`。下面是 **agent / 人机** 用的会话层：一次拉起 v0+v1，给工作区路径和端口，用状态轮询，用 HMAC 校 flag。

## 已经有的（认证）

| 你要的 | 现状 |
|---|---|
| 启动失败返回错误 | `GET /api/v1/runs/{id}` 的 `error.category` + `error.detail`（`source_fetch_error` / `prepare_error` / `startup_error` / `readiness_error`） |
| 什么时候能打 | `state=ready`。轮询 `GET /api/v1/runs/{id}` 或 `GET /api/v1/sessions/{id}` |
| 平台自己打 seed/residual | `POST .../submissions` `type=verify` `mode=seed\|residual`。`rc=0` = 效果通道里看到本次 `RUN_FLAG` |
| 校 flag | **以前 schema 写了 `type=flag` 但没接上。** 现在 HMAC 比较：`type=flag` + `value`，或 session `POST .../flag` |
| v0+v1 源码 / diff / exp / 端口 | **以前没有。** 用 `POST /api/v1/sessions` |

判定：**看到本次 run 的 `PCBFLAG_*` 算出成功**，不是「exp 进程退出 0」。`verify.sh` 退出码 0/10/20 就是这个意思。

`GET /api/v1/runs/{id}` 仍带 `flag` 字段，给 `run_mvp` 做 stale-flag 门。**Agent 不要读这个字段**；会话接口不返回 flag。

## Agent 流程

`POST /sessions` 立刻返回 `state=starting`（compose 可能要十几分钟）。轮询 `GET`：`v0.state` / `v1.state` 会从 `queued → materializing → preparing → starting → ready` 往前走；两边都 `ready` 时 session 才 `ready`，并写出工作区。

```
POST /api/v1/sessions  {"case_id":"PCBV2-0064"}
  → {session_id, state:starting}

GET  /api/v1/sessions              # 可选：列出近期会话
GET  /api/v1/sessions/{id}         # 每 5s；看 v0.state / v1.state
  → state=ready 时：
     tmp / workspace : /tmp/pcb_sess_... → work/sessions/...
       v0/  v1/  patch_real.diff  exp/
     v0.endpoints / v1.endpoints : [{host, port, url, name}]
  → state=error 时：error.category + error.detail，可 GET .../log?version=v0|v1

POST /api/v1/sessions/{id}/flag  {"value":"PCBFLAG_..."}
  → {accepted:true, matched:["v0"|"v1"]}

POST /api/v1/runs/{v1_run_id}/submissions  {"type":"verify","mode":"seed"}
  → 平台代打 seed；v1 上 rc=10 表示首次修复挡住了

POST /api/v1/sessions/{id}/stop
```

工作区**不含** residual / heldout / `INCOMPLETE_FIX_ANALYSIS.md`。diff 是 `patch_real.diff`（seed 官方首次修复）。

## 单 run（认证仍用这个）

```
POST /api/v1/runs  {case_id, target_version:v0|v1}
GET  /api/v1/runs/{id}          state / endpoints / source_dir / error
GET  /api/v1/runs/{id}/log
POST /api/v1/runs/{id}/submissions  type=verify|flag
POST /api/v1/runs/{id}/reset
POST /api/v1/runs/{id}/stop
GET  /api/v1/cases / GET /api/v1/cases/{id}
```

启动是异步的：`POST` 立刻返回 `queued`，worker 再 `materializing → preparing → starting → ready`。失败进 `error` 并 best-effort `stop`。
