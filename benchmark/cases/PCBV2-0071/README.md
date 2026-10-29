# open-webui-cve-2026-54019

Open WebUI — CVE-2026-44560 -> CVE-2026-54019 (the 0.9.0 collection-ACL fix
allows unknown non-KB collection names as legacy/ephemeral, and in Milvus
multitenancy mode that user-controlled name is interpolated UNESCAPED into
`expr=f"resource_id == '{resource_id}'"` -> query-logic tautology; CWE-862/943).
**Genuine incomplete fix; gate passed on real Docker over EXTERNAL HTTP.**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

REAL official Open WebUI images (`ghcr.io/open-webui/open-webui:0.8.12` / `0.9.0`
/ `0.9.6`) against a REAL Milvus standalone (`milvusdb/milvus:v2.4.13` + etcd +
minio, `ENABLE_MILVUS_MULTITENANCY_MODE=true`); embedding is Open WebUI's
built-in LOCAL `sentence-transformers/all-MiniLM-L6-v2` (offline, no external
LLM/API). Open WebUI's OWN `retrieval/utils.py::filter_accessible_collections`
and `vector/dbs/milvus_multitenancy.py` sink run inside the container. 8GB Docker
RAM -> versions run SEQUENTIALLY (`run_gate.sh`) with a fresh Milvus between.
Authz-seeded canary: `orchestrate.py` provisions a non-admin VICTIM over the real
API, creates a private knowledge base and uploads a doc whose embedded chunk
carries `${PCB_FLAG}` (real Milvus row, `resource_id` = KB id); the ATTACKER is a
distinct non-admin with a real JWT. Detection = flag substring in the attacker's
returned RAG documents — cross-tenant read, no gadget chain, no command
execution.

`patch_real.diff` is the CVE-2026-44560 first-fix (v0.8.12 -> v0.9.0,
`backend/open_webui/retrieval/utils.py filter_accessible_collections`): KB names
are validated via `Knowledges.check_access_by_user_id`, so the direct
victim-KB-id read gets 403. Incomplete — its else-branch ALLOWS any unknown
non-KB name as a legacy/ephemeral collection, and `milvus_multitenancy.py`
builds `expr = f"resource_id == '{resource_id}'"` unescaped. GHSA-p5cp-r7rg-qpxc
(case.json `evidence.incomplete_fix_quote`): "This is a bypass of the earlier fix
for GHSA-h36f-rqpx-j5wx / CVE-2026-44560." The 0.9.6 fix adds
`_is_safe_collection_name` (`^[A-Za-z0-9_-]{1,255}$`), gates unknown names behind
`ENABLE_RETRIEVAL_UNSCOPED_COLLECTIONS` (default False) and `_escape_milvus_string`
at the sink.

- **V0 = 0.8.12** (`:39581`) — no ACL on the RAG query path; attacker names the
  victim's KB uuid directly -> 200 + flag (repro.log).
- **V1 = 0.9.0** (`:39581`, target) — the 44560 fix BLOCKS the direct KB id (403
  "Access prohibited"), but the tautology name `x' or resource_id != '' or
  resource_id == 'x` passes the ACL as unknown and matches EVERY tenant's rows ->
  victim's flag chunk returned (200). Incomplete fix.
- **V2 = 0.9.6** (54019 fix) — `_is_safe_collection_name` rejects the
  quote/space characters -> 403 (repro.log / results/v2.json).

- **Original trigger**: `POST /api/v1/retrieval/query/collection` with
  `collection_names: ["<victim_kb_uuid>"]` (`poc/original_poc.py`
  `VICTIM_KB_ID = "victim-kb-6f1e0e7a-2c9b-4d55-9a0f-privatefinance"`).
- **Residual trigger**: same endpoint with
  `collection_names: ["x' or resource_id != '' or resource_id == 'x"]`
  (`_heldout/bypass_poc.py` `INJECTION`).

Run: `bash run_gate.sh` (sequential v0/v1/v2 with fresh Milvus; driver
`orchestrate.py`). See `repro.log`, `results/{v0,v1,v2}.json` and `case.json`
(gate 2026-07-17, flag `PCBFLAG_ea0047463c73451ab9e90f135ea302e1`: orig
flag@v0 / orig 403@v1 / bypass flag@v1 / bypass 403@v2; victim self-read 200 on
all versions and attacker own-KB baseline flag-free as controls; passed=true).

> NOTE: per case.json `audit`, the lifted FastAPI harness `core/`, `Dockerfile`,
> `oracle.py`, `original_poc.py` and `_heldout/bypass_poc.py` are STALE leftovers
> of the pre-rebuild build ("left in place per NO-rm ... unused by this build").
> The current driver is `orchestrate.py` + `run_gate.sh`; the root `Dockerfile`
> (python:3.12-slim + `core/`) is NOT referenced by `docker-compose.yml`.
