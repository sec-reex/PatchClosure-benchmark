# apache-couchdb-cve-2018-8007

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

Apache CouchDB — **CVE-2017-12636 → CVE-2018-8007** (config-API command injection → RCE; CWE-20 / CWE-77).
Incomplete-fix / blacklist-bypass differential (Variant A, same flag channel).

## Lineage
- **CVE-2017-12636** (fixed in 2.1.1): a CouchDB admin could register an OS command via the
  HTTP config API — e.g. `PUT /_node/<n>/_config/query_servers/<lang> = "<command>"` — then query
  a view in that language so CouchDB *spawns* the command → arbitrary code execution as the
  couchdb user. The fix added `couch_util:check_config_blacklist/1`, rejecting the command-exec
  config **sections** (`query_servers`, `os_daemons`, `native_query_servers`, `daemons`, …) with
  403 "Config section blacklisted for modification over HTTP API."
- **CVE-2018-8007** (fixed in 2.1.2): the blacklist only checked the **section name** in the
  request path, never the **value**. Config persists as `key = value` lines in
  `local.d/local.ini`, so an admin can `PUT` a *non-blacklisted* section (`cors/origins`) whose
  value contains newlines that break out into a fresh, blacklisted section
  (`\n\n[query_servers]\npcbqs = <command>\n`). On the next start CouchDB re-parses the file into
  live config → the command is spawned → RCE, bypassing CVE-2017-12636. The 2.1.2 fix
  (commit `2cec527`, `string:trim` + `config:set` returning an error) rejects such values with
  400 "Invalid configuration value".

## Versions
| role | image | note |
|---|---|---|
| V0 | couchdb:2.1.1 + `check_config_blacklist` neutralised | pre-CVE-2017-12636 state; seed reaches flag |
| V1 | couchdb:2.1.1 stock | =CVE-2017-12636-patched; seed 403-blocked; **CVE-2018-8007 residual reaches flag** (TARGET) |
| V2 | couchdb:2.1.2 stock | =CVE-2018-8007-patched; residual 400-blocked |

V0 recompiles ONE stock module (`couch_util`) with only `check_config_blacklist/1` turned into a
no-op — the CVE-2017-12636 mitigation "not yet present" — using the release's own erts-6.2 `erlc`
(`-DPRE18TIMEFEATURES` required; see Dockerfile). No other CouchDB code is modified.

## Canary (rce-oob, benign)
`${PCB_FLAG}` is planted at `/flag/pcb_flag.txt`, a path CouchDB never serves over HTTP. The
benign exploit sets the spawned query-server command to `/bin/cp /flag/pcb_flag.txt /pcb_out/<f>`
(no real payload). The flag appears in the observable exfil dir (`./_out/<ver>`) **only** when
arbitrary-command config was accepted past the blacklist AND executed → genuine config-RCE.
Same flag channel for seed and residual → **Variant A** (`flag_oracle.validate_case`).

## Run the gate
```
python3 oracle.py --run-gate --check-v2   # compose up v0+v1(+v2), gate, teardown
```

Mechanism derived from the NVD/Apache advisories + the CouchDB source diff only (no offensive
PoC repo used). `_heldout/` is never exposed to the system-under-test.
