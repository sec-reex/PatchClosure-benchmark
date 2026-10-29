# rocketmq-cve-2023-37582

Apache RocketMQ — CVE-2023-33246 → CVE-2023-37582 (UPDATE_NAMESRV_CONFIG config-path
blocklist typo → arbitrary file write, Improper Input Validation).
**Genuine incomplete fix; gate passed on real Docker over the REAL RocketMQ remoting TCP
protocol** (`apache/rocketmq` 5.1.0/5.1.1/5.1.2 official images; repro.log: V0 kvConfigPath write
lands, V1 rejects it with code 16 NO_PERMISSION, V1 configStorePath write lands, V2 rejects with
code 16 — gate Variant A "passed", `provenance.verified = runtime_gate_passed`).

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

REAL NameServer process, no broker needed: each profile runs the official image's
`sh mqnamesrv` with the RocketMQ remoting protocol on container port 9876 — binary framed
request/response over TCP, not HTTP (`run_mode: real-server-tcp`,
`external_trigger: "tcp"`). The driver is `DefaultRequestProcessor.updateConfig`: request code
318 `UPDATE_NAMESRV_CONFIG` feeds an attacker-supplied Java Properties body into
`Configuration.update` with NO authentication. Same sink on all three versions (`MixAll.string2File`
persist of nameserver config); the advisory itself says "the CVE-2023-33246 issue was not
completely fixed in version 5.1.1".

- **V0 = apache/rocketmq:5.1.0** (`:39870` → 9876) — no blocklist at all: `kvConfigPath` can be
  repointed -> the CVE-2023-33246-class seed write reaches (`KVConfigManager.persist` writes the
  KV table JSON containing the flag to the attacker path).
- **V1 = apache/rocketmq:5.1.1** (`:39871`, target) — the CVE-2023-33246 fix adds
  `properties.containsKey("kvConfigPath") || properties.containsKey("configStorePathName")` ->
  the `kvConfigPath` seed is BLOCKED (code 16), but `configStorePathName` does NOT exist in
  `NamesrvConfig` — the real field is `configStorePath` -> the CVE-2023-37582 residual passes the
  check and the same request's `Configuration.persist()` writes to the attacker path. Incomplete
  fix: the blocklist guards a property name that was never a field.
- **V2 = apache/rocketmq:5.1.2** (`:39872`, -37582 fix, PR #6843 "Fix incorrect naming") —
  blocklist corrected to `configStorePath` -> residual BLOCKED (code 16 NO_PERMISSION).

Benign canary channel: the flag travels as a config VALUE — seed path stores it via
`PUT_KV_CONFIG` (code 100) as KV pair `PCB_CANARY.flag`, bypass path sets property
`productEnvName=<PCB_FLAG>` — and lands in `/tmp/pcb_marker.txt` inside the container, read back
with `docker exec ... cat` (verify.sh: exit 0 = flag found, 10 = not found, 20 = env failure).
Observed artifact is an arbitrary file WRITE; no command execution, no crontab payload.

- **Original trigger**: TCP `:9876`, request 318 body `kvConfigPath=/tmp/pcb_marker.txt`, then
  request 100 `PUT_KV_CONFIG` -> `KVConfigManager.persist` -> `string2File` to `kvConfigPath`
  (blocked on V1 by the one name the blocklist got right).
- **Residual trigger**: TCP `:9876`, request 318 body
  `configStorePath=/tmp/pcb_marker.txt` + `productEnvName=<FLAG>` -> reflection
  (`MixAll.properties2Object` → `setConfigStorePath`) rewrites the field that
  `Configuration.persist()`/`getStorePath()` reads -> full NamesrvConfig incl. the flag written to
  the marker path in the SAME request; the V1 check only ever compared the string
  `configStorePathName`.

Run: `PCB_FLAG=<token> python3 oracle.py --gate` (envs up) or `python3 oracle.py --run-gate`.
See `repro.log` and `case.json`.

> NOTE: the docker-compose.yml header comment claims "The canary is planted as
> /tmp/pcb_seed.txt in the container", but no script in the case creates or reads that file —
> the flag actually flows in the request bodies (KV value / `productEnvName`) and is detected in
> `/tmp/pcb_marker.txt` per case.json.
