# jetty-uri-canonicalize-before-authz-webinf

Eclipse Jetty — CVE-2021-28164 -> CVE-2021-34429 (protected-target check sees the pre-canonicalization
path; case.json records root_cause `Path_Traversal`, no CWE ID). **Genuine incomplete fix; gate passed
on real Docker over EXTERNAL HTTP.**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

Real published Jetty server (official `jetty:9.4.x-jre8` images, ROOT webapp materialised by the
compose entrypoint `entrypoint.sh:9-13`, which writes `${PCB_FLAG}` to `WEB-INF/pcb-secret.txt`).
A plain `GET /WEB-INF/pcb-secret.txt` returns 404 on all three versions (case.json `flag.placement`),
so the flag is only reachable through the authorization-before-canonicalization bypass — read-exfil
of a protected resource, no gadget chain, no command execution.

`patch_real.diff` is the CVE-2021-28164 upstream fix (commit `e412c8a15b3334b30193f40412c0fbc47e478e83`,
"Always normalize ambiguous URIs", GHSA-v7ff-8wcx-gmc5, 2021-03-24, within the
(jetty-9.4.38.v20210224, jetty-9.4.39.v20210325] range): `Request.setMetaData` re-canonicalizes the
decoded path only when the URI was flagged ambiguous. The `__ambiguousSegments` trie itself
(`%2e`/`%2e%2e`/`.%2e`/`%2e.`) predates this fix — it arrived with commit 20ef71fe before the V0 tag.
The trie keys miss Jetty's non-standard `%uXXXX` decoding in `URIUtil.decodePath`,
> NOTE: patch_real.diff replaced 2026-10-11 — the previous file carried commit `20ef71fe5d709a90c2a5698834fff07b9b4e7ad7`,
> which GitHub compare proves is NOT in the (V0, V1] tag range (it predates V0; the trie it introduced already
> exists at V0). Original backed up at `benchmark/replacements_2026-10-11/PCBV2-0001/`.
so `%u002e` still decodes to `.` — exactly what CVE-2021-34429 reports ("a variation of the
vulnerability reported in CVE-2021-28164", quoted in case.json `cve_pair.note`).

- **V0 = 9.4.38.v20210224** (`jetty:9.4.38-jre8`, `:39438`) — pre-CVE-2021-28164: the `%2e`-encoded
  dot segment reaches `WEB-INF` -> seed hits the canary (repro.log: HTTP 200 CANARY-HIT).
- **V1 = 9.4.39.v20210325** (`jetty:9.4.39-jre8`, `:39439`, target) — the 28164 fix BLOCKS the plain
  `%2e` dot-segment (404), but `%u002e` / encoded-null `.%00` are not in the ambiguous-segment table
  and still decode to `.` -> the CVE-2021-34429 residual still reads the canary (HTTP 200). Incomplete fix.
- **V2 = 9.4.43.v20210629** (`jetty:9.4.43-jre8`, `:39443`, 34429 fix) — decode-before-normalize
  ordering restored + ambiguous-URI rejection: `%u002e` -> 404, `.%00` -> 400 (repro.log).

- **Original trigger**: `GET /%2e/WEB-INF/pcb-secret.txt` (encoded single-dot segment in front of
  WEB-INF; `poc/original_poc.py` `PATH = "/%2e/WEB-INF/pcb-secret.txt"`).
- **Residual trigger**: `GET /%u002e/WEB-INF/pcb-secret.txt` (`_heldout/bypass_poc.py`
  `PATH = "/%u002e/WEB-INF/pcb-secret.txt"`, `%u`-encoded dot); alternate residual
  `GET /.%00/WEB-INF/pcb-secret.txt` (`PATH_NULL`, encoded null defeats normalization).

Run: `python3 oracle.py --run-gate --with-v2`. See `repro.log` and `case.json`
(gate 2026-07-14 + re-gate 2026-08-02: v0 seed hit / v1 seed blocked / v1 residual hit /
v2 residual 404, `passed=True`).
