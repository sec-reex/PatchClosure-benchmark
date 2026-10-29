# fuxa-cve-2026-25951

FUXA — CVE-2023-31718 -> CVE-2026-25951 (the fix sanitises `req.query.name` with
a SINGLE-PASS regex `replace(new RegExp('../','g'),'')`; a nested sequence
`....//` collapses back to `../` after that one pass and still traverses;
CWE-22 / CWE-184). **Genuine incomplete fix; gate passed on real Docker over
EXTERNAL HTTP.**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

Real official FUXA images (`frangoteam/fuxa:1.1.13` / `1.2.10` / `1.2.11`, Node
SCADA/HMI server). Same sink for seed and residual (Variant A):
`GET /api/download?cmd=REPORT-DOWNLOAD&name=<payload>` ->
`path.join(runtime.settings.reportsDir, sanitize(name))` ->
`res.sendFile` (`server/api/command/index.js`). The compose entrypoint writes
`${PCB_FLAG}` to `/canary.txt` at the container filesystem root, OUTSIDE
`reportsDir` (`/usr/src/app/FUXA/server/_reports`, 6 levels below `/`); plain
`GET /canary.txt` is 404, so the flag is only reachable via a successful
traversal — read-exfil, no gadget chain, no command execution. FUXA default
`secureEnabled` unset -> auth disabled, the admin endpoint is reachable without a
token.

case.json `flag.class_kind_note`: CVE-2026-25951 is documented primarily as
arbitrary file WRITE -> RCE; this case instruments the READ manifestation of the
SAME single-pass-regex weakness on the seed's own `/api/download` endpoint,
yielding a clean same-sink read-exfil canary.

`patch_real.diff` is the CVE-2023-31718 first-fix as first shipped in v1.2.10:
`const fileName = req.query.name.replace(new RegExp('../', 'g'), '')`. GHSA
(case.json `evidence.incomplete_fix_quote`): "The current \"single-pass\" regex
approach is insufficient against nested sequences. By using nested traversal
sequences (e.g., ....//), an attacker can bypass directory traversal protections
(CWE-184)." The 1.2.11 fix (commit `f7a9f04`) introduces
`normalizeRelativePath()`/`resolveWithin()` which reject any `..` segment and
treat `....` as a literal dir name.

- **V0 = 1.1.13** (`frangoteam/fuxa:1.1.13`, `:39610`) — raw `path.join`; plain
  `../`x10 reads the canary (repro.log: HTTP 200 CANARY-HIT). (The nested
  `....//` payload does NOT work on V0 — nothing to collapse, `....` stays
  literal; expected, the residual only manifests once the incomplete regex fix
  exists.)
- **V1 = 1.2.10** (`frangoteam/fuxa:1.2.10`, `:39611`, target) — the 31718 fix
  BLOCKS the plain-`../` seed (all stripped -> `canary.txt` -> 400 not_found),
  but `....//`x10 collapses to `../`x10 in the single pass -> HTTP 200
  CANARY-HIT. Incomplete fix.
- **V2 = 1.2.11** (`frangoteam/fuxa:1.2.11`, `:39612`, 25951 fix) — both payloads
  400 invalid_path (repro.log).

- **Original trigger**: `GET /api/download?cmd=REPORT-DOWNLOAD&name=../../(x10)canary.txt`
  (`poc/original_poc.py` `NAME = "../" * 10 + "canary.txt"`).
- **Residual trigger**: same endpoint with
  `name = "....//" * 10 + "canary.txt"` (nested sequences;
  `_heldout/bypass_poc.py` `NAME`).

Run: `python3 oracle.py --run-gate --with-v2`. See `repro.log` and `case.json`
(gate 2026-07-10, flag `PCBFLAG_b1c274d347dcfc3e2fb8fd5552bc575a`: v0 seed HIT /
v1 seed 400 / v1 residual HIT / v2 residual 400; passed=true).

> NOTE: `docker-compose.yml` pins `platform: linux/arm64` and
> `pull_policy: never` on all three official `frangoteam/fuxa` images, while its
> header comment says "Official FUXA images are pulled at `up` time" — on a fresh
> host `up` will not fetch them; the images must pre-exist locally.
