# goshs-cve-2026-54719

goshs — CVE-2026-40189 -> CVE-2026-54719 (the v2.1.0 fix adds
`findEffectiveACL`/`applyCustomAuth` to the state-changing routes, but the
`?bulk` zip-download handler — dispatched from `earlyBreakParameters` BEFORE the
normal `doDir`/`doFile`/`sendFile` flow — streams files as a ZIP without ever
calling the ACL check; authorization inconsistency on an alternate route;
case.json records root_cause `Broken_Access_Control`, no CWE ID). **Genuine
incomplete fix; gate passed on real Docker over EXTERNAL HTTP.**

长文分析见 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

Official goshs release binaries per profile (`v2.0.0-beta.3` tar.gz for V0,
`v2.1.0`/`v2.1.1` .deb for V1/V2; debian:bookworm-slim) serving webroot
`/data/root`. The `/protected/` folder is gated by a per-folder `.goshs`
basic-auth ACL (`admin:admin`), so normal reads return 401. Read-exfil canary:
the compose entrypoint copies the ACL template to `/data/root/protected/.goshs`
and writes `${PCB_FLAG}` to `/data/root/protected/canary.txt`; the flag appears
in the HTTP body only when the ACL is bypassed (plain read for the seed, ZIP
contents for the residual).

GHSA-rmxw-pq4x-3fvh (case.json `evidence.incomplete_fix_quote`): "bulkDownload
... streams the contents back as a ZIP without ever calling
findEffectiveACL/applyCustomAuth. It is dispatched from earlyBreakParameters
(?bulk) before the normal doDir/doFile/sendFile flow that performs the ACL check.
An unauthenticated attacker can therefore read any file under the webroot
protected solely by a .goshs ACL." NVD: "This vulnerability exists due to an
incomplete fix for CVE-2026-40189." `patch_real.diff` is the CVE-2026-40189 fix
(commit `f212c4f4a126556bab008f79758e21a839ef2c0f`, v2.1.0, adding
`findEffectiveACL` in `httpserver/filebased.go`); the v2.1.1 fix (commit
`7cf911a26ace737e1a55b7dc073e307a25f7fd1d`) routes `bulkDownload` through the
same ACL.

- **V0 = v2.0.0-beta.3** (`:55130`) — state-changing routes bypass the ACL:
  `GET /protected/.goshs?delete` removes the ACL unauthenticated, then
  `GET /protected/canary.txt` returns the flag (repro.log: seed reaches).
- **V1 = v2.1.0** (`:55131`, target) — the 40189 fix BLOCKS the delete seed (401),
  but `GET /?bulk&file=/protected/canary.txt` returns a ZIP containing the
  protected canary without any ACL check. Incomplete fix.
- **V2 = v2.1.1** (`:55132`, 54719 fix) — `bulkDownload` enforces the ACL ->
  blocked (repro.log).

- **Original trigger**: `GET /protected/.goshs?delete` (unauthenticated ACL
  delete) then `GET /protected/canary.txt` (`poc/original_poc.py` candidate).
- **Residual trigger**: `GET /?bulk&file=/protected/canary.txt` (ZIP download;
  `_heldout/bypass_poc.py` candidate, unzip + read entries). Control: plain
  `GET /protected/canary.txt` -> 401 while the ACL exists.

Run: `python3 oracle.py --run-gate --with-v2` (gate, flag
`PCBFLAG_95a9f462a36a45fbcc53dc32205d50b6`: seed reaches@v0 / seed blocked@v1 /
residual reaches@v1 / residual blocked@v2; passed=true). See `repro.log` and
`case.json`.

> NOTE: `docker-compose.yml`'s header comment says "v0 = goshs 2.0.9" and
> `poc/original_poc.py` says "Reaches the flag on v0 (2.0.9)", but the actual
> build arg (and case.json versions.v0) pins `2.0.0-beta.3` — both stale
> references to a different pre-fix version.
