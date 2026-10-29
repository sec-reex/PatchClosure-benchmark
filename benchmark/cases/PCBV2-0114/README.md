# freescout-cve-2026-53593

FreeScout — CVE-2025-48471 -> CVE-2026-53593 (the 1.8.179 fix adds `phtml`/`phar`
to the `Helper::$restricted_extensions` upload denylist but not `.pht`, which
Debian Apache's mod_php handler `<FilesMatch ".+\.ph(ar|p[3457]?|t|tml)$">`
executes; upload denylist extension bypass -> RCE; case.json records root_cause
`Unrestricted_Upload`, no CWE ID). **Genuine incomplete fix; gate passed on real
Docker over EXTERNAL HTTP.**

长文分析见 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

Real FreeScout from the FULL upstream tree at pinned git tags (1.8.178 / 1.8.223 /
1.8.224, `php:7.4-apache` + `mariadb:10.6`, Laravel migrate + `freescout:create-user`
admin + seeded mailbox/conversation via artisan). The sink is the real
`SecureController@upload` -> `Helper::uploadFile`/`sanitizeUploadedFileName`:
authenticated `POST /uploads/upload` stores the file with its (sanitized)
extension into `storage/app/public/uploads/`, web-reachable via the `public/storage`
symlink at `/storage/uploads/<name>`. RCE canary: the entrypoint writes
`${PCB_FLAG}` to `/canary.txt`; the uploaded webshell runs `cat /canary.txt`
(`?c=cat /canary.txt`) and the flag returns in the HTTP response.

`patch_real.diff` is the CVE-2025-48471 fix (commit
`e136660e8dbc220454b8d3f646dd1b144e49e9ed`, 1.8.179, `app/Misc/Helper.php`):
`'phtml', 'phar'` appended to the denylist. GHSA-27vp-fpg8-j8wv (case.json
`evidence.incomplete_fix_quote`): "The denylist that neutralises dangerous file
uploads (Helper::$restricted_extensions) is incomplete: it does not cover the
.pht extension. ... On the standard Apache + libapache2-mod-php deployment, the
default handler <FilesMatch \".+\.ph(ar|p[3457]?|t|tml)$\"> executes .pht, so any
authenticated agent can upload a .pht web shell and run arbitrary commands." The
1.8.224 fix adds `.pht`.

- **V0 = 1.8.178** (`:33660`) — no denylist entry for `.phtml`: the `.phtml`
  webshell is stored live and executes -> flag (repro.log: seed reaches).
- **V1 = 1.8.223** (`:33661`, target) — the 48471 fix BLOCKS the `.phtml` seed
  (renamed inert, plaintext source returned), but the `.pht` residual is stored
  live (denylist regex `/php.*/` doesn't match "pht") and the Debian handler
  executes it -> RCE -> flag. Incomplete fix.
- **V2 = 1.8.224** (`:33662`, 53593 fix) — `.pht` denylisted -> blocked
  (repro.log).

- **Original trigger**: authenticated `POST /uploads/upload` with a `.phtml`
  webshell, then `GET /storage/uploads/<random>.phtml?c=cat /canary.txt`
  (`poc/original_poc.py` `candidate`, extension `phtml` via `poc_common.upload_and_exec`).
- **Residual trigger**: same endpoint with a `.pht` webshell, then
  `GET /storage/uploads/<random>.pht?c=cat /canary.txt`
  (`_heldout/bypass_poc.py` candidate, extension `pht`).

Run: `python3 oracle.py --run-gate --with-v2` (gate, flag
`PCBFLAG_ceee4b6f3ab4f16b7527197f56e6cc01`: seed reaches@v0 / seed blocked@v1 /
residual reaches@v1 / residual blocked@v2; passed=true). See `repro.log` and
`case.json`.

> NOTE (1): repro.log asserts `original_poc_blocked_on_v1` /
> `bypass_poc_reaches_flag_on_v1` / `bypass_poc_blocked_on_v2` while
> `_env_ready` shows `v1:false, v2:false` — the gate booleans are recorded ahead
> of the readiness flags in the same JSON.
> NOTE (2): case.json `provenance.patch_diff_fix` records that `patch.diff` was
> ROUND7-corrected (was a V1->V2 mislabel, replaced with the upstream V0->V1
> diff); the security delta used here is `patch_real.diff` (commit `e136660e`).
