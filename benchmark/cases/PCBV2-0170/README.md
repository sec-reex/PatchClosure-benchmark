# phpmyfaq-cve-2026-56396

不完整修复分析见 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

phpMyFAQ IDOR / missing-authorization incomplete-fix differential (CWE-639 / CWE-862 / CWE-269),
on **REAL phpMyFAQ** (PHP 8.3 + Apache/mod_php + MariaDB), attacked over **external HTTP**.

**CVE-2026-35671** (GHSA-xvp4-phqj-cjr3): `overwritePassword()` at `admin/api/user/overwrite-password`
took `userId` with no object-level authz check — a low-priv user administrator could overwrite the
SuperAdmin's password and take over uid=1. Fixed in **4.1.3** by guarding *that method only*.

**CVE-2026-56396** (GHSA-985r-q3qp-299h): the 4.1.3 fix left the sibling methods `editUser()`
(`admin/api/user/edit`, mass-assigns `is_superadmin`) and `updateUserRights()`
(`admin/api/user/update-rights`) byte-identical to 4.1.2 — still unguarded. Closed in **4.1.4**.

Versions (real git tags, cloned + `composer install` + real web installer per image):
**V0** = 4.1.2 (all unguarded), **V1** = 4.1.3 (target: overwritePassword guarded, siblings open),
**V2** = 4.1.4 (siblings guarded). phpMyFAQ serves its OWN Symfony routing / `Api\UserController` —
**nothing is lifted or shimmed.**

Attacker = low-privilege user administrator `editor` (add_user+edit_user+delete_user, NOT SuperAdmin,
NOT editconfig). Canary (authz-seeded, benign): `${PCB_FLAG}` = phpMyFAQ's real REST-API client token,
config item `api.apiClientToken`, disclosed only via `GET /admin/api/configuration/list/api`
(gated by `CONFIGURATION_EDIT`; a SuperAdmin holds every right implicitly). `editor` reading it proves
privilege escalation to SuperAdmin.

Gate (Variant A, real Docker): original@v0 reaches flag; original@v1 blocked (403); bypass@v1 reaches
flag; bypass@v2 blocked (403). See `repro.log`.

Run: `PCB_FLAG=<tok> docker compose --profile v0 --profile v1 --profile v2 up -d --build`
then `PCB_FLAG=<tok> python3 oracle.py --wait --v2check`.

## Layout
- `Dockerfile`, `docker-compose.yml` — real phpMyFAQ per version + MariaDB.
- `pcb/` — harness only (NOT phpMyFAQ code): Apache vhost, entrypoint (runs the real installer),
  `pcb_seed.php`/`pcb_reset.php` (seed/reset the editor + canary via phpMyFAQ's own APIs), `db-init.sql`.
- `oracle.py`, `original_poc.py`, `_heldout/bypass_poc.py`, `patch.diff`, `case.json`, `repro.log`.

## STALE (superseded by the real-app rebuild; left in place, NOT used — do not ship)
- `router.php` — old php-built-in-server shim router.
- `core/pmf_shim.php`, `core/v0/UserController.php`, `core/v1/UserController.php`,
  `core/v2/UserController.php` — the BANNED verbatim source lift.
- `__pycache__/` — stale bytecode.
