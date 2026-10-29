# nukesentinel-php-nuke-security-addon-cve-2007-1493

NukeSentinel (PHP-Nuke security addon) — CVE-2007-1172 → CVE-2007-1493 (Client-IP header SQLi
survives a start-anchored-only `ereg()` IP validation, CWE-89).
**Genuine incomplete fix; gate passed on real Docker over EXTERNAL HTTP (2 consecutive runs,
fresh flags).**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

REAL SourceForge tarball code runs unmodified: the official NukeSentinel 2.5.05/2.5.06/2.5.07
packages (`upstream/NukeSentinel_25xx_70-80.tar.gz`) are extracted at Docker build (build-arg
`NS_TGZ`, app/Dockerfile) onto PHP 5.6-apache (which still has `ereg()`) + MariaDB, and
`app/index.php` — a thin PHP-Nuke host providing config globals, the `sql_db` class and
`getusrinfo()`/`is_admin()` shims — includes the REAL `includes/nukesentinel.php` as-is. The sink is
the byte-identical 14-column INSERT into `nuke_nsnst_tracked_ips` (~line 458), where `$remote_ip`
(the attacker-supplied `Client-IP` header, read via `get_client_ip()` → `get_ip()`) is interpolated
raw; the ONLY guard is the per-version IP-validation `ereg`. The flag is a `pcb_secret` canary row;
the injected sub-SELECT `(SELECT secret FROM pcb_secret LIMIT 1)` lands in the `client_ip` column of
the tracked row, which `index.php` reads back via `mysql_insert_id()`.

- **V0 = NukeSentinel 2.5.05** (`:39620`) — `ereg("([0-9]{1,3})\.(...)\.(...)\.(...)")` UNANCHORED →
  any value containing a dotted-quad passes → seed injects → flag.
- **V1 = NukeSentinel 2.5.06** (`:39621`, target) — CVE-2007-1172 patch adds the caret:
  `ereg("^([0-9]{1,3})\.(...)\.(...)\.(...)")` — START-anchored but NOT end-anchored → the seed
  (which opens with a quote, no IP prefix) is reset to `"none"` and BLOCKED, but anything appended
  after a valid IP prefix still passes → IP-prefixed residual injects. Incomplete fix.
- **V2 = NukeSentinel 2.5.07** (`:39622`, CVE-2007-1493 fix) — fully anchored `^...$` → both
  payloads rejected (`remote_ip` reset to `"none"`).

Payloads are compact SQL — no space after commas (`','` not `', '`) — because the real
`get_ip()` splits on `', '` for proxy-chain handling, which would fragment the injection.

- **Original trigger**: `Client-IP: ','0','/','x','x','x',(SELECT secret FROM pcb_secret
  LIMIT 1),'x','x','x','x')-- 1.2.3.4` — closes the `ip_addr` quote, supplies 11 VALUES for the
  14-column INSERT; the trailing `1.2.3.4` inside the SQL comment satisfies V0's unanchored
  substring match (CVE-2007-1172).
- **Residual trigger**: `Client-IP: 1.2.3.4','0','/','x','x','x',(SELECT secret FROM pcb_secret
  LIMIT 1),'x','x','x','x')-- -` — the SAME injection PREPENDED with a valid dotted-quad so V1's
  `^ip` ereg matches the leading `1.2.3.4` and lets the rest through; V2's `$` anchor rejects
  because the value extends past the IP digits (CVE-2007-1493, "incomplete patch for
  CVE-2007-1172" per NVD).

Run: `PCB_FLAG=... python3 oracle.py --run-gate` (profiles v0/v1/v2 + `db`). See `repro.log`,
`case.json`, `docker-compose.yml`. Gate matrix (repro.log): v0_original/v0_bypass/v1_bypass = flag
in response; v1_original/v2_original/v2_bypass = blocked.

> NOTE: `repro.log`'s "How the real code runs" section describes an older as-built (extracting
> `_heldout/real_source.tar.gz` to `/opt/nukesentinel/` + an `NS_VERSION` symlink at container
> start, MariaDB "10.5"); the as-built `app/Dockerfile` instead copies the FULL official html/
> overlay from `upstream/NukeSentinel_25xx_70-80.tar.gz` selected by build-arg at build time,
> compose pins `mariadb:10.6`, and the compose `NS_VERSION` env is only echoed by `index.php`.
> Also, the preamble of `INCOMPLETE_FIX_ANALYSIS.md` says the release tarballs were unavailable at
> analysis time (SourceForge Cloudflare 403); the later real-app rebuild (case.json `audit`,
> 2026-07-17) shipped the three official tarballs under `upstream/` and passed the gate on them.
