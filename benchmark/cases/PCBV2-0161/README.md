# openstack-glance-cve-2015-1195

不完全修复分析见 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

OpenStack Glance — **CVE-2014-9493 → CVE-2015-1195** (arbitrary host-file
disclosure via the Glance v2 image-location URI scheme; CWE-22).

**Incomplete fix.** CVE-2014-9493 (commit `4afdb017`) added
`glance/common/store_utils.py::validate_external_location`, which strips only
`file` and `swift+config` from the allowed image-location schemes. But the
`glance_store` filesystem backend answers to **two** schemes for the same
local-file store — `file` *and* `filesystem` — and `filesystem` was left off the
blocklist. So `filesystem:///etc/passwd` still passes the guard and the store
reads the host file (CVE-2015-1195). CVE-2015-1195 (commit `a2d986b9`) adds
`filesystem` to `RESTRICTED_URI_SCHEMAS`.

- V0 `81b3c04e` (pre-9493): `file://` and `filesystem://` both disclose.
- V1 `4afdb017` (9493 fix, **target**): `file://` blocked, `filesystem://` discloses.
- V2 `a2d986b9` (1195 fix): both blocked.

Each container runs the **real** `store_utils.py` guard at its commit over the
**genuine** `glance_store` filesystem backend (real read-exfil). The canary is
planted by the entrypoint at `/canary/secret.txt`, outside the store datadir.
No Glance code is modified.

Gate (real Docker): `python3 oracle.py --run-gate` → all three booleans true.
See `repro.log`. Teardown:
`PCB_FLAG=teardown docker compose --profile v0 --profile v1 --profile v2 down -v --rmi all`.
