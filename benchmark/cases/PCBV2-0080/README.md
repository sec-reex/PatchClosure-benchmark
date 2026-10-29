# arcadedb-cve-2026-54076

ArcadeDB — CVE-2026-44221 → CVE-2026-54076 (broken authorization on schema mutation: the
UPDATE_SCHEMA check added to ONE schema-mutating method, sibling mutators left unchecked,
CWE-862 / CWE-863).
**Genuine incomplete fix; 4-boolean gate observed live on real official ArcadeDB images over
EXTERNAL HTTP (2026-07-17 — see `repro.log`).**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

REAL official `arcadedata/arcadedb` images per version (`:24801` / `:24802` / `:24803` → container
:2480, `POST /api/v1/command/pcb` over HTTP). Root seeds database `pcb` with document type `Widget`
carrying a STRING property named after the per-run `${PCB_FLAG}`; a REAL read-only identity is minted
via `POST /api/v1/server/api-tokens` (`permissions.database=[]`, `types.*.access=[readRecord]` ⇒ no
`updateSchema`) and then issues schema-mutating DDL over the SAME HTTP command endpoint. Detection =
the DDL returns HTTP 2xx AND an admin follow-up `SELECT properties FROM schema:types` shows the
planted property state changed (a new injected property for the seed; the flag property gone for the
residual). Benign authz canary only — no record data disclosed or destroyed beyond the planted property.

- **V0 = 26.3.2** (`:24801`) — pre-CVE-2026-44221: `LocalDocumentType` has NO UPDATE_SCHEMA check on
  any schema mutator → read-only `CREATE PROPERTY Widget.injected_${PCB_FLAG} STRING` returns 200 and
  the property appears in the admin schema query. Seed and residual both open.
- **V1 = 26.4.2** (`:24802`, target; CVE-2026-44221 fix commit `04110c06`, GHSA-fxc7-fm93-6q77) —
  `LocalDocumentType.createProperty(String, Type, String)` gains an inline
  `checkPermissionsOnDatabase(UPDATE_SCHEMA)` → seed DDL is HTTP 403
  `"...is not allowed to update schema"` (SecurityException), BLOCKED. But `dropProperty` (and the
  other sibling mutators — `setSuperTypes` / `addSuperType` / `LocalProperty` setters) is UNCHANGED →
  `DROP PROPERTY Widget.${PCB_FLAG}` by the SAME read-only token returns 200 and the flag property is
  removed from the schema. Incomplete fix.
- **V2 = 26.6.1** (`:24803`, CVE-2026-54076 fix; commit `2ee76fe` / PR `#4423`, GHSA-vg6x-6pg9-6qwg
  "Read-only users can mutate database schema (incomplete fix of CVE-2026-44221)") — a shared
  `LocalDocumentType.checkForSchemaMutation()` helper is invoked at all 10 public schema-mutator call
  sites (no-op in embedded/system contexts); `dropProperty`'s first line is the check → residual DDL
  is HTTP 403, schema unchanged, BLOCKED.

- **Original trigger**: read-only API token POSTs `CREATE PROPERTY Widget.injected_${PCB_FLAG} STRING`
  to `/api/v1/command/pcb` — the `LocalDocumentType.createProperty(String, Type, String)` mutator.
- **Residual trigger**: the SAME read-only token POSTs `DROP PROPERTY Widget.${PCB_FLAG}` — the
  sibling `LocalDocumentType.dropProperty` mutator, which writes the same schema but had no
  UPDATE_SCHEMA check at 26.4.2. Only the DDL verb differs.

Run: `python3 oracle.py <base_url> <original|residual>` per check (four `detected` booleans in
`repro.log`; platform `scripts/verify.sh --seed|--residual` wraps the same vectors). See `repro.log` and `case.json`.

> NOTE: `_heldout/bypass_poc.py` is claimed as held out in `case.json` (`held_out`), but an identical
> copy exists at `poc/bypass_poc.py` (`diff` reports the two files SAME).
