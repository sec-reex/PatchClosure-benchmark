# PatchClosure Benchmark

PatchClosure is a benchmark of **213 executable incomplete-fix chains** from
**184 real web products** in 8 languages. Each chain is:

```
V0 (vulnerable)  →  V1 (incomplete fix)  →  V2 (complete fix)
```

with a live-flag oracle: a fresh, unguessable canary token is planted in the
effect channel of each deployment, and a trial succeeds only if the tool's
input makes the running V1 instance emit that token through the real effect
channel. Scoring uses a double-replant protocol (same port, two deployments,
two different flags) so a hardcoded or remembered token cannot pass.

## Layout

```
benchmark/
  cases/PCBV2-XXXX/       one directory per chain:
                            case.json / case.yaml    metadata (visible inputs whitelisted)
                            docker-compose.yml       v0/v1/v2 profiles on pinned refs
                            patch.diff               the V0→V1 first-fix diff (shipped header-stripped)
                            poc/original_poc.py      the blocked seed (sanitized copy ships to contestants)
                            scripts/, overlays/      deployment + verification helpers
  secrets/PCBV2-XXXX/     HELD-OUT per case: oracle.py (ground-truth judge),
                          bypass_poc.py (the residual), INCOMPLETE_FIX_ANALYSIS.md,
                          gate_result.json (four-gate validation record).
                          Never ship these to a system under test.
  gold_frozen.json        frozen gold answers + manifest hash
  flag_oracle.py          the generic canary checker
  provenance/             source manifest: per-case repo URL + pinned ref
  tools/                  gate/scoring helpers; fetch_v1_sources.py rebuilds the
                          V1 source trees (not shipped; ~10 GB) from provenance pins
  schemas/ tests/ ci/     case schema, self-tests, CI
sessions/
  session_data.json       the 7-arm × 213-case exploratory-study session ledger
  RESULTS.jsonl           verdict ledger (append-only, schema in file head)
  generate_dashboard.py   rebuilds the study dashboard from the two ledgers
                          (raw transcripts are not required for regeneration)
```

## Rebuilding V1 sources

```bash
python3 benchmark/tools/fetch_v1_sources.py   # shallow-clones each case's pinned ref
```

## Giving a case to a system under test

Ship ONLY: `v1_source/` (from the fetch), header-stripped `patch.diff`,
sanitized `poc/original_poc.py`, and `env.json = {"port": N}` of a live V1
deployment. Everything under `secrets/` and any `residual_poc.py` must be
withheld. The trial succeeds when the system's `residual_test.py` prints
`FLAG: <this deployment's canary>` on both double-replant runs.

## Provenance

Every chain is derived from a public CVE pair in which the second report
states the first fix was incomplete. Per-case product, versions, and refs are
in `case.json` (`versions`, `provenance`) and `provenance/source_manifest.json`.

## License / citation

See the paper for the study this benchmark supported. Each embedded product's
source retains its upstream license (see per-case `case.json`).
