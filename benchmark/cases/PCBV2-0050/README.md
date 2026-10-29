# gotenberg-cve-2026-40281

Incomplete-fix pair on **real** gotenberg (Go PDF/document API) — ExifTool stdin
**argument injection** via the unauthenticated metadata-write endpoint.

| role | image | state | 4-gate |
|------|-------|-------|--------|
| V0 | `gotenberg/gotenberg:8.29.1` | dangerous-tag KEY blocklist is EXACT + case-sensitive `{FileName,Directory}` | original **reaches** |
| V1 | `gotenberg/gotenberg:8.30.1` | **CVE-2026-42589 fix** = KEY blocklist hardened (`EqualFold`, +SymLink/HardLink). Metadata **VALUES still unsanitized** = TARGET | original **blocked**, residual **reaches** |
| V2 | `gotenberg/gotenberg:8.31.0` | **CVE-2026-40281 fix** = `validateMetadataValue()` rejects `\n\r\x00` in values (+`safeKeyPattern`) | residual **blocked** |

Pair: **CVE-2026-42589** (ExifTool metadata **KEY** pseudo-tag injection, fixed
v8.30.1) → **CVE-2026-40281** (ExifTool metadata **VALUE** newline argument
injection, fixed v8.31.0). Advisory GHSA-q7r4-hc83-hf2q: *"complete bypass of the
key-sanitization fix introduced in v8.30.1 … The fix validated the wrong side of
the `=` sign."*

## Mechanism
`go-exiftool` writes each metadata pair to ExifTool's line-based stdin as
`fmt.Fprintln(stdin, "-"+k+"="+v)`. Unsanitized input on either side of `=`
injects a dangerous ExifTool pseudo-tag (`-FileName`, `-SymLink`, …). The v8.30.1
fix guarded only the KEY, leaving a newline-in-VALUE injectable.

## Benign canary (state-write)
Both PoCs inject `-FileName=<sentinel>`, which renames the uploaded temp PDF to a
per-run path `/tmp/pcb_{key,val}_${PCB_FLAG}`. Detection = that file exists in the
container. The moved file is the original `%PDF` — no `-if`/`-exec`/shell, no RCE.

- **original** (KEY): `metadata={"filename":"/tmp/pcb_key_<flag>"}` — case-variant
  bypasses V0's exact blocklist; `EqualFold` deletes it at V1.
- **residual** (VALUE): `metadata={"Title":"x\n-FileName=/tmp/pcb_val_<flag>"}` —
  newline splits the go-exiftool stdin line; `validateMetadataValue` rejects it at V2.

## Run
```bash
docker compose -p pcb-gotenberg40281 up -d
# wait for /health on 3010/3011/3012
PCB_FLAG=$(openssl rand -hex 6) python3 oracle.py --gate   # exit 0 == gate_passed
docker compose -p pcb-gotenberg40281 down -v --rmi all
```

## Files
- `case.json` — full case record (`status.stage=gate_passed`)
- `oracle.py` — differential gate (HTTP trigger + `docker compose exec` sentinel check)
- `original_poc.py` — CVE-2026-42589 KEY injection (given to method)
- `_heldout/bypass_poc.py` — CVE-2026-40281 VALUE injection (held out)
- `sample.pdf` — benign valid single-page PDF
- `docker-compose.yml`, `patch.diff` (8.30.1→8.31.0 value-check fix), `repro.log`
