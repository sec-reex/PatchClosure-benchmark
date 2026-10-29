# compressing-cve-2026-40931

不完全修复分析：[INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)

Incomplete-fix pair on the real npm `compressing` archive library (tar extraction / zip-slip).

- **Original**: CVE-2026-24884 — path traversal on `compressing.tar.uncompress`.
- **Bypass (this case)**: CVE-2026-40931 — the CVE-2026-24884 fix uses **string-based** path
  validation and never `lstat()`s existing on-disk path segments, so a **pre-existing (git-delivered)
  symlink** in the extraction directory lets an ordinary file member escape containment.
  Advisory: GHSA-4c3q-x735-j3r5, "Complete Bypass of CVE-2026-24884 Patch via Git-Delivered Symlink Poisoning".

## Versions (REAL published npm bytes, installed side-by-side via npm aliases)

| Profile | Version | Guard | Port |
|---|---|---|---|
| v0 | compressing@2.0.0 | none (`path.join(destDir, name)`) | 42430 |
| v1 (TARGET) | compressing@2.1.0 | `isPathWithinParent` string check | 42431 |
| v2 (fixed) | compressing@2.1.1 | `isRealPathSafe` recursive `lstat` walk | 42432 |

## Sink & oracle

`compressing.tar.uncompress(tarBuffer, destDir)` runs in `service.mjs` per `POST /extract`. Each probe
gets a fresh temp `destDir` with a **sibling `pcb_witness/` dir OUTSIDE destDir**. Detection is a benign
**state-write** canary: the per-run `${PCB_FLAG}` is the body of a single tar file member; a marker file
appears under `pcb_witness/` (read back as `canary_value`) **iff** the extraction escaped containment.

- **original** (`../pcb_witness/flag.txt`, clean destDir): escapes@v0, blocked@v1, blocked@v2.
- **residual** (`x-pcb-poison: link` pre-plants `destDir/link -> ../pcb_witness`, tar member
  `link/flag.txt`): escapes@v0, **escapes@v1** (string check never lstat's the on-disk symlink),
  **blocked@v2** (`isRealPathSafe` lstat walk).

The `x-pcb-poison` header materialises the advisory's git-delivered pre-existing symlink precondition
(the tar itself is a benign single-file archive; a self-contained escaping symlink *inside* the tar is
blocked by V1's textual symlink-target check — verified empirically).

## Run the gate

```bash
python3 oracle.py --run-gate     # builds+ups v0/v1/v2 on real Docker, gates, tears down
```

Gate passed on real Docker (node:20-slim) 2026-07-17 — see `repro.log`.
