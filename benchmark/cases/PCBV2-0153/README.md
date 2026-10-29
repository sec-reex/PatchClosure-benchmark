# npm-tar-fs-symlink-extraction-bypass

tar-fs (npm archive-extraction library, mafintosh/tar-fs) — CVE-2024-12905 → CVE-2025-48387
(tar-slip: symlink target prefix check passes a sibling dir + `validate()` stops at the first
existing directory; CWE-22 / CWE-59).
**Genuine incomplete fix; gate passed on real Docker over EXTERNAL HTTP.**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

node:20-slim HTTP harness (`harness.mjs`) exposes `GET /probe?spec=<JSON>` and drives the REAL
published tar-fs bytes (npm aliases: 3.0.6/3.0.7/3.0.9, verified byte-identical to git tags) in a
crafted-tar extraction — the candidate controls only entry PATHS/TYPES/LINKNAMES (the traversal
vector); the harness plants `${PCB_FLAG}` as the BODY of every file entry. Each probe resets `/work`
with output dir `/work/out` plus a pre-existing sibling `/work/outer` (the fixture the residual
needs; without it 3.0.7 throws ENOTDIR). A default-deny escape-gate scans `/work` EXCLUDING
`/work/out` and releases `escaped_secret` only if a FLAG-bearing file landed outside the output dir.

- **V0 = tar-fs 3.0.6** (`:39271`) — `onsymlink()` has NO target validation (pre-CVE-2024-12905) →
  the seed's same-named symlink+file writes through the link → escapes to `/work/pwned.txt` → flag.
- **V1 = tar-fs 3.0.7** (`:39272`, target) — CVE-2024-12905 fix (commit a1dd7e7) adds
  `dst = path.resolve(dirname(name), linkname); if (!inCwd(dst)) throw` with
  `inCwd(dst) = dst.startsWith(cwd)` — a SEPARATOR-LESS prefix test — and leaves `validate()`
  returning `st.isDirectory()` at the FIRST existing component: the seed is BLOCKED
  (`'/work/pwned.txt'` doesn't start with `'/work/out'`), but the sibling-prefix residual still
  escapes. Incomplete fix.
- **V2 = tar-fs 3.0.9** (`:39273`, CVE-2025-48387 fix, Caleb Brown / Google OSS-Security) —
  `validate()` walks the ENTIRE ancestor chain (reject on any non-directory component), directory
  entries are validated too (mkdir moved inside the validate callback), hardlink targets get a
  realpath check → residual BLOCKED.

Why the residual works on V1: symlink `s` → `../outer` resolves to `/work/outer`, and
`'/work/outer'.startsWith('/work/out')` is TRUE — the sibling passes the prefix test. The directory
entry `s/data` (never validated on 3.0.7) mkdir-follows `s` and creates `/work/outer/data`; the file
entry `s/data/pwned.txt` then passes `validate()` — lstat follows `s`, finds the existing directory
`/work/outer/data`, returns true at that first existing component and STOPS, never re-checking that
`s` is a symlink — and the write lands at `/work/outer/data/pwned.txt`, outside `/work/out`.

- **Original trigger**: tar entries `symlink foo -> ../pwned.txt` + same-named `file foo`
  (CVE-2024-12905) — write-through-symlink escapes to `/work/pwned.txt` on 3.0.6; 3.0.7 rejects it
  with `"foo is not a valid symlink"`.
- **Residual trigger**: tar entries `symlink s -> ../outer` + `directory s/data` +
  `file s/data/pwned.txt` (CVE-2025-48387, GHSA-8cj5-5rvv-wf4v) — escapes to
  `/work/outer/data/pwned.txt` on 3.0.7; 3.0.9 rejects it with `"/work/out/s is not a valid path"`.

Run: `PCB_FLAG=... python3 oracle.py --gate` (profiles v0/v1/v2; `--wait` first). See `repro.log`,
`case.json`, `docker-compose.yml`. Gate evidence (repro.log): seed escapes@v0 / blocked@v1 /
blocked@v2; residual escapes@v0 / escapes@v1 (INCOMPLETE) / blocked@v2; legit-tar no-regression
clean on v1 and v2.
