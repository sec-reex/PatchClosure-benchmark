# codeinj_pyyaml_fullloader

PyYAML — CVE-2020-1747 -> CVE-2020-14343 (YAML deserialization / FullLoader object escape
bypassing a state-key blacklist, CWE-502).
**Genuine incomplete fix; gate passed on real Docker over EXTERNAL HTTP.**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

REAL Python HTTP service (`app.py`, Flask `POST /parse`) passes the raw attacker-supplied
request body to the REAL, unmodified published `yaml.full_load(request.data)` — exactly how
an app parses user-supplied YAML (config upload, API body). Same sink, same CVE pair: NVD
states the CVE-2020-14343 flaw "is due to an incomplete fix for CVE-2020-1747". Each profile
pip-installs the EXACT published PyYAML sdist (5.3 / 5.3.1 / 5.4) on python:3.8-slim; only
the PyYAML version varies across profiles, the service code is identical. The per-run
`${PCB_FLAG}` canary is planted at `/flag` (outside /app) by the compose command wrapper;
the object escape's BENIGN reader copies it into `/out/leak.txt` (local file read+copy —
no shell, no subprocess, no network) and `/parse` surfaces it in the JSON response. No
gadget beyond the read-copy, nothing in PyYAML is modified.

- **V0 = PyYAML 5.3** (`:34810`) — no state-key blacklist; `set_python_instance_state`
  writes any `state:` mapping -> the `extend` = `exec` seed fires during `full_load` -> flag
  reaches the `/parse` response.
- **V1 = PyYAML 5.3.1** (`:34811`, target; CVE-2020-1747 fix, merge `5080ba5`) — the new
  `check_state_key` / `get_state_keys_blacklist` (`^extend$`, `^__.*__$`) refuses the seed's
  state key -> `ConstructorError: blacklisted key 'extend' in instance state found` -> seed
  BLOCKED. But the blacklist only inspects the instance STATE; `python/object/new` is still
  registered on `FullConstructor` and never inspects class-CONSTRUCTION arguments -> the
  CVE-2020-14343 residual still reaches the flag. Incomplete fix.
- **V2 = PyYAML 5.4** (`:34812`, CVE-2020-14343 fix, commit `a001f27`) — `python/module`,
  `python/object`, `python/object/new`, `python/object/apply` multi-constructors are MOVED
  from `FullConstructor` to `UnsafeConstructor` -> both the original and the residual hit
  `ConstructorError: could not determine a constructor` -> BLOCKED.

- **Original trigger**: `!!python/object/new:_frozen_importlib.ModuleSpec` +
  `state: {extend: !!python/name:builtins.exec}` + `listitems: "open('/out/leak.txt','w').write(open('/flag').read())"`
  — poisons `extend` THROUGH the state mapping (carrier has a writable `__dict__` and no
  `__setstate__`), so `instance.extend(listitems)` becomes `exec(<code>)`. Reaches on 5.3,
  blocked on 5.3.1.
- **Residual trigger**: `!!python/object/new:type` + `args: [z, !!python/tuple [], {extend: !!python/name:builtins.exec}]`
  + the same benign `listitems` — `type("z", (), {"extend": exec})` installs `extend` = `exec`
  as a CLASS-attribute via the construction namespace, which `check_state_key` never sees
  (state stays empty). Same `instance.extend(listitems)` sink, so it reaches on 5.3.1;
  blocked on 5.4 because the tag has no FullLoader constructor any more.

Run: `python3 oracle.py --run-gate --with-v2`. See `repro.log` and `case.json`.

Note: `patch_real.diff` in this case dir carries the upstream CVE-2020-1747 fix commit
verbatim (yaml/pyyaml `5080ba513377b6355a0502104846ee804656f1e0`, PR #386, shipped in
5.3.1) under a comment header — replaced 2026-10-11 from an earlier binary diff of
`.git/index` (backup + MANIFEST: `benchmark/replacements_2026-10-11/PCBV2-0089/`).
The readable guard-evolution summary is `patch.diff`.
