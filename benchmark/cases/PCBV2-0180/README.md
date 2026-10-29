# pyyaml-cve-2019-20477

PyYAML — CVE-2017-18342 -> CVE-2019-20477 (the 5.1 fix introduces
`FullLoader`/`FullConstructor`, whose `make_python_instance` blocks
`python/object/apply` on a FUNCTION ("expected a class") — but the
`python/object/apply` multi-constructor is still REGISTERED on `FullConstructor`
and any CLASS (a `type`) is instantiated with no allowlist, so class
deserialization still executes; unsafe deserialization, CWE-502). **Genuine
incomplete fix; gate passed on real Docker over EXTERNAL HTTP.**

不完整修复分析见 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

Faithful-core: one Dockerfile pins the REAL PyYAML release per profile via
`PYYAML_VERSION` (V0=3.13 with `yaml.Loader`, the pre-fix full/unsafe default;
V1=5.1 and V2=5.2 with `yaml.FullLoader`, the CVE-2017-18342 guard);
`harness.py` drives the genuine `yaml.load` sink (`POST /load`, body = attacker
YAML, response = `repr(loaded object)`). Benign rce-oob canary: `harness.py`
writes `${PCB_FLAG}` to `/canary/flag.txt` (outside `/app`) at startup; probes
only READ that file via deserialization — no `os.system`, no network, no process
spawn.

NVD (case.json `evidence.incomplete_fix_quote`): "PyYAML 5.1 through 5.1.2 has
insufficient restrictions on the load and load_all functions because of a class
deserialization issue, e.g., Popen is a class in the subprocess module. NOTE:
this issue exists because of an incomplete fix for CVE-2017-18342."
`patch_real.diff` is the CVE-2017-18342 fix (commits `0cedb2a…`/`857dff1…`,
PyYAML 5.1). The CVE-2019-20477 fix (5.2, PR #347) DELETES the
`FullConstructor.add_multi_constructor('tag:yaml.org,2002:python/object/apply:',
...)` line (moved to `UnsafeConstructor`), so FullLoader has no constructor for
the tag. (Later FullLoader bypasses CVE-2020-1747/-14343 use the different
`python/object/new` tag and are separate chain links, per repro.log.)

- **V0 = 3.13** (`:39410`) — `!!python/object/apply:builtins.eval ["open('/canary/flag.txt').read()"]`
  executes -> flag in the loaded repr (repro.log: FLAG ran).
- **V1 = 5.1** (`:39411`, target) — the 18342 guard BLOCKS the function-apply
  seed (ConstructorError "expected a class, but found builtin_function_or_method"),
  but the CLASS-only residual `!!python/object/apply:builtins.list` of
  `!!python/object/apply:io.FileIO ['/canary/flag.txt','r']` passes
  `isinstance(cls, type)` and instantiates -> `[b'<flag>\n']`. Incomplete fix.
- **V2 = 5.2** (`:39412`, 20477 fix) — tag unregistered -> "could not determine a
  constructor for the tag python/object/apply" -> blocked (repro.log).

- **Original trigger**: `POST /load` with
  `!!python/object/apply:builtins.eval ["open('/canary/flag.txt').read()"]`
  (`poc/original_poc.py` `PAYLOAD`, function apply).
- **Residual trigger**: `POST /load` with
  `!!python/object/apply:builtins.list` / `- !!python/object/apply:io.FileIO` /
  `  - /canary/flag.txt` / `  - r` (class-only applies;
  `_heldout/bypass_poc.py` `PAYLOAD`).

Run: `python3 oracle.py --wait --v2` (gate 2026-07-12, flag
`PCBFLAG_e9019672bcf9a36e6c8f65e75cd345b3`: seed FLAG@v0 / seed BLOCKED@v1 /
residual FLAG@v1 / residual BLOCKED@v2; passed=true, residual_blocked_on_v2).
See `repro.log` and `case.json`.
