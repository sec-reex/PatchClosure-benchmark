# git-submodule-url-dash-argument-injection

长文分析见 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

Gold CVE→CVE incomplete-fix pair (PatchClosure-Bench).

- **CVE-2017-1000117** (V1 = git 2.14.1, incomplete fix) → **CVE-2018-17456** (V2 = git 2.19.1, complete). V0 = git 2.13.4.
- **Class:** argument injection → RCE (CWE-88). A `.gitmodules` submodule value beginning with `-` is passed verbatim as an argv element to a child process during `git clone --recurse-submodules`.
- The 2.14.1 fix guarded only the spawned **ssh** side (`connect.c`, leading-dash host). The residual (CVE-2018-17456) injects into the child **`git clone`** itself (`url = -u/…` == `--upload-pack`), closed only in 2.19.1 (`submodule--helper.c` inserts `--`).

Build + verify (real Docker, three from-source git builds, benign canary):

```
python3 oracle.py --run-gate      # build 3 images -> plant flag -> gate -> teardown
```

Gate (`flag_oracle.validate_case`, Variant A): original reaches flag on V0, original
blocked on V1, residual (bypass) reaches flag on V1. See `repro.log`.
