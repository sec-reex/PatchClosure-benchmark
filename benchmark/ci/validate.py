#!/usr/bin/env python3
"""validate.py — PatchClosure-Bench CI: four machine checks per case (task book §2.2).

Checks (per case, each emits PASS / WARN / FAIL + reason):
  1. diff integrity   — patch.diff 4-line canonical header is well-formed; body from the
                        first `diff --git` is byte-identical to patch_real.diff's body; no
                        bypass-payload / canary marker injected into our header region.
  2. schema           — case.json satisfies the frozen schema (benchmark/schemas/case.schema.json):
                        hard-required fields present; cve_pair.advisory_url present (WARN if not);
                        ports consistent with docker-compose.yml; deep source check (patch applied
                        to V0 == V1) when both trees are locally available, else WARN-skip.
  3. four gates green — seed@V0 reaches / seed@V1 blocked / residual@V1 reaches / residual@V2 blocked,
                        verified by a fresh gate_result.json. --offline reuses a result < 7 days old;
                        a live run is delegated to runner/ (deploy+oracle on gpu1_wg). WARN when no
                        fresh result and not run live.
  4. isolation        — benchmark/cases/<id>/ contains NO answer-class file
                        (_heldout/, poc/bypass_poc.py, oracle.py, gate_result.json,
                        INCOMPLETE_FIX_ANALYSIS.md, repro.log). Passes only AFTER the §3 secrets/ move.

Exit code is non-zero iff at least one FAIL exists. WARN never fails the build.

Usage:
  python3 benchmark/ci/validate.py --case PCBV2-0144
  python3 benchmark/ci/validate.py --all [--jobs 4] [--offline] [--json reports/ci_validate.json]
  python3 benchmark/ci/validate.py --all --checks 1,2,4        # skip the live/remote gate
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
BENCH = HERE.parent                      # benchmark/
ROOT = BENCH.parent                      # repo root
CASES = BENCH / "cases"
SECRETS = BENCH / "secrets"
SCHEMA_FILE = BENCH / "schemas" / "case.schema.json"

PASS, WARN, FAIL = "PASS", "WARN", "FAIL"

ANSWER_FILES = ["_heldout", "poc/bypass_poc.py", "poc/residual_poc.py", "oracle.py",
                "gate_result.json", "INCOMPLETE_FIX_ANALYSIS.md", "repro.log"]

# Bypass-payload / canary markers that must never be injected into OUR header region.
# Structural tokens (__proto__, constructor.prototype) legitimately occur in upstream fix
# bodies, so they are only forbidden in the header (pre-`diff --git`) region. The synthetic
# markers must not appear ANYWHERE in patch.diff.
HEADER_FORBIDDEN = [r"__proto__", r"constructor\.prototype", r"%%32", r"\\evil"]
ANYWHERE_FORBIDDEN = [r"PcbCanary", r"PCBFLAG_"]

GATE_FRESH_SECONDS = 7 * 24 * 3600


def load_schema_required():
    sch = json.loads(SCHEMA_FILE.read_text())
    top = sch.get("required", [])
    cve_req = (((sch.get("properties") or {}).get("cve_pair") or {}).get("required")) or []
    ver_req = (((sch.get("properties") or {}).get("versions") or {}).get("required")) or []
    return top, cve_req, ver_req


TOP_REQ, CVE_REQ, VER_REQ = load_schema_required()


# ---------------------------------------------------------------- check 1: diff
def _split_header_body(pd_b: bytes):
    """Return (header_bytes, body_bytes). Header = the 4 canonical lines plus any leading
    blank lines and the optional parenthetical '(... format ...)' note; body = the faithful
    copy of the upstream diff (format-agnostic: git / unified / context / bash patch report)."""
    lines = pd_b.split(b"\n")
    rest = lines[4:]
    i = 0
    while i < len(rest) and (rest[i].strip() == b"" or
                             (rest[i].lstrip().startswith(b"(") and b"format" in rest[i].lower())):
        i += 1
    header = b"\n".join(lines[:4 + i])
    body = b"\n".join(rest[i:])
    return header, body


def check_diff(cid: str, cdir: Path):
    res = []  # (status, reason)
    pd = cdir / "patch.diff"
    pr = cdir / "patch_real.diff"
    if not pd.exists() or not pr.exists():
        return [(FAIL, "missing patch.diff or patch_real.diff")]
    pd_b = pd.read_bytes()
    pr_b = pr.read_bytes()
    lines = pd_b.split(b"\n")

    # header lines (1,3,4)
    l1 = lines[0].decode("utf-8", "replace") if len(lines) > 0 else ""
    l3 = lines[2].decode("utf-8", "replace") if len(lines) > 2 else ""
    l4 = lines[3].decode("utf-8", "replace") if len(lines) > 3 else ""
    if not re.match(rf"^{re.escape(cid)} V0 -> V1 fix", l1):
        res.append((FAIL, f"L1 header malformed: {l1[:80]!r}"))
    if "METHOD-VISIBLE" not in l3:
        res.append((FAIL, f"L3 header missing METHOD-VISIBLE: {l3[:80]!r}"))
    if f"replacements_2026-10-11/{cid}/" not in l4:
        res.append((FAIL, f"L4 header missing backup ref: {l4[:80]!r}"))

    # body = verbatim byte-substring of patch_real.diff (faithful upstream copy, any diff format)
    header_region, body = _split_header_body(pd_b)
    if not body.strip():
        res.append((FAIL, "patch.diff has empty body after header"))
    elif body not in pr_b:
        res.append((FAIL, "patch.diff body is not a verbatim substring of patch_real.diff"))

    # forbidden bypass-payload tokens must not be injected into OUR header region
    hdr_txt = header_region.decode("utf-8", "replace")
    for tok in HEADER_FORBIDDEN:
        if re.search(tok, hdr_txt):
            res.append((FAIL, f"bypass payload token /{tok}/ injected into header region"))
    whole = pd_b.decode("utf-8", "replace")
    for tok in ANYWHERE_FORBIDDEN:
        if re.search(tok, whole):
            res.append((FAIL, f"canary/synthetic marker /{tok}/ present in patch.diff"))

    return res or [(PASS, "header ok + body is faithful upstream copy + no injected payload")]


# ---------------------------------------------------------------- check 2: schema
PORT_RX = re.compile(r'\$\{PORT_[A-Z0-9_]*V([012])[A-Z0-9_]*(?::-(\d*))?\}:(\d+)')


def _compose_ports(cdir: Path) -> dict:
    comp = cdir / "docker-compose.yml"
    out = {}
    if not comp.exists():
        return out
    for m in PORT_RX.finditer(comp.read_text(errors="replace")):
        prof = "v" + m.group(1)
        out.setdefault(prof, {"host_default": int(m.group(2)) if m.group(2) else None,
                              "container": int(m.group(3))})
    return out


def check_schema(cid: str, cdir: Path):
    res = []
    try:
        j = json.loads((cdir / "case.json").read_text())
    except Exception as e:
        return [(FAIL, f"case.json not valid JSON: {e}")]

    # hard-required top-level
    for k in TOP_REQ:
        if k not in j:
            res.append((FAIL, f"missing hard-required field: {k}"))
    # cve_pair sub-keys
    cp = j.get("cve_pair") or {}
    for k in CVE_REQ:
        if k not in cp:
            res.append((FAIL, f"missing cve_pair.{k}"))
    # versions sub-keys
    vs = j.get("versions") or {}
    for k in VER_REQ:
        if k not in vs:
            res.append((FAIL, f"missing versions.{k}"))
    # effect_type enum
    if j.get("effect_type") not in ("exfiltration", "effect"):
        res.append((FAIL, f"effect_type invalid: {j.get('effect_type')!r}"))

    # RECOMMENDED: advisory_url
    if not (cp.get("advisory_url")):
        res.append((WARN, "cve_pair.advisory_url absent (historical debt)"))

    # ports consistency with compose (RECOMMENDED)
    cj_ports = j.get("ports") or {}
    comp_ports = _compose_ports(cdir)
    if not comp_ports:
        res.append((WARN, "no host ports derivable from docker-compose.yml"))
    else:
        for prof, pv in cj_ports.items():
            if prof in comp_ports and comp_ports[prof] != pv:
                res.append((FAIL, f"ports.{prof} {pv} != compose {comp_ports[prof]}"))
        if not all(k in comp_ports for k in ("v0", "v1", "v2")):
            res.append((WARN, f"compose ports incomplete triple: {sorted(comp_ports)}"))

    # deep source check: patch_real.diff applied to V0 == V1 (WARN-skip if trees unavailable)
    res.append(_deep_source_check(cid, cdir))

    hard_fail = [r for r in res if r[0] == FAIL]
    if hard_fail:
        return res
    warns = [r for r in res if r[0] == WARN]
    return (warns or []) + [(PASS, "schema fields present + ports consistent")]


def _deep_source_check(cid: str, cdir: Path):
    manifest = BENCH / "provenance" / "source_manifest.json"
    alt = ROOT / "bench_experiments" / "harness" / "source_manifest.json"
    man = None
    for mf in (manifest, alt):
        if mf.exists():
            try:
                man = json.loads(mf.read_text())
                break
            except Exception:
                pass
    if not man or cid not in man:
        return (WARN, "deep source check skipped (no source manifest entry)")
    # We'd need BOTH V0 and V1 trees locally to apply patch_real.diff and compare.
    # The manifest currently caches only v1; V0 is not materialized -> WARN-skip.
    return (WARN, "deep source check skipped (V0 tree not locally available)")


# ---------------------------------------------------------------- check 3: four gates
def _gate_result_path(cid: str) -> Path | None:
    for base in (SECRETS / cid, CASES / cid):
        p = base / "gate_result.json"
        if p.exists():
            return p
    return None


def check_gates(cid: str, cdir: Path, offline: bool, live_runner: str | None):
    gp = _gate_result_path(cid)
    if gp:
        try:
            gr = json.loads(gp.read_text())
        except Exception as e:
            gr = None
        if gr:
            ts = gr.get("timestamp") or gr.get("ts") or 0
            try:
                age = time.time() - float(ts)
            except Exception:
                age = GATE_FRESH_SECONDS + 1
            passed = gr.get("passed") or (isinstance(gr.get("gate"), dict) and gr["gate"].get("passed"))
            if age <= GATE_FRESH_SECONDS:
                if passed:
                    return [(PASS, f"four gates green (fresh gate_result.json, age {int(age)}s)")]
                return [(FAIL, "gate_result.json present but passed != true")]
            else:
                if offline:
                    return [(WARN, f"gate_result.json stale (age {int(age)}s) and --offline")]
    # no fresh result
    if live_runner:
        return _run_four_gate_live(cid, live_runner)
    return [(WARN, "no fresh gate_result.json; run runner gate (or --offline reuse)")]


def _run_four_gate_live(cid: str, runner: str):
    """Delegate to runner/gate.sh <case_id> which deploys on gpu1_wg, runs the oracle via
    ci_gate_driver, and writes a fresh secrets/<id>/gate_result.json. Wired in Phase 3/4."""
    gate_sh = ROOT / "runner" / "gate.sh"
    if not gate_sh.exists():
        return [(WARN, "live gate requested but runner/gate.sh not present yet")]
    try:
        r = subprocess.run(["bash", str(gate_sh), cid], capture_output=True, text=True, timeout=1800)
    except Exception as e:
        return [(FAIL, f"live gate error: {e}")]
    if r.returncode != 0:
        return [(FAIL, f"live gate FAIL: {r.stderr.strip()[-200:]}")]
    return [(PASS, "four gates green (fresh live run on gpu1_wg)")]


# ---------------------------------------------------------------- check 4: isolation
def check_isolation(cid: str, cdir: Path):
    hits = []
    for rel in ANSWER_FILES:
        p = cdir / rel
        if p.exists():
            hits.append(rel)
    if hits:
        return [(FAIL, f"answer file(s) still in cases/: {', '.join(hits)}")]
    return [(PASS, "no answer-class files in cases/")]


# Check 5 — residual-leak hygiene (task book v2 2026-10-13 goal 2). Gates the leak classes found:
#   (a) the PACKAGE seed must sanitize clean (no strong residual hint survives) AND still parse;
#   (b) no answer bytecode (__pycache__ of bypass_poc/residual_poc) on the public side;
#   (c) seed_exec.py describing the residual -> WARN (poc/ is byte-frozen; flagged for relocation).
_SEED_SAN = None
def _seed_sanitizer():
    global _SEED_SAN
    if _SEED_SAN is None:
        sys.path.insert(0, str(ROOT / "runner" / "lib"))
        import seed_sanitize  # noqa: E402
        _SEED_SAN = seed_sanitize
    return _SEED_SAN

def _bypass_cve(cdir: Path) -> str:
    try:
        c = json.loads((cdir / "case.json").read_text()).get("cve_pair", {})
        return c.get("bypass_cve") or c.get("cve2") or ""
    except Exception:
        return ""

def check_leak(cid: str, cdir: Path):
    import ast as _ast
    res = []
    S = _seed_sanitizer()
    bcve = _bypass_cve(cdir)
    seed = cdir / "poc" / "original_poc.py"
    if seed.exists():
        src = seed.read_text(encoding="utf-8", errors="replace")
        sanitized, _notes = S.sanitize(src, bcve)
        surv = S.check(src, bcve)
        if surv:
            res.append((FAIL, f"package seed still leaks residual after sanitize: {surv[0][:90]!r}"))
        try:
            _ast.parse(sanitized)
        except Exception as e:
            res.append((FAIL, f"sanitized package seed does not parse: {e}"))
    # (b) answer bytecode on public side
    pyc = list((cdir / "poc").glob("__pycache__/*bypass*.pyc")) + \
          list((cdir / "poc").glob("__pycache__/*residual*.pyc"))
    if pyc:
        res.append((FAIL, f"answer bytecode present in public poc/__pycache__: {pyc[0].name}"))
    # (c) seed_exec.py residual narration (byte-frozen -> WARN, recommend relocation to secrets/)
    se = cdir / "poc" / "seed_exec.py"
    if se.exists():
        st = se.read_text(encoding="utf-8", errors="replace")
        if S.STRONG.search(st) or (bcve and bcve in st):
            res.append((WARN, "seed_exec.py describes the residual (public-side at-rest leak; "
                              "poc/ byte-frozen — recommend relocating to secrets/)"))
    return res or [(PASS, "no residual leak in package seed / public side")]


# ---------------------------------------------------------------- driver
CHECKS = {
    "1": ("diff", check_diff),
    "2": ("schema", check_schema),
    "3": ("gates", None),       # special (needs flags)
    "4": ("isolation", check_isolation),
    "5": ("leak", check_leak),
}


def validate_case(cid: str, which, offline: bool, live_runner: str | None):
    cdir = CASES / cid
    out = {"case": cid, "checks": {}, "status": PASS}
    for n in which:
        name = CHECKS[n][0]
        if n == "3":
            results = check_gates(cid, cdir, offline, live_runner)
        else:
            results = CHECKS[n][1](cid, cdir)
        worst = PASS
        for st, _ in results:
            if st == FAIL:
                worst = FAIL
            elif st == WARN and worst != FAIL:
                worst = WARN
        out["checks"][name] = [{"status": s, "reason": r} for s, r in results]
        if worst == FAIL:
            out["status"] = FAIL
        elif worst == WARN and out["status"] != FAIL:
            out["status"] = WARN
    return out


def main():
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--case", help="single case id")
    g.add_argument("--all", action="store_true")
    ap.add_argument("--checks", default="1,2,3,4,5", help="comma list of checks to run")
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--offline", action="store_true", help="reuse fresh gate_result.json; no live run")
    ap.add_argument("--live-gate", metavar="RUNNER", default=None,
                    help="run check 3 live via runner (pass any truthy value; uses runner/gate.sh)")
    ap.add_argument("--json", help="write full results to this path")
    args = ap.parse_args()

    which = [c.strip() for c in args.checks.split(",") if c.strip() in CHECKS]
    if args.case:
        cases = [args.case]
    else:
        cases = sorted(d.name for d in CASES.iterdir()
                       if d.is_dir() and d.name.startswith("PCBV2-"))

    results = []
    if args.all and len(cases) > 1 and "3" not in which:
        # pure-local checks parallelize trivially
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as ex:
            futs = {ex.submit(validate_case, c, which, args.offline, args.live_gate): c for c in cases}
            for f in concurrent.futures.as_completed(futs):
                results.append(f.result())
    else:
        for c in cases:
            results.append(validate_case(c, which, args.offline, args.live_gate))
    results.sort(key=lambda r: r["case"])

    n_fail = n_warn = n_pass = 0
    for r in results:
        if r["status"] == FAIL:
            n_fail += 1
        elif r["status"] == WARN:
            n_warn += 1
        else:
            n_pass += 1
        flat = []
        for cname, items in r["checks"].items():
            for it in items:
                if it["status"] != PASS:
                    flat.append(f"{cname}:{it['status']}({it['reason']})")
        line = f"[{r['status']:4}] {r['case']}"
        if flat:
            line += "  " + "; ".join(flat)
        print(line)

    print(f"\n=== {n_pass} PASS / {n_warn} WARN / {n_fail} FAIL  (of {len(results)}) ===")
    if args.json:
        Path(args.json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json).write_text(json.dumps(results, indent=2, ensure_ascii=False))
        print(f"wrote {args.json}")
    return 1 if n_fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
