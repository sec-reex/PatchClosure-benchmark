#!/usr/bin/env python3
"""freeze_schema_v2.py — migrate benchmark/cases/*/case.json to the frozen v2 schema.

Normative schema: benchmark/schemas/case.schema.json.

Contract (task book §2.1):
  * IDEMPOTENT: re-running produces no further change.
  * ONLY-ADD: never mutates or removes an existing value. It only ADDS the
    normalized/derived hard-required fields (at the top level or under cve_pair)
    when they are absent, copying authoritative values from their historical
    locations (execution.run_mode, flag.class_kind, cve_pair.cve1/cve2,
    evidence.advisory_url, docker-compose.yml, ...).
  * BACKS UP first: every case.json is copied, with a sha256 manifest, to
    backup_2026-10-12_schema_freeze/ before any file is written.

Hard-required adds (FAIL if still missing after migration):
    run_mode, class_kind, cve_pair.original_cve, cve_pair.bypass_cve,
    given_to_method, effect_type   (+ schema_frozen marker)
RECOMMENDED adds (WARN-only; tracked in the exceptions report, never fabricated):
    cve_pair.advisory_url, ports, provenance

Usage:
    python3 benchmark/migrations/freeze_schema_v2.py            # dry-run (default)
    python3 benchmark/migrations/freeze_schema_v2.py --apply    # write changes + backup
    python3 benchmark/migrations/freeze_schema_v2.py --apply --case PCBV2-0205
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
BENCH = HERE.parent                      # benchmark/
CASES = BENCH / "cases"
BACKUP = HERE / "backup_2026-10-12_schema_freeze"
STAMP = "case-schema-v2-2026-10-12"

GIVEN_TO_METHOD_DEFAULT = ["v1 source", "patch.diff", "original_poc.py", "v1 env (profile v1)"]
EFFECT_CASES = {"PCBV2-0015"}            # confirmed effect-type; all else exfiltration
IS_DOS_REVIEW = {"PCBV2-0008", "PCBV2-0059", "PCBV2-0105", "PCBV2-0110",
                 "PCBV2-0183", "PCBV2-0184", "PCBV2-0188"}

PORT_RX = re.compile(r'\$\{PORT_[A-Z0-9_]*V([012])[A-Z0-9_]*(?::-(\d*))?\}:(\d+)')


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    h.update(p.read_bytes())
    return h.hexdigest()


def derive_ports(case_dir: Path) -> dict:
    """Parse docker-compose.yml published ports into {vN: {host_default, container}}.
    Pure-regex (no YAML dep): the PORT_*V<n>* env-var name carries the profile."""
    comp = case_dir / "docker-compose.yml"
    out: dict = {}
    if not comp.exists():
        return out
    txt = comp.read_text(errors="replace")
    for m in PORT_RX.finditer(txt):
        prof = "v" + m.group(1)
        if prof in out:
            continue
        hd = m.group(2)
        out[prof] = {"host_default": int(hd) if hd else None, "container": int(m.group(3))}
    return out


def _advisory_from_evidence(j: dict):
    ev = j.get("evidence") or {}
    if not isinstance(ev, dict):
        return None
    for k in ("advisory_url", "nvd_url", "original_advisory_url",
              "advisory_original", "advisory_bypass", "bypass_advisory_url"):
        v = ev.get(k)
        if isinstance(v, str) and v.strip():
            return v
    return None


def plan_case(cid: str, j: dict, case_dir: Path):
    """Return (adds, warns) where adds is a list of (jsonpath, value, kind)."""
    adds = []   # (dotted_path, value, 'HARD'|'REC')
    warns = []

    # run_mode (top-level) <- execution.run_mode
    if "run_mode" not in j:
        exr = (j.get("execution") or {}).get("run_mode")
        if exr:
            adds.append(("run_mode", exr, "HARD"))
        else:
            warns.append("run_mode: absent and no execution.run_mode to derive from")

    # class_kind (top-level) <- flag.class_kind
    if "class_kind" not in j:
        fk = (j.get("flag") or {}).get("class_kind")
        if fk:
            adds.append(("class_kind", fk, "HARD"))
        else:
            warns.append("class_kind: absent and no flag.class_kind to derive from")

    # cve_pair.original_cve / bypass_cve <- cve1 / cve2
    cp = j.get("cve_pair") or {}
    if "original_cve" not in cp:
        if cp.get("cve1"):
            adds.append(("cve_pair.original_cve", cp["cve1"], "HARD"))
        else:
            warns.append("cve_pair.original_cve: absent and no cve1 to derive from")
    if "bypass_cve" not in cp:
        if cp.get("cve2"):
            adds.append(("cve_pair.bypass_cve", cp["cve2"], "HARD"))
        else:
            warns.append("cve_pair.bypass_cve: absent and no cve2 to derive from")

    # cve_pair.advisory_url (RECOMMENDED) <- evidence.*
    if not cp.get("advisory_url"):
        adv = _advisory_from_evidence(j)
        if adv:
            adds.append(("cve_pair.advisory_url", adv, "REC"))
        else:
            warns.append("cve_pair.advisory_url: no advisory source anywhere (WARN)")

    # versions.v0/v1/v2 (HARD) <- *_vulnerable/_incomplete/_fixed alternate naming
    versions = j.get("versions") or {}
    ALT = {"v0": "v0_vulnerable", "v1": "v1_incomplete", "v2": "v2_fixed"}
    for canon, alt in ALT.items():
        if canon not in versions:
            if alt in versions:
                adds.append((f"versions.{canon}", versions[alt], "HARD"))
            else:
                warns.append(f"versions.{canon}: absent and no {alt} to derive from")

    # given_to_method (HARD) <- canonical protocol default
    if "given_to_method" not in j:
        adds.append(("given_to_method", list(GIVEN_TO_METHOD_DEFAULT), "HARD"))
        warns.append("given_to_method: backfilled canonical protocol default (was absent)")

    # provenance (RECOMMENDED) — never fabricate
    if "provenance" not in j:
        warns.append("provenance: absent (WARN; not backfilled)")

    # effect_type (HARD, NEW)
    if "effect_type" not in j:
        et = "effect" if cid in EFFECT_CASES else "exfiltration"
        adds.append(("effect_type", et, "HARD"))
        if cid in IS_DOS_REVIEW:
            warns.append("effect_type: defaulted exfiltration but is_dos — pending manual review")

    # ports (RECOMMENDED) <- compose
    if "ports" not in j:
        ports = derive_ports(case_dir)
        if ports:
            adds.append(("ports", ports, "REC"))
        if not all(k in ports for k in ("v0", "v1", "v2")):
            warns.append(f"ports: incomplete triple from compose (got {sorted(ports)}) (WARN)")

    # schema_frozen marker (idempotency sentinel)
    if j.get("schema_frozen") != STAMP:
        adds.append(("schema_frozen", STAMP, "HARD"))

    return adds, warns


def apply_adds(j: dict, adds):
    for path, value, _kind in adds:
        if "." in path:
            top, sub = path.split(".", 1)
            j.setdefault(top, {})
            if sub not in j[top]:
                j[top][sub] = value
        else:
            if path not in j:
                j[path] = value


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true", help="write changes (default: dry-run)")
    ap.add_argument("--case", help="limit to one case id")
    args = ap.parse_args()

    cases = sorted(d.name for d in CASES.iterdir()
                   if d.is_dir() and d.name.startswith("PCBV2-"))
    if args.case:
        cases = [c for c in cases if c == args.case]
        if not cases:
            print(f"no such case: {args.case}", file=sys.stderr)
            return 2

    # Backup (only when applying, and only once)
    if args.apply:
        BACKUP.mkdir(parents=True, exist_ok=True)
        man = BACKUP / "MANIFEST.md"
        if not man.exists():
            lines = [f"# freeze_schema_v2 backup — {datetime.date.today().isoformat()}",
                     "", "Pre-migration snapshot of every case.json (only-add migration; "
                     "restore = copy these back).", "", "| case | sha256(case.json) |", "|---|---|"]
            (BACKUP / "case_json").mkdir(exist_ok=True)
            for c in sorted(d.name for d in CASES.iterdir()
                            if d.is_dir() and d.name.startswith("PCBV2-")):
                src = CASES / c / "case.json"
                if not src.exists():
                    continue
                dst = BACKUP / "case_json" / f"{c}.case.json"
                dst.write_bytes(src.read_bytes())
                lines.append(f"| {c} | {sha256_file(src)} |")
            man.write_text("\n".join(lines) + "\n")
            print(f"[backup] wrote {BACKUP}/case_json/ + MANIFEST.md")
        else:
            print(f"[backup] already present at {BACKUP} (not overwriting)")

    n_changed = 0
    all_warns = {}
    for c in cases:
        p = CASES / c / "case.json"
        j = json.loads(p.read_text())
        adds, warns = plan_case(c, j, CASES / c)
        real_adds = [a for a in adds if a[2] != "MARK"]
        if warns:
            all_warns[c] = warns
        if adds:
            n_changed += 1
            tag = "APPLY" if args.apply else "DRY"
            print(f"[{tag}] {c}: +{len(adds)} field(s): "
                  + ", ".join(f"{p2}({k})" for p2, _v, k in adds))
            for w in warns:
                print(f"        WARN {c}: {w}")
            if args.apply:
                apply_adds(j, adds)
                p.write_text(json.dumps(j, indent=2, ensure_ascii=False))
        else:
            if warns:
                for w in warns:
                    print(f"        WARN {c}: {w}")

    print(f"\n{'APPLIED' if args.apply else 'DRY-RUN'}: {n_changed}/{len(cases)} "
          f"case.json would change; {len(all_warns)} case(s) have WARN items.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
