#!/usr/bin/env python3
"""PatchClosure-Bench freeze: aggregate every number from benchmark/cases/*/case.json.
No hardcoded counts. Output: gold_frozen.json (timestamped snapshot).
Classification is decided by the LLM (status.classification in each case.json);
this script only COUNTS and CROSS-CHECKS. It never overwrites classifications.
"""
import json, glob, os, hashlib, sys
from collections import Counter

ROOT = os.path.dirname(os.path.abspath(__file__))
CASES = os.path.join(ROOT, 'cases')
ARCHIVE = os.path.join(ROOT, 'archive_non_gold')

ORACLE_KEYS = ['seed_v0_reaches', 'seed_v1_blocked', 'residual_v1_reaches', 'residual_v2_blocked']
KEYMAP = {
    'seed_v0_reaches': ['seed_open_on_v0', 'original_poc_reaches_flag_on_v0', 'original_reaches_flag_on_v0', 'original_read_on_v0', 'seed_v0_reaches'],
    'seed_v1_blocked': ['seed_closed_on_v1', 'original_poc_blocked_on_v1', 'original_blocked_on_v1', 'original_read_on_v1', 'seed_v1_blocked'],
    'residual_v1_reaches': ['residual_reaches_flag_on_v1', 'bypass_poc_reaches_flag_on_v1', 'residual_reaches_on_v1', 'residual_read_on_v1', 'residual_v1_reaches'],
    'residual_v2_blocked': ['residual_blocked_on_v2', 'bypass_poc_blocked_on_v2', 'bypass_blocked_on_v2', 'residual_closed_on_v2', 'residual_v2_blocked'],
}

def deep_get(d, key):
    if isinstance(d, dict):
        if key in d and isinstance(d[key], bool):
            return d[key]
        for v in d.values():
            r = deep_get(v, key)
            if r is not None:
                return r
    return None

def four_way_anywhere(st):
    out = {}
    for k, alts in KEYMAP.items():
        v = None
        for a in alts:
            v = deep_get(st, a)
            if v is not None:
                break
        out[k] = v
    return out

def main():
    def collect(root):
        out = []
        for f in sorted(glob.glob(os.path.join(root, '*/case.json'))):
            d = json.load(open(f))
            dirname = os.path.basename(os.path.dirname(f))
            # 目录名 = eval_id（PCBV2-XXXX）；学术口径 id 用 case.json 的 case_id（slug/public_name），
            # 没有该字段时退回目录名（历史 archive 目录同为 slug，语义不变）。
            name = d.get('case_id') or dirname
            st = d.get('status', {}) or {}
            classification = st.get('classification') or st.get('stage') or 'unclassified'
            o = d.get('oracle', {})
            checks = o.get('checks') if isinstance(o, dict) else None
            if isinstance(checks, dict) and all(k in checks for k in ORACLE_KEYS):
                oracle = {k: checks[k] for k in ORACLE_KEYS}
            else:
                oracle = four_way_anywhere(st)
            n_true = sum(1 for v in oracle.values() if v is True)
            cp = d.get('cve_pair', {}) or {}
            out.append({
                'case_id': name,
                'eval_id': d.get('eval_id', dirname if dirname.startswith('PCBV2-') else None),
                'classification': classification,
                'oracle': oracle,
                'oracle_n_true': n_true,
                'original_cve': cp.get('original_cve'),
                'bypass_cve': cp.get('bypass_cve'),
            })
        return out

    rows = collect(CASES)
    archived = collect(ARCHIVE) if os.path.isdir(ARCHIVE) else []
    all_rows = rows + archived

    counts = Counter(r['classification'] for r in all_rows)
    # cross-checks (report only; never mutate)
    warnings = []
    for r in all_rows:
        if r['classification'] == 'strict_gold' and r['oracle_n_true'] != 4:
            warnings.append(f"{r['case_id']}: strict_gold but oracle {r['oracle_n_true']}/4 {r['oracle']}")
        if r['classification'] != 'strict_gold' and r['classification'] not in ('duplicate', 'excluded_from_strict', 'unclassified') and r['oracle_n_true'] == 4:
            warnings.append(f"{r['case_id']}: oracle 4/4 but classification={r['classification']}")

    sha = hashlib.sha256()
    for root in (CASES, ARCHIVE):
        if os.path.isdir(root):
            for f in glob.glob(os.path.join(root, '*/case.json')):
                sha.update(open(f, 'rb').read())
    frozen = {
        'generated_at': __import__('datetime').datetime.now().isoformat(),
        'source': 'benchmark/cases/*/case.json (gold) + benchmark/archive_non_gold/*/case.json (archived non-gold, evidence kept)',
        'total_cases': len(all_rows),
        'active_cases': len(rows),
        'archived_cases': len(archived),
        'counts': dict(counts),
        'strict_gold': sorted(r['case_id'] for r in rows if r['classification'] == 'strict_gold'),
        'archived_details': [r for r in archived],
        'warnings': warnings,
        'cases_sha256': sha.hexdigest(),
    }
    out = os.path.join(ROOT, 'gold_frozen.json')
    json.dump(frozen, open(out, 'w'), ensure_ascii=False, indent=2)
    print(f"total={len(all_rows)} (active={len(rows)} archived={len(archived)})")
    for k, v in counts.most_common():
        print(f"  {k}: {v}")
    print(f"warnings: {len(warnings)}")
    for w in warnings[:20]:
        print(f"  ! {w}")
    print(f"written: {out}")

if __name__ == '__main__':
    main()
