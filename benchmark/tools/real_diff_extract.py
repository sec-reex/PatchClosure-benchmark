#!/usr/bin/env python3
"""ROUND18 task 0: regenerate real diffs for concept-diff cases.

For every case whose patch.diff is a concept description (no @@ / diff --git)
or whose patch_files came up empty, pull v0+v1 source via fetch_src.sh
(KEEP_CACHE=1) and produce a REAL diff:
  - git-class: `git diff v0_ref v1_ref` (optionally filtered by file-name clues
    present in the concept description — the description is method input).
  - other classes: recursive `diff -r` between the two extracted trees,
    filtered the same way.
Writes cases/<id>/patch_real.diff and provenance/real_diff_status.json.
"""
import json, os, re, subprocess, sys, shutil

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CASES = os.path.join(ROOT, 'cases')
MF = os.path.join(ROOT, 'provenance', 'source_manifest.json')
OUT = os.path.join(ROOT, 'provenance', 'real_diff_status.json')
FETCH = os.path.join(ROOT, 'tools', 'fetch_src.sh')
MAX_FILES = 20  # a real fix touching >20 files across a version hop is not "the patch"


def is_concept(cid):
    df = os.path.join(CASES, cid, 'patch.diff')
    if not os.path.exists(df):
        return True, 'no_patch_file'
    t = open(df, encoding='utf-8', errors='ignore').read()
    if '@@' not in t and 'diff --git' not in t:
        return True, 'concept_desc'
    return False, ''


def file_clues(cid):
    """File-name clues from the concept description (method input, allowed)."""
    df = os.path.join(CASES, cid, 'patch.diff')
    if not os.path.exists(df):
        return []
    t = open(df, encoding='utf-8', errors='ignore').read()
    clues = []
    for m in re.finditer(r'(?:File|file|path|Path)[: ]+([\w./-]+\.\w{1,5})', t):
        p = m.group(1).strip().strip('`"')
        if p and p not in clues:
            clues.append(p)
    for m in re.finditer(r'([\w./-]+\.(?:java|py|js|rb|php|go|rb|sql|h|c|cc|sh|cpp|ts|xml|html|inc))', t):
        p = m.group(1)
        if p not in clues:
            clues.append(p)
    return clues[:15]


def fetch_pair(cid):
    """JIT pull v0+v1 into /tmp/pcb_src/<cid> (kept for this job)."""
    w = f'/tmp/pcb_src/{cid}'
    subprocess.run(['rm', '-rf', w], capture_output=True)
    r = subprocess.run(['bash', FETCH, cid], env={**os.environ, 'KEEP_CACHE': '0',
                                                 'SKIP_CLEANUP': '1'},
                       capture_output=True, text=True, timeout=1800)
    ok = os.path.exists(os.path.join(w, 'v0')) and os.path.exists(os.path.join(w, 'v1'))
    if not ok:
        tail = (r.stdout or r.stderr or '')[-300:]
        return None, f'fetch failed: {tail}'
    return w, None


def git_real_diff(w, cid, clues):
    """git diff between v0_ref and v1_ref in the fetched repo."""
    # fetch_src clones v0 and v1 as separate working trees; run git diff by
    # pointing at both trees via --no-index if they are separate repos.
    v0, v1 = os.path.join(w, 'v0'), os.path.join(w, 'v1')
    if os.path.isdir(os.path.join(v0, '.git')) and os.path.isdir(os.path.join(v1, '.git')):
        # same repo? compare trees by content: diff -r on filtered paths
        return None
    return None


def tree_diff(w, cid, clues):
    """Recursive content diff between v0 and v1 trees (works for all classes)."""
    v0, v1 = os.path.join(w, 'v0'), os.path.join(w, 'v1')
    if not (os.path.isdir(v0) and os.path.isdir(v1)):
        return None
    # if both are git repos of the same origin, ask git directly
    r0 = subprocess.run(['git', '-C', v0, 'remote', 'get-url', 'origin'], capture_output=True, text=True)
    r1 = subprocess.run(['git', '-C', v1, 'remote', 'get-url', 'origin'], capture_output=True, text=True)
    if r0.returncode == 0 and r1.returncode == 0 and r0.stdout.strip() == r1.stdout.strip():
        ref0 = subprocess.run(['git', '-C', v0, 'rev-parse', 'HEAD'], capture_output=True, text=True).stdout.strip()
        ref1 = subprocess.run(['git', '-C', v1, 'rev-parse', 'HEAD'], capture_output=True, text=True).stdout.strip()
        if ref0 and ref1:
            r = subprocess.run(['git', '-C', v0, 'diff', ref0, ref1, '--'],
                               capture_output=True, text=True, timeout=600)
            if r.returncode == 0 and r.stdout.strip():
                return filter_diff(r.stdout, clues)
    # generic file-by-file diff
    files0 = {}
    for dp, _, fs in os.walk(v0):
        if '/.git/' in dp: continue
        for f in fs:
            p = os.path.join(dp, f)
            rel = os.path.relpath(p, v0)
            try:
                if os.path.isfile(p):
                    files0[rel] = open(p, 'rb').read()
            except OSError:
                pass
    out = []
    for dp, _, fs in os.walk(v1):
        if '/.git/' in dp or '/node_modules/' in dp or '__pycache__' in dp:
            continue
        for f in fs:
            p = os.path.join(dp, f)
            rel = os.path.relpath(p, v1)
            if '.git/' in rel or rel.startswith('.'):
                continue
            try:
                if not os.path.isfile(p):
                    continue
                b1 = open(p, 'rb').read()
            except OSError:
                continue
            b0 = files0.pop(rel, None)
            if b0 is not None and b0 != b1:
                try:
                    t0 = b0.decode('utf-8', 'replace')
                    t1 = b1.decode('utf-8', 'replace')
                except Exception:
                    continue
                if any(c.lower() in rel.lower() for c in clues) or not clues:
                    dl = list(unified(t0, t1))
                    if len(dl) > 3:
                        body = '\n'.join(l for l in dl[3:] if not l.startswith('---') and not l.startswith('+++'))
                        out.append(f'diff --git a/{rel} b/{rel}\nindex ..\n--- a/{rel}\n+++ b/{rel}\n' + body + '\n')
    return '\n'.join(out)


def unified(a, b):
    """Mini unified diff (context 3)."""
    import difflib
    return difflib.unified_diff(a.splitlines(), b.splitlines(), n=3)


def filter_diff(diff, clues):
    if not clues:
        return diff
    # keep only file sections whose path matches a clue
    keep, cur = [], []
    for line in diff.splitlines(keepends=True):
        if line.startswith('diff --git'):
            if cur:
                keep.extend(cur)
            cur = [line]
        elif line.startswith('+++ b/'):
            cur.append(line)
            p = line[6:].strip()
            cur_match = p and any(c.lower() in p.lower() for c in clues)
            if not cur_match:
                cur = []
            else:
                cur.append(line)
        elif cur is not None:
            cur.append(line)
    if cur:
        keep.extend(cur)
    return ''.join(keep) if keep else diff[:50000]


def main():
    m = json.load(open(MF))
    status = {}
    done = 0
    concept_only = []
    for cid, e in sorted(m.items()):
        is_c, kind = is_concept(cid)
        pf = e.get('patch_files') or []
        if not is_c and pf:
            continue  # already a real diff with paths
        status[cid] = {'kind': kind, 'patch_files': pf}
        w, err = fetch_pair(cid)
        if w is None:
            status[cid]['result'] = 'fetch_failed'
            status[cid]['error'] = err
            concept_only.append(cid)
            continue
        clues = file_clues(cid)
        diff = tree_diff(w, cid, clues)
        nfiles = diff.count('diff --git') + diff.count('+++ b/')
        if diff and nfiles <= MAX_FILES * 2:
            pd = os.path.join(CASES, cid, 'patch_real.diff')
            open(pd, 'w').write(diff)
            status[cid]['result'] = 'success'
            status[cid]['diff_bytes'] = len(diff)
            status[cid]['clues'] = clues
            done += 1
        else:
            status[cid]['result'] = 'concept_only'
            status[cid]['error'] = f'diff too large/empty ({nfiles} file-sections, clues={clues})'
            concept_only.append(cid)
        subprocess.run(['rm', '-rf', w], capture_output=True)
    json.dump(status, open(OUT, 'w'), ensure_ascii=False, indent=1)
    from collections import Counter
    c = Counter(v['result'] for v in status.values())
    print(f'total processed: {len(status)} | {dict(c)}')
    print(f'concept_only ({len(concept_only)}):')
    for cid in concept_only:
        print(f'  {cid[:46]:<48} {status[cid].get("error", "")[:90]}')


if __name__ == '__main__':
    main()
