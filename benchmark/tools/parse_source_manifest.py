#!/usr/bin/env python3
"""ROUND16 task 1: parse case.json versions into a structured source manifest.

Purity rule: reads ONLY the `versions` field and the patch.diff headers.
Never touches _heldout/ or case.json residual/evidence/held_out fields.
Case-agnostic regex rules only; anything not parseable -> source_type
"unresolved" with sub_type + raw ref text for human judgment.
"""
import json, glob, os, re, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # benchmark/
CASES = os.path.join(ROOT, 'cases')
OUT = os.path.join(ROOT, 'provenance', 'source_manifest.json')

GIT_RE = re.compile(
    r'github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+'           # github.com/owner/repo
    r'|raw\.githubusercontent\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+'  # raw.githubusercontent owner/repo
    r'|git\s*:\s*[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+'            # git:owner/repo
    r'|git\s+tag\s+[\w./-]+'                                  # git tag release/x
    r'|git\+https?://'                                        # git+https
    r'|https?://[^/\s]+/[^/\s]+\.git'                         # repo.git url
    r'|\b[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[vV]?[\w.-]+'       # owner/repo@tag (suitecrm style)
)
GITHUB_TREE_RE = re.compile(r'github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)')
GIT_TAG_INLINE_RE = re.compile(r'git\s*:\s*([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@([\w./-]+)')
GIT_TAG_WORD_RE = re.compile(r'git\s+tag\s+([\w./-]+)')
COMMIT_RE = re.compile(r'\bcommit\s+([0-9a-f]{7,40})\b')

NPM_RE = re.compile(
    r'npm\s*:\s*([@A-Za-z0-9_./-]+?)(?:@|$)([\w.-]*)'
    r'|npm\s+package\s+([\w@./-]+)'
    r'|npm\s+([@A-Za-z0-9._/-]+)@([\w.-]+)'                   # npm @scope/pkg@ver / npm pkg@ver
    r'|\b@[a-z0-9._-]+/[a-z0-9._-]+\s*@?\s*([\w.-]+)'         # @scope/pkg @ver
    r'|\b[a-z0-9][a-z0-9._-]*@\d+\.\d+[\w.-]*'                # bare pkg@ver (lodash@4.17.21)
)
PYPI_RE = re.compile(
    r'\b([a-zA-Z0-9_-]+)\s+v?([0-9]+\.[0-9]+[\w.-]*)'
    r'|pip[\s:]+[A-Za-z0-9_-]+={2}[\w.]+'                     # pip Django==1.8.0
    r'|\b[A-Za-z0-9_][A-Za-z0-9_.-]*==[\w.]+'                 # jinja2==2.8.1 / Django==1.8
    r'|pypi'
    r'|pip\s+download'
)
COMPOSER_RE = re.compile(r'composer\s*:\s*([\w./-]+)(?:[/:])([\w.-]+)')
MAVEN_RE = re.compile(
    r'maven\s*:\s*([A-Za-z0-9_.-]+(?::[A-Za-z0-9_.-]+)+)\s*:?\s*([\w.-]+)?'
    r'|repo1\.maven\.org|central\.sonatype\.com'
)
CRATES_RE = re.compile(r'crates\.io\s+([a-z0-9_-]+)\s*([\w.-]*)')
WORD_PRESS_RE = re.compile(r'https?://downloads\.wordpress\.org/plugin/([a-z0-9-]+)\.([\w.-]+)\.zip')
TGZ_RE = re.compile(r'https?://\S+\.(?:tgz|tar\.gz|zip)')
DOCKER_RE = re.compile(
    r'official\s+image\s+([\w./-]+):([\w.-]+)'
    r'|image\s+([\w./-]+):([\w.-]+)'
    r'|docker\s+image\s+([\w./-]+)'
    r'|\b(?:[a-z0-9_.-]+/){0,3}([a-z0-9_-]+):([\w.-]+)(?:\s|\b|$)'  # loose X:Y / owner/img:tag
)

PATCH_FILE_RE = re.compile(
    r'^diff --git a/(\S+) b/\S+'
    r'|^--- a/(\S+)'
    r'|^\+\+\+ b/(\S+)'
)


def parse_version(ident, ref):
    """Return (source_type, sub_type, locator) for one version entry."""
    txt = f"{ident or ''} {ref or ''}"
    locator = None
    if GIT_RE.search(txt):
        sub = 'git'
        if GITHUB_TREE_RE.search(txt):
            locator = {'repo_url': 'https://github.com/' + GITHUB_TREE_RE.search(txt).group(1)}
        else:
            m = GIT_TAG_INLINE_RE.search(txt)
            if m:
                locator = {'repo_url': f"https://github.com/{m.group(1)}", 'ref': m.group(2)}
            else:
                m = GIT_TAG_WORD_RE.search(txt)
                if m:
                    locator = {'repo_url': txt.split(' ')[0], 'ref': m.group(1)}
        # extract any tag/commit
        if locator is None:
            locator = {}
        m = GITHUB_TREE_RE.search(txt)
        if m and not locator.get('ref'):
            tm = re.search(r'/tree/([\w./-]+)', txt)
            if tm:
                locator['ref'] = tm.group(1)
        mc = COMMIT_RE.search(txt)
        if mc and not locator.get('ref'):
            locator['ref'] = mc.group(1)
        mraw = re.search(r'raw\.githubusercontent\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)', txt)
        if mraw and not locator.get('repo_url'):
            locator['repo_url'] = 'https://github.com/' + mraw.group(1)
        # owner/repo@tag (no github.com prefix)
        mtag = re.search(r'\b([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@([vV]?[\w.-]+)', txt)
        if mtag and not locator.get('repo_url'):
            locator['repo_url'] = 'https://github.com/' + mtag.group(1)
            locator['ref'] = mtag.group(2)
        return 'git', sub, locator
    if COMPOSER_RE.search(txt):
        m = COMPOSER_RE.search(txt)
        return 'unresolved', 'composer', {'pkg': m.group(1) if m else '', 'version': m.group(2) if m else ''}
    if MAVEN_RE.search(txt):
        m = MAVEN_RE.search(txt)
        return 'unresolved', 'maven', {'gav': m.group(1) if m else '', 'version': m.group(2) if m and m.group(2) else ''}
    if NPM_RE.search(txt):
        m = NPM_RE.search(txt)
        if m:
            pkg = m.group(1) or m.group(3) or m.group(4) or m.group(5)
            ver = m.group(2) or ''
            locator = {'pkg': pkg, 'version': ver}
        return 'npm', 'npm', locator
    if DOCKER_RE.search(txt):
        m = DOCKER_RE.search(txt)
        img = (m.group(1) or m.group(3) or m.group(5) or m.group(6) or '')
        tag = (m.group(2) or m.group(4) or m.group(7) or '')
        locator = {'image': img, 'tag': tag}
        return 'docker_image', 'docker', locator
    if PYPI_RE.search(txt):
        m = PYPI_RE.search(txt)
        locator = {'pkg': m.group(1) if m and m.group(1) else '', 'version': m.group(2) if m else ''}
        return 'pypi', 'pypi', locator
    # unresolved sub-typing for the human-judgment list
    if CRATES_RE.search(txt):
        m = CRATES_RE.search(txt)
        locator = {'crate': m.group(1) if m else '', 'version': m.group(2) or ''}
        return 'unresolved', 'crates', locator
    if WORD_PRESS_RE.search(txt):
        m = WORD_PRESS_RE.search(txt)
        locator = {'slug': m.group(1) if m else '', 'version': m.group(2) if m else ''}
        return 'unresolved', 'wordpress_plugin_zip', locator
    if TGZ_RE.search(txt):
        return 'unresolved', 'url_tgz', {'url': TGZ_RE.search(txt).group(0)}
    if COMMIT_RE.search(txt):
        return 'unresolved', 'commit_only', {'commit': COMMIT_RE.search(txt).group(1)}
    return 'unresolved', 'other', None


def patch_files(case_dir):
    """Extract touched file paths from patch.diff headers (diff --git / --- / +++)."""
    pf = os.path.join(case_dir, 'patch.diff')
    if not os.path.exists(pf):
        return []
    files, seen = [], set()
    for line in open(pf, encoding='utf-8', errors='ignore'):
        if line.startswith('diff --git') and '/dev/null' not in line:
            m = re.match(r'diff --git a/(\S+) b/(\S+)', line)
            p = m.group(1) if m else None
        else:
            p = None
        if p and p not in seen:
            seen.add(p); files.append(p)
    # fallback to --- / +++ when no diff --git headers (unified-only patches)
    if not files:
        for line in open(pf, encoding='utf-8', errors='ignore'):
            for pat in (r'^--- a/(\S+)', r'^\+\+\+ b/(\S+)'):
                m = re.match(pat, line)
                if m:
                    p = m.group(1)
                    if p not in seen and p != '/dev/null':
                        seen.add(p); files.append(p)
                    break
    return files


def main():
    manifest = {}
    stats = {}
    unresolved = []
    for f in sorted(glob.glob(os.path.join(CASES, '*', 'case.json'))):
        d = json.load(open(f))
        cid = d.get('case_id')
        versions = d.get('versions', {})
        entry = {'case_id': cid, 'source_type': None, 'v0': None, 'v1': None,
                 'v2': None, 'patch_files': [], 'fetch_plan': None, 'notes': []}
        for ver in ('v0', 'v1', 'v2'):
            e = versions.get(ver) or {}
            ident, ref = e.get('identifier') or '', e.get('ref') or ''
            st, sub, loc = parse_version(ident, ref)
            entry[ver] = {'source_type': st, 'sub_type': sub, 'locator': loc,
                          'raw': (ident + ' | ' + ref)[:200]}
            if ver == 'v1':
                entry['source_type'] = st
        entry['patch_files'] = patch_files(os.path.dirname(f))
        plan = {'git': 'sparse_git', 'npm': 'npm_pack', 'pypi': 'pip_download',
                'docker_image': 'docker_cp'}.get(entry['source_type'], 'none')
        entry['fetch_plan'] = plan
        manifest[cid] = entry
        if entry['source_type'] == 'unresolved':
            unresolved.append({'case_id': cid, 'sub_type': entry['v1']['sub_type'],
                               'raw_v1': entry['v1']['raw']})
    json.dump(manifest, open(OUT, 'w'), ensure_ascii=False, indent=1)
    # stats
    from collections import Counter
    st = Counter(e['source_type'] for e in manifest.values())
    sub = Counter(u['sub_type'] for u in unresolved)
    auto = sum(1 for e in manifest.values() if e['fetch_plan'] in ('sparse_git', 'npm_pack', 'pip_download', 'docker_cp'))
    print(f"total cases: {len(manifest)}")
    print(f"source_type: {dict(st)}")
    print(f"unresolved sub_type: {dict(sub)}")
    print(f"fetch_plan auto-executable: {auto}/215")
    print(f"patch_files extracted: {sum(1 for e in manifest.values() if e['patch_files'])}/215")
    print(f"\nunresolved list ({len(unresolved)}):")
    for u in unresolved:
        print(f"  {u['case_id'][:38]:<40} {u['sub_type']:<24} {u['raw_v1'][:60]}")


if __name__ == '__main__':
    main()
