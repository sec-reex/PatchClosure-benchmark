# fastify-static-cve-2026-7120

CVE-2026-15074 -> CVE-2026-7120 (incomplete-fix chain, path normalization variant).

- V0 = @fastify/static 10.1.0 (non-leading '..' + non-canonical '/./' both bypass allowedPath)
- V1 = @fastify/static 10.1.1 (CVE-2026-15074 '..' fixed; '/./' still bypasses) <- target
- V2 = @fastify/static 10.1.2 (CVE-2026-7120 fixed: allowedPath sees normalized pathname)

allowedPath returns 404 for any pathname starting with /private/. The seed uses
`/static/foo/../private/canary.txt`; the residual uses `/static/./private/canary.txt`
(and `//` variants), which the fix for CVE-2026-15074 did not normalize before the
allowedPath callback.

GitHub advisory (GHSA-8pvw-jcv7-9cmj): "evaluates the allowedPath callback before
normalizing dot segments and duplicate slashes in the pathname used for file
resolution."

Gate (all four edges, real Docker): seed@V0 reaches, seed@V1 blocked,
residual@V1 reaches, residual@V2 blocked. See repro.log.

Incomplete-fix writeup: [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md).
