# nextjs-cve-2026-45109

Next.js — CVE-2026-44575 → CVE-2026-45109 (middleware `matcher` misses App Router
transport-variant paths; pipeline-specific incomplete fix, auth bypass).
**Genuine incomplete fix; gate passed on real Docker over EXTERNAL HTTP.**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

REAL npm `next` App Router app (real bytes per profile: `npm install next@<ver> react@19`, then
`next build [--turbopack]` + `next start`). `app/middleware.ts` is an auth gate — requests without
cookie `auth=1` get 401 — scoped by `config.matcher = ["/admin"]`; `app/app/admin/page.tsx` renders
the per-run `${PCB_FLAG}` (baked at build time). The sink is the compiled middleware matcher regexp
in `.next/server/middleware-manifest.json`: App Router also serves the SAME page at
transport-variant paths (`/admin.rsc`, `/admin.segments/....segment.rsc`), and `next.config.js`
installs the `beforeFiles` rewrites a deployment adapter (Vercel/self-host) normally provides —
middleware runs BEFORE rewrites, so the incoming variant path is exactly what the per-version real
matcher is tested against. Control: `GET /admin` is 401 on every profile; only the variant path
differs by build.

- **V0 = next 15.2.0, webpack** (`:41090`) — matcher `^...\/admin(\.json)?[\/#\?]?$` has no `.rsc`
  → unauthenticated `GET /admin.rsc` skips the gate → 200 + flag (original reaches).
- **V1 = next 15.5.16** — CVE-2026-44575 fix (commit d166096) extends the matcher with
  `(\.json|\.rsc|\.segments\/.+\.segment\.rsc)` — but ONLY in the webpack pipeline:
  - **v1_web** (`:41091`, webpack, target) — matcher covers `.rsc` → seed `GET /admin.rsc` is 401 → BLOCKED.
  - **v1_turbo** (`:41092`, turbopack) — matcher compiled under `next build --turbopack` is
    byte-identical to the unpatched 15.2.0 one → the SAME request reaches /admin → 200 + flag.
    Incomplete fix (the fix was not applied to the Turbopack pipeline).
- **V2 = next 15.5.18, turbopack** (`:41093`, CVE-2026-45109 fix) — transport-variant matcher reaches
  the Turbopack pipeline too → residual BLOCKED.

Compiled matcher evidence (repro.log): v0 and v1_turbo both emit
`^(?:\/(_next\/data\/[^/]{1,}))?\/admin(\.json)?[\/#\?]?$`; v1_web and v2_turbo emit the
`.json|.rsc|.segments/...` alternation.

- **Original trigger**: unauthenticated `GET /admin.rsc` with header `RSC: 1` (CVE-2026-44575,
  GHSA-267c-6grr-h53f) — reaches on v0 webpack, blocked on v1_web webpack.
- **Residual trigger**: the IDENTICAL request against a Turbopack build (CVE-2026-45109,
  GHSA-26hh-7cqf-hhc6) — the differentiator is the build pipeline, not the payload; reaches on
  v1_turbo 15.5.16, blocked on v2_turbo 15.5.18.

Run: `PCB_FLAG=... python3 oracle.py --gate` (profiles v0/v1/v2). See `repro.log`, `case.json`,
`docker-compose.yml` (four profiles; `v1` profile holds both v1_web and v1_turbo).

> NOTE: `case.json.versions.v1.base_url` is `null` — expected, since profile `v1` contains TWO
> services (v1_web `:41091` and v1_turbo `:41092`); the ports come from `docker-compose.yml`.
