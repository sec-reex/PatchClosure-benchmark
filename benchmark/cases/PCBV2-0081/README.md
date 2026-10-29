# astro-cloudflare-cve-2026-41321

Incomplete-fix gold case for **CVE-2026-41321** (@astrojs/cloudflare SSRF via
redirect following), the incomplete fix of **CVE-2025-58179**.

The `/_image` image-transform endpoint validates only the *initial* href against
the `image.domains` allowlist (`isRemoteAllowed()`), then the Cloudflare Worker
fetches it. In **13.1.9** the remote fetch uses the WHATWG default
`redirect:'follow'`, so an open redirect on an allow-listed domain is followed to
an internal host — blind SSRF (CWE-918). **13.1.10** switches to
`redirect:'manual'` and turns any 3xx into a 404.

## Profiles (real npm bytes, workerd)
| profile | adapter | astro | runtime | port |
|---|---|---|---|---|
| v0 | 12.6.5 | 5.18.2 | `wrangler pages dev` (built worker) | 4310 |
| v1 | 13.1.9 | 6.4.8 | `astro dev` + @cloudflare/vite-plugin | 4311 |
| v2 | 13.1.10 | 6.4.8 | `astro dev` + @cloudflare/vite-plugin | 4312 |

## Run
```bash
export PCB_FLAG="PCB_$(openssl rand -hex 8)"
docker compose --profile v1 up -d --build          # (or v0 / v2)
PCB_FLAG=$PCB_FLAG python3 oracle.py --profile v1 --base-url http://127.0.0.1:4311 --wait
docker compose down -v --rmi all
```

## Payloads (external HTTP GET to /_image)
- **Original** (CVE-2025-58179): `?href=http://canary/orig-<p>` — direct internal
  href, no allowlist. Reaches canary on v0; 403 on v1/v2.
- **Residual** (CVE-2026-41321): `?href=http://allowed/redirect?to=http://canary/resid-<p>`
  — allow-listed open redirect to the internal canary. Followed on v1 (canary
  reached); blocked on v2 (404).

Detection is a benign blind-SSRF canary: the internal `canary` sidecar (no host
port, not allow-listed) logs `${PCB_FLAG}` for every request it receives.

## Gate (real-docker, 2026-07-17): all four true
`original_reaches_flag_on_v0`, `original_blocked_on_v1`,
`residual_reaches_flag_on_v1`, `residual_blocked_on_v2`. See `repro.log`.

不完全修复分析见 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。
