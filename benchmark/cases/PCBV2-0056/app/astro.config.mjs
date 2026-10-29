// REAL Astro site for the /_image isRemotePath allowlist SSRF case
// (CVE-2025-55303 -> CVE-2025-59837). This is a genuine published-Astro project:
//   - output: 'server'      -> on-demand rendered SSR (the image endpoint runs per request)
//   - @astrojs/node adapter -> booted as a REAL standalone Node HTTP server (dist/server/entry.mjs)
//   - image.domains         -> remote-image allowlist == ['public-app'] (an internal-but-PERMITTED
//                              host). The attacker-controlled `internal-sidecar` host is NOT allowlisted.
//
// image.service = the built-in `noop` local service: it runs the SAME /_image guard flow
// (imageService.parseURL -> isRemotePath -> isRemoteAllowed -> loadRemoteImage) but its transform()
// returns the fetched bytes UNCHANGED, so the observable HTTP response body is exactly what the
// server fetched upstream. That is what lets the differential oracle SEE the sidecar flag bytes when
// the SSRF fires (a transcoding service like sharp would re-encode or reject non-image bytes and hide it).
//
// image.endpoint = the built-in `generic` endpoint (astro/assets/endpoint/generic). This is the REAL
// Astro image endpoint used by every SSR / serverless deployment; it is the endpoint the CVE actually
// affects. (The @astrojs/node adapter additionally ships its own `node` endpoint variant whose local
// branch has an unrelated dist/-assets path check that incidentally shadows this SSRF; selecting the
// generic endpoint via this PUBLIC config option exercises the true vulnerable code path. The guard
// under test -- isRemotePath in @astrojs/internal-helpers -- is byte-identical between both endpoints,
// so the version differential is unchanged.)
import { defineConfig } from 'astro/config';
import node from '@astrojs/node';

export default defineConfig({
  output: 'server',
  adapter: node({ mode: 'standalone' }),
  image: {
    domains: ['public-app'],
    service: { entrypoint: 'astro/assets/services/noop' },
    endpoint: { entrypoint: 'astro/assets/endpoint/generic' },
  },
});
