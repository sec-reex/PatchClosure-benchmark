/**
 * Environment canary hosts for the ssrf-sidecar oracle (BUILD_GUIDE "canary = in the ENVIRONMENT").
 * These are NOT part of the app under test -- they are the SSRF target + a legit allowlisted upstream.
 * The application under test is the REAL Astro server (see app/, Dockerfile); this file only stands up
 * the two plain HTTP hosts that Astro's /_image endpoint may (mis)fetch.
 *
 *   ROLE=sidecar  internal-sidecar : serves ${PCB_FLAG} on any path. NOT on the image.domains allowlist,
 *                                    NO published host port, distinct hostname. The flag can appear in an
 *                                    /_image response ONLY if isRemotePath misclassified the href so the
 *                                    allowlist was skipped and Astro server-side fetched this host.
 *   ROLE=public   public-app       : the allowlisted upstream (image.domains=['public-app']). Serves a
 *                                    benign, non-flag body -- where a correctly validated remote fetch lands.
 */
import http from 'node:http';

const ROLE = process.env.ROLE || 'sidecar';
const PORT = Number(process.env.APP_PORT || 80);
const FLAG = process.env.PCB_FLAG || 'PCB_FLAG_unset';

const server = http.createServer((req, res) => {
  if (ROLE === 'public') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end(`PUBLIC-APP OK path=${req.url} (allowlisted image host; NOT the flag)`);
  } else {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end(FLAG);
  }
});

server.listen(PORT, '0.0.0.0', () =>
  console.log(`[${ROLE}] listening on :${PORT}`));
