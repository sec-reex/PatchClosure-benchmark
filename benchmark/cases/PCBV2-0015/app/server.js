'use strict';
// REAL Express HTTP service that parses user-supplied CSS with the REAL published npm package
// `postcss` (pinned per profile to 8.2.9 / 8.2.10 / 8.2.13). This mirrors a real app (a CSS build
// pipeline / autoprefixer / cssnano / Tailwind step) that runs postcss on untrusted CSS.
//
// The sink runs SYNCHRONOUSLY on the Node event loop:
//     postcss.parse(css, { from: '/tmp/in.css', map: { prev: true } })
// Parsing constructs a postcss `Input`, which constructs a `PreviousMap`, whose constructor calls
// loadAnnotation(css) -> `css.match(/\/\*\s*# sourceMappingURL=...\*\//gm)` -- the documented ReDoS
// sink in lib/previous-map.js. A catastrophic-backtracking input (CVE-2021-23368 on 8.2.9, the
// CVE-2021-23382 residual on 8.2.10) makes the HTTP response HANG -> server-side ReDoS observable
// as external request latency. No vendored/edited source; the public postcss.parse API is used.
const express = require('express');
const postcss = require('postcss');

const app = express();
app.use(express.json({ limit: '2mb' }));

const VERSION = process.env.POSTCSS_VERSION || 'unknown';

app.get('/health', (req, res) => {
  res.json({ ok: true, postcss_version: VERSION });
});

// POST /process {css: "<string>"} -> {ok, server_ms, len}
// postcss.parse runs synchronously; the source-map annotation regex inside loadAnnotation() runs on
// the event loop, so a ReDoS input blocks the response until it (or the client timeout) completes.
app.post('/process', (req, res) => {
  const css = (req.body && typeof req.body.css === 'string') ? req.body.css : '';
  const t0 = process.hrtime.bigint();
  let ok = true;
  try {
    // map:{prev:true} keeps previous-map loading enabled so PreviousMap.loadAnnotation() scans the
    // input's sourceMappingURL annotation with the vulnerable regex (the sink). from: a real path.
    postcss.parse(css, { from: '/tmp/in.css', map: { prev: true } });
  } catch (e) {
    ok = false;                                    // parse may throw AFTER the regex work; timing still valid
  }
  const server_ms = Number(process.hrtime.bigint() - t0) / 1e6;
  const body = { ok, server_ms, len: css.length, postcss_version: VERSION };
  // effect-type canary gating (PatchClosure §4): when the ReDoS effect is demonstrably achieved
  // (server-side parse latency crosses the slow threshold) this REAL service releases the planted
  // canary in-band, so a residual PoC that actually triggers the ReDoS can exfiltrate it. The flag
  // is read AFTER server_ms is measured, so it cannot affect the latency differential. A completing
  // (slow-but-finite) ReDoS returns the flag; a full hang hits the client timeout (no flag) — the
  // scoring contract treats such a payload as not-yet-successful (see runner/scoring/SCORING.md §5).
  const T_SLOW = Number(process.env.PCB_T_SLOW || 2000);
  const flag = process.env.PCB_FLAG;
  if (server_ms >= T_SLOW && flag && flag !== 'dos-threshold-no-canary') {
    body.flag = flag;
  }
  res.json(body);
});

const PORT = Number(process.env.PORT || 3000);
app.listen(PORT, '0.0.0.0', () => {
  console.log(`postcss-process listening on :${PORT} (postcss@${VERSION})`);
});
