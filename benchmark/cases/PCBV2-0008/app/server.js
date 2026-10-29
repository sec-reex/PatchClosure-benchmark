'use strict';
// REAL Express HTTP service that validates a user-supplied version string with the REAL published
// npm package `semver-regex` (pinned per profile to 3.1.1 / 3.1.3 / 3.1.4). This mirrors a real app
// (release tooling / changelog parser / CI) that validates untrusted input with semverRegex().
//
// The sink runs SYNCHRONOUSLY on the Node event loop:
//     const ok = semverRegex().test(req.body.version)
// so a catastrophic-backtracking input (CVE-2021-3795 on 3.1.1, CVE-2021-43307 residual on 3.1.3)
// makes the HTTP response HANG -> server-side ReDoS observable as external request latency.
// A fresh regex is built per call via semverRegex(), so the /g-flag lastIndex is always 0.
const express = require('express');
const semverRegex = require('semver-regex');

const app = express();
app.use(express.json({ limit: '64kb' }));

const VERSION = process.env.SEMVER_REGEX_VERSION || 'unknown';

app.get('/health', (req, res) => {
  res.json({ ok: true, semver_regex_version: VERSION });
});

// POST /check {version: "<string>"} -> {ok: <bool>}
// The regex .test() runs synchronously on the event loop; a ReDoS input blocks the response.
app.post('/check', (req, res) => {
  const version = (req.body && typeof req.body.version === 'string') ? req.body.version : '';
  const t0 = process.hrtime.bigint();
  const ok = semverRegex().test(version);          // <-- synchronous ReDoS sink
  const server_ms = Number(process.hrtime.bigint() - t0) / 1e6;
  res.json({ ok, server_ms, len: version.length, semver_regex_version: VERSION });
});

const PORT = Number(process.env.PORT || 3000);
app.listen(PORT, '0.0.0.0', () => {
  console.log(`semver-check listening on :${PORT} (semver-regex@${VERSION})`);
});
