'use strict';
// REAL Express HTTP service that parses a user-supplied CSS string with the REAL published npm
// package `@adobe/css-tools` (pinned per profile to 4.3.0 / 4.3.1 / 4.3.2). This mirrors a real app
// (a CSS-in-JS toolchain, jest-dom / testing-library, a style linter or theme editor) that parses
// untrusted CSS with css.parse().
//
// The sink runs SYNCHRONOUSLY on the Node event loop:
//     css.parse(req.body.css)
// so a catastrophic-backtracking input (CVE-2023-26364 @import bomb on 4.3.0; CVE-2023-48631
// selector-paren bomb on 4.3.0 AND 4.3.1) makes the HTTP response HANG -> server-side ReDoS
// observable as external request latency. No vendored/edited source: the real package is required.
const express = require('express');
const css = require('@adobe/css-tools');

const app = express();
// residual payload is ~140 KB of '(' — allow a comfortable body so it reaches the parser
app.use(express.json({ limit: '4mb' }));

const VERSION = process.env.CSS_TOOLS_VERSION || 'unknown';

app.get('/health', (req, res) => {
  res.json({ ok: true, css_tools_version: VERSION });
});

// POST /parse {css: "<string>"} -> {ok, rules, server_ms, len}
// css.parse() runs synchronously on the event loop; a ReDoS input blocks the response.
app.post('/parse', (req, res) => {
  const input = (req.body && typeof req.body.css === 'string') ? req.body.css : '';
  const t0 = process.hrtime.bigint();
  let ok = true, rules = 0, err = null;
  try {
    const ast = css.parse(input, { silent: true });   // <-- synchronous ReDoS sink
    rules = (ast && ast.stylesheet && ast.stylesheet.rules) ? ast.stylesheet.rules.length : 0;
  } catch (e) {
    ok = false;
    err = String(e && e.message || e).slice(0, 120);
  }
  const server_ms = Number(process.hrtime.bigint() - t0) / 1e6;
  res.json({ ok, rules, error: err, server_ms, len: input.length, css_tools_version: VERSION });
});

const PORT = Number(process.env.PORT || 3000);
app.listen(PORT, '0.0.0.0', () => {
  console.log(`css-parse listening on :${PORT} (@adobe/css-tools@${VERSION})`);
});
