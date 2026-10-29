// PatchClosure-Bench harness for the n8n expression-sandbox escape
// incomplete-fix pair:
//   CVE-2025-68613 (n8n-workflow 1.119.0 / n8n 1.122.0: FunctionThisSanitizer --
//     binds regular-function `this` to { process: {} })
//   -> CVE-2026-25049 (n8n-workflow 1.120.7 / n8n 1.123.17: ThisSanitizer +
//     PrototypeSanitizer.visitObjectPattern -- blocks destructuring escape)
//
// FAITHFUL CORE: this harness imports the REAL n8n expression-evaluation sink
// VERBATIM from the pinned n8n-workflow npm package (no source modified):
//   - expression-evaluator-proxy.js  -> evaluateExpression() : the exact Tournament
//     instance wired with { before:[FunctionThisSanitizer], after:[PrototypeSanitizer,
//     DollarSignValidator] } that n8n's Expression.renderExpression() calls.
//   - expression-sandboxing.js       -> sanitizer / sanitizerName (the __sanitize hook)
//   - Expression.initializeGlobalContext(data) : the REAL allow/deny context object
//     (data.Function={}, data.globalThis={}, data.process is unset, ...) so a benign
//     expression cannot see the real `process`/`Function`.
//
//   POST /  {"expr":"<n8n-expression>"}  -> {"output":"<evaluated>"}
//
// The canary ${PCB_FLAG} lives ONLY in the container ENVIRONMENT (process.env.PCB_FLAG)
// and in /canary/flag.txt (planted by the entrypoint) -- NOT on the data context and
// NOT in app code. A benign expression evaluated against the sandbox context cannot see
// it. Only an expression that ESCAPES the sandbox to the REAL `process` / Function
// constructor (and reads process.env.PCB_FLAG, or execSync `cat /canary/flag.txt`) can
// surface it.  FLAG appears in output  <=>  the sandbox was escaped.
//
// This is the BENIGN benchmark canary: the "RCE" merely reads a planted random token --
// no real payload, no persistence.  The n8n-workflow version is pinned per profile at
// image-build time (npm i n8n-workflow@$NW_VERSION).

const http = require('http');
const path = require('path');

const NW = path.dirname(require.resolve('n8n-workflow/package.json'));
const proxy = require(path.join(NW, 'dist/cjs/expression-evaluator-proxy.js'));
const sandbox = require(path.join(NW, 'dist/cjs/expression-sandboxing.js'));
const { Expression } = require('n8n-workflow');
const NW_VERSION = require(path.join(NW, 'package.json')).version;

const FLAG = process.env.PCB_FLAG;
if (!FLAG) {
  console.error('PCB_FLAG not set');
  process.exit(1);
}

function evaluate(expr) {
  // Rebuild the REAL n8n expression context for every request (as n8n does).
  const data = {};
  Expression.initializeGlobalContext(data);
  data[sandbox.sanitizerName] = sandbox.sanitizer;
  return proxy.evaluateExpression(String(expr), data);
}

const server = http.createServer((req, res) => {
  if (req.method !== 'POST') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true, nw: NW_VERSION }));
    return;
  }
  let body = '';
  req.on('data', (c) => (body += c));
  req.on('end', () => {
    let out, err = null;
    try {
      const { expr } = JSON.parse(body || '{}');
      const val = evaluate(expr);
      out = typeof val === 'string' ? val : JSON.stringify(val);
    } catch (e) {
      err = String((e && e.message) || e).split('\n')[0];
      out = '';
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ output: out, error: err, nw: NW_VERSION }));
  });
});

server.listen(8080, () => {
  process.stdout.write('harness up n8n-workflow=' + NW_VERSION + '\n');
});
