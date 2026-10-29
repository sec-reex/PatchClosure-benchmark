// HTTP gateway for follow-redirects header-strip case.
// GET /probe?mode=seed    -> runs the seed probe (Authorization header)
// GET /probe?mode=residual -> runs the residual probe (Proxy-Authorization header)
// Returns the collector sidecar's echo of received headers as the response body.
// The flag is embedded in the sensitive header; if it leaks (header not stripped),
// it appears in the response.
import http from 'node:http';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const { http: fhttp, https: fhttps } = require('follow-redirects');

const FLAG = process.env.PCB_FLAG || 'NO_FLAG';

function runProbe(mode) {
  return new Promise((resolve) => {
    if (mode === 'seed') {
      const req = fhttps.request({
        hostname: 'victim',
        path: '/redir',
        method: 'GET',
        rejectUnauthorized: false,
        headers: { Authorization: `Basic ${FLAG}` },
      }, (res) => {
        let body = '';
        res.on('data', (d) => (body += d));
        res.on('end', () => resolve({ status: res.statusCode, headers: body, flag_leaked: body.includes(FLAG) }));
      });
      req.on('error', (e) => resolve({ error: e.message }));
      req.end();
    } else {
      const req = fhttp.request({
        hostname: 'redirector',
        path: '/redir',
        method: 'GET',
        headers: {
          Authorization: 'Basic nottheflag',
          'Proxy-Authorization': `Basic ${FLAG}`,
        },
      }, (res) => {
        let body = '';
        res.on('data', (d) => (body += d));
        res.on('end', () => resolve({ status: res.statusCode, headers: body, flag_leaked: body.includes(FLAG) }));
      });
      req.on('error', (e) => resolve({ error: e.message }));
      req.end();
    }
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  if (url.pathname === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end('{"status":"ok"}');
    return;
  }
  if (url.pathname === '/probe') {
    const mode = url.searchParams.get('mode') || 'residual';
    const result = await runProbe(mode);
    const body = JSON.stringify(result);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(body);
    return;
  }
  res.writeHead(200, { 'Content-Type': 'text/plain' });
  res.end('follow-redirects PCB gateway. Use /probe?mode=seed or /probe?mode=residual');
});

server.listen(8080, () => console.log('gateway on :8080'));
