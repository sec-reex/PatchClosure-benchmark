// INTERNAL canary sidecar (hostname "canary"). NOT on the image.domains
// allowlist and NOT published to any host port. Reachable only if the Astro
// server's /_image SSRF guard is bypassed (blind SSRF target).
//
// Every inbound request is appended to /hits/hits.log with the secret flag
// token, so the oracle can detect (from the shared volume) whether the
// internal service was actually reached. Also returns a tiny valid PNG so any
// pass-through path stays benign.
import http from 'node:http';
import fs from 'node:fs';

const FLAG = process.env.PCB_FLAG || 'PCB_FLAG_UNSET';
const HITLOG = '/hits/hits.log';

// 1x1 transparent PNG
const PNG = Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+M8AAAMBAQDJ/pLvAAAAAElFTkSuQmCC',
  'base64'
);

http.createServer((req, res) => {
  const line = `${new Date().toISOString()} FLAG=${FLAG} path=${req.url}\n`;
  try { fs.appendFileSync(HITLOG, line); } catch (e) { /* ignore */ }
  console.log('[canary] HIT', req.url);
  res.writeHead(200, { 'Content-Type': 'image/png', 'X-PCB-Flag': FLAG });
  res.end(PNG);
}).listen(80, '0.0.0.0', () => console.log('[canary] listening :80'));
