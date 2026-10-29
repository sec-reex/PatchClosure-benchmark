// ALLOWED-domain sidecar (hostname "allowed"). This host IS on the Astro
// image.domains allowlist, so isRemoteAllowed("http://allowed/...") === true.
//
// It serves a benign image on /img.png, and exposes an OPEN REDIRECT at
// /redirect?to=<url> that 302-redirects to an arbitrary URL. This models the
// real-world CVE-2026-41321 prerequisite: an open redirect on an allow-listed
// domain that points at an internal host. The SSRF guard only validates the
// INITIAL url (allowed), so a redirect-following fetch reaches the internal
// canary.
import http from 'node:http';

// 1x1 transparent PNG (benign legitimate image)
const PNG = Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+M8AAAMBAQDJ/pLvAAAAAElFTkSuQmCC',
  'base64'
);

http.createServer((req, res) => {
  const u = new URL(req.url, 'http://allowed');
  if (u.pathname === '/redirect') {
    const to = u.searchParams.get('to') || 'http://canary/redirected';
    console.log('[allowed] 302 ->', to);
    res.writeHead(302, { Location: to });
    res.end();
    return;
  }
  console.log('[allowed] 200 img', req.url);
  res.writeHead(200, { 'Content-Type': 'image/png' });
  res.end(PNG);
}).listen(80, '0.0.0.0', () => console.log('[allowed] listening :80'));
