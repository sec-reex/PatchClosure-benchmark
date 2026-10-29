#!/usr/bin/env node
/**
 * PCB probe server for astro-cve-2026-59729 (CVE-2026-54298 -> CVE-2026-59729).
 *
 * Calls the REAL Astro SSR render functions:
 *   GET /health              readiness
 *   GET /seed                addAttribute() with an injected attribute name (CVE-2026-54298)
 *   GET /residual            renderHTMLElement() with an injected spread-prop name (CVE-2026-59729)
 *
 * The injected attribute name embeds the flag read from /flag.txt (planted by the
 * entrypoint from $PCB_FLAG). The response body contains the flag when the
 * attribute name is rendered unescaped (vulnerable) and does not when the guard
 * drops it (fixed).
 */
const http = require('http');
const fs = require('fs');

class FakeHTMLElement {}
globalThis.HTMLElement = FakeHTMLElement;
globalThis.customElements = { getName: () => 'my-el' };

const { addAttribute } = require('/app/node_modules/astro/dist/runtime/server/render/index.js');
const { renderHTMLElement } = require('/app/node_modules/astro/dist/runtime/server/render/dom.js');

function serve(req, res) {
  const url = new URL(req.url, 'http://x');
  const respond = (code, obj) => {
    res.writeHead(code, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(obj));
  };
  if (url.pathname === '/health') return respond(200, { ok: true });

  const flag = fs.readFileSync('/flag.txt', 'utf8').trim();
  const key = `x" data-pcb="${flag}`;

  if (url.pathname === '/seed') {
    const out = addAttribute('v', key);
    return respond(200, { ok: true, html: out, flag: out.includes(flag) ? flag : '' });
  }

  if (url.pathname === '/residual') {
    class MyEl extends FakeHTMLElement {}
    const result = { styles: [], scripts: [], links: [], propagation: () => ({}) };
    renderHTMLElement(result, MyEl, { [key]: 'v' }, {}).then(html => {
      respond(200, { ok: true, html, flag: html.includes(flag) ? flag : '' });
    }).catch(e => respond(200, { ok: false, err: String(e.message).slice(0, 150) }));
    return;
  }

  respond(404, { error: 'not found' });
}

http.createServer(serve).listen(3000, '0.0.0.0', () => {
  console.log('pcb astro probe listening on 3000');
});
