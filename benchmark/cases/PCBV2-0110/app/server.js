'use strict';
/*
 * Real HTTP sink service for fastxmlparser_entity_expansion_limit
 * (CVE-2026-26278 [fast-xml-parser entity-expansion DoS; the fix added expansion accounting
 *  (maxTotalExpansions/maxExpandedLength) to replaceEntitiesValue() but ONLY inside the DOCTYPE
 *  loop], fixed 5.3.6 = TARGET
 *  -> CVE-2026-33036 [the 5.3.6 fix is INCOMPLETE: the standard-entity (lastEntities) and
 *  HTML-entity (htmlEntities, incl numeric &#..; refs) loops stayed UNCOUNTED, so a long run of
 *  standard/numeric entity references drives O(N^2) work that ignores every configured limit;
 *  fixed 5.5.6 by wrapping the SAME lastEntities/htmlEntities loops with the count guard], CWE-776/400).
 *
 * A minimal REAL Express web service that mirrors an ordinary app which accepts a user-supplied XML
 * document (config upload, API body, feed, SOAP, ...) and parses it with the REAL, unmodified
 * fast-xml-parser -- SYNCHRONOUSLY on the Node event loop:
 *
 *     const { XMLParser } = require('fast-xml-parser');
 *     const out = new XMLParser({ processEntities: true }).parse(req.body);   // <-- THE SINK
 *
 * The installed fast-xml-parser version (build-arg FXP_VERSION, npm i fast-xml-parser@X) is the ONLY
 * thing that varies across v0/v1/v2; the service code + Express are identical. A malicious
 * entity-expansion input makes the synchronous parse blow up CPU and HANG the HTTP response (the
 * event loop is single-threaded, the entity-replacement loop cannot be interrupted mid-run) -- or,
 * on the FIXED versions, the parser throws the configured-limit error and the response returns fast.
 * That is the DoS signal, observed EXTERNALLY as server-side response latency.
 */
const express = require('express');
const { XMLParser } = require('fast-xml-parser');

const app = express();
const VERSION = process.env.FXP_VERSION || 'unknown';

// Accept the raw request body as text for ANY content-type (text/xml, application/xml, ...).
// The limit is generous because a legitimately large XML upload is normal; the DoS is CPU-bound
// (O(N^2) entity replacement), not size-bound -- the malicious body is well under this cap.
app.use(express.text({ type: () => true, limit: '8mb' }));

app.post('/parse', (req, res) => {
  const xml = (typeof req.body === 'string') ? req.body : '';
  const out = { fxp: VERSION, loaded: false, error: null, server_ms: 0, in_len: xml.length };
  const t0 = process.hrtime.bigint();
  try {
    // THE SINK: the real, unmodified fast-xml-parser over the external request body, run
    // SYNCHRONOUSLY. A billion-laughs / long-entity-run input wedges the event loop here.
    const parser = new XMLParser({ processEntities: true });
    parser.parse(xml);
    out.loaded = true;
  } catch (e) {
    // On a FIXED version the parser throws "Entity expansion limit exceeded: ..." -> fast response.
    out.error = (e && e.message) ? e.message : String(e);
  }
  out.server_ms = Number(process.hrtime.bigint() - t0) / 1e6;
  res.json(out);
});

app.get('/health', (req, res) => res.json({ status: 'ok', fxp: VERSION }));

const PORT = parseInt(process.env.PORT || '80', 10);
app.listen(PORT, '0.0.0.0', () => {
  console.log('fxp entity-expansion parse service listening on', PORT, '(fast-xml-parser ' + VERSION + ')');
});
