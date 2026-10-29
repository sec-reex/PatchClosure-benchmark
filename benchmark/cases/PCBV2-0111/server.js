'use strict';
/*
 * Real HTTP sink service for fastxmlparser_entityname_regex_injection
 * (CVE-2023-34104 [fast-xml-parser DOCTYPE entity-name -> RegExp injection; the entity NAME
 *  is interpolated UNESCAPED into RegExp(`&${entityName};`,"g") in DocTypeReader.js and run over
 *  element text before the built-in XML entities decode], fixed 4.2.4 = TARGET
 *  -> CVE-2026-25896 [the 4.2.4 blocklist added '|','+' but MISSED '.', so a period-wildcard
 *  entity name still shadows a built-in entity; fixed 5.3.5 by escaping regex metachars]).
 *
 * A minimal REAL Express web service that mirrors an ordinary app which accepts a user-supplied
 * XML document (config upload, API body, feed, SOAP, ...) and parses it with the REAL, unmodified
 * fast-xml-parser:
 *
 *     const { XMLParser } = require('fast-xml-parser');
 *     const out = new XMLParser({ processEntities: true }).parse(req.body);   // <-- THE SINK
 *
 * The installed fast-xml-parser version (build-arg FXP_VERSION, npm i fast-xml-parser@X) is the
 * ONLY thing that varies across v0/v1/v2 -- the service code is identical. Same POST /parse
 * endpoint, same XMLParser.parse call, three consecutive published releases, and whether the
 * DOCTYPE entity-name regex injection fires (a wildcard/quantifier entity NAME shadows the
 * built-in &lt; and overwrites its decoded value with attacker-controlled DOCTYPE entity content)
 * differs per version.
 *
 * Content-injection canary (benign): the attacker's malicious XML carries the per-run ${PCB_FLAG}
 * token AS THE DOCTYPE ENTITY VALUE. When the entity-name regex shadows the built-in &lt;
 * reference in the body <r>&lt;</r>, the real XMLParser writes that attacker value into the parsed
 * <r> field -> the flag surfaces in the JSON HTTP response. If the injection does NOT fire, &lt;
 * decodes normally to "<" and the flag never appears. Nothing in fast-xml-parser is modified.
 */
const express = require('express');
const { XMLParser } = require('fast-xml-parser');

const app = express();
const VERSION = process.env.FXP_VERSION || 'unknown';

// Accept the raw request body as text for ANY content-type (text/xml, application/xml, ...).
app.use(express.text({ type: () => true, limit: '256kb' }));

app.post('/parse', (req, res) => {
  const xml = (typeof req.body === 'string') ? req.body : '';
  const out = { fxp: VERSION, loaded: false, error: null, parsed: null };
  try {
    // THE SINK: the real, unmodified fast-xml-parser over the external request body.
    const parser = new XMLParser({ processEntities: true });
    out.parsed = parser.parse(xml);
    out.loaded = true;
  } catch (e) {
    out.error = (e && e.message) ? e.message : String(e);
  }
  res.json(out);
});

app.get('/health', (req, res) => res.json({ status: 'ok', fxp: VERSION }));

const PORT = parseInt(process.env.PORT || '80', 10);
app.listen(PORT, '0.0.0.0', () => {
  console.log('fxp parse service listening on', PORT, '(fast-xml-parser ' + VERSION + ')');
});
