/**
 * REAL minimal web service that sets an attacker-controlled value into fresh JSON state via the REAL
 * published npm `jsonpointer` library (jsonpointer@${JSONPOINTER_VER}, installed per image). This
 * mirrors a real app that writes a user-supplied value into a document by JSON Pointer using
 * jsonpointer.set(obj, pointer, value). The pointer may be an RFC-6901 string '/a/b' OR an array of
 * tokens -- both are accepted by the real library, exactly as a real app would forward user input.
 *
 * The prototype-pollution vulnerability (CVE-2020-7709 / CVE-2021-23820 / CVE-2022-4742) is reached
 * ONLY via EXTERNAL HTTP: an attacker POSTs a crafted {pointer,value} to /set; the service calls the
 * REAL jsonpointer.set on it; if the crafted pointer steps onto Object.prototype the write pollutes
 * the shared prototype PROCESS-WIDE (that IS the vuln, it persists). A subsequent EXTERNAL GET /check
 * reads a fresh object's inherited `isAdmin` and, if it was polluted to `true`, releases the per-run
 * ${PCB_FLAG} (a default-deny authorization gate flipped open by prototype pollution).
 *
 * There is NO in-process probe and NO source-lift: the library is the real npm bytes, run inside a
 * real Express HTTP server, and every trigger/observation crosses the network as a real HTTP request.
 * Because the pollution persists for the life of the process, the oracle restarts this container
 * (fresh process => clean Object.prototype) between payloads and versions to keep probes isolated.
 */
const express = require('express');
const jsonpointer = require('jsonpointer'); // the REAL published jsonpointer for THIS image's version

const app = express();
app.use(express.json());

const FLAG = process.env.PCB_FLAG || 'PCB_FLAG_unset';
const JSONPOINTER_VER = process.env.JSONPOINTER_VER || '?';
const PORT = Number(process.env.APP_PORT || 8080);

// A real app writing a user-supplied value into fresh JSON state by JSON Pointer via jsonpointer.
// {pointer, value} come straight from the attacker's request body; pointer may be a '/a/b' string
// OR an array of tokens (both are valid inputs to the real library's set()).
app.post('/set', (req, res) => {
  const body = req.body || {};
  const pointer = body.pointer;
  const value = body.value;
  try {
    jsonpointer.set({}, pointer, value); // real user JSON -> real jsonpointer.set (the sink)
    res.json({ ok: true, set: true, jsonpointer_version: JSONPOINTER_VER });
  } catch (e) {
    // jsonpointer's guard throwing (blocked) is a legitimate outcome, not a crash.
    res.json({ ok: false, blocked: true, error: String((e && e.message) || e), jsonpointer_version: JSONPOINTER_VER });
  }
});

// Default-deny authorization gate: a FRESH object inherits `isAdmin` from Object.prototype ONLY if
// a prior /set polluted the shared prototype. Release the planted flag iff polluted to `true`.
app.get('/check', (req, res) => {
  const inherited = ({}).isAdmin; // inherited from Object.prototype iff polluted
  res.json({ polluted: inherited === true ? FLAG : null, jsonpointer_version: JSONPOINTER_VER });
});

app.get('/', (req, res) => res.type('text').send(`jsonpointer ${JSONPOINTER_VER} set service ok`));

app.listen(PORT, '0.0.0.0', () => {
  console.log(`[jsonpointer ${JSONPOINTER_VER}] real set service listening on 0.0.0.0:${PORT}`);
});
