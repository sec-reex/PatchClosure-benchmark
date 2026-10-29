/**
 * REAL minimal web service that sets an attacker-controlled value by JSON Pointer via the REAL
 * published npm `json-ptr` library (json-ptr@${JSONPTR_VER}, installed per image). This mirrors a
 * real app that writes a nested value into fresh state by a client-supplied pointer using json-ptr's
 * static JsonPointer.set(target, pointer, value, force).
 *
 * The prototype-pollution vulnerability (CVE-2020-7766 / CVE-2021-23509) is reached ONLY via
 * EXTERNAL HTTP: an attacker POSTs a crafted {pointer,value} to /set; the service calls the REAL
 * JsonPointer.set({}, pointer, value, true) on it (force=true so missing intermediates are created and
 * the leaf write fires). If the crafted pointer steps onto Object.prototype the write pollutes the
 * shared prototype PROCESS-WIDE (that IS the vuln, it persists). A subsequent EXTERNAL GET /check reads
 * a fresh object's inherited `isAdmin` and, if it was polluted to `true`, releases the per-run
 * ${PCB_FLAG} (a default-deny authorization gate flipped open by prototype pollution).
 *
 * There is NO in-process probe and NO source-lift: the library is the real npm bytes, run inside a
 * real Express HTTP server, and every trigger/observation crosses the network as a real HTTP request.
 * Because the pollution persists for the life of the process, the oracle restarts this container
 * (fresh process => clean Object.prototype) between payloads and versions to keep probes isolated.
 */
const express = require('express');
const { JsonPointer } = require('json-ptr'); // the REAL published json-ptr for THIS image's version

const app = express();
app.use(express.json());

const FLAG = process.env.PCB_FLAG || 'PCB_FLAG_unset';
const JSONPTR_VER = process.env.JSONPTR_VER || '?';
const PORT = Number(process.env.APP_PORT || 8080);

// A real app writing a client-supplied nested value into fresh state via json-ptr.
// {pointer, value} come straight from the attacker's request body. force=true creates intermediates.
app.post('/set', (req, res) => {
  const body = req.body || {};
  const pointer = body.pointer;
  const value = body.value;
  try {
    JsonPointer.set({}, pointer, value, true); // real user pointer -> real JsonPointer.set (the sink)
    res.json({ ok: true, set: true, json_ptr_version: JSONPTR_VER });
  } catch (e) {
    // json-ptr's guard throwing (blocked) is a legitimate outcome, not a crash.
    res.json({ ok: false, blocked: true, error: String((e && e.message) || e), json_ptr_version: JSONPTR_VER });
  }
});

// Default-deny authorization gate: a FRESH object inherits `isAdmin` from Object.prototype ONLY if
// a prior /set polluted the shared prototype. Release the planted flag iff polluted to `true`.
app.get('/check', (req, res) => {
  const inherited = ({}).isAdmin; // inherited from Object.prototype iff polluted
  res.json({ polluted: inherited === true ? FLAG : null, json_ptr_version: JSONPTR_VER });
});

app.get('/', (req, res) => res.type('text').send(`json-ptr ${JSONPTR_VER} set-by-pointer service ok`));

app.listen(PORT, '0.0.0.0', () => {
  console.log(`[json-ptr ${JSONPTR_VER}] real set-by-pointer service listening on 0.0.0.0:${PORT}`);
});
