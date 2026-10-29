/**
 * REAL minimal web service that replays attacker-controlled JSON patches via the REAL published npm
 * `immer` library (immer@${IMMER_VER}, installed per image). This mirrors a real app (e.g. a
 * Redux-Toolkit-style server) that applies user-supplied JSON-patch ops to state with immer's
 * applyPatches(base, patches).
 *
 * The prototype-pollution vulnerability (CVE-2020-28477 / CVE-2021-3757 / CVE-2021-23436) is reached
 * ONLY via EXTERNAL HTTP: an attacker POSTs a crafted `patches` array to /apply; the service calls the
 * REAL applyPatches on a FRESH immerable base; if a patch's path steps an intermediate `__proto__`
 * segment onto Object.prototype the leaf assignment pollutes the shared prototype PROCESS-WIDE (that IS
 * the vuln, it persists). A subsequent EXTERNAL GET /check reads a fresh object's inherited `isAdmin`
 * and, if it was polluted to `true`, releases the per-run ${PCB_FLAG} (a default-deny authorization
 * gate flipped open by prototype pollution).
 *
 * There is NO in-process probe and NO source-lift: the library is the real npm bytes, run inside a real
 * Express HTTP server, and every trigger/observation crosses the network as a real HTTP request. Because
 * the pollution persists for the life of the process, the oracle restarts this container (fresh process
 * => clean Object.prototype) between payloads and versions to keep probes isolated.
 */
const express = require('express');
const { applyPatches, enablePatches } = require('immer'); // the REAL published immer for THIS image's version
enablePatches(); // applyPatches requires the Patches plugin to be enabled

const app = express();
app.use(express.json());

const FLAG = process.env.PCB_FLAG || 'PCB_FLAG_unset';
const IMMER_VER = process.env.IMMER_VER || '?';
const PORT = Number(process.env.APP_PORT || 8080);

// A real app applying user-supplied JSON patches to fresh state via immer.
// `patches` (an array of {op,path,value}) comes straight from the attacker's request body; the base is
// a fresh plain (immerable) object so applyPatches genuinely produces a draft and walks the patch paths.
app.post('/apply', (req, res) => {
  const body = req.body || {};
  const patches = body.patches;
  const base = { seeded: 1 }; // fresh immerable base -> applyPatches produces a draft and applies onto it
  try {
    applyPatches(base, patches); // real user patch JSON -> real immer applyPatches path-walk (the sink)
    res.json({ ok: true, applied: true, immer_version: IMMER_VER });
  } catch (e) {
    // immer's guard throwing (die(24) blocked) is a legitimate outcome, not a crash.
    res.json({ ok: false, blocked: true, error: String((e && e.message) || e), immer_version: IMMER_VER });
  }
});

// Default-deny authorization gate: a FRESH object inherits `isAdmin` from Object.prototype ONLY if a
// prior /apply polluted the shared prototype. Release the planted flag iff polluted to `true`.
app.get('/check', (req, res) => {
  const inherited = ({}).isAdmin; // inherited from Object.prototype iff polluted
  res.json({ polluted: inherited === true ? FLAG : null, immer_version: IMMER_VER });
});

app.get('/', (req, res) => res.type('text').send(`immer ${IMMER_VER} applyPatches service ok`));

app.listen(PORT, '0.0.0.0', () => {
  console.log(`[immer ${IMMER_VER}] real applyPatches service listening on 0.0.0.0:${PORT}`);
});
