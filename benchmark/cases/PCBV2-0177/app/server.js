/**
 * REAL minimal web service that merges attacker-controlled JSON via the REAL published
 * npm `set-in` library (set-in@${SETIN_VER}, installed per image). This mirrors a real app
 * that deep-merges user-supplied JSON into fresh state with set-in's setIn(object, path, value).
 *
 * The prototype-pollution vulnerability (CVE-2020-28273 / CVE-2022-25354) is reached ONLY via
 * EXTERNAL HTTP: an attacker POSTs a crafted {path,value} to /merge; the service calls the REAL
 * setIn on it; if the crafted path steps onto Object.prototype the write pollutes the shared
 * prototype PROCESS-WIDE (that IS the vuln, it persists). A subsequent EXTERNAL GET /check reads a
 * fresh object's inherited `isAdmin` and, if it was polluted to `true`, releases the per-run
 * ${PCB_FLAG} (a default-deny authorization gate flipped open by prototype pollution).
 *
 * There is NO in-process probe and NO source-lift: the library is the real npm bytes, run inside a
 * real Express HTTP server, and every trigger/observation crosses the network as a real HTTP request.
 * Because the pollution persists for the life of the process, the oracle restarts this container
 * (fresh process => clean Object.prototype) between payloads and versions to keep probes isolated.
 */
const express = require('express');
const setIn = require('set-in'); // the REAL published set-in for THIS image's version

const app = express();
app.use(express.json());

const FLAG = process.env.PCB_FLAG || 'PCB_FLAG_unset';
const SETIN_VER = process.env.SETIN_VER || '?';
const PORT = Number(process.env.APP_PORT || 8080);

// A real app merging user-supplied JSON into fresh state via set-in.
// {path, value} come straight from the attacker's request body.
app.post('/merge', (req, res) => {
  const body = req.body || {};
  const path = body.path;
  const value = body.value;
  try {
    setIn({}, path, value); // real user JSON -> real setIn set-by-path (the sink)
    res.json({ ok: true, merged: true, set_in_version: SETIN_VER });
  } catch (e) {
    // set-in's guard throwing (blocked) is a legitimate outcome, not a crash.
    res.json({ ok: false, blocked: true, error: String((e && e.message) || e), set_in_version: SETIN_VER });
  }
});

// Default-deny authorization gate: a FRESH object inherits `isAdmin` from Object.prototype ONLY if
// a prior /merge polluted the shared prototype. Release the planted flag iff polluted to `true`.
app.get('/check', (req, res) => {
  const inherited = ({}).isAdmin; // inherited from Object.prototype iff polluted
  res.json({ polluted: inherited === true ? FLAG : null, set_in_version: SETIN_VER });
});

app.get('/', (req, res) => res.type('text').send(`set-in ${SETIN_VER} merge service ok`));

app.listen(PORT, '0.0.0.0', () => {
  console.log(`[set-in ${SETIN_VER}] real merge service listening on 0.0.0.0:${PORT}`);
});
