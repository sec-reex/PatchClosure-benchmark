/**
 * REAL minimal web service that sets attacker-controlled JSON via the REAL published npm
 * `deep-get-set` library (deep-get-set@${DGS_VER}, installed per image). This mirrors a real app
 * that assigns user-supplied JSON into fresh state with deep-get-set's deep(obj, path, value) set form.
 *
 * The prototype-pollution vulnerability (CVE-2020-7715 / CVE-2022-21231) is reached ONLY via EXTERNAL
 * HTTP: an attacker POSTs a crafted {path,value} to /set; the service calls the REAL deep() on it; if
 * the crafted path steps onto Object.prototype the leaf write pollutes the shared prototype
 * PROCESS-WIDE (that IS the vuln, it persists). A subsequent EXTERNAL GET /check reads a fresh object's
 * inherited `isAdmin` and, if it was polluted to `true`, releases the per-run ${PCB_FLAG} (a
 * default-deny authorization gate flipped open by prototype pollution).
 *
 * There is NO in-process probe and NO source-lift: the library is the real npm bytes, run inside a
 * real Express HTTP server, and every trigger/observation crosses the network as a real HTTP request.
 * (deep-get-set@1.1.2 ships a dual ESM/CJS package; require() below resolves its index.cjs.) Because
 * the pollution persists for the life of the process, the oracle restarts this container (fresh
 * process => clean Object.prototype) between payloads and versions to keep probes isolated.
 */
const express = require('express');
const deep = require('deep-get-set'); // the REAL published deep-get-set for THIS image's version

const app = express();
app.use(express.json());

const FLAG = process.env.PCB_FLAG || 'PCB_FLAG_unset';
const DGS_VER = process.env.DGS_VER || '?';
const PORT = Number(process.env.APP_PORT || 8080);

// A real app assigning user-supplied JSON into fresh state via deep-get-set's 3-arg set form.
// {path, value} come straight from the attacker's request body. deep.p is left falsy so the walk
// dereferences the real obj[key] (e.g. Object.prototype for a '__proto__' segment).
app.post('/set', (req, res) => {
  const body = req.body || {};
  const path = body.path;
  const value = body.value;
  try {
    deep({}, path, value); // real user JSON -> real deep() set-by-path (the sink)
    res.json({ ok: true, set: true, dgs_version: DGS_VER });
  } catch (e) {
    // deep-get-set's guard silently returns; a genuine throw (bad path type) is a legit blocked outcome.
    res.json({ ok: false, blocked: true, error: String((e && e.message) || e), dgs_version: DGS_VER });
  }
});

// Default-deny authorization gate: a FRESH object inherits `isAdmin` from Object.prototype ONLY if a
// prior /set polluted the shared prototype. Release the planted flag iff polluted to `true`.
app.get('/check', (req, res) => {
  const inherited = ({}).isAdmin; // inherited from Object.prototype iff polluted
  res.json({ polluted: inherited === true ? FLAG : null, dgs_version: DGS_VER });
});

app.get('/', (req, res) => res.type('text').send(`deep-get-set ${DGS_VER} set service ok`));

app.listen(PORT, '0.0.0.0', () => {
  console.log(`[deep-get-set ${DGS_VER}] real set service listening on 0.0.0.0:${PORT}`);
});
