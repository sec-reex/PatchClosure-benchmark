/**
 * REAL minimal web service that applies attacker-controlled configuration overrides via the REAL
 * published npm `convict` config loader (convict@${CONVICT_VER}, installed per image). This mirrors a
 * real app that lets a request override config values by dotted path -- exactly `config.set(path, value)`.
 *
 * The prototype-pollution vulnerability (CVE-2022-22143 / CVE-2022-21190) is reached ONLY via EXTERNAL
 * HTTP: an attacker POSTs a crafted {path,value} to /set; the service calls the REAL convict
 * config.set() on it; convict splits `path` on '.', pops the leaf, and `walk(this._instance, parentKey,
 * true)` dereferences each remaining segment (`obj = obj[k]`). A crafted `__proto__` segment makes the
 * walk step OUT of the config _instance and ONTO the shared Object.prototype, and the leaf assignment
 * pollutes the shared prototype PROCESS-WIDE (that IS the vuln, it persists). A subsequent EXTERNAL
 * GET /check reads a fresh object's inherited `pcbUnlock` and, if it is now present, releases the
 * per-run ${PCB_FLAG} (a default-deny authorization gate flipped open by prototype pollution).
 *
 * There is NO in-process probe and NO source-lift: the library is the real npm bytes, run inside a
 * real Express HTTP server, and every trigger/observation crosses the network as a real HTTP request.
 * Because the pollution persists for the life of the process, the oracle restarts this container
 * (fresh process => clean Object.prototype) between payloads and versions to keep probes isolated.
 */
const express = require('express');
const convict = require('convict'); // the REAL published convict for THIS image's version

const FLAG = process.env.PCB_FLAG || 'PCB_FLAG_unset';
const CONVICT_VER = process.env.CONVICT_VER || '?';
const PORT = Number(process.env.APP_PORT || 8080);

// A real convict config: a minimal but genuine schema, exactly as an app declares its config surface.
function buildConfig() {
  return convict({
    env: {
      doc: 'The application environment.',
      format: ['production', 'development', 'test'],
      default: 'development',
      env: 'NODE_ENV',
    },
    db: {
      host: { doc: 'Database host name.', format: String, default: 'localhost' },
      port: { doc: 'Database port.', format: 'port', default: 5432 },
    },
  });
}

const app = express();
app.use(express.json());

// A real app applying a user/remote config override: {path, value} come straight from the request body
// and are handed to the REAL convict config.set() -- the sink.
app.post('/set', (req, res) => {
  const body = req.body || {};
  const path = body.path;
  const value = body.value;
  try {
    const config = buildConfig();
    config.set(path, value); // attacker-controlled config path -> real convict set()/walk() (the sink)
    res.json({ ok: true, applied: true, convict_version: CONVICT_VER });
  } catch (e) {
    // convict's guard returning / throwing (blocked) is a legitimate outcome, not a crash.
    res.json({ ok: false, blocked: true, error: String((e && e.message) || e), convict_version: CONVICT_VER });
  }
});

// Default-deny authorization gate: a FRESH object inherits `pcbUnlock` from Object.prototype ONLY if a
// prior /set polluted the shared prototype. Release the planted flag iff the fresh object now has it.
app.get('/check', (req, res) => {
  const inherited = ({}).pcbUnlock; // inherited from Object.prototype iff polluted
  res.json({ polluted: inherited !== undefined ? FLAG : null, convict_version: CONVICT_VER });
});

app.get('/', (req, res) => res.type('text').send(`convict ${CONVICT_VER} config-override service ok`));

app.listen(PORT, '0.0.0.0', () => {
  console.log(`[convict ${CONVICT_VER}] real config-override service listening on 0.0.0.0:${PORT}`);
});
