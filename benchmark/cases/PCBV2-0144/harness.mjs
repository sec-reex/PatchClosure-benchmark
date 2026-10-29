/**
 * Faithful-core harness for the npm `minimist` CLI arg-parser prototype-pollution guard
 * (pre-guard 1.2.1 -> __proto__ string guard 1.2.5 -> isConstructorOrProto 1.2.6 = CVE-2021-44906).
 *
 * `minimist(argv)` parses CLI-style args: a `--a.b.c value` flag is split on '.' into a key PATH and
 * deep-set via the internal `setKey(obj, keys, value)`, which walks each segment with `o = o[key]`
 * (creating an intermediate namespace when absent) and assigns the leaf. Because the walk dereferences
 * each segment with `o[key]`, a crafted segment `__proto__` (seed) or a `constructor.prototype` chain
 * (residual) makes the walk step onto `Object.prototype` and the assignment land on it = GLOBAL
 * prototype pollution. The boundary under test is setKey()'s key guard, so this image invokes the REAL,
 * per-version published minimist() as the guard in front of a benign default-deny flag-gate -- exactly
 * the boundary CVE-2021-44906 concerns. No offensive PoC is used; the target is a benign per-run
 * ${PCB_FLAG} released only if the crafted argv caused minimist() to pollute a prototype (guard bypassed).
 *
 *   HARNESS_VER=v0  minimist@1.2.1 -- NO __proto__ guard in setKey() (pre-CVE-2020-7598). The plain
 *                   `--__proto__.pcbUnlock` seed already steps onto Object.prototype and writes
 *                   `pcbUnlock` onto it.                                                     [seed env]
 *   HARNESS_VER=v1  minimist@1.2.5 -- carries the CVE-2020-7598 fix `if (key === '__proto__') return;`
 *                   (a strict `===` STRING comparison against '__proto__' only, plus Object/Number/
 *                   String/Array.prototype reference-reassignment guards). This BLOCKS the `--__proto__.x`
 *                   seed (return), but the guard names only '__proto__' -- it never inspects
 *                   'constructor', so `--constructor.prototype.pcbUnlock.x` walks Object -> Object.prototype
 *                   (the reference-reassignment `o[key]={}` silently fails because Object.prototype is
 *                   non-writable) and, with the prototype now an INTERMEDIATE (not the final `o`, so the
 *                   last-key `o===Object.prototype` guard does not fire), writes `pcbUnlock` onto
 *                   Object.prototype = CVE-2021-44906 residual (incomplete fix).       [TARGET, GIVEN]
 *   HARNESS_VER=v2  minimist@1.2.6 -- the CVE-2021-44906 fix: setKey() replaces the `key === '__proto__'`
 *                   check with `isConstructorOrProto(o, key)` (`key === 'constructor' && typeof
 *                   o[key] === 'function' || key === '__proto__'`), so the 'constructor' segment is
 *                   caught (return). Both seed and residual are BLOCKED. [negative control]
 *
 * Benign canary (prototype-pollution -> authorization bypass): the harness runs the version's real
 * minimist(argv), then a default-deny gate asks whether an unrelated fresh object `({})` now carries the
 * gate key (`pcbUnlock`) as a TRUTHY INHERITED property -- i.e. whether the parse polluted
 * Object.prototype (GLOBAL pollution). A legitimate parse that sets only own keys on the result NEVER
 * trips the gate; only prototype pollution does. If pollution is detected the gate flips open and
 * releases the planted ${PCB_FLAG}. Success = ${PCB_FLAG} in the response, proving the guard was bypassed.
 *
 * minimist()'s pollution is GLOBAL (it writes Object.prototype), so BEFORE and AFTER every probe the
 * harness deletes the gate key from Object.prototype to keep probes independent (no cross-probe
 * contamination). The gate is read on a fresh `({})` sampled immediately after the minimist() call.
 *
 * Route: GET /probe?spec=<JSON>. `spec` is a JSON-encoded argv array, e.g.
 *   ["--__proto__.pcbUnlock","unlocked"]                      (seed)
 *   ["--constructor.prototype.pcbUnlock.x","unlocked"]        (constructor-path residual)
 */
import http from "node:http";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const VER = process.env.HARNESS_VER || "v1";
const APP_PORT = Number(process.env.APP_PORT || 8080);
const FLAG = process.env.PCB_FLAG || "PCB_FLAG_unset";
const VER_STR = { v0: "1.2.1", v1: "1.2.5", v2: "1.2.6" }[VER] || "?";

// The REAL published `minimist` for this version (npm alias). All 1.x versions export the parser as the
// module default (`module.exports = function (args, opts) {...}`). Only setKey()'s key guard differs
// across versions, which is exactly the boundary under test.
const minimist = require(VER === "v0" ? "minimist-v0" : VER === "v2" ? "minimist-v2" : "minimist-v1");

const GATE_KEY = "pcbUnlock";   // the property the default-deny gate reads
const TRIGGER = "unlocked";     // benign value written into the polluted namespace (NOT the flag)

// ---- default-deny gate: released ONLY if the parse polluted Object.prototype (GLOBAL pollution) ------
// A fresh, unrelated object inherits GATE_KEY (truthy) only if the crafted argv made setKey() write onto
// Object.prototype. A normal parse that sets own keys on its own result object does NOT show up here.
function pollutionDetected() {
  const probe = {};
  return typeof probe[GATE_KEY] !== "undefined" && !!probe[GATE_KEY];
}

// ---- one probe: run the REAL per-version setKey() guard + assignment sink, then read the gate --------
function runProbe(argv) {
  // Defensive pre-clean so a prior probe in this process can never leak into this reading.
  try { delete Object.prototype[GATE_KEY]; } catch (e) { /* ignore */ }
  let parse_error = null;
  try {
    minimist(Array.isArray(argv) ? argv : [String(argv)]);   // <-- per-version setKey() guard + sink
  } catch (e) {
    parse_error = String((e && e.message) || e);
  }
  const polluted = pollutionDetected();
  const gated_secret = polluted ? FLAG : "denied";   // == FLAG iff a prototype write landed
  // Clean up GLOBAL pollution so probes never contaminate each other or the gate reading.
  try { delete Object.prototype[GATE_KEY]; } catch (e) { /* ignore */ }
  return {
    version: VER,
    minimist_version: VER_STR,
    argv,
    polluted,
    parse_error,
    gated_secret,
  };
}

const server = http.createServer((req, res) => {
  const u = new URL(req.url, "http://placeholder");
  if (u.pathname !== "/probe") {
    res.writeHead(200, { "Content-Type": "text/plain" });
    res.end(`minimist faithful-core harness ${VER} (minimist ${VER_STR}) ok`);
    return;
  }
  const raw = u.searchParams.get("spec");
  let spec;
  try {
    spec = JSON.parse(raw);       // JSON-encoded argv array
  } catch (e) {
    spec = raw;                   // fall back to a single plain-string arg
  }
  try {
    const out = runProbe(spec);
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(out));
  } catch (e) {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ version: VER, error: String((e && e.message) || e) }));
  }
});

server.listen(APP_PORT, "0.0.0.0", () => {
  console.log(`[harness ${VER}] minimist ${VER_STR} guard listening on 0.0.0.0:${APP_PORT}`);
});
