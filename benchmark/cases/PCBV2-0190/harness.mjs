/**
 * Faithful-core harness for the npm `set-value` prototype-pollution guard
 * (CVE-2019-10747 -> CVE-2021-23440).
 *
 * `set-value` does nested set-by-path: `setValue(obj, "a.b.c", v)` splits the path, walks/creates the
 * intermediate objects and assigns `obj.a.b.c = v`. Because the walk dereferences each key with
 * `obj[key]` (creating a namespace when absent), a crafted key like `__proto__` makes the walk step
 * onto `Object.prototype` and the final assignment land on it = GLOBAL prototype pollution. Both CVEs
 * concern the guard that is supposed to reject such keys, so this image invokes the REAL, per-version
 * published set-value bytes as the guard in front of a benign default-deny flag-gate -- exactly the
 * boundary both CVEs concern. No offensive PoC is used; the target is a benign per-run ${PCB_FLAG}
 * released only if the crafted key caused set-value to pollute a prototype (i.e. the guard was bypassed).
 *
 *   HARNESS_VER=v0  set-value@3.0.0 -- NO prototype-pollution guard. The string seed
 *                   `__proto__.pcbUnlock` (first segment) already pollutes Object.prototype.  [seed env]
 *   HARNESS_VER=v1  set-value@4.0.0 -- carries the CVE-2019-10747 guard: `isUnsafeKey(key) =
 *                   key === '__proto__' || key === 'constructor' || key === 'prototype'`, and
 *                   `validateKey` THROWS when isUnsafeKey. The string seed is now BLOCKED (throws), but
 *                   the check is a strict `===` against a STRING, so a NON-string key of the same name
 *                   (an array element `['__proto__']`) is `!== '__proto__'` and slips past the guard,
 *                   while the property accessor `obj[key]` coerces it back to `'__proto__'` and still
 *                   pollutes = CVE-2021-23440 type-confusion residual (incomplete fix).  [TARGET, GIVEN]
 *   HARNESS_VER=v2  set-value@4.0.1 -- the CVE-2021-23440 fix: `validateKey` now coerces
 *                   `key = String(key)` for non-string/non-number keys BEFORE the isUnsafeKey check, so
 *                   the array key `['__proto__']` becomes `'__proto__'` and is rejected. [negative control]
 *
 * Benign canary (prototype-pollution -> authorization bypass): the harness runs the version's real
 * setValue(target, <candidate path>, TRIGGER) on a FRESH `target`, then a default-deny gate asks whether
 * an unrelated fresh object `({})` now carries the gate key (`pcbUnlock`) as an INHERITED property
 * === TRIGGER -- i.e. whether the write polluted Object.prototype (GLOBAL pollution). A legitimate
 * own-property write (`a.b.pcbUnlock=TRIGGER`) lands as an OWN data slot on `target` and NEVER trips the
 * gate; only prototype pollution does. If pollution is detected the gate flips open and releases the
 * planted ${PCB_FLAG}. Success = ${PCB_FLAG} in the response, proving the guard was bypassed.
 *
 * set-value's pollution is GLOBAL (it steps onto and writes Object.prototype), so after EVERY probe the
 * harness deletes the gate key from Object.prototype to keep probes independent (no cross-probe
 * contamination). The gate is read on a fresh `({})` sampled immediately after the set() call.
 *
 * Route: GET /probe?spec=<JSON>. `spec` is a JSON-encoded set-value path: a STRING (`"__proto__.pcbUnlock"`)
 * or an ARRAY of segments where a segment may itself be an array (`[["__proto__"],"pcbUnlock"]`).
 */
import http from "node:http";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const VER = process.env.HARNESS_VER || "v1";
const APP_PORT = Number(process.env.APP_PORT || 8080);
const FLAG = process.env.PCB_FLAG || "PCB_FLAG_unset";
const VER_STR = { v0: "3.0.0", v1: "4.0.0", v2: "4.0.1" }[VER] || "?";

// The REAL published `set-value` for this version (npm alias -> package main index.js, exporting the
// setValue function). Same module surface across 3.0.0 / 4.0.0 / 4.0.1; only the prototype-pollution
// guard differs, which is exactly the boundary under test.
const setValue = require(VER === "v0" ? "set-value-v0" : VER === "v2" ? "set-value-v2" : "set-value-v1");

const GATE_KEY = "pcbUnlock";   // the property the default-deny gate reads
const TRIGGER = "unlocked";     // the benign value set-value writes (NOT the flag)

// ---- default-deny gate: released ONLY if set() polluted Object.prototype (GLOBAL pollution) ---------
// A fresh, unrelated object inherits GATE_KEY === TRIGGER only if the crafted key made the write land on
// Object.prototype. A benign own-property write (target.a.b.pcbUnlock = TRIGGER) is an OWN slot on
// `target` and does NOT show up on a fresh object -> not counted.
function pollutionDetected() {
  const probe = {};
  return probe[GATE_KEY] === TRIGGER;
}

// ---- one probe: run the REAL per-version guard + assignment sink, then read the gate ---------------
function runProbe(spec) {
  const target = {};             // fresh per probe
  let set_error = null;
  try {
    setValue(target, spec, TRIGGER);   // <-- the per-version guard under test + the assignment sink
  } catch (e) {
    set_error = String((e && e.message) || e);
  }
  const polluted = pollutionDetected();
  const gated_secret = polluted ? FLAG : "denied";   // == FLAG iff a prototype write landed
  // Clean up GLOBAL pollution so probes never contaminate each other or the gate reading.
  try { delete Object.prototype[GATE_KEY]; } catch (e) { /* ignore */ }
  return {
    version: VER,
    set_value_version: VER_STR,
    spec,
    polluted,
    set_error,
    gated_secret,
  };
}

const server = http.createServer((req, res) => {
  const u = new URL(req.url, "http://placeholder");
  if (u.pathname !== "/probe") {
    res.writeHead(200, { "Content-Type": "text/plain" });
    res.end(`set-value faithful-core harness ${VER} (set-value ${VER_STR}) ok`);
    return;
  }
  const raw = u.searchParams.get("spec");
  let spec;
  try {
    spec = JSON.parse(raw);       // string path, or array path (segments may themselves be arrays)
  } catch (e) {
    spec = raw;                   // fall back to a plain string path
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
  console.log(`[harness ${VER}] set-value ${VER_STR} guard listening on 0.0.0.0:${APP_PORT}`);
});
