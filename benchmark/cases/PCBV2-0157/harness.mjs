/**
 * Faithful-core harness for the npm `object-path` deep-set prototype-pollution guard
 * (pre-guard 0.11.4 -> string-only `=== '__proto__'` guard 0.11.5 [CVE-2020-15256 fix] ->
 *  type-coercion 0.11.6 [CVE-2021-23434 fix]).
 *
 * `objectPath.withInheritedProps.set(obj, path, value)` does nested set-by-path: its `set()` walks
 * `path`, dereferencing each segment via `getShallowProperty(obj, currentPath)` (which, for the
 * `withInheritedProps` instance, returns inherited props too) and recurses into `obj[currentPath]`.
 * Because the walk dereferences each key, a crafted `__proto__` segment makes the walk step onto
 * `Object.prototype` and the leaf assignment land on it = GLOBAL prototype pollution. The boundary
 * under test is the `set()` magic-property guard, so this image invokes the REAL, per-version
 * published `set()` as the guard in front of a benign default-deny flag-gate -- exactly the boundary
 * CVE-2021-23434 concerns. No offensive PoC is used; the target is a benign per-run ${PCB_FLAG}
 * released only if the crafted key caused set() to pollute a prototype (guard bypassed).
 *
 * The CVE requires the `withInheritedProps` instance (options.includeInheritedProps = true) -- the
 * `__proto__` guard is gated on that flag, and only that instance dereferences inherited props during
 * the walk. The default `objectPath` instance does not pollute here.
 *
 *   HARNESS_VER=v0  object-path@0.11.4 -- NO `__proto__` guard in set() (pre-CVE-2020-15256). The plain
 *                   string seed path `["__proto__","pcbUnlock"]` steps onto Object.prototype and writes
 *                   `pcbUnlock` onto it.                                                       [seed env]
 *   HARNESS_VER=v1  object-path@0.11.5 -- carries the string-comparison guard
 *                   `if (options.includeInheritedProps && (currentPath === '__proto__' || ...)) throw`.
 *                   This is the CVE-2020-15256 fixed release; it blocks the STRING seed (throw), but the
 *                   check is a strict `===` against a STRING, so a NON-string key of the same name (an
 *                   array element `["__proto__"]`) is `!== '__proto__'` and slips past, while
 *                   `obj[currentPath]` coerces it back to `"__proto__"` and still pollutes =
 *                   CVE-2021-23434 residual (incomplete fix).                            [TARGET, GIVEN]
 *   HARNESS_VER=v2  object-path@0.11.6 -- the CVE-2021-23434 fix: coerces
 *                   `if (typeof currentPath !== 'string' && typeof currentPath !== 'number')
 *                    currentPath = String(currentPath)` BEFORE the guard, so the array key
 *                   `["__proto__"]` becomes `"__proto__"` and is caught (throw). [negative control]
 *
 * Benign canary (prototype-pollution -> authorization bypass): the harness runs the version's real
 * set(target, <candidate keys>, TRIGGER) on a FRESH `target`, then a default-deny gate asks whether an
 * unrelated fresh object `({})` now carries the gate key (`pcbUnlock`) as an INHERITED property ===
 * TRIGGER -- i.e. whether the write polluted Object.prototype (GLOBAL pollution). A legitimate
 * own-property write never trips the gate; only prototype pollution does. If pollution is detected the
 * gate flips open and releases the planted ${PCB_FLAG}. Success = ${PCB_FLAG} in the response.
 *
 * set()'s pollution is GLOBAL, so after EVERY probe the harness deletes the gate key from
 * Object.prototype to keep probes independent (no cross-probe contamination). The gate is read on a
 * fresh `({})` sampled immediately after the set() call.
 *
 * Route: GET /probe?spec=<JSON>. `spec` is a JSON-encoded set() key path: a STRING
 * (`"__proto__.pcbUnlock"`), an ARRAY of string segments (`["__proto__","pcbUnlock"]`), or an ARRAY
 * where a segment is itself an array (`[["__proto__"],"pcbUnlock"]` -- the non-string / type-confusion
 * residual).
 */
import http from "node:http";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const VER = process.env.HARNESS_VER || "v1";
const APP_PORT = Number(process.env.APP_PORT || 8080);
const FLAG = process.env.PCB_FLAG || "PCB_FLAG_unset";
const VER_STR = { v0: "0.11.4", v1: "0.11.5", v2: "0.11.6" }[VER] || "?";

// The REAL published `object-path` for this version (npm alias). All versions export an object with a
// `withInheritedProps` instance (options.includeInheritedProps = true). The CVE requires that instance:
// its set() dereferences inherited props during the walk AND the __proto__ guard is gated on that flag.
const _mod = require(VER === "v0" ? "object-path-v0" : VER === "v2" ? "object-path-v2" : "object-path-v1");
const objectPath = _mod.withInheritedProps;

const GATE_KEY = "pcbUnlock";   // the property the default-deny gate reads
const TRIGGER = "unlocked";     // the benign value set() writes (NOT the flag)

// ---- default-deny gate: released ONLY if set() polluted Object.prototype (GLOBAL pollution) --------
function pollutionDetected() {
  const probe = {};
  return probe[GATE_KEY] === TRIGGER;
}

// ---- one probe: run the REAL per-version guard + assignment sink, then read the gate ---------------
function runProbe(spec) {
  const target = {};             // fresh per probe
  let set_error = null;
  try {
    objectPath.set(target, spec, TRIGGER);   // <-- per-version set() magic-property guard + assignment sink
  } catch (e) {
    set_error = String((e && e.message) || e);
  }
  const polluted = pollutionDetected();
  const gated_secret = polluted ? FLAG : "denied";   // == FLAG iff a prototype write landed
  // Clean up GLOBAL pollution so probes never contaminate each other or the gate reading.
  try { delete Object.prototype[GATE_KEY]; } catch (e) { /* ignore */ }
  return {
    version: VER,
    object_path_version: VER_STR,
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
    res.end(`object-path faithful-core harness ${VER} (object-path ${VER_STR}) ok`);
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
  console.log(`[harness ${VER}] object-path ${VER_STR} guard listening on 0.0.0.0:${APP_PORT}`);
});
