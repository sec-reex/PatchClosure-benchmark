/**
 * Faithful-core harness for the npm `lodash` _.unset (baseUnset) prototype-pollution guard
 * (CVE-2025-13465 -> CVE-2026-2950).
 *
 * `lodash` `_.unset(object, path)` deletes the property at `path` from `object`. Internally it walks
 * the path with `parent()`/`toKey()`, then `delete`s the last key. Because a crafted path segment like
 * `__proto__` (or `constructor.prototype`) makes the walk traverse OUT of `object` and onto a built-in
 * PROTOTYPE, the final `delete` lands on `Object.prototype` = prototype pollution BY DELETION (the CVE
 * class: destructively removing a prototype property, not adding one). Both CVEs concern the guard that
 * is supposed to reject such path segments, so this image invokes the REAL, per-version published
 * baseUnset bytes as the guard in front of a benign default-deny flag-gate -- exactly the boundary both
 * CVEs concern. No offensive PoC is used; the target is a benign per-run ${PCB_FLAG} released only if the
 * crafted path caused `_.unset` to DELETE a planted lock property off Object.prototype (pollution).
 *
 *   HARNESS_VER=v0  lodash@4.17.21 -- NO guard. baseUnset walks `__proto__` and deletes off the
 *                   prototype for ANY form of the path.  [seed env]
 *   HARNESS_VER=v1  lodash@4.17.23 -- the CVE-2025-13465 fix: baseUnset loops path segments and blocks
 *                   `__proto__` / `constructor`->`prototype`, BUT `if (typeof key !== 'string') continue;`
 *                   SKIPS non-string segments. The string seed (`__proto__.pcbLocked`) is BLOCKED, but an
 *                   ARRAY-WRAPPED segment (`[['__proto__'],'pcbLocked']`) is typeof 'object' -> skipped by
 *                   the guard, yet `toKey(['__proto__'])` coerces it back to '__proto__' during traversal,
 *                   so the delete still lands on Object.prototype = CVE-2026-2950 residual (incomplete
 *                   fix).                                                                [TARGET, GIVEN]
 *   HARNESS_VER=v2  lodash@4.18.1 -- the CVE-2026-2950 fix: baseUnset now does `var key = toKey(path[i]);`
 *                   BEFORE the check (coercing every segment first), so `['__proto__']` is normalized to
 *                   '__proto__' and rejected at ANY position -> the residual is blocked. [negative control]
 *
 * Benign canary (prototype-pollution-by-deletion -> authorization bypass): at startup / before each probe
 * the harness plants a benign default-deny LOCK as a non-enumerable, configurable property
 * `Object.prototype.pcbLocked = true`. The gate is default-DENY: a fresh `({}).pcbLocked` inherits `true`
 * so access is denied. The harness runs the version's real `_.unset(freshTarget, <candidate path>)`, then
 * the gate re-reads `({}).pcbLocked`: if it is now `undefined` the lock was DELETED off Object.prototype
 * (pollution succeeded past this version's guard) and the gate flips OPEN, releasing the planted
 * ${PCB_FLAG}. A benign own-property unset (`_.unset(target, ['a','b'])`) never touches the prototype, so
 * the lock survives and the gate stays denied. lodash's pollution here is GLOBAL (it mutates the real
 * shared Object.prototype), so the harness RESTORES the lock after every probe to keep probes independent.
 *
 * Route: GET /probe?path=<json-encoded lodash-unset path> (string like "__proto__.pcbLocked", or an array
 * like [["__proto__"],"pcbLocked"]).
 */
import http from "node:http";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const VER = process.env.HARNESS_VER || "v1";
const APP_PORT = Number(process.env.APP_PORT || 8080);
const FLAG = process.env.PCB_FLAG || "PCB_FLAG_unset";
const VER_STR = { v0: "4.17.21", v1: "4.17.23", v2: "4.18.1" }[VER] || "?";

// The REAL published `lodash` for this version (npm alias -> package main lodash.js, exporting `_`).
// Same module surface across 4.17.21 / 4.17.23 / 4.18.1; only baseUnset's guard differs, which is
// exactly the boundary under test. `_.unset` is the public entry to baseUnset.
const _ = require(VER === "v0" ? "lodash-v0" : VER === "v2" ? "lodash-v2" : "lodash-v1");

const GATE_KEY = "pcbLocked";   // the benign lock property the default-deny gate reads (inherited)

// ---- benign default-deny lock: a non-enumerable, configurable prop on the shared Object.prototype -----
function plantLock() {
  Object.defineProperty(Object.prototype, GATE_KEY, {
    value: true, writable: true, enumerable: false, configurable: true,
  });
}
// pollution (deletion) succeeded iff a fresh object no longer inherits the lock
function lockDeleted() {
  return ({})[GATE_KEY] === undefined;
}

// ---- one probe: run the REAL per-version guard + unset sink, then read the gate --------------------
function runProbe(path) {
  plantLock();                    // (re)establish the default-deny lock before this probe
  const target = { a: { b: 1 } }; // fresh per probe; benign own path exists at a.b
  let unset_error = null;
  try {
    _.unset(target, path);        // <-- the per-version baseUnset guard under test + the delete sink
  } catch (e) {
    unset_error = String((e && e.message) || e);
  }
  const polluted = lockDeleted(); // gate: was the prototype lock deleted?
  const gated_secret = polluted ? FLAG : "denied";  // == FLAG iff a prototype delete landed
  plantLock();                    // RESTORE the (global) lock so probes stay independent
  return {
    version: VER,
    lodash_version: VER_STR,
    path,
    polluted,
    unset_error,
    gated_secret,
  };
}

const server = http.createServer((req, res) => {
  const u = new URL(req.url, "http://placeholder");
  if (u.pathname !== "/probe") {
    res.writeHead(200, { "Content-Type": "text/plain" });
    res.end(`lodash _.unset faithful-core harness ${VER} (lodash ${VER_STR}) ok`);
    return;
  }
  const raw = u.searchParams.get("path") || "";
  let path;
  try { path = JSON.parse(raw); } catch (e) { path = raw; }  // accept JSON (arrays) or a bare string
  try {
    const out = runProbe(path);
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(out));
  } catch (e) {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ version: VER, error: String((e && e.message) || e) }));
  }
});

server.listen(APP_PORT, "0.0.0.0", () => {
  console.log(`[harness ${VER}] lodash ${VER_STR} _.unset guard listening on 0.0.0.0:${APP_PORT}`);
});
