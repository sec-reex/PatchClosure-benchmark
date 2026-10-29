/**
 * Faithful-core harness for the npm `dottie` Dottie.set prototype-pollution guard
 * (CVE-2023-26132 -> CVE-2026-27837).
 *
 * `dottie` does dot-notation nested get/set: `dottie.set(obj, "a.b.c", v)` walks/creates the path and
 * assigns `obj.a.b.c = v`. Because the walk creates a namespace for any key that is not an OWN property
 * of the current node, a crafted key like `__proto__` makes the assignment land on an object's
 * PROTOTYPE instead of an own slot = prototype pollution. Both CVEs concern the guard that is supposed
 * to reject such keys, so this image invokes the REAL, per-version published Dottie.set bytes as the
 * guard in front of a benign default-deny flag-gate -- exactly the boundary both CVEs concern. No
 * offensive PoC is used; the target is a benign per-run ${PCB_FLAG} released only if the crafted key
 * caused Dottie.set to write onto a prototype (i.e. pollution succeeded past this version's guard).
 *
 *   HARNESS_VER=v0  dottie@2.0.3 -- NO guard. `__proto__.<key>` (first segment) already pollutes.  [seed env]
 *   HARNESS_VER=v1  dottie@2.0.4 -- the CVE-2023-26132 fix: `if (pieces[0] === '__proto__') return;`.
 *                   Only the FIRST path segment is checked, and only for `__proto__`. The seed
 *                   (`__proto__.<key>`) is now BLOCKED, but `__proto__` at a NON-first position
 *                   (`x.__proto__.<key>`) slips past pieces[0] and still pollutes = CVE-2026-27837
 *                   residual (the incomplete fix).                                    [TARGET, GIVEN]
 *   HARNESS_VER=v2  dottie@2.0.7 -- the CVE-2026-27837 fix: `DANGEROUS_KEYS=['__proto__','constructor',
 *                   'prototype']; pieces.some(p => DANGEROUS_KEYS.indexOf(p) !== -1)` rejects the
 *                   dangerous key at ANY position -> the residual is blocked.       [negative control]
 *
 * Benign canary (prototype-pollution -> authorization bypass): the harness runs the version's real
 * Dottie.set(target, <candidate path>, TRIGGER) on a fresh `target`, then a default-deny gate walks the
 * objects Dottie.set touched and asks whether the gate key (`pcbUnlock`) shows up as an INHERITED
 * (non-own) property === TRIGGER on any of them -- i.e. whether the write landed on a PROTOTYPE
 * (pollution) rather than a normal own nested slot (benign). A legitimate own-property write
 * (`a.b.pcbUnlock=TRIGGER`) is stored as own data and NEVER trips the gate; only prototype pollution
 * does. If pollution is detected the gate flips open and releases the planted ${PCB_FLAG}. Success =
 * ${PCB_FLAG} in the response, proving the guard was bypassed. dottie's pollution is LOCAL (it replaces
 * an object's own [[Prototype]] with a fresh object, per the CVE-2026-27837 advisory note that it does
 * not touch the global Object.prototype), so the gate observes the touched objects, not a global fresh
 * object. Every probe uses a fresh `target`, so probes never contaminate each other.
 *
 * Route: GET /probe?path=<dottieSetPath>.
 */
import http from "node:http";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const VER = process.env.HARNESS_VER || "v1";
const APP_PORT = Number(process.env.APP_PORT || 8080);
const FLAG = process.env.PCB_FLAG || "PCB_FLAG_unset";
const VER_STR = { v0: "2.0.3", v1: "2.0.4", v2: "2.0.7" }[VER] || "?";

// The REAL published `dottie` for this version (npm alias -> package main dottie.js, which exports the
// Dottie object with `.set`). Same module surface across 2.0.3 / 2.0.4 / 2.0.7; only Dottie.set's guard
// differs, which is exactly the boundary under test.
const dottie = require(VER === "v0" ? "dottie-v0" : VER === "v2" ? "dottie-v2" : "dottie-v1");

const GATE_KEY = "pcbUnlock";   // the property the default-deny gate reads
const TRIGGER = "unlocked";     // the benign value Dottie.set writes (NOT the flag)

// ---- default-deny gate: released ONLY if Dottie.set wrote GATE_KEY onto a PROTOTYPE (pollution) -----
// Walk the objects reachable through OWN enumerable keys from `root`; pollution = some touched node
// carries GATE_KEY as an INHERITED (non-own) property === TRIGGER (the write landed on a prototype).
// A benign own-property write (target.a.b.pcbUnlock = TRIGGER) is an OWN slot and is NOT counted.
function pollutionDetected(root) {
  const seen = new Set();
  const stack = [root];
  while (stack.length) {
    const o = stack.pop();
    if (o === null || typeof o !== "object" || seen.has(o)) continue;
    seen.add(o);
    const own = Object.prototype.hasOwnProperty.call(o, GATE_KEY);
    if (!own && o[GATE_KEY] === TRIGGER) return true;   // inherited via a polluted prototype
    for (const k of Object.keys(o)) {
      try { if (o[k] && typeof o[k] === "object") stack.push(o[k]); } catch (e) { /* getter throw */ }
    }
  }
  return false;
}

// ---- one probe: run the REAL per-version guard + assignment sink, then read the gate ---------------
function runProbe(path) {
  const target = {};             // fresh per probe; no cross-probe contamination
  let set_error = null;
  try {
    dottie.set(target, path, TRIGGER);   // <-- the per-version guard under test + the assignment sink
  } catch (e) {
    set_error = String((e && e.message) || e);
  }
  const polluted = pollutionDetected(target);
  const gated_secret = polluted ? FLAG : "denied";   // == FLAG iff a prototype write landed
  return {
    version: VER,
    dottie_version: VER_STR,
    path,
    polluted,
    set_error,
    gated_secret,
  };
}

const server = http.createServer((req, res) => {
  const u = new URL(req.url, "http://placeholder");
  if (u.pathname !== "/probe") {
    res.writeHead(200, { "Content-Type": "text/plain" });
    res.end(`dottie Dottie.set faithful-core harness ${VER} (dottie ${VER_STR}) ok`);
    return;
  }
  const path = u.searchParams.get("path") || "";
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
  console.log(`[harness ${VER}] dottie ${VER_STR} Dottie.set guard listening on 0.0.0.0:${APP_PORT}`);
});
