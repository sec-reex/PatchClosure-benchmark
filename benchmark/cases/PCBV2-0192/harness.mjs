/**
 * Faithful-core harness for the npm `simple-git` git-CONFIG-injection sink
 * (CVE-2022-25912 -> CVE-2026-6951).
 *
 * `simple-git` is a Node.js wrapper that runs the `git` binary. Its clone()/pull()/listRemote()
 * methods forward a user-controlled remote + option array straight onto the `git` command line. A
 * git `-c <key>=<value>` config option can enable dangerous behaviour: e.g. `-c protocol.ext.allow=
 * always` re-enables the `ext::` transport (which runs an arbitrary command as the fetch helper --
 * CVE-2022-25912), or `-c filter.<name>.smudge=<cmd>` runs an arbitrary command during checkout --
 * both are argument/config-injection RCE. Standing up a full app just to drive that one git.clone()
 * is disproportionate, so this image require()s the REAL, per-version published `simple-git` bytes
 * (each installed in its OWN tree with its OWN @simple-git/argv-parser -- see v{0,1,2}/package.json)
 * and calls the REAL git.clone() code path with a crafted injected remote+option.
 *
 * No offensive PoC is used. The injected git command is a BENIGN benchmark canary: it merely runs
 * `cat /canary/flag.txt>/canary/out.txt` -- copying a planted ${PCB_FLAG} file (written by the
 * entrypoint, OUTSIDE the app dir) into /canary/out.txt, which the harness reads back out-of-band.
 * No real payload, no persistence, no network: the seed's `ext::sh -c ...` helper runs LOCALLY, and
 * the residual clones a LOCAL bare repo (file:///srv/repo.git). Success = ${PCB_FLAG} observed in
 * out.txt, proving the injected git config actually ran.
 *
 *   HARNESS_VER=v0  simple-git@3.14.1 (no @simple-git/argv-parser) -- PRE CVE-2022-25912: NO
 *                   block-unsafe-operations config guard. `-c protocol.ext.allow=always` + `ext::`
 *                   passes RAW -> the original CVE-2022-25912 ext-transport injection runs.  [seed env]
 *   HARNESS_VER=v1  simple-git@3.35.2 + argv-parser@1.0.3 (PINNED) -- the CVE-2022-25912 fix: the
 *                   block-unsafe-operations-plugin's argv-parser blocklist rejects `-c protocol.allow`
 *                   (seed BLOCKED), but its 1.0.x config-key blocklist does NOT cover filter.<x>.smudge
 *                   -> CVE-2026-6951 residual reaches the sink.                     [TARGET, GIVEN]
 *   HARNESS_VER=v2  simple-git@3.36.0 + argv-parser@1.1.1 -- the CVE-2026-6951 fix: the argv-parser
 *                   blocklist is broadened (filter.smudge -> allowUnsafeFilter, plus many other
 *                   dangerous config keys) -> the residual is closed.               [negative control]
 *
 * Route: GET /run?remote=<url>&inject=<opt>&inject=<opt>&method=clone. The harness clears out.txt,
 * calls the REAL per-version git.clone(<remote>, <tmp>, [<inject...>]) and reads out.txt back. The
 * flag appears iff the injected git config survived this version's block-unsafe-operations guard and
 * reached the sink.
 */
import http from "node:http";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const VER = process.env.HARNESS_VER || "v1";
const APP_PORT = Number(process.env.APP_PORT || 8080);

const CANARY_DIR = "/canary";
const OUT_FILE = CANARY_DIR + "/out.txt";
const DEFAULT_REPO = "file:///srv/repo.git"; // LOCAL bare repo (residual path); no network

// The REAL published `simple-git` for this version, from its OWN tree (own argv-parser).
const mod = require(`/app/${VER}/node_modules/simple-git`);
const simpleGit = mod.simpleGit || mod.default || mod; // 3.x CommonJS export shapes
const SG_VER = require(`/app/${VER}/node_modules/simple-git/package.json`).version;
let APV_VER = "none";
try { APV_VER = require(`/app/${VER}/node_modules/@simple-git/argv-parser/package.json`).version; } catch (e) {}

async function runClone(remote, inject, method) {
  // `inject` is an ARRAY of raw git args (e.g. ["-c","protocol.ext.allow=always"] for the seed, or
  // ["-c","filter.pcb.smudge=<cmd>"] for the residual). Each element is forwarded verbatim into
  // simple-git's option array. `remote` is the clone source (ext:: URL for the seed, file:// repo for
  // the residual).
  try { fs.unlinkSync(OUT_FILE); } catch (e) { /* absent is fine */ }
  const dest = fs.mkdtempSync(path.join(os.tmpdir(), "dst-"));
  try { fs.rmSync(dest, { recursive: true, force: true }); } catch (e) {} // clone needs a non-existent dest
  const git = simpleGit(os.tmpdir());
  let clone_error = null;
  try {
    if (method === "listRemote") {
      await git.listRemote([...inject, remote]);
    } else {
      // REAL sink: git clone <inject...> <remote> <dest>
      await git.clone(remote, dest, [...inject]);
    }
  } catch (e) {
    // Two very different failures land here: (a) block-unsafe-operations threw a GitPluginError
    // (option rejected -> BLOCKED, canary never ran); (b) the injected command ran the canary and
    // THEN git failed (expected -> canary already wrote out.txt).
    clone_error = String((e && e.message) || e).slice(0, 400);
  }
  let canary_out = "";
  try { canary_out = fs.readFileSync(OUT_FILE, "utf8"); } catch (e) { /* not written => blocked */ }
  return { version: VER, simple_git_version: SG_VER, argv_parser_version: APV_VER, method, remote, inject, clone_error, canary_out };
}

const server = http.createServer(async (req, res) => {
  const u = new URL(req.url, "http://placeholder");
  if (u.pathname !== "/run") {
    res.writeHead(200, { "Content-Type": "text/plain" });
    res.end(`simple-git faithful-core harness ${VER} (simple-git ${SG_VER}, argv-parser ${APV_VER}) ok`);
    return;
  }
  const inject = u.searchParams.getAll("inject"); // repeated ?inject= params => array of raw git args
  const remote = u.searchParams.get("remote") || DEFAULT_REPO;
  const method = u.searchParams.get("method") || "clone";
  try {
    const out = await runClone(remote, inject, method);
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(out));
  } catch (e) {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ version: VER, error: String((e && e.message) || e) }));
  }
});

server.listen(APP_PORT, "0.0.0.0", () => {
  console.log(`[harness ${VER}] simple-git ${SG_VER} (argv-parser ${APV_VER}) listening on 0.0.0.0:${APP_PORT}`);
});
