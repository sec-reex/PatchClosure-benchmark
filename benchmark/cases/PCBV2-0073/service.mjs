/**
 * Real-library-wrap HTTP service for @adonisjs/bodyparser FormFields prototype pollution.
 * Pair: CVE-2026-25754 (V1 = incomplete-fix TARGET) -> CVE-2026-48795 (V2 = complete fix).
 *
 * The three profiles run the EXACT published npm bytes of @adonisjs/bodyparser, installed
 * side-by-side via npm aliases (see package.json) and selected by HARNESS_VER:
 *   V0 = bp_v0 -> @adonisjs/bodyparser@10.1.2  (FormFields #fields = {} plain object; unprotected)
 *   V1 = bp_v1 -> @adonisjs/bodyparser@10.1.4  (CVE-2026-25754 fix: #fields = Object.create(null);
 *                                               blocks a DIRECT __proto__ segment, but a NESTED
 *                                               user.__proto__.x still reaches Object.prototype) TARGET
 *   V2 = bp_v2 -> @adonisjs/bodyparser@10.1.5  (CVE-2026-48795 fix: FormFields.add() rejects any key
 *                                               whose lodash.toPath() contains __proto__/prototype/
 *                                               constructor)                                 negative
 *
 * SINK: BodyParserMiddleware -> Multipart.process() -> #handleField(key,value) ->
 *       FormFields.add(key,value) -> lodash.set(#fields, key, value). A multipart field NAME is used
 *       as a lodash path, so `user.__proto__.pcbPolluted` walks into Object.prototype.
 *
 * The external trigger is a REAL `multipart/form-data` POST. Because prototype pollution is
 * process-global and persistent, EACH probe is served in a FRESH forked worker (worker.mjs) so no
 * pollution leaks across probes or across versions. The worker replays the exact received body bytes
 * through the REAL middleware and reports ONLY `({}).pcbPolluted` (a fresh empty object's inherited
 * canary) -- it never echoes the parsed body, so the flag surfaces IFF Object.prototype was polluted.
 */
import http from "node:http";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { fork } from "node:child_process";

const VER = process.env.HARNESS_VER || "v1";
const APP_PORT = Number(process.env.APP_PORT || 8080);
const HERE = dirname(fileURLToPath(import.meta.url));
const WORKER = join(HERE, "worker.mjs");

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

// Fork a fresh worker to parse ONE body through the real middleware in an isolated process.
function probeInFreshProcess({ contentType, bodyB64 }) {
  return new Promise((resolve) => {
    const child = fork(WORKER, [], {
      env: { ...process.env, HARNESS_VER: VER },
      stdio: ["ignore", "ignore", "inherit", "ipc"],
    });
    let done = false;
    const finish = (r) => { if (!done) { done = true; try { child.kill(); } catch {} resolve(r); } };
    child.on("message", (m) => finish(m));
    child.on("error", (e) => finish({ ok: false, error: String(e) }));
    child.on("exit", (code) => finish({ ok: false, error: `worker exited ${code} without result` }));
    child.send({ contentType, bodyB64 });
    setTimeout(() => finish({ ok: false, error: "worker timeout" }), 15000);
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, "http://localhost");
  if (url.pathname === "/healthz") {
    res.writeHead(200, { "content-type": "text/plain" });
    res.end("ok");
    return;
  }
  if (req.method === "POST" && url.pathname === "/probe") {
    const body = await readBody(req);
    const contentType = req.headers["content-type"] || "";
    const result = await probeInFreshProcess({ contentType, bodyB64: body.toString("base64") });
    // Response reflects ONLY the fresh-object canary observation; the parsed body is never echoed.
    res.writeHead(200, { "content-type": "application/json", "x-pcb-version": VER });
    res.end(JSON.stringify({
      version: VER,
      object_prototype_polluted: result.object_prototype_polluted === true,
      canary_value: result.canary_value ?? null,
      inner_http_status: result.inner_http_status ?? null,
      worker_ok: result.ok !== false,
      worker_error: result.error ?? null,
    }));
    return;
  }
  res.writeHead(404, { "content-type": "text/plain" });
  res.end("not found");
});

server.listen(APP_PORT, "0.0.0.0", () => {
  console.log(`[bodyparser-service ${VER}] listening on ${APP_PORT}`);
});
