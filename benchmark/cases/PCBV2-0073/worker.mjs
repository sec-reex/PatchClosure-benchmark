/**
 * Fresh-process worker: replays ONE multipart body through the REAL @adonisjs/bodyparser
 * BodyParserMiddleware for the selected version, then reports whether Object.prototype was polluted.
 *
 * The version's REAL published bytes are loaded via the npm alias (bp_v0/bp_v1/bp_v2). A minimal
 * ephemeral loopback HTTP server delivers the exact received bytes to the middleware over a genuine
 * request stream (`ctx.request.request`), so the real Multipart parser -> FormFields.add ->
 * lodash.set path executes exactly as it would for an external client. After parsing we read a
 * FRESH empty object's inherited canary `({}).pcbPolluted`; it is defined IFF Object.prototype was
 * polluted by the parse. The parsed body is deliberately NOT reported.
 *
 * Fork isolation: this whole process is short-lived (one probe), so Object.prototype starts clean
 * and any pollution dies with the process -> no leak across probes/versions.
 */
const VER = process.env.HARNESS_VER || "v1";
const CANARY_KEY = "pcbPolluted";

const ALIAS = { v0: "bp_v0", v1: "bp_v1", v2: "bp_v2" }[VER];
if (!ALIAS) { process.send?.({ ok: false, error: `unknown HARNESS_VER ${VER}` }); process.exit(1); }

const { BodyParserMiddlewareFactory } = await import(`${ALIAS}/factories`);
const { RequestFactory, HttpContextFactory } = await import("@adonisjs/http-server/factories");

async function runOnce({ contentType, bodyB64 }) {
  const bytes = Buffer.from(bodyB64, "base64");
  const http = await import("node:http");

  const middleware = new BodyParserMiddlewareFactory().create();
  let innerStatus = null;

  const server = http.createServer(async (req, res) => {
    try {
      const request = new RequestFactory()
        .merge({ req, res, url: req.url, method: req.method })
        .create();
      const ctx = new HttpContextFactory().merge({ request }).create();
      await middleware.handle(ctx, async () => {});
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("parsed");
    } catch (e) {
      res.writeHead(500, { "content-type": "text/plain" });
      res.end("err:" + String(e && e.message || e));
    }
  });

  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const port = server.address().port;

  await new Promise((resolve) => {
    const reqOut = http.request(
      { host: "127.0.0.1", port, method: "POST", path: "/",
        headers: { "content-type": contentType, "content-length": bytes.length } },
      (resp) => { innerStatus = resp.statusCode; resp.on("data", () => {}); resp.on("end", resolve); }
    );
    reqOut.on("error", () => resolve());
    reqOut.end(bytes);
  });

  await new Promise((r) => server.close(r));

  // Fresh empty object: inherits pcbPolluted ONLY if Object.prototype was polluted by the parse.
  const canary = ({})[CANARY_KEY];
  return {
    ok: true,
    object_prototype_polluted: Object.prototype.hasOwnProperty(CANARY_KEY),
    canary_value: canary === undefined ? null : canary,
    inner_http_status: innerStatus,
  };
}

process.on("message", async (msg) => {
  try {
    const result = await runOnce(msg);
    process.send?.(result);
  } catch (e) {
    process.send?.({ ok: false, error: String(e && e.message || e) });
  } finally {
    process.exit(0);
  }
});
