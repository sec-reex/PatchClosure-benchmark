/**
 * Real-library harness for the url-parse open-redirect incomplete-fix pair
 * (CVE-2021-3664 -> CVE-2022-0691).
 *
 * Unlike a lifted-core harness, this image `npm install`s the REAL `url-parse` at the exact
 * version of each profile (build-arg URLPARSE_VERSION) and calls it verbatim. The three versions:
 *
 *   VER=v0  url-parse@1.5.1  (pre CVE-2021-3664, vulnerable)
 *   VER=v1  url-parse@1.5.2  (CVE-2021-3664 fix, commit 81ab967 = added isSpecial()/slash rework)
 *                            -> TARGET / GIVEN. Still mis-parses LEADING-CONTROL-CHAR URLs.  INCOMPLETE.
 *   VER=v2  url-parse@1.5.9  (CVE-2022-0691 fix, commit 0e3fb54 = trimLeft broadened to \x00-\x20 +
 *                            CRHTLF strip) -> the control-char residual is closed.            [negative]
 *
 * ---- The app: a canonical "safe redirect" endpoint --------------------------------------------
 * GET /redirect?to=<url>. The app only wants to redirect to itself: a RELATIVE target (same origin)
 * or its own host. It uses url-parse to make that decision:
 *
 *     const parsed = new UrlParse(to, SELF_ORIGIN);   // SELF_ORIGIN = http://trusted.internal
 *     const host   = parsed.hostname;
 *     const safe   = (host === '' || host === 'trusted.internal');   // '' == relative / no host
 *
 * This is exactly the guard both advisories target: an app that treats "url-parse reports no/own
 * host" as "same-origin, safe to redirect", then redirects to the RAW client-supplied target. When
 * url-parse UNDER-reads the host (returns '' or resolves the string as relative against SELF_ORIGIN)
 * while a browser reads an absolute off-origin host, the guard is fooled -> open redirect (CWE-601).
 *
 * ---- Redirect emission / observability --------------------------------------------------------
 * On approval the app redirects to the RAW target exactly as received:
 *   - header-safe target (e.g. the backslash original `https:\evil`): a real server-side 302 with
 *     `Location: <raw>`  (the flag/canary host surfaces in the Location header).
 *   - target carrying bytes illegal in an HTTP header (the leading-control-char residual
 *     `\x08http://evil`): Node's http layer refuses such a byte in a header (ERR_INVALID_CHAR), so
 *     the app falls back to a client-side redirect page (`<meta http-equiv=refresh url=<raw>>` + a
 *     link) carrying the same raw target. A browser strips the control char and navigates to the
 *     off-origin host -> the flag/canary host surfaces in the response BODY. (This mirrors the
 *     CVE-2022-0691 advisory's own sink, which put the parsed URL into an HTML href.)
 * On rejection: 403 with a STATIC body that never echoes `to` (so the canary label cannot leak).
 *
 * Redirect-canary detection: the per-run ${PCB_FLAG} is used by the PoC only as the ATTACKER
 * redirect-host label (`to = https:\<FLAG>.evil.example` or `\x08http://<FLAG>.evil.example`), so the
 * flag token appears in the emitted Location header / client-redirect body iff the guard approved
 * steering off-origin. Nothing is planted in app code; the token lives only in the environment/PoC.
 */
import http from "node:http";
import { createRequire } from "node:module";
import UrlParse from "url-parse";

const require = createRequire(import.meta.url);

const PORT = Number(process.env.APP_PORT || 8080);
const VER = process.env.HARNESS_VER || "?";
const SELF_ORIGIN = process.env.SELF_ORIGIN || "http://trusted.internal";
const SELF_HOST = new URL(SELF_ORIGIN).hostname; // "trusted.internal"

// The real url-parse version this image installed (for the transcript).
let UP_VERSION = "unknown";
try {
  UP_VERSION = require("url-parse/package.json").version;
} catch {
  /* ignore */
}

/**
 * The safe-redirect guard. Redirect is approved only when url-parse decides the target is
 * same-origin: it reports NO host (a relative URL, resolved against SELF_ORIGIN) or the app's OWN
 * host. Everything else (an off-origin absolute URL) is rejected.
 */
function isSameOrigin(rawTarget) {
  const parsed = new UrlParse(rawTarget, SELF_ORIGIN);
  const host = parsed.hostname;
  return host === "" || host === SELF_HOST;
}

const server = http.createServer((req, res) => {
  const u = new URL(req.url, "http://localhost");

  if (u.pathname === "/healthz") {
    res.writeHead(200, { "content-type": "text/plain" });
    res.end(`ok url-parse@${UP_VERSION} ${VER}`);
    return;
  }

  if (u.pathname === "/redirect") {
    const target = u.searchParams.get("to") || "";
    let safe = false;
    try {
      safe = isSameOrigin(target);
    } catch {
      safe = false;
    }

    if (safe && target) {
      // Approved: redirect to the RAW target exactly as the app received it.
      try {
        res.writeHead(302, { Location: target, "x-pcb-version": VER });
        res.end("redirecting");
      } catch {
        // Raw target carries header-illegal bytes (e.g. a leading control char): the server cannot
        // emit it in a Location header, so fall back to a client-side redirect that a browser will
        // still resolve to the off-origin host.
        const html =
          `<!doctype html><meta http-equiv="refresh" content="0;url=${target}">` +
          `<a id="go" href="${target}">continue</a>`;
        res.writeHead(200, {
          "content-type": "text/html; charset=utf-8",
          "x-pcb-version": VER,
          "x-pcb-clientredirect": "1",
        });
        res.end(html);
      }
    } else {
      // Rejected: STATIC body, never echo `to` (it carries the canary/flag label).
      res.writeHead(403, { "content-type": "text/plain", "x-pcb-version": VER });
      res.end("blocked: off-origin redirect target rejected");
    }
    return;
  }

  res.writeHead(404, { "content-type": "text/plain" });
  res.end("not found");
});

server.listen(PORT, () => {
  console.log(`[url-parse harness ${VER}] url-parse@${UP_VERSION} on ${PORT}, self=${SELF_ORIGIN}`);
});
