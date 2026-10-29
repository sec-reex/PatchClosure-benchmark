/**
 * Faithful-core harness for the npm `shell-quote` quote() OS-command-injection sink
 * (pre-CVE-2021-42740 1.7.2 -> CVE-2021-42740 fix 1.7.3 -> CVE-2026-9277 fix 1.8.4).
 *
 * `shellQuote.quote(tokens)` is supposed to return a string in which every token is a SINGLE, inert
 * shell literal -- i.e. no token can inject shell syntax. The security boundary under test is exactly
 * quote()'s per-token metacharacter neutralization. This image drives the REAL, per-version published
 * quote() as that boundary: the app builds `echo ok <quote(tokens)>` and runs it via
 * child_process.exec (== /bin/sh -c ...). If quote() fails to neutralize a metacharacter in an
 * attacker-controlled token, an injected command executes and reads the planted ${PCB_FLAG}. No real
 * payload: the injected command merely runs a benign planted flag-reader (`cat /canary/flag.txt`).
 *
 *   HARNESS_VER=v0  shell-quote@1.7.2 -- quote()'s string else-branch uses
 *                   `String(s).replace(/([A-z]:)?([#!"$&'()*,:;<=>?@\[\\\]^`{|}])/g, '$1\\$2')`.
 *                   The `[A-z]` char class of the drive-letter prefix group ALSO matches the 6 ASCII
 *                   chars between 'Z'(90) and 'a'(97): [ \ ] ^ _ and BACKTICK(96). So a token
 *                   `` `:;rf`:; `` matches group1 as `` `: `` and the backticks are re-emitted UNESCAPED
 *                   via `$1` -> `echo` runs a command substitution -> injection.        [pre-CVE seed env]
 *   HARNESS_VER=v1  shell-quote@1.7.3 -- CVE-2021-42740 fix: group1 char class tightened `[A-z]`->
 *                   `[A-Za-z]`, so the backtick is no longer swallowed by the drive-letter prefix and is
 *                   escaped by group2. The backtick seed is BLOCKED. BUT the SAME quote() still escapes
 *                   OBJECT op-tokens with `s.op.replace(/(.)/g, '\\$1')`, and JS `.` does NOT match line
 *                   terminators, so a NEWLINE in `{op: ';\n<cmd>'}` passes through UNESCAPED and acts as a
 *                   POSIX command separator -> injection = CVE-2026-9277 residual.        [TARGET, GIVEN]
 *   HARNESS_VER=v2  shell-quote@1.8.4 -- CVE-2026-9277 fix: op tokens are validated against an allowlist
 *                   (OPS) and line-terminators are rejected with a TypeError, so `{op: ';\n<cmd>'}`
 *                   THROWS before any command is built. Both seed and residual BLOCKED. [negative control]
 *
 * Benign canary (OS command injection -> flag read): the harness plants ${PCB_FLAG} in /canary/flag.txt
 * and two benign no-argument flag-reader scripts that `cat /canary/flag.txt`:
 *   - /canary/rf                 (absolute path; used by the newline residual: `{op:';\n/canary/rf'}`)
 *   - /usr/local/bin/`:;rf`      (PATH command literally named ":;rf"; used by the backtick seed, whose
 *                                 `[A-z]:` bypass yields the colon-glued command-substitution word `:;rf`)
 * If the crafted token's metacharacter survives quote(), /bin/sh executes the planted reader and the flag
 * appears in the command output. A legitimate token (plain string, or an allowlisted op like {op:'&&'})
 * is fully neutralized and the flag never appears.
 *
 * Route: GET /probe?tokens=<JSON>. `tokens` is a JSON array of shell-quote tokens: strings and/or
 * objects (`{op:"..."}`). The harness runs `echo ok <quote(tokens)>` under /bin/sh and returns the
 * combined stdout+stderr as `output`.
 */
import http from "node:http";
import { execSync } from "node:child_process";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const VER = process.env.HARNESS_VER || "v1";
const APP_PORT = Number(process.env.APP_PORT || 8080);
const FLAG = process.env.PCB_FLAG || "PCB_FLAG_unset";
const VER_STR = { v0: "1.7.2", v1: "1.7.3", v2: "1.8.4" }[VER] || "?";

// The REAL published `shell-quote` for this version (npm alias). Only quote()'s per-token escaping
// differs across versions -- exactly the boundary under test.
const shellQuote = require(VER === "v0" ? "sq-v0" : VER === "v2" ? "sq-v2" : "sq-v1");
const quote = shellQuote.quote;

// ---- one probe: build `echo ok <quote(tokens)>` with the REAL per-version quote(), then exec it ------
function runProbe(tokens) {
  let built = null;
  let quote_error = null;
  let output = "";
  let exec_error = null;
  try {
    built = "echo ok " + quote(tokens);       // <-- the per-version quote() escaping sink under test
  } catch (e) {
    quote_error = String((e && e.message) || e);
  }
  if (built !== null) {
    try {
      output = execSync(built, { shell: "/bin/sh", timeout: 5000, env: process.env }).toString();
    } catch (e) {
      // capture whatever the shell produced (an injected command may error yet still have leaked output)
      const so = e.stdout ? e.stdout.toString() : "";
      const se = e.stderr ? e.stderr.toString() : "";
      output = so + se;
      exec_error = String((e && e.message) || e);
    }
  }
  return {
    version: VER,
    shell_quote_version: VER_STR,
    tokens,
    built,
    quote_error,
    exec_error,
    output,
  };
}

const server = http.createServer((req, res) => {
  const u = new URL(req.url, "http://placeholder");
  if (u.pathname !== "/probe") {
    res.writeHead(200, { "Content-Type": "text/plain" });
    res.end(`shell-quote faithful-core harness ${VER} (shell-quote ${VER_STR}) ok`);
    return;
  }
  const raw = u.searchParams.get("tokens");
  let tokens;
  try {
    tokens = JSON.parse(raw);                  // array of strings and/or {op:"..."} objects
    if (!Array.isArray(tokens)) tokens = [String(raw)];
  } catch (e) {
    tokens = [String(raw)];                     // fall back to a single string token
  }
  try {
    const out = runProbe(tokens);
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(out));
  } catch (e) {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ version: VER, error: String((e && e.message) || e) }));
  }
});

server.listen(APP_PORT, "0.0.0.0", () => {
  console.log(`[harness ${VER}] shell-quote ${VER_STR} quote() sink listening on 0.0.0.0:${APP_PORT}`);
});
