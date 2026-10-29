/**
 * Faithful-core harness for the Deno `node:child_process` shell:true OS-command-injection sink
 * (pre-CVE-2026-27190 2.6.7 -> CVE-2026-27190 fix carried in 2.7.1 [TARGET] -> CVE-2026-32260 fix 2.7.2).
 *
 * The security boundary under test lives ENTIRELY inside the Deno binary: when a shell command that
 * begins with the Deno executable is spawned via `node:child_process` with `shell: true`, Deno's
 * `transformDenoShellCommand()` (ext/node/polyfills/internal/child_process.ts) re-parses the deno CLI
 * args and re-quotes them so they are "safe to embed in a shell command string". Both CVEs are that
 * per-arg shell-metacharacter neutralization failing:
 *
 *   HARNESS_VER=v0  deno 2.6.7 -- transformDenoShellCommand() has an INCOMPLETE blocklist
 *                   `/[();&|<>` + "`" + `!]/`: if a translated arg matches it, the ORIGINAL command is
 *                   returned unchanged (so the metachar reaches /bin/sh); if it does NOT match, args are
 *                   joined WITHOUT any quoting. Either way a shell metacharacter (e.g. a backtick) is left
 *                   live -> command substitution executes.                         [pre-CVE-2026-27190 seed]
 *   HARNESS_VER=v1  deno 2.7.1 -- carries the CVE-2026-27190 fix (2.6.8): translated args are now
 *                   shell-QUOTED. POSIX branch: args with a `$VAR`/`${VAR}` ref are wrapped in DOUBLE
 *                   quotes to preserve expansion; all other metachar args are wrapped in SINGLE quotes.
 *                   A plain backtick arg is single-quoted -> BLOCKED. BUT an arg that ALSO contains a
 *                   `$VAR` pattern takes the double-quote branch, and double quotes in POSIX sh do NOT
 *                   suppress backtick command substitution -> injection = CVE-2026-32260.  [TARGET, GIVEN]
 *   HARNESS_VER=v2  deno 2.7.2 -- CVE-2026-32260 fix: the double-quote branch is gated by
 *                   `unsafeInDoubleQuotes = /` + "`" + `|\$\(|\\/` and only taken when the arg has NO
 *                   backtick/`$(`/backslash; otherwise it falls back to SINGLE quotes. The `$VAR`+backtick
 *                   residual is now single-quoted -> BLOCKED.                       [negative control]
 *
 * Benign canary (OS command injection -> flag read): the entrypoint plants ${PCB_FLAG} in
 * /canary/flag.txt and a benign no-argument reader /canary/rf that `cat /canary/flag.txt`. If the crafted
 * arg's backtick survives transformDenoShellCommand(), /bin/sh runs the command substitution `/canary/rf`,
 * its output (the flag) is interpolated into the deno command line, and deno echoes it back in a
 * "Module not found <flag>" error on stderr. Flag in output == injection succeeded. No real payload; the
 * injected command merely reads a planted flag file (derived from the advisories + source diff only).
 *
 * Route: GET /probe?arg=<deno CLI args string>. The harness builds `<Deno.execPath()> <arg>` and runs it
 * via node:child_process spawnSync(cmd, {shell:true}) -- i.e. /bin/sh -c ... -- returning stdout+stderr.
 */
import { spawnSync } from "node:child_process";

const VER = Deno.env.get("HARNESS_VER") || "v1";
const PORT = Number(Deno.env.get("APP_PORT") || 8080);
const DENO_PATH = Deno.execPath();

function runProbe(userArg: string) {
  // The app runs the Deno executable as a subprocess with user-influenced CLI args, via shell:true.
  // transformDenoShellCommand() fires because the command begins with Deno.execPath().
  const cmd = DENO_PATH + " " + userArg;
  let stdout = "", stderr = "", status: number | null = null, error: string | null = null;
  try {
    const r = spawnSync(cmd, { shell: true, encoding: "utf-8", timeout: 5000 });
    stdout = r.stdout ?? "";
    stderr = r.stderr ?? "";
    status = r.status;
    if (r.error) error = String(r.error.message || r.error);
  } catch (e) {
    error = String((e && (e as Error).message) || e);
  }
  return {
    version: VER,
    deno_version: Deno.version.deno,
    userArg,
    cmd,
    stdout,
    stderr,
    status,
    error,
    output: stdout + stderr, // uniform channel the oracle scans for the flag
  };
}

Deno.serve({ port: PORT, hostname: "0.0.0.0" }, (req: Request) => {
  const u = new URL(req.url);
  if (u.pathname !== "/probe") {
    return new Response(
      `deno node:child_process shell:true harness ${VER} (deno ${Deno.version.deno}) ok`,
      { headers: { "content-type": "text/plain" } },
    );
  }
  const userArg = u.searchParams.get("arg") ?? "";
  const out = runProbe(userArg);
  return new Response(JSON.stringify(out), {
    headers: { "content-type": "application/json" },
  });
});
