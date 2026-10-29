/**
 * Real-library-wrap HTTP service for the `compressing` npm tar-extraction zip-slip incomplete-fix.
 * Pair: CVE-2026-24884 (V1 = incomplete-fix TARGET) -> CVE-2026-40931 (V2 = complete fix).
 *
 * The three profiles run the EXACT published npm bytes of `compressing`, installed side-by-side via
 * npm aliases (see package.json) and selected by HARNESS_VER:
 *   V0 = comp_v0 -> compressing@2.0.0  (no path validation at all: path.join(destDir, header.name);
 *                                       plain `../` traversal escapes)
 *   V1 = comp_v1 -> compressing@2.1.0  (CVE-2026-24884 fix: isPathWithinParent STRING validation of
 *                                       the resolved dest path AND of the symlink TARGET; blocks a
 *                                       plain `../` member, but does NOT lstat existing on-disk path
 *                                       segments, so a PRE-EXISTING symlink in destDir is followed) TARGET
 *   V2 = comp_v2 -> compressing@2.1.1  (CVE-2026-40931 fix: isRealPathSafe() walks every path segment
 *                                       with lstat and rejects any entry whose real path escapes via a
 *                                       filesystem symlink)                                    negative
 *
 * SINK: compressing.tar.uncompress(tarBuffer, destDir) -> utils.makeUncompressFn 'entry' handler ->
 *       for a 'file' entry it computes destFilePath = path.join(resolvedDestDir, name) and writes it.
 *
 * External trigger: a REAL POST /extract carrying raw tar bytes. Detection is a BENIGN state-write
 * canary: the service extracts into a FRESH temp destDir that has a sibling `pcb_witness` dir OUTSIDE
 * destDir, then reads back any file that landed under pcb_witness. A marker file appears there IFF the
 * extraction escaped containment. The parsed archive is never echoed; canary_value = the escaped
 * file's content (which the client put in the tar) IFF it escaped, else null.
 *
 * `x-pcb-poison: <name>`  (optional) materialises the documented "git-delivered symlink poisoning"
 * precondition of CVE-2026-40931: a pre-existing on-disk symlink `<name>` inside destDir pointing at
 * the sibling witness dir (as if checked out from a git working tree / left by a prior extraction).
 * Absent header => a clean destDir. Each probe gets a fresh temp root, destDir and witness.
 */
import http from "node:http";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const VER = process.env.HARNESS_VER || "v1";
const APP_PORT = Number(process.env.APP_PORT || 8080);
const ALIAS = { v0: "comp_v0", v1: "comp_v1", v2: "comp_v2" }[VER];
if (!ALIAS) { console.error(`unknown HARNESS_VER ${VER}`); process.exit(1); }
const compressing = (await import(ALIAS)).default;

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

// Recursively read back the first regular file that landed under `dir` (outside destDir).
function readWitness(dir) {
  for (const name of fs.readdirSync(dir)) {
    const p = path.join(dir, name);
    let st;
    try { st = fs.lstatSync(p); } catch { continue; }
    if (st.isDirectory()) { const r = readWitness(p); if (r) return r; }
    else if (st.isFile()) {
      try { return { rel: path.relative(dir, p), content: fs.readFileSync(p, "utf8").trim() }; }
      catch { /* skip unreadable */ }
    }
  }
  return null;
}

async function extractOnce(tarBuf, poisonName) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "pcb-comp-"));
  const destDir = path.join(root, "extract_dest");
  const witnessDir = path.join(root, "pcb_witness"); // sibling OUTSIDE destDir
  fs.mkdirSync(destDir, { recursive: true });
  fs.mkdirSync(witnessDir, { recursive: true });
  if (poisonName) {
    // Pre-existing on-disk symlink in destDir -> sibling witness (git-delivered poisoning).
    fs.symlinkSync(path.join("..", "pcb_witness"), path.join(destDir, poisonName));
  }
  let extractError = null;
  try {
    await compressing.tar.uncompress(tarBuf, destDir);
  } catch (e) { extractError = String((e && e.message) || e); }
  const hit = readWitness(witnessDir);
  // best-effort cleanup of the per-probe temp root
  try { fs.rmSync(root, { recursive: true, force: true }); } catch {}
  return {
    escaped: !!hit,
    escaped_path: hit ? hit.rel : null,
    canary_value: hit ? hit.content : null,
    extract_error: extractError,
  };
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, "http://localhost");
  if (url.pathname === "/healthz") {
    res.writeHead(200, { "content-type": "text/plain" });
    res.end("ok");
    return;
  }
  if (req.method === "POST" && url.pathname === "/extract") {
    const body = await readBody(req);
    const poison = (req.headers["x-pcb-poison"] || "").toString().trim() || null;
    let result;
    try { result = await extractOnce(body, poison); }
    catch (e) { result = { escaped: false, escaped_path: null, canary_value: null, extract_error: String(e) }; }
    res.writeHead(200, { "content-type": "application/json", "x-pcb-version": VER });
    res.end(JSON.stringify({ version: VER, poison, ...result }));
    return;
  }
  res.writeHead(404, { "content-type": "text/plain" });
  res.end("not found");
});

server.listen(APP_PORT, "0.0.0.0", () => {
  console.log(`[compressing-service ${VER}] real compressing@${ALIAS} listening on ${APP_PORT}`);
});
