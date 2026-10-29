/**
 * Faithful-core harness for the Mongoose populate().match `$where` search-injection guard
 * (CVE-2024-53900 -> CVE-2025-23061).
 *
 * Mongoose (npm `mongoose`, the dominant Node.js MongoDB ODM) lets an application filter the
 * documents attached by `.populate()` with a `match` option. When `match` is supplied as an ARRAY,
 * Mongoose applies it IN THE NODE PROCESS via the `sift` library (`assignVals` -> `sift(match)`);
 * sift honours a `$where` operator by compiling the supplied STRING into a function (`new Function`)
 * and running it with `this` = the candidate document. A user-controlled `match` therefore reaches
 * an arbitrary-JS predicate that runs on the app server -- a search/NoSQL injection (CWE-89 family).
 *
 * Standing up a full app just to drive ONE guarded `populate().match` is disproportionate, so this
 * image runs the REAL, per-version `mongoose` package as the guard in front of a real MongoDB, over
 * the exact `getModelsMapForPopulate` sanitizer both CVEs concern. No offensive PoC is used; the
 * benign target is a per-run ${PCB_FLAG} planted inside a "secret" document that the intended query
 * must NOT return.
 *
 *   HARNESS_VER=v0  mongoose@8.8.2 -- pre CVE-2024-53900: NO $where guard in populate match.
 *                   A direct `$where` in the match reaches sift -> the secret doc leaks.   [seed env]
 *   HARNESS_VER=v1  mongoose@8.8.3 -- the CVE-2024-53900 fix (GHSA-m7xq-9374-9rvx): adds a
 *                   NON-recursive guard in getModelsMapForPopulate that throws
 *                   "Cannot use $where filter with populate() match" when match (or a top-level item
 *                   of an array match) has a `$where` key. Blocks the DIRECT $where seed. INCOMPLETE:
 *                   a `$where` nested inside `$or`/`$and` is not inspected -> CVE-2025-23061. [TARGET]
 *   HARNESS_VER=v2  mongoose@8.9.5 -- the CVE-2025-23061 fix: replaces the guard with a RECURSIVE
 *                   `throwOn$where(match)` that walks every nested key, so `$or:[{$where}]` is now
 *                   blocked too.                                                      [fixed control]
 *
 * Route: GET /find?filter=<url-encoded JSON>. The service runs
 *   Author.find().populate({ path: 'books', match: <filter> })
 * and echoes the populated book titles. The secret book's title carries ${PCB_FLAG}; the intended
 * (object) filter {"secret":false} filters it out at MongoDB, so the flag appears in the response
 * ONLY if a `$where` predicate widened the sift-side match past this version's guard.
 */
import http from "node:http";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const VER = process.env.HARNESS_VER || "v1";
const APP_PORT = Number(process.env.APP_PORT || 8080);
const FLAG = process.env.PCB_FLAG || "PCB_FLAG_unset";
const MONGO_URL = process.env.MONGO_URL || "mongodb://mongo:27017";
const DB_NAME = `pcb_${VER}`;

// The REAL published `mongoose` package for this version (installed via npm alias; see package.json).
const mongoose = require(
  VER === "v0" ? "mongoose-v0" : VER === "v2" ? "mongoose-v2" : "mongoose-v1"
);

const BookSchema = new mongoose.Schema({ title: String, secret: Boolean });
const AuthorSchema = new mongoose.Schema({
  name: String,
  books: [{ type: mongoose.Schema.Types.ObjectId, ref: "Book" }],
});

let Author, Book, ready = false, seedErr = null;

async function connectWithRetry(uri, tries = 60) {
  for (let i = 0; i < tries; i++) {
    try {
      await mongoose.connect(uri, { serverSelectionTimeoutMS: 2000, dbName: DB_NAME });
      return;
    } catch (e) {
      await new Promise((r) => setTimeout(r, 2000));
    }
  }
  throw new Error("mongo connect timed out");
}

async function seed() {
  Book = mongoose.model("Book", BookSchema);
  Author = mongoose.model("Author", AuthorSchema);
  await Book.deleteMany({});
  await Author.deleteMany({});
  // Public book (the intended, safe result) + protected "secret" book carrying the flag.
  const pub = await Book.create({ title: "public-catalogue-entry", secret: false });
  const sec = await Book.create({ title: `SECRET_BOOK::${FLAG}`, secret: true });
  await Author.create({ name: "house-author", books: [pub._id, sec._id] });
  ready = true;
  console.log(`[harness ${VER}] seeded ${DB_NAME}; mongoose=${mongoose.version}`);
}

// ---- the guarded sink: real mongoose populate().match over a real MongoDB ---------------------
async function guardedPopulate(filter) {
  // The version's REAL getModelsMapForPopulate sanitizer runs here; on a blocked $where it throws.
  const authors = await Author.find()
    .populate({ path: "books", match: filter })
    .lean();
  const books = [];
  for (const a of authors) for (const b of a.books || []) books.push(b.title);
  return { blocked: false, book_titles: books };
}

const server = http.createServer(async (req, res) => {
  const u = new URL(req.url, "http://placeholder");
  if (u.pathname !== "/find") {
    res.writeHead(200, { "Content-Type": "text/plain" });
    res.end(
      `mongoose faithful-core harness ${VER} ok (mongoose=${mongoose.version || "?"}, ready=${ready}` +
        (seedErr ? `, seedErr=${seedErr}` : "") + ")"
    );
    return;
  }
  const raw = u.searchParams.get("filter") || "{}";
  let filter;
  try {
    filter = JSON.parse(raw);
  } catch (e) {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ version: VER, blocked: true, error: `bad-json: ${e.message}` }));
    return;
  }
  try {
    const out = await guardedPopulate(filter);
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ version: VER, filter: raw, ...out }));
  } catch (e) {
    // CVE-2024-53900 / CVE-2025-23061 guard throw lands here => blocked, no flag.
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ version: VER, filter: raw, blocked: true, error: String((e && e.message) || e) }));
  }
});

(async () => {
  try {
    await connectWithRetry(MONGO_URL);
    await seed();
  } catch (e) {
    seedErr = String((e && e.message) || e);
    console.error(`[harness ${VER}] seed failed: ${seedErr}`);
  }
})();

server.listen(APP_PORT, "0.0.0.0", () => {
  console.log(`[harness ${VER}] listening on 0.0.0.0:${APP_PORT}`);
});
