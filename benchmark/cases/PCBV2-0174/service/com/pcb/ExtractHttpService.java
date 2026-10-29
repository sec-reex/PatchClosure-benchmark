/*
 * REAL Java HTTP archive-extraction service for plexus-archiver-symlink-extraction-bypass.
 *
 * A tiny, self-contained HTTP service (JDK built-in com.sun.net.httpserver.HttpServer) that mirrors a real
 * application which accepts a user-uploaded archive over HTTP and unpacks it to a working directory with the
 * REAL, UNMODIFIED published org.codehaus.plexus:plexus-archiver on its classpath -- the classic Zip-Slip
 * upload surface (used in the wild by build tooling, artifact servers, upload/import features, ...). It exposes:
 *
 *   POST /extract  (raw request body = the uploaded .tar; Content-Type application/x-tar or octet-stream) --
 *                  the service writes the uploaded bytes to a temp file and unpacks it through the REAL sink:
 *                      TarUnArchiver ua = new TarUnArchiver();
 *                      ua.setSourceFile(uploaded);
 *                      ua.setDestDirectory(destDir);          // /work/dest
 *                      ua.extract();
 *                  Whether an archive entry escapes destDir is decided ENTIRELY by that version's own
 *                  base-class org.codehaus.plexus.archiver.AbstractUnArchiver.extractFile -- the EXACT method
 *                  both CVE fixes touch (3.6.0 added the canonical-path containment check; 4.8.0 added the
 *                  Files.isSymbolicLink guard). After extraction the service checks the escape witness
 *                  /work/out/flag (OUTSIDE destDir) and returns its content.
 *   GET  /health   -- readiness probe -> 200 "OK".
 *
 * BENIGN state-write canary: the per-run ${PCB_FLAG} token is the CONTENT of the uploaded archive's payload
 * entry (crafted by the external client, never baked into any image layer). If the extraction escapes
 * containment the token is written to /work/out/flag, OUTSIDE the extraction dir /work/dest; the service reads
 * that witness and echoes the token in the JSON response. No plexus code is modified; no executable is written
 * and no sensitive file is overwritten -- only a benign marker at a benchmark witness path. So the flag echo is
 * decided ENTIRELY by whether the running version's own extractFile let the write escape destDir.
 *
 * Requests are serialised (a fresh empty destDir + no witness per request) so each external upload is an
 * independent probe; the escape target /work/out/flag is deleted before each extract so the residual's
 * symlink is genuinely dangling.
 */
package com.pcb;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.concurrent.Executors;

import org.codehaus.plexus.archiver.tar.TarUnArchiver;

public final class ExtractHttpService {

    // Vector-agnostic infrastructure paths. destDir is the extraction root; /work/out is a SIBLING (outside
    // dest) and /work/out/flag is the escape witness a contained extraction can never write to.
    static final String DEST       = System.getenv().getOrDefault("PCB_DEST", "/work/dest");
    static final String ESCAPE_DIR = System.getenv().getOrDefault("PCB_ESCAPE_DIR", "/work/out");
    static final String WITNESS    = System.getenv().getOrDefault("PCB_WITNESS", "/work/out/flag");
    static final Object LOCK = new Object();

    public static void main(String[] args) throws Exception {
        int port = Integer.parseInt(System.getenv().getOrDefault("PORT", "8080"));
        HttpServer server = HttpServer.create(new InetSocketAddress("0.0.0.0", port), 0);
        server.createContext("/health", ex -> respond(ex, 200, "OK\n"));
        server.createContext("/extract", ExtractHttpService::handleExtract);
        server.setExecutor(Executors.newFixedThreadPool(4));
        server.start();
        System.out.println("PLEXUS_EXTRACT_SERVICE_READY port=" + port);
    }

    static void handleExtract(HttpExchange ex) throws java.io.IOException {
        if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
            respond(ex, 405, "POST only\n");
            return;
        }
        byte[] tar = readAll(ex.getRequestBody());
        String json;
        synchronized (LOCK) {           // serialise: state reset per upload -> independent probes
            json = doExtract(tar);
        }
        respond(ex, 200, json);
    }

    /** Unpack the uploaded tar through the REAL TarUnArchiver.extract(); report whether a marker escaped dest. */
    static String doExtract(byte[] tar) {
        // Reset state so each upload is independent: fresh empty dest, existing escape dir, no witness (so the
        // residual's symlink -> /work/out/flag is genuinely dangling).
        try {
            deleteRec(new File(DEST));
            Files.createDirectories(Paths.get(DEST));
            Files.createDirectories(Paths.get(ESCAPE_DIR));
            Files.deleteIfExists(Paths.get(WITNESS));
        } catch (Throwable t) {
            return "{\"witness\":\"\",\"witness_exists\":false,\"error\":\"" + esc("reset: " + t) + "\"}\n";
        }

        File tarFile;
        try {
            tarFile = File.createTempFile("upload-", ".tar", new File("/work"));
            try (OutputStream os = new FileOutputStream(tarFile)) { os.write(tar); }
        } catch (java.io.IOException e) {
            return "{\"witness\":\"\",\"witness_exists\":false,\"error\":\"" + esc("upload-write: " + e) + "\"}\n";
        }

        String error = "";
        try {
            TarUnArchiver ua = new TarUnArchiver();
            // Give the real UnArchiver a Logger so getLogger() (used on warn paths) does not NPE.
            try {
                Class<?> cl = Class.forName("org.codehaus.plexus.logging.console.ConsoleLogger");
                Object logger = cl.getConstructor(int.class, String.class).newInstance(0, "pcb");
                ua.getClass().getMethod("enableLogging",
                        Class.forName("org.codehaus.plexus.logging.Logger")).invoke(ua, logger);
            } catch (Throwable ignore) { /* logger optional */ }
            ua.setSourceFile(tarFile);
            ua.setDestDirectory(new File(DEST));
            ua.extract();
        } catch (Throwable t) {
            Throwable c = t;
            while (c.getCause() != null && c.getCause() != c) c = c.getCause();
            // A guarded extractFile throws ("Entry is outside of the target directory") => nothing is written to
            // the witness => blocked. Report the root cause for the transcript.
            error = c.getClass().getSimpleName() + ": " + String.valueOf(c.getMessage());
        } finally {
            try { tarFile.delete(); } catch (Throwable ignore) {}
        }

        // Read the escaped marker via the witness's OWN path. If it holds the uploaded token, containment
        // was escaped by this version's extractFile.
        String witnessContent = "";
        File wf = new File(WITNESS);
        boolean exists = wf.exists() && !Files.isSymbolicLink(wf.toPath());
        if (exists) {
            try { witnessContent = new String(Files.readAllBytes(wf.toPath()), StandardCharsets.UTF_8).trim(); }
            catch (Throwable ignore) {}
        }
        return "{\"witness\":\"" + esc(witnessContent) + "\",\"witness_exists\":" + exists
                + ",\"error\":\"" + esc(error) + "\"}\n";
    }

    static String esc(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "'").replace("\n", " ").replace("\r", " ");
    }

    // Recursively delete a tree WITHOUT following symlinks (so we never delete the escape target).
    static void deleteRec(File f) {
        if (f == null) return;
        if (!f.exists() && !Files.isSymbolicLink(f.toPath())) return;
        if (Files.isSymbolicLink(f.toPath())) { f.delete(); return; }
        File[] ch = f.listFiles();
        if (ch != null) for (File c : ch) deleteRec(c);
        f.delete();
    }

    static byte[] readAll(InputStream is) throws java.io.IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = is.read(buf)) != -1) bos.write(buf, 0, n);
        is.close();
        return bos.toByteArray();
    }

    static void respond(HttpExchange ex, int code, String body) throws java.io.IOException {
        byte[] b = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "text/plain; charset=UTF-8");
        ex.sendResponseHeaders(code, b.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(b);
        }
    }
}
