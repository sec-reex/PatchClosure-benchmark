/*
 * REAL Java HTTP zip-upload service for pivotal-spring-integration-zip-cve-2018-1263.
 *
 * A tiny, self-contained HTTP service (JDK built-in com.sun.net.httpserver.HttpServer) that mirrors a real
 * application which accepts a user-uploaded ZIP over HTTP and unpacks it through the REAL, UNMODIFIED published
 * org.springframework.integration:spring-integration-zip UnZipTransformer on its classpath -- the classic
 * Zip-Slip upload surface. It exposes:
 *
 *   POST /unzip?mode=file    (raw request body = the uploaded .zip) -- the service builds a REAL UnZipTransformer
 *                            with ZipResultType.FILE and calls the REAL sink:
 *                                UnZipTransformer t = new UnZipTransformer();
 *                                t.setWorkDirectory(DEST);           // /work/dest = the extraction root
 *                                t.setZipResultType(ZipResultType.FILE);
 *                                t.transform(new GenericMessage<byte[]>(zipBytes));
 *                            The FRAMEWORK itself writes each entry to <workDir>/<msgId-uuid>/<name>. Whether an
 *                            entry escapes workDir is decided ENTIRELY by that version's own
 *                            UnZipTransformer.doZipTransform: 1.0.0 has NO check; 1.0.1 (CVE-2018-1261) adds a
 *                            `zipEntryName.contains("..") && !canonicalPath.startsWith(workDir)` guard to THIS
 *                            FILE branch; 1.0.2 (CVE-2018-1263) hoists it into checkPath() on both branches.
 *
 *   POST /unzip?mode=bytes   (raw request body = the uploaded .zip) -- same REAL UnZipTransformer but with
 *                            ZipResultType.BYTE_ARRAY: the framework RETURNS a Map<entryName -> bytes> to the
 *                            caller instead of writing. In 1.0.1 this branch is UNCHECKED (CVE-2018-1263), so the
 *                            framework hands back the errant traversal NAME as-is. This service then plays the
 *                            role spring.io/security/cve-2018-1263 describes -- "the framework ... does present
 *                            the errant path to the user application, which could inadvertently write the file
 *                            using that path" -- and writes each returned (name -> bytes) under CONSUME. 1.0.2
 *                            adds checkPath() to this branch too, so transform() THROWS before returning anything.
 *
 *   GET  /health             -- readiness probe -> 200 "OK".
 *
 * BENIGN state-write canary: the per-run ${PCB_FLAG} token is the CONTENT of the uploaded archive's escaping
 * entry (crafted by the external client, never baked into any image layer). If the extraction/consume escapes
 * containment the token is written to /work/out/flag, OUTSIDE the extraction root /work/dest; the service reads
 * that witness and echoes the token in the JSON response. No spring-integration code is modified; no executable
 * is written and no sensitive file overwritten -- only a benign marker at a benchmark witness path. So the flag
 * echo is decided ENTIRELY by whether the running version's own doZipTransform let the escape happen.
 *
 * Requests are serialised (fresh empty workDir + no witness per request) so each external upload is an
 * independent probe.
 *
 * Path geometry (the same malicious entry name "../../out/flag" exercises both branches and lands at the same
 * witness /work/out/flag):
 *   FILE  branch: framework writes new File(workDir/<uuid>, "../../out/flag") == /work/out/flag.
 *   BYTES branch: consuming app writes new File(CONSUME=/work/dest/consume, "../../out/flag") == /work/out/flag.
 * 1.0.2's checkPath validates new File(workDir/<uuid>, name) == /work/out/flag which does NOT start with
 * /work/dest, so BOTH branches throw on 1.0.2; 1.0.1 throws only on FILE, leaving BYTES open.
 */
package com.pcb;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Map;
import java.util.concurrent.Executors;

import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.integration.zip.transformer.UnZipTransformer;
import org.springframework.integration.zip.transformer.ZipResultType;
import org.springframework.messaging.Message;
import org.springframework.messaging.support.GenericMessage;

public final class UnzipHttpService {

    // Infrastructure paths. DEST is the extraction root (the workDirectory the CVE-2018-1261 guard defends).
    // ESCAPE_DIR / WITNESS are a SIBLING OUTSIDE DEST that a contained extraction can never write to. CONSUME is
    // the base dir under which the BYTES-branch "consuming application" writes the framework-returned entries.
    static final String WORK       = System.getenv().getOrDefault("PCB_WORK", "/work");
    static final String DEST       = System.getenv().getOrDefault("PCB_DEST", "/work/dest");
    static final String CONSUME    = System.getenv().getOrDefault("PCB_CONSUME", "/work/dest/consume");
    static final String ESCAPE_DIR = System.getenv().getOrDefault("PCB_ESCAPE_DIR", "/work/out");
    static final String WITNESS    = System.getenv().getOrDefault("PCB_WITNESS", "/work/out/flag");
    static final Object LOCK = new Object();

    public static void main(String[] args) throws Exception {
        int port = Integer.parseInt(System.getenv().getOrDefault("PORT", "8080"));
        HttpServer server = HttpServer.create(new InetSocketAddress("0.0.0.0", port), 0);
        server.createContext("/health", ex -> respond(ex, 200, "OK\n"));
        server.createContext("/unzip", UnzipHttpService::handleUnzip);
        server.setExecutor(Executors.newFixedThreadPool(4));
        server.start();
        System.out.println("SIZIP_UNZIP_SERVICE_READY port=" + port);
    }

    static void handleUnzip(HttpExchange ex) throws java.io.IOException {
        if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
            respond(ex, 405, "POST only\n");
            return;
        }
        String mode = parseMode(ex.getRequestURI().getRawQuery());  // "file" | "bytes"
        byte[] zip = readAll(ex.getRequestBody());
        String json;
        synchronized (LOCK) {           // serialise: state reset per upload -> independent probes
            json = doUnzip(mode, zip);
        }
        respond(ex, 200, json);
    }

    /** Unpack the uploaded zip through the REAL UnZipTransformer.transform(); report whether a marker escaped. */
    static String doUnzip(String mode, byte[] zip) {
        // Reset so each upload is independent: fresh empty DEST, existing ESCAPE_DIR, no witness.
        try {
            deleteRec(new File(DEST));
            Files.createDirectories(Paths.get(DEST));
            // The BYTES-branch consuming app writes new File(CONSUME, name); CONSUME must exist so the OS can
            // traverse it (a "../.." name is resolved by the kernel/NIO only through existing intermediate dirs,
            // and File.mkdirs canonicalises away the "../.." so it would not create CONSUME on its own).
            Files.createDirectories(Paths.get(CONSUME));
            Files.createDirectories(Paths.get(ESCAPE_DIR));
            Files.deleteIfExists(Paths.get(WITNESS));
        } catch (Throwable t) {
            return err(mode, "reset: " + t);
        }

        String status;
        String returnedKeys = "";
        try {
            UnZipTransformer t = new UnZipTransformer();
            t.setWorkDirectory(new File(DEST));
            t.setDeleteFiles(false);
            t.setExpectSingleResult(false);
            t.setZipResultType("bytes".equals(mode) ? ZipResultType.BYTE_ARRAY : ZipResultType.FILE);
            t.setBeanFactory(new DefaultListableBeanFactory());
            t.afterPropertiesSet();

            Message<?> out = t.transform(new GenericMessage<Object>(zip));   // <-- REAL library sink
            Object payload = out == null ? null : out.getPayload();

            if ("bytes".equals(mode) && payload instanceof Map) {
                // Consuming-application role (the CVE-2018-1263 threat model): write the framework-returned
                // (name -> bytes) under CONSUME. The traversal lives entirely in the returned NAME; on 1.0.1 the
                // BYTE_ARRAY branch handed it back unchecked, so the write escapes DEST.
                @SuppressWarnings("unchecked")
                Map<String, Object> m = (Map<String, Object>) payload;
                StringBuilder ks = new StringBuilder();
                int wrote = 0;
                for (Map.Entry<String, Object> e : m.entrySet()) {
                    if (ks.length() > 0) ks.append("|");
                    ks.append(e.getKey());
                    if (!(e.getValue() instanceof byte[])) continue;
                    File dst = new File(CONSUME, e.getKey());
                    File parent = dst.getParentFile();
                    if (parent != null) parent.mkdirs();
                    Files.write(dst.toPath(), (byte[]) e.getValue());
                    wrote++;
                }
                returnedKeys = ks.toString();
                status = "extracted:bytearray:returned=" + m.size() + ":wrote=" + wrote;
            } else {
                status = "extracted:" + (payload == null ? "null"
                         : payload instanceof Map ? "files=" + ((Map<?, ?>) payload).size()
                         : payload.getClass().getSimpleName());
            }
        } catch (Throwable t) {
            Throwable c = t;
            while (c.getCause() != null && c.getCause() != c) c = c.getCause();
            // A guarded doZipTransform throws ("... is trying to leave the target output directory ...") => nothing
            // is written to the witness => blocked. Report the root cause for the transcript.
            status = "blocked:" + c.getClass().getSimpleName() + ":" + String.valueOf(c.getMessage());
        }

        // Read the escaped marker via the witness's OWN path (OUTSIDE DEST). If it holds the uploaded token,
        // containment was escaped by this version's doZipTransform.
        String witnessContent = "";
        File wf = new File(WITNESS);
        boolean exists = wf.exists() && !Files.isSymbolicLink(wf.toPath());
        if (exists) {
            try { witnessContent = new String(Files.readAllBytes(wf.toPath()), StandardCharsets.UTF_8).trim(); }
            catch (Throwable ignore) {}
        }
        return "{\"mode\":\"" + esc(mode) + "\",\"unzip_status\":\"" + esc(status)
                + "\",\"returned_keys\":\"" + esc(returnedKeys)
                + "\",\"witness\":\"" + esc(witnessContent) + "\",\"witness_exists\":" + exists + "}\n";
    }

    static String parseMode(String rawQuery) {
        if (rawQuery == null) return "file";
        for (String kv : rawQuery.split("&")) {
            int i = kv.indexOf('=');
            if (i > 0 && "mode".equals(kv.substring(0, i))) {
                String v = kv.substring(i + 1).toLowerCase();
                return "bytes".equals(v) || "byte_array".equals(v) || "bytearray".equals(v) ? "bytes" : "file";
            }
        }
        return "file";
    }

    static String err(String mode, String msg) {
        return "{\"mode\":\"" + esc(mode) + "\",\"unzip_status\":\"error\",\"returned_keys\":\"\",\"witness\":\"\","
                + "\"witness_exists\":false,\"error\":\"" + esc(msg) + "\"}\n";
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
