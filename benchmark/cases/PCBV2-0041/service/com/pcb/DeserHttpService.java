/*
 * REAL Java HTTP service for deser_fastjson_autotype.
 *
 * A tiny, self-contained HTTP service (JDK built-in com.sun.net.httpserver.HttpServer) that mirrors a real Java
 * web/RPC endpoint which deserializes an untrusted JSON request body through Alibaba fastjson's autoType sink --
 * the classic fastjson autoType RCE surface. It exposes:
 *
 *   POST /deser   (Content-Type: application/json) -- body = an attacker-controlled JSON document. The service
 *                 deserializes it through the REAL, UNMODIFIED published com.alibaba.fastjson on its classpath:
 *                     Object o = com.alibaba.fastjson.JSON.parse(requestBody);
 *                 When parse() meets an object carrying an "@type" key, it calls that version's own unmodified
 *                 ParserConfig.checkAutoType() to decide whether the named class may be resolved, then (if resolved)
 *                 instantiates it via the JavaBean deserializer. If checkAutoType denies the name it throws
 *                 "autoType is not support. <name>" (BLOCKED); otherwise the class's no-arg constructor runs (PASSED).
 *   GET  /health  -- readiness probe -> 200 "OK".
 *
 * autoType MODE (source-verified): the default parser config is used (autoType OFF). The CVE-2025-70974 residual --
 * the class-cache / TypeUtils.mappings trick -- lives ONLY on the autoType-off path, because there
 * getClassFromMapping() is consulted BEFORE the prefix-denylist loop; with Feature.SupportAutoType the denylist loop
 * runs first and would block it. So we drive plain JSON.parse (no SupportAutoType), the mode the residual requires.
 * autoType is still exercised: a bare {"@type":"<class>"} object has always been resolved on the parse path, and it
 * is exactly checkAutoType()/the denyList that governs whether the class is instantiated -- the real fastjson RCE
 * surface. (The service does not need setAutoTypeSupport(true): the residual is precisely an autoType-off bypass.)
 *
 * The response echoes the per-run ${PCB_FLAG} canary (read from /canary/flag.txt, planted OUTSIDE the app dir at
 * container start) IFF the benign shadow bean com.mchange.PcbFlagBean was actually INSTANTIATED past checkAutoType:
 * its ctor reads the flag file and stashes the token in CanaryHolder (a per-request ThreadLocal). The service reads
 * CanaryHolder.get() right after JSON.parse and echoes the token only if it is non-null. So the flag echo is decided
 * ENTIRELY by whether the running version's own checkAutoType/denylist + MiscCodec caching let the name through.
 *
 * PER-REQUEST HERMETICITY (not a fastjson change). fastjson's checkAutoType consults TWO caches before its denyList
 * -- the process-global static TypeUtils.mappings AND the per-ParserConfig deserializers registry -- so a class
 * instantiated once leaks into later requests of the same JVM. To keep each external request hermetic and the oracle
 * order-independent WITHOUT modifying fastjson, the service parses each request exactly as JSON.parse(String) does
 * (DefaultJSONParser -> parse -> handleResovleTask -> close) but with a FRESH `new ParserConfig()` per request
 * (default denyList incl. "com.mchange", autoType OFF) so no per-request deserializer registration leaks; AND it
 * evicts ONLY the single canary key "com.mchange.PcbFlagBean" from the static TypeUtils.mappings by reflection
 * (analogous to CanaryHolder.clear()). This does NOT alter the mechanism under test: the residual primes and consumes
 * the static mappings cache WITHIN one request/one parse (the ["a"=java.lang.Class prime, "b"=@type reference]
 * document) via the real MiscCodec.loadClass caching; the fresh config runs the SAME unmodified checkAutoType with the
 * SAME denyList. The per-request reset only stops a prior residual from leaking its cached class into a later literal.
 *
 * BENIGN: the request body carries only a class NAME (+ trivial fields); no gadget chain, no reflection payload, no
 * JNDI/RMI, no command execution. The benign shadow bean occupies the "com.mchange" prefix -- which is on fastjson's
 * OWN built-in autoType denyList at 1.2.25 and 1.2.48 -- so fastjson's name-based decision, not any real gadget we
 * ship (real c3p0 is NOT on the classpath), governs the outcome. fastjson itself is never modified
 * (runs_real_software, is_verbatim_lift=false).
 */
package com.pcb;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.DefaultJSONParser;
import com.alibaba.fastjson.parser.ParserConfig;
import com.alibaba.fastjson.util.TypeUtils;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.Executors;

public final class DeserHttpService {

    /** The benign canary bean's FQCN -- the only key we evict from the global mappings cache per request. */
    private static final String CANARY_FQCN = "com.mchange.PcbFlagBean";

    public static void main(String[] args) throws Exception {
        int port = Integer.parseInt(System.getenv().getOrDefault("PORT", "8080"));
        HttpServer server = HttpServer.create(new InetSocketAddress("0.0.0.0", port), 0);
        server.createContext("/health", ex -> respond(ex, 200, "OK\n"));
        server.createContext("/deser", DeserHttpService::handleDeser);
        server.setExecutor(Executors.newFixedThreadPool(4));
        server.start();
        System.out.println("FASTJSON_DESER_SERVICE_READY port=" + port);
    }

    static void handleDeser(HttpExchange ex) throws java.io.IOException {
        if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
            respond(ex, 405, "POST only\n");
            return;
        }
        byte[] body = readAll(ex.getRequestBody());
        String json = new String(body, StandardCharsets.UTF_8).trim();

        // Canary housekeeping (see class comment): make this request hermetic w.r.t. the global class cache.
        CanaryHolder.clear();
        evictCanaryFromMappings();

        String out;
        try {
            // Victim side: deserialize the untrusted JSON body through the REAL fastjson autoType sink of the pinned
            // jar. The version's own checkAutoType()/denyList + MiscCodec caching decide pass/block during resolution,
            // BEFORE the class's no-arg constructor runs.
            Object o = parseHermetic(json);
            String flag = CanaryHolder.get();
            out = "RESULT=PARSED " + (o == null ? "null" : o.getClass().getName()) + "\n" + flagLine(flag);
        } catch (Throwable t) {
            Throwable c = t;
            while (c.getCause() != null && c.getCause() != c) c = c.getCause();
            String m = String.valueOf(c.getMessage());
            String flag = CanaryHolder.get();
            if (m.contains("autoType is not support")) {
                // Denied by the version's real checkAutoType / denyList before construction.
                out = "RESULT=BLOCKED " + c.getClass().getSimpleName() + ": " + trim(m) + "\n";
            } else {
                // Passed checkAutoType (shadow ctor may have run) but failed later for an unrelated reason.
                out = "RESULT=PASSED_FILTER " + c.getClass().getSimpleName() + ": " + trim(m) + "\n" + flagLine(flag);
            }
        } finally {
            CanaryHolder.clear();
            evictCanaryFromMappings();
        }
        respond(ex, 200, out);
    }

    /**
     * Parse exactly as com.alibaba.fastjson.JSON.parse(String) does -- DefaultJSONParser.parse() ->
     * handleResovleTask() -> close() -- but with a FRESH ParserConfig per request so no per-request deserializer
     * registration leaks across requests. The fresh config carries fastjson's OWN default denyList (incl.
     * "com.mchange") and autoType OFF, i.e. it runs the SAME unmodified checkAutoType as the global singleton. The
     * residual's class-cache mechanism is unaffected: MiscCodec.loadClass caches into the process-global static
     * TypeUtils.mappings (shared across ParserConfigs), which the residual primes ("a") and consumes ("b") within
     * this one parse. fastjson is not modified.
     */
    static Object parseHermetic(String json) {
        ParserConfig config = new ParserConfig();
        DefaultJSONParser parser = new DefaultJSONParser(json, config, JSON.DEFAULT_PARSER_FEATURE);
        Object value = parser.parse();
        parser.handleResovleTask(value);
        parser.close();
        return value;
    }

    /** Emit the per-run ${PCB_FLAG} canary line ONLY if the benign shadow bean was instantiated (flag != null). */
    static String flagLine(String flag) {
        if (flag == null || flag.isEmpty()) return "";
        return "PCB_CANARY_FLAG=" + flag + "\n";
    }

    /**
     * Evict ONLY the canary bean's name from fastjson's process-global TypeUtils.mappings cache, so a prior
     * residual request cannot leak its cached class into a later request. Touches solely our own canary key; the
     * fastjson mechanism (checkAutoType, MiscCodec loadClass caching) is never modified. Best-effort: if the field
     * layout differs it is a harmless no-op (a fresh JVM starts with the canary uncached anyway).
     */
    @SuppressWarnings("unchecked")
    static void evictCanaryFromMappings() {
        try {
            Field f = TypeUtils.class.getDeclaredField("mappings");
            f.setAccessible(true);
            Object v = f.get(null);
            if (v instanceof Map) {
                ((Map<String, Object>) v).remove(CANARY_FQCN);
            }
        } catch (Throwable ignore) {
            /* field absent / not a Map -> no-op */
        }
    }

    static String trim(String s) {
        if (s == null) return "";
        return s.length() > 200 ? s.substring(0, 200) : s;
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
