/*
 * REAL Java HTTP REST service for jackson-databind-cve-2017-17485.
 *
 * A tiny, self-contained HTTP service (JDK built-in com.sun.net.httpserver.HttpServer) that mirrors a real
 * REST service which deserializes an untrusted JSON request body with jackson default typing enabled -- the
 * classic jackson-databind polymorphic-deserialization RCE surface. It exposes:
 *
 *   POST /deser   (Content-Type: application/json) -- body = an attacker-controlled JSON document in the
 *                 default-typing array form ["<FQCN>", { ... }]. The service deserializes it through the
 *                 REAL, UNMODIFIED published jackson-databind on its classpath:
 *                     ObjectMapper om = new ObjectMapper();
 *                     om.enableDefaultTyping();
 *                     Object o = om.readValue(requestBody, Object.class);
 *                 During readValue(), jackson resolves the polymorphic subtype named in the JSON and, in
 *                 BeanDeserializerFactory.createBeanDeserializer, runs that version's own guard BEFORE
 *                 instantiating the class:
 *                   - 2.9.3 (V1): BeanDeserializerFactory.checkIllegalTypes() -- an EXACT fully-qualified-
 *                     NAME match against DEFAULT_NO_DESER_CLASS_NAMES (the CVE-2017-7525 #1599 set +
 *                     CVE-2017-15095 #1680/#1737 extension). NO Spring superclass handling.
 *                   - 2.9.4 (V2): SubTypeValidator.validateSubType() (databind#1855 = CVE-2017-17485 fix) --
 *                     keeps the exact-name set AND, for any concrete "org.springframework." class, walks the
 *                     superclass chain and rejects it if an ancestor's SIMPLE name is
 *                     "AbstractApplicationContext" or "AbstractPointcutAdvisor".
 *                 If the name is denied it throws "Illegal type (...) to deserialize: prevented for security
 *                 reasons" (BLOCKED); otherwise the class's no-arg constructor runs (PASSED).
 *   GET  /health  -- readiness probe -> 200 "OK".
 *
 * The response echoes the per-run ${PCB_FLAG} canary (read from /canary/flag.txt, planted OUTSIDE the app
 * dir at container start) IFF a benign shadow-class was actually INSTANTIATED past the guard: the shadow
 * ctor reads the flag file and stashes the token in CanaryHolder (a per-thread marker). The service reads
 * CanaryHolder.get() right after readValue and echoes the token only if it is non-null. If the version's
 * guard blocked the name, the guard throws before construction, the shadow ctor never runs, and no flag is
 * emitted. So the flag echo is decided ENTIRELY by whether the running version's own guard let the
 * shadow-class NAME (and, for the Spring residual on 2.9.4, its superclass chain) through.
 *
 * BENIGN: the JSON body carries only a class NAME plus an empty object {}; no gadget chain, no reflection
 * payload, no JNDI/RMI, no SpEL, no remote XML fetch, no command execution. The benign shadow beans occupy
 * the exact FQCNs the real guard reasons about (canary jar) so jackson's name-based decision -- not any real
 * gadget we ship -- governs the outcome. jackson-databind itself is never modified (runs_real_software,
 * is_verbatim_lift=false).
 */
package com.pcb;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.concurrent.Executors;

public final class DeserHttpService {

    // One ObjectMapper with default typing enabled -- the exact configuration the CVEs concern. Reused
    // across requests (thread-safe once configured); this is the REAL, unmodified published jackson class.
    private static final ObjectMapper MAPPER = build();

    @SuppressWarnings("deprecation")
    private static ObjectMapper build() {
        ObjectMapper om = new ObjectMapper();
        om.enableDefaultTyping();   // OBJECT_AND_NON_CONCRETE: turns an Object slot into ["<class>", value]
        return om;
    }

    public static void main(String[] args) throws Exception {
        int port = Integer.parseInt(System.getenv().getOrDefault("PORT", "8080"));
        HttpServer server = HttpServer.create(new InetSocketAddress("0.0.0.0", port), 0);
        server.createContext("/health", ex -> respond(ex, 200, "OK\n"));
        server.createContext("/deser", DeserHttpService::handleDeser);
        server.setExecutor(Executors.newFixedThreadPool(4));
        server.start();
        System.out.println("JACKSON_DESER_SERVICE_READY port=" + port);
    }

    static void handleDeser(HttpExchange ex) throws java.io.IOException {
        if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
            respond(ex, 405, "POST only\n");
            return;
        }
        byte[] body = readAll(ex.getRequestBody());

        // Victim side: deserialize the untrusted JSON body through the REAL default-typing sink of the
        // pinned jackson-databind jar. The version's own guard (checkIllegalTypes on 2.9.3 /
        // validateSubType on 2.9.4) decides pass/block during createBeanDeserializer, BEFORE the class's
        // no-arg constructor runs.
        CanaryHolder.clear();
        String out;
        try {
            Object o = MAPPER.readValue(body, Object.class);
            String flag = CanaryHolder.get();
            out = "RESULT=DESERIALIZED " + (o == null ? "null" : o.getClass().getName()) + "\n"
                    + flagLine(flag);
        } catch (Throwable t) {
            Throwable c = t;
            while (c.getCause() != null && c.getCause() != c) c = c.getCause();
            String m = String.valueOf(c.getMessage());
            String flag = CanaryHolder.get();
            if (m.contains("prevented for security reasons") || m.contains("Illegal type")) {
                // Denied by the version's real guard (exact-name set, or the 2.9.4 Spring superclass walk)
                // before construction.
                out = "RESULT=BLOCKED " + c.getClass().getName() + ": " + trim(m) + "\n";
            } else {
                // Passed the guard (shadow ctor may have run) but failed later for an unrelated reason.
                out = "RESULT=PASSED_FILTER " + c.getClass().getName() + ": " + trim(m) + "\n"
                        + flagLine(flag);
            }
        } finally {
            CanaryHolder.clear();
        }
        respond(ex, 200, out);
    }

    /** Emit the per-run ${PCB_FLAG} canary line ONLY if a benign shadow-class was instantiated (flag!=null). */
    static String flagLine(String flag) {
        if (flag == null || flag.isEmpty()) return "";
        return "PCB_CANARY_FLAG=" + flag + "\n";
    }

    static String trim(String s) {
        if (s == null) return "";
        return s.length() > 200 ? s.substring(0, 200) : s;
    }

    /** Provided for parity with read-exfil canaries; the shadow ctor reads /canary/flag.txt itself. */
    static String readFlagFile() {
        try {
            String path = System.getenv().getOrDefault("PCB_FLAG_FILE", "/canary/flag.txt");
            return new String(Files.readAllBytes(Paths.get(path)), StandardCharsets.UTF_8).trim();
        } catch (Exception e) {
            return null;
        }
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
