/*
 * REAL Java HTTP service for xstream-cve-2020-26217.
 *
 * A tiny, self-contained HTTP service (JDK built-in com.sun.net.httpserver.HttpServer) that mirrors a
 * real service which deserializes an untrusted XML request body through XStream -- the classic XStream
 * fromXML() RCE surface. It exposes:
 *
 *   POST /deser   (Content-Type: text/xml) -- body = an attacker-controlled XML document. The service
 *                 deserializes it through the REAL, UNMODIFIED published XStream on its classpath:
 *                     XStream xs = new XStream();          // version's OWN default security
 *                     xs.registerConverter(new CanaryConverter());  // benign echo for pcb.PcbCanary
 *                     Object o = xs.fromXML(requestBody);
 *                 During fromXML(), XStream resolves each type NAME in the document and runs THAT
 *                 version's own default deny-list (XStream.setupSecurity() -> TypePermission /
 *                 ForbiddenClassException) BEFORE processing the type. If a name is denied it throws
 *                 ForbiddenClassException (BLOCKED); otherwise the type is processed (PASSED).
 *   GET  /health  -- readiness probe -> 200 "OK".
 *
 * The attacker XML body is <list><TRIGGER_TYPE/><pcb.PcbCanary/></list>: XStream deny-checks
 * TRIGGER_TYPE first, and ONLY if it is permitted does it reach the trailing benign <pcb.PcbCanary/>
 * element, whose registered CanaryConverter reads the per-run ${PCB_FLAG} canary (planted OUTSIDE the
 * app dir at container start) and stashes it in CanaryHolder. The service reads CanaryHolder.get()
 * right after fromXML() and echoes the token IFF a benign canary bean was actually reached past the
 * deny-list. If the version's deny-list blocked the trigger name, fromXML() throws
 * ForbiddenClassException before the canary element, the converter never runs, and no flag is emitted.
 * So the flag echo is decided ENTIRELY by whether the running version's own default deny-list let the
 * trigger type NAME through -- exactly the guard the CVE-2013-7285 / CVE-2020-26217 lineage concerns.
 *
 * BENIGN: no gadget chain is assembled. TRIGGER_TYPE is materialised only as a blank instance -- no
 * ProcessBuilder, no dynamic proxy, no EventHandler target method, no JNDI/RMI, no command execution.
 * The only side effect past the guard is echoing a random per-run canary token. XStream itself is
 * never modified (runs_real_software; the CanaryConverter only handles the benign pcb.PcbCanary marker
 * and touches no XStream security code).
 */
package com.pcb;

import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.converters.Converter;
import com.thoughtworks.xstream.converters.MarshallingContext;
import com.thoughtworks.xstream.converters.UnmarshallingContext;
import com.thoughtworks.xstream.io.HierarchicalStreamReader;
import com.thoughtworks.xstream.io.HierarchicalStreamWriter;
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

public final class XStreamDeserHttpService {

    /**
     * Benign converter for the pcb.PcbCanary marker: reads the planted canary flag when (and only when)
     * XStream actually REACHES a <pcb.PcbCanary/> element -- i.e. after the guarded trigger type that
     * precedes it passed the version's deny check. It stashes the token in CanaryHolder for the same
     * request thread. Registered on the per-request XStream; touches NO XStream security code.
     */
    public static final class CanaryConverter implements Converter {
        @SuppressWarnings("rawtypes")
        public boolean canConvert(Class type) {
            return type != null && "pcb.PcbCanary".equals(type.getName());
        }

        public void marshal(Object value, HierarchicalStreamWriter writer, MarshallingContext ctx) {
            /* not used */
        }

        public Object unmarshal(HierarchicalStreamReader reader, UnmarshallingContext ctx) {
            try {
                String path = System.getenv().getOrDefault("PCB_FLAG_FILE", "/canary/flag.txt");
                byte[] b = Files.readAllBytes(Paths.get(path));
                CanaryHolder.set(new String(b, StandardCharsets.UTF_8).trim());
            } catch (Throwable ignore) {
                /* canary file absent (build time) -> harmless no-op */
            }
            return new pcb.PcbCanary();
        }
    }

    public static void main(String[] args) throws Exception {
        int port = Integer.parseInt(System.getenv().getOrDefault("PORT", "8080"));
        HttpServer server = HttpServer.create(new InetSocketAddress("0.0.0.0", port), 0);
        server.createContext("/health", ex -> respond(ex, 200, "OK\n"));
        server.createContext("/deser", XStreamDeserHttpService::handleDeser);
        server.setExecutor(Executors.newFixedThreadPool(4));
        server.start();
        System.out.println("XSTREAM_DESER_SERVICE_READY port=" + port);
    }

    static void handleDeser(HttpExchange ex) throws java.io.IOException {
        if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
            respond(ex, 405, "POST only\n");
            return;
        }
        byte[] body = readAll(ex.getRequestBody());
        String xml = new String(body, StandardCharsets.UTF_8);

        // Victim side: deserialize the untrusted XML body through the REAL fromXML() sink of the pinned
        // XStream jar with the version's OWN default security (setupSecurity()). The version's own
        // deny-list decides pass/block on each named type during fromXML(), BEFORE the type is processed.
        CanaryHolder.clear();
        String out;
        try {
            XStream xstream = new XStream();                 // REAL, unmodified default security
            xstream.registerConverter(new CanaryConverter()); // benign echo for the pcb.PcbCanary marker
            Object o = xstream.fromXML(xml);
            String flag = CanaryHolder.get();
            out = "RESULT=DESERIALIZED " + (o == null ? "null" : o.getClass().getName()) + "\n"
                    + flagLine(flag);
        } catch (Throwable t) {
            String chain = causeChain(t);
            Throwable c = deepest(t);
            String m = String.valueOf(c.getMessage());
            String flag = CanaryHolder.get();
            if (chain.contains("ForbiddenClassException")) {
                // Denied by the version's real default deny-list (setupSecurity) before processing.
                out = "RESULT=BLOCKED " + c.getClass().getName() + ": " + trim(m) + "\n";
            } else {
                // Passed the deny-list (canary may have run) but failed later for an unrelated reason.
                out = "RESULT=PASSED_FILTER " + c.getClass().getName() + ": " + trim(m) + "\n"
                        + flagLine(flag);
            }
        } finally {
            CanaryHolder.clear();
        }
        respond(ex, 200, out);
    }

    /** Emit the per-run ${PCB_FLAG} canary line ONLY if a benign canary bean was reached (flag!=null). */
    static String flagLine(String flag) {
        if (flag == null || flag.isEmpty()) return "";
        return "PCB_CANARY_FLAG=" + flag + "\n";
    }

    /** Full "ClassName: message" chain, so a ForbiddenClassException anywhere in the causes is detected. */
    static String causeChain(Throwable t) {
        StringBuilder sb = new StringBuilder();
        Throwable c = t;
        int guard = 0;
        while (c != null && guard++ < 20) {
            sb.append(c.getClass().getName()).append(": ").append(c.getMessage()).append(" | ");
            if (c.getCause() == c) break;
            c = c.getCause();
        }
        return sb.toString();
    }

    static Throwable deepest(Throwable t) {
        Throwable c = t;
        int guard = 0;
        while (c.getCause() != null && c.getCause() != c && guard++ < 20) c = c.getCause();
        return c;
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
