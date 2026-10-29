/*
 * REAL Java HTTP service for deser_sofahessian_blacklist.
 *
 * A tiny, self-contained HTTP service (JDK built-in com.sun.net.httpserver.HttpServer) that mirrors how a
 * SOFA-RPC service deserializes a Hessian request body. It exposes:
 *
 *   POST /deser   -- body = raw Hessian2-serialized bytes of an attacker-crafted stream. The service reads
 *                    the whole body and deserializes it through the REAL, UNMODIFIED SOFA Hessian default
 *                    class-name blacklist:
 *                        SerializerFactory rf = new SerializerFactory();
 *                        rf.setClassNameResolver(ClassNameResolverBuilder.buildDefault());  // the version's
 *                                                                                           // bundled
 *                                                                                           // security/serialize.blacklist
 *                        new Hessian2Input(body).setSerializerFactory(rf).readObject();
 *                    During readObject(), Hessian calls SerializerFactory.getDeserializer(typeName) ->
 *                    ClassNameResolver.resolve(typeName) -> NameBlackListFilter.inBlackList(): a case-sensitive
 *                    className.startsWith(prefix) over the pinned jar's blacklist. If the name is denied the
 *                    filter throws "Class <name> is in blacklist." BEFORE the object is decoded (BLOCKED);
 *                    otherwise decoding proceeds (PASSED).
 *   GET  /health  -- readiness probe -> 200 "OK".
 *
 * The response echoes the per-run ${PCB_FLAG} canary (read from /canary/flag.txt, planted OUTSIDE the app
 * dir at container start) IFF deserialization got PAST the blacklist filter -- i.e. the class NAME passed the
 * real, unmodified NameBlackListFilter. If the filter blocks the name, the response says RESULT=BLOCKED and
 * NO flag is emitted. This is the benign shadow-class observation: the flag echo is decided ENTIRELY by
 * whether the running version's own bundled blacklist let the shadow-class name through.
 *
 * BENIGN: the request stream carries only a class NAME plus a tiny 2-string map (see attacker/StreamGen.java);
 * no gadget chain, no reflection payload, no command execution. The only side effect is echoing the per-run
 * canary token when the real blacklist passes the name. The benign canary bean com.caucho.naming.Qname is on
 * the classpath (canary jar) so the ORIGINAL shadow-class name is a genuinely resolvable class; the residual
 * name com.sun.org.apache.xpath.internal.objects.XString already exists in the JDK (java.xml module), so the
 * filter's name-based decision -- not any class we ship -- is what governs the outcome (documented in README).
 */
package com.pcb;

import com.caucho.hessian.io.Hessian2Input;
import com.caucho.hessian.io.SerializerFactory;
import com.alipay.hessian.ClassNameResolverBuilder;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.concurrent.Executors;

public final class HessianDeserService {

    public static void main(String[] args) throws Exception {
        int port = Integer.parseInt(System.getenv().getOrDefault("PORT", "8080"));
        HttpServer server = HttpServer.create(new InetSocketAddress("0.0.0.0", port), 0);
        server.createContext("/health", ex -> respond(ex, 200, "OK\n"));
        server.createContext("/deser", HessianDeserService::handleDeser);
        server.setExecutor(Executors.newFixedThreadPool(4));
        server.start();
        System.out.println("HESSIAN_DESER_SERVICE_READY port=" + port);
    }

    static void handleDeser(HttpExchange ex) throws java.io.IOException {
        if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
            respond(ex, 405, "POST only\n");
            return;
        }
        byte[] body = readAll(ex.getRequestBody());

        // Victim side: deserialize the request body through the REAL default blacklist resolver of the
        // pinned sofa-hessian jar -- exactly the resolve() gate SerializerFactory.getDeserializer applies
        // during Hessian2Input.readObject().
        SerializerFactory rf = new SerializerFactory();
        rf.setClassNameResolver(ClassNameResolverBuilder.buildDefault());
        Hessian2Input in = new Hessian2Input(new ByteArrayInputStream(body));
        in.setSerializerFactory(rf);

        String out;
        try {
            Object o = in.readObject();
            out = "RESULT=DESERIALIZED " + (o == null ? "null" : o.getClass().getName()) + "\n" + flagLine();
        } catch (Throwable t) {
            String m = String.valueOf(t.getMessage());
            Throwable c = t.getCause();
            String cm = (c == null) ? "" : String.valueOf(c.getMessage());
            if (m.contains("is in blacklist") || cm.contains("is in blacklist")) {
                // Denied by the version's real blacklist BEFORE decoding -> no flag.
                out = "RESULT=BLOCKED " + t.getClass().getName() + ": " + m + "\n";
            } else {
                // Passed the blacklist filter but failed later for an unrelated reason -> filter PASSED.
                out = "RESULT=PASSED_FILTER " + t.getClass().getName() + ": " + m + "\n" + flagLine();
            }
        }
        respond(ex, 200, out);
    }

    /** Read the per-run ${PCB_FLAG} canary planted OUTSIDE the app dir; emitted only past the filter. */
    static String flagLine() {
        try {
            String path = System.getenv().getOrDefault("PCB_FLAG_FILE", "/canary/flag.txt");
            String flag = new String(Files.readAllBytes(Paths.get(path)), StandardCharsets.UTF_8).trim();
            return "PCB_CANARY_FLAG=" + flag + "\n";
        } catch (Exception e) {
            return "PCB_CANARY_READ_FAIL=" + e + "\n";
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
