// PatchClosure-Bench faithful-core driver for undertow-jboss-wildfly-web-server-cve-2018-1067.
//
// A REAL Undertow HTTP server, published on a host port. Its handler reflects an
// attacker-controlled request query parameter `v` straight into the VALUE of a response header
// (X-Reflect) via the REAL, unmodified Undertow API (HeaderMap.put). The value is serialized onto
// the wire by the version's REAL io.undertow.server.protocol.http.HttpResponseConduit.writeString(...)
// -- the exact sink guarded by CVE-2016-4993 (char-based CR/LF check, added 1.4.3.Final) and
// re-guarded by CVE-2018-1067 (byte-narrowed check, added 1.4.25.Final, commit 85d4478). No Undertow
// code is modified: the version's own writeString decides whether a CRLF injected into the header
// value splits the response on the wire.
//
// The trigger is fully EXTERNAL: the server binds 0.0.0.0:${APP_PORT} (published to the host), and an
// external client opens a raw TCP socket to the published port and sends one GET /reflect?v=... whose
// value carries the CR/LF (or the truncating char whose low byte is 0x0D/0x0A) URL-encoded. Undertow
// URL-decodes it (UTF-8) into the header value String. This isolates the test to the RESPONSE-side
// writeString guard -- exactly the CWE-113 response-splitting sink both CVEs touch.
import io.undertow.Undertow;
import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;
import io.undertow.util.HttpString;

import java.util.Deque;

public final class ReflectServer {
    public static void main(String[] args) {
        int port = Integer.parseInt(System.getenv().getOrDefault("APP_PORT", "8080"));
        final HttpString reflectName = HttpString.tryFromString("X-Reflect");
        Undertow server = Undertow.builder()
                .addHttpListener(port, "0.0.0.0")
                .setHandler(new HttpHandler() {
                    @Override public void handleRequest(HttpServerExchange exchange) {
                        String v = "";
                        Deque<String> q = exchange.getQueryParameters().get("v");
                        if (q != null && !q.isEmpty()) {
                            v = q.getFirst();
                        }
                        // REAL Undertow API: an attacker-influenced value flows into a response
                        // header value. No app-side sanitization -- the version's writeString is
                        // the only guard.
                        exchange.getResponseHeaders().put(reflectName, v);
                        exchange.getResponseSender().send("ok");
                    }
                })
                .build();
        server.start();
        System.out.println("ReflectServer up on 0.0.0.0:" + port);
    }
}
