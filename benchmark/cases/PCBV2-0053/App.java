/*
 * Faithful sink app for the OWASP AntiSamy PRESERVE-COMMENTS mutation-XSS incomplete-fix pair
 * (CVE-2023-43643 partial fix in 1.7.4 = TARGET  ->  CVE-2024-23635 complete fix in 1.7.5).
 *
 * A tiny JDK-builtin HTTP server that runs the REAL OWASP AntiSamy sanitizer:
 *
 *     new AntiSamy().scan(userHtml, policy, AntiSamy.DOM).getCleanHTML()
 *
 * on attacker-controlled HTML and serves the *sanitized* output verbatim inside a page (exactly the
 * way an application that "sanitizes then displays user HTML" would). The AntiSamy VERSION pinned in
 * the image IS the only thing that changes between v0/v1/v2 (build-arg ANTISAMY_VER) -- the sink code
 * and the policy (antisamy.xml with preserveComments=true) are identical across all three. That
 * is the whole point: same call, same policy, three consecutive AntiSamy releases, and the
 * browser-side execution outcome differs per version because the comment-handling in the transitive
 * neko-htmlunit parser + the serializer changed:
 *   v0 1.7.3  neko 3.1.0: raw-text + bang-comment breakouts both survive -> mXSS
 *   v1 1.7.4  neko 3.6.0: raw-text breakout fixed, bang-comment --!> still mishandled -> partial fix
 *   v2 1.7.5  neko 3.11.1: both breakouts fixed -> complete
 */
import java.io.*;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import com.sun.net.httpserver.*;
import org.owasp.validator.html.AntiSamy;
import org.owasp.validator.html.CleanResults;
import org.owasp.validator.html.Policy;

public class App {
    static Policy POLICY;

    public static void main(String[] args) throws Exception {
        POLICY = Policy.getInstance(new File("/app/antisamy.xml"));
        int port = Integer.parseInt(System.getenv().getOrDefault("PORT", "80"));
        HttpServer server = HttpServer.create(new InetSocketAddress("0.0.0.0", port), 0);
        server.createContext("/", App::index);
        server.createContext("/raw", App::raw);
        server.createContext("/health", App::health);
        server.setExecutor(java.util.concurrent.Executors.newFixedThreadPool(8));
        server.start();
        System.out.println("antisamy sink up on :" + port);
    }

    static String param(HttpExchange ex, String key) {
        String q = ex.getRequestURI().getRawQuery();
        if (q == null) return "";
        for (String kv : q.split("&")) {
            int i = kv.indexOf('=');
            String k = i < 0 ? kv : kv.substring(0, i);
            String v = i < 0 ? "" : kv.substring(i + 1);
            if (k.equals(key)) {
                try { return java.net.URLDecoder.decode(v, "UTF-8"); }
                catch (Exception e) { return v; }
            }
        }
        return "";
    }

    static String clean(String raw) {
        try {
            CleanResults cr = new AntiSamy().scan(raw, POLICY, AntiSamy.DOM);
            return cr.getCleanHTML();
        } catch (Throwable t) {
            return "<!-- scan-error: " + t.getClass().getSimpleName() + " -->";
        }
    }

    static void send(HttpExchange ex, int code, String body, String ctype) throws IOException {
        byte[] b = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", ctype);
        ex.sendResponseHeaders(code, b.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(b); }
    }

    // THE SINK -- real AntiSamy output rendered verbatim into a normal HTML document.
    static void index(HttpExchange ex) throws IOException {
        String sanitized = clean(param(ex, "html"));
        String page = "<!doctype html><html><head><meta charset='utf-8'><title>antisamy-sink</title></head>"
                + "<body><div id='content'>" + sanitized + "</div></body></html>";
        send(ex, 200, page, "text/html; charset=utf-8");
    }

    // Server-side proof: ONLY the sanitized string (no page wrapper) for the repro log.
    static void raw(HttpExchange ex) throws IOException {
        send(ex, 200, clean(param(ex, "html")), "text/plain; charset=utf-8");
    }

    static void health(HttpExchange ex) throws IOException {
        String v = App.class.getPackage() == null ? "" : "";
        send(ex, 200, "ok antisamy sink", "text/plain; charset=utf-8");
    }
}
