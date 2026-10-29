/*
 * Faithful-core harness for Spring Framework's UriComponentsBuilder host-validation bypass
 * (CVE-2024-22243  ->  CVE-2024-22259), an OPEN REDIRECT / SSRF parser-differential (CWE-601).
 *
 * This models the REAL vulnerable application pattern that both CVEs target: an app validates a
 * user-supplied redirect URL by parsing it with Spring's UriComponentsBuilder and inspecting
 * getHost() against an allowlist, then (if "valid") emits that URL in a Location header. Because
 * Spring's regex-based parser extracts a DIFFERENT host than a browser / downstream HTTP client
 * resolves, a crafted URL can make getHost() return the allowed host ("trusted.internal") while
 * the URL actually navigates the browser to the attacker host ("attacker.test").
 *
 * The parser itself is NOT lifted or re-implemented here: the harness depends on the genuine
 * `org.springframework.web.util.UriComponentsBuilder` from spring-web:${SPRING_VER} on the
 * classpath (build-arg SPRING_VER = 5.3.31 / 5.3.32 / 5.3.33). The only thing that changes across
 * the three images is which spring-web JAR is on the classpath -- the app code is byte-identical.
 *
 *   SPRING_VER=5.3.31  V0 (pre CVE-2024-22243):  USERINFO_PATTERN "([^@\[/?#]*)"  HOST_IPV4 "[^\[/?#:]*"
 *   SPRING_VER=5.3.32  V1 (CVE-2024-22243 fix, TARGET, commit 7ec5c994): USERINFO "([^@/?#]*)"  (removed \[),
 *                      HOST_IPV4 unchanged "[^\[/?#:]*"  -- fixes the original input but NOT the residual.
 *   SPRING_VER=5.3.33  V2 (CVE-2024-22259 fix, commit 297cbae2): USERINFO "([^/?#]*)" (removed @),
 *                      HOST_IPV4 "[^/?#:]*" (removed \[)  -- fixes the residual too.
 *
 * Route: GET /redirect?url=<urlencoded target>. The app URL-decodes `url`, parses it with
 * UriComponentsBuilder.fromUriString(url).build(), and reads getHost(). If getHost().equals the
 * single allowlisted host "trusted.internal", it APPROVES and returns 302 with Location: <target>
 * (the raw decoded target, unchanged). Otherwise 403 "blocked" with a body that does NOT echo the
 * target. Redirect-canary: the per-run ${PCB_FLAG} rides in the target's QUERY STRING, so the flag
 * token appears in the emitted Location header IFF the guard approved steering off-origin. A blocked
 * request never surfaces the flag. Nothing is planted in app code.
 */
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

public class Harness {

    static final int APP_PORT = Integer.parseInt(System.getenv().getOrDefault("APP_PORT", "8080"));
    // The single trusted/allowlisted host. Only redirects whose PARSED host equals this are approved.
    static final String ALLOWED_HOST = System.getenv().getOrDefault("ALLOWED_HOST", "trusted.internal");

    /* ---- the faithful vulnerable decision: validate by UriComponentsBuilder.getHost() ---------- *
     * Returns the approved redirect target (echoing `url` unchanged) iff the Spring parser extracts
     * host == ALLOWED_HOST; returns null (=> blocked) otherwise. This is exactly the pattern the
     * spring.io advisories describe as vulnerable ("using UriComponentsBuilder to parse an externally
     * provided URL in order to validate its host"). */
    static String approveRedirect(String url) {
        if (url == null || url.isEmpty()) {
            return null;
        }
        String parsedHost;
        try {
            UriComponents uc = UriComponentsBuilder.fromUriString(url).build();
            parsedHost = uc.getHost();
        } catch (Exception e) {
            return null; // unparseable -> reject
        }
        if (parsedHost != null && parsedHost.equals(ALLOWED_HOST)) {
            return url; // allowlist passed -> approve, emit Location: <url>
        }
        return null;
    }

    // ---- HTTP layer (canary observation only; not part of the faithful core) -------------------
    static String queryParam(String rawQuery, String key) {
        if (rawQuery == null) return null;
        for (String pair : rawQuery.split("&")) {
            int eq = pair.indexOf('=');
            String k = (eq >= 0) ? pair.substring(0, eq) : pair;
            if (k.equals(key)) {
                String v = (eq >= 0) ? pair.substring(eq + 1) : "";
                try { return URLDecoder.decode(v, StandardCharsets.UTF_8.name()); }
                catch (Exception e) { return v; }
            }
        }
        return null;
    }

    public static void main(String[] args) throws Exception {
        String springVer = System.getenv().getOrDefault("SPRING_VER", "?");
        HttpServer server = HttpServer.create(new InetSocketAddress(APP_PORT), 0);
        server.createContext("/healthz", ex -> respond(ex, 200, "ok", springVer, null));
        // Debug endpoint: report the host UriComponentsBuilder extracts (used in repro.log evidence).
        server.createContext("/host", ex -> {
            String target = queryParam(ex.getRequestURI().getRawQuery(), "url");
            String host;
            try { host = UriComponentsBuilder.fromUriString(target).build().getHost(); }
            catch (Exception e) { host = "<parse-error:" + e.getClass().getSimpleName() + ">"; }
            respond(ex, 200, "getHost=" + host, springVer, null);
        });
        server.createContext("/redirect", ex -> {
            String target = queryParam(ex.getRequestURI().getRawQuery(), "url");
            String approved = approveRedirect(target);
            if (approved != null) {
                // Approved: Location is the raw target, carrying the flag in its query string. A browser
                // resolves this off-origin to attacker.test even though getHost() said trusted.internal.
                ex.getResponseHeaders().add("Location", approved);
                ex.getResponseHeaders().add("X-PCB-Spring-Version", springVer);
                respond(ex, 302, "redirecting", springVer, null);
            } else {
                // Blocked: never echo the target (it carries the flag label).
                respond(ex, 403, "blocked", springVer, null);
            }
        });
        server.setExecutor(null);
        server.start();
        System.out.println("[harness spring-web " + springVer + "] listening on " + APP_PORT
                + " allow=" + ALLOWED_HOST);
    }

    static void respond(HttpExchange ex, int code, String body, String ver, String unused)
            throws java.io.IOException {
        if (ver != null) ex.getResponseHeaders().add("X-PCB-Spring-Version", ver);
        byte[] b = body.getBytes(StandardCharsets.UTF_8);
        ex.sendResponseHeaders(code, b.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(b); }
    }
}
