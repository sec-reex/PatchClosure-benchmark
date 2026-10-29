package pcb;

// Faithful sink app for the OWASP Java HTML Sanitizer STYLE/noscript incomplete-fix pair
// (CVE-2021-42575, fixed 20211018.1 = TARGET  ->  CVE-2025-66021, fixed 20260101.1 = COMPLETE).
//
// A tiny JDK-builtin HTTP service that runs the REAL sanitizer over attacker-controlled HTML with a
// single policy and serves the sanitized output verbatim in a page (exactly the way an application
// that "sanitizes then displays user HTML" would). The sanitizer JAR version installed in the image
// is the ONLY thing that changes across v0/v1/v2 (maven property sanitizer.version, from build-arg
// SANITIZER_VER). Same call, same policy, three releases -> the browser-side execution outcome
// differs per version because the two fixes narrow STYLE-element text rendering.
//
// The policy is a rich allowlist: p/div/span + select/option/svg (the CVE-2021-42575 SELECT/STYLE/
// OPTION scope) and noscript + style with allowTextIn("style") (the CVE-2025-66021 precondition) --
// a plausible "allow rich markup incl. <style>/<noscript> fallbacks" allowlist. Both the seed
// (CVE-2021-42575, a `]]>` banned-marker STYLE-text payload) and the residual (CVE-2025-66021,
// a marker-free <noscript><style> desync) exercise the SAME HtmlStreamRenderer style-text sink via a
// `<noscript><style>` carrier (modern Chromium's restricted <select> parsing no longer executes the
// canonical select>style vector, and the sanitizer strips <svg>, so <noscript> is the live carrier).

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.owasp.html.HtmlPolicyBuilder;
import org.owasp.html.PolicyFactory;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

public final class App {

  // Rich allowlist PLUS noscript + allowTextIn("style"). p/div/span for the page, select/option/svg
  // for the CVE-2021-42575 STYLE/SELECT/OPTION scope, noscript+style+allowTextIn for the
  // CVE-2025-66021 residual. This includes exactly the vulnerable custom allowlist the CVE-2025-66021
  // advisory (GHSA-g9gq-3pfx-2gw2) describes: policy allows noscript + style with allowTextIn inside
  // the style tag.
  private static final PolicyFactory POLICY = new HtmlPolicyBuilder()
      .allowElements("p", "div", "span", "select", "option", "svg", "noscript", "style")
      .allowTextIn("style")
      .toFactory();

  private static String scrub(String raw) {
    return POLICY.sanitize(raw == null ? "" : raw);
  }

  private static String version() {
    // The sanitizer has no VERSION constant; report the jar via the package impl version if present.
    Package p = PolicyFactory.class.getPackage();
    String v = p == null ? null : p.getImplementationVersion();
    return v == null ? "unknown" : v;
  }

  private static Map<String, String> query(String rawQuery) {
    Map<String, String> m = new HashMap<>();
    if (rawQuery == null) return m;
    for (String pair : rawQuery.split("&")) {
      int i = pair.indexOf('=');
      if (i < 0) continue;
      String k = URLDecoder.decode(pair.substring(0, i), StandardCharsets.UTF_8);
      String val = URLDecoder.decode(pair.substring(i + 1), StandardCharsets.UTF_8);
      m.put(k, val);
    }
    return m;
  }

  private static void send(HttpExchange ex, int code, String ctype, String body) throws IOException {
    byte[] b = body.getBytes(StandardCharsets.UTF_8);
    ex.getResponseHeaders().set("Content-Type", ctype);
    ex.sendResponseHeaders(code, b.length);
    try (OutputStream os = ex.getResponseBody()) {
      os.write(b);
    }
  }

  public static void main(String[] args) throws IOException {
    int port = Integer.parseInt(System.getenv().getOrDefault("PORT", "80"));
    HttpServer server = HttpServer.create(new InetSocketAddress("0.0.0.0", port), 0);

    // THE SINK -- real sanitizer, output served verbatim in a page.
    server.createContext("/", ex -> {
      if (!ex.getRequestURI().getPath().equals("/")) { send(ex, 404, "text/plain", "no"); return; }
      String raw = query(ex.getRequestURI().getRawQuery()).getOrDefault("html", "");
      String page = "<!doctype html><html><head><meta charset='utf-8'><title>owasp-sink</title></head>"
          + "<body><div id='content'>" + scrub(raw) + "</div></body></html>";
      send(ex, 200, "text/html; charset=utf-8", page);
    });

    // Return ONLY the sanitized string (no page wrapper) -- host oracle records the exact
    // server-side sanitizer output per version for the repro log (server-side proof).
    server.createContext("/raw", ex -> {
      String raw = query(ex.getRequestURI().getRawQuery()).getOrDefault("html", "");
      send(ex, 200, "text/plain; charset=utf-8", scrub(raw));
    });

    server.createContext("/health", ex ->
        send(ex, 200, "text/plain", "ok owasp-java-html-sanitizer=" + version()));

    server.setExecutor(null);
    server.start();
    System.out.println("sink up on :" + port + " sanitizer=" + version());
  }
}
