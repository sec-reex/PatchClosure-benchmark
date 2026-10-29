package pcb;

import com.hubspot.jinjava.Jinjava;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * RenderService — a REAL small HTTP application that renders user-supplied Jinjava
 * templates. It mirrors a web app that accepts a template over the network and
 * returns the rendered result.
 *
 *   GET  /health  -> "ok"                 (readiness probe)
 *   POST /render  -> body = a Jinjava template; response = new Jinjava().render(body, {})
 *
 * jinjava is a REAL published dependency (com.hubspot.jinjava:jinjava:${JINJAVA_VER})
 * on the classpath — pulled from Maven Central at build time, NOT source-lifted.
 * A benign per-run ${PCB_FLAG} canary file is planted at /flag by the entrypoint,
 * OUTSIDE the application code. The default Jinjava sandbox forbids file access, so
 * the flag can only appear in an HTTP response if a genuine sandbox escape reads it.
 */
public final class RenderService {

  public static void main(String[] args) throws IOException {
    int port = 8080;
    String p = System.getenv("PORT");
    if (p != null && !p.isEmpty()) {
      port = Integer.parseInt(p.trim());
    }
    HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
    server.createContext("/health", ex -> respond(ex, 200, "ok"));
    server.createContext("/render", RenderService::handleRender);
    server.setExecutor(null);
    server.start();
    System.out.println("jinjava render service listening on :" + port);
  }

  private static void handleRender(HttpExchange ex) throws IOException {
    if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
      respond(ex, 405, "POST /render only");
      return;
    }
    String template;
    try (InputStream is = ex.getRequestBody()) {
      template = new String(is.readAllBytes(), StandardCharsets.UTF_8);
    }
    String out;
    try {
      // A fresh, default-configured Jinjava per request (default sandbox).
      Jinjava jinjava = new Jinjava();
      Map<String, Object> ctx = new HashMap<>();
      out = jinjava.render(template, ctx);
    } catch (Throwable t) {
      out = "RENDER_ERROR: " + t;
    }
    respond(ex, 200, out);
  }

  private static void respond(HttpExchange ex, int code, String body) throws IOException {
    byte[] b = body.getBytes(StandardCharsets.UTF_8);
    ex.sendResponseHeaders(code, b.length == 0 ? -1 : b.length);
    try (OutputStream os = ex.getResponseBody()) {
      os.write(b);
    }
  }

  private RenderService() {}
}
