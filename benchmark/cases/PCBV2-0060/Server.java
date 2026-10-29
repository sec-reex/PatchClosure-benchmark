// PatchClosure-Bench REAL HTTP upload service (NOT part of org.hl7.fhir code).
// A com.sun.net.httpserver.HttpServer that accepts an EXTERNAL HTTP zip upload
// (POST /unzip, raw application/zip body) and extracts it with the REAL,
// unmodified org.hl7.fhir.r4b.terminologies.TerminologyCacheManager.unzip(is,
// targetDir) sink -- the exact archive-extraction path guarded by the
// CVE-2023-24057 fix (String.startsWith) and hardened by CVE-2023-28465
// (Path#startsWith). This mirrors a real FHIR tool extracting a user-supplied
// package / tx-cache zip. We only invoke the library API; we do not reimplement
// or edit it.
//
// Per request: a FRESH temp base dir is created (so the sibling dir is reset
// between probes); extraction root (cacheFolder / targetDir) = <base>/cache/tx-cache.
// After extraction we walk <base> and report every regular file that landed
// OUTSIDE the extraction root == a zip-slip escape, returning its name+content.
// The per-run ${PCB_FLAG} canary is supplied ONLY by the uploader as the
// escaping entry's content; the server never hard-codes it.
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Stream;
import org.hl7.fhir.r4b.terminologies.TerminologyCacheManager;

public class Server {
  public static void main(String[] args) throws Exception {
    int port = Integer.parseInt(System.getenv().getOrDefault("PORT", "8080"));
    HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
    server.createContext("/unzip", Server::handleUnzip);
    server.createContext("/", ex -> respond(ex, 200,
        "{\"status\":\"ok\",\"service\":\"fhir-tx-cache-unzip\"}"));
    server.setExecutor(null);
    server.start();
    System.out.println("LISTENING on " + port);
  }

  static void handleUnzip(HttpExchange ex) throws java.io.IOException {
    if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
      respond(ex, 405, "{\"error\":\"POST a raw zip body to /unzip\"}");
      return;
    }
    byte[] body;
    try (InputStream in = ex.getRequestBody()) {
      body = in.readAllBytes();
    }
    Path base = Files.createTempDirectory("pcb_");
    // cacheFolder == the extraction root the CVE-2023-24057 guard confines writes to
    Path target = base.resolve("cache").resolve("tx-cache");
    Files.createDirectories(target);
    Path zip = base.resolve("upload.zip");
    Files.write(zip, body);

    String status;
    try (InputStream is = Files.newInputStream(zip)) {
      // REAL, unmodified library sink -- the same call a FHIR tool uses to
      // extract a downloaded package / terminology-cache zip.
      TerminologyCacheManager.unzip(is, target.toString());
      status = "extracted";
    } catch (Throwable t) {
      String msg = t.getMessage();
      status = "blocked:" + t.getClass().getSimpleName() + (msg != null ? ":" + msg : "");
    }

    List<String> escaped = new ArrayList<>();
    Path targetReal = target.toRealPath();
    try (Stream<Path> walk = Files.walk(base)) {
      for (Path p : (Iterable<Path>) walk::iterator) {
        if (!Files.isRegularFile(p)) continue;
        if (p.equals(zip)) continue;                 // the uploaded archive itself
        Path real = p.toRealPath();
        if (real.startsWith(targetReal)) continue;   // inside extraction root => contained, OK
        String name = base.relativize(p).toString();
        String content = new String(Files.readAllBytes(p), StandardCharsets.UTF_8)
            .replace("\r", " ").replace("\n", " ").trim();
        escaped.add("{\"name\":\"" + jsonEsc(name) + "\",\"content\":\"" + jsonEsc(content) + "\"}");
      }
    }

    String out = "{\"unzip_status\":\"" + jsonEsc(status.replace("\n", " ")) + "\","
        + "\"target\":\"" + jsonEsc(target.toString()) + "\","
        + "\"escaped_files\":[" + String.join(",", escaped) + "]}";

    deleteRec(base);
    respond(ex, 200, out);
  }

  static void respond(HttpExchange ex, int code, String body) {
    try {
      byte[] b = body.getBytes(StandardCharsets.UTF_8);
      ex.getResponseHeaders().set("Content-Type", "application/json");
      ex.sendResponseHeaders(code, b.length);
      try (OutputStream os = ex.getResponseBody()) { os.write(b); }
    } catch (Exception ignore) {
    } finally {
      ex.close();
    }
  }

  static void deleteRec(Path root) {
    try (Stream<Path> walk = Files.walk(root)) {
      walk.sorted(Comparator.reverseOrder()).forEach(p -> {
        try { Files.deleteIfExists(p); } catch (Exception ignore) {}
      });
    } catch (Exception ignore) {}
  }

  static String jsonEsc(String s) {
    if (s == null) return "";
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      switch (c) {
        case '"': sb.append("\\\""); break;
        case '\\': sb.append("\\\\"); break;
        case '\n': sb.append(" "); break;
        case '\r': sb.append(" "); break;
        case '\t': sb.append(" "); break;
        default:
          if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
          else sb.append(c);
      }
    }
    return sb.toString();
  }
}
