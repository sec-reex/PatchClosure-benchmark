import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import org.hl7.fhir.dstu2.model.StringType;
import org.hl7.fhir.dstu2.utils.FHIRPathEngine;
import org.hl7.fhir.exceptions.FHIRException;

/**
 * Rebuilt harness (ROUND9): evaluates user-supplied FHIRPath expressions via the
 * REAL published ca.uhn.hapi.fhir:org.hl7.fhir.dstu2 engine, synchronously in the
 * HTTP handler thread (so a catastrophic regex starves the server = latency oracle).
 */
public class Server {
    public static void main(String[] args) throws IOException {
        int port = Integer.parseInt(System.getenv().getOrDefault("PORT", "8080"));
        HttpServer server = HttpServer.create(new java.net.InetSocketAddress(port), 0);
        ExecutorService pool = Executors.newFixedThreadPool(1);
        server.setExecutor(pool);
        server.createContext("/health", exchange -> {
            byte[] resp = "{\"ok\":true}".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, resp.length);
            try (OutputStream os = exchange.getResponseBody()) { os.write(resp); }
        });
        server.createContext("/eval", new EvalHandler());
        server.start();
        System.out.println("fhirpath harness listening on :" + port);
    }

    static class EvalHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            byte[] body = exchange.getRequestBody().readAllBytes();
            String raw = new String(body, StandardCharsets.UTF_8);
            long t0 = System.currentTimeMillis();
            String result;
            int status = 200;
            try {
                var obj = new com.google.gson.JsonParser().parse(raw).getAsJsonObject();
                String expr = obj.get("expr").getAsString();
                String input = obj.has("input") ? obj.get("input").getAsString() : "";
                FHIRPathEngine engine = new FHIRPathEngine(null);
                Object eval = engine.evaluate(new StringType(input), expr);
                result = String.valueOf(eval);
            } catch (Exception e) {
                status = 400;
                result = "exception:" + (e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName());
            }
            long ms = System.currentTimeMillis() - t0;
            String out = "{\"result\":" + jsonEscape(result) + ",\"server_ms\":" + ms + "}";
            byte[] resp = out.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(status, resp.length);
            try (OutputStream os = exchange.getResponseBody()) { os.write(resp); }
        }

        private static String jsonEscape(String s) {
            return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n") + "\"";
        }
    }
}
