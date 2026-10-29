/*
 * Real-library-wrap HTTP service for the cyclonedx-core-java XXE incomplete-fix pair
 * (CVE-2024-38374 parser fix in 9.0.4  ->  CVE-2025-64518 validator fix in 11.0.1).
 *
 * A tiny JDK-builtin HTTP server that hands the attacker-supplied request-body XML SBOM straight to
 * the REAL org.cyclonedx.parsers.XmlParser of the pinned cyclonedx-core-java version:
 *
 *     POST /parse      ->  new XmlParser().parse(bodyBytes)         (the XML BOM PARSER path)
 *     POST /validate   ->  new XmlParser().validate(bodyBytes)      (the XML BOM VALIDATOR path)
 *
 * The ONLY thing that changes between v0/v1/v2 images is the pinned cyclonedx-core-java version
 * (build-arg CDX_VER -> -Dcdx.version). Everything the service does is identical across versions.
 * The browser-free, benign local-file-read oracle: a malicious SBOM whose external DTD/entity reads
 * file:///flag; if the REAL library resolves it, the flag content surfaces in the library's own
 * error/exception text (error-based XXE), which we echo verbatim in the HTTP response.
 *
 * Differential (see case.json):
 *   /parse    : XXE resolves on v0 (8.0.0, insecure XPath DocumentBuilder) -> flag;
 *               blocked on v1 (9.0.4, createSecureDocument sets ACCESS_EXTERNAL_DTD="").
 *   /validate : XXE resolves on v0 AND v1 (getXmlSchema SchemaFactory left unhardened until 11.0.1,
 *               so the spawned javax.xml.validation.Validator resolves external entities) -> flag;
 *               blocked on v2 (11.0.1, getXmlSchema sets ACCESS_EXTERNAL_DTD/SCHEMA="" +
 *               FEATURE_SECURE_PROCESSING, which propagate to the Validator).
 */
import java.io.*;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import com.sun.net.httpserver.*;
import org.cyclonedx.parsers.XmlParser;
import org.cyclonedx.exception.ParseException;

public class App {

    public static void main(String[] args) throws Exception {
        int port = Integer.parseInt(System.getenv().getOrDefault("PORT", "80"));
        HttpServer server = HttpServer.create(new InetSocketAddress("0.0.0.0", port), 0);
        server.createContext("/parse", App::parse);
        server.createContext("/validate", App::validate);
        server.createContext("/health", App::health);
        server.setExecutor(java.util.concurrent.Executors.newFixedThreadPool(8));
        server.start();
        System.out.println("cyclonedx-core-java xxe sink up on :" + port);
    }

    static byte[] body(HttpExchange ex) throws IOException {
        try (InputStream is = ex.getRequestBody();
             ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
            byte[] buf = new byte[8192]; int n;
            while ((n = is.read(buf)) != -1) bos.write(buf, 0, n);
            return bos.toByteArray();
        }
    }

    static void send(HttpExchange ex, int code, String s) throws IOException {
        byte[] b = s.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
        ex.sendResponseHeaders(code, b.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(b); }
    }

    // Collect every message in a throwable's cause chain + full stack trace, so any flag content the
    // REAL library places in an exception (error-based XXE) surfaces verbatim in the HTTP response.
    static String dump(Throwable t) {
        StringBuilder sb = new StringBuilder();
        for (Throwable c = t; c != null; c = c.getCause()) {
            sb.append(c.getClass().getName()).append(": ").append(String.valueOf(c.getMessage())).append('\n');
        }
        StringWriter sw = new StringWriter();
        t.printStackTrace(new PrintWriter(sw));
        sb.append(sw);
        return sb.toString();
    }

    // POST /parse  -> REAL XmlParser.parse(byte[])  (the XML BOM parser path; CVE-2024-38374)
    static void parse(HttpExchange ex) throws IOException {
        byte[] xml = body(ex);
        StringBuilder out = new StringBuilder("=== XmlParser.parse ===\n");
        try {
            org.cyclonedx.model.Bom bom = new XmlParser().parse(xml);
            out.append("PARSED_OK specVersion=").append(bom == null ? "null" : String.valueOf(bom.getSpecVersion()));
        } catch (Throwable t) {
            out.append("PARSE_EXCEPTION\n").append(dump(t));
        }
        send(ex, 200, out.toString());
    }

    // POST /validate -> REAL XmlParser.validate(byte[]) -> List<ParseException> (validator; CVE-2025-64518)
    static void validate(HttpExchange ex) throws IOException {
        byte[] xml = body(ex);
        StringBuilder out = new StringBuilder("=== XmlParser.validate ===\n");
        try {
            List<ParseException> exs = new XmlParser().validate(xml);
            out.append("VALIDATE_RETURNED count=").append(exs.size()).append('\n');
            for (ParseException pe : exs) {
                out.append("-- validation-exception --\n").append(dump(pe)).append('\n');
            }
        } catch (Throwable t) {
            out.append("VALIDATE_THROWN\n").append(dump(t));
        }
        send(ex, 200, out.toString());
    }

    static void health(HttpExchange ex) throws IOException {
        send(ex, 200, "ok cyclonedx xxe sink");
    }
}
