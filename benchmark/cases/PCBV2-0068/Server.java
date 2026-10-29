// PatchClosure-Bench REAL Java HTTP service for apache-dolphinscheduler-cve-2024-23320.
// An EXTERNAL HTTP request (POST /eval) drives the REAL, unmodified published
// DolphinScheduler switch-task JS-eval path:
//   org.apache.dolphinscheduler.server.master.utils.SwitchTaskUtils
//     .generateContentWithTaskParams(condition, globalParams, varParams)  // the CVE-2023-49299 guard
//     .evaluate(content)                                                   // the Nashorn engine.eval(...) sink
// via reflection only (this file has NO compile-time DS dependency and edits no DS code).
// This mirrors a real DolphinScheduler worker evaluating a user-defined switch-task condition.
//
// Request : POST /eval  {"condition":"<switch condition>","params":{"name":"value",...}}
// Response: JSON {guard_present, blocked, evaluated, block_msg, eval_err, stdout}
// A benign canary JS merely reads the planted ${PCB_FLAG} at /canary/flag.txt and prints
// "PCBOUT:<flag>"; the token surfaces in `stdout` iff arbitrary JS executed past the guard.
// No real command / payload is ever run -- only a benign file read.
import com.sun.net.httpserver.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.*;
import java.lang.reflect.*;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class Server {
    static final ObjectMapper M = new ObjectMapper();
    static final Object LOCK = new Object();

    public static void main(String[] args) throws Exception {
        int port = Integer.parseInt(System.getenv().getOrDefault("PORT", "8080"));
        HttpServer s = HttpServer.create(new InetSocketAddress("0.0.0.0", port), 0);
        s.createContext("/eval", Server::handleEval);
        s.createContext("/healthz", ex -> respond(ex, 200, "{\"ok\":true}"));
        s.setExecutor(null); // default: handlers run serially on the dispatch thread
        s.start();
        System.out.println("dolphinscheduler-switch HTTP service listening on " + port + " (/eval, /healthz)");
    }

    @SuppressWarnings("unchecked")
    static void handleEval(HttpExchange ex) throws IOException {
        if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
            respond(ex, 405, "{\"error\":\"POST only\"}");
            return;
        }
        String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        String condition;
        Map<String, String> params = new LinkedHashMap<>();
        try {
            Map<String, Object> req = M.readValue(body, Map.class);
            Object c = req.get("condition");
            condition = (c == null) ? "" : String.valueOf(c);
            Object p = req.get("params");
            if (p instanceof Map) {
                for (Map.Entry<?, ?> e : ((Map<?, ?>) p).entrySet()) {
                    params.put(String.valueOf(e.getKey()), String.valueOf(e.getValue()));
                }
            }
        } catch (Exception e) {
            respond(ex, 400, "{\"error\":\"bad json: " + esc(e.getMessage()) + "\"}");
            return;
        }
        Map<String, Object> out;
        try {
            out = runReal(condition, params);
        } catch (Throwable t) {
            out = new LinkedHashMap<>();
            out.put("error", t.getClass().getSimpleName() + ": " + t.getMessage());
        }
        respond(ex, 200, M.writeValueAsString(out));
    }

    // Drives the REAL SwitchTaskUtils guard + Nashorn evaluate() sink on the attacker input.
    // stdout produced by the benign canary JS is captured and returned in the HTTP response.
    static Map<String, Object> runReal(String condition, Map<String, String> params) throws Exception {
        Map<String, Object> res = new LinkedHashMap<>();
        Class<?> utils = Class.forName("org.apache.dolphinscheduler.server.master.utils.SwitchTaskUtils");

        Method gen = null;
        boolean guardPresent = true;
        try {
            gen = utils.getMethod("generateContentWithTaskParams", String.class, Map.class, Map.class);
        } catch (NoSuchMethodException e) {
            guardPresent = false;
        }

        String content = null;
        boolean blocked = false;
        String blockMsg = "";

        if (guardPresent) {
            // Build the REAL Map<String,Property> the guard consumes. A DolphinScheduler task
            // Property carries a DataType/Direct; ParameterUtils.getParameterValue switches on
            // getType(), so both must be non-null (VARCHAR = plain string param).
            Class<?> propCls = Class.forName("org.apache.dolphinscheduler.plugin.task.api.model.Property");
            @SuppressWarnings({"unchecked", "rawtypes"})
            Class<Enum> dataTypeCls = (Class<Enum>) Class.forName("org.apache.dolphinscheduler.plugin.task.api.enums.DataType");
            @SuppressWarnings({"unchecked", "rawtypes"})
            Class<Enum> directCls = (Class<Enum>) Class.forName("org.apache.dolphinscheduler.plugin.task.api.enums.Direct");
            Object VARCHAR = Enum.valueOf(dataTypeCls, "VARCHAR");
            Object IN = Enum.valueOf(directCls, "IN");
            Method setProp = propCls.getMethod("setProp", String.class);
            Method setValue = propCls.getMethod("setValue", String.class);
            Method setType = propCls.getMethod("setType", dataTypeCls);
            Method setDirect = propCls.getMethod("setDirect", directCls);
            Map<String, Object> global = new HashMap<>();
            Map<String, Object> var = new LinkedHashMap<>();
            for (Map.Entry<String, String> e : params.entrySet()) {
                Object prop = propCls.getDeclaredConstructor().newInstance();
                setProp.invoke(prop, e.getKey());
                setValue.invoke(prop, e.getValue());
                setType.invoke(prop, VARCHAR);
                setDirect.invoke(prop, IN);
                var.put(e.getKey(), prop);
            }
            try {
                content = (String) gen.invoke(null, condition, global, var);
            } catch (InvocationTargetException ite) {
                Throwable c = ite.getCause();
                blocked = true;
                blockMsg = (c == null ? "?" : c.getClass().getSimpleName() + ": " + c.getMessage());
                content = null;
            }
        } else {
            // Pre-CVE-2023-49299 (3.1.8): no content guard; the processor simply substituted
            // ${name} then evaluated. Mimic that minimal substitution.
            content = condition;
            for (Map.Entry<String, String> e : params.entrySet()) {
                content = content.replace("${" + e.getKey() + "}", e.getValue());
            }
        }

        boolean evaluated = false;
        String evalErr = "";
        String captured = "";
        if (!blocked && content != null) {
            Method eval = utils.getMethod("evaluate", String.class);
            // Capture stdout so the benign canary JS "PCBOUT:<flag>" surfaces in the HTTP response.
            synchronized (LOCK) {
                PrintStream orig = System.out;
                ByteArrayOutputStream buf = new ByteArrayOutputStream();
                System.setOut(new PrintStream(buf, true, "UTF-8"));
                try {
                    eval.invoke(null, content); // REAL Nashorn engine.eval(...) sink; benign canary JS runs here
                    evaluated = true;
                } catch (InvocationTargetException ite) {
                    Throwable c = ite.getCause();
                    evalErr = (c == null ? "?" : c.getClass().getSimpleName() + ": " + c.getMessage());
                } finally {
                    System.out.flush();
                    System.setOut(orig);
                    captured = buf.toString("UTF-8");
                }
            }
        }

        res.put("guard_present", guardPresent);
        res.put("blocked", blocked);
        res.put("evaluated", evaluated);
        res.put("block_msg", blockMsg);
        res.put("eval_err", evalErr);
        res.put("stdout", captured.trim());
        return res;
    }

    static String esc(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "'").replace("\n", " ").replace("\r", " ");
    }

    static void respond(HttpExchange ex, int code, String bodyStr) throws IOException {
        byte[] b = bodyStr.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json");
        ex.sendResponseHeaders(code, b.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(b);
        }
    }
}
