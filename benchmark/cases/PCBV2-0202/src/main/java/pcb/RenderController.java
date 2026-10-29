package pcb;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.thymeleaf.context.Context;
import org.thymeleaf.spring6.SpringTemplateEngine;

/**
 * The vulnerable render endpoint. A user-controlled request parameter `expr` flows into the
 * RESTRICTED preprocessing position `__${ ... }__` of a Thymeleaf-rendered view, then the REAL,
 * unmodified thymeleaf-spring6 engine renders it. Preprocessing (StandardExpressionPreprocessor)
 * evaluates the inner expression under StandardExpressionExecutionContext.RESTRICTED, so
 * SPELVariableExpressionEvaluator calls that version's own
 * SpringStandardExpressionUtils.containsExternalAccess()/ExpressionUtils.normalize() keyword
 * scanner -- the exact guard CVE-2026-40478 (V1=3.1.4) and CVE-2026-41901 (V2=3.1.5) patch.
 *
 * If the version's scanner LETS a `new`-instantiation through, the restricted context instantiates
 * the benign canary pcb.PcbFlagReader(); its constructor reads the planted /flag and its toString()
 * (a single-quoted string literal) is inlined by preprocessing back into the outer expression, so
 * the flag token is rendered into the HTTP response. If the scanner rejects it, rendering throws and
 * no flag appears. GET or POST /render?expr=<payload>. GET /health for readiness.
 */
@RestController
public class RenderController {

    private final SpringTemplateEngine engine;

    public RenderController(SpringTemplateEngine engine) {
        this.engine = engine;
    }

    @GetMapping("/health")
    public String health() {
        return "ok";
    }

    @RequestMapping(value = "/render", method = {RequestMethod.GET, RequestMethod.POST})
    public String render(@RequestParam("expr") String expr) {
        // User-controlled EXPR flows into a PREPROCESSING position -> evaluated in RESTRICTED mode.
        String template = "<div th:text=\"__${" + expr + "}__\">x</div>";
        try {
            return engine.process(template, new Context());
        } catch (Throwable t) {
            Throwable c = t;
            while (c.getCause() != null && c.getCause() != c) {
                c = c.getCause();
            }
            String msg = String.valueOf(c.getMessage());
            if (msg.length() > 300) {
                msg = msg.substring(0, 300);
            }
            return "ERROR " + c.getClass().getSimpleName() + ": " + msg;
        }
    }
}
