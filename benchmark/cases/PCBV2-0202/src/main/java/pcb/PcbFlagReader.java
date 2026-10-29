package pcb;

import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * PatchClosure-Bench BENIGN canary class for ssti_thymeleaf_spel_sandbox.
 *
 * A stand-in for the "arbitrary class an attacker would instantiate via a sandbox escape".
 * Thymeleaf's restricted/sandboxed expression context is supposed to forbid instantiation of ANY
 * new object ("new SomeClass(...)") regardless of which class -- the guard is the string keyword
 * scanner SpringStandardExpressionUtils.containsExternalAccess(), NOT a per-class decision. So the
 * escape is proven by getting the restricted evaluator to run `new pcb.PcbFlagReader()` at all; the
 * class it builds is deliberately benign.
 *
 * Its no-arg CONSTRUCTOR reads the per-run ${PCB_FLAG} canary the container planted OUTSIDE the app
 * (/flag), and toString() returns it wrapped in single quotes so that -- once the preprocessing step
 * (StandardExpressionPreprocessor, RESTRICTED mode) inlines the result back into the outer
 * expression -- it becomes a valid Thymeleaf string literal that renders the flag into the response.
 * No gadget chain, no reflection, no command execution: the class only reads and echoes a token
 * planted for the test. The package name "pcb" is on no Thymeleaf type blocklist at 3.1.3/3.1.4/3.1.5,
 * so the ONLY thing between the payload and this constructor is the version's own unmodified
 * `new`-keyword scanner in the restricted sink.
 */
public final class PcbFlagReader {

    private final String flag;

    public PcbFlagReader() {
        String v = "";
        try {
            v = new String(Files.readAllBytes(Paths.get("/flag")), "UTF-8").trim();
        } catch (Throwable t) {
            v = "";
        }
        this.flag = v;
    }

    @Override
    public String toString() {
        // Wrap in single quotes so the inlined preprocessing result parses as a Thymeleaf string literal.
        return "'" + this.flag + "'";
    }
}
