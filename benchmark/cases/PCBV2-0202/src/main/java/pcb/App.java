package pcb;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * PatchClosure-Bench REAL Spring Boot web app for ssti_thymeleaf_spel_sandbox
 * (CVE-2026-40478 -> CVE-2026-41901, Thymeleaf restricted/sandboxed SpEL preprocessing escape).
 *
 * A minimal but genuine Spring Boot MVC application booted on an embedded Tomcat. The only
 * app code is RenderController (the vulnerable render endpoint) + the benign canary class
 * pcb.PcbFlagReader. Everything that decides whether the sandbox escape fires lives in the
 * REAL, unmodified published thymeleaf-spring6 pinned per version.
 */
@SpringBootApplication
public class App {
    public static void main(String[] args) {
        SpringApplication.run(App.class, args);
    }
}
