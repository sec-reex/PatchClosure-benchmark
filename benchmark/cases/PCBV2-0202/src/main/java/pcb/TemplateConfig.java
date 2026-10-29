package pcb;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.thymeleaf.spring6.SpringTemplateEngine;
import org.thymeleaf.templatemode.TemplateMode;
import org.thymeleaf.templateresolver.StringTemplateResolver;

/**
 * Wires the REAL published org.thymeleaf.spring6.SpringTemplateEngine (which auto-registers the
 * SpringStandardDialect -> the SPELVariableExpressionEvaluator + the restricted-context guard
 * SpringStandardExpressionUtils.containsExternalAccess that both CVEs patch). A StringTemplateResolver
 * lets the app render an inline view whose text is influenced by the request -- the classic Thymeleaf
 * SSTI surface. The engine bean is created from the version's own unmodified thymeleaf-spring6 jar;
 * nothing about the sandbox is configured or altered here.
 */
@Configuration
public class TemplateConfig {

    @Bean
    public SpringTemplateEngine templateEngine() {
        SpringTemplateEngine engine = new SpringTemplateEngine();
        StringTemplateResolver resolver = new StringTemplateResolver();
        resolver.setTemplateMode(TemplateMode.HTML);
        resolver.setCacheable(false);
        engine.setTemplateResolver(resolver);
        return engine;
    }
}
