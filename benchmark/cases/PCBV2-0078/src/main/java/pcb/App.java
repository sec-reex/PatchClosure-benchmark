/*
 * PatchClosure-Bench harness app for apache-shiro-cve-2020-13933.
 *
 * A MINIMAL Spring Boot app that protects /admin/* with the REAL, unmodified Apache
 * Shiro ShiroFilterFactoryBean (authc filter), mirroring the real-world CVE setup
 * (protect /res/* ; a /res/{name} controller). The admin resource controller
 * GET /admin/{name} returns the per-run ${PCB_FLAG} (read from the process
 * ENVIRONMENT, never hardcoded). A plain unauthenticated GET /admin/flag is
 * redirected (302) to the login URL by Shiro's authc filter => no flag.
 *
 * The vulnerability: a crafted request path is normalized DIFFERENTLY by Shiro's
 * PathMatchingFilterChainResolver (WebUtils.removeSemicolon over servletPath, which
 * strips from the FIRST ';' to end -> resolves to /admin, NOT matching /admin/*)
 * than by Spring's controller routing (which still binds /admin/{name}) -> the
 * request skips Shiro's authc chain but STILL reaches the /admin/{name} controller
 * => FLAG returned = auth bypass.
 *
 * No Shiro source is modified; only published Maven artifacts (shiro-spring/
 * shiro-web/shiro-core at ${shiro.version}) are consumed. Spring path matching uses
 * framework defaults (as in the public reproduction).
 */
package pcb;

import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.realm.SimpleAccountRealm;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

@SpringBootApplication
public class App {
    public static void main(String[] args) {
        SpringApplication.run(App.class, args);
    }

    @RestController
    public static class Web {
        private static final String FLAG =
                System.getenv().getOrDefault("PCB_FLAG", "PCBFLAG_unset");

        /** Public readiness endpoint. */
        @GetMapping("/")
        @ResponseBody
        public String home() {
            return "public-ok";
        }

        /** Protected admin resource (the seeded canary). Any single-segment name
         *  under /admin returns the flag; Shiro's authc chain must gate it. */
        @GetMapping("/admin/{name}")
        @ResponseBody
        public String res(@PathVariable String name) {
            return "ADMIN-FLAG:" + FLAG + " (name=" + name + ")";
        }

        /** Empty /admin/ resource: no flag (mirrors the /res/ endpoint). */
        @GetMapping("/admin/")
        @ResponseBody
        public String noRes() {
            return "no-resource";
        }
    }

    @Configuration
    public static class ShiroConfig {

        @Bean
        public Realm realm() {
            SimpleAccountRealm realm = new SimpleAccountRealm();
            realm.addAccount("admin", "admin");
            return realm;
        }

        @Bean
        public DefaultWebSecurityManager securityManager(Realm realm) {
            DefaultWebSecurityManager sm = new DefaultWebSecurityManager();
            sm.setRealm(realm);
            return sm;
        }

        @Bean
        public ShiroFilterFactoryBean shiroFilter(SecurityManager securityManager) {
            ShiroFilterFactoryBean bean = new ShiroFilterFactoryBean();
            bean.setSecurityManager(securityManager);
            bean.setLoginUrl("/login");
            Map<String, String> chains = new LinkedHashMap<String, String>();
            // Guard under test: /admin/<one-segment> requires authentication (single
            // '*', as in the real PoC's /res/*). Ant '/admin/*' matches /admin/flag
            // but NOT /admin -- so a crafted path Shiro collapses to /admin evades it.
            chains.put("/admin/*", "authc");
            // Catch-all so EVERY request matches some chain: this makes the 1.6.0
            // global InvalidRequestFilter (prepended to each configured chain) run on
            // crafted paths that Shiro resolves outside /admin, yielding HTTP 400 on V2.
            chains.put("/**", "anon");
            bean.setFilterChainDefinitionMap(chains);
            return bean;
        }
    }
}
