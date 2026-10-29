/*
 * BENIGN CANARY -- RESIDUAL (CVE-2017-17485) shadow-class, shipped as a classpath-only JAR.
 *
 * This is NOT the real Spring FileSystemXmlApplicationContext gadget (spring-context is deliberately
 * NOT on the classpath). It is a benign shadow class that occupies the exact fully-qualified name
 * "org.springframework.context.support.FileSystemXmlApplicationContext" -- the Spring application-context
 * gadget the CVE-2017-17485 advisory (NVD: "bypassing a blacklist that is ineffective if the Spring
 * libraries are available in the classpath") identifies as the residual the incomplete CVE-2017-7525 /
 * CVE-2017-15095 blacklist still lets through. The real class fetches a remote Spring context definition
 * via URL and evaluates it -> RCE; here the shadow only stashes a random per-run canary token.
 *
 * Crucially, this NAME is NOT present in the 2.9.3 (V1) DEFAULT_NO_DESER_CLASS_NAMES exact-name set, and
 * 2.9.3 has NO Spring superclass handling. It is the residual added to the guard only in 2.9.4 (V2) via the
 * databind#1855 superclass walk. So it is exactly the residual the incomplete V1 fix lets through and that
 * V2 closes.
 *
 * Same sink (ObjectMapper default-typing polymorphic deserialization over POST /deser) and same canary
 * channel (CanaryHolder token echoed by the HTTP service) as the original; only the CLASS NAME changes from
 * an on-blacklist name to the residual off-2.9.3-blacklist Spring name. It extends the benign
 * AbstractApplicationContext so that 2.9.4's validateSubType() superclass walk recognises it. The flag read
 * is again in the INSTANCE CONSTRUCTOR (fires only if the guard PERMITS the name and jackson instantiates):
 *
 *   V1 (2.9.3, -7525 + -15095 blacklist): the guard is BeanDeserializerFactory.checkIllegalTypes(), an EXACT
 *       fully-qualified-name set. This name is NOT in the set and 2.9.3 has NO Spring superclass handling ->
 *       checkIllegalTypes() permits it -> ObjectMapper instantiates -> ctor reads the planted ${PCB_FLAG} ->
 *       flag echoed  => REACHES (the CVE-2017-17485 residual: the enumerated blacklist is incomplete).
 *   V2 (2.9.4, CVE-2017-17485 fix / databind#1855): the guard is SubTypeValidator.validateSubType, which --
 *       for any concrete "org.springframework." class -- walks the superclass chain and rejects it if an
 *       ancestor's SIMPLE name is "AbstractApplicationContext". This class extends AbstractApplicationContext
 *       -> validateSubType throws "Illegal type ... prevented for security reasons" before construction ->
 *       no flag  => BLOCKED.
 *
 * No gadget chain, no remote XML fetch, no SpEL, no command execution: the constructor only stashes a random
 * per-run canary token for this authorized defensive benchmark.
 */
package org.springframework.context.support;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

public class FileSystemXmlApplicationContext extends AbstractApplicationContext {
    private static final long serialVersionUID = 1L;

    public FileSystemXmlApplicationContext() {
        super();
        try {
            byte[] b = Files.readAllBytes(Paths.get("/canary/flag.txt"));
            com.pcb.CanaryHolder.set(new String(b, StandardCharsets.UTF_8).trim());
        } catch (Throwable ignore) {
            /* build-time / canary file absent -> harmless no-op */
        }
    }
}
