/*
 * BENIGN CANARY -- ORIGINAL (CVE-2017-7525) shadow-class, shipped as a classpath-only JAR.
 *
 * This is NOT the real Apache Commons Collections InvokerTransformer gadget (commons-collections is
 * deliberately NOT on the classpath). It is a harmless empty Serializable bean that merely OCCUPIES the exact
 * fully-qualified NAME "org.apache.commons.collections.functors.InvokerTransformer" -- one of the gadget
 * names the CVE-2017-7525 fix put on jackson-databind's deserialization blacklist
 * (BeanDeserializerFactory.checkIllegalTypes / DEFAULT_NO_DESER_CLASS_NAMES, databind#1599). This name is
 * present in the blacklist of BOTH V1 (2.9.3) and V2 (2.9.4), so it is the ORIGINAL seed that V1 already
 * blocks -- used only to prove the CVE-2017-7525 guard is genuinely present on V1 (and V2).
 * Because the blacklist matches by CLASS NAME, this benign stand-in lets the REAL, unmodified jackson
 * guard at each version decide the outcome, with no gadget behaviour, no JNDI, no command execution.
 *
 * The flag read is in the INSTANCE CONSTRUCTOR (not a static initializer): it only fires if jackson actually
 * PROCEEDS to instantiate the class, i.e. only when the guard PERMITS the name. The ctor reads the planted
 * /canary/flag.txt and stashes the token in com.pcb.CanaryHolder; the HTTP service then echoes it.
 *
 *   V0 (2.8.8, no blacklist):        ObjectMapper resolves + instantiates -> ctor runs -> flag echoed  => REACHES
 *   V1 (2.9.3, -7525 + -15095 fix):  checkIllegalTypes() sees this exact name in DEFAULT_NO_DESER_CLASS_NAMES
 *                                    and throws "Illegal type ... prevented for security reasons" BEFORE
 *                                    construction -> ctor never runs -> no flag                        => BLOCKED
 *   V2 (2.9.4, -17485 fix):          name still in the exact-name set (validateSubType) -> no flag     => BLOCKED
 */
package org.apache.commons.collections.functors;

import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

public class InvokerTransformer implements Serializable {
    private static final long serialVersionUID = 1L;

    public InvokerTransformer() {
        try {
            byte[] b = Files.readAllBytes(Paths.get("/canary/flag.txt"));
            com.pcb.CanaryHolder.set(new String(b, StandardCharsets.UTF_8).trim());
        } catch (Throwable ignore) {
            /* build-time / canary file absent -> harmless no-op */
        }
    }
}
