/*
 * BENIGN CANARY -- RESIDUAL (CVE-2018-5968) shadow-class #1, shipped as a classpath-only JAR.
 *
 * This is NOT the real Hibernate JMX StatisticsService gadget (hibernate-core is deliberately NOT on the
 * classpath). It is a harmless empty Serializable bean that OCCUPIES the exact fully-qualified NAME
 * "org.hibernate.jmx.StatisticsService" -- one of the two additional gadget names the CVE-2018-5968 fix
 * (databind#1899, released 2.8.11.1 / 2.9.5, under the comment "// [databind#1899]: more 3rd party") ADDS
 * to jackson-databind's SubTypeValidator.DEFAULT_NO_DESER_CLASS_NAMES blacklist. Crucially, this name is NOT
 * present in the V1 (2.8.11) blacklist -- which carries the -7525 (#1599) + -15095 (#1680/#1737) + -17485
 * (#1855) gadget set and the Spring superclass walk, but not #1899 -- so it is exactly the residual the
 * incomplete 2.8.11 fix still lets through and that 2.8.11.1 closes.
 *
 * Same sink (ObjectMapper default-typing polymorphic deserialization over POST /deser) and same canary
 * channel (CanaryHolder token echoed by the HTTP service) as the original; only the CLASS NAME changes from
 * an on-2.8.11-blacklist name to a residual off-2.8.11-blacklist name. The flag read is again in the INSTANCE
 * CONSTRUCTOR (fires only if the blacklist PERMITS the name and jackson instantiates):
 *
 *   V1 (2.8.11, -7525/-15095/-17485 blacklist): this name is NOT blacklisted -> validateSubType() permits it ->
 *       ObjectMapper instantiates -> ctor reads the planted ${PCB_FLAG} -> flag echoed  => REACHES
 *       (the CVE-2018-5968 residual: the maintained blacklist is still incomplete).
 *   V2 (2.8.11.1, CVE-2018-5968 fix): this exact name is now in DEFAULT_NO_DESER_CLASS_NAMES ->
 *       validateSubType() throws "Illegal type ... prevented for security reasons" before construction ->
 *       no flag  => BLOCKED.
 *
 * No gadget chain, no JNDI/RMI, no command execution: the constructor only stashes a random per-run canary
 * token for this authorized defensive benchmark.
 */
package org.hibernate.jmx;

import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

public class StatisticsService implements Serializable {
    private static final long serialVersionUID = 1L;

    public StatisticsService() {
        try {
            byte[] b = Files.readAllBytes(Paths.get("/canary/flag.txt"));
            com.pcb.CanaryHolder.set(new String(b, StandardCharsets.UTF_8).trim());
        } catch (Throwable ignore) {
            /* build-time / canary file absent -> harmless no-op */
        }
    }
}
