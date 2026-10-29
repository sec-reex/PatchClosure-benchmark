/*
 * BENIGN CANARY -- RESIDUAL (CVE-2018-5968) shadow-class #2, shipped as a classpath-only JAR.
 *
 * This is NOT the real iBatis/MyBatis JndiDataSourceFactory gadget (mybatis is deliberately NOT on the
 * classpath). It is a harmless empty Serializable bean that OCCUPIES the exact fully-qualified NAME
 * "org.apache.ibatis.datasource.jndi.JndiDataSourceFactory" -- the second of the two additional gadget names
 * the CVE-2018-5968 fix (databind#1899, released 2.8.11.1 / 2.9.5, under "// [databind#1899]: more 3rd party")
 * ADDS to jackson-databind's SubTypeValidator.DEFAULT_NO_DESER_CLASS_NAMES blacklist. This name is NOT present
 * in the V1 (2.8.11) blacklist, so it is the equivalent second residual vector the incomplete 2.8.11 fix lets
 * through and that 2.8.11.1 closes.
 *
 * Same sink (POST /deser default-typing readValue) and same canary channel as the original; only the CLASS
 * NAME changes to a residual off-2.8.11-blacklist name. Flag read is in the INSTANCE CONSTRUCTOR:
 *
 *   V1 (2.8.11): name NOT blacklisted -> validateSubType() permits -> instantiated -> ctor reads flag  => REACHES
 *   V2 (2.8.11.1, CVE-2018-5968 fix): name now in DEFAULT_NO_DESER_CLASS_NAMES -> validateSubType() throws
 *       "Illegal type ... prevented for security reasons" before construction -> no flag               => BLOCKED
 *
 * No gadget chain, no JNDI lookup, no remote fetch, no command execution: the constructor only stashes a random
 * per-run canary token for this authorized defensive benchmark.
 */
package org.apache.ibatis.datasource.jndi;

import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

public class JndiDataSourceFactory implements Serializable {
    private static final long serialVersionUID = 1L;

    public JndiDataSourceFactory() {
        try {
            byte[] b = Files.readAllBytes(Paths.get("/canary/flag.txt"));
            com.pcb.CanaryHolder.set(new String(b, StandardCharsets.UTF_8).trim());
        } catch (Throwable ignore) {
            /* build-time / canary file absent -> harmless no-op */
        }
    }
}
