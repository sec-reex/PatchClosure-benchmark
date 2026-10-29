/*
 * BENIGN CANARY -- RESIDUAL (CVE-2017-15095) shadow-class, shipped as a classpath-only JAR.
 *
 * This is NOT the real c3p0 WrapperConnectionPoolDataSource gadget (c3p0 is deliberately NOT on the
 * classpath). It is a harmless empty Serializable bean that OCCUPIES the exact fully-qualified NAME
 * "com.mchange.v2.c3p0.WrapperConnectionPoolDataSource" -- one of the additional gadget names the
 * CVE-2017-15095 fix (databind#1737, batched with #1680, released in 2.8.10) ADDED to the deserialization
 * blacklist. Crucially, this name is NOT present in the 2.8.9 (CVE-2017-7525 / databind#1599) blacklist, so
 * it is exactly the residual that the incomplete 2.8.9 fix still lets through and that 2.8.10 closes.
 *
 * Same sink (ObjectMapper default-typing polymorphic deserialization over POST /deser) and same canary
 * channel (CanaryHolder token echoed by the HTTP service) as the original; only the CLASS NAME changes from
 * an on-2.8.9-blacklist name to a residual off-2.8.9-blacklist name. The flag read is again in the INSTANCE
 * CONSTRUCTOR (fires only if the blacklist PERMITS the name and jackson instantiates):
 *
 *   V1 (2.8.9, CVE-2017-7525 blacklist): this name is NOT blacklisted -> checkIllegalTypes() permits it ->
 *       ObjectMapper instantiates -> ctor reads the planted ${PCB_FLAG} -> flag echoed  => REACHES
 *       (the CVE-2017-15095 residual: the -7525 blacklist is incomplete).
 *   V2 (2.8.10, CVE-2017-15095 blacklist): this exact name is now in DEFAULT_NO_DESER_CLASS_NAMES ->
 *       checkIllegalTypes() throws "Illegal type ... prevented for security reasons" before construction ->
 *       no flag  => BLOCKED.
 *
 * No gadget chain, no JNDI/RMI, no command execution: the constructor only stashes a random per-run canary
 * token for this authorized defensive benchmark.
 */
package com.mchange.v2.c3p0;

import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

public class WrapperConnectionPoolDataSource implements Serializable {
    private static final long serialVersionUID = 1L;

    public WrapperConnectionPoolDataSource() {
        try {
            byte[] b = Files.readAllBytes(Paths.get("/canary/flag.txt"));
            com.pcb.CanaryHolder.set(new String(b, StandardCharsets.UTF_8).trim());
        } catch (Throwable ignore) {
            /* build-time / canary file absent -> harmless no-op */
        }
    }
}
