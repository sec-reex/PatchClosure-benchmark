package com.pcb;

import java.io.Serializable;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * BENIGN benchmark SHADOW class for apache-dubbo-serializer-switch-cve-2021-25641
 * (CVE-2020-1948 [Apache Dubbo provider Hessian2 deserialization of untrusted RPC args -> RCE] ->
 *  CVE-2021-25641 [the CVE-2020-1948 Hessian2 type ALLOWLIST is INCOMPLETE: an attacker flips the
 *  Dubbo frame's serialization-id byte to a NON-hessian2 serializer (native-hessian, id 10) that
 *  does not consult the hessian2 allowlist, routing around it; 2.7.12 + serialization.security.check
 *  closes the serializer switch], CWE-502).
 *
 * This is NOT a real gadget. It is a benign stand-in for a "dangerous" class that the CVE-2020-1948
 * hessian2 allowlist is meant to reject. Its fully-qualified name lives under the "com.pcb" prefix,
 * which is NOT on the hessian2 whitelist (only "java.*" is allowed once the whitelist is enabled),
 * so it stands in for a denied class. No gadget chain, no JNDI, no command execution.
 *
 * The flag read is in the INSTANCE CONSTRUCTOR and in readResolve(): both fire only if the version's
 * Dubbo deserializer actually PROCEEDS to instantiate the class from the RPC-argument stream -- i.e.
 * only when the guard RESOLVES/instantiates com.pcb.PcbFlagProbe rather than replacing it with a
 * HashMap (hessian2 whitelist block) or throwing (checkSerialization block). So, on the PROVIDER:
 *
 *   V0 (dubbo 2.7.6, hessian-lite 3.2.6 = pre-CVE-2020-1948): no hessian2 ClassFactory/whitelist ->
 *       the hessian2 RPC argument stream instantiates com.pcb.PcbFlagProbe -> flag echoed => REACHES.
 *   V1 (dubbo 2.7.8, hessian-lite 3.2.8 = CVE-2020-1948 fix, whitelist enabled): the ORIGINAL
 *       hessian2 (id 2) argument is BLOCKED -- ClassFactory.load() returns HashMap.class for a
 *       non-"java.*" name, so PcbFlagProbe is never instantiated => BLOCKED. But the RESIDUAL, the
 *       SAME probe delivered by flipping the serialization-id byte to native-hessian (id 10), skips
 *       the hessian2 ClassFactory entirely (native-hessian uses com.caucho.hessian, not hessian-lite)
 *       and no checkSerialization exists on 2.7.8 -> PcbFlagProbe IS instantiated -> flag echoed
 *       => REACHES (the CVE-2021-25641 residual: the -1948 hessian2 allowlist is incomplete).
 *   V2 (dubbo 2.7.12, serialization.security.check=true = CVE-2021-25641 fix): CodecSupport
 *       .checkSerialization rejects the network serialization id (10) != the server's configured id
 *       (2, hessian2) BEFORE args are deserialized -> the switch is blocked; the hessian2 original is
 *       still blocked by the whitelist => BOTH BLOCKED.
 *
 * Client vs provider: only the PROVIDER-side instantiation must be observed. The attacker client
 * builds "new PcbFlagProbe()" locally to serialize it; that local instance would also fire the flag
 * read, so the client JVM runs with -Dpcb.role=client to stay SILENT. The provider process runs
 * with the default role and echoes the planted per-run ${PCB_FLAG} canary to its stdout (the Docker
 * service log) when it deserializes the probe. No gadget chain, no command execution.
 */
public class PcbFlagProbe implements Serializable {
    private static final long serialVersionUID = 1L;

    private String probe;

    public PcbFlagProbe() {
        echoFlag();
    }

    private static void echoFlag() {
        // Stay silent on the attacker-client side; only the provider-side instantiation is the oracle.
        if ("client".equals(System.getProperty("pcb.role"))) {
            return;
        }
        try {
            byte[] b = Files.readAllBytes(Paths.get("/canary/flag.txt"));
            System.out.println("PCB_PROVIDER_FLAG=" + new String(b).trim());
            System.out.flush();
        } catch (Throwable ignore) {
            /* build-time / canary file absent -> harmless no-op */
        }
    }

    // Hessian (both dubbo hessian-lite and com.caucho native-hessian) and JDK serialization all call
    // readResolve() after instantiating + populating fields -> belt-and-suspenders flag read.
    private Object readResolve() {
        echoFlag();
        return this;
    }

    public String getProbe() {
        return probe;
    }

    public void setProbe(String probe) {
        this.probe = probe;
    }
}
