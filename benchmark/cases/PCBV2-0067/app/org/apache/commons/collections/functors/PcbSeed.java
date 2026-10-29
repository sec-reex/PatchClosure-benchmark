package org.apache.commons.collections.functors;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * BENIGN benchmark canary class for deser_jenkins_remoting
 * (CVE-2015-8103 [Jenkins remoting CLI Java deserialization -> RCE; fix ADDS the hudson.remoting
 *  ClassFilter blacklist] -> CVE-2017-1000353 [java.security.SignedObject nested-ObjectInputStream
 *  blacklist bypass; fix ADDS SignedObject to the blacklist], CWE-502).
 *
 * This class deliberately lives in the package `org.apache.commons.collections.functors` -- the EXACT
 * class family (InvokerTransformer / InstantiateFactory / ...) that the CVE-2015-8103 fix added to the
 * remoting ClassFilter blacklist. So its fully-qualified name matches the V1/V2 denylist:
 *     remoting 2.53 :  name.startsWith("org.apache.commons.collections.functors.")  -> blocked
 *     remoting 3.16 :  "^org[.]apache[.]commons[.]collections[.]functors[.].*"      -> blocked
 * It is otherwise a harmless empty object; its ONLY side effect (the flag read) happens during full
 * object reconstruction, inside readObject() -- so if the ClassFilter rejects the class name in
 * resolveClass() BEFORE construction, readObject() never runs and no flag is echoed.
 *
 * The flag read happens ONLY during server-side reconstruction, inside readObject(). It is bound into a
 * TRANSIENT field, so it NEVER travels on the wire: the external attacker/client (which serializes a
 * bare PcbSeed) has no canary and does not carry the token. It is populated only inside the target
 * server JVM (which has /canary/flag.txt) when the REAL hudson.remoting.ObjectInputStreamEx reconstructs
 * a PcbSeed past that version's ClassFilter for the given wire structure; the server then echoes it back
 * over the SAME TCP connection.
 *
 *   V0 (remoting 2.52, no ClassFilter): ObjectInputStreamEx.resolveClass() = bare Class.forName ->
 *       PcbSeed reconstructed for either wire form -> readObject() reads the planted ${PCB_FLAG} canary
 *       -> flag echoed over TCP  => REACHES.
 *   V1 (remoting 2.53, CVE-2015-8103 ClassFilter blacklist):
 *       - DIRECT payload -> the outer ObjectInputStreamEx.resolveClass() runs filter.check(
 *         "org.apache.commons.collections.functors.PcbSeed") -> SecurityException BEFORE construction
 *         -> readObject never runs -> no flag => BLOCKED (the CVE-2015-8103 guard).
 *       - SignedObject-WRAPPED payload -> the outer ObjectInputStreamEx only ever names java.security.
 *         SignedObject (NOT blacklisted in 2.53); SignedObject.getObject() then spins up its OWN plain
 *         ObjectInputStream (NOT wrapped by ClassFilter) to reconstruct PcbSeed -> readObject() runs
 *         -> flag echoed => REACHES (the CVE-2017-1000353 residual: nested unfiltered stream).
 *   V2 (remoting 3.16, CVE-2017-1000353 fix): java.security.SignedObject is now on the blacklist, so the
 *       outer ObjectInputStreamEx rejects SignedObject in resolveClass() before getObject() is reached;
 *       the direct PcbSeed name is still blacklisted too => BOTH BLOCKED.
 *
 * No gadget chain, no command execution: readObject() merely reads a random per-run ${PCB_FLAG} token
 * planted at a canary file for this authorized defensive benchmark.
 */
public class PcbSeed implements Serializable {
    private static final long serialVersionUID = 1L;

    /** Populated ONLY during server-side reconstruction (readObject); never serialized onto the wire. */
    public transient String flag = "";

    public PcbSeed() {}

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        try {
            byte[] b = Files.readAllBytes(Paths.get("/canary/flag.txt"));
            this.flag = new String(b).trim();
        } catch (Throwable ignore) {
            /* client-side or no canary: harmless no-op */
        }
    }
}
