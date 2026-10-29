/*
 * BENIGN CANARY -- ORIGINAL (CVE-2021-26295) shadow-class.
 *
 * This is a harmless Serializable canary shipped as a small JAR added to the OFBiz DEPLOYMENT classpath
 * (plugins/pcbcanary/lib/pcb-canary.jar). It does NOT modify OFBiz source. It carries NO gadget chain, NO
 * reflection, NO command execution. Its readObject merely reads the per-run ${PCB_FLAG} token planted
 * OUTSIDE the app dir at /canary/flag.txt and echoes it to /canary/echo.txt (and stdout). The token is
 * echoed ONLY if the running OFBiz's real SafeObjectInputStream.resolveClass() ALLOWS this class name
 * (i.e. deserialization actually reaches readObject through the real HTTP path).
 *
 * Fully-qualified name:  com.pcb.java.rmi.server.PcbFlagProbe.  The distinguishing substring is
 * "java.rmi.server" -- exactly the token the CVE-2021-26295 fix (17.12.06) added to SafeObjectInputStream's
 * BLOCKLIST. (It lives under the loadable "com.pcb.*" prefix -- a real java.* package is JVM-reserved --
 * while preserving the "java.rmi.server" substring the filter keys on.)
 *   OFBiz 17.12.05 (V0): no rmi blocklist; allowlist "java..*" (regex .find) matches -> ALLOWED -> flag echoed
 *   OFBiz 17.12.06 (V1): resolveClass -> className.contains("java.rmi.server") -> return null -> BLOCKED, no flag
 *   OFBiz 17.12.07 (V2): denyList {"rmi","<"}: contains("rmi") -> InvalidClassException -> BLOCKED, no flag
 */
package com.pcb.java.rmi.server;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;
import java.nio.file.Files;
import java.nio.file.Paths;

public class PcbFlagProbe implements Serializable {
    private static final long serialVersionUID = 1L;

    public PcbFlagProbe() {
        // Empty: the flag echo happens ONLY on deserialize (readObject), i.e. only past the real filter.
    }

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        try {
            String flag = new String(Files.readAllBytes(Paths.get("/canary/flag.txt"))).trim();
            String line = "PCB_CANARY_FLAG=" + flag + " class=" + getClass().getName();
            System.out.println(line);
            Files.write(Paths.get("/canary/echo.txt"), (line + "\n").getBytes());
        } catch (Exception e) {
            System.out.println("PCB_CANARY_READ_FAIL=" + e);
        }
    }
}
