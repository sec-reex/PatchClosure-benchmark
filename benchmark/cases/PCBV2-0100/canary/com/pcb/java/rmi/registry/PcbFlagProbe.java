/*
 * BENIGN CANARY -- RESIDUAL (CVE-2021-30128) shadow-class.
 *
 * Identical harmless behaviour to the original canary (reads the planted ${PCB_FLAG} at /canary/flag.txt
 * in readObject and echoes it to /canary/echo.txt + stdout -- NO gadget, NO exec). Only the class NAME
 * differs, and the name is the whole point. Shipped as part of the same deployment-classpath canary JAR;
 * OFBiz source is untouched.
 *
 * Fully-qualified name:  com.pcb.java.rmi.registry.PcbFlagProbe.  It embodies BOTH residual flaws that
 * 17.12.06 left open and 17.12.07 closed:
 *   (a) CVE-2021-30128 allowlist ".find()" flaw -- an "xxx.java.xxx" class name: the token "java." appears
 *       MID-NAME (com.pcb.JAVA.rmi.registry...), and OFBiz's allowlist uses regex .find() (substring match,
 *       not anchored), so the permissive "java..*" pattern matches though it is NOT a real java.* class.
 *       (Ridge Security: "If the class name is xxx.java.xxx, it will also pass the whitelist check.")
 *   (b) narrow-blocklist gap -- the name is an RMI-family class NOT under "java.rmi.server"
 *       (java.rmi.registry), so V1's contains("java.rmi.server") blocklist MISSES it.
 * Behaviour across the real running OFBiz versions:
 *   17.12.05 (V0): allowlist "java..*" .find matches -> ALLOWED  -> flag echoed
 *   17.12.06 (V1): not "java.rmi.server" -> blocklist miss; allowlist .find matches -> ALLOWED -> flag echoed  (RESIDUAL REACHES)
 *   17.12.07 (V2): denyList {"rmi","<"}: contains("rmi") -> InvalidClassException -> BLOCKED, no flag
 */
package com.pcb.java.rmi.registry;

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
