import java.io.Serializable;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * CVE-2026-42778 RESIDUAL class (BENIGN benchmark canary) -- the STATIC-INITIALIZER flag channel.
 *
 * The flag read happens in a STATIC INITIALIZER, i.e. at class-initialization time, NOT in readObject().
 * This models a class whose observable effect is in its static block. The MINA decoder's inner
 * ObjectInputStream.readClassDescriptor() for a Serializable class (type 1) calls
 *     Class.forName(className, initialize=true, classLoader)
 * which RUNS this static initializer -- BEFORE resolveClass() consults the acceptMatchers allowlist.
 * Because the object is never delivered to the IoHandler (the allowlist rejects the class after the
 * static block already ran), the flag is surfaced via the shared Beacon rather than an instance field;
 * the server's exceptionCaught() then echoes Beacon.staticInitFlag over the SAME TCP connection.
 *
 *   V1 (mina-core 2.2.4): readClassDescriptor() -> Class.forName("PcbCanary", true) runs THIS static
 *       initializer -> the planted ${PCB_FLAG} canary is read into Beacon, BEFORE resolveClass() later
 *       rejects the (non-allowlisted) class. The flag has already leaked  => REACHES (allowlist bypassed).
 *   V2 (mina-core 2.2.7): readClassDescriptor() applies the acceptMatchers allowlist BEFORE Class.forName,
 *       so a non-allowlisted class is rejected before initialization -> this static initializer never
 *       runs -> Beacon stays empty => BLOCKED.
 *
 * No gadget chain, no command execution: only echoes a random per-run canary token.
 */
public class PcbCanary implements Serializable {
    private static final long serialVersionUID = 1L;

    static {
        try {
            byte[] b = Files.readAllBytes(Paths.get("/canary/flag.txt"));
            Beacon.staticInitFlag = new String(b).trim();
        } catch (Throwable ignore) {
            /* client-side or no canary: harmless no-op */
        }
    }

    public PcbCanary() {}
}
