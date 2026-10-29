import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * CVE-2024-52046 SEED class (BENIGN benchmark canary) -- the READOBJECT flag channel.
 *
 * The flag read happens ONLY during FULL object reconstruction, inside readObject(). It has NO
 * flag-reading static initializer. This models the original MINA deserialization RCE: an untrusted,
 * non-allowlisted class is deserialized to completion and its readObject runs. The flag is bound into
 * a transient instance field, so it never travels on the wire (the external client has no canary);
 * it is set only server-side during reconstruction, then the server's IoHandler echoes it over TCP.
 *
 *   V0 (mina-core 2.2.3, no allowlist): the real getObject() reconstructs PcbSeed -> readObject()
 *       reads the planted ${PCB_FLAG} canary -> echoed as PCB_READOBJECT=<flag>  => REACHES.
 *   V1 (mina-core 2.2.4, acceptMatchers allowlist): resolveClass() rejects PcbSeed (not allowlisted)
 *       and throws BEFORE the object is constructed -> readObject() never runs -> no readObject flag
 *       => BLOCKED. (PcbSeed has no static initializer flag, so nothing else leaks either.)
 *
 * No gadget chain, no command execution: readObject() merely echoes a random per-run token planted
 * at a canary file for this authorized defensive benchmark.
 */
public class PcbSeed implements Serializable {
    private static final long serialVersionUID = 1L;

    /** Populated ONLY during server-side reconstruction (readObject); transient => never on the wire. */
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
