import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * BENIGN benchmark canary class for deser_mina_objser
 * (CVE-2024-52046 acceptMatchers allowlist -> CVE-2026-42779 type-0/null-clazz allowlist bypass, CWE-502).
 *
 * This class is NOT on the MINA server's acceptMatchers allowlist (the server accepts only PcbExpected).
 * The flag read happens ONLY during full object reconstruction, inside readObject() -- so it runs iff
 * the real ObjectSerializationDecoder / AbstractIoBuffer.getObject() actually reconstructs a PcbSeed
 * PAST the allowlist. The ONLY difference between the original seed and the residual is the MINA WIRE
 * ENCODING of the class descriptor (type-1 vs type-0), not the class, the sink, or the channel.
 *
 *   V0 (mina-core 2.2.3, no allowlist API): the decoder reconstructs PcbSeed for EITHER wire encoding
 *       -> readObject() reads the planted ${PCB_FLAG} canary file -> flag echoed back over TCP => REACHES.
 *   V1 (mina-core 2.2.6, CVE-2024-52046 acceptMatchers allowlist):
 *       - NORMAL type-1 payload  -> resolveClass()'s non-null branch runs the allowlist; PcbSeed is not
 *         allowlisted -> ClassNotFoundException BEFORE construction -> readObject never runs => BLOCKED.
 *       - TYPE-0/null-clazz payload -> resolveClass()'s null-clazz branch does Class.forName(name,false)
 *         with NO allowlist -> PcbSeed reconstructed, readObject() runs -> flag echoed => REACHES (residual).
 *   V2 (mina-core 2.2.7, CVE-2026-42779 fix): resolveClass() applies the allowlist FIRST for BOTH
 *       branches -> PcbSeed rejected before any Class.forName -> readObject never runs => BLOCKED.
 *
 * No gadget chain, no command execution: readObject() merely reads a random per-run ${PCB_FLAG} token
 * planted at a canary file for this authorized defensive benchmark. `flag` is transient: it never travels
 * on the wire (the attacker/client has no canary) -- it is bound only server-side during reconstruction,
 * then the server's IoHandler echoes it back over the same TCP connection.
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
