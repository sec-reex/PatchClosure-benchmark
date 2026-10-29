import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.SignedObject;

import hudson.remoting.ObjectInputStreamEx;

import org.apache.commons.collections.functors.PcbSeed;

/**
 * REAL Jenkins remoting TCP server for deser_jenkins_remoting -- the genuine way remoting is used
 * (hudson.remoting is a NETWORK channel framework; its real usage is a TCP channel between two JVMs).
 *
 * (CVE-2015-8103 [Jenkins remoting CLI Java deserialization -> RCE; fix ADDS the hudson.remoting
 *  ClassFilter blacklist applied in ObjectInputStreamEx.resolveClass()] -> CVE-2017-1000353 [a serialized
 *  java.security.SignedObject is deserialized by the remoting deser sink, and SignedObject.getObject()
 *  reconstructs its signed payload with a NEW, PLAIN ObjectInputStream that is NOT wrapped by the
 *  ClassFilter -> the blacklist is bypassed; the fix ADDS java.security.SignedObject to the blacklist],
 *  CWE-502).
 *
 * This server binds a real TCP ServerSocket and, for each incoming connection from an EXTERNAL client,
 * reads the object off the socket THROUGH THE REAL, UNMODIFIED remoting deserialization class:
 *
 *     ObjectInputStreamEx ois = new ObjectInputStreamEx(socket.getInputStream(), cl);   // the 2-arg
 *         // CLI Command#readFrom form -> resolveClass() runs ClassFilter.DEFAULT.check(name) on V1/V2
 *     Object obj = ois.readObject();
 *
 * This is EXACTLY the sink hudson.remoting.Command#readFrom uses to unmarshal objects arriving off the
 * network channel: `new ObjectInputStreamEx(in, getClassLoader())`. On remoting 2.52 (V0) that 2-arg
 * ctor applies NO filter (bare Class.forName); on 2.53 (V1) it delegates to ClassFilter.DEFAULT
 * (CVE-2015-8103 blacklist); on 3.16 (V2) to ClassFilter.DEFAULT + java.security.SignedObject. No
 * remoting code is modified -- whether the flag is read is decided ENTIRELY by that version's own
 * unmodified ObjectInputStreamEx/ClassFilter, applied to bytes arriving over a real TCP socket from a
 * separate process/container.
 *
 * After the outer readObject(), if the result is a java.security.SignedObject the server calls
 * getObject() -- faithfully the CVE-2017-1000353 trigger, where SignedObject.getObject() spins up its OWN
 * plain ObjectInputStream (no ClassFilter) to reconstruct the signed payload. On V2 that call is never
 * reached because the outer ClassFilter rejects SignedObject first. The reconstructed PcbSeed's
 * readObject() has already read the planted ${PCB_FLAG} canary into its transient `flag` field; the
 * server then echoes that flag back over the SAME TCP connection.
 *
 * Nothing is deserialized in-process by a test harness: the trigger is a real external client sending
 * bytes over a real TCP socket to this real remoting deserialization sink.
 *
 * args: [port]   (default 9009)
 */
public class Server {

    static Throwable root(Throwable t) {
        Throwable c = t;
        while (c.getCause() != null && c.getCause() != c) {
            c = c.getCause();
        }
        return c;
    }

    static String clean(String s) {
        if (s == null) return "";
        return s.replace('\n', ' ').replace('\r', ' ');
    }

    /** Handle one external TCP connection through the REAL remoting deser sink. */
    static void handle(Socket sock, ClassLoader cl) {
        String reply;
        try {
            InputStream in = sock.getInputStream();
            // THE REAL REMOTING SINK over a real network socket: ObjectInputStreamEx(in, cl)
            // -> resolveClass() -> ClassFilter.DEFAULT (on remoting 2.53+). Exactly what
            // hudson.remoting.Command#readFrom does to unmarshal objects off the channel.
            ObjectInputStreamEx ois = new ObjectInputStreamEx(in, cl);
            Object obj = ois.readObject();
            String outer = obj == null ? "null" : obj.getClass().getName();
            Object result = obj;
            String inner = "";
            if (obj instanceof SignedObject) {
                // Nested, UNFILTERED reconstruction: SignedObject.getObject() opens its own plain
                // ObjectInputStream, not wrapped by remoting's ClassFilter (the CVE-2017-1000353 bypass).
                result = ((SignedObject) obj).getObject();
                inner = result == null ? "null" : result.getClass().getName();
            }
            if (result instanceof PcbSeed) {
                String f = ((PcbSeed) result).flag;
                reply = "PCB_SEED_FLAG=" + (f == null ? "" : f) + " outer=" + outer + " inner=" + inner;
            } else {
                reply = "PCB_OK=" + outer + " inner=" + inner;
            }
        } catch (Throwable t) {
            // The ClassFilter (or any decode error) rejected the class BEFORE reconstruction:
            // no PcbSeed instance, no flag -- report the block.
            Throwable c = root(t);
            reply = "PCB_BLOCKED=" + c.getClass().getSimpleName() + ":" + clean(String.valueOf(c.getMessage()));
        }
        try {
            OutputStream os = sock.getOutputStream();
            os.write(reply.getBytes(StandardCharsets.UTF_8));
            os.flush();
        } catch (Throwable ignore) {
        }
        try {
            sock.close();
        } catch (Throwable ignore) {
        }
    }

    public static void main(String[] args) throws Exception {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 9009;
        final ClassLoader cl = Server.class.getClassLoader();

        ServerSocket ss = new ServerSocket(port);
        System.out.println("PCB_SERVER_LISTENING port=" + port
                + " sink=hudson.remoting.ObjectInputStreamEx(socket,cl)+ClassFilter.DEFAULT");
        System.out.flush();

        // Real server loop: accept external TCP connections forever, one deser per connection.
        while (true) {
            final Socket sock = ss.accept();
            Thread t = new Thread(new Runnable() {
                @Override
                public void run() {
                    handle(sock, cl);
                }
            });
            t.setDaemon(true);
            t.start();
        }
    }
}
