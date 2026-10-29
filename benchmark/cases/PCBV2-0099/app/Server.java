import java.lang.reflect.Method;
import java.net.InetSocketAddress;
import java.util.regex.Pattern;

import org.apache.mina.core.service.IoHandlerAdapter;
import org.apache.mina.core.session.IdleStatus;
import org.apache.mina.core.session.IoSession;
import org.apache.mina.filter.codec.ProtocolCodecFilter;
import org.apache.mina.filter.codec.serialization.ObjectSerializationCodecFactory;
import org.apache.mina.transport.socket.nio.NioSocketAcceptor;

/**
 * REAL Apache MINA TCP server for deser_mina_objser -- the genuine way MINA is used (a network server).
 *
 * (CVE-2024-52046 [ObjectSerializationDecoder / AbstractIoBuffer.getObject() unbounded Java
 *  deserialization -> RCE; fix ADDS the acceptMatchers class allowlist, enforced ONLY in resolveClass()'s
 *  non-null (type-1) branch] -> CVE-2026-42779 [type-0/null-clazz descriptor bypass: a 0x00 class
 *  descriptor routes to resolveClass()'s null-clazz branch, which calls Class.forName WITHOUT the
 *  allowlist -- the incomplete-fix follow-up to CVE-2026-41635, un-backported to the mina-core 2.2.x
 *  line], CWE-502).
 *
 * A NioSocketAcceptor binds a TCP port and installs a ProtocolCodecFilter(ObjectSerializationCodecFactory).
 * The factory's acceptMatchers allowlist is configured (via reflection, so ONE Server.java compiles on
 * V0=2.2.3 which predates the accept() API) to accept ONLY the legitimate app class PcbExpected -- NOT the
 * attacker's PcbSeed. An EXTERNAL TCP client (see Client.java, a separate process/container) connects over
 * the network and writes a length-prefixed MINA serialized stream; the decoder's doDecode calls the REAL,
 * unmodified in.setMatchers(acceptMatchers) + in.getObject(classLoader), so this version's own
 * readClassDescriptor()/resolveClass() ordering decides whether PcbSeed is reconstructed for the given
 * wire descriptor type. If it is, PcbSeed.readObject() has already read the planted ${PCB_FLAG} canary
 * into its `flag` field; the IoHandler then echoes that flag back over the SAME TCP connection.
 *
 * No MINA code is modified. Nothing is deserialized in-process by a test harness: the trigger is a real
 * external client sending bytes over a real TCP socket to a real MINA acceptor.
 *
 * args: [port]   (default 9009)
 */
public class Server {

    static final String ALLOW = "PcbExpected"; // the ONE allowlisted legit class; PcbSeed is NOT on it.

    static class Handler extends IoHandlerAdapter {
        @Override
        public void messageReceived(IoSession session, Object message) {
            // We only reach here if the decoder reconstructed the object PAST the allowlist.
            if (message instanceof PcbSeed) {
                String f = ((PcbSeed) message).flag;
                session.write("PCB_SEED_FLAG=" + (f == null ? "" : f));
            } else {
                session.write("PCB_OK=" + message.getClass().getName());
            }
        }

        @Override
        public void messageSent(IoSession session, Object message) {
            session.closeOnFlush();
        }

        @Override
        public void exceptionCaught(IoSession session, Throwable cause) {
            // The allowlist (or any decode error) rejected the class BEFORE reconstruction:
            // no PcbSeed instance, no flag -- report the block and close.
            Throwable c = cause;
            while (c.getCause() != null) {
                c = c.getCause();
            }
            String msg = c.getClass().getSimpleName() + ":" + String.valueOf(c.getMessage());
            try {
                session.write("PCB_BLOCKED=" + msg.replace('\n', ' ').replace('\r', ' '));
            } catch (Throwable ignore) {
            }
            session.closeOnFlush();
        }
    }

    public static void main(String[] args) throws Exception {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 9009;

        ObjectSerializationCodecFactory codec = new ObjectSerializationCodecFactory();

        // Configure the CVE-2024-52046 acceptMatchers allowlist to accept ONLY PcbExpected.
        // Reflection so the SAME source compiles/runs on V0=2.2.3 (no accept() API => unrestricted).
        String allowlist;
        try {
            Method accept = codec.getClass().getMethod("accept", Pattern.class);
            accept.invoke(codec, Pattern.compile(ALLOW));
            allowlist = "accept(Pattern:" + ALLOW + ")";
        } catch (NoSuchMethodException nsme) {
            allowlist = "<no accept() API on this mina-core version: unrestricted deserialization>";
        }

        NioSocketAcceptor acceptor = new NioSocketAcceptor();
        acceptor.getFilterChain().addLast("codec", new ProtocolCodecFilter(codec));
        acceptor.setHandler(new Handler());
        acceptor.getSessionConfig().setReadBufferSize(2048);
        acceptor.getSessionConfig().setIdleTime(IdleStatus.BOTH_IDLE, 30);
        acceptor.bind(new InetSocketAddress(port));

        System.out.println("PCB_SERVER_LISTENING port=" + port + " allowlist=" + allowlist);
        System.out.flush();

        // Block forever (real server).
        Thread.currentThread().join();
    }
}
