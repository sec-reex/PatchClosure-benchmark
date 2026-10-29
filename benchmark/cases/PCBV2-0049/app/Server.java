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
 * REAL Apache MINA TCP server for apache-mina-cve-2026-42778 -- the genuine way MINA is used (a network
 * server), NOT an in-process harness.
 *
 * (CVE-2024-52046 [ObjectSerializationDecoder / AbstractIoBuffer.getObject() unbounded Java
 *  deserialization -> RCE; fix ADDS the acceptMatchers class allowlist, enforced in resolveClass()] ->
 *  CVE-2026-42778 [the allowlist is applied TOO LATE: the decoder's readClassDescriptor() calls
 *  Class.forName(name, initialize=true) BEFORE the allowlist, so a non-allowlisted class's STATIC
 *  INITIALIZER already ran by the time resolveClass() rejects it], CWE-502).
 *
 * A NioSocketAcceptor binds a TCP port and installs ProtocolCodecFilter(ObjectSerializationCodecFactory).
 * The factory's acceptMatchers allowlist is configured (via reflection, so ONE Server.java compiles on
 * V0=2.2.3 which predates the accept() API) to accept ONLY the legitimate app class PcbExpected -- NOT the
 * attacker's PcbSeed / PcbCanary. An EXTERNAL TCP client (Client.java, a separate process/container)
 * connects over the network and writes a length-prefixed MINA serialized stream; the decoder's doDecode
 * calls the REAL, unmodified in.setMatchers(acceptMatchers) + in.getObject(classLoader), so this version's
 * own readClassDescriptor()/resolveClass() ordering decides what runs before the class is rejected:
 *
 *   - PcbSeed  (readObject flag channel)  : flag read only during FULL reconstruction. Reaches on V0
 *       (no allowlist); BLOCKED on V1 (resolveClass rejects before construction -> readObject never runs).
 *   - PcbCanary (static-initializer flag channel) : flag read in a STATIC block. On V1 the class is
 *       RESOLVED (Class.forName(name,true) -> static init -> Beacon) BEFORE resolveClass rejects it, so
 *       the flag leaks anyway (the CVE-2026-42778 residual). On V2 the allowlist runs first -> never
 *       resolved -> static init never runs.
 *
 * Two DISTINCT side-channels let the oracle tell the readObject flag from the static-init flag:
 *   messageReceived  -> "PCB_MSG ... PCB_READOBJECT=<PcbSeed.flag> PCB_STATICINIT=<Beacon>"
 *   exceptionCaught  -> "PCB_ERR <cause> PCB_STATICINIT=<Beacon>"     (class rejected; static may have run)
 * Beacon is reset to "" on every new connection so a stale value can never leak into another probe.
 *
 * No MINA code is modified. Nothing is deserialized in-process by a test harness: the trigger is a real
 * external client sending bytes over a real TCP socket to a real MINA acceptor.
 *
 * args: [port]   (default 9009)
 */
public class Server {

    static final String ALLOW = "PcbExpected"; // the ONE allowlisted legit class; attacker classes are NOT on it.

    static String nz(String s) { return s == null ? "" : s; }

    static class Handler extends IoHandlerAdapter {
        @Override
        public void sessionCreated(IoSession session) {
            // Fresh per-connection state: no stale static-initializer flag can leak into this probe.
            Beacon.staticInitFlag = "";
        }

        @Override
        public void messageReceived(IoSession session, Object message) {
            // Reached only if the decoder reconstructed the object PAST the allowlist (V0 any class;
            // V1/V2 only the allowlisted PcbExpected).
            String ro = (message instanceof PcbSeed) ? nz(((PcbSeed) message).flag) : "";
            String si = nz(Beacon.staticInitFlag);
            session.write("PCB_MSG class=" + message.getClass().getName()
                    + " PCB_READOBJECT=" + ro + " PCB_STATICINIT=" + si);
        }

        @Override
        public void messageSent(IoSession session, Object message) {
            session.closeOnFlush();
        }

        @Override
        public void exceptionCaught(IoSession session, Throwable cause) {
            // The allowlist (or a decode error) rejected the class: no object was constructed and none
            // reached messageReceived. BUT on V1 a non-allowlisted class's STATIC INITIALIZER already ran
            // during readClassDescriptor()'s Class.forName(name,true) -> its flag sits in Beacon. Echo it.
            Throwable c = cause;
            while (c.getCause() != null) {
                c = c.getCause();
            }
            String si = nz(Beacon.staticInitFlag);
            String msg = (c.getClass().getSimpleName() + ":" + String.valueOf(c.getMessage()))
                    .replace('\n', ' ').replace('\r', ' ');
            try {
                session.write("PCB_ERR " + msg + " PCB_STATICINIT=" + si);
            } catch (Throwable ignore) {
            }
            session.closeOnFlush();
        }
    }

    public static void main(String[] args) throws Exception {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 9009;

        ObjectSerializationCodecFactory codec = new ObjectSerializationCodecFactory();

        // Configure the CVE-2024-52046 acceptMatchers allowlist to accept ONLY PcbExpected. Reflection so
        // the SAME source compiles/runs on V0=2.2.3 (no accept() API => unrestricted deserialization).
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
