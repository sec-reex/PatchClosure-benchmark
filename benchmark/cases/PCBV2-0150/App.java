// PatchClosure-Bench REAL Netty app for netty-cve-2026-42578.
//
// A REAL, unmodified Netty CLIENT/SERVER application. It runs a Netty HTTP server
// (HttpServerCodec) on APP_PORT and, on an EXTERNAL HTTP request to its own endpoint,
// drives the REAL, unmodified published Netty client code to make an OUTBOUND request to
// a SEPARATE proxy sidecar container over the docker network. No Netty code is modified;
// the version's own guard decides whether an attacker-influenced CRLF splits the wire.
//
// Endpoints (the attacker value is delivered RAW -- CRLF and all -- in the POST body of the
// EXTERNAL HTTP request, so no query/percent encoding can perturb it; the app forwards that value
// straight into the outbound request, a realistic value-forwarding app):
//
//   POST /fetch?nonce=<n>   body=<value>   SEED  (CVE-2025-67735): the body value becomes the
//        request URI of an outbound Netty DefaultHttpRequest, encoded by the REAL HttpRequestEncoder
//        and sent to the sidecar. Pre-fix (4.1.128) writes the URI raw so a second "GET /flag"
//        request line splits off at the sidecar; the CVE-2025-67735 fix (4.1.129) runs
//        HttpUtil.validateRequestLineTokens in the constructor and THROWS on the CR/LF -> no bytes
//        sent -> BLOCKED.
//
//   POST /proxyfetch?nonce=<n>  body=<value>  RESIDUAL (CVE-2026-42578): the body value becomes a
//        CONNECT proxy header value added via the REAL HttpProxyHandler pointed at the sidecar (the
//        upstream proxy) over a real Nio socket. On 4.1.129..4.1.132 newInitialMessage() hard-codes
//        withValidation(false), so the CRLF survives and a "GET /flag" line splits off in the CONNECT
//        bytes at the sidecar (REACHES on V1). The CVE-2026-42578 fix (4.1.133) defaults
//        validateInitialHeaders=true, so req.headers().add(value) validates and THROWS (prohibited
//        char 0x0d) -> handshake fails, no bytes -> BLOCKED on V2.
import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.DefaultHttpHeaders;
import io.netty.handler.codec.http.DefaultHttpRequest;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpHeaders;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpObjectAggregator;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpRequestEncoder;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpServerCodec;
import io.netty.handler.codec.http.HttpVersion;
import io.netty.handler.codec.http.LastHttpContent;
import io.netty.handler.codec.http.QueryStringDecoder;
import io.netty.handler.proxy.HttpProxyHandler;
import io.netty.resolver.NoopAddressResolverGroup;
import io.netty.util.CharsetUtil;
import io.netty.util.ReferenceCountUtil;

import java.io.ByteArrayOutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.List;

public final class App {
    static final String NETTY_VER = System.getProperty("nettyver", "?");
    static final int PORT = Integer.parseInt(System.getenv().getOrDefault("APP_PORT", "8080"));
    static final String PROXY_HOST = System.getenv().getOrDefault("PROXY_HOST", "sidecar");
    static final int PROXY_PORT = Integer.parseInt(System.getenv().getOrDefault("PROXY_PORT", "9000"));

    public static void main(String[] args) throws Exception {
        EventLoopGroup boss = new NioEventLoopGroup(1);
        EventLoopGroup work = new NioEventLoopGroup();
        try {
            ServerBootstrapBind(boss, work);
        } finally {
            // never reached; server runs until killed
        }
    }

    static void ServerBootstrapBind(EventLoopGroup boss, EventLoopGroup work) throws Exception {
        io.netty.bootstrap.ServerBootstrap b = new io.netty.bootstrap.ServerBootstrap();
        b.group(boss, work)
         .channel(NioServerSocketChannel.class)
         .childHandler(new ChannelInitializer<SocketChannel>() {
             @Override protected void initChannel(SocketChannel ch) {
                 ChannelPipeline p = ch.pipeline();
                 p.addLast(new HttpServerCodec());
                 p.addLast(new HttpObjectAggregator(65536));
                 p.addLast(new Api());
             }
         });
        Channel c = b.bind(PORT).sync().channel();
        System.out.println("[netty-app netty=" + NETTY_VER + "] listening on 0.0.0.0:" + PORT
                + " proxy=" + PROXY_HOST + ":" + PROXY_PORT);
        System.out.flush();
        c.closeFuture().sync();
    }

    // Inbound HTTP endpoint: an EXTERNAL request triggers a REAL outbound Netty request.
    static final class Api extends SimpleChannelInboundHandler<FullHttpRequest> {
        @Override protected void channelRead0(ChannelHandlerContext ctx, FullHttpRequest req) {
            String out;
            try {
                QueryStringDecoder q = new QueryStringDecoder(req.uri());
                String path = q.path();
                String nonce = param(q, "nonce");
                // The attacker value arrives RAW in the request body (CRLF preserved verbatim).
                String hdr = req.content().toString(CharsetUtil.ISO_8859_1);
                if ("/proxyfetch".equals(path)) {
                    out = proxyFetch(hdr, nonce);
                } else if ("/fetch".equals(path)) {
                    out = seedFetch(hdr, nonce);
                } else if ("/health".equals(path)) {
                    out = "ok";
                } else {
                    out = "usage: GET /fetch?hdr=..&nonce=..  |  GET /proxyfetch?hdr=..&nonce=..";
                }
            } catch (Throwable t) {
                out = "APP_ERROR: " + t;
            }
            reply(ctx, out);
        }

        @Override public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            ctx.close();
        }
    }

    static String param(QueryStringDecoder q, String k) {
        List<String> v = q.parameters().get(k);
        return (v == null || v.isEmpty()) ? "" : v.get(0);
    }

    // SEED (CVE-2025-67735): the attacker value becomes the outbound request URI. The version's
    // DefaultHttpRequest constructor is the guard the CVE-2025-67735 fix strengthened.
    static String seedFetch(String hdr, String nonce) {
        byte[] raw;
        try {
            // 4.1.129+ validateRequestLineTokens() throws HERE on the embedded CR/LF.
            HttpRequest req = new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, hdr);
            req.headers().set(HttpHeaderNames.HOST, "victim");
            EmbeddedChannel enc = new EmbeddedChannel(new HttpRequestEncoder());
            enc.writeOutbound(req);
            enc.writeOutbound(LastHttpContent.EMPTY_LAST_CONTENT);
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            for (;;) {
                Object o = enc.readOutbound();
                if (o == null) break;
                if (o instanceof ByteBuf) {
                    ByteBuf bb = (ByteBuf) o;
                    byte[] a = new byte[bb.readableBytes()];
                    bb.readBytes(a);
                    bos.write(a);
                }
                ReferenceCountUtil.release(o);
            }
            raw = bos.toByteArray();
        } catch (Throwable t) {
            return "SEED_BLOCKED: request-line validation rejected value: " + t;
        }
        // Send the REAL Netty-serialized bytes to the SEPARATE sidecar over the network.
        try (Socket s = new Socket(PROXY_HOST, PROXY_PORT)) {
            s.getOutputStream().write(raw);
            s.getOutputStream().flush();
            s.setSoTimeout(800);
            try { s.getInputStream().read(new byte[256]); } catch (Exception ignore) {}
        } catch (Exception e) {
            return "SEED_SENDERR: " + e;
        }
        return "SEED_SENT: " + raw.length + " bytes to " + PROXY_HOST + ":" + PROXY_PORT;
    }

    // RESIDUAL (CVE-2026-42578): the attacker value becomes a CONNECT proxy header value added
    // by the REAL HttpProxyHandler pointed at the sidecar (the upstream proxy) over a real socket.
    static String proxyFetch(String hdr, String nonce) {
        HttpHeaders outbound = new DefaultHttpHeaders(false); // caller-supplied, unvalidated here
        outbound.add("X-Forwarded-For", hdr);
        EventLoopGroup group = new NioEventLoopGroup(1);
        final java.util.concurrent.atomic.AtomicReference<Throwable> err =
                new java.util.concurrent.atomic.AtomicReference<>();
        try {
            Bootstrap b = new Bootstrap();
            b.group(group).channel(NioSocketChannel.class)
             // ProxyHandler needs the final destination unresolved (the proxy resolves it).
             .resolver(NoopAddressResolverGroup.INSTANCE)
             .handler(new ChannelInitializer<Channel>() {
                 @Override protected void initChannel(Channel c) {
                     // newInitialMessage() runs when the handler activates: on 4.1.133 the
                     // withValidation(true) default makes headers().add(value) THROW here, which
                     // propagates as a pipeline exception (captured below); on 4.1.129..4.1.132
                     // it is a no-op and the CRLF survives onto the wire.
                     c.pipeline().addLast(new HttpProxyHandler(
                             new InetSocketAddress(PROXY_HOST, PROXY_PORT), outbound));
                     c.pipeline().addLast(new ChannelInboundHandlerAdapter() {
                         @Override public void channelRead(ChannelHandlerContext x, Object m) {
                             ReferenceCountUtil.release(m);
                         }
                         @Override public void exceptionCaught(ChannelHandlerContext x, Throwable t) {
                             err.compareAndSet(null, t);
                             x.close();
                         }
                     });
                 }
             });
            // Transport connects to the PROXY (sidecar); CONNECT targets this unresolved host.
            ChannelFuture cf = b.connect(InetSocketAddress.createUnresolved("internal.local", 1337));
            cf.awaitUninterruptibly(4000);
            Thread.sleep(400);  // let newInitialMessage()/handshake settle
            Throwable t = err.get();
            if (t == null && cf.cause() != null) t = cf.cause();
            if (t != null) {
                return "PROXY_BLOCKED: CONNECT header validation rejected value: " + t;
            }
            return "PROXY_SENT: CONNECT handshake ok to " + PROXY_HOST + ":" + PROXY_PORT
                    + " (headers not validated on this version)";
        } catch (Throwable t) {
            return "PROXY_BLOCKED: " + t;
        } finally {
            group.shutdownGracefully();
        }
    }

    static void reply(ChannelHandlerContext ctx, String body) {
        FullHttpResponse r = new DefaultFullHttpResponse(
                HttpVersion.HTTP_1_1, HttpResponseStatus.OK,
                Unpooled.copiedBuffer(body + "\n", CharsetUtil.UTF_8));
        r.headers().set(HttpHeaderNames.CONTENT_TYPE, "text/plain; charset=UTF-8");
        r.headers().setInt(HttpHeaderNames.CONTENT_LENGTH, r.content().readableBytes());
        r.headers().set(HttpHeaderNames.CONNECTION, "close");
        ctx.writeAndFlush(r).addListener(ChannelFutureListener.CLOSE);
    }
}
