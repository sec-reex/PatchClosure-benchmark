import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpObjectAggregator;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpServerCodec;
import io.netty.handler.codec.http.HttpVersion;
import io.netty.util.CharsetUtil;

/**
 * Faithful-core harness for io.netty:netty-codec-http request-smuggling
 * (CVE-2019-16869 -> CVE-2020-7238, CWE-444). A tiny, unmodified Netty HTTP
 * origin server. The pipeline is exactly HttpServerCodec (the class both CVEs
 * patch) + HttpObjectAggregator + a router. The version's OWN HttpObjectDecoder
 * decides whether a malformed-framed front request is accepted; nothing in Netty
 * is modified.
 *
 * Routes:
 *   POST /       -> "ok"          (the benign front request)
 *   GET  /flag   -> ${PCB_FLAG}   (internal canary the smuggled sub-request targets)
 *
 * If the front request's framing is MIS-parsed (accepted) by this version's
 * decoder, the pipelined "GET /flag" that follows on the same connection is
 * decoded as a SECOND request and reaches /flag -> FLAG. If the decoder REJECTS
 * the malformed framing it enters BAD_MESSAGE: the front request carries a failed
 * DecoderResult (we answer 400 + close) and the trailing "GET /flag" bytes are
 * swallowed as opaque bad-message content, never decoded -> NO FLAG.
 */
public class Server {
    static final String FLAG = System.getenv().getOrDefault("PCB_FLAG", "PCB_FLAG_unset");
    static final int PORT = Integer.parseInt(System.getenv().getOrDefault("APP_PORT", "8080"));

    public static void main(String[] args) throws Exception {
        EventLoopGroup boss = new NioEventLoopGroup(1);
        EventLoopGroup work = new NioEventLoopGroup();
        try {
            ServerBootstrap b = new ServerBootstrap();
            b.group(boss, work)
             .channel(NioServerSocketChannel.class)
             .childHandler(new ChannelInitializer<SocketChannel>() {
                 @Override
                 protected void initChannel(SocketChannel ch) {
                     ChannelPipeline p = ch.pipeline();
                     p.addLast(new HttpServerCodec());
                     p.addLast(new HttpObjectAggregator(65536));
                     p.addLast(new Router());
                 }
             });
            Channel c = b.bind(PORT).sync().channel();
            System.out.println("[netty-harness netty=" + System.getProperty("nettyver", "?")
                    + "] listening on 0.0.0.0:" + PORT
                    + " flag_set=" + (!FLAG.equals("PCB_FLAG_unset")));
            System.out.flush();
            c.closeFuture().sync();
        } finally {
            boss.shutdownGracefully();
            work.shutdownGracefully();
        }
    }

    static class Router extends SimpleChannelInboundHandler<FullHttpRequest> {
        @Override
        protected void channelRead0(ChannelHandlerContext ctx, FullHttpRequest req) {
            // A malformed-framed request that the decoder rejected arrives with a
            // failed DecoderResult -> reject with 400 and close (no flag path).
            if (req.decoderResult().isFailure()) {
                send(ctx, HttpResponseStatus.BAD_REQUEST, "bad request", true);
                return;
            }
            String uri = req.uri();
            boolean close = "close".equalsIgnoreCase(req.headers().get(HttpHeaderNames.CONNECTION));
            if (uri.equals("/flag") || uri.startsWith("/flag?")) {
                send(ctx, HttpResponseStatus.OK, FLAG, close);
            } else {
                send(ctx, HttpResponseStatus.OK, "ok", close);
            }
        }

        private void send(ChannelHandlerContext ctx, HttpResponseStatus st, String body, boolean close) {
            FullHttpResponse r = new DefaultFullHttpResponse(
                    HttpVersion.HTTP_1_1, st, Unpooled.copiedBuffer(body, CharsetUtil.UTF_8));
            r.headers().set(HttpHeaderNames.CONTENT_TYPE, "text/plain; charset=UTF-8");
            r.headers().setInt(HttpHeaderNames.CONTENT_LENGTH, r.content().readableBytes());
            if (close) {
                r.headers().set(HttpHeaderNames.CONNECTION, "close");
                ctx.writeAndFlush(r).addListener(ChannelFutureListener.CLOSE);
            } else {
                r.headers().set(HttpHeaderNames.CONNECTION, "keep-alive");
                ctx.writeAndFlush(r);
            }
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            ctx.close();
        }
    }
}
