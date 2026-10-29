package com.pcb;

import org.apache.dubbo.config.ApplicationConfig;
import org.apache.dubbo.config.ProtocolConfig;
import org.apache.dubbo.config.RegistryConfig;
import org.apache.dubbo.config.ServiceConfig;

/**
 * Minimal REAL Dubbo provider. Exports DemoService over the dubbo:// protocol on a fixed TCP port
 * with NO registry (RegistryConfig "N/A") -- no ZooKeeper needed. It binds 0.0.0.0:20880 so a
 * SEPARATE attacker-client container can reach it over the REAL docker network by service name
 * (dubbo://<service>:20880). The provider's default remoting serialization is hessian2 (id 2), so on
 * V2 CodecSupport.checkSerialization expects id 2 and rejects a network frame that flips to
 * native-hessian (id 10).
 *
 * The provider is UNMODIFIED Dubbo at the pinned version (DUBBO_VER build-arg). Whether an incoming
 * RPC argument instantiates com.pcb.PcbFlagProbe is decided ENTIRELY by that version's own codec +
 * hessian2 ClassFactory whitelist (enabled on V1/V2 via -Ddubbo.application.hessian2.whitelist=true)
 * + checkSerialization (enabled on V2 via -Dserialization.security.check=true).
 */
public class Provider {
    public static final int PORT = 20880;
    public static final String VERSION = "1.0.0";

    public static void main(String[] args) throws Exception {
        System.setProperty("dubbo.application.qos.enable", "false");
        System.setProperty("java.net.preferIPv4Stack", "true");

        ApplicationConfig application = new ApplicationConfig("pcb-dubbo-provider");
        application.setQosEnable(false);

        RegistryConfig registry = new RegistryConfig();
        registry.setAddress(RegistryConfig.NO_AVAILABLE); // "N/A" -> export without a registry

        ProtocolConfig protocol = new ProtocolConfig("dubbo", PORT);
        protocol.setHost("0.0.0.0");                 // bind all interfaces -> reachable across the docker network
        protocol.setSerialization("hessian2");       // server-side configured serialization = id 2
        // 2.7.6 closes the Netty channel if the first inbound is a raw TCP probe or a
        // newer-client heartbeat it cannot decode. Keep the default codec; do not idle-kill.
        protocol.setHeartbeat(60000);
        protocol.setDispatcher("all");

        ServiceConfig<DemoService> service = new ServiceConfig<>();
        service.setApplication(application);
        service.setRegistry(registry);
        service.setRegister(false);
        service.setProtocol(protocol);
        service.setInterface(DemoService.class);
        service.setRef(new DemoServiceImpl());
        service.setVersion(VERSION);
        service.export();

        System.out.println("PROVIDER_READY port=" + PORT + " version=" + VERSION
                + " whitelist=" + System.getProperty("dubbo.application.hessian2.whitelist")
                + " seccheck=" + System.getProperty("serialization.security.check"));
        System.out.flush();

        // 2.7.6 can interrupt main after a decode error; do not let that exit the JVM.
        while (true) {
            try {
                Thread.sleep(60_000L);
            } catch (InterruptedException ie) {
                Thread.interrupted();
            }
        }
    }
}
