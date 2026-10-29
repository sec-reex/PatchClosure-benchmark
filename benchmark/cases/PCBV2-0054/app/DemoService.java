package com.pcb;

/**
 * The one service the minimal Dubbo provider exports. The method takes Object so any concrete class
 * named in the incoming RPC-argument stream is resolved/instantiated by the provider's deserializer
 * (the real Dubbo sink). The method MUST exist so the CVE-2020-1948 "do not deserialize args for
 * unknown service/method" gate does not short-circuit -- the differential here is the hessian2
 * allowlist / serializer-switch, not the method-lookup gate.
 */
public interface DemoService {
    String probe(Object arg);
}
