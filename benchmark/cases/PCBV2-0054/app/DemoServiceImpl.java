package com.pcb;

/**
 * Trivial implementation. The business logic is irrelevant: the vulnerability/oracle fires during
 * the provider's DESERIALIZATION of the RPC argument (before the method body runs), when the real
 * Dubbo codec instantiates the class named in the argument stream. By the time probe() runs the
 * argument has already been (or been prevented from being) instantiated.
 */
public class DemoServiceImpl implements DemoService {
    @Override
    public String probe(Object arg) {
        return "ok:" + (arg == null ? "null" : arg.getClass().getName());
    }
}
