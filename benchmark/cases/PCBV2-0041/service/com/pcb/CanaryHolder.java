/*
 * Per-request instantiation marker for the benign PatchClosure-Bench canary (deser_fastjson_autotype).
 *
 * The benign shadow bean com.mchange.PcbFlagBean's no-arg CONSTRUCTOR (see canary/com/mchange/PcbFlagBean.java)
 * reads the planted /canary/flag.txt and calls CanaryHolder.set(token) DURING com.alibaba.fastjson.JSON.parse() --
 * i.e. only if the running fastjson version's real ParserConfig.checkAutoType() RESOLVED the @type class name and
 * fastjson actually instantiated the bean. The HTTP service reads CanaryHolder.get() right after JSON.parse on the
 * SAME request thread and echoes the token in the HTTP response. If checkAutoType denied the name, it throws
 * "autoType is not support ..." BEFORE construction, the bean ctor never runs, get() is null, and no flag is emitted.
 *
 * A ThreadLocal keeps concurrent requests isolated: the ctor runs on the same thread as JSON.parse().
 */
package com.pcb;

public final class CanaryHolder {
    private static final ThreadLocal<String> LAST = new ThreadLocal<>();

    private CanaryHolder() { }

    /** Called by the benign shadow bean ctor once fastjson instantiates it past checkAutoType. */
    public static void set(String token) { LAST.set(token); }

    /** The token captured by a shadow bean instantiated on this request thread, or null. */
    public static String get() { return LAST.get(); }

    /** Reset before each request so a stale value cannot leak across requests. */
    public static void clear() { LAST.remove(); }
}
