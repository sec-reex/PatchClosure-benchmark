/*
 * Per-request instantiation marker for the benign PatchClosure-Bench canary.
 *
 * A benign shadow-class's no-arg constructor (see canary/.../InvokerTransformer.java and
 * canary/.../WrapperConnectionPoolDataSource.java) reads the planted /canary/flag.txt and calls
 * CanaryHolder.set(token) DURING jackson's ObjectMapper.readValue() -- i.e. only if the version's real
 * DEFAULT_NO_DESER_CLASS_NAMES blacklist PERMITTED the class name and jackson actually instantiated it.
 * The HTTP service reads CanaryHolder.get() right after readValue on the SAME request thread and echoes
 * the token in the HTTP response. If the blacklist blocked the name, checkIllegalTypes() throws BEFORE
 * construction, the shadow ctor never runs, get() is null, and no flag is emitted.
 *
 * A ThreadLocal keeps concurrent requests isolated: the ctor runs on the same thread as readValue().
 */
package com.pcb;

public final class CanaryHolder {
    private static final ThreadLocal<String> LAST = new ThreadLocal<>();

    private CanaryHolder() { }

    /** Called by a benign shadow-class ctor once jackson instantiates it past the blacklist. */
    public static void set(String token) { LAST.set(token); }

    /** The token captured by a shadow-class instantiated on this request thread, or null. */
    public static String get() { return LAST.get(); }

    /** Reset before each request so a stale value cannot leak across requests. */
    public static void clear() { LAST.remove(); }
}
