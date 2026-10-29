/*
 * Per-request instantiation marker for the benign PatchClosure-Bench canary (xstream-cve-2020-26217).
 *
 * The benign shadow canary bean's converter (see XStreamDeserHttpService.CanaryConverter, keyed to
 * pcb.PcbCanary) reads the planted /canary/flag.txt and calls CanaryHolder.set(token) DURING the REAL
 * new XStream().fromXML() -- i.e. only if the version's own default deny-list (setupSecurity())
 * PERMITTED the trigger type that precedes <pcb.PcbCanary/> in the same document, so XStream actually
 * reached and converted the canary element. The HTTP service reads CanaryHolder.get() right after
 * fromXML() on the SAME request thread and echoes the token in the HTTP response. If the deny-list
 * blocked the trigger name, XStream throws ForbiddenClassException BEFORE reaching <pcb.PcbCanary/>,
 * the canary converter never runs, get() is null, and no flag is emitted.
 *
 * A ThreadLocal keeps concurrent requests isolated: the converter runs on the same thread as fromXML().
 */
package com.pcb;

public final class CanaryHolder {
    private static final ThreadLocal<String> LAST = new ThreadLocal<String>();

    private CanaryHolder() { }

    /** Called by the benign pcb.PcbCanary converter once XStream reaches it past the deny-list. */
    public static void set(String token) { LAST.set(token); }

    /** The token captured on this request thread, or null if the canary element was never reached. */
    public static String get() { return LAST.get(); }

    /** Reset before each request so a stale value cannot leak across requests. */
    public static void clear() { LAST.remove(); }
}
