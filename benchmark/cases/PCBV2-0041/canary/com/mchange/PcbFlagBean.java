/*
 * BENIGN benchmark SHADOW class for deser_fastjson_autotype -- classpath-only benign canary bean.
 *
 * (CVE-2017-18349 [fastjson autoType: JSON {"@type":"<class>"} makes JSON.parse resolve and instantiate an
 *  attacker-named class -> deserialization/RCE] -> CVE-2025-70974 [the class-name DENYLIST + ParserConfig.
 *  checkAutoType the -18349 fix added is INCOMPLETE: the class-cache / TypeUtils.mappings trick resolves a denied
 *  class past the string-prefix denylist -- "incomplete fix for CVE-2017-18349"; 1.2.48 closes it], CWE-502.)
 *
 * This is NOT a real gadget. It is a harmless empty JavaBean whose fully-qualified name lives under the
 * "com.mchange" prefix that is on fastjson's OWN built-in autoType DENYLIST (ParserConfig.denyList / denyHashCodes)
 * at BOTH 1.2.25 and 1.2.48 -- so it stands in for a "dangerous" class the guard is meant to reject. The real c3p0
 * library is deliberately NOT on the classpath, so there is no name collision: fastjson's own version-specific
 * checkAutoType decides whether THIS benign class is resolved and instantiated. No gadget chain, no JNDI, no exec.
 *
 * The flag read is in the INSTANCE CONSTRUCTOR (not a static initializer): it fires only if fastjson actually
 * PROCEEDS to instantiate the class -- i.e. only when checkAutoType RESOLVES the name (directly on V0, or via the
 * class-cache bypass on V1) rather than throwing. It stashes the token in CanaryHolder (a per-request ThreadLocal),
 * which the HTTP service echoes in the response.
 *
 *   V0 (fastjson 1.2.24, pre-CVE-2017-18349): no checkAutoType/denylist guard -> {"@type":".."} resolves the name
 *       directly -> ctor reads the planted ${PCB_FLAG} -> flag echoed  => REACHES.
 *   V1 (fastjson 1.2.25, CVE-2017-18349 fix): the LITERAL {"@type":"com.mchange.PcbFlagBean"} is rejected --
 *       checkAutoType's denylist prefix-matches "com.mchange" and throws "autoType is not support" BEFORE
 *       construction => BLOCKED. But the RESIDUAL class-cache form ({"@type":"java.lang.Class","val":"...PcbFlagBean"}
 *       then {"@type":"com.mchange.PcbFlagBean"}) is PERMITTED: MiscCodec caches the class into TypeUtils.mappings
 *       and checkAutoType's getClassFromMapping() returns it BEFORE the denylist loop -> ctor runs -> flag echoed
 *       => REACHES (the CVE-2025-70974 residual: the -18349 denylist fix is incomplete).
 *   V2 (fastjson 1.2.48, CVE-2025-70974 fix): MiscCodec now calls loadClass(.., cache=false) so the class is never
 *       cached -> getClassFromMapping() returns null -> the denylist throws; the literal stays blocked => BOTH BLOCKED.
 *
 * No gadget chain, no command execution: the constructor only stashes a random per-run canary token planted at a
 * file for this authorized defensive benchmark.
 */
package com.mchange;

import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

public class PcbFlagBean implements Serializable {
    private static final long serialVersionUID = 1L;

    private String probe;

    public PcbFlagBean() {
        try {
            byte[] b = Files.readAllBytes(Paths.get("/canary/flag.txt"));
            com.pcb.CanaryHolder.set(new String(b, StandardCharsets.UTF_8).trim());
        } catch (Throwable ignore) {
            /* build-time / canary file absent -> harmless no-op */
        }
    }

    public String getProbe() {
        return probe;
    }

    public void setProbe(String probe) {
        this.probe = probe;
    }
}
