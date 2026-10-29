/*
 * BENIGN CANARY -- ORIGINAL (CVE-2019-9212) shadow-class, shipped as a classpath-only JAR.
 *
 * A harmless, empty Serializable bean whose fully-qualified NAME is `com.caucho.naming.Qname` -- VERBATIM the
 * entry the CVE-2019-9212 remediation added to SOFA Hessian's security/serialize.blacklist on the 3.x line
 * (note the case-typo'd lowercase `Qname`, not the real Resin gadget class QName). It carries NO gadget chain,
 * NO reflection, NO command execution, NO JNDI/RMI -- just a public no-arg constructor and one String field so
 * Hessian can resolve/instantiate the name as an ordinary bean when the real blacklist lets it through.
 *
 * This class exists ONLY to make the ORIGINAL shadow-class name a genuinely resolvable class on the service
 * classpath. The real, UNMODIFIED com.alipay.hessian.NameBlackListFilter decides pass/block on the NAME during
 * SerializerFactory.getDeserializer(typeName) -> ClassNameResolver.resolve(typeName); this bean never runs any
 * flag logic itself (the ${PCB_FLAG} echo is done by the HTTP service upon a successful, non-blacklisted
 * deserialization). The residual shadow-class name com.sun.org.apache.xpath.internal.objects.XString already
 * exists in the JDK (java.xml module) and so is NOT shipped here -- the filter's name-based decision governs.
 *
 *   V0 (3.3.13, pre-9212): blacklist has no com.caucho.naming entry  -> name PASSES  -> flag echoed
 *   V1 (3.5.4, 9212 fix):  blacklist has com.caucho.naming.Qname     -> name BLOCKED -> no flag
 *   V2 (3.5.5, 46983 fix): blacklist retains com.caucho.naming.Qname -> name BLOCKED -> no flag
 */
package com.caucho.naming;

import java.io.Serializable;

public class Qname implements Serializable {
    private static final long serialVersionUID = 1L;
    public String probe;

    public Qname() {
        // Empty: no behavior. Presence on the classpath merely makes the name resolvable.
    }
}
