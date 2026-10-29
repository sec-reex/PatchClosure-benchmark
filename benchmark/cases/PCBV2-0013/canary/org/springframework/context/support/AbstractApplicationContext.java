/*
 * CVE-2017-17485 residual: BENIGN shadow SUPERCLASS (no gadget behaviour), classpath-only canary jar.
 *
 * This is NOT the real Spring Framework AbstractApplicationContext (spring-context is deliberately
 * NOT on the classpath). It is a minimal benign stand-in that occupies the exact simple name
 * "AbstractApplicationContext" under the "org.springframework." package prefix, so that the
 * CVE-2017-17485 fix in jackson-databind 2.9.4 (databind#1855, SubTypeValidator.validateSubType)
 * can recognise the residual leaf class by walking its superclass chain.
 *
 * The CVE-2017-17485 guard added in 2.9.4 does NOT blacklist the residual by fully-qualified name;
 * instead, for any concrete class whose name starts with "org.springframework." it walks the
 * superclass chain and rejects the type if any ancestor's SIMPLE name equals
 * "AbstractApplicationContext" (or "AbstractPointcutAdvisor"). Faithfully reproducing the guard
 * therefore requires the residual leaf (FileSystemXmlApplicationContext) to extend a class named
 * AbstractApplicationContext -- this class.
 *
 * It carries no bean properties and no flag logic; the per-run canary is read only by the leaf's
 * constructor (which runs only if the version's guard PERMITS the residual and jackson instantiates).
 */
package org.springframework.context.support;

import java.io.Serializable;

public class AbstractApplicationContext implements Serializable {
    private static final long serialVersionUID = 1L;

    public AbstractApplicationContext() {
        /* benign no-arg superclass constructor; no gadget behaviour */
    }
}
