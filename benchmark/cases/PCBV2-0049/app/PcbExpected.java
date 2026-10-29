import java.io.Serializable;

/**
 * BENIGN "legitimate application" class for apache-mina-cve-2026-42778. This is the ONE class the MINA
 * server adds to its acceptMatchers allowlist (the required post-CVE-2024-52046 configuration step). It
 * has NO flag side effect (no readObject, no static initializer). It exists so V1/V2 carry a real,
 * NON-EMPTY allowlist that permits genuine app traffic while rejecting the attacker's PcbSeed/PcbCanary.
 * The client also sends it as a control ("expected" mode) to prove the allowlist is live (PcbExpected
 * accepted while the attacker classes are rejected), i.e. the guard is not a trivial deny-all.
 */
public class PcbExpected implements Serializable {
    private static final long serialVersionUID = 1L;
    public String note = "legit-app-object";
    public PcbExpected() {}
}
