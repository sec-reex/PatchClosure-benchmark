import java.io.Serializable;

/**
 * BENIGN "legitimate application" class for deser_mina_objser. This is the ONE class the MINA server
 * adds to its acceptMatchers allowlist (the required post-CVE-2024-52046 configuration step). It has NO
 * flag side effect. It exists so V1/V2 carry a real, NON-EMPTY allowlist that permits genuine app
 * traffic while rejecting the attacker's PcbSeed. The client also sends it as a control ("expected"
 * mode) to prove the allowlist is live (PcbExpected accepted while PcbSeed is rejected).
 */
public class PcbExpected implements Serializable {
    private static final long serialVersionUID = 1L;
    public String note = "legit-app-object";
    public PcbExpected() {}
}
