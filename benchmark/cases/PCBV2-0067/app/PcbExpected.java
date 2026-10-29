import java.io.Serializable;

/**
 * BENIGN "legitimate application" control object for deser_jenkins_remoting. Its class name is NOT on the
 * remoting ClassFilter blacklist, so it deserializes successfully on ALL of V0/V1/V2. The external client
 * sends it as a control ("expected" mode) to prove the ClassFilter blacklist is SELECTIVE (it blocks the
 * dangerous gadget family, not all traffic) -- i.e. V1/V2 still carry ordinary remoting objects over the
 * same TCP sink while rejecting the attacker's PcbSeed. It has NO flag side effect.
 */
public class PcbExpected implements Serializable {
    private static final long serialVersionUID = 1L;
    public String note = "legit-remoting-object";
    public PcbExpected() {}
}
