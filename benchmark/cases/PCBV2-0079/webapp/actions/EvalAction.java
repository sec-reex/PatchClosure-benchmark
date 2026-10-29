// PatchClosure-Bench action for apache-struts-cve-2021-31805
// (CVE-2020-17530 [S2-061] -> CVE-2021-31805 [S2-062], Apache Struts 2 forced double OGNL
//  evaluation of UI-tag attributes, CWE-917 EL-injection). SAME action for all 3 profiles: the
//  differential lives entirely inside the version's own unmodified struts2-core UIBean/Component
//  code, not in this application code.
//
// The action binds the request parameter `prop` onto a String property (ordinary Struts parameter
// binding -- a String setter is assigned the raw value, NOT OGNL-evaluated) and plants the benign
// per-run ${PCB_FLAG} canary as an OGNL context variable #pcbflag on the ValueStack context that
// eval.jsp later renders over. A developer then forced-OGNL-evaluates `prop` inside a real
// <s:textfield> attribute (id="%{prop}" / name="%{prop}"). Whether that already-substituted value
// is OGNL-evaluated a SECOND time (resolving #pcbflag) is decided by the version's own code.
//
// BENIGN CANARY (read-exfil): the attacker OGNL only READS the planted context variable #pcbflag
// (= ${PCB_FLAG}); there is NO Runtime.exec, NO ProcessBuilder, NO reflection, NO static-method
// call. The flag merely surfacing in the rendered tag proves the second evaluation fired.
package pcb;

import com.opensymphony.xwork2.ActionContext;
import com.opensymphony.xwork2.ActionSupport;

public class EvalAction extends ActionSupport {

    // Attacker-controlled action property that a developer forced-evaluates via %{prop} in a tag
    // attribute. Bound from the request parameter `prop` by the ordinary ParametersInterceptor
    // (String setter => the raw value is assigned, not evaluated).
    private String prop;

    public void setProp(String prop) { this.prop = prop; }
    public String getProp() { return prop; }

    @Override
    public String execute() {
        String flag = System.getenv("PCB_FLAG");
        if (flag == null) flag = "";
        // Plant the benign canary as an OGNL context variable: #pcbflag -> ${PCB_FLAG}. This is the
        // SAME ValueStack context that eval.jsp's <s:textfield> tags render over, so a second OGNL
        // evaluation of the forced attribute can resolve #pcbflag.
        ActionContext.getContext().put("pcbflag", flag);
        return SUCCESS;
    }
}
