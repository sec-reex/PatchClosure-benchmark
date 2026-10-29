// [init hook] jenkins-core-cve-2019-10384 -- register a tiny crumb-guarded state-write endpoint.
//
// The seeded secret ${PCB_FLAG} is revealed ONLY by a state-changing POST that the REAL Jenkins
// CrumbFilter + DefaultCrumbIssuer accepts. We register a stock UnprotectedRootAction so the
// endpoint is reachable, but we do NOT do any crumb work ourselves: for POST/PUT/DELETE the real
// CrumbFilter (installed because 10-csrf set a non-null CrumbIssuer) validates the crumb with the
// version-exact DefaultCrumbIssuer BEFORE doReveal is ever invoked. Reaching doReveal on a POST
// therefore PROVES the replayed crumb was accepted by real Jenkins.
//
//   POST /pcbReveal/reveal   (crumb-guarded state-write) -> "STATE_CHANGED secret=<PCB_FLAG>"
//   GET  /pcbReveal/session  (benign helper)             -> creates a web session, returns its id
//
// /pcbReveal/session exists only so the ORIGINAL CVE-2019-10353 seed can model a crumb replayed
// across two DISTINCT web sessions (each client gets its own session). The residual (CVE-2019-10384)
// deliberately never calls it -- its clients stay SESSIONLESS, which is the whole point.
//
// The flag is read from the process environment at request time; it is NEVER baked into the image
// or written to disk (docker-compose injects PCB_FLAG at run time).
import jenkins.model.Jenkins
import hudson.model.RootAction
import hudson.model.UnprotectedRootAction
import org.kohsuke.stapler.StaplerRequest
import org.kohsuke.stapler.StaplerResponse

class PcbRevealAction implements UnprotectedRootAction {
    String getIconFileName() { return null }
    String getDisplayName() { return null }
    String getUrlName() { return "pcbReveal" }

    // Crumb-guarded state-write. The real CrumbFilter has already validated the crumb (real
    // DefaultCrumbIssuer) for this POST; we only enforce the POST verb and reveal the secret.
    void doReveal(StaplerRequest req, StaplerResponse rsp) {
        if (!"POST".equals(req.getMethod())) {
            rsp.sendError(405, "POST required")
            return
        }
        String flag = System.getenv("PCB_FLAG")
        if (flag == null || flag.isEmpty()) {
            rsp.sendError(500, "PCB_FLAG not set")
            return
        }
        rsp.setStatus(200)
        rsp.setContentType("text/plain;charset=UTF-8")
        rsp.getWriter().write("STATE_CHANGED secret=" + flag)
    }

    // Benign helper: force a real web session so the CVE-2019-10353 seed can replay a crumb
    // across two different sessions. GET, so no crumb is required to obtain a session.
    void doSession(StaplerRequest req, StaplerResponse rsp) {
        def s = req.getSession(true)
        rsp.setStatus(200)
        rsp.setContentType("text/plain;charset=UTF-8")
        rsp.getWriter().write("session=" + s.getId())
    }
}

def action = new PcbRevealAction()
// Register so Jenkins routes /pcbReveal/* to it (no plugin, no restart). Jenkins.getDynamic(token)
// resolves a top-level URL by scanning Jenkins.get().getActions(); adding the instance there makes
// the endpoint reachable at boot. (Merely adding to the RootAction ExtensionList at runtime is not
// picked up by the already-initialised URL router.)
def acts = Jenkins.get().getActions()
if (!acts.contains(action)) acts.add(action)

println "[init] 20-endpoint: /pcbReveal registered (POST /pcbReveal/reveal crumb-guarded; GET /pcbReveal/session)"
