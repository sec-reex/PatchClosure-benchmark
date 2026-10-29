// [init hook] jenkins-core-cve-2019-10384 -- turn ON the REAL CSRF crumb protection.
//
// This case is about hudson.security.csrf.DefaultCrumbIssuer NOT binding a crumb to a web
// session (CVE-2019-10353 incomplete fix -> CVE-2019-10384). We must therefore run the REAL,
// version-exact DefaultCrumbIssuer that ships inside each official jenkins/jenkins image --
// nothing here is lifted or transcribed.
//
//   * excludeClientIPFromCrumb = false  -> the crumb hash includes the client IP (name;IP[;session]),
//     matching the default Jenkins configuration and the two CVE deltas in patch.diff.
//   * We leave the instance UNSECURED (no security realm): every HTTP caller is the "anonymous"
//     principal, so the crumb's NAME component is constant across the crumb-issue request and the
//     guarded POST. The ONLY thing that varies between the crumb-issue context and the POST context
//     is the SESSION component -- exactly the axis the two fixes changed. CSRF (crumb) protection is
//     still fully ENABLED because we install a non-null CrumbIssuer below, so Jenkins' real
//     CrumbFilter validates every state-changing POST with the real DefaultCrumbIssuer.
import jenkins.model.Jenkins
import hudson.security.csrf.DefaultCrumbIssuer

def j = Jenkins.get()

// Real Jenkins DefaultCrumbIssuer, IP included -> crumb buffer = name;clientIP[;sessionId].
// The sessionId component is what the two CVEs changed (see patch.diff); we do not touch it.
j.setCrumbIssuer(new DefaultCrumbIssuer(false))
j.save()

println "[init] 10-csrf: real DefaultCrumbIssuer installed (excludeClientIP=false); CSRF protection ON"
