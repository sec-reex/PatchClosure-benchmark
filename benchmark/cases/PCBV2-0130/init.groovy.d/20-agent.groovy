// [init hook] jenkins-cve-2025-31721 -- plant the defended asset.
//
// Creates a permanent agent "agentA" whose config.xml carries a GENUINE hudson.util.Secret:
// the version-exact controller encrypts the per-run ${PCB_FLAG} at boot with its own key, so
//   * the REAL jenkins.security.ExtendedReadSecretRedaction redacts it on the read path
//     iff the caller lacks Agent/Configure (only redacts values that Secret.decrypt() accepts),
//   * the REAL ComputerSet.doCreateItem copy guard (V2) refuses to copy it without Agent/Configure.
// The plaintext flag is NEVER written to disk or baked into the image; only its ciphertext,
// produced at runtime, lands in nodes/agentA/config.xml.
//
// The secret rides in a core hudson.slaves.EnvironmentVariablesNodeProperty value. That value
// is a real Secret.getEncryptedValue() ciphertext under THIS controller's key, so the redaction
// routine (which validates decryptability) treats it exactly as any agent secret -- no plugin,
// no custom class, round-trips through XStream copy cleanly.
import jenkins.model.Jenkins
import hudson.slaves.DumbSlave
import hudson.slaves.JNLPLauncher
import hudson.slaves.RetentionStrategy
import hudson.slaves.EnvironmentVariablesNodeProperty
import hudson.util.Secret

def j = Jenkins.get()

def flag = System.getenv('PCB_FLAG')
if (flag == null || flag.isEmpty()) {
    throw new IllegalStateException('[init] PCB_FLAG not set -- refusing to seed a blank secret')
}

// Encrypt the flag with THIS controller's key -> a genuine, decryptable hudson.util.Secret.
def enc = Secret.fromString(flag).getEncryptedValue()

// Ride the ciphertext in a core node-property env value (redaction is content-generic + validates decrypt()).
def entry = new EnvironmentVariablesNodeProperty.Entry('PCB_AGENT_SECRET', enc)
def envProp = new EnvironmentVariablesNodeProperty(entry)

if (j.getNode('agentA') == null) {
    def agent = new DumbSlave('agentA', '/home/jenkins/agentA', new JNLPLauncher())
    agent.setNodeDescription('build agent carrying a secret NodeProperty (CVE-2025-27622 asset)')
    agent.setRetentionStrategy(RetentionStrategy.NOOP)
    agent.setNumExecutors(1)
    agent.getNodeProperties().add(envProp)
    j.addNode(agent)
    println '[init] 20-agent: agentA seeded with an encrypted PCB_AGENT_SECRET NodeProperty'
} else {
    println '[init] 20-agent: agentA already exists'
}
j.save()
