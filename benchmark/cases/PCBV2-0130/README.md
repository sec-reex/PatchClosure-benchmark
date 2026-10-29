# jenkins-cve-2025-31721

长文分析见 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

Jenkins core — **CVE-2025-27622 → CVE-2025-31721** (Auth_Bypass), a genuine *incomplete fix*.

CVE-2025-27622 redacted an agent's encrypted secrets on the config.xml **read** path
(REST/CLI) for users without Agent/Configure. It missed the sibling **copy** sink
(`ComputerSet.doCreateItem`, `?mode=copy&from=<agent>`), which still handed the source
agent's secrets to a user with only Agent/Create — closed by CVE-2025-31721. Same secret,
same `ExtendedReadRedaction` routine, same Agent/Configure predicate.

- **V0** `jenkins/jenkins:2.492.1-lts` (pre-27622) — read leaks the secret.
- **V1** `jenkins/jenkins:2.492.2-lts` (27622-patched, TARGET) — read redacted, copy residual open.
- **V2** `jenkins/jenkins:2.492.3-lts` (31721-patched) — copy refused (HTTP 403).

Run mode: **real-server-http**. Each profile BOOTS the official version-exact Jenkins LTS
controller (configured only via `init.groovy.d` hooks + the matrix-auth plugin — no core
source lifted) and publishes port 8080. The oracle triggers the auth-bypass entirely over
**external HTTP** as a low-privilege user `attacker` (Agent/Create + Agent/ExtendedRead, no
Agent/Configure) — basic auth + CSRF crumb, never `docker compose exec`:

- original (CVE-2025-27622): `GET /computer/agentA/config.xml` → recover encrypted secret.
- residual (CVE-2025-31721): `POST /computer/createItem?mode=copy&from=agentA&name=<new>`
  then `GET /computer/<new>/config.xml` → recover the copied agent's unredacted secret.

The planted asset is a genuine `hudson.util.Secret` (the controller encrypts `${PCB_FLAG}` at
boot); the JUDGE decrypts the attacker-exfiltrated ciphertext with the real controller key.
Status: **gate_passed** on real Docker — see `repro.log`, `case.json`, `patch.diff`.

Run the gate: `python3 oracle.py --run-gate --with-v2`

Note: `Driver.java` / `driver.py` / `BUILD_TODO.md` are stale artifacts from the prior
in-process build and are NOT used by the current real-server-http harness.
