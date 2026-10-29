# jenkins-core-cve-2019-10384

长文分析见 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

Jenkins (core) — **CVE-2019-10353 -> CVE-2019-10384** — CSRF crumb, CWE-352.
Incomplete-fix lineage, Variant A (same sink). **REAL booted Jenkins**, external-HTTP gate passed.

## Lineage (confirmed from Jenkins security advisories + source diff)
- **CVE-2019-10353 (SECURITY-626, adv 2019-07-17):** the `DefaultCrumbIssuer` CSRF
  crumb was bound only to `(user, clientIP)` — it carried no web-session id, so crumbs
  never expired and a crumb from one session could be replayed in another. Fixed in
  LTS **2.176.2** by appending the web **session id** to the crumb hash.
- **CVE-2019-10384 (SECURITY-1491, adv 2019-08-28):** *"result of an incomplete fix
  for SECURITY-626."* The session component was computed with `getSession(false)`, so a
  request **without** a session hashed the constant `"NO_SESSION"`. Anonymous/sessionless
  crumbs therefore still never bind to a session and stay replayable. Fixed in LTS
  **2.176.3** by using `req.getSession()` (which **creates** a session).

## Source delta (hudson.security.csrf.DefaultCrumbIssuer.issueCrumb) — see patch.diff
```
buffer = name ; clientIP [ ; sessionComponent ]           # MD5(buffer) digested with salt
  v0  jenkins-2.176.1:  (no session component)
  v1  jenkins-2.176.2:  ; getSessionId(req)      getSession(FALSE) -> id or "NO_SESSION"
  v2  jenkins-2.176.3:  ; req.getSession().getId()          getSession() CREATES a session
```

## Environment (REAL Jenkins — nothing lifted)
Each profile boots the **official, version-exact** `jenkins/jenkins:{2.176.1,2.176.2,2.176.3}`
image (ports 39420/39421/39422). CSRF protection is turned ON via `init.groovy.d/10-csrf.groovy`
(installs the stock `DefaultCrumbIssuer`, IP included). `init.groovy.d/20-endpoint.groovy` registers
a tiny `UnprotectedRootAction`:
- `POST /pcbReveal/reveal` — crumb-guarded state-write. The **real** Jenkins `CrumbFilter` validates
  the crumb with the version-exact `DefaultCrumbIssuer` **before** the action runs, so reaching the
  state-write (which echoes `${PCB_FLAG}`) proves the replayed crumb was accepted by real Jenkins.
- `GET /pcbReveal/session` — benign helper that creates a web session (so the seed can replay a crumb
  across two distinct sessions). GET, so no crumb needed.

The instance is left unsecured, so every caller is the constant `anonymous` principal; the ONLY thing
that varies between the crumb-mint context and the POST context is the **session component** — the exact
axis the two CVE fixes changed. `${PCB_FLAG}` is injected at run time and read from the process env at
request time (never baked into the image or written to disk).

## Differential (same sink: mint crumb -> replay on `POST /pcbReveal/reveal` -> read `secret=FLAG`)
- **Seed (CVE-2019-10353):** crumb minted in web session A (client A hits `/pcbReveal/session` first),
  replayed from a different web session B. V0 (no session in hash) -> reaches flag; V1 (A != B) -> 403.
- **Residual (CVE-2019-10384):** crumb minted by a **sessionless** client, replayed from a separate
  sessionless client. V1 (both `...;NO_SESSION`) -> reaches flag; V2 (each side gets a distinct
  *created* session) -> 403 "No valid crumb".

## Run
```
python3 oracle.py --run-gate            # builds, ups v0/v1, runs Variant A gate, tears down
python3 oracle.py --run-gate --with-v2  # also verifies the residual is blocked on v2
```
Gate: `original@V0 reaches`, `original@V1 blocked`, `bypass@V1 reaches` (+ residual blocked on V2).
`_heldout/` must never be exposed to the system-under-test.

## Stale files (superseded by the real-Jenkins rebuild; left in place, NOT used by the build)
`Dockerfile`/`docker-compose.yml`/`oracle.py`/`original_poc.py`/`_heldout/bypass_poc.py` are the
current real-Jenkins build. `src/main/java/pcb/CrumbApp.java` and `pom.xml` are the OLD banned
lifted-harness (Jetty servlet transcribing `DefaultCrumbIssuer`); they are no longer referenced by
the Dockerfile and can be ignored.
```
```
