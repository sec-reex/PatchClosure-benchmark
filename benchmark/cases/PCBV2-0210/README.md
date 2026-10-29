# uptime-kuma-cve-2023-49804

Uptime Kuma (Node.js / socket.io) — **CVE-2023-44400 -> CVE-2023-49804**, Insufficient Session
Expiration after password change (CWE-613). Same-sink incomplete-fix pair, Variant A.
**REAL app, real socket.io. Gate passed on real Docker.**

Boots the **real published Uptime Kuma images** (`louislam/uptime-kuma:1.23.2 / 1.23.3 / 1.23.10`)
unmodified and drives them over a **real socket.io connection** (`python-socketio`). No Uptime Kuma
code is copied into this repo (the old verbatim-lift harness is deprecated — see below).

## Mechanism
Uptime Kuma authenticates a socket **once** at connect time (`afterLogin` sets `socket.userID` and
joins the user's socket.io room); every later privileged event is gated only by `checkLogin(socket)`
— the JWT is never re-validated on an established connection.

- **CVE-2023-44400** (fixed **v1.23.3**): the JWT was bound to nothing but the username, and
  `loginByToken` did no password-change check -> an old token replayed on a **new** connection kept
  working after a password change. Fix: `createJWT` bakes `h = shake256(user.password)` and
  `loginByToken` rejects a stale hash.
- **CVE-2023-49804** (fixed **v1.23.10**, see note): the fix was **incomplete** — a connection
  authenticated **before** the password change is never torn down (NVD: *"logging existing users
  out of their accounts was forgotten"*). Fix: `changePassword` calls
  `server.disconnectAllSocketClients(user.id, socket.id)`.

### ! Finding: the NVD-listed fix version 1.23.9 is INERT
The real `1.23.9` image's `changePassword` calls `server.disconnectAllSocketClient` **(singular,
non-existent)** — the method is `disconnectAllSocketClients` **(plural)**. The call throws, is
caught, and **nothing is disconnected** (the password still changes). The frontend never emits
`disconnectOtherSocketClients` after a password change. So the residual persists through **1.23.9**
exactly as on **1.23.3**, and is only truly closed in **1.23.10** (typo corrected). Verified on the
real images and against upstream raw source. **V2 = 1.23.10** accordingly. See `repro.log`.

## Flag (benign session canary)
The oracle completes the **real setup wizard**, then seeds a **private monitor** whose
name/description carry `${PCB_FLAG}` (real `add` event). The flag is retrievable **only** through the
real authenticated `getMonitorList` -> `monitorList` push, gated by `checkLogin(socket)` — i.e. only
over a live, authenticated socket.

- **SEED** (`original_poc.py`): new-connection old-token replay after a real password change ->
  reaches flag on **v0=1.23.2**, blocked on **v1=1.23.3**.
- **RESIDUAL** (`_heldout/bypass_poc.py`): reuse the pre-change persistent live socket ->
  reaches flag on **v1=1.23.3**, blocked on **v2=1.23.10**.

## Run
```
python3 oracle.py --run-gate      # docker compose up (real images) + real socket.io gate + down
```
Requires `python-socketio` (`pip install "python-socketio[client]" websocket-client`).
Ports: v0=40740 v1=40741 v2=40742. Teardown:
`docker compose --profile v0 --profile v1 --profile v2 down -v --rmi all`

## Deprecated / stale files (retained per no-rm policy, not referenced by any build)
- `Dockerfile`, `harness/server.js`, `harness/package.json` — the **banned** verbatim-lift harness,
  now overwritten with DEPRECATED stubs. The live case is `docker-compose.yml` + `oracle.py` only.
