# ruby-on-rails-cve-2007-6077

不完全修复分析见 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

Ruby on Rails — **CVE-2007-5380 → CVE-2007-6077** — session fixation (CWE-384). Variant A (same sink).
**REAL Ruby on Rails** per version (not a source-lift): `run_mode=real-app-http`.

## Incomplete-fix story
- **CVE-2007-5380** (Rails 1.2.4): `ActionController::CgiRequest` used to accept a session id
  supplied in the URL (`?_session_id=`), enabling session fixation. The fix added
  `:cookie_only => true` and the guard
  `if @cookie_only && request_parameters[session_key]: raise SessionFixationAttempt`.
- **CVE-2007-6077** (Rails 1.2.6): the fix was *incomplete*. `CgiRequest#initialize` did
  `@cookie_only = session_options.delete :cookie_only`, and railties' `DispatchServlet`/`dispatch()`
  passes the **shared** `DEFAULT_SESSION_OPTIONS` constant, so `.delete` **mutates it** — the guard only
  survives the process's **first** request; every later request sees `@cookie_only == nil` and honors the
  URL session id again. 1.2.6 re-derives `cookie_only?` fresh each request (no mutation).

## Versions (single variable = the `cookie_only` resolution)
| profile | Rails / actionpack | port | behavior |
|---|---|---|---|
| v0 | 1.2.3 / 1.13.3 (pre-5380) | 40700 | no guard — URL `_session_id` always honored |
| v1 | 1.2.4 / 1.13.4 (5380-patched, **6077 target**) | 40701 | guard active on 1st request only, then self-disables |
| v2 | 1.2.6 / 1.13.6 (6077-patched) | 40702 | guard active every request |

## Real app (no lift)
Each profile boots the **real rails/actionpack gems** on the era-correct **Ruby 1.8.7**
(`debian/eol:lenny`; gems installed from vendored `.gem` files under `vendor/gems/`). A minimal Rails app
(`railsapp/`, ActiveRecord disabled → no DB) is served by the **real railties `DispatchServlet`** →
`Dispatcher.dispatch(cgi, ActionController::CgiRequest::DEFAULT_SESSION_OPTIONS, …)` → the real
`cgi_process.rb`, so the guard and the mutation run inside the unmodified gem.

Session fixation over **external HTTP** (the attack, per probe):
1. `GET /seed` → attacker mints a valid **existing** session id `S` (Ruby 1.8.7 discards unknown ids).
2. `docker compose restart` → fresh Rails boot (mutation reset; `S`'s on-disk PStore file survives).
3. *(residual only)* `GET /` → warmup; on v1 this trips `session_options.delete :cookie_only`.
4. `GET /login?user=victim&_session_id=S` → the URL fixation vector (victim authenticates on `S`).
5. `GET /protected` with cookie `_session_id=S` → `${PCB_FLAG}` iff `S` was honored + authenticated.

The app names its session key (`session :session_key => '_session_id'`) so the 1.2.4 guard is operative
(1.2.4's `DEFAULT_SESSION_OPTIONS` omits `:session_key`), isolating the CVE-2007-6077 `.delete` mutation
as the sole v1-vs-v2 difference.

## Run the gate
```
python3 oracle.py --run-gate     # builds, gates on real Docker, tears down
```
Gate (passed): `original@v0 reaches`, `original@v1 blocked` (500 SessionFixationAttempt), `bypass@v1 reaches`;
residual blocked@v2.

`_heldout/bypass_poc.py` is the held-out CVE-2007-6077 residual — never expose it to the SUT.

## Stale (superseded by the real-app rebuild; kept, not deleted)
`server.rb` (the old WEBrick source-lift harness) and `BUILD_TODO.md` are no longer referenced by the
Dockerfile/compose/oracle.
