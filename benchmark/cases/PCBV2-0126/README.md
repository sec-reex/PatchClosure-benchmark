# handlebars-lookup-helper-proto-access-cve-2021-23369

handlebars.js — CVE-2019-20920 -> CVE-2021-23369 (the 4.7.6 fix routes the
`lookup` helper through the `container.lookupProperty` proto-access filter, but
leaves the STRICT-mode terminal lookup `container.strict: return obj[name];`
unguarded — `strictLookup` compiles intermediates through the guarded
`lookupProperty` and only the TERMINAL through `strict`; prototype access /
code injection; case.json root_cause `Prototype_Access_Code_Injection`, no CWE
ID). **Genuine incomplete fix; gate passed on real Docker over EXTERNAL HTTP.**

长文分析见 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

Real npm `handlebars` pinned per profile (4.5.2 / 4.7.6 / 4.7.7, node:18-slim)
rendering UNTRUSTED templates POSTed to a tiny HTTP harness (`harness.js`, JSON
`{template, strict}`). RCE-oob class canary: `${PCB_FLAG}` is injected via the
container environment and planted by the harness on the render context's
PROTOTYPE (`Ctx.prototype.pcbCanary`) — a NON-OWN secret no normal own-property
template can read; the flag appears in rendered output ⇔ the proto-access guard
was bypassed. No handlebars source modified; only the template varies.

CVE-2021-23369's fix commit `b6d3de7` is titled "check prototype property access
in strict-mode" and adds `describe('in strict-mode', ...)` to the
proto-property-access regression suite (case.json `evidence` notes). case.json
`evidence.incomplete_fix_quote`: CVE-2019-20920's lookup helper failed to
properly validate templates "due to an incomplete fix for a previous issue";
`patch_real.diff` is the CVE-2019-20920 fix (commits `1988878…`/`f7f05d7…`,
including the `no-prototype-builtins` lint): the lookup helper now returns
`options.lookupProperty(obj, field)`.

- **V0 = 4.5.2** (`:39696`) — lookup helper returns `obj[field]` unfiltered:
  `{{lookup this "pcbCanary"}}` reads the prototype canary (repro.log: FLAG);
  strict mode also leaks.
- **V1 = 4.7.6** (`:39697`, target) — the 20920 fix BLOCKS the lookup-helper seed
  (output empty), but `{{pcbCanary}}` compiled `{strict:true}` terminates in
  `container.strict` -> `obj[name]` unguarded -> flag. Incomplete fix.
- **V2 = 4.7.7** (`:39698`, 23369 fix) — `strict` returns
  `container.lookupProperty(obj, name)` -> both payloads blocked (repro.log).

- **Original trigger**: template `{{lookup this "pcbCanary"}}` with
  `{strict: false}` (`poc/original_poc.py` candidate).
- **Residual trigger**: template `{{pcbCanary}}` with `{strict: true}`
  (strict-mode terminal lookup; `_heldout/bypass_poc.py` candidate).

Run: `python3 oracle.py --run-gate --with-v2` (gate 2026-07-13, flag
`PCBFLAG_11711e77a13b80fc23a29cc0f6291a89`: seed FLAG@v0 / seed blocked@v1 /
residual FLAG@v1 / both blocked@v2; passed=true, `_env_ready` all true). See
`repro.log` and `case.json`.
