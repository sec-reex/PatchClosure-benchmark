# twiki-cve-2009-4898

TWiki — CVE-2009-1339 -> CVE-2009-4898 (the 4.3.1 fix only forces `/bin/save` to
POST via `post_method_only` — but a cross-site auto-submitting FORM with
`method="post"` (the advisory's FORM-ACTION + BODY-onload-submit demo) rides the
victim admin's TWIKISID cookie just as well and carries NO one-time crypt token,
so the privileged save still executes; CSRF, CWE-352). **Genuine incomplete fix;
gate passed on real Docker over EXTERNAL HTTP.**

不完整修复分析见 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

REAL published TWiki per version (full SourceForge tarballs TWiki-4.3.0 / 4.3.1 /
4.3.2 fetched at build) on Debian + Apache2 mod_cgi + Perl 5.36, running TWiki's
OWN `bin/` + `lib/` tree (RcsLite store, TemplateLogin sessions, HtPasswd auth).
The guard under test is TWiki's OWN `lib/TWiki/UI/Save.pm` (`post_method_only`)
and `lib/TWiki/UI.pm verifyCryptToken` — NOT lifted; only a security-neutral Perl
5.36 portability rewrite is applied at build (wrap `foreach $x qw(...)`, drop
`defined @array`; the CSRF predicates are byte-for-byte unchanged). The attack is
an EXTERNAL HTTP forged `/bin/save` riding the victim admin's authenticated
TWIKISID cookie. Authz-seeded canary: the entrypoint writes `${PCB_FLAG}` into the
admin-only topic `Main.PcbSecret` (`ALLOWTOPICVIEW = TWikiAdminGroup`); a
guard-passing forged save writes `%INCLUDE{"Main.PcbSecret"}%` into a page, and
the victim admin's own view surfaces the flag.

NVD (case.json `evidence.incomplete_fix_quote`): "this issue exists because of an
insufficient fix for CVE-2009-1339." `patch_real.diff` is the TWiki-4.3.1 hotfix
(the EditTablePlugin POST check; the core `Save.pm` adds `if ($reqmethod !~
/^POST$/i) { throw ... def => 'post_method_only' }`). The 4.3.2 fix adds, after
the POST check, `TWiki::UI::verifyCryptToken($session, $query->param('crypttoken'))`
with one-time tokens (`createCryptToken` = MD5(rand), consumed via `cleanCryptToken`).

- **V0 = 4.3.0** (`:39600`) — no guard: forged **GET** save performs the save ->
  flag surfaced (repro.log: reveals flag@v0).
- **V1 = 4.3.1** (`:39601`, target) — the 1339 fix BLOCKS the GET seed
  (`post_method_only`), but the tokenless forged **POST** is accepted (no token
  check) -> privileged save runs -> flag. Incomplete fix.
- **V2 = 4.3.2** (`:39602`, 4898 fix) — `verifyCryptToken` rejects the missing
  token (`invalidtoken`) -> tokenless POST and GET both blocked
  (repro.log: `_residual_blocked_on_v2`, `_seed_blocked_on_v2`).

- **Original trigger**: forged `GET /bin/save/Sandbox/<topic>?text=...` with the
  victim's TWIKISID cookie (`poc/original_poc.py` candidate, `mode: "seed"`).
- **Residual trigger**: forged tokenless `POST /bin/save/...` (cross-site
  auto-submitting form; `_heldout/bypass_poc.py` candidate, `mode: "residual"`).

Run: `python3 oracle.py --run-gate` (live gate on real Docker: GET flag@v0 /
blocked post_method_only@v1 / tokenless POST flag@v1 / blocked invalidtoken@v2;
passed=true). See `repro.log` and `case.json`.

> NOTE: `app.pl` is the stale, BANNED prior verbatim-lift harness — left in-tree
> per the NO-rm policy, unused by this build (provenance: "Rebuilt from the
> earlier BANNED app.pl verbatim-lift harness").
