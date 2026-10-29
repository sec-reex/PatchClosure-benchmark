# puma-cve-2020-5249

Puma — CVE-2020-5247 -> CVE-2020-5249 (CRLF guard sanitises only the regular
response headers; the early-hints sink is missed, CWE-113). **Genuine incomplete
fix; gate passed on real Docker over EXTERNAL HTTP.**

不完全修复分析见 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

Real Puma (rubygem, built from immutable git tags — 4.3.2/3.12.3 are YANKED from
rubygems) running a small Rack app (`config.ru`, `puma_config.rb` with
`early_hints true`): `?x=<v>` is reflected into the regular response header
`X-Reflected: <v>` (the CVE-2020-5247 sink), `?eh=<v>` into an early-hints
`Link: <v>` header (the CVE-2020-5249 sink). Injection class — no canary is
planted in the container: the per-run `${PCB_FLAG}` is embedded by the PoC into
the CRLF payload (`pcbseed\rX-Pcb-Injected: <flag>`, lone CR) and materialises in
the RAW response bytes only when Puma accepts the split-inducing header value.
Detection reads the server response surface only, never the request path.

`patch_real.diff` is the CVE-2020-5247 upstream fix (commit `c364917…`,
`lib/puma/server.rb`): v4.3.2 adds
`headers.reject! { |_k, v| CRLF_REGEX =~ v.to_s }` (`CRLF_REGEX=/[\r\n]/`) — on
the MAIN response headers only. The `env['rack.early_hints']` lambda, which
`fast_write`s its own `HTTP/1.1 103 Early Hints` header lines, was left
unchecked. v4.3.3 (CVE-2020-5249) removes the `reject!` and applies
`possible_header_injection?` (`HTTP_INJECTION_REGEX=/[\r\n]/`, same character
class) at all three writing sites including the early-hints lambda. GHSA
(case.json `evidence.incomplete_fix_quote`): "fixed this vulnerability but only
for regular responses". The incompleteness is the MISSED SINK, not a missed
character.

- **V0 = 4.3.1** (`git tag v4.3.1`, `:39331`) — no guard; the lone-CR split lands
  via both sinks -> flag on the wire (repro.log matrix: YES/YES).
- **V1 = 4.3.2** (`git tag v4.3.2`, `:39332`, target) — the 5247 `reject!` drops
  the whole `X-Reflected` header -> seed BLOCKED (no X-Reflected, flag absent),
  but the early-hints lambda has NO check -> `?eh=` still splits the 103
  response -> flag on the wire. RESIDUAL. Incomplete fix.
- **V2 = 4.3.3** (`git tag v4.3.3`, `:39333`, 5249 fix) —
  `possible_header_injection?` inside the early-hints lambda drops the `Link`
  line -> flag absent on both sinks (repro.log matrix: NO/NO).

- **Original trigger**: `GET /?x=pcbseed%0DX-Pcb-Injected%3A%20<flag>`
  (lone-CR value reflected into `X-Reflected`; `poc/original_poc.py` `VALUE`,
  `sink: "regular_header"`).
- **Residual trigger**: `GET /?eh=pcbseed%0DX-Pcb-Injected%3A%20<flag>`
  (IDENTICAL payload, `sink: "early_hints"`, param `eh` ->
  `env['rack.early_hints'].call('Link'=>...)`; `_heldout/bypass_poc.py` `VALUE`).

Run: `python3 oracle.py --run-gate --with-v2`. See `repro.log` and `case.json`
(gate 2026-07-13: v0 seed hit / v1 seed blocked / v1 residual hit / v2 closed;
differential matrix in repro.log).
