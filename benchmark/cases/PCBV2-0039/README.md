# froxlor-cve-2026-41234

CVE-2026-30932 -> CVE-2026-41234 (incomplete-fix chain, BIND zone newline injection).

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

- V0 = Froxlor 2.3.4 (no content validation for LOC/RP/SSHFP/TLSA in `DomainZones.add`)
- V1 = Froxlor 2.3.5 (CVE-2026-30932 fix: `Validate::validateDnsLoc/Rp/Sshfp/Tlsa`;
      TXT records were missed) <- target
- V2 = Froxlor 2.3.7 (CVE-2026-41234 fix: `preg_replace('/[^\x09\x20-\x7E]/','',$content)`
      strips control chars from ALL content, then whitespace is collapsed)

## Mechanism

`DomainZones.add` (API, customer with DNS enabled) stores the `content` of a DNS record
verbatim into `panel_domains_dns`. The DNS rebuild cron (`froxlor:cron -r 4`) writes the
zone via `Dns::createDomainZone` -> `DnsEntry::__toString` (`record TTL IN TYPE content\n`)
into `/etc/bind/domains/<domain>.zone`. A `\n` inside content therefore breaks out of the
record line and injects arbitrary BIND directives (`$INCLUDE`, `$GENERATE`, records,
comments) into the zone file. CVE-2026-30932's fix (2.3.5) added strict validators for
LOC/RP/SSHFP/TLSA only; TXT content is merely wrapped in quotes
(`Dns::encloseTXTContent`), so a newline inside the quotes still breaks the zone line.

## Seed (CVE-2026-30932)

RP record content `mbox.example.com. txt.example.com.\n; pcb_<FLAG>`:
- v0 (2.3.4): stored raw -> zone contains the standalone comment line `; pcb_<FLAG>`
- v1 (2.3.5): `validateDnsRp` splits on `\s+` -> >2 fields -> 406 error, nothing stored

## Residual (CVE-2026-41234)

TXT record content `hello\n; pcb_<FLAG>`:
- v1 (2.3.5): `encloseTXTContent` -> `"hello\n; pcb_<FLAG>"` -> the newline still breaks
  the zone line -> comment line `; pcb_<FLAG>"` observable
- v2 (2.3.7): control chars are stripped before the type branch -> `"hello; pcb_<FLAG>"`
  -> single zone line, no injection

## Flag

The PoC embeds the eval-injected `PCB_FLAG` in the injected BIND comment directive. The
oracle reads the generated zone file via `docker exec` (after running the REAL
`froxlor:cron -r 4`) and returns only the zone file's comment lines; the flag is
observable exactly when the newline injection worked.

## Gate

Four edges verified in real Docker: seed@V0 reaches, seed@V1 blocked (406),
residual@V1 reaches, residual@V2 blocked (sanitized). See repro.log.
