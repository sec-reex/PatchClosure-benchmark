# openstack-nova-cve-2024-40767

OpenStack Nova — CVE-2022-47951 -> CVE-2024-40767 (CVE-2022-47951 restricted VMDK
create-types and OSSA-2024-001 added `format_inspector` deep inspection, but BOTH
key their safety checks off the caller-CLAIMED `disk_format`; a malicious
`monolithicFlat` VMDK whose FLAT extent points at an arbitrary host file, uploaded
as `disk_format=raw`, takes the always-safe RawFileInspector, `qemu-img` is forced
to interpret it as raw, and the VMDK create-type check is skipped — the same image
is disclosed downstream; arbitrary host-file disclosure, CWE-22). **Genuine
incomplete fix; gate passed on real Docker over EXTERNAL HTTP.**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

The WHOLE `openstack/nova` tree is pip-installed at pinned commits
(`a90bd508…` V0 / `1191a49a…` V1 / `8b4c522f…` V2) and the REAL
`nova.virt.images.fetch_to_raw` (+ the REAL `nova/image/format_inspector.py` on
V1/V2) runs verbatim behind a thin HTTP consumer (`GET /read?claim=<disk_format>&extent=...`);
the convert/info sink is genuine `qemu-img` (only guard-irrelevant nova.*
sibling imports are stubbed — the privsep stub shells to the real binary).
Read-exfil canary: the entrypoint writes `${PCB_FLAG}` to
`/canary/secret.txt` (outside any image store); the flag appears in the response
body iff qemu-img consumes the delivered image and follows the FLAT extent.

OSSA-2024-002 (case.json `evidence.incomplete_fix_quote`): "When we moved the
qemu-img command in fetch_to_raw() to force the format to what we expect, we lost
the ability to identify and react to situations where qemu-img detected a file as
a format that is not supported by us ... This helps us avoid cases where the
uploader lies about the image format." (CVE-2024-40767 is an incomplete fix for
CVE-2022-47951 and CVE-2024-32498.) `patch_real.diff` is the a90bd508..1191a49a
V0->V1 delta (`format_inspector.py` + `do_image_deep_inspection`). The V2 fix
("Change force_format strategy to catch mismatches") re-probes with an UNFORCED
`qemu-img info` and rejects when detected != claimed. (Note from repro.log:
`format_inspector`'s VMDKInspector only recognizes KDMV-binary VMDKs, not flat
text descriptors — the V2 block comes from the unforced recheck, not from
format_inspector detection.)

- **V0 = `a90bd508` (pre-47951)** (`:40640`) — claimed-vmdk monolithicFlat is
  admitted; `qemu-img convert` reads the FLAT extent -> flag disclosed (also
  allowed under a raw claim).
- **V1 = `1191a49a` (47951 + format_inspector)** (`:40641`, target) — the
  claimed-vmdk seed is BLOCKED (content != disk_format / create-type check), but
  the SAME image claimed `disk_format=raw` passes (RawFileInspector, forced
  qemu-img 'raw', VMDK check skipped) -> flag disclosed. Incomplete fix.
- **V2 = `8b4c522f` (40767 fix)** (`:40642`) — unforced re-probe: claim=raw on a
  VMDK -> "content != disk_format" BLOCKED; claimed-vmdk also blocked
  (unsupported format) (repro.log full matrix).

- **Original trigger**: `GET /read?claim=vmdk&extent=/canary/secret.txt`
  (monolithicFlat descriptor honestly claimed as vmdk;
  `poc/original_poc.py` candidate).
- **Residual trigger**: `GET /read?claim=raw&extent=/canary/secret.txt`
  (IDENTICAL malicious VMDK, claim lies as raw; `_heldout/bypass_poc.py`
  candidate).

Run: `python3 oracle.py --gate` (gate, flag
`PCBFLAG_33497b8705b77dea71dace886a5b163b`: original reaches@v0 / blocked@v1 /
residual reaches@v1 / residual blocked@v2; passed=true). See `repro.log` and
`case.json`.
