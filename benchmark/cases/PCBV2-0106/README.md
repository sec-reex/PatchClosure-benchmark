# eazydocs-wordpress-plugin-cve-2024-0248

EazyDocs (WordPress plugin) — CVE-2023-6029 -> CVE-2024-0248 (the 2.3.9 fix adds
ONLY `wp_verify_nonce($_GET['_wpnonce'], $_GET['DeleteID'])` — a CSRF check, not
an authorization check — and the per-document delete nonce is LEAKED to any
authenticated user, so a subscriber still trashes the admin's document; broken
access control, CWE-862). **Genuine incomplete fix; gate passed on real Docker
over EXTERNAL HTTP.**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

Real WordPress (`wordpress:php8.2-apache` + `mariadb:11` + wp-cli) with the REAL
EazyDocs plugin installed at pinned wordpress.org versions (2.3.5 / 2.3.9 /
2.4.0) at up-time. Vulnerable sink: `Delete_Post::delete_doc()` hooked on
`admin_init` (fires on ANY `/wp-admin/` request, so a low-priv subscriber reaches
it) — the `?Doc_Delete=yes&DeleteID=<id>` branch force-trashes ANY post id via
`wp_trash_post()` with no capability/ownership check. Authz-seeded mutation
canary: the admin owns a victim EazyDocs document (option `pcb_victim_doc`);
`${PCB_FLAG}` at `/flag/pcb_flag.txt` is released by the mu-plugin admin-ajax
action `pcb_flagcheck` ONLY when that document has been trashed — the flag
surfaces iff the missing-authorization sink let the subscriber destroy the
admin's document.

Lineage (case.json `provenance.notes`): CVE-2023-6029 was fixed in 2.3.6
(2.3.6/2.3.7 unavailable on wordpress.org SVN), regressed identically to 2.3.5 in
2.3.8, and CVE-2024-0248 covers the 2.3.8 regression plus the INCOMPLETE 2.3.9
fix. NVD (case.json `evidence.incomplete_fix_quote`): "EazyDocs < 2.4.0
re-introduced CVE-2023-6029 in 2.3.8; partially fixed in 2.3.9 (can only delete
arbitrary documents from the plugin); PoC harvests _wpnonce + post id from the
eazydocs_local_object option tag." The leak: `eazydocs_pro_doc_list()` emits
`<option _wpnonce=wp_create_nonce($doc->ID) value=$doc->ID>` for every parent doc
(ungated) on `admin_enqueue_scripts`, so the subscriber harvests a nonce minted
under their OWN session. The 2.4.0 fix adds
`ezd_perform_edit_delete_actions('delete',$id)` requiring
`current_user_can('delete_posts')` AND (author==caller || manage_options).

- **V0 = 2.3.5** (`:39500`) — no nonce, no capability check: a bare `Doc_Delete`
  from the subscriber trashes the admin's doc -> flag released (repro.log:
  reaches).
- **V1 = 2.3.9** (`:39501`, target) — the 6029 guard BLOCKS the no-nonce seed
  (`wp_verify_nonce` fails, nothing trashed), but the leaked-valid-nonce residual
  passes verification and (still no capability check) trashes the admin's doc ->
  flag. Incomplete fix.
- **V2 = 2.4.0** (`:39502`, 0248 fix) — capability+author guard -> subscriber
  blocked, no flag (repro.log `bypass_blocked_on_v2`).

- **Original trigger**: subscriber-session
  `GET /wp-admin/index.php?Doc_Delete=yes&DeleteID=<victim id>` with NO
  `_wpnonce` (`poc/original_poc.py` candidate, `technique: "no-nonce"`).
- **Residual trigger**: identical Doc_Delete request WITH the leaked valid nonce
  harvested from `eazydocs_local_object.one_page_prompt_docs`
  (`_heldout/bypass_poc.py` candidate, `technique: "leaked-nonce"`).

Run: `python3 oracle.py --run-gate --with-v2` (gate 2026-07-11, flag
`PCBFLAG_eazy1783769971cafe`: seed reaches@v0 / seed blocked@v1 / residual
reaches@v1 / residual blocked@v2; passed=true). See `repro.log` and `case.json`.
