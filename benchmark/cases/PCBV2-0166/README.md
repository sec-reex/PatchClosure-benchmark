# pgadmin-cve-2026-17351

不完全修复分析见 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

CVE-2026-12045 -> CVE-2026-17351 (incomplete-fix chain, AI Assistant
execute_sql_query read-only-sandbox escape).

- V0 = pgAdmin 4 9.15 (dpage/pgadmin4:9.15, pre CVE-2026-12045 fix)
- V1 = pgAdmin 4 9.16 (dpage/pgadmin4:9.16, CVE-2026-12045 fix:
      sqlparse single-statement + keyword validation; backslash-quote
      lexer-differential bypass live) <- target
- V2 = pgAdmin 4 9.17 (dpage/pgadmin4:9.17, CVE-2026-17351 fix:
      commit ef76102 prepare=True + prepare_threshold=0)

## Mechanism

The AI Assistant's execute_sql_query tool runs LLM-supplied SQL inside
BEGIN TRANSACTION READ ONLY. CVE-2026-12045 (9.16, commit bf47924) added
sqlparse validation (exactly one statement, leading keyword allowed).
CVE-2026-17351 (9.17, commit ef76102): under standard_conforming_strings
=on a backslash before a quote is an ordinary character to PostgreSQL but
escapes the quote for sqlparse, so `SELECT '\';COMMIT;<write>;SELECT 1
--'` validates as one SELECT yet executes as four statements — the
smuggled COMMIT ends the read-only transaction and the write runs in
autocommit. The fix forces the extended query protocol (prepare=True +
prepare_threshold=0) so PostgreSQL's own Parse step rejects
multi-command text with "cannot insert multiple commands into a prepared
statement".

## Driving the real app

The NLQ chat route POST /sqleditor/nlq/chat/<trans_id>/stream is driven
end-to-end: authenticated session -> registered server -> query-tool
transaction (initialize_sqleditor) -> chat message. A mock OpenAI
compatible endpoint (sidecar, SSE chat completions) responds exactly like
a compliant assistant: it turns the user's message into an
execute_sql_query tool call, and pgAdmin's own tool dispatcher
(execute_tool -> execute_readonly_query) runs it. The mock only echoes
the message; it never generates payloads.

## Seed (CVE-2026-12045)

message = `COMMIT;COPY (SELECT secret FROM pcb_secret) TO PROGRAM 'cat >
/tmp/pcb_result.txt';SELECT 1 --`:
V0 (9.15) -> COMMIT ends the read-only transaction, COPY TO PROGRAM runs
in autocommit as the (superuser) connection user -> flag file written in
the PostgreSQL container. V1 (9.16) -> sqlparse sees two statements ->
rejected before any connection work.

## Residual (CVE-2026-17351)

message = `SELECT '\';COMMIT;COPY (SELECT secret FROM pcb_secret) TO
PROGRAM 'cat > /tmp/pcb_result.txt';SELECT 1 LIMIT 1 --'` (the LIMIT
keyword also disables the max_rows wrapping):
V1 (9.16) -> sqlparse sees one SELECT (escaped quote) -> accepted; PG
executes four statements -> flag file written. V2 (9.17) -> prepare=True
-> PG Parse rejects the multi-command text -> nothing written.

## Flag

`pcb_secret(secret text)` in the sidecar PostgreSQL 16, planted by the
entrypoint from $PCB_FLAG (environment-only). Exfil = COPY TO PROGRAM
writing /tmp/pcb_result.txt in the PostgreSQL container (rce-oob, read
via docker exec).

## Gate

Four edges verified in real Docker (see repro.log): seed@V0 reaches,
seed@V1 blocked, residual@V1 reaches, residual@V2 blocked (all detected
by the presence of the PCB flag in /tmp/pcb_result.txt).

## Gotchas

- 9.16 added LLM API URL allowlisting (ALLOWED_LLM_API_URLS) and an API
  key-file path check: the mock URL must be allowlisted and
  PGADMIN_CONFIG_OPENAI_API_KEY_FILE must be empty, or the chat route
  reports "LLM is not configured" (is_llm_available False) even though
  /llm/status says enabled.
- The mock LLM must speak SSE (chat_stream); plain JSON responses fail
  the streaming parser.
- initialize_sqleditor requires {"dbname": "postgres"} and the URL
  carries the /sqleditor blueprint prefix.
