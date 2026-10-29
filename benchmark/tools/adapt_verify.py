#!/usr/bin/env python3
"""adapt_verify.py — 为每个 case 自动生成定制 verify.sh（不再用通用模板碰运气）。

方法：分析 case 的 poc/seed_exec.py 源码形态：
  - 执行器型（main 调 run_probe(cand, version)）：提取 return dict 字段，
    按字段语义生成判定（X==RUN_FLAG / ok+status / body 含 RUN_FLAG）。
  - wrapper 型（mod.candidate/run/original_poc）：按 seed.py 函数生成直接调用。
candidate 清洗（去引号 + flag 占位替换）由 poc/_clean_candidate.py 承担（独立脚本，
避免内嵌 python 的引号/花括号地狱）。
"""
import json
import re
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CASES = ROOT / "cases"

CLEANER = """#!/usr/bin/env python3
# auto-generated candidate cleaner: strip quotes + replace PCBFLAG_* placeholder
import json, re, sys
s = sys.argv[1]
flag = sys.argv[2]

def clean(x):
    x = x.strip().strip(chr(34)).strip(chr(39))
    x = re.sub(r'PCBFLAG_[A-Za-z0-9_]+', flag, x)
    return x

try:
    d = json.loads(s)
    if isinstance(d, dict):
        d = {k: (clean(v) if isinstance(v, str) else v) for k, v in d.items()}
    print(json.dumps(d))
except Exception:
    print(json.dumps({'path': clean(s), 'to': clean(s), 'payload': clean(s), 'css': clean(s)}))
"""


def analyze(cid: str) -> dict:
    d = CASES / cid
    sp = d / "poc" / "seed_exec.py"
    if not sp.exists():
        return {"case_id": cid, "kind": "no_seed_exec"}
    src = sp.read_text(errors="ignore")
    info = {"case_id": cid, "kind": "unknown"}
    if re.search(r"importlib.*spec_from_file_location|mod\.candidate|mod\.run\b|mod\.original_poc", src):
        info["kind"] = "wrapper"
        info["has_run"] = bool(re.search(r"mod\.run\b", src))
        info["has_candidate"] = bool(re.search(r"mod\.candidate", src))
        info["has_original_poc"] = bool(re.search(r"mod\.original_poc", src))
        return info
    m = re.search(r"def run_probe\(.*?return\s*\{(.*?)\n\s*\}", src, re.S)
    if m:
        keys = re.findall(r'"([A-Za-z_][A-Za-z0-9_]*)"\s*:', m.group(1))
        info["kind"] = "executor"
        info["return_keys"] = keys
        if "X" in keys:
            info["flag_channel"] = "X"
        elif "ok" in keys:
            info["flag_channel"] = "ok"
        elif any(k in keys for k in ("body", "fetched_body", "resp", "response")):
            info["flag_channel"] = "body"
        else:
            info["flag_channel"] = "raw"
        return info
    return info


def write_cleaner(cid: str) -> None:
    p = CASES / cid / "poc" / "_clean_candidate.py"
    p.write_text(CLEANER)
    p.chmod(0o755)


def gen_executor_verify(cid: str, info: str) -> str:
    ch = info
    if ch == "X":
        py = [
            "import json,sys",
            "try:",
            "    d = json.loads(sys.argv[1])",
            "except Exception:",
            "    sys.exit(20)",
            "sys.exit(0 if d.get('X') == '$RUN_FLAG' else 10)",
        ]
    elif ch == "ok":
        py = [
            "import json,sys",
            "try:",
            "    d = json.loads(sys.argv[1])",
            "except Exception:",
            "    sys.exit(20)",
            "ok = bool(d.get('ok')) and d.get('status') in (200, 201) and '$RUN_FLAG' in str(d.get('body',''))",
            "sys.exit(0 if ok else 10)",
        ]
    else:
        py = [
            "import json,sys",
            "try:",
            "    d = json.loads(sys.argv[1])",
            "except Exception:",
            "    sys.exit(20)",
            "body = str(d.get('body') or d.get('fetched_body') or d.get('resp') or d.get('response') or d.get('location') or '')",
            "sys.exit(0 if '$RUN_FLAG' in body else 10)",
        ]
    judge = '"$PY" -c "' + "\n".join(py) + '" "$OUT"'
    x_export = 'export PCB_X="$RUN_FLAG"\n' if ch == "X" else ""
    tpl = (
        "#!/usr/bin/env bash\n"
        "# verify.sh (auto-adapted for {cid}, executor, flag_channel={ch})\n"
        "# 0=效果发生 10=未发生 20=环境失败 30=参数错误\n"
        "set -uo pipefail\n"
        ': "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"\n'
        'MODE="${1:-}"\n'
        '[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }\n'
        'CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"\n'
        'PY="${PCB_PYTHON:-python3}"\n'
        'mkdir -p "$WORK_DIR"\n'
        '"$PY" "$CASE_DIR/poc/original_poc.py" "$VERSION" > "$WORK_DIR/cand.json" 2>/dev/null \\n'
        '  || "$PY" "$CASE_DIR/poc/original_poc.py" > "$WORK_DIR/cand.json" 2>/dev/null\n'
        "# flag placeholder replace (file-based)\n"
        '"$PY" - "$RUN_FLAG" "$WORK_DIR/cand.json" <<ADAPTEOF\n'
        "import re, sys\n"
        "flag, p = sys.argv[1], sys.argv[2]\n"
        's = open(p, encoding="utf-8", errors="replace").read()\n'
        "s = re.sub(r'PCBFLAG_[A-Za-z0-9_]+', flag, s)\n"
        'open(p, "w").write(s)\n'
        "ADAPTEOF\n"
        "# wrap non-JSON candidate into multi-field dict (file-based)\n"
        '"$PY" - "$WORK_DIR/cand.json" <<ADAPTEOF2\n'
        "import json, sys\n"
        "p = sys.argv[1]\n"
        's = open(p, encoding="utf-8", errors="replace").read().strip().strip(chr(34)).strip(chr(39))\n'
        "try:\n"
        "    json.loads(s)\n"
        "except Exception:\n"
        '    open(p, "w").write(json.dumps({"path": s, "to": s, "payload": s, "css": s}))\n'
        "ADAPTEOF2\n"
        + x_export +
        'OUT="$("$PY" "$CASE_DIR/poc/seed_exec.py" "$WORK_DIR/cand.json" "$VERSION" 2>&1)" || { echo "$OUT" >&2; exit 20; }\n'
        'echo "$OUT" | head -c 500; echo\n'
        + judge + "\n"
    )
    return tpl.replace("{cid}", cid).replace("{ch}", ch)


def gen_wrapper_verify(cid: str) -> str:
    tpl = """#!/usr/bin/env bash
# verify.sh (auto-adapted for {cid}, wrapper)
# 0=效果发生 10=未发生 20=环境失败 30=参数错误
set -uo pipefail
: "${{RUN_ID:?}}" "${{COMPOSE_PROJECT_NAME:?}}" "${{RUN_FLAG:?}}" "${{VERSION:?}}" "${{WORK_DIR:?}}"
MODE="${{1:-}}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || {{ echo "usage: --seed|--residual" >&2; exit 30; }}
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${{PCB_PYTHON:-python3}}"
mkdir -p "$WORK_DIR"
OUT="$("$PY" - "$VERSION" "$RUN_FLAG" "$CASE_DIR" <<'PYEOF'
import sys, json, importlib.util, os
spec = importlib.util.spec_from_file_location('_seedmod', sys.argv[4] + '/poc/seed_exec.py')
mod = importlib.util.module_from_spec(spec)
try:
    spec.loader.exec_module(mod)
except Exception as e:
    print(json.dumps({'error': str(e)[:200]})); sys.exit(0)
version, flag = sys.argv[1], sys.argv[2]
out = None
if hasattr(mod, 'candidate'):
    out = mod.candidate(version=version, flag=flag)
elif hasattr(mod, 'run'):
    base = os.environ.get('PCB_BASE', '')
    out = mod.run(base) if base else None
elif hasattr(mod, 'original_poc'):
    out = mod.original_poc(version=version)
print(json.dumps(out, default=str))
PYEOF
)" || {{ echo "$OUT" >&2; exit 20; }}
echo "$OUT" | head -c 500; echo
"$PY" -c "import json,sys
try:
    d = json.loads(sys.argv[1])
except Exception:
    sys.exit(20)
s = json.dumps(d)
sys.exit(0 if '$RUN_FLAG' in s and d.get('status') in (200, 201, None) else 10)" "$OUT"
"""
    return tpl.replace("{cid}", cid)


def adapt(cid: str) -> dict:
    d = CASES / cid
    vf = d / "scripts" / "verify.sh"
    info = analyze(cid)
    if info["kind"] == "executor":
        write_cleaner(cid)
        body = gen_executor_verify(cid, info["flag_channel"])
    elif info["kind"] == "wrapper":
        write_cleaner(cid)
        body = gen_wrapper_verify(cid)
    else:
        return {"case_id": cid, "status": "skipped", "kind": info["kind"]}
    if vf.exists() and not (d / "scripts" / "verify.sh.tpl").exists():
        shutil.copy2(vf, d / "scripts" / "verify.sh.tpl")
    vf.write_text(body)
    vf.chmod(0o755)
    return {"case_id": cid, "status": "adapted", "kind": info["kind"],
            "flag_channel": info.get("flag_channel", "")}


def main():
    args = sys.argv[1:]
    if not args or args[0] == "--all":
        ids = sorted(p.name for p in CASES.iterdir() if (p / "case.yaml").exists())
    else:
        ids = args
    from collections import Counter
    stats = Counter()
    for cid in ids:
        r = adapt(cid)
        stats[r["status"] + (":" + r.get("kind", "") if r["status"] == "adapted" else "")] += 1
        print(json.dumps(r, ensure_ascii=False))
    print("summary:", dict(stats))


if __name__ == "__main__":
    main()
