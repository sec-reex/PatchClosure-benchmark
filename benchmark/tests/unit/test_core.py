"""Unit tests: flag HMAC, verdict scanning, scorer families."""
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest


@pytest.fixture()
def flag_env(tmp_path, monkeypatch):
    monkeypatch.setenv("PCB_PLATFORM_SECRET_FILE", str(tmp_path / "secret"))
    return tmp_path


def test_flag_hmac_store_roundtrip(tmp_path, flag_env):
    from controller.flag import flag_hmac, new_flag, verify_flag
    from controller.state import StateStore
    s = StateStore(str(tmp_path / "t.db"))
    flag = new_flag("run_x")
    s.store_flag_hmac("run_x", flag_hmac(flag))
    h = s.get_flag_hmac("run_x")
    assert verify_flag(flag, h)
    assert not verify_flag("PCBFLAG_WRONG_deadbeefdead", h)


def test_fresh_flag_entropy_and_hmac(flag_env):
    from controller.flag import flag_hmac, new_flag, verify_flag
    f1 = new_flag("run_abc")
    f2 = new_flag("run_abc")
    assert f1.startswith("PCBFLAG_")
    assert f1 != f2  # 128-bit random per call
    h = flag_hmac(f1)
    assert verify_flag(f1, h)
    assert not verify_flag(f2, h)  # wrong flag rejected
    assert not verify_flag("PCBFLAG_x", h)


def test_standalone_scan_pollution(flag_env):
    from hidden.evaluators.family_scorer import standalone_regex
    flag = "PCBFLAG_abc123"
    pat = standalone_regex(flag)
    assert pat.search('{"flag": "PCBFLAG_abc123"}')
    assert pat.search("PCBFLAG_abc123")
    assert not pat.search("FileNotFoundException: /PCBERR/PCBFLAG_abc123")
    assert not pat.search("GET /read/PCBFLAG_abc123 -> 200")
    assert not pat.search("DROP PROPERTY Widget.PCBFLAG_abc123")


def test_read_exfil_reject_block(flag_env):
    from hidden.evaluators.family_scorer import FamilyScorer
    scorer = FamilyScorer("read_exfil", {"timeout_seconds": 5}, flag="PCBFLAG_z9",
                          run_dir=Path("."), target="http://127.0.0.1:1")
    # target unreachable -> no effect, not a hit
    v = scorer.score({"method": "GET", "path": "/"})
    assert not v["reached"]


def test_state_store_transactions(tmp_path):
    from controller.state import StateStore
    db = tmp_path / "t.db"
    s = StateStore(str(db))
    row, created = s.create_run(run_id="r1", trial_id="t1", case_id="C1",
                                exposure_profile="method_v0v1", target_version="v1",
                                idempotency_key="k1", payload="{}", ttl_seconds=100)
    assert created
    row2, created2 = s.create_run(run_id="r2", trial_id="t2", case_id="C1",
                                  exposure_profile="method_v0v1", target_version="v1",
                                  idempotency_key="k1", payload="{}", ttl_seconds=100)
    assert not created2
    assert row2["run_id"] == "r1"  # idempotent replay returns the same run
    s.update_run("r1", state="ready")
    assert s.get_run("r1")["state"] == "ready"
    # submission uniqueness
    s.create_submission(submission_id="s1", run_id="r1", seq=1, idempotency_key="sk1",
                        type_="flag", outcome="ok", oracle_family="read_exfil",
                        accepted=True, detail="")
    s2, created3 = s.create_submission(submission_id="s2", run_id="r1", seq=2,
                                       idempotency_key="sk1", type_="flag",
                                       outcome="ok", oracle_family="read_exfil",
                                       accepted=True, detail="")
    assert not created3
    assert s2["submission_id"] == "s1"
