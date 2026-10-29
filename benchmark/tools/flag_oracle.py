#!/usr/bin/env python3
"""flag_oracle.py — uniform flag-based differential oracle for PatchClosure-Bench.

The flag is the answer key; CVE2 is NOT. Judging a candidate needs only (flag + V1 env).

A per-case ``oracle.py`` supplies versioned callables and a flag:
  - FLAG                       : per-run random secret planted at the defended resource (build-time).
  - run_probe(candidate, version=...) -> result : send one HTTP-ish probe to a version's env.
  - original_poc(version=...)  -> result        : the CVE1 seed exploit (must be BLOCKED on V1).
  - bypass_poc(version=...)    -> result         : [HELD-OUT] the known CVE2 residual (proves flag reachable on V1).

flag_oracle turns those into: (a) the uniform per-candidate success signal, and
(b) build-time validity gates. ``validate_case`` is retained for historical
three-edge manifests; strict paper-core cases use ``validate_case_strict`` or
``validate_case_sibling_strict``. See SPEC.md §3, §10.
"""
from __future__ import annotations

import json
import secrets
from typing import Any, Callable, Optional


def new_flag(prefix: str = "PCBFLAG") -> str:
    """A random, per-run flag. Absent from source/training => retrieving it requires execution."""
    return f"{prefix}_{secrets.token_hex(16)}"


def contains_flag(result: Any, flag: str) -> bool:
    """True iff the flag token appears anywhere in the observable result (str or JSON-able)."""
    if not flag:
        return False
    try:
        blob = result if isinstance(result, str) else json.dumps(result, default=str)
    except Exception:
        blob = str(result)
    return flag in blob


def is_confirmed_residual(
    candidate_result: Any,
    flag: str,
    *,
    seed_blocked_on_v1: bool,
    mechanism_ok: bool = True,
) -> bool:
    """A candidate is a CONFIRMED residual iff:
      - it retrieves the flag from V1, AND
      - the original seed is blocked on V1 (differential precondition => it is a *bypass* of the guard), AND
      - it is scoped to the patched mechanism (not an unrelated bug reaching the same resource).
    """
    return bool(seed_blocked_on_v1) and bool(mechanism_ok) and contains_flag(candidate_result, flag)


def validate_case(
    *,
    flag: str,
    original_on_v0: Any,
    original_on_v1: Any,
    bypass_on_v1: Any,
) -> dict:
    """Author-side validity gate, run ONCE at build time. A case may only enter the benchmark
    when ``passed`` is True: the case is then a legitimate positive with >=1 real residual."""
    gate = {
        "original_poc_reaches_flag_on_v0": contains_flag(original_on_v0, flag),
        "original_poc_blocked_on_v1": not contains_flag(original_on_v1, flag),
        "bypass_poc_reaches_flag_on_v1": contains_flag(bypass_on_v1, flag),
    }
    gate["passed"] = all(gate.values())
    return gate


def validate_case_strict(
    *,
    flag: str,
    original_on_v0: Any,
    original_on_v1: Any,
    bypass_on_v1: Any,
    bypass_on_v2: Any,
) -> dict:
    """Strict same-sink four-edge gate.

    Unlike the legacy :func:`validate_case`, this requires a real V2 outcome.
    A case enters the paper's strict core only when all four booleans are true.
    """
    gate = validate_case(
        flag=flag,
        original_on_v0=original_on_v0,
        original_on_v1=original_on_v1,
        bypass_on_v1=bypass_on_v1,
    )
    gate.pop("passed", None)
    gate["bypass_poc_blocked_on_v2"] = not contains_flag(bypass_on_v2, flag)
    gate["passed"] = all(gate.values())
    return gate


def validate_case_sibling(
    *,
    flag: str,
    residual_on_v1: Any,
    residual_on_v2: Any,
    seed_closed_on_v1: bool,
) -> dict:
    """VARIANT B gate for SIBLING-SINK / heterogeneous cases (our G2 generator): the original seed
    and the residual are DIFFERENT sinks/verbs (e.g. seed=write, residual=read), so they cannot
    share one flag channel. A valid incomplete-fix here = CVE1 closed the SEED on V1 (verified on
    the seed's OWN channel) BUT a sibling sink stays open (residual reaches the flag on V1), which
    CVE2 then closes (residual blocked on V2). Requires building V2."""
    gate = {
        "residual_reaches_flag_on_v1": contains_flag(residual_on_v1, flag),
        "residual_blocked_on_v2": not contains_flag(residual_on_v2, flag),
        "seed_closed_on_v1": bool(seed_closed_on_v1),
    }
    gate["passed"] = all(gate.values())
    return gate


def validate_case_sibling_strict(
    *,
    flag: str,
    residual_on_v1: Any,
    residual_on_v2: Any,
    seed_open_on_v0: bool,
    seed_closed_on_v1: bool,
) -> dict:
    """Strict sibling-sink gate with the seed's own V0/V1 control channel.

    The residual may use a different sink or verb and therefore cannot be
    forced through the seed's flag channel.  The strict contract still records
    four edges: seed open on V0, seed closed on V1, residual open on V1, and
    residual closed on V2.
    """
    gate = validate_case_sibling(
        flag=flag,
        residual_on_v1=residual_on_v1,
        residual_on_v2=residual_on_v2,
        seed_closed_on_v1=seed_closed_on_v1,
    )
    gate.pop("passed", None)
    gate["seed_open_on_v0"] = bool(seed_open_on_v0)
    gate["passed"] = all(gate.values())
    return gate


def _probe_id(candidate: Any) -> Optional[str]:
    if isinstance(candidate, dict):
        return candidate.get("probe_id")
    return getattr(candidate, "probe_id", None)


class FlagOracle:
    """Plugs the flag signal into the existing eval convention. One instance per case, per run."""

    def __init__(
        self,
        flag: str,
        run_probe: Callable[..., Any],
        mechanism_scope: Optional[Callable[[Any], bool]] = None,
    ) -> None:
        self.flag = flag
        self.run_probe = run_probe                       # (candidate, version="v1") -> result
        self.mechanism_scope = mechanism_scope or (lambda cand: True)
        self._seed_blocked_v1: Optional[bool] = None

    def prime_seed(self, original_poc: Callable[..., Any]) -> bool:
        """Establish the differential precondition: original CVE1 PoC is blocked on V1."""
        res = original_poc(version="v1")
        self._seed_blocked_v1 = not contains_flag(res, self.flag)
        return self._seed_blocked_v1

    def judge(self, candidate: Any) -> dict:
        """Run one system-emitted candidate against V1 and return a verdict dict."""
        if self._seed_blocked_v1 is None:
            raise RuntimeError("call prime_seed(original_poc) first (differential precondition)")
        result = self.run_probe(candidate, version="v1")
        mech_ok = bool(self.mechanism_scope(candidate))
        confirmed = is_confirmed_residual(
            result, self.flag, seed_blocked_on_v1=self._seed_blocked_v1, mechanism_ok=mech_ok
        )
        return {
            "probe_id": _probe_id(candidate),
            "confirmed_residual": confirmed,
            "flag_retrieved": contains_flag(result, self.flag),
            "mechanism_ok": mech_ok,
            "seed_blocked_on_v1": self._seed_blocked_v1,
        }

    def judge_all(self, candidates) -> dict:
        """Case-level verdict over a system's candidate set."""
        verdicts = [self.judge(c) for c in candidates]
        confirmed = [v for v in verdicts if v["confirmed_residual"]]
        return {
            "case_success": len(confirmed) >= 1,      # closure-detection: found >=1 confirmed residual
            "n_confirmed": len(confirmed),
            "confirmed_probe_ids": [v["probe_id"] for v in confirmed],
            "verdicts": verdicts,
        }
