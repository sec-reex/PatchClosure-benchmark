#!/usr/bin/env python3
"""[HELD-OUT] CVE-2024-2756 residual — the CVE-2022-31629 fix was INCOMPLETE.

CVE-2022-31629's fix placed the __Host-/__Secure- forbidden-name check TOO EARLY
in php_register_variable_ex — right after the mangling loop, BEFORE the '[' array
path runs. A raw cookie named "_[Host-flag":
  1. mangling loop hits '[' -> sets is_array, null-terminates -> name seen as "_"
     (the early CVE-2022-31629 check sees "_", not "__Host-", and passes it);
  2. the array path then finds NO closing ']', "un-terminates" by restoring
     '[' -> '_', and falls through to plain_var, inserting the SCALAR name
     "__Host-flag" — which the early check already waved through.

So "_[Host-flag" still collides with the protected "__Host-flag" slot on V1
(php 8.1.11). CVE-2024-2756 (php 8.1.28) moves the check into
php_is_forbidden_variable_name(), invoked at the plain_var insertion point on the
FINAL name, closing this residual.

Reaches the flag on V1; blocked on V2. Advisory PoC: `curl -b '_[Host-x=y'` -> {"__Host-x":"y"}.
"""

# Residual raw cookie NAME. Not literally "__Host-flag"; the unclosed-'[' array
# path restores it to "__Host-flag" AFTER the early guard has already passed it.
COOKIE_NAME = "_[Host-flag"


def candidate():
    return {"probe_id": "residual-bracket", "cookie_name": COOKIE_NAME}


if __name__ == "__main__":
    print(candidate())
