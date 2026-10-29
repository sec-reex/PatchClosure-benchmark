#!/usr/bin/env python3
"""[GIVEN] CVE-2024-43333 seed — ASE "View Admin as Role" privilege escalation.

Scenario: the attacker account `viewer` was an administrator who used the plugin's
"View Admin as Role" feature to preview a lower role (subscriber). That legitimately
stores `_asenha_view_admin_as_original_roles = [administrator]` and lists `viewer` in
the option `viewing_admin_as_role_are`. The admin then DEMOTES `viewer` — and here is
the seed's distinguishing choice: the demotion is done VIA THE PROFILE-EDIT SCREEN
(`wp_update_user` -> `profile_update` hook).

Then, UNAUTHENTICATED, `GET /?reset-for=viewer` asks the reset handler to restore the
stored original roles -> `viewer` becomes administrator again -> can read the admin-only
canary.

Contract:
  V0 (ASE 7.6.2): no cleanup exists on ANY demotion path -> stale meta survives ->
      reset-for restores administrator -> reads flag.  REACHES flag.
  V1 (ASE 7.6.3): CVE-2024-43333 fix hooks `profile_update` -> demoting via the profile
      screen deletes the stale meta + drops `viewer` from the allow-list -> reset-for
      finds nothing to restore.  BLOCKED (no flag).

The residual (CVE-2026-12083) reaches the SAME flag on V1 by demoting via a path the
fix forgot to hook (`set_user_role`).
"""
from __future__ import annotations


def candidate() -> dict:
    """Request candidate for the CVE-2024-43333 seed: demotion via the profile-edit path."""
    return {
        "probe_id": "cve-2024-43333-reset-for-after-profile_update-demotion",
        "demotion_path": "profile_update",   # wp_update_user -> fires profile_update
        "attack": "reset-for",
        "victim": "viewer",
    }


if __name__ == "__main__":
    print(candidate())
