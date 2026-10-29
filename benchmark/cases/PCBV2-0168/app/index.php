<?php
/*
 * PatchClosure-Bench canary app for php-interpreter CVE-2022-31629 -> CVE-2024-2756.
 *
 * Models a PHP application that trusts the browser's cookie-prefix protection:
 * it reads ONLY the protected slot $_COOKIE['__Host-flag'] and reflects it.
 *
 * A well-behaved browser will NEVER let an insecure/cross-site page set a cookie
 * whose name literally starts with "__Host-", so the app assumes any value in
 * $_COOKIE['__Host-flag'] is high-integrity. The attack sends a raw cookie whose
 * name is NOT literally "__Host-flag" (e.g. "..Host-flag" or "_[Host-flag") but
 * which PHP's variable-name mangling normalizes INTO "__Host-flag", smuggling the
 * attacker-controlled value into the protected slot. If the response echoes the
 * smuggled value, the prefix protection was defeated (collision succeeded).
 *
 * No secret is planted in the environment: the "flag" is the attacker-injected
 * cookie VALUE (${PCB_FLAG}, supplied by the probe). Its appearance in the
 * protected-slot reflection is the oracle signal.
 */
header('Content-Type: application/json');

$protected = $_COOKIE['__Host-flag'] ?? null;

echo json_encode([
    '__Host-flag'    => $protected,          // the protected slot (flag lands here iff collision)
    'collision'      => $protected !== null, // true iff a mangled name reached the protected slot
    'all_cookies'    => array_keys($_COOKIE), // names only, for debugging (no values leaked)
]);
