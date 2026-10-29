<?php
// One-time fixture seed (runs once after the REAL installer, from the entrypoint, CLI).
// Creates the low-privilege 'editor' user-administrator and plants the benign canary.
//
// Threat model (faithful to CVE-2026-35671 -> CVE-2026-56396): 'editor' is a delegated user
// administrator -- holds add_user + edit_user + delete_user (so it may legitimately call the
// user-admin API), but is NOT a SuperAdmin and does NOT hold editconfig. The canary is
// phpMyFAQ's real REST API client token (config item api.apiClientToken), which only a
// SuperAdmin / editconfig holder may read via GET admin/api/configuration/list/api.
require '/opt/pcb_common.php';

use phpMyFAQ\User;

$flag      = getenv('PCB_FLAG') ?: 'PCB_FLAG_MISSING';
$editorPw  = getenv('PMF_EDITOR_PW') ?: 'EditorPass12345';

$editor = new User($faqConfig);
if (!$editor->getUserByLogin('editor', false)) {
    if (!$editor->createUser('editor', $editorPw, '', 0)) {
        fwrite(STDERR, "[seed] createUser failed: " . implode(', ', $editor->errors ?? []) . "\n");
        exit(1);
    }
}
$editorId = $editor->getUserId();
$editor->setStatus('active');
$editor->setSuperAdmin(false);

// Grant exactly the user-administration rights (delegable), nothing SuperAdmin-only.
$editor->perm->refuseAllUserRights($editorId);
foreach (['add_user', 'edit_user', 'delete_user'] as $rightName) {
    $rid = $editor->perm->getRightId($rightName);
    if ($rid > 0) {
        $editor->perm->grantUserRight($editorId, $rid);
    }
}

// Plant the canary in phpMyFAQ's real configuration + fix reference URL so CSRF cookies bind
// to the 127.0.0.1 host the external attacker connects to.
$faqConfig->update(['api.apiClientToken' => $flag]);
$faqConfig->update(['main.referenceURL' => 'http://127.0.0.1']);

fwrite(STDOUT, "[seed] editor uid={$editorId} seeded; canary planted in api.apiClientToken\n");
