<?php
// Harness fixture-reset endpoint (NOT a phpMyFAQ route). Restores the pristine world between
// oracle probes so the missing-authorization differential is order-independent:
//   * editor -> is_superadmin=0, user-admin rights re-granted (add/edit/delete_user)
//   * SuperAdmin uid=1 -> password restored (undo an overwrite-password takeover on v0)
//   * canary api.apiClientToken re-planted with ${PCB_FLAG}
// Returns JSON { ok, editor_id, admin_id } so the oracle can target the editor by real uid.
if (!defined('IS_VALID_PHPMYFAQ')) {
    define('IS_VALID_PHPMYFAQ', null);
}
require __DIR__ . '/src/Bootstrap.php';   // -> $faqConfig, $db

use phpMyFAQ\User;
use phpMyFAQ\Auth;

header('Content-Type: application/json');

$flag     = getenv('PCB_FLAG') ?: 'PCB_FLAG_MISSING';
$adminPw  = getenv('PMF_ADMIN_PW') ?: 'AdminPass12345';

// --- reset editor ---
$editor = new User($faqConfig);
$editor->getUserByLogin('editor', false);
$editorId = $editor->getUserId();
if ($editorId > 0) {
    $editor->setSuperAdmin(false);
    $editor->setStatus('active');
    $editor->perm->refuseAllUserRights($editorId);
    foreach (['add_user', 'edit_user', 'delete_user'] as $rightName) {
        $rid = $editor->perm->getRightId($rightName);
        if ($rid > 0) {
            $editor->perm->grantUserRight($editorId, $rid);
        }
    }
}

// --- restore SuperAdmin uid=1 password (undo a v0 overwrite-password takeover) ---
$admin = new User($faqConfig);
$admin->getUserById(1, true);
if ($admin->getUserId() === 1) {
    $auth = new Auth($faqConfig);
    $authSource = $auth->selectAuth($admin->getAuthSource(key: 'name'));
    $authSource->getEncryptionContainer($admin->getAuthData(key: 'encType'));
    $admin->changePassword($adminPw);
    $admin->setSuperAdmin(true);
}

// --- re-plant the canary ---
$faqConfig->update(['api.apiClientToken' => $flag]);
$faqConfig->update(['main.referenceURL' => 'http://127.0.0.1']);

echo json_encode(['ok' => true, 'editor_id' => $editorId, 'admin_id' => 1]);
