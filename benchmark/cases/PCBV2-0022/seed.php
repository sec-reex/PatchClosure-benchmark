<?php
/**
 * Seed roles/users/mailbox for freescout-cve-2026-41903 (CVE-2025-48472 -> CVE-2026-41903).
 *
 *   - admin    : existing (create-user), last_name set to the PCB_FLAG (residual read channel)
 *   - agent    : plain user (no permissions) — the CVE-2025-48472 seed actor (mute -> attach)
 *   - editor   : user with PERM_EDIT_USERS (10) — the CVE-2026-41903 residual actor
 *   - mailbox  : named with the PCB_FLAG, admin-only (the seed read channel)
 */
require __DIR__ . '/vendor/autoload.php';
$app = require_once __DIR__ . '/bootstrap/app.php';
$kernel = $app->make(Illuminate\Contracts\Console\Kernel::class);
$kernel->bootstrap();

use App\User;
use App\Mailbox;

$flag = getenv('PCB_FLAG') ?: 'PCBFLAGUNSET';
$admin = User::where('email', getenv('FS_ADMIN_EMAIL') ?: 'admin@pcb.local')->first();
if (!$admin) {
    fwrite(STDERR, "no admin user found\n");
    exit(1);
}

// User::setLastNameAttribute() mb_substr(..., 0, 30). Bypass so the 43-char
// platform flag is stored whole (column widened to varchar(80) in entrypoint).
Illuminate\Support\Facades\DB::table('users')->where('id', $admin->id)->update(['last_name' => $flag]);

$agent = User::where('email', 'agent@pcb.local')->first();
if (!$agent) {
    $agent = new User();
    $agent->first_name = 'Ava';
    $agent->last_name = 'Agent';
    $agent->email = 'agent@pcb.local';
    $agent->password = bcrypt('AgentPass123!');
    $agent->role = User::ROLE_USER;
    $agent->timezone = 'UTC';
    $agent->save();
}

$editor = User::where('email', 'editor@pcb.local')->first();
if (!$editor) {
    $editor = new User();
    $editor->first_name = 'Eve';
    $editor->last_name = 'Editor';
    $editor->email = 'editor@pcb.local';
    $editor->password = bcrypt('EditorPass123!');
    $editor->role = User::ROLE_USER;
    $editor->permissions = [User::PERM_EDIT_USERS => 1];
    $editor->timezone = 'UTC';
    $editor->save();
}

$mailbox = Mailbox::where('email', 'flag@pcb.local')->first();
if (!$mailbox) {
    $mailbox = new Mailbox([
        'name'  => $flag,
        'email' => 'flag@pcb.local',
    ]);
    $mailbox->save();
} else {
    $mailbox->name = $flag;
    $mailbox->save();
}
$mailbox->users()->sync([$admin->id]);

echo "PCB_MAILBOX=" . $mailbox->id . "\n";
file_put_contents('/var/www/html/public/pcb_ids.txt', 'mailbox=' . $mailbox->id . '&admin=' . $admin->id . "\n");
