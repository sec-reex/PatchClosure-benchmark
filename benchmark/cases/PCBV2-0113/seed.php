<?php
/**
 * Seed a known admin + mailbox + one conversation using the REAL FreeScout
 * Eloquent models and factories (same code the app's own DatabaseSeeder uses).
 * Prints "PCB_MAILBOX=<id> PCB_CONV=<id>" which the entrypoint / oracle can read.
 */
require __DIR__ . '/vendor/autoload.php';
$app = require_once __DIR__ . '/bootstrap/app.php';
$kernel = $app->make(Illuminate\Contracts\Console\Kernel::class);
$kernel->bootstrap();

use App\User;
use App\Mailbox;
use App\Customer;
use App\Email;
use App\Conversation;
use App\Thread;

$admin = User::where('email', getenv('FS_ADMIN_EMAIL') ?: 'admin@pcb.local')->first();
if (!$admin) {
    fwrite(STDERR, "no admin user found\n");
    exit(1);
}

$mailbox = factory(Mailbox::class)->create([
    'name'  => 'Support',
    'email' => 'support@pcb.local',
]);
// Attach admin to the mailbox (grants access to settings/signature + conversation view).
$mailbox->users()->sync([$admin->id]);

$customer = factory(Customer::class)->create();
$email = factory(Email::class)->make();
$customer->emails()->save($email);

$conversation = factory(Conversation::class)->create([
    'created_by_user_id' => $admin->id,
    'mailbox_id'         => $mailbox->id,
    'customer_id'        => $customer->id,
    'customer_email'     => $email->email,
    'user_id'            => $admin->id,
    'status'             => Conversation::STATUS_ACTIVE,
    'subject'            => 'PCB support request',
]);

$thread = factory(Thread::class)->make([
    'customer_id'     => $customer->id,
    'to'              => $email->email,
    'conversation_id' => $conversation->id,
    'body'            => 'Hello, I need help with my order.',
]);
$conversation->threads()->save($thread);

echo "PCB_MAILBOX=" . $mailbox->id . " PCB_CONV=" . $conversation->id . "\n";
// Persist ids to a file the running app can expose for the oracle.
file_put_contents('/var/www/html/public/pcb_ids.txt', 'mailbox=' . $mailbox->id . '&conv=' . $conversation->id . "\n");
