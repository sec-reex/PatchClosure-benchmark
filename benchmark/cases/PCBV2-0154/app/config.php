<?php
// Minimal PHP-Nuke config.php — provides the globals that nukesentinel.php expects.
// This is PHP-Nuke infrastructure (not NukeSentinel code).

$dbhost  = getenv('DB_HOST') ?: 'db';
$dbuname = getenv('DB_USER') ?: 'nuke';
$dbpass  = getenv('DB_PASS') ?: 'nuke';
$dbname  = getenv('DB_NAME') ?: 'phpnuke';
$prefix  = 'nuke';
$user_prefix = 'nuke';
$admin_file  = 'admin';
