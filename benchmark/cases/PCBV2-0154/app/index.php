<?php
/*
 * Thin PHP-Nuke host for the official NukeSentinel html/ overlay.
 * Defines the few PHP-Nuke core symbols nukesentinel.php calls, then includes
 * the REAL /var/www/html/includes/nukesentinel.php from the SourceForge package.
 * After the real tracker INSERT, print the last tracked row (effect channel).
 */
error_reporting(E_ALL & ~E_NOTICE & ~E_STRICT & ~E_DEPRECATED & ~E_WARNING);
date_default_timezone_set('UTC');

global $db, $prefix, $user_prefix, $admin_file, $nuke_config, $ab_config, $nsnst_const;

function getusrinfo($cookie_val = '') {
    return array('user_id' => 1, 'username' => '');
}

function is_admin($cookie_val = '') { return false; }

$ns_file = '/var/www/html/includes/nukesentinel.php';
if (!file_exists($ns_file)) {
    header("HTTP/1.1 500 Internal Server Error");
    die("nukesentinel.php not found at $ns_file");
}
include($ns_file);

header("Content-Type: text/plain");
$ns_version = getenv('NS_VERSION') ?: 'v1';
echo "NukeSentinel real-app [NS_VERSION=$ns_version]\n";
echo "seen_remote_ip=" . (isset($nsnst_const['remote_ip']) ? $nsnst_const['remote_ip'] : 'unset') . "\n";
echo "--- tracked hit ---\n";

if (isset($db) && $db->db_connect_id) {
    $last_id = mysql_insert_id($db->db_connect_id);
    if ($last_id > 0) {
        $result = $db->sql_query("SELECT * FROM `" . $prefix . "_nsnst_tracked_ips` WHERE `id` = " . intval($last_id));
    } else {
        $result = $db->sql_query("SELECT * FROM `" . $prefix . "_nsnst_tracked_ips` ORDER BY `id` DESC LIMIT 1");
    }
    $row = $db->sql_fetchrow($result);
    if ($row) {
        echo "ip_addr=" . $row['ip_addr'] . "\n";
        echo "user_agent=" . $row['user_agent'] . "\n";
        echo "client_ip=" . $row['client_ip'] . "\n";
        echo "x_forward_for=" . $row['x_forward_for'] . "\n";
        echo "remote_addr=" . $row['remote_addr'] . "\n";
    } else {
        echo "(no tracked row)\n";
    }
} else {
    echo "(db not connected)\n";
}
