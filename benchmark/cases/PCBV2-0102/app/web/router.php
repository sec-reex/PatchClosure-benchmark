<?php
/**
 * Router script for the PHP built-in web server (php -S) so the REAL Yii2 app gets clean
 * pretty-URL routing (POST /trigger). Every non-static request is dispatched through index.php
 * with SCRIPT_NAME normalized to /index.php so yii\web\Request resolves PATH_INFO from the URI.
 */
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
if ($path !== '/' && $path !== '' && is_file(__DIR__ . $path)) {
    return false; // let the built-in server serve a real static file (none exist here)
}

$_SERVER['SCRIPT_NAME'] = '/index.php';
$_SERVER['SCRIPT_FILENAME'] = __DIR__ . '/index.php';
$_SERVER['PHP_SELF'] = '/index.php';

require __DIR__ . '/index.php';
