<?php
/*
 * Router for the PHP built-in server so every route (notably POST /upload) is handled by index.php,
 * mirroring a real front-controller web app. Returning nothing (not false) => index.php handles all.
 */
require __DIR__ . '/index.php';
