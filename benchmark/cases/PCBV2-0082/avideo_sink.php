<?php
/*
 * PatchClosure-Bench real-app entry for WWBN/AVideo comment markdown XSS
 * (CVE-2026-27568 -> CVE-2026-33500).
 *
 * This file is GLUE ONLY. It does NOT implement or re-implement the sink. It boots the REAL,
 * unmodified WWBN/AVideo tree that was `git clone`d at the exact CVE commit into /app and calls
 * the REAL sink markDownToHTML() (from /app/objects/functionsSecurity.php) over the REAL vendored
 * Parsedown (/app/vendor/erusev/parsedown). No ParsedownSafeWithLinks / sanitizeATag / inlineLink
 * logic lives here -- it all executes out of the cloned repo files. The comment is rendered exactly
 * as objects/comment.php does it:
 *     $row['commentHTML'] = markDownToHTML(str_replace('`', "'", $row['commentPlain']));
 *
 * Why not the full DB-backed comment endpoint: reaching objects/comment.php over HTTP needs the
 * whole AVideo install wizard + MySQL + Comments plugin + a user + a video + a stored comment row,
 * which is disproportionate to render one string. The sink itself depends only on Parsedown (the
 * REAL vendored copy, loaded by the REAL composer autoloader) and the REAL objects/functionsSecurity.php,
 * both of which are the actual repo files at the pinned commit -- so this is the SMALLEST REAL AVideo
 * HTTP path that runs the REAL sink on external request input.
 */
error_reporting(E_ERROR | E_PARSE);

require '/app/vendor/autoload.php';            // REAL composer autoloader -> REAL vendored Parsedown
require '/app/objects/functionsSecurity.php';  // REAL AVideo sink file (markDownToHTML / ParsedownSafeWithLinks)

$store = '/tmp/comment.txt';
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

if ($path === '/health') {
    header('Content-Type: text/plain');
    $fs = is_file('/app/objects/functionsSecurity.php');
    $pd = is_file('/app/vendor/erusev/parsedown/Parsedown.php');
    echo ($fs && $pd ? "ok" : "missing") . " " . (getenv('AE_REF') ?: '') . "\n";
    exit;
}

if ($path === '/comment' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    // Attacker stores a comment (stored XSS). commentPlain is persisted verbatim, as AVideo does.
    file_put_contents($store, isset($_POST['c']) ? $_POST['c'] : '');
    header('Content-Type: text/plain');
    echo "stored\n";
    exit;
}

// GET / : render the stored comment through the REAL sink -- the page the headless victim views.
$commentPlain = is_file($store) ? file_get_contents($store) : '';
$commentHTML  = markDownToHTML(str_replace('`', "'", $commentPlain));  // REAL objects/functionsSecurity.php
header('Content-Type: text/html; charset=utf-8');
?>
<!doctype html><html><head><meta charset="utf-8"><title>AVideo comment</title></head>
<body>
<h3>Comment</h3>
<div id="comments"><p id="commentWithLinks"><?php echo $commentHTML; ?></p></div>
</body></html>
