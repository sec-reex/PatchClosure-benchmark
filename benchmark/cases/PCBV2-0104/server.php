<?php
/**
 * Real dompdf render service for the SVG-image SSRF pair (CVE-2023-23924 -> CVE-2023-24813).
 *
 * This is a THIN HTTP wrapper around the REAL composer `dompdf/dompdf` library (installed at
 * build time, version selected by ${DOMPDF_VERSION}). It runs the genuine dompdf pipeline
 *     $dompdf = new Dompdf($options);
 *     $dompdf->loadHtml($html);
 *     $dompdf->render();
 * on attacker-supplied HTML. The HTML embeds an SVG whose inner <image> element points at the
 * internal canary sidecar (http://canary:9000/<token>). An SSRF = the real dompdf image cache /
 * php-svg-lib actually fetching that URL. Detection is out-of-band: the canary records every
 * path it was hit on; this service resets + reads that record around each render, so the
 * observable is the CANARY's ground-truth, not anything this wrapper fabricates.
 *
 * Options mirror a typical dompdf deployment that renders untrusted HTML:
 *   - setIsRemoteEnabled(false)  <-- default; the http:// protocol rule is exactly the guard
 *        that CVE-2023-23924's inner-<image> resolve_url() validation is supposed to enforce.
 *        (With remote ENABLED there is no protocol restriction and thus no CVE to speak of;
 *         the vuln is precisely that the SVG path bypasses this restriction.)
 *   - setChroot / temp dir kept at defaults.
 *
 * Routes:
 *   GET  /health                 -> "ok" once composer autoload + Dompdf class are ready
 *   POST /render  {"html": "..."} -> renders, returns {"rendered":bool,"canary_hits":[...],"error":...}
 */

// dompdf 2.0.x + php-svg-lib 0.5.4 emit PHP 8.1 deprecation notices (e.g. passing null to
// file_get_contents in SurfaceCpdf.php). Keep them OUT of the HTTP body so the JSON response
// stays clean; real render failures are still caught as Throwables below.
error_reporting(E_ERROR | E_PARSE);
ini_set('display_errors', '0');

require '/app/vendor/autoload.php';

use Dompdf\Dompdf;
use Dompdf\Options;

const CANARY = 'http://canary:9000';

function canary_get(string $path): string
{
    $ctx = stream_context_create(['http' => ['timeout' => 5, 'ignore_errors' => true]]);
    $r = @file_get_contents(CANARY . $path, false, $ctx);
    return $r === false ? '' : $r;
}

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);

if ($path === '/health') {
    header('Content-Type: text/plain');
    echo class_exists(Dompdf::class) ? ('ok ' . ($_ENV['DOMPDF_VERSION'] ?? getenv('DOMPDF_VERSION'))) : 'loading';
    return true;
}

if ($path !== '/render' || ($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    http_response_code(404);
    echo 'not found';
    return true;
}

$raw = file_get_contents('php://input');
$in = json_decode($raw, true);
$html = is_array($in) ? ($in['html'] ?? '') : '';
if ($html === '') {
    http_response_code(400);
    echo json_encode(['error' => 'missing html']);
    return true;
}

// --- out-of-band SSRF detection: clear the canary's hit record before this render ---
canary_get('/_reset');

$error = null;
$rendered = false;
try {
    $options = new Options();
    // Real-world untrusted-HTML posture: remote images NOT globally enabled. The SVG
    // inner-<image> resolve_url() validation (CVE-2023-23924 fix) is the guard under test.
    $options->setIsRemoteEnabled(false);
    $options->setIsHtml5ParserEnabled(true);

    $dompdf = new Dompdf($options);
    $dompdf->loadHtml($html);
    $dompdf->setPaper('A4');
    $dompdf->render();
    $dompdf->output();          // force the full pipeline (image cache + svg render)
    $rendered = true;
} catch (\Throwable $e) {
    $error = get_class($e) . ': ' . $e->getMessage();
}

// --- read the canary ground-truth: which paths did dompdf actually fetch? ---
$hitsRaw = canary_get('/_hits');
$hits = json_decode($hitsRaw, true);
if (!is_array($hits)) {
    $hits = [];
}

header('Content-Type: application/json');
echo json_encode([
    'rendered'     => $rendered,
    'dompdf_ver'   => $_ENV['DOMPDF_VERSION'] ?? getenv('DOMPDF_VERSION'),
    'canary_hits'  => $hits,      // e.g. ["/PCBFLAG_ab12..."] iff the SVG inner-image was fetched
    'error'        => $error,
]);
return true;
