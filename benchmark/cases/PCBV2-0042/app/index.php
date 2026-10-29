<?php
/**
 * Tiny HTTP service wrapping the REAL knplabs/knp-snappy library.
 *
 * Endpoints:
 *   GET /health             — readiness probe (returns 200 + "ok").
 *   GET /trigger?filename=X — calls snappy->generateFromHtml with X as the
 *                             output filename, then checks whether PHAR
 *                             deserialization fired (marker file written by
 *                             BenignMarker::__wakeup).  Returns the PCB_FLAG
 *                             token when deserialization occurred, or an error
 *                             message otherwise.
 */

require_once __DIR__ . '/vendor/autoload.php';
require_once __DIR__ . '/BenignMarker.php';

use Knp\Snappy\Pdf;

$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

// ---- health probe ----
if ($uri === '/health') {
    header('Content-Type: text/plain');
    echo 'ok';
    exit;
}

// ---- trigger endpoint ----
if ($uri === '/trigger') {
    header('Content-Type: text/plain');

    $filename = $_GET['filename'] ?? '';
    if ($filename === '') {
        http_response_code(400);
        echo 'missing filename parameter';
        exit;
    }

    // Clean slate: remove any previous marker.
    $marker = '/tmp/pcb_marker.txt';
    if (file_exists($marker)) {
        @unlink($marker);
    }

    // Instantiate the REAL snappy PDF generator.
    // wkhtmltopdf binary path — standard Debian location.
    $snappy = new Pdf('/usr/bin/wkhtmltopdf');

    $error = '';
    try {
        // This calls prepareOutput($filename, ...) internally,
        // which calls file_exists($filename).
        // On PHP 7.x, file_exists('phar://...') triggers PHAR metadata
        // deserialization — the BenignMarker::__wakeup writes the marker.
        $snappy->generateFromHtml('<h1>test</h1>', $filename);
    } catch (\Throwable $e) {
        $error = $e->getMessage();
    }

    // Did PHAR deserialization fire?
    if (file_exists($marker)) {
        // Deserialization occurred — return the planted flag.
        $flag = trim(file_get_contents('/tmp/pcb_flag.txt'));
        echo $flag;
    } else {
        // No deserialization — the guard blocked it or the path was invalid.
        echo 'BLOCKED';
        if ($error !== '') {
            echo "\n" . $error;
        }
    }
    exit;
}

// ---- fallback ----
http_response_code(404);
echo 'not found';
