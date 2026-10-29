<?php
/**
 * REAL HTTP service endpoint for phpspreadsheet-phar-wrapper-parseurl-bypass.
 *
 * This is a minimal, realistic "import a spreadsheet" web app. It is served by Apache
 * (mod_php, php:8.2-apache) at the document root and is reachable over an EXTERNAL HTTP
 * request. A request carries an attacker-controlled file reference in the `path` field;
 * the app hands it straight to the REAL, unmodified PhpSpreadsheet Csv reader -- exactly
 * as an application importing a user-supplied spreadsheet would:
 *
 *     Reader\Csv::load($path)
 *        -> BaseReader::openFile($path)
 *        -> File::assertFile($path)
 *        -> File::prohibitWrappers($path)     <-- the guard hardened across 1.30.2/1.30.3/1.30.5
 *
 * Nothing in PhpSpreadsheet is modified: the version's own prohibitWrappers() decides
 * whether a `phar://` wrapper reaches the loader.
 *
 *   V0 = 1.30.2 : no prohibitWrappers()          -> any phar:// path loads.
 *   V1 = 1.30.3 : parse_url(PHP_URL_SCHEME) guard -> `phar://work/...` (scheme='phar') THROWS;
 *                                                    `phar:///work/...` (3 slashes, parse_url
 *                                                     returns false) SLIPS THROUGH (CVE-2026-45034).
 *   V2 = 1.30.5 : `^phar://` regex guard          -> both forms THROW.
 *
 * Benign: on PHP 8.2 the phar wrapper is only a file-READ primitive; the loaded archive is our own
 * /work/flag.phar whose sole content is the planted ${PCB_FLAG}. Surfacing the flag == the wrapper
 * reached the loader (prohibitWrappers bypassed). No gadget, no deserialization, no code execution.
 *
 *   GET  /            -> {"status":"ok", ...}          (health check, no library call)
 *   POST /  path=<u>  -> {"path","surfaced","error"}   (real Csv::load of <u>; flag in `surfaced`
 *                                                        iff the wrapper reached the loader)
 */
require __DIR__ . '/vendor/autoload.php';

use PhpOffice\PhpSpreadsheet\Reader\Csv as CsvReader;

header('Content-Type: application/json');

$path = $_POST['path'] ?? $_GET['path'] ?? '';

if ($path === '') {
    $ver = '?';
    try {
        $ver = \Composer\InstalledVersions::getPrettyVersion('phpoffice/phpspreadsheet');
    } catch (\Throwable $t) {
        // ignore
    }
    echo json_encode([
        'status' => 'ok',
        'service' => 'phpspreadsheet-import',
        'phpspreadsheet' => $ver,
        'php' => PHP_VERSION,
    ]) . "\n";
    exit;
}

// chdir('/') so the canonical two-slash form `phar://work/flag.phar/...` resolves to /work
// (the archive path sits in the URL "host" position and PHP resolves it against cwd).
chdir('/');

$out = ['path' => $path, 'surfaced' => '', 'error' => ''];
try {
    // Force the Csv reader (the planted phar member is a CSV). This still runs
    // File::assertFile -> File::prohibitWrappers on $path, i.e. the exact guard under test,
    // while avoiding IOFactory type-sniffing quirks on the guarded load path.
    $reader = new CsvReader();
    $spreadsheet = $reader->load($path);
    $cells = [];
    foreach ($spreadsheet->getActiveSheet()->getRowIterator(1, 1) as $row) {
        foreach ($row->getCellIterator() as $cell) {
            $cells[] = (string) $cell->getValue();
        }
    }
    $out['surfaced'] = implode('|', $cells);
} catch (\Throwable $t) {
    $out['error'] = get_class($t) . ': ' . $t->getMessage();
}

echo json_encode($out) . "\n";
