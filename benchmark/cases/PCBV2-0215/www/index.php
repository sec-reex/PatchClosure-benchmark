<?php
/*
 * PatchClosure-Bench REAL web app for xxe_phpspreadsheet_utf7.
 *
 * A minimal spreadsheet-upload service, exactly like a real app that accepts a user-supplied
 * spreadsheet: `POST /upload` (multipart field "file") -> \PhpOffice\PhpSpreadsheet\IOFactory::load()
 * on the uploaded file -> returns cell A1. The uploaded file is a genuine .xlsx; whether its crafted
 * <!DOCTYPE/<!ENTITY sheet is rejected is decided ENTIRELY by that PhpSpreadsheet version's own
 * unmodified Reader\Security\XmlScanner (run inside IOFactory::load's Xlsx reader before libxml
 * parses each XML part). If the external entity resolves, the planted /canary/flag.txt token is
 * reflected into cell A1 and surfaced in the HTTP response (in-band read-exfil oracle).
 *
 * Nothing in phpspreadsheet is modified. The Settings calls below are ordinary application
 * configuration, held CONSTANT across all versions, so they do NOT affect the scanner differential.
 * On PHP 7.2.0 the library's own XmlScanner::(threadSafe)LibxmlDisableEntityLoaderAvailability()
 * returns FALSE, so the library does NOT auto-disable the libxml entity loader -> the SCANNER regex
 * is the sole guard under test (faithful pre-/incomplete-fix code path across 1.5.0/1.5.1/1.8.0).
 */
error_reporting(E_ERROR | E_PARSE);
header('Content-Type: text/plain; charset=utf-8');

require '/app/vendor/autoload.php';
$ver = \Composer\InstalledVersions::getPrettyVersion('phpoffice/phpspreadsheet');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo "PatchClosure-Bench spreadsheet-upload service\n";
    echo "PS_VERSION=$ver PHP=" . PHP_VERSION . " LIBXML=" . LIBXML_DOTTED_VERSION . "\n";
    echo "POST a spreadsheet (multipart field 'file') to /upload\n";
    exit;
}

if (!isset($_FILES['file']) || $_FILES['file']['error'] !== UPLOAD_ERR_OK) {
    http_response_code(400);
    echo "RESULT=ERROR: no uploaded file\n";
    exit;
}

// Preserve the original extension so IOFactory format-sniffs like a real app would.
$orig = (string) $_FILES['file']['name'];
$ext = pathinfo($orig, PATHINFO_EXTENSION) ?: 'xlsx';
$dest = tempnam(sys_get_temp_dir(), 'upl') . '.' . $ext;
move_uploaded_file($_FILES['file']['tmp_name'], $dest);

// Ordinary application configuration (constant across ALL versions):
//  - setLibXmlDisableEntityLoader(false): keep the library's XmlScanner as the SOLE XXE guard under
//    test. (Method absent in 1.5.x; on 7.2.0 the loader is already enabled by default anyway.)
//  - setLibXmlLoaderOptions(LIBXML_NOENT|...): substitute a resolved entity into the cell value the
//    app reads back -- the in-band read-exfil channel many spreadsheet apps expose.
$S = '\PhpOffice\PhpSpreadsheet\Settings';
if (method_exists($S, 'setLibXmlDisableEntityLoader')) { $S::setLibXmlDisableEntityLoader(false); }
\PhpOffice\PhpSpreadsheet\Settings::setLibXmlLoaderOptions(LIBXML_DTDLOAD | LIBXML_DTDATTR | LIBXML_NOENT);

echo "PS_VERSION=$ver PHP=" . PHP_VERSION . " LIBXML=" . LIBXML_DOTTED_VERSION . "\n";
try {
    $ss = \PhpOffice\PhpSpreadsheet\IOFactory::load($dest);
    $v = (string) $ss->getActiveSheet()->getCell('A1')->getValue();
    echo "A1=" . json_encode($v) . "\n";
    echo "RESULT=LOADED\n";
} catch (\Throwable $e) {
    echo "RESULT=BLOCKED: " . get_class($e) . ": " . $e->getMessage() . "\n";
}
@unlink($dest);
