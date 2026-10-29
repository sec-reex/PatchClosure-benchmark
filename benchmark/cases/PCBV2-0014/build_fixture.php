<?php
/*
 * PatchClosure-Bench upload-fixture PACKAGER for xxe_phpspreadsheet_ucs4 (NOT the sink under test).
 *
 * Reads base64 of a crafted xl/worksheets/sheet1.xml on STDIN, scaffolds a VALID .xlsx with THIS
 * library version's OWN writer (so every required part -- styles/theme/docProps -- is present and
 * this version's reader accepts it), swaps in the crafted sheet1.xml, and writes the resulting
 * .xlsx bytes as base64 to STDOUT.
 *
 * This only PACKAGES a malicious spreadsheet the way an attacker would craft one offline; it never
 * loads/reads it. The XmlScanner XXE sink is exercised ONLY later, by the real HTTP /upload web app
 * (www/index.php) when a client uploads this fixture. Using the writer here is the same, ordinary
 * packaging step across all versions and is independent of the Reader\Security\XmlScanner differential.
 */
error_reporting(E_ERROR | E_PARSE);
require '/app/vendor/autoload.php';

$b64 = trim(stream_get_contents(STDIN));
$sheet = base64_decode($b64);
if ($sheet === false || $sheet === '') { fwrite(STDERR, "no sheet on stdin\n"); exit(2); }

$base = tempnam(sys_get_temp_dir(), 'fix') . '.xlsx';
$ss0 = new \PhpOffice\PhpSpreadsheet\Spreadsheet();
$ss0->getActiveSheet()->setCellValue('A1', 'placeholder');
(new \PhpOffice\PhpSpreadsheet\Writer\Xlsx($ss0))->save($base);

$zip = new ZipArchive();
$zip->open($base);
$zip->deleteName('xl/worksheets/sheet1.xml');
$zip->close();
$zip->open($base);
$zip->addFromString('xl/worksheets/sheet1.xml', $sheet);
$zip->close();

echo base64_encode(file_get_contents($base));
@unlink($base);
