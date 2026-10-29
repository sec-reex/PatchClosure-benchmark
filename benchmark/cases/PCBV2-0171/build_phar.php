<?php
/**
 * Per-run canary builder (runs at container start, from the compose command).
 * Builds a BENIGN phar archive /work/flag.phar containing a single CSV member `sheet.csv`
 * whose first cell is the per-run ${PCB_FLAG} token. Nothing else — no stub logic, no metadata,
 * no gadget. If IOFactory::load() ever reaches the phar wrapper for this archive, PhpSpreadsheet
 * reads sheet.csv and the flag surfaces in the loaded spreadsheet output. That surfacing is the
 * ONLY thing the oracle checks: it proves the File::prohibitWrappers guard was bypassed.
 */
$flag = getenv('PCB_FLAG');
if ($flag === false || $flag === '') { $flag = 'NOFLAG'; }

@mkdir('/work', 0777, true);
@unlink('/work/flag.phar');

$p = new Phar('/work/flag.phar');
$p->startBuffering();
// benign spreadsheet payload: row 1 carries the flag token in column A
$p['sheet.csv'] = $flag . ",benign-phpspreadsheet-phar-canary\n";
$p->setStub("<?php __HALT_COMPILER(); ?>");
$p->stopBuffering();

echo "built /work/flag.phar (" . filesize('/work/flag.phar') . " bytes)\n";
