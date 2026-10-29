<?php
/**
 * REAL-APP HTTP driver (served by apache out of the Concrete CMS webroot, /app/pcb_driver.php).
 *
 * This is the EXTERNAL HTTP entry point that exercises the vulnerability end-to-end through the REAL
 * booted Concrete CMS -- NO source-lift, NO re-implementation of the guard or the sink:
 *
 *   1) The request body is parsed with json_decode() -- exactly what the Concrete CMS REST API does,
 *      and the crux of CVE-2026-8135: a JSON boolean `"_fromCIF": true` becomes a real PHP bool(true),
 *      whereas a browser form POST could only ever send the string "true".
 *   2) We load the REAL seeded express_entry_list block and call the REAL cloned
 *      concrete/blocks/express_entry_list/controller.php  save($data)  method -- the version-specific
 *      write guard (V0 none / V1 `$data['_fromCIF']===true` / V2 internal saveMode===IMPORT) decides
 *      whether the malicious serialized `filterFields`/`columns` is stored.
 *   3) We then run the REAL render-path unserialize() sink by calling the REAL controller view()
 *      (the "block is viewed by an administrator" path, line ~351/419 of controller.php). If the
 *      payload survived the guard, unserialize() instantiates the benign shadow PcbFlagProbe, whose
 *      __wakeup() reads the /canary/flag.txt token and echoes it -> proves the object was constructed.
 *
 * Response: JSON {stored_filterFields_len, flag_echoed, flag_line, error}. flag_echoed==true iff the
 * render-path unserialize() constructed PcbFlagProbe (i.e. the guard let the payload through).
 */
define('PCB_DIR_BASE', '/app');
/** @var \Concrete\Core\Application\Application $app */
$app = require '/work/pcb_boot.php';

use Concrete\Core\Block\Block;

@require_once '/app/application/src/PcbProbe/PcbFlagProbe.php'; // class must exist for unserialize()

header('Content-Type: application/json');

$raw  = file_get_contents('php://input');
$envelope = json_decode($raw, true);        // <-- REST-API json_decode channel (real bool vs string)
if (!is_array($envelope)) { $envelope = []; }
// PoCs send {"args":{...},"saveMode":"..."}; unwrap to get the block-save $data.
// If no "args" wrapper, treat the whole body as the block-save data (flat format).
$data = (isset($envelope['args']) && is_array($envelope['args'])) ? $envelope['args'] : $envelope;

$bID = (int) trim(@file_get_contents('/app/application/files/pcb_bid.txt'));
$status = ['bID' => $bID, 'phase' => 'start', 'stored_filterFields_len' => null,
           'flag_echoed' => false, 'flag_line' => '', 'error' => ''];

try {
    $db = $app->make('database')->connection();
    // exEntityID is a UUID string -- keep it as string, not cast to int
    $entityID = (string) $db->fetchOne('SELECT exEntityID FROM btExpressEntryList WHERE bID=?', [$bID]);

    // Inject exEntityID into $data so the real save() can find the Express entity (Doctrine needs it).
    // Also inject safe defaults for fields that save() references but the PoC doesn't send.
    if (!isset($data['exEntityID'])) {
        $data['exEntityID'] = $entityID;
    }
    $data['displayLimit']    = $data['displayLimit'] ?? 10;
    $data['enablePagination'] = $data['enablePagination'] ?? 0;
    $data['enableItemsPerPageSelection'] = $data['enableItemsPerPageSelection'] ?? 0;
    $data['enableKeywordSearch'] = $data['enableKeywordSearch'] ?? 0;
    $data['enableSearch']    = $data['enableSearch'] ?? 0;

    // ---- (2) REAL controller save() guard on the external JSON input ----------------------------
    $block = Block::getByID($bID);
    $controller = $block->getController();
    $controller->save($data);                                   // REAL cloned guard runs here
    // Restore exEntityID: parent::save() writes all $data columns and may overwrite exEntityID if
    // the blanking branch cleared it. Force-restore the real entity binding.
    $db->executeQuery('UPDATE btExpressEntryList SET exEntityID=? WHERE bID=?', [$entityID, $bID]);
    $status['phase'] = 'saved';

    $row = $db->fetchAssociative('SELECT filterFields, columns FROM btExpressEntryList WHERE bID=?', [$bID]);
    $storedFF = (string) ($row['filterFields'] ?? '');
    $storedCol = (string) ($row['columns'] ?? '');
    $status['stored_filterFields_len'] = strlen($storedFF);
    $status['stored_columns_len'] = strlen($storedCol);

    // ---- (3) REAL render-path unserialize() sink over exactly what the guard stored -------------
    $c2 = $block->getController();
    $c2->on_start();                        // real BlockController wiring (entityManager, app)
    $c2->exEntityID   = $entityID;          // real Express entity (so view() enters the sink branch)
    $c2->filterFields = $storedFF;          // exactly what the real guarded save() persisted
    $c2->columns      = $storedCol;
    ob_start();
    try {
        $c2->view();                        // REAL sink: unserialize($this->filterFields) -> __wakeup
    } catch (\Throwable $e) {
        // any later render error is irrelevant: unserialize() (and __wakeup) already executed
        $status['view_note'] = get_class($e) . ': ' . $e->getMessage();
    }
    $render = ob_get_clean();
    $status['phase'] = 'rendered';

    $pos = strpos($render, 'PCB_CTOR_FLAG=');
    if ($pos !== false) {
        $status['flag_echoed'] = true;
        $status['flag_line'] = trim(strtok(substr($render, $pos), "\n"));
    }
} catch (\Throwable $t) {
    $status['error'] = get_class($t) . ': ' . $t->getMessage();
}

echo json_encode($status) . "\n";
