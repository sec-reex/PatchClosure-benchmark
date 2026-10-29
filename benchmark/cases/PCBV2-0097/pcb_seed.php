<?php
/**
 * CLI seeder (runs inside the container on the REAL booted Concrete CMS). Creates a REAL Express
 * object + a REAL express_entry_list block on the home page so the render path's unserialize() sink
 * is reachable, then records the block id for the HTTP driver. Uses ONLY real Concrete CMS APIs
 * (Express\ObjectManager, Page, BlockType) -- nothing is re-implemented.
 *
 * Also plants the benign shadow class PcbFlagProbe on the include path (application/src) so the REAL
 * render-path unserialize() can instantiate it; its __wakeup() reads the per-run canary and echoes it.
 */
define('PCB_DIR_BASE', '/app');
/** @var \Concrete\Core\Application\Application $app */
$app = require '/work/pcb_boot.php';

use Concrete\Core\Express\ObjectManager;
use Concrete\Core\Page\Page;
use Concrete\Core\Block\BlockType\BlockType;

function out($m){ fwrite(STDOUT, "PCBSEED: $m\n"); }

// --- plant the benign shadow class so unserialize() can construct it (autoloadable) -------------
$probeDir = '/app/application/src/PcbProbe';
@mkdir($probeDir, 0775, true);
file_put_contents($probeDir . '/PcbFlagProbe.php', <<<'PHP'
<?php
// Benign PatchClosure-Bench canary object. If the REAL render-path unserialize() instantiates it,
// its __wakeup() reads the per-run ${PCB_FLAG} from /canary/flag.txt (outside the app) and echoes it.
class PcbFlagProbe
{
    public $probe;
    public function __wakeup()
    {
        $f = @file_get_contents('/canary/flag.txt');
        if ($f !== false) {
            echo 'PCB_CTOR_FLAG=' . trim($f) . "\n";
        }
    }
}
PHP);
require $probeDir . '/PcbFlagProbe.php';

try {
    // --- 1) create (or reuse) a REAL Express object -------------------------------------------
    /** @var ObjectManager $om */
    $om = $app->make(ObjectManager::class);
    $entity = $om->getObjectByHandle('pcbthing');
    if (!is_object($entity)) {
        $builder = $om->buildObject('pcbthing', 'pcbthings', 'PCB Thing');
        $builder->addAttribute('text', 'Title', 'title');
        $entity = $builder->save();
        out('created Express object');
    } else {
        out('Express object exists');
    }
    $entityID = $entity->getID();
    out('entityID=' . $entityID);

    // --- 2) place a REAL express_entry_list block on the home page ----------------------------
    $home = Page::getByID(Page::getHomePageID());
    $bt = BlockType::getByHandle('express_entry_list');
    if (!is_object($bt)) { out('FATAL: express_entry_list block type missing'); exit(2); }

    $bidFile = '/app/application/files/pcb_bid.txt';
    $bID = is_file($bidFile) ? (int) trim(file_get_contents($bidFile)) : 0;
    $reuse = false;
    if ($bID) {
        $b = \Concrete\Core\Block\Block::getByID($bID);
        if (is_object($b) && !$b->isError()) { $reuse = true; out('reusing block bID=' . $bID); }
    }
    if (!$reuse) {
        $data = [
            'exEntityID'   => $entityID,
            'title'        => 'PCB',
            'columns'      => '',
            'filterFields' => '',
            'enableSearch' => 0,
            'rowLimit'     => 10,
            'enablePagination' => 0,
        ];
        $block = $home->addBlock($bt, 'Main', $data);
        $bID = $block->getBlockID();
        file_put_contents($bidFile, (string) $bID);
        out('created block bID=' . $bID);
    }
    // ensure exEntityID persisted on the block record (independent of the save() blanking guard)
    $db = $app->make('database')->connection();
    $db->executeQuery('UPDATE btExpressEntryList SET exEntityID = ? WHERE bID = ?', [$entityID, $bID]);
    out('OK bID=' . $bID . ' entityID=' . $entityID);
} catch (\Throwable $t) {
    out('EXC ' . get_class($t) . ': ' . $t->getMessage());
    out($t->getTraceAsString());
    exit(3);
}
