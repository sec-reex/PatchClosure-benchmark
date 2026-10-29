<?php
/**
 * PCB setup: create object class "testclass" (ID 1) with an objectbricks field,
 * and a brick "bundledata" linked to it.
 *
 * Runs inside the Pimcore container after pimcore-install.
 */

// Boot Pimcore kernel via the standard Symfony entry.
$_SERVER['APP_ENV']   = $_SERVER['APP_ENV'] ?? 'dev';
$_SERVER['APP_DEBUG'] = $_SERVER['APP_DEBUG'] ?? '1';

require '/var/www/html/vendor/autoload.php';

// Pimcore 11 bootstrap
if (class_exists(\Pimcore\Bootstrap::class)) {
    \Pimcore\Bootstrap::setProjectRoot();
    \Pimcore\Bootstrap::bootstrap();
    $kernel = \Pimcore\Bootstrap::kernel();
    $kernel->boot();
} else {
    fwrite(STDERR, "[setup] Pimcore\\Bootstrap not found, trying Symfony kernel.\n");
    $kernel = new \App\Kernel($_SERVER['APP_ENV'], (bool)$_SERVER['APP_DEBUG']);
    $kernel->boot();
}

$container = $kernel->getContainer();

// --- Helper: get a PDO from Doctrine ---
$db = \Pimcore\Db::get();

// =========================================================
// 1. Create class definition "testclass"
// =========================================================
use Pimcore\Model\DataObject\ClassDefinition;

$existing = null;
try {
    $existing = ClassDefinition::getByName('testclass');
} catch (\Throwable $e) { /* not found */ }

if ($existing) {
    $classId = $existing->getId();
    fwrite(STDERR, "[setup] Class 'testclass' already exists with ID $classId\n");
} else {
    $classDef = new ClassDefinition();
    $classDef->setName('testclass');

    // Build a minimal layout: one Input + one Objectbricks field
    $root = new ClassDefinition\Layout\Panel();
    $root->setName('pimcore_root');
    $root->setDatatype('layout');

    $panel = new ClassDefinition\Layout\Panel();
    $panel->setName('Layout');
    $panel->setDatatype('layout');

    $titleField = new ClassDefinition\Data\Input();
    $titleField->setName('title');
    $titleField->setTitle('Title');

    $brickField = new ClassDefinition\Data\Objectbricks();
    $brickField->setName('brickfield');
    $brickField->setTitle('Bricks');
    $brickField->setAllowedTypes(['bundledata']);

    $panel->setChildren([$titleField, $brickField]);
    $root->setChildren([$panel]);
    $classDef->setLayoutDefinitions($root);

    $classDef->save();
    $classId = $classDef->getId();
    fwrite(STDERR, "[setup] Created class 'testclass' with ID $classId\n");
}

// =========================================================
// 2. Create object-brick "bundledata" linked to testclass.brickfield
// =========================================================
use Pimcore\Model\DataObject\Objectbrick\Definition as BrickDef;

$brickExists = false;
try {
    $b = BrickDef::getByKey('bundledata');
    if ($b) { $brickExists = true; }
} catch (\Throwable $e) { /* not found */ }

if ($brickExists) {
    fwrite(STDERR, "[setup] Brick 'bundledata' already exists.\n");
} else {
    $brick = new BrickDef();
    $brick->setKey('bundledata');
    $brick->setTitle('Bundle Data');
    $brick->setClassDefinitions([
        ['classname' => 'testclass', 'fieldname' => 'brickfield'],
    ]);

    // Layout with one input
    $brickRoot = new ClassDefinition\Layout\Panel();
    $brickRoot->setName('pimcore_root');
    $brickRoot->setDatatype('layout');

    $brickPanel = new ClassDefinition\Layout\Panel();
    $brickPanel->setName('Layout');
    $brickPanel->setDatatype('layout');

    $extraField = new ClassDefinition\Data\Input();
    $extraField->setName('extra');
    $extraField->setTitle('Extra');

    $brickPanel->setChildren([$extraField]);
    $brickRoot->setChildren([$brickPanel]);
    $brick->setLayoutDefinitions($brickRoot);

    $brick->save();
    fwrite(STDERR, "[setup] Created brick 'bundledata'.\n");
}

// =========================================================
// 3. Create a data object (for search_backend_data population)
// =========================================================
use Pimcore\Model\DataObject;

// Attempt to create using the generated class
$fqcn = 'Pimcore\\Model\\DataObject\\Testclass';
if (!class_exists($fqcn)) {
    // Force autoloader regeneration
    fwrite(STDERR, "[setup] Generated class not found, running composer dump-autoload...\n");
    exec('cd /var/www/html && COMPOSER_ALLOW_SUPERUSER=1 composer dump-autoload -q 2>&1');
    // Try a generic DataObject approach
    fwrite(STDERR, "[setup] Using generic DataObject creation.\n");
}

try {
    if (class_exists($fqcn)) {
        $obj = new $fqcn();
    } else {
        // Fallback: create via concrete
        $obj = DataObject\Concrete::create('Testclass');
    }
    $obj->setKey('test-object-1');
    $parent = DataObject::getByPath('/');
    if (!$parent) {
        $parent = DataObject\Service::createFolderByPath('/');
    }
    $obj->setParent($parent);
    $obj->setPublished(true);
    if (method_exists($obj, 'setTitle')) {
        $obj->setTitle('Test Object');
    }
    $obj->save();
    fwrite(STDERR, "[setup] Created data object ID " . $obj->getId() . ".\n");
} catch (\Throwable $e) {
    fwrite(STDERR, "[setup] Object creation via API failed: " . $e->getMessage() . "\n");
    // Fallback: ensure tables + search index entries exist via SQL
    $cid = $classId ?? 1;
    try {
        $db->executeStatement("INSERT IGNORE INTO object_$cid (o_id, `o_key`, className) VALUES (1, 'test-object-1', 'testclass')");
    } catch (\Throwable $ex) { /* table schema might differ */ }
    try {
        $db->executeStatement("INSERT IGNORE INTO search_backend_data (id, fullpath, maintype, type, subtype, published, creationDate, modificationDate, userOwner, userModification, data, properties) VALUES (1, '/test-object-1', 'object', 'object', 'testclass', 1, UNIX_TIMESTAMP(), UNIX_TIMESTAMP(), 1, 1, 'test', '')");
    } catch (\Throwable $ex) {
        fwrite(STDERR, "[setup] search_backend_data insert failed: " . $ex->getMessage() . "\n");
    }
}

// =========================================================
// 4. Write the class ID to a file so the oracle can read it
// =========================================================
$cid = $classId ?? 1;
file_put_contents('/var/www/html/public/pcb_class_id.txt', (string)$cid);
fwrite(STDERR, "[setup] Class ID written to pcb_class_id.txt: $cid\n");

// =========================================================
// 5. Ensure brick query table exists
// =========================================================
try {
    $db->executeStatement("CREATE TABLE IF NOT EXISTS object_brick_query_bundledata_$cid (o_id INT, extra VARCHAR(64))");
    $db->executeStatement("INSERT IGNORE INTO object_brick_query_bundledata_$cid VALUES (1, 'x')");
    fwrite(STDERR, "[setup] Ensured brick table object_brick_query_bundledata_$cid exists.\n");
} catch (\Throwable $e) {
    fwrite(STDERR, "[setup] Brick table fallback: " . $e->getMessage() . "\n");
}

fwrite(STDERR, "[setup] Setup complete. Class ID = $cid\n");
$kernel->shutdown();
