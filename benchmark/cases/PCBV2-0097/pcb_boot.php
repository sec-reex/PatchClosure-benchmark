<?php
/**
 * Shared bootstrap of the REAL Concrete CMS application (no source-lift, no re-implementation).
 * Mirrors concrete/dispatcher.php up to (but not including) the HTTP runtime, so we obtain the real
 * booted \Concrete\Core\Application\Application $app (real config, real DB connection, real container,
 * real Doctrine EntityManager, real block framework). Used by both the CLI seeder (pcb_seed.php) and
 * the HTTP driver (pcb_driver.php). This is the same bootstrap the real app runs on every request.
 */
if (!defined('PCB_DIR_BASE')) {
    define('PCB_DIR_BASE', '/app');
}
chdir(PCB_DIR_BASE);
// Concrete derives DIR_BASE from dirname($_SERVER['SCRIPT_FILENAME']); when this bootstrap is required
// from a CLI seeder living under /work that would wrongly resolve to /work. Pin it to the real webroot.
$_SERVER['SCRIPT_FILENAME'] = PCB_DIR_BASE . '/index.php';
defined('DIR_BASE') or define('DIR_BASE', PCB_DIR_BASE);

require PCB_DIR_BASE . '/concrete/bootstrap/configure.php';
require PCB_DIR_BASE . '/concrete/bootstrap/autoload.php';
/** @var \Concrete\Core\Application\Application $app */
$app = require PCB_DIR_BASE . '/concrete/bootstrap/start.php';

return $app;
