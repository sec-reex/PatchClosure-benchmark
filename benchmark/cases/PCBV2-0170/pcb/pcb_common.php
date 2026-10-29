<?php
// Harness bootstrap shim (NOT phpMyFAQ business code).
// Boots the REAL phpMyFAQ runtime (Bootstrap.php) so the seed/reset helpers can use phpMyFAQ's
// own User / Configuration / Auth APIs against the installed database. Exposes $faqConfig, $db.
if (!defined('IS_VALID_PHPMYFAQ')) {
    define('IS_VALID_PHPMYFAQ', null);
}
require '/opt/phpmyfaq-src/phpmyfaq/src/Bootstrap.php';
// After this require, $faqConfig (phpMyFAQ\Configuration) and $db are in scope.
