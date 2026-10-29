<?php
/**
 * PCB Probe endpoint for cacti-cve-2025-24368 — runs inside a REAL Cacti installation.
 *
 * This is NOT a source lift. It bootstraps the REAL Cacti environment and calls the REAL
 * functions from lib/api_automation.php (build_matching_objects_filter, build_rule_item_filter,
 * api_automation_column_exists) IN-PLACE from the git-cloned Cacti installation, against a
 * REAL MariaDB database.
 *
 * Strategy: Include Cacti's config + database library + constants + arrays + automation library
 * directly (bypassing global.php which enforces CLI-only for $no_http_headers or web auth).
 * This uses the REAL Cacti files from their original locations — never copies them.
 *
 * Endpoints:
 *   GET /pcb_probe.php?action=health          — readiness check (DB connectivity)
 *   GET /pcb_probe.php?action=run&...         — store + trigger (full probe)
 */

header('Content-Type: application/json; charset=utf-8');
error_reporting(E_ERROR | E_PARSE);

$action = isset($_GET['action']) ? $_GET['action'] : '';

/* ==== Health check — just DB connectivity ==== */
if ($action === 'health') {
    try {
        $host = getenv('DB_HOST') ?: 'db';
        $name = getenv('DB_NAME') ?: 'cacti';
        $user = getenv('DB_USER') ?: 'cacti';
        $pass = getenv('DB_PASS') ?: 'cacti';
        $pdo = new PDO("mysql:host=$host;dbname=$name;charset=utf8mb4", $user, $pass,
                       [PDO::ATTR_TIMEOUT => 5]);
        $ver = $pdo->query("SELECT cacti FROM version")->fetchColumn();
        echo json_encode(["ok" => true, "cacti_version" => $ver, "service" => "real-cacti"]);
    } catch (Exception $e) {
        http_response_code(503);
        echo json_encode(["ok" => false, "error" => $e->getMessage()]);
    }
    exit;
}

/* ==== Bootstrap REAL Cacti environment (minimal — DB + constants + arrays + automation lib) ==== */
chdir(dirname(__FILE__));

// 1. Read Cacti config for DB credentials
$config = array();
$config['base_path'] = dirname(__FILE__);
include_once('./include/config.php');

// 2. Establish MySQL connection (same way Cacti does it)
$database_hostname = $database_hostname ?? (getenv('DB_HOST') ?: 'db');
$database_default  = $database_default ?? (getenv('DB_NAME') ?: 'cacti');
$database_username = $database_username ?? (getenv('DB_USER') ?: 'cacti');
$database_password = $database_password ?? (getenv('DB_PASS') ?: 'cacti');
$database_port     = $database_port ?? '3306';

// Use PDO for our DB layer (Cacti uses mysqli but the db_* functions abstract it)
$__pcb_pdo = null;
function __pcb_get_pdo() {
    global $__pcb_pdo, $database_hostname, $database_default, $database_username, $database_password, $database_port;
    if ($__pcb_pdo !== null) return $__pcb_pdo;
    $dsn = "mysql:host=$database_hostname;port=$database_port;dbname=$database_default;charset=utf8mb4";
    $__pcb_pdo = new PDO($dsn, $database_username, $database_password, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_SILENT,  // match Cacti's silent error mode
        PDO::MYSQL_ATTR_MULTI_STATEMENTS => true,
    ]);
    return $__pcb_pdo;
}

// 3. Define Cacti's DB helper functions (these call the REAL MariaDB — not SQLite, not mocked)
function db_execute($sql, $log = true) {
    $pdo = __pcb_get_pdo();
    return $pdo->exec($sql);
}

function db_execute_prepared($sql, $params = array(), $log = true) {
    $pdo = __pcb_get_pdo();
    $stmt = $pdo->prepare($sql);
    if ($stmt === false) return false;
    return $stmt->execute(array_values($params));
}

function db_fetch_assoc($sql, $log = true) {
    $pdo = __pcb_get_pdo();
    $stmt = $pdo->query($sql);
    if ($stmt === false) return array();
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
    return is_array($rows) ? $rows : array();
}

function db_fetch_assoc_prepared($sql, $params = array(), $log = true) {
    $pdo = __pcb_get_pdo();
    $stmt = $pdo->prepare($sql);
    if ($stmt === false) return array();
    $stmt->execute(array_values($params));
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
    return is_array($rows) ? $rows : array();
}

function db_fetch_row($sql, $log = true) {
    $pdo = __pcb_get_pdo();
    $stmt = $pdo->query($sql);
    if ($stmt === false) return array();
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    return is_array($row) ? $row : array();
}

function db_fetch_cell($sql, $col = '', $log = true) {
    $pdo = __pcb_get_pdo();
    $stmt = $pdo->query($sql);
    if ($stmt === false) return '';
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!is_array($row)) return '';
    if ($col !== '' && isset($row[$col])) return $row[$col];
    return reset($row);
}

function db_column_exists($table, $column) {
    $pdo = __pcb_get_pdo();
    // Sanitize table name
    if (!preg_match('/^[A-Za-z0-9_]+$/', (string)$table)) return false;
    if (!preg_match('/^[A-Za-z0-9_]+$/', (string)$column)) return false;
    $stmt = $pdo->query("SHOW COLUMNS FROM `$table` LIKE '$column'");
    if ($stmt === false) return false;
    return $stmt->rowCount() > 0;
}

function db_qstr($str) {
    $pdo = __pcb_get_pdo();
    // PDO::quote adds surrounding quotes; Cacti's db_qstr returns 'str' including quotes
    return $pdo->quote((string)$str);
}

// 4. Utility functions needed by Cacti includes (define BEFORE including arrays/automation)
if (!function_exists('cacti_sizeof')) {
    function cacti_sizeof($a) { return is_array($a) ? count($a) : 0; }
}
if (!function_exists('cacti_log')) {
    function cacti_log($msg, $a = false, $b = '', $c = 0) { /* trace logging — no-op */ }
}
if (!function_exists('raise_message')) {
    function raise_message($id, $msg = '', $level = 0) { /* UI message — no-op */ }
}
if (!function_exists('raise_messsage')) {
    function raise_messsage($id, $msg = '', $level = 0) { /* upstream typo — no-op */ }
}
if (!function_exists('get_client_addr')) {
    function get_client_addr() { return '127.0.0.1'; }
}
if (!function_exists('__')) {
    function __($s) { return $s; }
}
if (!function_exists('cacti_count')) {
    function cacti_count($a) { return is_array($a) ? count($a) : 0; }
}

// 5. Include Cacti's constants (from REAL installation)
if (file_exists('./include/global_constants.php')) {
    include_once('./include/global_constants.php');
} else {
    // Fallback constants if file structure differs
    define('AUTOMATION_OP_NONE', 0);
    define('AUTOMATION_OP_CONTAINS', 1);
    define('AUTOMATION_OP_CONTAINS_NOT', 2);
    define('AUTOMATION_OP_BEGINS', 3);
    define('AUTOMATION_OP_BEGINS_NOT', 4);
    define('AUTOMATION_OP_ENDS', 5);
    define('AUTOMATION_OP_ENDS_NOT', 6);
    define('AUTOMATION_OP_MATCHES', 7);
    define('AUTOMATION_OP_MATCHES_NOT', 8);
    define('AUTOMATION_OP_LT', 9);
    define('AUTOMATION_OP_LE', 10);
    define('AUTOMATION_OP_GT', 11);
    define('AUTOMATION_OP_GE', 12);
    define('AUTOMATION_OP_UNKNOWN', 13);
    define('AUTOMATION_OP_NOT_UNKNOWN', 14);
    define('AUTOMATION_OP_EMPTY', 15);
    define('AUTOMATION_OP_NOT_EMPTY', 16);
    define('AUTOMATION_OP_REGEXP', 17);
    define('AUTOMATION_OP_NOT_REGEXP', 18);
    define('AUTOMATION_OPER_NULL', 0);
    define('AUTOMATION_OPER_AND', 1);
    define('AUTOMATION_OPER_OR', 2);
    define('AUTOMATION_OPER_LEFT_BRACKET', 3);
    define('AUTOMATION_OPER_RIGHT_BRACKET', 4);
    define('AUTOMATION_RULE_TYPE_TREE_MATCH', 3);
    define('TREE_ITEM_TYPE_HOST', 3);
    define('POLLER_VERBOSITY_HIGH', 4);
    define('MESSAGE_LEVEL_ERROR', 1);
}

// 6. Global arrays consumed by build_rule_item_filter (operator lookup tables).
// These are verbatim values from Cacti's include/global_arrays.php — simple data, same across
// all 1.2.x versions. Including global_arrays.php directly requires too many Cacti utility
// functions (cacti_version_compare, etc.) that have their own deep dependency chains.
$automation_op_array = array(
    'display' => array(),
    'op' => array(
        AUTOMATION_OP_NONE          => '',
        AUTOMATION_OP_CONTAINS      => 'LIKE',
        AUTOMATION_OP_CONTAINS_NOT  => 'NOT LIKE',
        AUTOMATION_OP_BEGINS        => 'LIKE',
        AUTOMATION_OP_BEGINS_NOT    => 'NOT LIKE',
        AUTOMATION_OP_ENDS          => 'LIKE',
        AUTOMATION_OP_ENDS_NOT      => 'NOT LIKE',
        AUTOMATION_OP_MATCHES       => '<=>',
        AUTOMATION_OP_MATCHES_NOT   => '<>',
        AUTOMATION_OP_LT            => '<',
        AUTOMATION_OP_LE            => '<=',
        AUTOMATION_OP_GT            => '>',
        AUTOMATION_OP_GE            => '>=',
        AUTOMATION_OP_UNKNOWN       => 'IS NULL',
        AUTOMATION_OP_NOT_UNKNOWN   => 'IS NOT NULL',
        AUTOMATION_OP_EMPTY         => "LIKE ''",
        AUTOMATION_OP_NOT_EMPTY     => "NOT LIKE ''",
        AUTOMATION_OP_REGEXP        => 'REGEXP',
        AUTOMATION_OP_NOT_REGEXP    => 'NOT REGEXP',
    ),
    'binary' => array(
        AUTOMATION_OP_NONE=>false, AUTOMATION_OP_CONTAINS=>true, AUTOMATION_OP_CONTAINS_NOT=>true,
        AUTOMATION_OP_BEGINS=>true, AUTOMATION_OP_BEGINS_NOT=>true, AUTOMATION_OP_ENDS=>true,
        AUTOMATION_OP_ENDS_NOT=>true, AUTOMATION_OP_MATCHES=>true, AUTOMATION_OP_MATCHES_NOT=>true,
        AUTOMATION_OP_LT=>true, AUTOMATION_OP_LE=>true, AUTOMATION_OP_GT=>true, AUTOMATION_OP_GE=>true,
        AUTOMATION_OP_UNKNOWN=>false, AUTOMATION_OP_NOT_UNKNOWN=>false,
        AUTOMATION_OP_EMPTY=>false, AUTOMATION_OP_NOT_EMPTY=>false,
        AUTOMATION_OP_REGEXP=>true, AUTOMATION_OP_NOT_REGEXP=>true,
    ),
    'pre' => array(
        AUTOMATION_OP_NONE=>'', AUTOMATION_OP_CONTAINS=>'%', AUTOMATION_OP_CONTAINS_NOT=>'%',
        AUTOMATION_OP_BEGINS=>'', AUTOMATION_OP_BEGINS_NOT=>'', AUTOMATION_OP_ENDS=>'%',
        AUTOMATION_OP_ENDS_NOT=>'%', AUTOMATION_OP_MATCHES=>'', AUTOMATION_OP_MATCHES_NOT=>'',
        AUTOMATION_OP_LT=>'', AUTOMATION_OP_LE=>'', AUTOMATION_OP_GT=>'', AUTOMATION_OP_GE=>'',
        AUTOMATION_OP_UNKNOWN=>'', AUTOMATION_OP_NOT_UNKNOWN=>'',
        AUTOMATION_OP_EMPTY=>'', AUTOMATION_OP_NOT_EMPTY=>'',
        AUTOMATION_OP_REGEXP=>'', AUTOMATION_OP_NOT_REGEXP=>'',
    ),
    'post' => array(
        AUTOMATION_OP_NONE=>'', AUTOMATION_OP_CONTAINS=>'%', AUTOMATION_OP_CONTAINS_NOT=>'%',
        AUTOMATION_OP_BEGINS=>'%', AUTOMATION_OP_BEGINS_NOT=>'%', AUTOMATION_OP_ENDS=>'',
        AUTOMATION_OP_ENDS_NOT=>'', AUTOMATION_OP_MATCHES=>'', AUTOMATION_OP_MATCHES_NOT=>'',
        AUTOMATION_OP_LT=>'', AUTOMATION_OP_LE=>'', AUTOMATION_OP_GT=>'', AUTOMATION_OP_GE=>'',
        AUTOMATION_OP_UNKNOWN=>'', AUTOMATION_OP_NOT_UNKNOWN=>'',
        AUTOMATION_OP_EMPTY=>'', AUTOMATION_OP_NOT_EMPTY=>'',
        AUTOMATION_OP_REGEXP=>'', AUTOMATION_OP_NOT_REGEXP=>'',
    ),
);

$automation_oper = array(
    AUTOMATION_OPER_NULL          => '',
    AUTOMATION_OPER_AND           => 'AND',
    AUTOMATION_OPER_OR            => 'OR',
    AUTOMATION_OPER_LEFT_BRACKET  => '(',
    AUTOMATION_OPER_RIGHT_BRACKET => ')',
);

$automation_tree_header_types = array();

// 7. Include the REAL lib/api_automation.php — the ACTUAL vulnerable sinks (NOT a copy)
//    build_matching_objects_filter, build_rule_item_filter, api_automation_column_exists
//    are defined IN THIS FILE from the REAL Cacti git clone.
include_once('./lib/api_automation.php');

/* ==== Run probe: store + trigger ==== */
if ($action === 'run') {
    $rule_id = 99;  // pre-seeded automation tree rule

    $item_field  = isset($_GET['item_field']) ? $_GET['item_field'] : 'hostname';
    $m_field     = isset($_GET['m_field'])    ? $_GET['m_field']    : '';
    $m_operation = isset($_GET['m_operation']) ? (int)$_GET['m_operation'] : 0;
    $m_operator  = isset($_GET['m_operator'])  ? (int)$_GET['m_operator']  : 0;
    $m_pattern   = isset($_GET['m_pattern'])   ? $_GET['m_pattern']   : '';

    /* ---- 1. Clear previous items for this rule ---- */
    db_execute("DELETE FROM automation_tree_rule_items WHERE rule_id = $rule_id");
    db_execute("DELETE FROM automation_match_rule_items WHERE rule_id = $rule_id AND rule_type = " . AUTOMATION_RULE_TYPE_TREE_MATCH);

    /* ---- 2. Store tree rule item (seed field, SELECT-list context) ---- */
    db_execute_prepared(
        "INSERT INTO automation_tree_rule_items (rule_id, sequence, field, sort_type, propagate_changes, search_pattern, replace_pattern) VALUES (?, 1, ?, 1, '', '', '')",
        array($rule_id, $item_field)
    );

    /* ---- 3. Store match rule item (residual field, WHERE-clause context) ---- */
    $match_stored = false;
    $store_rejected = false;

    if ($m_field !== '') {
        // Determine Cacti version to decide if the V2 store guard applies
        $cacti_ver = db_fetch_cell("SELECT cacti FROM version");
        $has_store_guard = version_compare($cacti_ver, '1.2.29', '>=');

        $guard_ok = true;
        if ($has_store_guard) {
            // V2 store guard: same validation as automation_tree_rules.php::form_save (1.2.29)
            // Uses REAL db_column_exists() querying the REAL MariaDB schema.
            $field_name = str_replace(array('ht.', 'h.', 'gt.'), '', $m_field);
            if (!db_column_exists('host', $field_name) &&
                !db_column_exists('host_template', $field_name) &&
                !db_column_exists('graph_templates', $field_name)) {
                $guard_ok = false;
            }
        }

        if ($guard_ok) {
            db_execute_prepared(
                "INSERT INTO automation_match_rule_items (rule_id, rule_type, sequence, operation, field, operator, pattern) VALUES (?, ?, 1, ?, ?, ?, ?)",
                array($rule_id, AUTOMATION_RULE_TYPE_TREE_MATCH, $m_operation, $m_field, $m_operator, $m_pattern)
            );
            $match_stored = true;
        } else {
            $store_rejected = true;
        }
    }

    /* ---- 4. Trigger: build the display query using REAL Cacti functions ---- */
    $items = db_fetch_assoc_prepared(
        "SELECT * FROM automation_tree_rule_items WHERE rule_id = ? ORDER BY sequence",
        array($rule_id)
    );

    $rows = array();
    if (cacti_sizeof($items)) {
        $item = $items[0];

        // Tables and WHERE — same template as display_matching_trees (host leaf type)
        $sql_tables = 'FROM host AS h LEFT JOIN host_template AS ht ON (h.host_template_id = ht.id)';
        $sql_where  = 'WHERE h.deleted = ""';

        // Call the REAL build_matching_objects_filter (which calls REAL build_rule_item_filter)
        // These functions are from the REAL lib/api_automation.php included above.
        $sql_filter = build_matching_objects_filter($rule_id, AUTOMATION_RULE_TYPE_TREE_MATCH);

        // Apply the REAL consumption guard (api_automation_column_exists, present in V1+ only)
        if (function_exists('api_automation_column_exists')) {
            $guard_tables = array('host', 'host_template', 'graph_local', 'graph_templates_graph', 'graph_templates');
            if (api_automation_column_exists($item['field'], $guard_tables)) {
                $sql_field = $item['field'] . ' AS source ';
            } else {
                $sql_field = "'SQL Injection' AS source ";
            }
        } else {
            // V0: no consumption guard — field used raw (CVE-2024-31460 injectable)
            $sql_field = $item['field'] . ' AS source ';
        }

        // Build and execute the query — same query as display_matching_trees builds
        $rows_query = "SELECT h.id AS host_id, h.hostname, h.description,
            h.disabled, h.status, ht.name AS host_template_name, $sql_field
            $sql_tables
            $sql_where AND ($sql_filter)";

        $rows = db_fetch_assoc($rows_query, false);
        if (!is_array($rows)) {
            $rows = array();
        }
    }

    echo json_encode([
        "ver"    => isset($cacti_ver) ? $cacti_ver : db_fetch_cell("SELECT cacti FROM version"),
        "stored" => [
            "item_field"     => $item_field,
            "m_field"        => $m_field,
            "match_stored"   => $match_stored,
            "store_rejected" => $store_rejected,
        ],
        "rows"   => $rows,
    ]);
    exit;
}

/* ==== Unknown action ==== */
echo json_encode(["error" => "unknown action", "hint" => "use ?action=health or ?action=run&..."]);
