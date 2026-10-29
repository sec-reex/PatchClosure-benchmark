<?php
/**
 * SQL-only fallback for creating the required tables and records
 * when the Pimcore API-based setup fails.
 *
 * Creates: classes record, object_1/object_brick_query_bundledata_1 tables,
 * search_backend_data entries, and writes class ID to pcb_class_id.txt.
 */

$host  = getenv('DB_HOST') ?: 'db';
$pass  = getenv('MYSQL_ROOT_PASSWORD') ?: 'pcbroot';
$dbname = getenv('DB_NAME') ?: 'pimcore';

$dsn = "mysql:host=$host;dbname=$dbname;charset=utf8mb4";
$pdo = new PDO($dsn, 'root', $pass, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);

// Determine existing class ID or insert
$stmt = $pdo->query("SELECT id FROM classes WHERE name = 'testclass' LIMIT 1");
$row = $stmt->fetch(PDO::FETCH_ASSOC);

if ($row) {
    $cid = $row['id'];
    fwrite(STDERR, "[sql-setup] Class 'testclass' already exists with ID $cid.\n");
} else {
    // Insert class record
    $pdo->exec("INSERT INTO classes (name) VALUES ('testclass')");
    $cid = $pdo->lastInsertId();
    fwrite(STDERR, "[sql-setup] Inserted class 'testclass' with ID $cid.\n");
}

// Create object table
$pdo->exec("CREATE TABLE IF NOT EXISTS object_{$cid} (
    o_id INT PRIMARY KEY AUTO_INCREMENT,
    `o_key` VARCHAR(255),
    className VARCHAR(255)
)");
$pdo->exec("INSERT IGNORE INTO object_{$cid} (o_id, `o_key`, className) VALUES (1, 'test-object-1', 'testclass')");

// Create brick query table (10.5 JOIN uses .o_id)
$pdo->exec("CREATE TABLE IF NOT EXISTS object_brick_query_bundledata_{$cid} (
    o_id INT,
    extra VARCHAR(64)
)");
$pdo->exec("INSERT IGNORE INTO object_brick_query_bundledata_{$cid} VALUES (1, 'x')");

// Ensure search_backend_data has at least one entry
try {
    $pdo->exec("INSERT IGNORE INTO search_backend_data (id, fullpath, maintype, type, subtype, published, creationDate, modificationDate, userOwner, userModification, data, properties) VALUES (1, '/test-object-1', 'object', 'object', 'testclass', 1, UNIX_TIMESTAMP(), UNIX_TIMESTAMP(), 1, 1, 'test object', '')");
} catch (Throwable $e) {
    fwrite(STDERR, "[sql-setup] search_backend_data insert: " . $e->getMessage() . "\n");
}

// Write class ID for oracle
file_put_contents('/var/www/html/public/pcb_class_id.txt', (string)$cid);
fwrite(STDERR, "[sql-setup] Setup complete. Class ID = $cid\n");
