<?php
// Minimal PHP-Nuke sql_db class (db/db.php) — the database abstraction layer.
// This is PHP-Nuke infrastructure that NukeSentinel depends on.
// Provides: sql_query, sql_numrows, sql_fetchrow, sql_freeresult.

class sql_db {
    var $db_connect_id;

    function sql_db($server, $user, $password, $database) {
        $this->db_connect_id = @mysql_connect($server, $user, $password);
        if ($this->db_connect_id) {
            @mysql_select_db($database, $this->db_connect_id);
        }
    }

    function sql_query($query) {
        if (!$this->db_connect_id) return false;
        $result = @mysql_query($query, $this->db_connect_id);
        return $result;
    }

    function sql_numrows($result) {
        if (!$result) return 0;
        return @mysql_num_rows($result);
    }

    function sql_fetchrow($result) {
        if (!$result) return false;
        $row = @mysql_fetch_array($result, MYSQL_BOTH);
        return $row;
    }

    function sql_freeresult($result) {
        if ($result) @mysql_free_result($result);
    }
}

// Create the global $db connection (as PHP-Nuke's mainfile.php does)
global $dbhost, $dbuname, $dbpass, $dbname;
$db = new sql_db($dbhost, $dbuname, $dbpass, $dbname);
