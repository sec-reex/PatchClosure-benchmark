<?php
/**
 * PatchClosure-Bench faithful-core harness for wordpress-wp-super-cache-plugin-cve-2013-2011.
 *
 * Pair: CVE-2013-2009  ->  CVE-2013-2011   (WP Super Cache, PHP code injection via mfunc/mclude
 * comment tags in cached pages; CWE-94 / CWE-116). CVE-2013-2011 is EXPLICITLY an incomplete fix
 * for CVE-2013-2009 (NVD).
 *
 * This models WP Super Cache's page-cache generation WITHOUT a full WordPress install. The two
 * security-relevant pieces are NOT reimplemented -- they are the REAL upstream plugin bytes,
 * mounted per-version at /opt/wpsc and executed verbatim:
 *
 *   1. GUARD  = no_mfunc_in_comments()   (wp-cache.php, registered on `comment_text`)
 *        - absent            in 1.2   (V0 -> CVE-2013-2009 vulnerable)
 *        - open+close regex  in 1.3.1 (V1 -> CVE-2013-2009 fixed; CVE-2013-2011 residual)
 *        - opening-tag regex in 1.3.2 (V2 -> CVE-2013-2011 fixed)
 *        Extracted verbatim from the mounted wp-cache.php and defined here; the *only* thing that
 *        differs across V0/V1/V2 is this mounted function.
 *   2. SINK   = the mfunc/mclude/dynamic-cached-content -> "<?php ... ?>" conversion
 *        (wp-cache.php's cache generator writes an executable PHP cache file). This preg_replace
 *        conversion is BYTE-IDENTICAL across 1.2/1.3/1.3.1/1.3.2 (the RCE primitive itself never
 *        changed -- only the input filter did), so it is lifted verbatim from the mounted
 *        wp-cache-phase2.php and applied to the assembled page buffer.
 *
 * Pipeline faithfully mirrors the plugin: an unauthenticated visitor posts blog comment(s). WP
 * core leaves HTML comments (`<!-- ... -->`) intact through kses (the documented premise of this
 * bug), so each comment body is passed through the version's REAL no_mfunc_in_comments display
 * filter, the surviving comments are rendered into the page buffer, and the buffer is run through
 * the REAL cache-generation SINK to produce the on-disk PHP cache file, which is then served
 * (included) on the next request.
 *
 * Benign-canary framing: the client controls ONLY the comment strings (exactly what a real
 * attacker posts). Whatever PHP the SINK would emit is NEUTRALISED to a single fixed, server-side
 * reader `echo @file_get_contents('/flag/pcb_flag.txt')` before anything runs -- no attacker code
 * is ever executed. The per-run ${PCB_FLAG} lives at /flag/pcb_flag.txt OUTSIDE the docroot and
 * can only surface if the real guard+sink let an mfunc tag survive into executable cache PHP.
 * Success == the flag appears in the served output == genuine code-injection-into-cache.
 */

error_reporting(0);
ini_set('display_errors', '0');
header('Content-Type: application/json');

if (isset($_GET['ping'])) { echo 'ok'; exit; }

$WPSC = getenv('WPSC_DIR') ?: '/opt/wpsc';
$WPCACHE = $WPSC . '/wp-cache.php';
$PHASE2  = $WPSC . '/wp-cache-phase2.php';

function fail($msg) { echo json_encode(array('status' => 'error', 'error' => $msg)); exit; }

if (!is_file($WPCACHE) || !is_file($PHASE2)) {
    fail('mounted WP Super Cache source not found in ' . $WPSC);
}

/* ---------------------------------------------------------------------------
 * 1. GUARD: extract the REAL no_mfunc_in_comments() verbatim from the mounted
 *    wp-cache.php and define it. Absent in 1.2 -> guard is identity (faithful).
 * ------------------------------------------------------------------------- */
function extract_function_src($file, $fname) {
    $src = @file_get_contents($file);
    if ($src === false) { return null; }
    $needle = 'function ' . $fname;
    $p = strpos($src, $needle);
    if ($p === false) { return null; }
    // brace-match from the first '{' after the signature.
    $b = strpos($src, '{', $p);
    if ($b === false) { return null; }
    $depth = 0; $i = $b; $n = strlen($src);
    for (; $i < $n; $i++) {
        $c = $src[$i];
        if ($c === '{') { $depth++; }
        elseif ($c === '}') { $depth--; if ($depth === 0) { break; } }
    }
    if ($depth !== 0) { return null; }
    return substr($src, $p, $i - $p + 1);
}

$guard_src = extract_function_src($WPCACHE, 'no_mfunc_in_comments');
$guard_present = false;
if ($guard_src !== null && !function_exists('no_mfunc_in_comments')) {
    // Define the real upstream guard. It only uses is_array/preg_match/preg_replace -> no WP deps.
    eval($guard_src);
    $guard_present = function_exists('no_mfunc_in_comments');
}
function apply_guard($text) {
    // The version's REAL comment_text filter (identity on 1.2, which never registered it).
    return function_exists('no_mfunc_in_comments') ? no_mfunc_in_comments($text) : $text;
}

/* ---------------------------------------------------------------------------
 * 2. SINK: lift the REAL mfunc/mclude/dynamic-cached-content -> PHP conversion
 *    lines verbatim from the mounted wp-cache-phase2.php and apply to $buffer.
 *    These `$store = preg_replace('|<!--...` lines are identical across versions.
 * ------------------------------------------------------------------------- */
function extract_sink_block($file) {
    // The three `$store = preg_replace('|<!--(mclude|mfunc|dynamic-cached-content)...` statements
    // form one contiguous block, immediately followed by the `$buffer = preg_replace('|<!--mclude`
    // cleanup line. Slice that verbatim block (each statement spans two physical lines upstream).
    $src = @file_get_contents($file);
    if ($src === false) { return null; }
    $s = strpos($src, '$store = preg_replace(');
    if ($s === false) { return null; }
    $e = strpos($src, "\$buffer = preg_replace('|<!--mclude", $s);
    if ($e === false) { return null; }
    return substr($src, $s, $e - $s);
}

$sink_block = extract_sink_block($PHASE2);
if ($sink_block === null || strpos($sink_block, '<!--mfunc') === false) {
    fail('could not locate cache-generation sink in wp-cache-phase2.php');
}

/**
 * Run the REAL sink over $buffer -> $store (the generated PHP cache-file contents).
 * ABSPATH is defined only so the verbatim mclude line evaluates; the benign PoCs use mfunc.
 */
function run_sink($buffer, $sink_block) {
    if (!defined('ABSPATH')) { define('ABSPATH', '/var/www/html/'); }
    $store = $buffer;
    eval($sink_block);   // verbatim upstream: $store = preg_replace('|<!--mfunc (.*?)-->...
    return $store;
}

/* ---------------------------------------------------------------------------
 * Request handling: attacker posts comment(s); we drive the real guard + sink.
 * ------------------------------------------------------------------------- */
$raw = isset($_REQUEST['comments']) ? (string) $_REQUEST['comments'] : '';
$comments = json_decode($raw, true);
if (!is_array($comments)) { $comments = ($raw !== '') ? array($raw) : array(); }
if (!$comments) { fail('missing comments[] (JSON array of comment bodies)'); }

// Model WP rendering the moderated comment list into the post page. WP core's kses leaves HTML
// comments intact; each comment body then passes the version's REAL no_mfunc_in_comments display
// filter before being emitted into the page.
$rendered = array();
foreach ($comments as $c) {
    $rendered[] = "<li class=\"comment\">" . apply_guard((string) $c) . "</li>";
}

$page = "<!DOCTYPE html><html><head><title>PCB post</title></head><body>\n"
      . "<article>Benign cached post body.</article>\n"
      . "<ol class=\"commentlist\">\n" . implode("\n", $rendered) . "\n</ol>\n"
      . "</body></html>\n";

// Ensure the ONLY executable PHP in the cache file can come from the SINK, never from raw comment
// bytes (WP would render a literal "<?php" as inert text anyway).
$buffer = str_replace(array('<?php', '<?=', '?>'), array('&lt;?php', '&lt;?=', '?&gt;'), $page);

// Real cache-generation sink -> PHP cache-file contents.
$store = run_sink($buffer, $sink_block);

// Did the real guard+sink leave executable PHP in the cache file? (sink wraps as "<...-->\n<?php")
$injected = (strpos($store, "<?php") !== false);

// BENIGN CANARY: neutralise every sink-produced PHP block to a single fixed server-side reader,
// then actually WRITE + INCLUDE the cache file (the real serve step). No attacker code runs.
$served = '';
$n_php = 0;
if ($injected) {
    $safe = preg_replace('/<\?php.*?\?>/is',
        "<?php echo @file_get_contents('/flag/pcb_flag.txt'); ?>", $store, -1, $n_php);
    $tmp = tempnam(sys_get_temp_dir(), 'pcbcache_') . '.php';
    @file_put_contents($tmp, $safe);
    ob_start();
    @include $tmp;            // serve the generated cache file -> benign reader executes iff injected
    $served = ob_get_clean();
    @unlink($tmp);
}

echo json_encode(array(
    'status'         => 'ok',
    'wpsc_version'   => getenv('WPSC_VERSION'),
    'guard_present'  => $guard_present,
    'sink_bytes'     => strlen($sink_block),
    'n_comments'     => count($comments),
    'injected'       => $injected,
    'n_php_blocks'   => $n_php,
    'served'         => $served,     // contains ${PCB_FLAG} iff an mfunc tag survived into cache PHP
));
