<?php
/**
 * PatchClosure-Bench faithful-core harness for drupal-core-cve-2018-7602.
 *
 * Models Drupal's "render-array key starting with '#' is treated as a callable" code-execution
 * class ("Drupalgeddon2" CVE-2018-7600 -> "Drupalgeddon3" CVE-2018-7602) WITHOUT a full Drupal
 * install (DB + user + login + form token). The security decision is NOT reimplemented: it is
 * taken by the REAL upstream Drupal core class shipped in the pinned official image and loaded
 * via Drupal's own Composer autoloader:
 *
 *   \Drupal\Core\Security\RequestSanitizer::sanitize()   (the CVE-2018-7600 guard; V0 absent,
 *                                                          V1 = query/POST/cookie only,
 *                                                          V2 = + checkDestination())
 *   \Drupal\Component\Utility\UrlHelper::parse()          (how a destination string's inner query
 *                                                          is decoded -- the exact fn V2's
 *                                                          checkDestination() uses)
 *   \Symfony\Component\HttpFoundation\Request             (the real request object sanitize() takes)
 *
 * Whether the '#'-prefixed render keys survive sanitisation is decided ENTIRELY by the real
 * RequestSanitizer baked into each image tag, so the V0/V1/V2 differential comes only from the
 * pinned Drupal core. The render-callback SINK (below) is version-invariant and is a faithful
 * minimal model of \Drupal\Core\Render\Renderer's dispatch of '#pre_render'/'#post_render'/
 * '#lazy_builder' callables (Renderer::doCallback) -- exactly the sink both CVEs reach.
 *
 * Benign-canary framing: the "RCE" is demonstrated benignly. The attacker-named callable used by
 * the probes is the ordinary PHP function file_get_contents and the attacker-controlled argument
 * (#markup) is the path of a per-run canary planted at /flag/pcb_flag.txt OUTSIDE the docroot by
 * the entrypoint. NO shell / exec / system / passthru / persistence. Success == the flag token
 * appears in the response, which is only possible if a '#'-callable actually executed on this
 * version (i.e. the sanitizer failed to strip it).
 */

error_reporting(0);
ini_set('display_errors', '0');
header('Content-Type: application/json');

if (isset($_GET['ping'])) { echo 'ok'; exit; }

$AUTOLOAD = '/var/www/html/vendor/autoload.php';
if (!is_file($AUTOLOAD)) { echo json_encode(['status' => 'error', 'error' => 'no autoload']); exit; }
require $AUTOLOAD;

use Symfony\Component\HttpFoundation\Request;
use Drupal\Component\Utility\UrlHelper;

$RS   = 'Drupal\\Core\\Security\\RequestSanitizer';
$UH   = 'Drupal\\Component\\Utility\\UrlHelper';
$FLAG = '/flag/pcb_flag.txt';

/**
 * Faithful minimal model of Drupal's Renderer callback dispatch for the render-array callable
 * properties the RequestSanitizer defends. Version-invariant: it is identical across 8.5.0/1/3.
 * Given a render array, any '#pre_render'/'#post_render' entry is invoked as a callable on the
 * markup, and '#lazy_builder' as [callable, args] -- exactly the arbitrary-callable sink of the
 * Drupalgeddon vulnerability class. (Benign here: the probes only ever name file_get_contents.)
 */
function pcb_render_sink(array $el) {
    $markup = isset($el['#markup']) ? (string) $el['#markup'] : '';
    if (!empty($el['#lazy_builder']) && is_array($el['#lazy_builder'])) {
        $lb = $el['#lazy_builder'];
        $callable = $lb[0];
        $args = isset($lb[1]) ? (array) $lb[1] : [$markup];
        $markup = (string) call_user_func_array($callable, $args);
    }
    foreach (['#pre_render', '#post_render'] as $prop) {
        if (!empty($el[$prop])) {
            foreach ((array) $el[$prop] as $callable) {
                $markup = (string) call_user_func($callable, $markup);
            }
        }
    }
    return $markup;
}

/** Collect the '#'-prefixed render keys from a decoded parameter array. */
function pcb_collect_render_keys(array $params) {
    $render = [];
    foreach ($params as $k => $v) {
        if ($k !== '' && $k[0] === '#') { $render[$k] = $v; }
    }
    return $render;
}

// ---- 1. Build the REAL request object the guard expects, from the actual HTTP input. ----
$request = Request::createFromGlobals();

// ---- 2. Run this VERSION's REAL guard (absent on V0). Drupal calls it with the default empty
//         whitelist: RequestSanitizer::sanitize($request, Settings::get('sanitize_input_whitelist', [])). ----
$sanitizer_present = class_exists($RS);
if ($sanitizer_present) {
    call_user_func([$RS, 'sanitize'], $request, []); // default whitelist = []
}

// ---- 3. Assemble the render array from whatever survived, over the two real attack channels. ----
$render = [];
// Channel A -- top-level query '#'-keys  (Drupalgeddon2 / CVE-2018-7600 seed channel).
$render = array_merge($render, pcb_collect_render_keys($request->query->all()));
// Channel B -- '#'-keys smuggled inside the 'destination' parameter's query string
//              (Drupalgeddon3 / CVE-2018-7602 residual channel). Decoded with the SAME UrlHelper
//              that V2's checkDestination() inspects. On V1 sanitize() never looks inside a string
//              value, so these survive; on V2 checkDestination() removes the whole destination.
$dest = $request->query->get('destination');
$dest_seen = is_string($dest) && $dest !== '';
if ($dest_seen && class_exists($UH)) {
    $parts = UrlHelper::parse($dest);
    if (!empty($parts['query']) && is_array($parts['query'])) {
        $render = array_merge($render, pcb_collect_render_keys($parts['query']));
    }
}

// ---- 4. The version-invariant render sink executes any surviving '#'-callable. ----
$rendered = pcb_render_sink($render);

echo json_encode([
    'status'            => 'ok',
    'drupal_tag'        => getenv('DRUPAL_TAG'),
    'sanitizer_present' => $sanitizer_present,
    'destination_survived_sanitize' => is_string($request->query->get('destination')),
    'render_keys'       => array_keys($render),
    'rendered'          => $rendered,   // contains the canary iff a '#'-callable executed
]);
