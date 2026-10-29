<?php
namespace app;

/**
 * BENIGN benchmark canary class -- stands in for a "dangerous" attacker-chosen class
 * in a PHP object-injection / class-resolver bypass. It is NOT a yii\base\Behavior
 * subclass, so Yii 2's post-CVE-2024-4990 behavior type-allowlist is supposed to refuse
 * to instantiate it via the `as <name>` sink.
 *
 * Its ONLY effect is to prove instantiation: the constructor READS the planted per-run
 * canary file (/canary/flag.txt, populated from env PCB_FLAG at container start) and echoes
 * it. If the token surfaces in the HTTP response, the object-injection sink instantiated an
 * arbitrary (non-Behavior) class == the type check was bypassed. No POP gadget chain, no
 * command execution, no network.
 */
class PcbFlagProbe
{
    public function __construct()
    {
        $flag = '';
        if (is_file('/canary/flag.txt')) {
            $flag = trim(@file_get_contents('/canary/flag.txt'));
        }
        if ($flag === '') {
            $flag = (string) getenv('PCB_FLAG');
        }
        echo "PCB_LEAKED " . $flag . "\n";
    }
}
