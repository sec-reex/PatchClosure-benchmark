<?php
/**
 * BenignMarker — a BENIGN gadget class for PatchClosure-Bench PHAR-deser oracle.
 *
 * When PHP deserialises the PHAR metadata that contains a BenignMarker instance,
 * __wakeup() fires and writes a marker file.  The HTTP service then checks for
 * that marker to decide whether deserialization occurred.
 *
 * This is NOT a real POP-chain / RCE gadget.  It writes a fixed string to a
 * predetermined path — no shell commands, no network calls, no file exfiltration.
 */

class BenignMarker
{
    /** @var string  Path where the marker is written on wakeup. */
    public $marker_path = '/tmp/pcb_marker.txt';

    /** @var string  Sentinel written to the marker file. */
    public $sentinel = 'PHAR_DESERIALIZED';

    public function __wakeup()
    {
        @file_put_contents($this->marker_path, $this->sentinel);
    }

    public function __destruct()
    {
        // Belt-and-suspenders: also fire on destruct in case __wakeup is skipped.
        if (!file_exists($this->marker_path)) {
            @file_put_contents($this->marker_path, $this->sentinel);
        }
    }
}
