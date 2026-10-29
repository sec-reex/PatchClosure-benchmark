# [GIVEN] CVE-2013-4250 seed: the original file-rename PHP-execution vector.
#
# The editor uploads a benign file and renames it directly to "<x>.php". On V0 (TYPO3 6.0.4,
# pre-fix) renameFile performs NO extension check, so the file lands as .php and Apache executes
# it -> the canary is exfiltrated. On V1 (TYPO3 6.0.8, CVE-2013-4250 patched) the rename target
# is checked against fileDenyPattern on the RAW name "<x>.php", which matches -> BLOCKED (no flag).
#
# candidate schema: {"mode","target"} consumed by oracle.run_probe.


def candidate():
    return {
        "mode": "direct_php_rename",   # CVE-2013-4250 seed
        "target": "seed_shell.php",    # plain denied extension; blocked once the deny check exists
    }


if __name__ == "__main__":
    # 平台约定：stdout 输出 JSON candidate（verify.sh 捕获；VERSION 参数仅占位，保持原调用签名）。
    import json
    import sys
    _ = sys.argv  # original_poc.py <version> — 忽略版本号，candidate 与版本无关
    print(json.dumps(candidate()))
