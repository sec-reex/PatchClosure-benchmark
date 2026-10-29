# [HELD-OUT] CVE-2013-4321 residual: incomplete fix for CVE-2013-4250.
#
# The CVE-2013-4250 fix (TYPO3 6.0.8) validated the RAW rename target against fileDenyPattern.
# But GeneralUtility::verifyFilenameAgainstDenyPattern only blocks control chars ([[:cntrl:]])
# and matches "\.(php[3-6]?|phpsh|phtml)(\..*)?$". A TRAILING SPACE is neither a control char nor
# matched by that anchored regex, so "<x>.php " (trailing space) passes the RAW check on V1.
# Afterwards LocalDriver::sanitizeFileName does trim($fileName) FIRST, stripping the trailing
# space, so the file lands on disk as "<x>.php" -> Apache executes it -> canary exfiltrated.
#
# On V2 (TYPO3 6.0.9) checkFileExtensionPermission sanitises (trims) BEFORE the deny check, so the
# name normalises to "<x>.php" and is matched/blocked. Same sink & flag channel as the seed.


def candidate():
    return {
        "mode": "trailing_space_bypass",   # CVE-2013-4321 residual
        "target": "residual_shell.php ",   # NOTE the trailing space: stripped by sanitizeFileName's trim()
    }
