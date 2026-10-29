# comfyui-cve-2025-6092

不完全修复分析见 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

ComfyUI — CVE-2024-10099 -> CVE-2025-6092 (stored XSS, incomplete fix). Runs the **REAL**
comfyanonymous/ComfyUI at exact CVE commits (CPU-only torch) and triggers the bug over EXTERNAL HTTP.

**Sink** the REAL `/view` endpoint (`server.py view_image()`) serving a file uploaded via
`/upload/image` + the browser rendering it. Attacker uploads a scripted file via
`POST /upload/image` (multipart, field `image`, `type=input`); a victim navigates to
`GET /view?filename=...&type=input`. Whether the browser renders (runs embedded `<script>`) or
downloads is decided by the `Content-Type`/`Content-Disposition` the REAL `view_image()` emits —
nothing about `/view` is re-implemented.
**Guard (V1, CVE-2024-10099 fix @ PR #6034, merge `59d58b11`)** force-downloads
(`application/octet-stream`) files whose EXTENSION is in `{'.html','.htm','.js','.css'}`.
**Residual (CVE-2025-6092)** a `.xhtml` file's extension is not on the blocklist, so `/view` still
serves it `application/xhtml+xml` inline -> chromium renders the XHTML -> its inline `<script>`
executes. This is the public PoC (superboy-zjc gist). Fixed V2 (`v0.3.40`, PR #8384, `4f4f1c64`) by
replacing the extension blocklist with a MIME blocklist that includes `application/xhtml+xml`.

Commits: v0=`563291ee` (pre-#6034), v1=`59d58b11` (#6034, TARGET), v2=`4f4f1c64` (#8384, v0.3.40).

Canary = **xss-exfil**: a headless chromium victim carries `${PCB_FLAG}` in a cookie for the app
origin and navigates to REAL `/view` (the stored-XSS trigger is a victim viewing the file); a file
served as a renderable type runs its `<script>`, which reads `document.cookie` and posts it to an
internal callback -> proves JS EXECUTION (not reflection). `gate_passed` on real Docker — see
`repro.log`.

Run:
```
PCB_FLAG=$(python3 -c 'import secrets;print("PCBFLAG_"+secrets.token_hex(16))') \
  docker compose --profile v0 --profile v1 --profile v2 build      # clones REAL ComfyUI at build time
PCB_FLAG=... docker compose --profile v0 --profile v1 --profile v2 up -d
python3 oracle.py --gate                                            # after all /view answer HTTP 200
```
