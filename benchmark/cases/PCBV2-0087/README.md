# camaleon-cms-cve-2026-1776

Incomplete-fix pair on **Camaleon CMS** (Ruby on Rails CMS):
**CVE-2024-46987** (original) -> **CVE-2026-1776** (residual, AWS S3 storage backend).

`download_private_file` path traversal. CVE-2024-46987's fix (2.8.1) added a `..` guard to the
**LocalUploader** only; the **AwsUploader** (`filesystem_type='s3'`) was left unguarded, so S3-backed
deployments stayed traversable = CVE-2026-1776, fixed in 2.9.2 (PR #1127, `valid_folder_path?`).

## Layout
- `docker-compose.yml` — minio + 4 real Camaleon apps (2.8.0 local, 2.8.1 local, 2.8.1 s3, 2.9.2 s3)
- `Dockerfile` / `entrypoint.sh` / `seed.rb` / `aws_minio.rb` — real gem-pinned Camaleon per version
- `oracle.py` — flag differential oracle (low-priv user, external HTTP)
- `original_poc.py` — [GIVEN] CVE-2024-46987 local-uploader traversal
- `_heldout/bypass_poc.py` — [HELD OUT] CVE-2026-1776 S3-uploader residual (same payload, s3 backend)
- `_heldout/bypass_fix.diff` — [HELD OUT] the CVE-2026-1776 fix (AwsUploader `valid_folder_path?`)
- `patch.diff` — [GIVEN] the CVE-2024-46987 fix (LocalUploader `..` guard)
- `case.json` / `repro.log`

## Run the gate
```bash
export PCB_FLAG="PCBFLAG_$(openssl rand -hex 12)"
docker compose up -d --build
python3 oracle.py --wait     # or --gate once all 4 apps answer /admin/login
docker compose down -v --rmi all
```
Gate (real Docker, 2026-07-17): all 4 booleans true, `passed`.

不完全修复分析见 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。
