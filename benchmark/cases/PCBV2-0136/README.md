# librechat-cve-2026-54024

CVE-2024-11171 -> CVE-2026-54024 (incomplete-fix chain, upload-size-limit DoS family).

- V0 = LibreChat v0.7.5 (avatar upload: unlimited in-memory multer -> OOM DoS)
- V1 = LibreChat v0.7.6 (CVE-2024-11171 fix `bb58a2d0`: avatar limited by
  `filterFile` avatarSizeLimit=2MB; `/api/convos/import` STILL unlimited) <- target
- V2 = LibreChat v0.8.4-rc1 (CVE-2026-54024 fix: import multer gets
  `limits:{fileSize}` + 413 `handleUpload`)

## Seed (CVE-2024-11171)

POST `/api/files/images/avatar` with a 6MB PNG. On v0.7.5 the route uses
`multer()` in-memory storage with no size limit -> `200 {"url": ...}`. On v0.7.6
the fix routes the upload through `filterFile({isAvatar: true})`, which rejects
uploads over `avatarSizeLimit` (2MB) -> `500 {"message":"An error occurred while
uploading the profile picture"}`.

Multipart field name changed with the fix (`input` -> `file`); the PoC uses the
per-version field. A browser User-Agent is required by the `uaParser` middleware.

## Residual (CVE-2026-54024)

The CVE-1 fix added size limits to the file/avatar endpoints but missed the
conversation-import multipart route: `POST /api/convos/import` used
`multer({ storage, fileFilter: importFileFilter })` with **no** `limits` from
0.7.6 through 0.8.3. An authenticated user uploads an oversized
conversation-export JSON (6MB > the 5MB limit configured on V2 via
`CONVERSATION_IMPORT_MAX_FILE_SIZE_BYTES`): V1 (0.7.6) accepts -> `201
"Conversation(s) imported successfully"`; V2 (0.8.4-rc1) multer rejects with
`413 "File exceeds the maximum allowed size"`.

## Gate

DoS-threshold variant (no planted flag token): four edges verified in real
Docker with the official images and real MongoDB:

| edge | probe | result |
|---|---|---|
| seed@V0 | avatar 6MB | 200 (reaches) |
| seed@V1 | avatar 6MB | 500 (blocked) |
| residual@V1 | import 6MB | 201 (reaches) |
| residual@V2 | import 6MB | 413 (blocked) |

See repro.log. Env: `PCB_FLAG` accepted but unused (threshold case).
