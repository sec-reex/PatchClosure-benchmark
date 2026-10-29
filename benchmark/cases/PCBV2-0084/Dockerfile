# Faithful-core image for the axios baseURL destination-control SSRF guard
# (CVE-2024-39338 -> CVE-2025-27152). One image, three roles selected by ROLE:
#   ROLE=public   -> the PUBLIC upstream the server is CONFIGURED to call (baseURL host).
#   ROLE=sidecar  -> the INTERNAL-only service that serves ${PCB_FLAG} (must NOT be reachable
#                    via baseURL; only via a baseURL-destination-override SSRF).
#   ROLE=server   -> a destination-pinned proxy that does
#                    axios.get(userPath, {baseURL:'http://public-app', allowAbsoluteUrls:false})
#                    with the REAL per-version axios chosen by HARNESS_VER.
# node:20-slim ships the node http/https stack axios' http adapter uses as the outbound sink.
# The three axios versions are installed side-by-side via npm aliases (see package.json), so the
# server imports the exact published bytes of axios@1.7.3 (V0), axios@1.7.4 (V1, the
# CVE-2024-39338 fix / TARGET) and axios@1.8.2 (V2, the CVE-2025-27152 complete fix).
FROM node:20-slim
WORKDIR /app
COPY package.json /app/
RUN npm install --no-audit --no-fund
COPY harness.mjs /app/
EXPOSE 8080
