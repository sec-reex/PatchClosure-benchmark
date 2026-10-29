#!/usr/bin/env bash
set -e
cd /build/app

# Plant the benign canary flag OUTSIDE the app root, where the download_private_file
# path traversal escapes to. ${PCB_FLAG} is injected at container start.
: "${PCB_FLAG:=PCB_FLAG_UNSET}"
echo -n "${PCB_FLAG}" > /pcb_flag.txt
chmod 644 /pcb_flag.txt

# The on-disk private-media directory. Camaleon's LocalUploader creates Rails.root/private at
# request time (enable_private_mode!); the AwsUploader does not, but any Camaleon deployment that
# serves private media has this directory on disk. It must exist for the OS to resolve the `../`
# traversal in download_private_file (fetch_file -> File.exist?/send_file reads a LOCAL file).
mkdir -p /build/app/private

# Fresh DB per boot.
bundle exec rails db:create >/dev/null 2>&1 || true
bundle exec rails db:migrate 2>&1 | tail -5

# Wait for minio (s3 backend only) before seeding the bucket.
if [ "${BACKEND}" = "s3" ]; then
  echo "waiting for minio at ${AWS_ENDPOINT} ..."
  for i in $(seq 1 60); do
    if curl -sf "${AWS_ENDPOINT}/minio/health/live" >/dev/null 2>&1; then echo "minio up"; break; fi
    sleep 2
  done
fi

bundle exec rails runner /build/app/seed.rb

echo "BOOT: camaleon=${CAMALEON_VERSION} backend=${BACKEND}"
exec bundle exec rails server -b 0.0.0.0 -p 3000
