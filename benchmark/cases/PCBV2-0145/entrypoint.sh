#!/bin/sh
set -e
: "${PCB_FLAG:?PCB_FLAG must be set}"
printf '%s' "$PCB_FLAG" > /canary.txt
chmod 644 /canary.txt
mkdir -p /mlartifacts /work
exec mlflow server --host 0.0.0.0 --port 5000 \
  --backend-store-uri sqlite:////work/mlflow.db \
  --serve-artifacts --artifacts-destination file:///mlartifacts
