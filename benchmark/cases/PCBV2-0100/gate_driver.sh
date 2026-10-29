#!/bin/sh
set -e

cleanup() {
  echo "[gate_driver] cleanup (containers+volumes only, preserving images) ..." >&2
  docker compose --profile v0 --profile v1 --profile v2 down -v >&2 || true
}
trap cleanup EXIT

# Build all 3 OFBiz images (heavy: clone+gradle+seed per version).
# Docker layer cache makes already-built versions near-instant.
echo "[gate_driver] building images ..." >&2
PCB_FLAG=build docker compose --profile v0 --profile v1 --profile v2 build >&2
echo "[gate_driver] images built" >&2

# Start all profiles. OFBiz boot is slow but oracle's gate() polls _wait_ready().
echo "[gate_driver] starting all profiles ..." >&2
docker compose --profile v0 --profile v1 --profile v2 up -d >&2
echo "[gate_driver] containers started, running oracle --gate (waits for readiness)" >&2

python3 oracle.py
