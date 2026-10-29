#!/usr/bin/env bash
# Shared: persist compose host ports and wait until GLPI login page answers.
# shellcheck shell=bash

glpi_assign_ports() {
  mkdir -p "$WORK_DIR"
  if [[ -f "$WORK_DIR/compose.env" ]]; then
    set -a
    # shellcheck disable=SC1091
    source "$WORK_DIR/compose.env"
    set +a
  fi
  if [[ -z "${PORT_V0_0:-}" || -z "${PORT_V1_0:-}" || -z "${PORT_V2_0:-}" ]]; then
    eval "$(python3 - <<'PY'
import re, random
text = open('docker-compose.yml').read()
names = sorted(set(re.findall(r'\$\{PORT_([A-Za-z0-9_]+):-', text)))
used = set()
out = []
for n in names:
    while True:
        p = random.randint(20000, 59999)
        if p not in used:
            used.add(p)
            out.append(f'PORT_{n}={p}')
            break
print('\n'.join(out))
PY
)"
  fi
  {
    printf 'PORT_V0_0=%s\n' "${PORT_V0_0}"
    printf 'PORT_V1_0=%s\n' "${PORT_V1_0}"
    printf 'PORT_V2_0=%s\n' "${PORT_V2_0}"
  } > "$WORK_DIR/compose.env"
  export PORT_V0_0 PORT_V1_0 PORT_V2_0
}

# Wait until the profile's published :80 serves the GLPI login form (install done).
# Prints the host port on success; returns 1 on timeout.
wait_glpi_ready() {
  local hp="" ok=0 code="" body=""
  for _ in $(seq 1 150); do
    hp="$(docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" \
      port "$VERSION" 80 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
    if [[ -n "$hp" ]]; then
      code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
        "http://127.0.0.1:${hp}/index.php" || true)"
      if [[ "$code" == "200" ]]; then
        body="$(curl -sS --max-time 5 "http://127.0.0.1:${hp}/index.php" || true)"
        if grep -q 'login_password' <<<"$body" && ! grep -qi 'install/install.php' <<<"$body"; then
          ok=1
          break
        fi
      fi
    fi
    sleep 2
  done
  if [[ "$ok" != "1" ]]; then
    echo "glpi: $VERSION login page never ready (host=${hp:-none})" >&2
    return 1
  fi
  printf '%s' "$hp"
  return 0
}
