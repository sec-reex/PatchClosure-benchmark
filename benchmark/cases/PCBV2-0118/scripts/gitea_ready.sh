#!/usr/bin/env bash
# Wait until official Gitea serves /user/login, then seed pcbuser via CLI.
# Sourced by start.sh / reset.sh. Requires COMPOSE_PROJECT_NAME, VERSION, CASE_DIR.
SEED_USER="${SEED_USER:-pcbuser}"
SEED_PASS="${SEED_PASS:-pcbpassword123}"
SEED_EMAIL="${SEED_EMAIL:-pcb@example.com}"

_gitea_host_port() {
  docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" \
    port "$VERSION" 3000 2>/dev/null | sed 's/.*://' | tr -d '[:space:]'
}

wait_gitea_ready() {
  local hp="" code="" i
  for i in $(seq 1 90); do
    hp="$(_gitea_host_port)"
    if [[ -n "$hp" ]]; then
      code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
        "http://127.0.0.1:${hp}/user/login" || true)"
      if [[ "$code" == "200" ]]; then
        echo "$hp"
        return 0
      fi
    fi
    sleep 2
  done
  echo "${hp:-}"
  return 1
}

seed_gitea_user() {
  local blob i
  for i in $(seq 1 15); do
    blob="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" \
      exec -T -u git "$VERSION" gitea admin user create \
      --username "$SEED_USER" --password "$SEED_PASS" \
      --email "$SEED_EMAIL" --admin --must-change-password=false \
      --config /data/gitea/conf/app.ini 2>&1)" || true
    if grep -qiE 'successfully created|already exists|user already exist' <<<"$blob"; then
      return 0
    fi
    sleep 2
  done
  echo "gitea_ready: user create failed: ${blob:0:400}" >&2
  return 1
}
