#!/usr/bin/env bash
# Shared wait: Jenkins login + init.groovy.d done (admin can read agentA).
# Echoes the published host port on success.

wait_jenkins_ready() {
  local svc="${1:?service name}"
  local hp="" code=""
  local i
  for i in $(seq 1 90); do
    hp="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" \
      port "$svc" 8080 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
    if [[ -n "$hp" ]]; then
      code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 \
        -u admin:admin123 "http://127.0.0.1:${hp}/computer/agentA/api/json" || true)"
      if [[ "$code" == "200" ]]; then
        printf '%s' "$hp"
        return 0
      fi
    fi
    sleep 4
  done
  printf '%s' "${hp:-}"
  return 1
}
