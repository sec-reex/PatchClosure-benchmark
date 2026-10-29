#!/usr/bin/env bash
# Shared wait: Jenkins HTTP up + init.groovy.d done (pcbReveal + crumbIssuer).
# Echoes the published host port on success.

wait_jenkins_ready() {
  local svc="${1:?service name}"
  local hp="" code="" crumb_code=""
  local i
  for i in $(seq 1 120); do
    hp="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" \
      port "$svc" 8080 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
    if [[ -n "$hp" ]]; then
      code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 \
        "http://127.0.0.1:${hp}/pcbReveal/session" || true)"
      if [[ "$code" == "200" ]]; then
        crumb_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 \
          "http://127.0.0.1:${hp}/crumbIssuer/api/json" || true)"
        if [[ "$crumb_code" == "200" ]]; then
          printf '%s' "$hp"
          return 0
        fi
      fi
    fi
    sleep 4
  done
  printf '%s' "${hp:-}"
  return 1
}
