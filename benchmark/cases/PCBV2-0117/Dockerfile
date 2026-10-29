# Faithful-core harness for Gitea public-only-token authz bypass
# (CVE-2025-68941 -> CVE-2026-24791).
#
# Rather than boot the full Gitea binary (DB + web UI + OAuth2 provider + a real private
# account + an issued public-only token) just to drive one authorization decision, this image
# runs the REAL guard `checkTokenPublicOnly()` (lifted verbatim from routers/api/v1/api.go)
# and the REAL per-version route wiring of the `/api/v1/users/{username}` (seed) and
# `/api/v1/user` (self, residual) route families. Behaviour is selected at runtime by
# HARNESS_VER (v0|v1|v2). Pure Go stdlib (no external deps).
FROM golang:1.23-alpine
WORKDIR /app
COPY go.mod harness.go /app/
RUN go build -o /harness harness.go
EXPOSE 80
CMD ["/harness"]
