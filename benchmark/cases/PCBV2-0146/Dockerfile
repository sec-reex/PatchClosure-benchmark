# Faithful-core harness for Moby/Docker Engine AuthZ plugin bypass
# (CVE-2024-41110 -> CVE-2026-34040).
#
# Rather than boot the full privileged dockerd (containerd + a real AuthZ plugin RPC +
# a privileged-container create that mounts the host) just to drive ONE authorization
# decision, this image runs the REAL AuthZ-middleware predicate of (*Ctx).AuthZRequest,
# lifted VERBATIM from moby/moby pkg/authorization/authz.go at the three tags:
#   - V0 pre-CVE-2024-41110   : body forwarded only when ContentLength>0 (chunked/CL:0 unseen)
#   - V1 CVE-2024-41110-patched: isChunked branch added, still gated on ContentLength<maxBodySize
#                                + drainBody skips oversized bodies  => CVE-2026-34040 residual
#   - V2 CVE-2026-34040-patched: Peek(maxBodySize+1) fail-closed reject (commit e89edb19)
# Behaviour is selected at runtime by HARNESS_VER (v0|v1|v2). Pure Go stdlib (no external deps).
FROM golang:1.23-alpine
WORKDIR /app
COPY go.mod harness.go /app/
RUN go build -o /harness harness.go
EXPOSE 80
CMD ["/harness"]
