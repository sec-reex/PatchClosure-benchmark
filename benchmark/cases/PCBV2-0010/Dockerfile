# Faithful-core harness for Traefik Connection-header X-Forwarded strip
# (CVE-2024-45410 -> CVE-2026-29054).
#
# Runs the REAL forwardedheaders sink lifted verbatim from
#   pkg/middlewares/forwardedheaders/forwarded_header.go
# at the three tags (v2.11.8 / v2.11.9 / v2.11.38), selected at runtime by HARNESS_VER, in front
# of the REAL Go httputil.ReverseProxy (authentic Connection hop-by-hop removal). Pure Go stdlib.
FROM golang:1.23-alpine
WORKDIR /app
COPY go.mod harness.go /app/
RUN go build -o /harness harness.go
EXPOSE 80
CMD ["/harness"]
