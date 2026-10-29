# Faithful-core harness for OAuth2-Proxy skip-auth bypass (CVE-2025-54576 -> CVE-2026-40575).
#
# Rather than boot the full oauth2-proxy binary + an OIDC provider + a cookie session store +
# a login flow just to exercise ONE skip-auth decision, this image runs the REAL auth-skip
# decision path lifted verbatim from upstream:
#   - pkg/requests/util/util.go : GetRequestURI / GetRequestPath / IsProxied /
#                                 CanTrustForwardedHeaders (byte-for-byte from v7.10.0/7.11.0/7.15.2)
#   - oauthproxy.go isAllowedPath/isAllowedRoute : the skip-auth sink; the EXACT line
#                                 CVE-2025-54576 changed (GetRequestURI -> GetRequestPath).
#   - pkg/apis/middleware/scope.go CanTrustForwardedHeaders (v7.15.2 = CVE-2026-40575 fix).
# Behaviour is selected at runtime by HARNESS_VER (v0|v1|v2). Pure Go stdlib (no external deps).
FROM golang:1.23-alpine
WORKDIR /app
COPY go.mod harness.go /app/
RUN go build -o /harness harness.go
EXPOSE 80
CMD ["/harness"]
