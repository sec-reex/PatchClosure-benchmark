// Faithful-core harness for Moby/Docker Engine AuthZ plugin bypass
// (CVE-2024-41110 -> CVE-2026-34040).
//
// Booting the full dockerd (privileged, containerd, an actual AuthZ plugin over
// a UNIX-socket RPC, a privileged-container create that mounts the host) just to
// drive ONE authorization decision is disproportionate and privileged; instead
// this image runs the REAL AuthZ-middleware predicate of Moby lifted VERBATIM from
// upstream `pkg/authorization/authz.go` at the three tags, wired to a stub AuthZ
// plugin that records exactly what body it was shown and a stub "daemon action"
// that acts on the FULL untruncated request:
//
//   - CVE-2024-41110 fix (present on V1 & V2, ABSENT on V0) = commit fc274cd2 /
//     v27.1.1: (*Ctx).AuthZRequest forwards the body to the plugin when
//     `sendBody(uri,hdr) && (r.ContentLength > 0 || isChunked(r)) && r.ContentLength < maxBodySize`
//     (V0 had only `r.ContentLength > 0` — no isChunked branch, so a chunked /
//     Content-Length:0 body was never shown to the plugin => the 41110/2019 seed).
//   - CVE-2026-34040 residual (open on V1) = the SAME predicate still gates on
//     `r.ContentLength < maxBodySize` (1 MiB) AND drainBody's `Peek(maxBodySize)`
//     returns a NIL body for oversized payloads ("skipping body"): a request whose
//     declared body >= 1 MiB is NEVER shown to the plugin, yet the daemon acts on
//     the full body => AuthZ desync.
//   - CVE-2026-34040 fix (V2) = commit e89edb19 / v29.3.1: AuthZRequest drops the
//     size condition and instead `Peek(maxBodySize + 1)`; if that succeeds (body too
//     large) it FAIL-CLOSED rejects the request ("request body too large for
//     authorization plugin") instead of forwarding an empty body.
//
// AuthZ plugin (faithful stub): DENIES a `POST /containers/create` whose body the
// plugin is shown contains `"Privileged":true`; ALLOWS otherwise — including when it
// is shown an EMPTY body (real AuthZ plugins default to allow when there is nothing
// to inspect). Daemon action (faithful stub): reads the FULL request body and, iff
// it actually requests a privileged container, "creates" it and returns ${PCB_FLAG}
// (standing in for the host secret a privileged container would expose).
//
// The differential = does the plugin's VIEW of the body match the daemon's ACTION.
//
// HARNESS_VER selects the per-version AuthZRequest predicate at runtime:
//   v0  Moby < v27.1.1 (pre-CVE-2024-41110): body forwarded only when ContentLength>0
//   v1  Moby v27.1.1..* (CVE-2024-41110-patched, target): isChunked branch added, but
//       still gated on ContentLength<maxBodySize + oversized-skip in drainBody => -34040
//   v2  Moby v29.3.1 (CVE-2026-34040-patched): Peek(maxBodySize+1), fail-closed reject
//
// Route: POST /v1.45/containers/create  (mirrors the daemon's container-create API,
// which real AuthZ plugins guard on the Privileged field). Pure Go stdlib.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
)

// ==========================================================================================
// VERBATIM from moby/moby pkg/authorization/authz.go (v27.1.1). maxBodySize, isChunked,
// drainBody, isAuthEndpoint, sendBody, the Request/Response types and the plugin-iteration
// in AuthZRequest are the REAL guard. Only two things vary: (1) AuthZRequest's body-forward
// predicate is selected by HARNESS_VER, and (2) ioutils.NewReadCloserWrapper is inlined so
// the image stays pure-stdlib. Nothing security-relevant is changed.
// ==========================================================================================

const maxBodySize = 1048576 // 1MB

func isChunked(r *http.Request) bool {
	// RFC 7230 specifies that content length is to be ignored if Transfer-Encoding is chunked
	if strings.EqualFold(r.Header.Get("Transfer-Encoding"), "chunked") {
		return true
	}
	for _, v := range r.TransferEncoding {
		if strings.EqualFold(v, "chunked") {
			return true
		}
	}
	return false
}

// drainBody dump the body (if its length is less than 1MB) without modifying the request state
func drainBody(body io.ReadCloser) ([]byte, io.ReadCloser, error) {
	bufReader := bufio.NewReaderSize(body, maxBodySize)
	newBody := newReadCloserWrapper(bufReader, func() error { return body.Close() })

	data, err := bufReader.Peek(maxBodySize)
	// Body size exceeds max body size
	if err == nil {
		// log.G(context.TODO()).Warnf("Request body is larger than: '%d' skipping body", maxBodySize)
		return nil, newBody, nil
	}
	// Body size is less than maximum size
	if err == io.EOF {
		return data, newBody, nil
	}
	// Unknown error
	return nil, newBody, err
}

func isAuthEndpoint(urlPath string) (bool, error) {
	// eg www.test.com/v1.24/auth/optional?optional1=something&optional2=something (version optional)
	matched, err := regexp.MatchString(`^[^\/]*\/(v\d[\d\.]*\/)?auth.*`, urlPath)
	if err != nil {
		return false, err
	}
	return matched, nil
}

// sendBody returns true when request/response body should be sent to AuthZPlugin
func sendBody(inURL string, header http.Header) bool {
	u, err := url.Parse(inURL)
	if err != nil {
		return false
	}
	// Skip body for auth endpoint
	isAuth, err := isAuthEndpoint(u.Path)
	if isAuth || err != nil {
		return false
	}
	// body is sent only for text or json messages
	contentType, _, err := mime.ParseMediaType(header.Get("Content-Type"))
	if err != nil {
		return false
	}
	return contentType == "application/json"
}

// Request holds data required for authZ plugins (VERBATIM subset).
type Request struct {
	RequestMethod string
	RequestURI    string
	RequestBody   []byte
}

// Response represents authZ plugin response (VERBATIM subset).
type Response struct {
	Allow bool
	Msg   string
}

type Plugin interface {
	Name() string
	AuthZRequest(*Request) (*Response, error)
}

// Ctx stores a single request-response interaction context (VERBATIM subset).
type Ctx struct {
	requestMethod string
	requestURI    string
	plugins       []Plugin
	authReq       *Request
}

func NewCtx(plugins []Plugin, requestMethod, requestURI string) *Ctx {
	return &Ctx{plugins: plugins, requestMethod: requestMethod, requestURI: requestURI}
}

// authzVer is the per-version body-forward predicate selector (the ONLY security-relevant
// per-tag difference in AuthZRequest). Everything else below is verbatim.
var authzVer = "v1"

// AuthZRequest authorized the request to the docker daemon using authZ plugins.
// The body-forwarding predicate is the per-version guard; the plugin-iteration is verbatim.
func (ctx *Ctx) AuthZRequest(w http.ResponseWriter, r *http.Request) error {
	var body []byte

	switch authzVer {
	case "v0":
		// pre-CVE-2024-41110 (regressed 2019 fix absent): forward only when ContentLength>0.
		// A chunked / Content-Length:0 body (ContentLength==-1 or 0) is NEVER shown to the plugin.
		if sendBody(ctx.requestURI, r.Header) && r.ContentLength > 0 && r.ContentLength < maxBodySize {
			var err error
			body, r.Body, err = drainBody(r.Body)
			if err != nil {
				return err
			}
		}
	case "v2":
		// CVE-2026-34040 fix (commit e89edb19 / v29.3.1): no size condition; Peek(maxBodySize+1)
		// and FAIL-CLOSED reject when the body is too large instead of forwarding an empty body.
		if sendBody(ctx.requestURI, r.Header) {
			bufBody := bufio.NewReaderSize(r.Body, maxBodySize+1)
			r.Body = newReadCloserWrapper(bufBody, r.Body.Close)
			peeked, err := bufBody.Peek(maxBodySize + 1)
			if err == nil {
				// Successfully peeked maxBodySize+1 bytes, so body is too large
				return fmt.Errorf("request body too large for authorization plugin: size exceeds %d bytes", maxBodySize)
			} else if err != io.EOF {
				return err
			}
			body = peeked
		}
	default: // "v1" — CVE-2024-41110-patched (commit fc274cd2 / v27.1.1). TARGET.
		// isChunked branch added (closes the -41110 seed), but STILL gated on
		// r.ContentLength < maxBodySize, and drainBody skips (nil body) for oversized => -34040.
		if sendBody(ctx.requestURI, r.Header) && (r.ContentLength > 0 || isChunked(r)) && r.ContentLength < maxBodySize {
			var err error
			body, r.Body, err = drainBody(r.Body)
			if err != nil {
				return err
			}
		}
	}

	ctx.authReq = &Request{
		RequestMethod: ctx.requestMethod,
		RequestURI:    ctx.requestURI,
		RequestBody:   body, // what the plugin is SHOWN (may be nil while the daemon acts on the full body)
	}

	for _, plugin := range ctx.plugins {
		authRes, err := plugin.AuthZRequest(ctx.authReq)
		if err != nil {
			return fmt.Errorf("plugin %s failed with error: %s", plugin.Name(), err)
		}
		if !authRes.Allow {
			return fmt.Errorf("authorization denied by plugin %s: %s", plugin.Name(), authRes.Msg)
		}
	}
	return nil
}

// ------------------------------------------------------------------------------------------
// inlined ioutils.NewReadCloserWrapper (github.com/docker/docker/pkg/ioutils) — pure stdlib.
// ------------------------------------------------------------------------------------------

type readCloserWrapper struct {
	io.Reader
	closer func() error
}

func (r *readCloserWrapper) Close() error { return r.closer() }

func newReadCloserWrapper(r io.Reader, closer func() error) io.ReadCloser {
	return &readCloserWrapper{Reader: r, closer: closer}
}

// ==========================================================================================
// Stub AuthZ plugin + stub daemon action. These are the benchmark canary, NOT app code.
// ==========================================================================================

// denyPrivilegedPlugin models a real AuthZ plugin that guards `/containers/create` on the
// Privileged field. It decides ONLY from the body it is SHOWN (authReq.RequestBody) and,
// like every real AuthZ plugin, DEFAULTS TO ALLOW when shown nothing to inspect.
type denyPrivilegedPlugin struct {
	shown []byte // records exactly what the plugin was shown, for the observable
}

func (p *denyPrivilegedPlugin) Name() string { return "deny-privileged" }

func (p *denyPrivilegedPlugin) AuthZRequest(authReq *Request) (*Response, error) {
	p.shown = authReq.RequestBody
	if bodyRequestsPrivileged(authReq.RequestBody) {
		return &Response{Allow: false, Msg: "privileged containers are denied by policy"}, nil
	}
	return &Response{Allow: true}, nil
}

// bodyRequestsPrivileged JSON-decodes the (possibly padded) body and reports Privileged.
// Unknown fields (e.g. the >1MiB padding) are ignored, exactly as the daemon's decoder does.
func bodyRequestsPrivileged(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	var cr struct {
		Privileged bool `json:"Privileged"`
	}
	if err := json.Unmarshal(b, &cr); err != nil {
		return false
	}
	return cr.Privileged
}

func main() {
	authzVer = os.Getenv("HARNESS_VER")
	if authzVer == "" {
		authzVer = "v1"
	}
	flag := os.Getenv("PCB_FLAG")

	http.HandleFunc("/v1.45/containers/create", func(w http.ResponseWriter, r *http.Request) {
		plugin := &denyPrivilegedPlugin{}
		ctx := NewCtx([]Plugin{plugin}, r.Method, r.RequestURI)

		// --- AuthZ middleware (WrapHandler): authorize BEFORE the daemon acts. ---
		if err := ctx.AuthZRequest(w, r); err != nil {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintf(w, "{\"message\":%q}\n", err.Error())
			return
		}

		// --- Daemon action: acts on the FULL, untruncated request body. ---
		full, _ := io.ReadAll(r.Body)
		privileged := bodyRequestsPrivileged(full)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		if privileged {
			// A privileged container was created -> host access -> expose the seeded secret.
			fmt.Fprintf(w, "{\"Id\":\"pcb\",\"Privileged\":true,\"HostSecret\":%q,\"plugin_shown_bytes\":%d}\n", flag, len(plugin.shown))
		} else {
			fmt.Fprintf(w, "{\"Id\":\"pcb\",\"Privileged\":false,\"plugin_shown_bytes\":%d}\n", len(plugin.shown))
		}
	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "moby-authz-bypass faithful-core harness ("+authzVer+")\n")
	})

	_ = context.Background()
	if err := http.ListenAndServe(":80", nil); err != nil {
		panic(err)
	}
}
