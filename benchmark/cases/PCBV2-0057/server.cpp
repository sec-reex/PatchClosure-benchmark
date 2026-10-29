// PatchClosure-Bench: cpp-httplib CRLF response-header-injection SUT
//
// A tiny REAL HTTP server built against the REAL, unmodified httplib.h fetched
// from the yhirose/cpp-httplib repo at a pinned release tag (see Dockerfile).
//
// The single handler reflects a request-supplied query parameter ("x") straight
// into a RESPONSE header value via httplib's res.set_header(). This is the exact
// sink whose CRLF-sanitization evolved across the CVE-2020-11709 -> CVE-2025-0825
// incomplete-fix chain:
//   * v0.5.8  (V0): Response::set_header does a raw headers.emplace() -> no filter
//   * v0.18.3 (V1): set_header guards with detail::has_crlf(val)  [CVE-2020-11709 fix]
//                   has_crlf walks val.c_str() and STOPS at the first NUL byte,
//                   so "safe\0\r\nInjected: ..." bypasses it (CVE-2025-0825).
//   * v0.18.4 (V2): set_header guards with detail::fields::is_field_value(val),
//                   a length-based RFC field-content check that inspects EVERY
//                   byte (incl. bytes after a NUL) -> the bypass is closed.
//
// The exact same source compiles unchanged against all three tags (the Server
// ::Get / get_param_value / set_header / listen signatures accept string
// literals on every version).

#include "httplib.h"
#include <cstdlib>
#include <string>

int main() {
  httplib::Server svr;

  // Reflect the user-controlled "x" param into a response header value.
  // get_param_value returns a std::string that faithfully carries any embedded
  // NUL byte and any post-NUL CRLF bytes produced by percent-decoding (%00%0d%0a).
  svr.Get("/echo", [](const httplib::Request &req, httplib::Response &res) {
    std::string echoed = req.get_param_value("x");
    res.set_header("X-Echo", echoed);   // <-- the sink under test
    res.set_content("ok\n", "text/plain");
  });

  svr.Get("/healthz", [](const httplib::Request &, httplib::Response &res) {
    res.set_content("ok\n", "text/plain");
  });

  const char *port_env = std::getenv("PORT");
  int port = port_env ? std::atoi(port_env) : 8080;
  svr.listen("0.0.0.0", port);
  return 0;
}
