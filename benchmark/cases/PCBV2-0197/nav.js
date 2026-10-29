// PatchClosure-Bench browser-equivalent navigation resolver (NOT Spring code).
// Models the REAL navigation an open-redirect/SSRF victim performs: parse the
// attacker-supplied URL with the WHATWG URL parser (the exact parser browsers'
// location bar and fetch() use), take the host it actually connects to, and
// perform a real HTTP GET to that host. If the host is the internal attacker
// sidecar, the response body carries the per-run ${PCB_FLAG}. This is the
// "downstream consumer" whose host differs from Spring's getHost() guard.
//
// Usage: node nav.js <url>   (env NAV_PORT = sidecar port, default 8080)
// Prints:  NAV_HOST=<whatwg hostname>
//          NAV_BODY=<response body, one line>   (or NAV_ERR=...)
const http = require("http");

const input = process.argv[2];
const port = process.env.NAV_PORT || "8080";

let host;
try {
  host = new URL(input).hostname;   // WHATWG host resolution == what a browser navigates to
} catch (e) {
  console.log("NAV_HOST=EXC:" + e.message.replace(/\n/g, " "));
  process.exit(0);
}
console.log("NAV_HOST=" + host);

if (!host) { console.log("NAV_ERR=empty-host"); process.exit(0); }

const req = http.get({ host: host, port: port, path: "/", timeout: 5000 }, (res) => {
  let data = "";
  res.on("data", (c) => (data += c));
  res.on("end", () => console.log("NAV_BODY=" + data.replace(/\n/g, " ")));
});
req.on("timeout", () => { req.destroy(); console.log("NAV_ERR=timeout"); });
req.on("error", (e) => console.log("NAV_ERR=" + e.message.replace(/\n/g, " ")));
