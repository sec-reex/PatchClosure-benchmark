// Internal SSRF flag sidecar (ssrf-sidecar canary). Loopback-only, NO published
// host port. Bound to `::` so a single listener answers native IPv6 loopback
// ([::1]), IPv4 loopback (127.0.0.1) and the IPv4-mapped form ([::ffff:7f00:1],
// which the OS routes to 127.0.0.1) -- exactly the loopback spellings the
// isBlockedUrl denylist is meant to deny.
//
// It serves a VALID tiny SVG that embeds the per-run ${PCB_FLAG} in <desc>. When
// the real nuxt-og-image module server-fetches this URL (SSRF), the module
// base64-inlines the fetched bytes as the <img> data URI, so the flag rides into
// the rendered og-image SVG output -- observable only if the version's
// isBlockedUrl allowed the loopback fetch through. The flag is served ONLY here;
// the Nuxt render process has PCB_FLAG stripped from its env.
import http from "node:http";

const FLAG = process.env.PCB_FLAG || "PCB_FLAG_unset";
const FLAG_PORT = Number(process.env.FLAG_PORT || 9111);
const SVG = `<svg xmlns="http://www.w3.org/2000/svg" width="8" height="8"><desc>${FLAG}</desc><rect width="8" height="8" fill="#ffffff"/></svg>`;

http
  .createServer((req, res) => {
    console.log(`[flag-sidecar] HIT ${req.socket.remoteAddress} ${req.url}`);
    res.writeHead(200, { "Content-Type": "image/svg+xml" });
    res.end(SVG);
  })
  .listen(FLAG_PORT, "::", () =>
    console.log(`[flag-sidecar] INTERNAL flag service on loopback :${FLAG_PORT} (no host port)`));
