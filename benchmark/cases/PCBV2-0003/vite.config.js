// Default Vite dev-server config. server.host exposes it to the network (the
// precondition for CVE-2025-30208 / CVE-2025-31125). server.fs.allow is left at
// its default (the project root /app), so /canary.txt is OUTSIDE the allow-list
// and is only readable through the CVE file-read bypass.
export default {
  server: { host: true },
};
