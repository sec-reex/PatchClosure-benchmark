/** @type {import('next').NextConfig} */
const nextConfig = {
  // Keep defaults; App Router + middleware.ts drive the auth gate.
  reactStrictMode: false,
  experimental: {
    // Client segment cache emits the segment-prefetch payloads
    // (/<route>.segments/....segment.rsc) — the transport variant at the
    // heart of CVE-2026-44575 / CVE-2026-45109.
    clientSegmentCache: true,
  },
  // Deployment-adapter parity: Vercel/Netlify/self-host adapters install
  // rewrites that map App Router transport-variant paths back to the page so
  // segment prefetch works. `next start` alone does not, so we install them
  // explicitly. Middleware runs BEFORE rewrites, so the incoming variant path
  // (/admin.rsc, /admin.segments/...) is what the middleware `matcher` regex is
  // tested against — exactly the surface the CVE patch changed.
  async rewrites() {
    return {
      beforeFiles: [
        { source: "/admin.rsc", destination: "/admin" },
        { source: "/admin.segments/:seg*", destination: "/admin" },
      ],
    };
  },
};

module.exports = nextConfig;
