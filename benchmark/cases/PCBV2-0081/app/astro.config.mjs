import { defineConfig } from 'astro/config';
import cloudflare from '@astrojs/cloudflare';

// On-demand-rendered Astro site using the Cloudflare SSR adapter.
// The built-in /_image optimization endpoint is restricted to remote images
// whose host is on the `image.domains` allowlist ("allowed" sidecar).
// Default imageService => cloudflare-binding => the @astrojs/cloudflare
// image-transform-endpoint (image-binding-transform.ts) — the CVE surface.
export default defineConfig({
  output: 'server',
  adapter: cloudflare(),
  image: {
    domains: ['allowed'],
  },
});
