// Minimal REAL Nuxt app that enables the real nuxt-og-image module. The og-image
// version is chosen at image-build time (npm i nuxt-og-image@<OGI_VER>).
export default defineNuxtConfig({
  modules: ['nuxt-og-image'],
  compatibilityDate: '2025-01-01',
  site: { url: 'http://app.local' },
  ogImage: {
    // Expose the module's own og.svg / og.json render output at runtime so the
    // rendered vnode tree (with any server-fetched <img src> inlined as a data
    // URI) is observable over HTTP. This does NOT relax isBlockedUrl -- only
    // import.meta.dev disables the SSRF guard, and this is a production build.
    debug: true
  }
})
