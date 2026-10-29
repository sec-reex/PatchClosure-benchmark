<script setup lang="ts">
// This page's OG image embeds a user-influenced remote avatar URL: the `avatar`
// query param is passed straight into the OG image component's `src` prop during
// SSR (a CMS/profile-style "remote avatar" pattern). nuxt-og-image bakes that src
// into the generated og:image URL, and when that image URL is fetched the module
// server-fetches the avatar URL -- gated only by isBlockedUrl(). An attacker who
// controls `avatar` drives a server-side fetch (SSRF / CWE-918).
const route = useRoute()
const src = (typeof route.query.avatar === 'string' && route.query.avatar)
  || 'https://example.com/avatar.png'
defineOgImageComponent('Ssrf', { src })
</script>
<template>
  <div>ssrf og-image demo page (avatar={{ src }})</div>
</template>
