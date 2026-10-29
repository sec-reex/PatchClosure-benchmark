<script setup lang="ts">
// OG image template (Satori renderer). `src` is a declared prop, so nuxt-og-image
// accepts it and renders it as a remote <img src>. During render the module
// server-fetches that URL (gated only by isBlockedUrl) and inlines the response
// as a base64 data URI in the rendered image.
defineProps<{ src?: string }>()
</script>
<template>
  <div style="width:100%;height:100%;display:flex;align-items:center;justify-content:center;background:#fff;">
    <img :src="src" width="200" height="200" />
    <span style="font-size:40px;">og</span>
  </div>
</template>
