# V1/V2: published @astrojs/cloudflare 13.1.9 / 13.1.10 on Astro 6.
# npm install the whole packages, astro build, then astro preview (workerd).
# Default imageService is cloudflare-binding → image-binding-transform (CVE surface).
FROM node:22-bookworm-slim

ARG ADAPTER_VER
ARG ASTRO_VER
ARG EXTRA_PKGS=""

WORKDIR /app
COPY app/package.json ./package.json
COPY app/astro.config.mjs ./astro.config.mjs
COPY app/src ./src

RUN npm install --no-audit --no-fund \
      astro@${ASTRO_VER} \
      @astrojs/cloudflare@${ADAPTER_VER} \
      ${EXTRA_PKGS} \
  && node -e "console.log('adapter', require('@astrojs/cloudflare/package.json').version, 'astro', require('astro/package.json').version)" \
  && npm ls --depth=0 @astrojs/cloudflare astro \
  && npx astro build

EXPOSE 4321
CMD ["npx", "astro", "preview", "--host", "0.0.0.0", "--port", "4321"]
