# Real Next.js app built per version, per bundler (webpack vs Turbopack).
# NEXT_VERSION selects the real npm `next` bytes; BUILD_MODE selects the bundler.
FROM node:20-bookworm-slim

ARG NEXT_VERSION
ARG BUILD_MODE=webpack

WORKDIR /app

# Install the REAL npm next bytes for this profile + React 19.
COPY app/package.json ./package.json
RUN npm install --no-audit --no-fund \
      next@${NEXT_VERSION} react@^19.0.0 react-dom@^19.0.0 \
      typescript@^5 @types/react@^19 @types/node@^20 \
    && node -e "console.log('installed next', require('next/package.json').version)"

COPY app/ ./

# Build with the selected bundler. Turbopack path is the residual-affected pipeline.
ENV NEXT_TELEMETRY_DISABLED=1
ARG PCB_FLAG=build-time-placeholder
ENV PCB_FLAG=${PCB_FLAG}
RUN set -eux; \
    if [ "$BUILD_MODE" = "turbopack" ]; then \
      npx --no-install next build --turbopack; \
    else \
      npx --no-install next build; \
    fi

EXPOSE 3000
# Runtime flag is injected via env at `docker compose up`; admin page is force-dynamic
# so it reads process.env.PCB_FLAG at request time (flag not baked into the image).
CMD ["npx", "--no-install", "next", "start", "-p", "3000", "-H", "0.0.0.0"]
