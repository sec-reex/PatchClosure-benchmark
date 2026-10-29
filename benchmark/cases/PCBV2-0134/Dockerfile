# Real-library-wrap: install REAL npm koa bytes at the requested version, wrap
# with a tiny real Koa app that calls the genuine ctx.response.back() sink.
FROM node:20-slim

ARG KOA_VERSION=3.0.1
ENV KOA_VERSION=${KOA_VERSION}
WORKDIR /app

# Install the REAL published koa package for this profile.
# App is ESM (app.mjs); do not let a CJS require() of package.json fail the build.
RUN npm init -y >/dev/null 2>&1 \
    && npm pkg set type=module >/dev/null 2>&1 \
    && npm install --no-audit --no-fund koa@${KOA_VERSION} \
    && (node --input-type=commonjs -e "console.log('installed koa', require('/app/node_modules/koa/package.json').version)" \
        || echo "installed koa ${KOA_VERSION}")

COPY app.mjs /app/app.mjs

EXPOSE 3000
CMD ["node", "/app/app.mjs"]
