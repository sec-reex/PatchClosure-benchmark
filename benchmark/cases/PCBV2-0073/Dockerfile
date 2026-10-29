# Real-library-wrap image for @adonisjs/bodyparser FormFields prototype pollution
# (CVE-2026-25754 -> CVE-2026-48795). One image, three roles selected by HARNESS_VER.
#
# The three published npm versions are installed SIDE-BY-SIDE via npm aliases (see package.json):
#   bp_v0 = @adonisjs/bodyparser@10.1.2  (V0, unprotected: FormFields #fields = {})
#   bp_v1 = @adonisjs/bodyparser@10.1.4  (V1 TARGET, CVE-2026-25754 fix: #fields = Object.create(null))
#   bp_v2 = @adonisjs/bodyparser@10.1.5  (V2, CVE-2026-48795 fix: FormFields.add() key sanitizer)
# so the service imports the EXACT published bytes of the real parser for the chosen version. The
# @adonisjs/http-server peer (RequestFactory/HttpContextFactory) is used only to wrap the real Node
# req/res into the AdonisJS request the middleware consumes -- the parse itself is 100% real bodyparser.
FROM node:20-slim
WORKDIR /app
COPY package.json /app/
RUN npm install --no-audit --no-fund
COPY service.mjs worker.mjs /app/
EXPOSE 8080
CMD ["node", "/app/service.mjs"]
