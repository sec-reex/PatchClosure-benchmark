# Real HTTP sink image for fastxmlparser_entityname_regex_injection
# (CVE-2023-34104 [fast-xml-parser DOCTYPE entity-name regex injection: the entity NAME is
#  interpolated UNESCAPED into RegExp(`&${entityName};`,"g") in src/xmlparser/DocTypeReader.js
#  and run over element text BEFORE the built-in XML entities are decoded, so a regex
#  metacharacter in the NAME lets the pattern MATCH & OVERWRITE a built-in entity reference],
#  fixed 4.2.4 = TARGET -> CVE-2026-25896 [the 4.2.4 blocklist widening is an INCOMPLETE fix:
#  it added '|' and '+' but MISSED '.', which is BOTH a valid XML Name char AND a regex
#  wildcard -> the entity-shadow bypass survives; 5.3.5 escapes /[.\-+*:]/ before building the
#  RegExp], CWE-185).
#
# Recipe only (NO vendored source, NO source-lift): the EXACT published fast-xml-parser is
# npm-installed at a pinned version (build-arg FXP_VERSION) from the npm registry, and a minimal
# REAL Express service (server.js) parses attacker-supplied request bodies with the real,
# unmodified `new XMLParser({processEntities:true}).parse(req.body)`. node:18 base.
FROM node:18-slim
ARG FXP_VERSION
ENV NODE_ENV=production
ENV FXP_VERSION=${FXP_VERSION}
WORKDIR /app
# Install the EXACT published fast-xml-parser + a real Express server. Only FXP_VERSION varies
# across v0/v1/v2; the service code and Express are identical -- the per-version DocTypeReader
# guard is the ONLY thing that changes whether the entity-name regex injection fires.
RUN npm init -y >/dev/null 2>&1 && \
    npm install --no-audit --no-fund --loglevel=error \
        express@4.19.2 "fast-xml-parser@${FXP_VERSION}"
COPY server.js /app/server.js
EXPOSE 80
CMD ["node", "/app/server.js"]
