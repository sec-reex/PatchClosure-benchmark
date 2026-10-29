# Real HTTP sink image for fastxmlparser_entity_expansion_limit
# (CVE-2026-26278 [fast-xml-parser entity-expansion DoS: replaceEntitiesValue() gained expansion
#  accounting (maxTotalExpansions/maxExpandedLength) but ONLY in the DOCTYPE-entities loop],
#  fixed 5.3.6 = TARGET -> CVE-2026-33036 [INCOMPLETE fix: the standard-entity (lastEntities) and
#  HTML-entity (htmlEntities, incl numeric &#..; refs) loops stayed UNCOUNTED, so a long run of
#  entity references drives O(N^2) work ignoring every configured limit; fixed 5.5.6 by adding the
#  identical count guard to those loops], CWE-776 / CWE-400).
#
# Recipe only (NO vendored source, NO source-lift): the EXACT published fast-xml-parser is
# npm-installed at a pinned version (build-arg FXP_VERSION) from the npm registry, and a minimal
# REAL Express service (app/server.js) parses attacker-supplied request bodies with the real,
# unmodified `new XMLParser({processEntities:true}).parse(req.body)` SYNCHRONOUSLY. node:18 base.
FROM node:18-slim
ARG FXP_VERSION
ENV NODE_ENV=production
ENV FXP_VERSION=${FXP_VERSION}
WORKDIR /app
# Install the EXACT published fast-xml-parser + a real Express server. Only FXP_VERSION varies
# across v0/v1/v2; the service code and Express are identical -- the per-version entity-expansion
# accounting in OrderedObjParser.replaceEntitiesValue() is the ONLY thing that changes whether the
# expansion is bounded (throws fast) or unbounded (hangs the event loop).
RUN npm init -y >/dev/null 2>&1 && \
    npm install --no-audit --no-fund --loglevel=error \
        express@4.19.2 "fast-xml-parser@${FXP_VERSION}"
COPY app/ /app/
EXPOSE 80
CMD ["node", "/app/server.js"]
