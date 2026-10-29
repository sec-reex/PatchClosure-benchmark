#!/bin/sh
# Plant the BENIGN read-exfil canary OUTSIDE the app dir, then boot the REAL Apache Solr server.
# The XXE (external HTTP POST) reads file:///flag; ${PCB_FLAG} surfaces in the Solr HTTP response
# iff the version's own request-handler XMLInputFactory still resolves external entities.
set -e
: "${PCB_FLAG:?set PCB_FLAG to the per-run canary token}"
printf '%s\n' "$PCB_FLAG" > /flag
chmod 644 /flag
cd /opt/solr/example
# Boot the bundled Jetty + example collection1 core (real server; both /update and
# /analysis/document handlers registered by the stock solrconfig.xml). Modest heap for CI.
exec java -Xms128m -Xmx512m -jar start.jar
