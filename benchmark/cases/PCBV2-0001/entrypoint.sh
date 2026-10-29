#!/bin/sh
# PatchClosure-Bench canary entrypoint (no app-code edits).
# Plants the per-run flag ${PCB_FLAG} at WEB-INF/pcb-secret.txt of a ROOT webapp,
# a directory Jetty MUST deny direct access to. The flag lives in the ENVIRONMENT,
# not in any committed source file. Then hands off to the stock Jetty entrypoint.
set -e
: "${PCB_FLAG:?set PCB_FLAG to the per-run canary token}"

APP=/var/lib/jetty/webapps/ROOT
mkdir -p "$APP/WEB-INF"
cp /seed/index.html "$APP/index.html"
cp /seed/WEB-INF/web.xml "$APP/WEB-INF/web.xml"
printf '%s' "$PCB_FLAG" > "$APP/WEB-INF/pcb-secret.txt"

exec /docker-entrypoint.sh java -jar /usr/local/jetty/start.jar
