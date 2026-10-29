#!/bin/sh
# Plant the benign per-run canary OUTSIDE the application: /flag holds the
# ${PCB_FLAG} token as a JSON string literal ("PCBFLAG_..."), so that a genuine
# ObjectMapper sandbox escape reading file:///flag via readValue(URL, String)
# surfaces the raw token in the HTTP /render response. No application-code edits.
set -e
: "${PCB_FLAG:?PCB_FLAG must be set}"
printf '"%s"' "$PCB_FLAG" > /flag
exec java -jar /app/app.jar
