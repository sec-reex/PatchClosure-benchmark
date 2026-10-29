#!/bin/sh
# Apache execs this CGI. Dash does not import bash functions from the
# environment, so it only forwards into the profile bash:
#   /usr/local/bin/target-bash -> /opt/bash-vN/bash
# Invoked as `bash -c`, the first command is exactly the leak-path line
# required by CVE-2014-7169 (leftover `>` becomes a redirect onto it).
exec /usr/local/bin/target-bash -c '/var/www/html/leaks/pcb_leak.dat cat /canary; echo "Content-Type: text/plain"; echo; echo "shellshock-demo-cgi ok"'
