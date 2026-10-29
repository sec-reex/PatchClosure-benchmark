#!/bin/sh
# victim.sh <submodule-url> <submodule-path>
#
# Generic harness modelling a victim who runs `git clone --recurse-submodules`
# on an attacker-supplied repository. It builds a malicious superproject whose
# single submodule uses the given `url` / `path` (all local file://, no network),
# plants the benign canary + a modeled ssh client, then clones it. The SPECIFIC
# payloads are NOT hard-coded here — they are supplied by original_poc.py (given)
# and _heldout/bypass_poc.py (held out).
#
# BENIGN CANARY (environment, never app code): /pcb-probe.sh echoes the per-run
# ${PCB_FLAG} when executed; also installed on PATH as `pcb-probe`. The flag
# reaches /out/hit ONLY if the argument injection actually fired. No real payload.
set -u
URL="${1:?submodule url}"
SMPATH="${2:?submodule path}"
export PCB_FLAG="${PCB_FLAG:?set PCB_FLAG to the per-run canary token}"
mkdir -p /out; rm -f /out/hit

git config --global user.email pcb@example.invalid >/dev/null 2>&1
git config --global user.name  pcb                 >/dev/null 2>&1
git config --global protocol.file.allow always     >/dev/null 2>&1

# benign canary probe (executed only if an injection fires)
cat > /pcb-probe.sh <<EOF
#!/bin/sh
printf 'PCB_HIT %s\n' "\$PCB_FLAG" >> /out/hit
exit 1
EOF
chmod +x /pcb-probe.sh
cp /pcb-probe.sh /usr/local/bin/pcb-probe && chmod +x /usr/local/bin/pcb-probe

# Modeled pre-OpenSSH-7.6 ssh client: honours an injected -oProxyCommand by
# executing it, as ssh did before hostname-validation hardening (the historical
# CVE-2017-1000117 sink). git's connect.c guard (V1+) rejects a dash host BEFORE
# ssh is invoked, so on patched git this file never runs. Placed early on PATH.
cat > /usr/local/bin/ssh <<'EOF'
#!/bin/sh
for a in "$@"; do
  case "$a" in
    -oProxyCommand=*) exec /bin/sh -c "${a#-oProxyCommand=}" ;;
  esac
done
exit 0
EOF
chmod +x /usr/local/bin/ssh

W=$(mktemp -d); cd "$W"; git init -q mal; cd mal
printf '[submodule "%s"]\n\tpath = %s\n\turl = %s\n' "$SMPATH" "$SMPATH" "$URL" > .gitmodules
git update-index --add --cacheinfo 160000,0000000000000000000000000000000000000001,"$SMPATH" 2>/dev/null
git add .gitmodules >/dev/null 2>&1
git commit -qm mal   >/dev/null 2>&1

cd "$W"
git clone --recurse-submodules "$W/mal" "$W/dst" > "$W/clone.log" 2>&1

echo "==== git $(git --version) | url=[$URL] path=[$SMPATH] ===="
sed 's/^/  /' "$W/clone.log" | head -12
if [ -f /out/hit ]; then
  echo "PROBE_RESULT: FLAG_REACHED"
  cat /out/hit
else
  echo "PROBE_RESULT: no-flag"
fi
rm -rf "$W"
