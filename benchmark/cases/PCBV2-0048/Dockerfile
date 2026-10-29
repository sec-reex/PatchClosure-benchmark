# PatchClosure-Bench image recipe for apache-couchdb-cve-2018-8007.
# One Dockerfile, parameterised by base image + blacklist neutralisation:
#   V0  BASE=couchdb:2.1.1  NEUTRALIZE=1  -> models pre-CVE-2017-12636 (no config blacklist)
#   V1  BASE=couchdb:2.1.1  NEUTRALIZE=0  -> stock 2.1.1 (=CVE-2017-12636-patched; -8007 residual) TARGET
#   V2  BASE=couchdb:2.1.2  NEUTRALIZE=0  -> stock 2.1.2 (=CVE-2018-8007-patched)
#
# NEUTRALIZE=1 recompiles ONE stock module (couch_util) with a single function
# (check_config_blacklist/1) turned into a no-op, i.e. the CVE-2017-12636 mitigation is
# simply "not yet present" -- identical to every other line of the 2.1.1 release. The
# patched source is vendored as v0_couch_util.erl (couch_util.erl @ tag 2.1.1 with only
# that function changed) and compiled IN-IMAGE with the release's own erts-6.2 erlc.
# -DPRE18TIMEFEATURES is REQUIRED (as the couch build defines it on erts<18): it selects
# couch_util:unique_monotonic_integer/0's erlang:now/0 branch instead of the OTP18-only
# erlang:unique_integer/1, which is undefined on this erts-6.2 runtime and would otherwise
# crash couch_server (via couch_lru:insert) on the first database open.
ARG BASE=couchdb:2.1.1
FROM ${BASE}

ARG NEUTRALIZE=0
# couch lib dir of the 2.1.1 base (only used when NEUTRALIZE=1, i.e. V0 on couchdb:2.1.1)
ARG COUCH_LIB=/opt/couchdb/lib/couch-2.1.1

COPY v0_couch_util.erl /pcb/couch_util.erl
RUN set -e; \
    if [ "$NEUTRALIZE" = "1" ]; then \
      cd /tmp && ERL_LIBS=/opt/couchdb/lib erlc -DPRE18TIMEFEATURES -o /tmp /pcb/couch_util.erl && \
      cp /tmp/couch_util.beam "${COUCH_LIB}/ebin/couch_util.beam" && \
      echo "[pcb] V0: CVE-2017-12636 config blacklist neutralised in couch_util.beam"; \
    else \
      echo "[pcb] stock blacklist retained"; \
    fi

COPY couchdb-entrypoint.sh /pcb/entrypoint.sh
COPY qs_canary.sh /pcb/qs_canary.sh
RUN chmod +x /pcb/entrypoint.sh /pcb/qs_canary.sh

ENTRYPOINT ["/pcb/entrypoint.sh"]
CMD ["/opt/couchdb/bin/couchdb"]
