#!/bin/bash
# Postgres init script: creates the canary table (defended resource) and
# the public_data table (the legitimate dataset Superset queries).
# The canary flag is planted from the PCB_FLAG environment variable.
set -e

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    -- Canary table: the defended resource. SQL injection reads from here.
    CREATE TABLE IF NOT EXISTS canary (
        id SERIAL PRIMARY KEY,
        flag TEXT NOT NULL
    );
    INSERT INTO canary (flag) VALUES ('${PCB_FLAG}');

    -- Public data table: the legitimate dataset Superset is configured to query.
    CREATE TABLE IF NOT EXISTS public_data (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        value INTEGER NOT NULL
    );
    INSERT INTO public_data (name, value) VALUES
        ('alpha', 10),
        ('beta', 20),
        ('gamma', 30),
        ('delta', 40),
        ('epsilon', 50);
EOSQL
