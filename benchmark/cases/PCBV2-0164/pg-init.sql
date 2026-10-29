-- Extensions Parse Server's Postgres adapter may rely on. postgis is already
-- enabled by the postgis image; pgcrypto is harmless-if-unused but avoids
-- schema-init surprises on older Parse versions.
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS postgis;
