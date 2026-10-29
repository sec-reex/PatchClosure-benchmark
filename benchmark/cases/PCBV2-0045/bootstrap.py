#!/usr/bin/env python3
"""PatchClosure-Bench init for the REAL Apache Superset (INJ-01-superset-denylist).

Runs ONCE at container start, inside the real Superset app context, AFTER `superset db upgrade`
and `superset init`. It uses Superset's OWN models/security-manager (no source lift) to:

  1. Seed ${PCB_FLAG} into a `pcb_secret` table in the REAL analytics postgres sidecar
     (the only thing the denylisted query_to_xml() can exfiltrate).
  2. Register that postgres as a REAL Superset "analytics" database connection (expose_in_sqllab).
  3. Create an admin (for CSRF/login plumbing) and a LOW-PRIV SQL-Lab user (`analyst`) whose
     role can use SQL Lab against the analytics DB but is NOT an admin.

The denylist itself is NOT touched here; it is the real Superset guard configured via
superset_config.py::DISALLOWED_SQL_FUNCTIONS and enforced by the installed Superset release.
"""
import os
import sys

ANALYTICS_HOST = os.environ.get("ANALYTICS_HOST", "analytics-db")
ANALYTICS_PORT = int(os.environ.get("ANALYTICS_PORT", "5432"))
ANALYTICS_DB = os.environ.get("ANALYTICS_DB", "analytics")
ANALYTICS_USER = os.environ.get("ANALYTICS_USER", "analytics")
ANALYTICS_PASS = os.environ.get("ANALYTICS_PASS", "analytics")

ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "admin-pw")
LOWPRIV_USER = os.environ.get("LOWPRIV_USER", "analyst")
LOWPRIV_PASS = os.environ.get("LOWPRIV_PASS", "analyst-pw")

FLAG = os.environ.get("PCB_FLAG", "PCBFLAG_missing")


def seed_flag():
    """Plant ${PCB_FLAG} in the analytics postgres. This is the victim secret query_to_xml exfils."""
    import psycopg2
    dsn = (f"host={ANALYTICS_HOST} port={ANALYTICS_PORT} dbname={ANALYTICS_DB} "
           f"user={ANALYTICS_USER} password={ANALYTICS_PASS}")
    conn = psycopg2.connect(dsn)
    conn.autocommit = True
    with conn.cursor() as cur:
        cur.execute("CREATE TABLE IF NOT EXISTS pcb_secret (val text)")
        cur.execute("DELETE FROM pcb_secret")
        cur.execute("INSERT INTO pcb_secret (val) VALUES (%s)", [FLAG])
    conn.close()
    print(f"[bootstrap] seeded flag into {ANALYTICS_HOST}:{ANALYTICS_PORT}/{ANALYTICS_DB}.pcb_secret",
          flush=True)


def main():
    seed_flag()

    from superset.app import create_app
    app = create_app()
    with app.app_context():
        from superset import appbuilder, db
        from superset.models.core import Database
        sm = appbuilder.sm

        # --- admin (login/CSRF plumbing) ---
        admin_role = sm.find_role("Admin")
        if not sm.find_user(username=ADMIN_USER):
            sm.add_user(ADMIN_USER, "Admin", "User", f"{ADMIN_USER}@pcb.local",
                        admin_role, password=ADMIN_PASS)
            print("[bootstrap] created admin user", flush=True)

        # --- register the REAL analytics postgres as a Superset database connection ---
        uri = (f"postgresql+psycopg2://{ANALYTICS_USER}:{ANALYTICS_PASS}"
               f"@{ANALYTICS_HOST}:{ANALYTICS_PORT}/{ANALYTICS_DB}")
        database = db.session.query(Database).filter_by(database_name="analytics").first()
        if not database:
            database = Database(database_name="analytics")
            database.set_sqlalchemy_uri(uri)
            database.expose_in_sqllab = True
            database.allow_ctas = False
            database.allow_cvas = False
            database.allow_dml = False
            db.session.add(database)
            db.session.commit()
            # Superset creates the [analytics].(id:N) database_access PVM on add; ensure it exists.
            sm.add_permission_view_menu("database_access", database.perm)
            db.session.commit()
            print(f"[bootstrap] registered analytics DB id={database.id} perm={database.perm}",
                  flush=True)

        # --- LOW-PRIV SQL-Lab role: sql_lab + Gamma perms + access to the analytics DB only ---
        low_role = sm.add_role("PCB_Analyst")
        src_perms = []
        for rn in ("sql_lab", "Gamma"):
            r = sm.find_role(rn)
            if r:
                src_perms += list(r.permissions)
        # database_access on the analytics DB (so the low-priv user may query it in SQL Lab)
        dbperm = sm.find_permission_view_menu("database_access", database.perm)
        if dbperm:
            src_perms.append(dbperm)
        for p in src_perms:
            if p and p not in low_role.permissions:
                low_role.permissions.append(p)
        db.session.commit()

        if not sm.find_user(username=LOWPRIV_USER):
            sm.add_user(LOWPRIV_USER, "Low", "Priv", f"{LOWPRIV_USER}@pcb.local",
                        low_role, password=LOWPRIV_PASS)
            print("[bootstrap] created low-priv user 'analyst' (role PCB_Analyst)", flush=True)

        db.session.commit()
        print("[bootstrap] done", flush=True)


if __name__ == "__main__":
    sys.exit(main())
