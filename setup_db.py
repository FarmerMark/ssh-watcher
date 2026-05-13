#!/usr/bin/env python3
"""
setup_db.py
Create or migrate the watcher.db schema to the current version.
Safe to run multiple times — uses ALTER TABLE only for missing columns.
"""

import sqlite3
import os
import sys
import stat
import logging

DB_PATH      = "/opt/ssh_watcher/watcher.db"
GRAFANA_GID  = "grafana"

logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(message)s",
                    handlers=[logging.StreamHandler(sys.stdout)])
log = logging.getLogger("setup_db")


def setup():
    log.info(f"Opening database: {DB_PATH}")
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")

    # ── Create tables ─────────────────────────────────────────────────────────
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS attackers (
            ip                      TEXT PRIMARY KEY,
            first_seen              TEXT NOT NULL,
            last_seen               TEXT NOT NULL,
            attempts                INTEGER DEFAULT 1,
            -- Geolocation (ip-api.com)
            country                 TEXT,
            region                  TEXT,
            city                    TEXT,
            lat                     REAL,
            lon                     REAL,
            isp                     TEXT,
            org                     TEXT,
            asn                     TEXT,
            -- VirusTotal
            vt_malicious            INTEGER,
            vt_suspicious           INTEGER,
            vt_harmless             INTEGER,
            vt_reputation           INTEGER,
            vt_checked_at           TEXT,
            -- Shodan
            shodan_checked_at       TEXT,
            -- AbuseIPDB
            abuseipdb_score         INTEGER,
            abuseipdb_reports       INTEGER,
            abuseipdb_categories    TEXT,
            abuseipdb_checked_at    TEXT,
            -- GreyNoise
            greynoise_classification TEXT,
            greynoise_name          TEXT,
            greynoise_tags          TEXT,
            greynoise_noise         INTEGER,
            greynoise_riot          INTEGER,
            greynoise_checked_at    TEXT,
            -- AI assessment
            ai_assessment           TEXT
        );

        CREATE TABLE IF NOT EXISTS scans (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ip          TEXT NOT NULL,
            scanned_at  TEXT NOT NULL,
            open_ports  TEXT,
            os_guess    TEXT,
            raw_xml     TEXT,
            FOREIGN KEY (ip) REFERENCES attackers(ip)
        );

        CREATE TABLE IF NOT EXISTS attempts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ip          TEXT NOT NULL,
            ts          TEXT NOT NULL,
            log_line    TEXT,
            FOREIGN KEY (ip) REFERENCES attackers(ip)
        );

        CREATE TABLE IF NOT EXISTS vulnerabilities (
            ip          TEXT NOT NULL,
            cve_id      TEXT NOT NULL,
            cvss        REAL,
            summary     TEXT,
            PRIMARY KEY (ip, cve_id),
            FOREIGN KEY (ip) REFERENCES attackers(ip)
        );

        CREATE INDEX IF NOT EXISTS idx_attempts_ip ON attempts(ip);
        CREATE INDEX IF NOT EXISTS idx_scans_ip    ON scans(ip);
        CREATE INDEX IF NOT EXISTS idx_vulns_ip    ON vulnerabilities(ip);
    """)

    # ── Migrate existing DB: add any missing columns ───────────────────────────
    existing = {row[1] for row in conn.execute("PRAGMA table_info(attackers)")}
    migrations = [
        ("country",                  "TEXT"),
        ("region",                   "TEXT"),
        ("city",                     "TEXT"),
        ("lat",                      "REAL"),
        ("lon",                      "REAL"),
        ("isp",                      "TEXT"),
        ("org",                      "TEXT"),
        ("asn",                      "TEXT"),
        ("vt_malicious",             "INTEGER"),
        ("vt_suspicious",            "INTEGER"),
        ("vt_harmless",              "INTEGER"),
        ("vt_reputation",            "INTEGER"),
        ("vt_checked_at",            "TEXT"),
        ("shodan_checked_at",        "TEXT"),
        ("abuseipdb_score",          "INTEGER"),
        ("abuseipdb_reports",        "INTEGER"),
        ("abuseipdb_categories",     "TEXT"),
        ("abuseipdb_checked_at",     "TEXT"),
        ("greynoise_classification", "TEXT"),
        ("greynoise_name",           "TEXT"),
        ("greynoise_tags",           "TEXT"),
        ("greynoise_noise",          "INTEGER"),
        ("greynoise_riot",           "INTEGER"),
        ("greynoise_checked_at",     "TEXT"),
        ("ai_assessment",            "TEXT"),
    ]
    for col, typedef in migrations:
        if col not in existing:
            conn.execute(f"ALTER TABLE attackers ADD COLUMN {col} {typedef}")
            log.info(f"  Migrated: added column '{col}'")

    conn.commit()
    conn.close()
    log.info("Schema up to date.")

    # ── Permissions: grafana needs read access ─────────────────────────────────
    try:
        import grp
        gid = grp.getgrnam(GRAFANA_GID).gr_gid
        os.chown(DB_PATH, 0, gid)           # root:grafana
        os.chmod(DB_PATH, 0o664)            # rw-rw-r--
        # Also fix WAL files if present
        for ext in ("-wal", "-shm"):
            p = DB_PATH + ext
            if os.path.exists(p):
                os.chown(p, 0, gid)
                os.chmod(p, 0o664)
        log.info(f"Permissions set: root:{GRAFANA_GID} 664")
    except KeyError:
        log.warning(f"Group '{GRAFANA_GID}' not found — skipping permission set (run after Grafana install)")
    except PermissionError:
        log.warning("Permission denied setting file ownership — re-run as root")

    log.info(f"Database ready: {DB_PATH}")


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Run as root: sudo python3 setup_db.py")
        sys.exit(1)
    setup()
