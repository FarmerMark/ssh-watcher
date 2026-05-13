#!/usr/bin/env python3
"""
backfill.py — Process historical auth.log data through the ssh_watcher pipeline.
Reads all past failed login attempts, loads them into the DB, then runs
geo lookups and nmap scans on each unique IP.
"""

import re
import sys
import json
import queue
import threading
import logging
from datetime import datetime, timezone, timedelta
from pathlib import Path

# Reuse everything from ssh_watcher
sys.path.insert(0, "/opt/ssh_watcher")
from ssh_watcher import (
    init_db, record_attempt, store_geo, should_scan,
    needs_geo, lookup_geo, run_nmap,
    FAIL_RE, DB_PATH, LOG_FILE, RESCAN_HRS, NMAP_TIMEOUT
)

AUTH_LOG  = "/var/log/auth.log"
WORKERS   = 3

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout),
    ]
)
log = logging.getLogger("backfill")


def scan_worker(scan_queue: queue.Queue, conn, db_lock: threading.Lock, stats: dict):
    while True:
        ip = scan_queue.get()
        try:
            # Geo lookup
            with db_lock:
                do_geo = needs_geo(conn, ip)
            if do_geo:
                geo = lookup_geo(ip)
                if geo:
                    with db_lock:
                        store_geo(conn, ip, geo)
                    log.info(f"[GEO]  {ip} — {geo.get('city','?')}, {geo.get('country','?')} | {geo.get('as','?')}")
                else:
                    log.warning(f"[GEO]  {ip} — lookup failed")

            # nmap scan
            with db_lock:
                do_scan = should_scan(conn, ip)
            if do_scan:
                log.info(f"[SCAN] Scanning {ip} ...")
                ports, os_guess, raw_xml = run_nmap(ip)
                now = datetime.now(timezone.utc).isoformat()
                with db_lock:
                    conn.execute(
                        "INSERT INTO scans(ip, scanned_at, open_ports, os_guess, raw_xml) VALUES(?,?,?,?,?)",
                        (ip, now, json.dumps(ports), os_guess, raw_xml)
                    )
                    conn.commit()
                summary = ", ".join(
                    f"{p['port']}/{p['proto']} ({p['service']} {p['version']}".strip() + ")"
                    for p in ports
                ) or "no open ports"
                log.info(f"[SCAN] {ip} — OS: {os_guess} | {summary}")

            with db_lock:
                stats["done"] += 1
                log.info(f"[PROG] {stats['done']}/{stats['total']} IPs processed")

        except Exception as e:
            log.error(f"[ERR]  {ip}: {e}")
        finally:
            scan_queue.task_done()


def main():
    log.info("=== backfill starting ===")
    conn    = init_db(DB_PATH)
    db_lock = threading.Lock()
    scan_q  = queue.Queue()

    # Parse auth.log
    log.info(f"Reading {AUTH_LOG} ...")
    all_attempts = []  # (ip, line)
    with open(AUTH_LOG, "r", errors="replace") as f:
        for line in f:
            m = FAIL_RE.search(line)
            if m:
                all_attempts.append((m.group(1), line))

    log.info(f"Found {len(all_attempts)} failed login entries")

    # Insert all attempts into DB
    log.info("Loading into database ...")
    seen_ips = set()
    for ip, line in all_attempts:
        with db_lock:
            record_attempt(conn, ip, line)
        seen_ips.add(ip)

    unique_ips = len(seen_ips)
    log.info(f"Loaded {len(all_attempts)} attempts from {unique_ips} unique IPs")

    # Queue unique IPs for geo + scan
    stats = {"done": 0, "total": unique_ips}
    for ip in seen_ips:
        scan_q.put(ip)

    # Start workers
    for i in range(WORKERS):
        t = threading.Thread(
            target=scan_worker,
            args=(scan_q, conn, db_lock, stats),
            daemon=True,
            name=f"worker-{i}"
        )
        t.start()

    log.info(f"Processing {unique_ips} unique IPs with {WORKERS} workers ...")
    log.info("(nmap scans take time — grab a coffee ☕)")
    scan_q.join()
    log.info("=== backfill complete ===")

    # Summary
    total_ips      = conn.execute("SELECT COUNT(*) FROM attackers").fetchone()[0]
    total_attempts = conn.execute("SELECT COALESCE(SUM(attempts),0) FROM attackers").fetchone()[0]
    total_scans    = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    geo_done       = conn.execute("SELECT COUNT(*) FROM attackers WHERE country IS NOT NULL").fetchone()[0]
    log.info(f"DB summary — IPs: {total_ips} | Attempts: {total_attempts} | Scans: {total_scans} | Geo: {geo_done}")


if __name__ == "__main__":
    main()
