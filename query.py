#!/usr/bin/env python3
"""
query.py — Query the ssh_watcher database for analysis
Usage:
    python3 query.py                   # Top attackers summary
    python3 query.py --ip 1.2.3.4     # Detail for a specific IP
    python3 query.py --top 20         # Top N attackers
    python3 query.py --recent 24      # Activity in last N hours
    python3 query.py --services       # Most common services found on attackers
    python3 query.py --countries      # Attacks grouped by country
"""

import sqlite3
import json
import argparse
from datetime import datetime, timezone, timedelta
from collections import Counter

DB_PATH = "/opt/ssh_watcher/watcher.db"


def get_conn():
    return sqlite3.connect(DB_PATH)


def summary(conn):
    total_ips      = conn.execute("SELECT COUNT(*) FROM attackers").fetchone()[0]
    total_attempts = conn.execute("SELECT SUM(attempts) FROM attackers").fetchone()[0] or 0
    total_scans    = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    geo_done       = conn.execute("SELECT COUNT(*) FROM attackers WHERE country IS NOT NULL").fetchone()[0]
    print(f"\n  DATABASE SUMMARY")
    print(f"{'─'*45}")
    print(f"  Unique IPs tracked : {total_ips:,}")
    print(f"  Total attempts     : {total_attempts:,}")
    print(f"  nmap scans done    : {total_scans:,}")
    print(f"  IPs with geo data  : {geo_done:,}")
    print()


def top_attackers(conn, limit=10):
    print(f"\n{'─'*90}")
    print(f"  TOP {limit} ATTACKERS")
    print(f"{'─'*90}")
    print(f"  {'IP':<18} {'ATTEMPTS':>8}  {'COUNTRY':<18} {'CITY':<16} {'ASN/ORG':<25} SCANNED")
    print(f"{'─'*90}")
    rows = conn.execute(
        "SELECT a.ip, a.attempts, a.country, a.city, a.asn, a.org, COUNT(s.id) "
        "FROM attackers a LEFT JOIN scans s ON a.ip=s.ip "
        "GROUP BY a.ip ORDER BY a.attempts DESC LIMIT ?",
        (limit,)
    ).fetchall()
    for ip, attempts, country, city, asn, org, scanned in rows:
        location = country or "?"
        city_str = (city or "?")[:15]
        asn_str  = (asn or org or "?")[:24]
        print(f"  {ip:<18} {attempts:>8}  {location:<18} {city_str:<16} {asn_str:<25} {'✓' if scanned else '—'}")
    print(f"{'─'*90}\n")


def ip_detail(conn, ip):
    row = conn.execute(
        "SELECT ip, attempts, first_seen, last_seen, country, region, city, "
        "lat, lon, isp, org, asn FROM attackers WHERE ip=?",
        (ip,)
    ).fetchone()
    if not row:
        print(f"  No data found for {ip}")
        return

    ip, attempts, first, last, country, region, city, lat, lon, isp, org, asn = row
    print(f"\n{'─'*60}")
    print(f"  IP         : {ip}")
    print(f"  Attempts   : {attempts}")
    print(f"  First seen : {first[:19].replace('T',' ')} UTC")
    print(f"  Last seen  : {last[:19].replace('T',' ')} UTC")

    if country:
        print(f"\n  GEOLOCATION")
        print(f"  Location   : {city or '?'}, {region or '?'}, {country or '?'}")
        if lat and lon:
            print(f"  Coordinates: {lat}, {lon}")
        print(f"  ISP        : {isp or '?'}")
        print(f"  Org        : {org or '?'}")
        print(f"  ASN        : {asn or '?'}")
    else:
        print(f"\n  Geo data not yet available.")

    scans = conn.execute(
        "SELECT scanned_at, open_ports, os_guess FROM scans WHERE ip=? ORDER BY scanned_at DESC LIMIT 3",
        (ip,)
    ).fetchall()

    if scans:
        print(f"\n  SCANS ({len(scans)}):")
        for ts, ports_json, os_guess in scans:
            print(f"    [{ts[:19].replace('T',' ')} UTC]  OS: {os_guess}")
            ports = json.loads(ports_json) if ports_json else []
            if ports:
                for p in ports:
                    ver = f" {p['product']} {p['version']}".strip()
                    print(f"      port {p['port']:>5}/{p['proto']}  {p['service']}{ver}")
            else:
                print("      No open ports found")
    else:
        print("\n  No nmap scans yet.")

    print(f"\n  RECENT ATTEMPTS (last 5):")
    attempt_rows = conn.execute(
        "SELECT ts, log_line FROM attempts WHERE ip=? ORDER BY ts DESC LIMIT 5",
        (ip,)
    ).fetchall()
    for ts, line in attempt_rows:
        print(f"    {ts[:19].replace('T',' ')}  {line[:80]}")
    print(f"{'─'*60}\n")


def recent_activity(conn, hours=24):
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    print(f"\n  Activity in last {hours}h:")
    print(f"{'─'*65}")
    print(f"  {'IP':<18} {'ATTEMPTS':>8}  {'COUNTRY':<18} {'CITY'}")
    print(f"{'─'*65}")
    rows = conn.execute(
        "SELECT a.ip, COUNT(t.id) as c, a.country, a.city "
        "FROM attempts t JOIN attackers a ON t.ip=a.ip "
        "WHERE t.ts >= ? GROUP BY t.ip ORDER BY c DESC LIMIT 20",
        (since,)
    ).fetchall()
    if not rows:
        print("  None.")
    for ip, c, country, city in rows:
        print(f"  {ip:<18} {c:>8}  {(country or '?'):<18} {city or '?'}")
    print()


def service_stats(conn):
    rows = conn.execute("SELECT open_ports FROM scans WHERE open_ports IS NOT NULL").fetchall()
    counter = Counter()
    for (ports_json,) in rows:
        ports = json.loads(ports_json)
        for p in ports:
            label = p['service'] or 'unknown'
            counter[label] += 1

    print(f"\n  TOP SERVICES ON ATTACKER IPs:")
    print(f"{'─'*45}")
    for svc, count in counter.most_common(15):
        bar = "█" * min(count, 30)
        print(f"  {svc:<20} {count:>5}  {bar}")
    print()


def country_stats(conn):
    rows = conn.execute(
        "SELECT country, COUNT(*) as ips, SUM(attempts) as total_attempts "
        "FROM attackers WHERE country IS NOT NULL "
        "GROUP BY country ORDER BY total_attempts DESC LIMIT 20"
    ).fetchall()
    print(f"\n  ATTACKS BY COUNTRY:")
    print(f"{'─'*55}")
    print(f"  {'COUNTRY':<25} {'UNIQUE IPs':>10}  {'ATTEMPTS':>10}")
    print(f"{'─'*55}")
    for country, ips, attempts in rows:
        print(f"  {(country or 'Unknown'):<25} {ips:>10}  {attempts:>10}")
    print()


def main():
    parser = argparse.ArgumentParser(description="Query ssh_watcher database")
    parser.add_argument("--ip",        help="Detail for a specific IP")
    parser.add_argument("--top",       type=int, default=10, help="Top N attackers (default 10)")
    parser.add_argument("--recent",    type=int, help="Activity in last N hours")
    parser.add_argument("--services",  action="store_true", help="Service stats from scans")
    parser.add_argument("--countries", action="store_true", help="Attacks grouped by country")
    args = parser.parse_args()

    conn = get_conn()
    summary(conn)

    if args.ip:
        ip_detail(conn, args.ip)
    elif args.recent is not None:
        recent_activity(conn, args.recent)
    elif args.services:
        service_stats(conn)
    elif args.countries:
        country_stats(conn)
    else:
        top_attackers(conn, args.top)


if __name__ == "__main__":
    main()
