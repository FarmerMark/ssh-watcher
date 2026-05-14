#!/usr/bin/env python3
"""
ssh_watcher.py
Stream auth.log → extract failed-login IPs → geo lookup → nmap fingerprint
→ Shodan vuln lookup → VirusTotal reputation → SQLite
"""

import re
import subprocess
import sqlite3
import threading
import queue
import json
import sys
import time
import logging
import urllib.request
import urllib.error
import xml.etree.ElementTree as ET
from datetime import datetime, timezone, timedelta
from pathlib import Path

# ── Config ────────────────────────────────────────────────────────────────────
AUTH_LOG      = "/var/log/auth.log"
DB_PATH       = "/opt/ssh_watcher/watcher.db"
LOG_FILE      = "/opt/ssh_watcher/watcher.log"
RESCAN_HRS    = 24
WORKERS       = 3
NMAP_TIMEOUT  = 120
GEO_TIMEOUT   = 10
VT_TIMEOUT    = 15
SHODAN_TIMEOUT= 15
GEO_API       = "http://ip-api.com/json/{}?fields=status,country,regionName,city,lat,lon,isp,org,as"
VT_API_KEY        = "c1e3505114243969fe2cfcf0acc915f1ff09b338c837dedd60a58caae274647d"
SHODAN_KEY        = "sre2H1tHuQGe2OTsT9FqjGkUdpTdajQZ"
ABUSEIPDB_KEY     = "798cbbadff61d1b41dbbc82d9c9d7dfb480e2ede115622da90f8321d2aeaea88cad426e2ebdebc54"
GREYNOISE_KEY     = "ch0lumVMon9I6MiglbHDwqGnxx3T01NXxfTy4PUk18CO7u7BcAuPt5OthHwtOe8T"

FAIL_RE = re.compile(
    r'(?:Invalid user \S+ from|'
    r'Failed password for (?:invalid user )?\S+ from|'
    r'Connection closed by invalid user \S+)'
    r'\s+(\d{1,3}(?:\.\d{1,3}){3})'
)

# ── Logging ───────────────────────────────────────────────────────────────────
Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout),
    ]
)
log = logging.getLogger("ssh_watcher")


# ── Database ──────────────────────────────────────────────────────────────────
def init_db(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS attackers (
            ip              TEXT PRIMARY KEY,
            first_seen      TEXT NOT NULL,
            last_seen       TEXT NOT NULL,
            attempts        INTEGER DEFAULT 1,
            country         TEXT,
            region          TEXT,
            city            TEXT,
            lat             REAL,
            lon             REAL,
            isp             TEXT,
            org             TEXT,
            asn             TEXT
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

        CREATE INDEX IF NOT EXISTS idx_attempts_ip  ON attempts(ip);
        CREATE INDEX IF NOT EXISTS idx_scans_ip     ON scans(ip);
        CREATE INDEX IF NOT EXISTS idx_vulns_ip     ON vulnerabilities(ip);
    """)

    # Migrate: add any missing columns
    existing = {row[1] for row in conn.execute("PRAGMA table_info(attackers)")}
    migrations = [
        ("country",          "TEXT"),
        ("region",           "TEXT"),
        ("city",             "TEXT"),
        ("lat",              "REAL"),
        ("lon",              "REAL"),
        ("isp",              "TEXT"),
        ("org",              "TEXT"),
        ("asn",              "TEXT"),
        ("vt_malicious",     "INTEGER"),
        ("vt_suspicious",    "INTEGER"),
        ("vt_harmless",      "INTEGER"),
        ("vt_reputation",    "INTEGER"),
        ("vt_checked_at",    "TEXT"),
        ("shodan_checked_at","TEXT"),
    ]
    for col, typedef in migrations:
        if col not in existing:
            conn.execute(f"ALTER TABLE attackers ADD COLUMN {col} {typedef}")
            log.info(f"[DB] Migrated: added column '{col}' to attackers")

    conn.commit()
    return conn


def record_attempt(conn, ip, line):
    now = datetime.now(timezone.utc).isoformat()
    existing = conn.execute("SELECT ip FROM attackers WHERE ip=?", (ip,)).fetchone()
    conn.execute(
        "INSERT INTO attackers(ip, first_seen, last_seen, attempts) VALUES(?,?,?,1) "
        "ON CONFLICT(ip) DO UPDATE SET last_seen=excluded.last_seen, attempts=attempts+1",
        (ip, now, now)
    )
    conn.execute("INSERT INTO attempts(ip, ts, log_line) VALUES(?,?,?)", (ip, now, line.strip()))
    conn.commit()
    return existing is None


def store_geo(conn, ip, geo):
    conn.execute(
        "UPDATE attackers SET country=?, region=?, city=?, lat=?, lon=?, isp=?, org=?, asn=? WHERE ip=?",
        (geo.get("country"), geo.get("regionName"), geo.get("city"),
         geo.get("lat"), geo.get("lon"), geo.get("isp"), geo.get("org"), geo.get("as"), ip)
    )
    conn.commit()


def store_virustotal(conn, ip, stats, reputation):
    conn.execute(
        "UPDATE attackers SET vt_malicious=?, vt_suspicious=?, vt_harmless=?, "
        "vt_reputation=?, vt_checked_at=? WHERE ip=?",
        (stats.get("malicious", 0), stats.get("suspicious", 0),
         stats.get("harmless", 0), reputation,
         datetime.now(timezone.utc).isoformat(), ip)
    )
    conn.commit()


def store_vulns(conn, ip, vulns: dict):
    """vulns: {cve_id: {cvss, summary}} from Shodan"""
    for cve_id, data in vulns.items():
        conn.execute(
            "INSERT OR REPLACE INTO vulnerabilities(ip, cve_id, cvss, summary) VALUES(?,?,?,?)",
            (ip, cve_id, data.get("cvss"), data.get("summary", ""))
        )
    conn.execute("UPDATE attackers SET shodan_checked_at=? WHERE ip=?",
                 (datetime.now(timezone.utc).isoformat(), ip))
    conn.commit()


def needs_geo(conn, ip):
    row = conn.execute("SELECT country FROM attackers WHERE ip=?", (ip,)).fetchone()
    return row is not None and row[0] is None


def needs_vt(conn, ip):
    row = conn.execute("SELECT vt_checked_at FROM attackers WHERE ip=?", (ip,)).fetchone()
    return row is not None and row[0] is None


def needs_shodan(conn, ip):
    row = conn.execute("SELECT shodan_checked_at FROM attackers WHERE ip=?", (ip,)).fetchone()
    return row is not None and row[0] is None


def should_scan(conn, ip):
    row = conn.execute(
        "SELECT scanned_at FROM scans WHERE ip=? ORDER BY scanned_at DESC LIMIT 1", (ip,)
    ).fetchone()
    if not row:
        return True
    last = datetime.fromisoformat(row[0])
    if last.tzinfo is None:
        last = last.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc) - last > timedelta(hours=RESCAN_HRS)


# ── Geo Lookup ────────────────────────────────────────────────────────────────
def lookup_geo(ip):
    try:
        req = urllib.request.urlopen(GEO_API.format(ip), timeout=GEO_TIMEOUT)
        data = json.loads(req.read().decode())
        if data.get("status") == "success":
            return data
    except Exception as e:
        log.warning(f"[GEO]  {ip} — {e}")
    return None


# ── VirusTotal ────────────────────────────────────────────────────────────────
def lookup_virustotal(ip):
    """Returns (stats_dict, reputation_int) or (None, None) on failure."""
    try:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        req = urllib.request.Request(url, headers={"x-apikey": VT_API_KEY})
        resp = urllib.request.urlopen(req, timeout=VT_TIMEOUT)
        data = json.loads(resp.read().decode())
        attrs = data["data"]["attributes"]
        stats = attrs.get("last_analysis_stats", {})
        reputation = attrs.get("reputation", 0)
        return stats, reputation
    except urllib.error.HTTPError as e:
        log.warning(f"[VT]   {ip} — HTTP {e.code}: {e.reason}")
    except Exception as e:
        log.warning(f"[VT]   {ip} — {e}")
    return None, None


# ── AbuseIPDB ─────────────────────────────────────────────────────────────────
ABUSE_CATEGORIES = {
    1:"DNS Compromise", 2:"DNS Poisoning", 3:"Fraud Orders", 4:"DDoS Attack",
    5:"FTP Brute-Force", 6:"Ping of Death", 7:"Phishing", 8:"Fraud VoIP",
    9:"Open Proxy", 10:"Web Spam", 11:"Email Spam", 12:"Blog Spam",
    13:"VPN IP", 14:"Port Scan", 15:"Hacking", 16:"SQL Injection",
    17:"Spoofing", 18:"Brute-Force", 19:"Bad Web Bot", 20:"Exploited Host",
    21:"Web App Attack", 22:"SSH", 23:"IoT Targeted",
}

def lookup_abuseipdb(ip):
    """Returns (score, total_reports, category_names) or (None, None, None)."""
    try:
        url  = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90&verbose"
        req  = urllib.request.Request(url, headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"})
        resp = urllib.request.urlopen(req, timeout=VT_TIMEOUT)
        d    = json.loads(resp.read())["data"]
        cats = list({ABUSE_CATEGORIES.get(c, str(c)) for c in (d.get("reports") and
               [r.get("categories",[]) for r in d.get("reports",[])] and
               [cat for sub in [r.get("categories",[]) for r in d.get("reports",[])] for cat in sub])
               or []})
        return d.get("abuseConfidenceScore"), d.get("totalReports"), cats
    except Exception as e:
        log.warning(f"[ABUSE] {ip} — {e}")
    return None, None, None


def store_abuseipdb(conn, ip, score, reports, categories):
    conn.execute(
        "UPDATE attackers SET abuseipdb_score=?, abuseipdb_reports=?, "
        "abuseipdb_categories=?, abuseipdb_checked_at=? WHERE ip=?",
        (score, reports, json.dumps(categories), datetime.now(timezone.utc).isoformat(), ip)
    )
    conn.commit()


def needs_abuseipdb(conn, ip):
    row = conn.execute("SELECT abuseipdb_checked_at FROM attackers WHERE ip=?", (ip,)).fetchone()
    return row is not None and row[0] is None


# ── GreyNoise ──────────────────────────────────────────────────────────────────
def lookup_greynoise(ip):
    """Returns (classification, name, tags, noise, riot) or (None,...) on failure."""
    try:
        url  = f"https://api.greynoise.io/v3/community/{ip}"
        req  = urllib.request.Request(url, headers={"key": GREYNOISE_KEY, "Accept": "application/json"})
        resp = urllib.request.urlopen(req, timeout=VT_TIMEOUT)
        d    = json.loads(resp.read())
        return (
            d.get("classification"),
            d.get("name"),
            d.get("tags", []),
            int(d.get("noise", False)),
            int(d.get("riot", False)),
        )
    except urllib.error.HTTPError as e:
        if e.code == 404:
            # Not in GreyNoise DB — return unknown cleanly
            return "unknown", None, [], 0, 0
        log.warning(f"[GN]   {ip} — HTTP {e.code}")
    except Exception as e:
        log.warning(f"[GN]   {ip} — {e}")
    return None, None, None, None, None


def store_greynoise(conn, ip, classification, name, tags, noise, riot):
    conn.execute(
        "UPDATE attackers SET greynoise_classification=?, greynoise_name=?, "
        "greynoise_tags=?, greynoise_noise=?, greynoise_riot=?, greynoise_checked_at=? WHERE ip=?",
        (classification, name, json.dumps(tags), noise, riot,
         datetime.now(timezone.utc).isoformat(), ip)
    )
    conn.commit()


def needs_greynoise(conn, ip):
    row = conn.execute("SELECT greynoise_checked_at FROM attackers WHERE ip=?", (ip,)).fetchone()
    return row is not None and row[0] is None


# ── Shodan ─────────────────────────────────────────────────────────────────────
def lookup_shodan(ip):
    """Returns dict of {cve_id: {cvss, summary}} or empty dict."""
    try:
        import shodan
        api = shodan.Shodan(SHODAN_KEY)
        host = api.host(ip)
        vulns = host.get("vulns", {})
        # Normalise — Shodan returns {CVE-ID: {cvss, summary, references, ...}}
        result = {}
        # Shodan free tier returns a list of CVE IDs; paid returns a dict with details
        if isinstance(vulns, dict):
            for cve_id, info in vulns.items():
                result[cve_id] = {
                    "cvss":    info.get("cvss", info.get("cvss_v2", 0)),
                    "summary": info.get("summary", ""),
                }
        elif isinstance(vulns, list):
            for cve_id in vulns:
                result[str(cve_id)] = {"cvss": None, "summary": ""}
        ports = host.get("ports", [])
        log.info(f"[SHDN] {ip} — {len(result)} CVEs, ports: {ports}")
        return result
    except Exception as e:
        log.warning(f"[SHDN] {ip} — {e}")
    return {}


# ── nmap ──────────────────────────────────────────────────────────────────────
def run_nmap(ip):
    cmd = [
        "sudo", "nmap", "-sV", "--version-intensity", "5",
        "-O", "--osscan-limit", "-T4", "--top-ports", "1000",
        "-oX", "-", ip
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=NMAP_TIMEOUT)
        raw_xml = result.stdout
    except subprocess.TimeoutExpired:
        log.warning(f"[NMAP] Timeout for {ip}")
        return [], "timeout", ""
    except Exception as e:
        log.error(f"[NMAP] Error for {ip}: {e}")
        return [], "error", ""

    ports, os_guess = [], "unknown"
    try:
        root = ET.fromstring(raw_xml)
        for port_el in root.findall(".//port"):
            state = port_el.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = port_el.find("service")
            ports.append({
                "port":    port_el.get("portid"),
                "proto":   port_el.get("protocol"),
                "service": svc.get("name", "")    if svc is not None else "",
                "product": svc.get("product", "") if svc is not None else "",
                "version": svc.get("version", "") if svc is not None else "",
            })
        best = root.find(".//osmatch")
        if best is not None:
            os_guess = f"{best.get('name', '')} ({best.get('accuracy', '')}%)"
    except ET.ParseError as e:
        log.warning(f"[NMAP] XML parse error for {ip}: {e}")

    return ports, os_guess, raw_xml


# ── Scan Worker ───────────────────────────────────────────────────────────────
def scan_worker(scan_queue, conn, db_lock):
    while True:
        ip = scan_queue.get()
        try:
            # 1. Geo lookup
            with db_lock:
                do_geo = needs_geo(conn, ip)
            if do_geo:
                geo = lookup_geo(ip)
                if geo:
                    with db_lock:
                        store_geo(conn, ip, geo)
                    log.info(f"[GEO]  {ip} — {geo.get('city')}, {geo.get('country')} | {geo.get('as')}")

            # 2. nmap fingerprint
            with db_lock:
                do_scan = should_scan(conn, ip)
            if do_scan:
                log.info(f"[SCAN] Starting nmap for {ip}")
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
                log.info(f"[SCAN] {ip} — OS: {os_guess} | Ports: {summary}")

            # 3. VirusTotal reputation
            with db_lock:
                do_vt = needs_vt(conn, ip)
            if do_vt:
                time.sleep(1)  # VT free tier: 4 req/min
                stats, reputation = lookup_virustotal(ip)
                if stats is not None:
                    with db_lock:
                        store_virustotal(conn, ip, stats, reputation)
                    log.info(
                        f"[VT]   {ip} — malicious:{stats.get('malicious',0)} "
                        f"suspicious:{stats.get('suspicious',0)} "
                        f"reputation:{reputation}"
                    )

            # 4. Shodan vulnerability scan
            with db_lock:
                do_shodan = needs_shodan(conn, ip)
            if do_shodan:
                time.sleep(1)  # Shodan rate limit
                vulns = lookup_shodan(ip)
                with db_lock:
                    store_vulns(conn, ip, vulns)
                if vulns:
                    log.info(f"[SHDN] {ip} — CVEs: {', '.join(list(vulns.keys())[:5])}")
                else:
                    log.info(f"[SHDN] {ip} — no CVEs found")

            # 5. AbuseIPDB
            with db_lock:
                do_abuse = needs_abuseipdb(conn, ip)
            if do_abuse:
                time.sleep(1)
                score, reports, cats = lookup_abuseipdb(ip)
                if score is not None:
                    with db_lock:
                        store_abuseipdb(conn, ip, score, reports, cats)
                    log.info(f"[ABUSE] {ip} — score={score}% reports={reports} cats={cats}")

            # 6. GreyNoise
            with db_lock:
                do_gn = needs_greynoise(conn, ip)
            if do_gn:
                time.sleep(1)
                gn_class, gn_name, gn_tags, noise, riot = lookup_greynoise(ip)
                if gn_class is not None:
                    with db_lock:
                        store_greynoise(conn, ip, gn_class, gn_name, gn_tags, noise, riot)
                    log.info(f"[GN]   {ip} — class={gn_class} name={gn_name} noise={noise} riot={riot}")

            # 7. AI assessment (runs after all data is collected)
            try:
                from assess import generate_assessment
                _attacker_cols = [
                    "ip", "org", "isp", "asn", "country", "city", "attempts",
                    "vt_malicious", "vt_suspicious",
                    "abuseipdb_score", "abuseipdb_reports", "abuseipdb_categories",
                    "greynoise_classification", "greynoise_name", "greynoise_tags",
                    "greynoise_noise", "greynoise_riot",
                ]
                with db_lock:
                    row = conn.execute(
                        "SELECT ip, org, isp, asn, country, city, attempts, "
                        "vt_malicious, vt_suspicious, "
                        "abuseipdb_score, abuseipdb_reports, abuseipdb_categories, "
                        "greynoise_classification, greynoise_name, greynoise_tags, "
                        "greynoise_noise, greynoise_riot "
                        "FROM attackers WHERE ip=?", (ip,)
                    ).fetchone()
                    scan = conn.execute(
                        "SELECT open_ports FROM scans WHERE ip=? ORDER BY scanned_at DESC LIMIT 1", (ip,)
                    ).fetchone()
                    if row:
                        row_dict = dict(zip(_attacker_cols, row))
                        scan_dict = {"open_ports": scan[0]} if scan else None
                        assessment = generate_assessment(row_dict, scan_dict)
                        conn.execute("UPDATE attackers SET ai_assessment=? WHERE ip=?", (assessment, ip))
                        conn.commit()
                        log.info(f"[ASSESS] {ip} — {assessment[:80]}...")
                    else:
                        log.warning(f"[ASSESS] {ip} — row not found in DB")
            except Exception as e:
                log.warning(f"[ASSESS] {ip} — {e}")

        except Exception as e:
            log.error(f"[WORKER] Exception for {ip}: {e}")
        finally:
            scan_queue.task_done()


# ── Log Tailer ────────────────────────────────────────────────────────────────
def tail_log(path, scan_queue, conn, db_lock):
    queued_ips = set()
    log.info(f"[WATCH] Tailing {path} ...")
    proc = subprocess.Popen(
        ["tail", "-F", "-n", "0", path],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
    )
    try:
        for line in proc.stdout:
            m = FAIL_RE.search(line)
            if not m:
                continue
            ip = m.group(1)
            with db_lock:
                record_attempt(conn, ip, line)
            log.info(f"[HIT]  Failed login from {ip}")
            if ip not in queued_ips:
                queued_ips.add(ip)
                scan_queue.put(ip)
                log.info(f"[QUEUE] {ip} queued for enrichment")
    except KeyboardInterrupt:
        log.info("Shutting down...")
        proc.terminate()


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    log.info("=== ssh_watcher starting (with Shodan + VT enrichment) ===")
    conn    = init_db(DB_PATH)
    db_lock = threading.Lock()
    scan_q  = queue.Queue()

    for i in range(WORKERS):
        t = threading.Thread(target=scan_worker, args=(scan_q, conn, db_lock), daemon=True, name=f"scanner-{i}")
        t.start()
        log.info(f"Started scan worker {i+1}/{WORKERS}")

    tail_log(AUTH_LOG, scan_q, conn, db_lock)


if __name__ == "__main__":
    main()
