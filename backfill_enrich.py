#!/usr/bin/env python3
"""
backfill_enrich.py
Run Shodan + VirusTotal enrichment for all IPs that haven't been checked yet.
"""

import sqlite3, json, time, sys, logging, urllib.request, urllib.error
from datetime import datetime, timezone

DB_PATH           = "/opt/ssh_watcher/watcher.db"
VT_API_KEY        = "c1e3505114243969fe2cfcf0acc915f1ff09b338c837dedd60a58caae274647d"
SHODAN_KEY        = "sre2H1tHuQGe2OTsT9FqjGkUdpTdajQZ"
ABUSEIPDB_KEY     = "798cbbadff61d1b41dbbc82d9c9d7dfb480e2ede115622da90f8321d2aeaea88cad426e2ebdebc54"
GREYNOISE_KEY     = "ch0lumVMon9I6MiglbHDwqGnxx3T01NXxfTy4PUk18CO7u7BcAuPt5OthHwtOe8T"

ABUSE_CATEGORIES = {
    1:"DNS Compromise", 2:"DNS Poisoning", 3:"Fraud Orders", 4:"DDoS Attack",
    5:"FTP Brute-Force", 7:"Phishing", 9:"Open Proxy", 10:"Web Spam",
    11:"Email Spam", 14:"Port Scan", 15:"Hacking", 16:"SQL Injection",
    18:"Brute-Force", 19:"Bad Web Bot", 20:"Exploited Host",
    21:"Web App Attack", 22:"SSH", 23:"IoT Targeted",
}

logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(levelname)-8s  %(message)s",
                    handlers=[logging.StreamHandler(sys.stdout)])
log = logging.getLogger("backfill_enrich")


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def lookup_abuseipdb(ip):
    try:
        url  = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90&verbose"
        req  = urllib.request.Request(url, headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"})
        d    = json.loads(urllib.request.urlopen(req, timeout=15).read())["data"]
        cats = list({ABUSE_CATEGORIES.get(c, str(c))
                     for r in d.get("reports", []) for c in r.get("categories", [])})
        return d.get("abuseConfidenceScore"), d.get("totalReports"), cats
    except Exception as e:
        log.warning(f"[ABUSE] {ip} — {e}")
    return None, None, None


def lookup_greynoise(ip):
    try:
        url  = f"https://api.greynoise.io/v3/community/{ip}"
        req  = urllib.request.Request(url, headers={"key": GREYNOISE_KEY, "Accept": "application/json"})
        d    = json.loads(urllib.request.urlopen(req, timeout=15).read())
        return (d.get("classification"), d.get("name"), d.get("tags", []),
                int(d.get("noise", False)), int(d.get("riot", False)))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return "unknown", None, [], 0, 0
        log.warning(f"[GN]   {ip} — HTTP {e.code}")
    except Exception as e:
        log.warning(f"[GN]   {ip} — {e}")
    return None, None, None, None, None


def lookup_virustotal(ip):
    try:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        req = urllib.request.Request(url, headers={"x-apikey": VT_API_KEY})
        resp = urllib.request.urlopen(req, timeout=15)
        data = json.loads(resp.read().decode())
        attrs = data["data"]["attributes"]
        return attrs.get("last_analysis_stats", {}), attrs.get("reputation", 0)
    except urllib.error.HTTPError as e:
        log.warning(f"[VT]   {ip} — HTTP {e.code}")
    except Exception as e:
        log.warning(f"[VT]   {ip} — {e}")
    return None, None


def lookup_shodan(ip):
    try:
        import shodan
        api = shodan.Shodan(SHODAN_KEY)
        host = api.host(ip)
        result = {}

        # Primary: per-service banner vulns — has full CVSS + summaries on free tier
        for svc in host.get("data", []):
            svc_vulns = svc.get("vulns", {})
            if not isinstance(svc_vulns, dict):
                continue
            for cve_id, info in svc_vulns.items():
                if cve_id not in result:
                    result[cve_id] = {
                        "cvss":    info.get("cvss") or info.get("cvss_v2"),
                        "summary": info.get("summary", ""),
                    }

        # Fallback: top-level host['vulns'] for any CVEs not in service data
        top_vulns = host.get("vulns", {})
        if isinstance(top_vulns, dict):
            for cve_id, info in top_vulns.items():
                if cve_id not in result:
                    result[cve_id] = {
                        "cvss":    info.get("cvss") or info.get("cvss_v2"),
                        "summary": info.get("summary", ""),
                    }
        elif isinstance(top_vulns, list):
            for cve_id in top_vulns:
                if str(cve_id) not in result:
                    result[str(cve_id)] = {"cvss": None, "summary": ""}

        return result
    except Exception as e:
        log.warning(f"[SHDN] {ip} — {e}")
    return {}


def main():
    conn = get_conn()
    ips  = [r["ip"] for r in conn.execute("SELECT ip FROM attackers ORDER BY attempts DESC").fetchall()]
    log.info(f"Found {len(ips)} IPs to process")

    for i, ip in enumerate(ips):
        log.info(f"[{i+1}/{len(ips)}] Processing {ip}")

        # VirusTotal
        row = conn.execute("SELECT vt_checked_at FROM attackers WHERE ip=?", (ip,)).fetchone()
        if not row["vt_checked_at"]:
            stats, reputation = lookup_virustotal(ip)
            if stats is not None:
                conn.execute(
                    "UPDATE attackers SET vt_malicious=?, vt_suspicious=?, vt_harmless=?, "
                    "vt_reputation=?, vt_checked_at=? WHERE ip=?",
                    (stats.get("malicious", 0), stats.get("suspicious", 0),
                     stats.get("harmless", 0), reputation,
                     datetime.now(timezone.utc).isoformat(), ip)
                )
                conn.commit()
                log.info(f"  VT: malicious={stats.get('malicious',0)} suspicious={stats.get('suspicious',0)} reputation={reputation}")
            time.sleep(16)  # VT free: 4 req/min = 15s apart
        else:
            log.info(f"  VT: already done")

        # AbuseIPDB
        row = conn.execute("SELECT abuseipdb_checked_at FROM attackers WHERE ip=?", (ip,)).fetchone()
        if not row["abuseipdb_checked_at"]:
            score, reports, cats = lookup_abuseipdb(ip)
            if score is not None:
                conn.execute(
                    "UPDATE attackers SET abuseipdb_score=?, abuseipdb_reports=?, "
                    "abuseipdb_categories=?, abuseipdb_checked_at=? WHERE ip=?",
                    (score, reports, json.dumps(cats), datetime.now(timezone.utc).isoformat(), ip)
                )
                conn.commit()
                log.info(f"  AbuseIPDB: score={score}% reports={reports} categories={cats}")
            time.sleep(2)
        else:
            log.info(f"  AbuseIPDB: already done")

        # GreyNoise
        row = conn.execute("SELECT greynoise_checked_at FROM attackers WHERE ip=?", (ip,)).fetchone()
        if not row["greynoise_checked_at"]:
            gn_class, gn_name, gn_tags, noise, riot = lookup_greynoise(ip)
            if gn_class is not None:
                conn.execute(
                    "UPDATE attackers SET greynoise_classification=?, greynoise_name=?, "
                    "greynoise_tags=?, greynoise_noise=?, greynoise_riot=?, greynoise_checked_at=? WHERE ip=?",
                    (gn_class, gn_name, json.dumps(gn_tags), noise, riot,
                     datetime.now(timezone.utc).isoformat(), ip)
                )
                conn.commit()
                log.info(f"  GreyNoise: class={gn_class} name={gn_name} noise={noise} riot={riot}")
            time.sleep(1)
        else:
            log.info(f"  GreyNoise: already done")

        # Shodan
        row = conn.execute("SELECT shodan_checked_at FROM attackers WHERE ip=?", (ip,)).fetchone()
        if not row["shodan_checked_at"]:
            vulns = lookup_shodan(ip)
            for cve_id, data in vulns.items():
                conn.execute(
                    "INSERT OR REPLACE INTO vulnerabilities(ip, cve_id, cvss, summary) VALUES(?,?,?,?)",
                    (ip, cve_id, data.get("cvss"), data.get("summary", ""))
                )
            conn.execute("UPDATE attackers SET shodan_checked_at=? WHERE ip=?",
                         (datetime.now(timezone.utc).isoformat(), ip))
            conn.commit()
            if vulns:
                log.info(f"  Shodan: {len(vulns)} CVEs — {', '.join(list(vulns.keys())[:5])}")
            else:
                log.info(f"  Shodan: no CVEs")
            time.sleep(1)
        else:
            log.info(f"  Shodan: already done")

    log.info("=== Backfill complete ===")
    # Summary
    vt_done     = conn.execute("SELECT COUNT(*) FROM attackers WHERE vt_checked_at IS NOT NULL").fetchone()[0]
    shdn_done   = conn.execute("SELECT COUNT(*) FROM attackers WHERE shodan_checked_at IS NOT NULL").fetchone()[0]
    total_vulns = conn.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]
    malicious   = conn.execute("SELECT COUNT(*) FROM attackers WHERE vt_malicious > 0").fetchone()[0]
    log.info(f"VT checked: {vt_done}/{len(ips)} | Shodan checked: {shdn_done}/{len(ips)} | CVEs: {total_vulns} | Malicious IPs: {malicious}")


if __name__ == "__main__":
    main()
