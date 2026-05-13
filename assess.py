#!/usr/bin/env python3
"""
assess.py — AI-style assessment generator for attacker IPs.
Uses org/ISP/ASN, VT scores, nmap ports, geo, and attempt volume
to produce a plain-English description of what each IP likely is.
"""

import sqlite3
import json
import re
import sys
import logging

DB_PATH = "/opt/ssh_watcher/watcher.db"
logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(levelname)-8s  %(message)s",
                    handlers=[logging.StreamHandler(sys.stdout)])
log = logging.getLogger("assess")


# ── Classification helpers ────────────────────────────────────────────────────

CLOUD_PATTERNS = [
    # (regex pattern on org+isp+asn,  friendly label)
    (r'google cloud|google llc|googlecloud|as396982',   "GCP instance"),
    (r'amazon|aws|ec2|as16509|as14618',                 "AWS instance"),
    (r'microsoft azure|azure|as8075',                    "Azure instance"),
    (r'digitalocean|as14061',                           "DigitalOcean VPS"),
    (r'linode|akamai.*cloud|as63949',                   "Linode/Akamai VPS"),
    (r'vultr|as20473|as64515',                          "Vultr VPS"),
    (r'hetzner|as24940',                                "Hetzner VPS"),
    (r'ovh|kimsufi|soyoustart|as16276',                 "OVH VPS"),
    (r'ionos|1&1|oneandone|as8560',                     "IONOS cloud server"),
    (r'scaleway|as12876',                               "Scaleway VPS"),
    (r'alibaba|aliyun|as45102|as37963',                 "Alibaba Cloud instance"),
    (r'tencent|as45090',                                "Tencent Cloud instance"),
    (r'baidu|as38365',                                  "Baidu corporate network"),
    (r'huawei cloud|as136907',                          "Huawei Cloud instance"),
    (r'choopa|quadranet|as20473',                       "dedicated hosting/scanner host"),
    (r'leaseweb|as60781|as28753',                       "LeaseWeb VPS"),
]

RESIDENTIAL_PATTERNS = [
    (r'comcast|xfinity|as7922|as7016',    "Comcast residential broadband"),
    (r'at&t|att internet|as7018|as20057', "AT&T residential broadband"),
    (r'verizon|as701|as702',              "Verizon residential broadband"),
    (r'virgin media|as5089',              "Virgin Media broadband"),
    (r'bt group|british telecom|as2856',  "BT residential broadband"),
    (r'sky broadband|as5607',             "Sky broadband"),
    (r'vodafone|as1273',                  "Vodafone broadband"),
    (r'telstra|as1221',                   "Telstra residential broadband"),
    (r'optus|as4804',                     "Optus residential broadband"),
    (r'tpg|as9269',                       "TPG residential broadband"),
    (r'chinanet|china telecom|as4134',    "China Telecom broadband (Chinanet backbone)"),
    (r'china unicom|as4837',              "China Unicom broadband"),
    (r'china mobile|as9808',              "China Mobile broadband"),
]

KNOWN_BAD = [
    (r'choopa|constant',   "dedicated scanning service"),
    (r'censys|shodan',     "security research scanner (Censys/Shodan)"),
]


def classify_host(org: str, isp: str, asn: str) -> tuple[str, str]:
    """Returns (host_type, category) where category is 'cloud', 'residential', 'corporate', 'unknown'."""
    combined = f"{org} {isp} {asn}".lower()

    for pattern, label in KNOWN_BAD:
        if re.search(pattern, combined):
            return label, "scanner"

    for pattern, label in CLOUD_PATTERNS:
        if re.search(pattern, combined):
            return label, "cloud"

    for pattern, label in RESIDENTIAL_PATTERNS:
        if re.search(pattern, combined):
            return label, "residential"

    # Heuristic: if ASN description mentions "broadband", "dsl", "cable", "mobile"
    if re.search(r'broadband|dsl|cable|mobile|telecom|residential', combined):
        return "residential/broadband connection", "residential"

    # If org looks like a named company (not a hosting provider)
    if org and len(org) > 3:
        return f"corporate/business network ({org})", "corporate"

    return "unknown host", "unknown"


def describe_behaviour(attempts: int) -> str:
    if attempts >= 50:
        return "sustained brute-force campaign"
    elif attempts >= 20:
        return "active credential stuffing attack"
    elif attempts >= 5:
        return "opportunistic SSH scan"
    else:
        return "automated single-probe scan"


def describe_vt(malicious: int, suspicious: int) -> str:
    if malicious is None:
        return "no VirusTotal data yet"
    total = (malicious or 0) + (suspicious or 0)
    mal   = malicious or 0
    if mal >= 15:
        return f"flagged by {mal} VT engines — well-known malicious actor"
    elif mal >= 10:
        return f"flagged by {mal} VT engines — confirmed threat"
    elif mal >= 5:
        return f"flagged by {mal} VT engines — known scanner"
    elif mal >= 1:
        return f"flagged by {mal} VT engine(s) — low-level threat"
    else:
        return "no VT detections — possibly newly deployed or unlisted scanner"


def describe_ports(open_ports_json: str) -> str:
    if not open_ports_json:
        return None
    try:
        ports = json.loads(open_ports_json)
    except Exception:
        return None
    if not ports:
        return None
    names = [f"{p['port']}/{p.get('service','?')}" for p in ports[:4]]
    note  = f"open ports: {', '.join(names)}"
    # Flag interesting services
    services = {p.get("service","").lower() for p in ports}
    if "http" in services or "https" in services:
        note += " (web server exposed)"
    if "ftp" in services:
        note += " (FTP exposed)"
    if "telnet" in services:
        note += " (Telnet — very old device)"
    if "rdp" in services or "ms-wbt-server" in services:
        note += " (RDP exposed — Windows host)"
    return note


def describe_abuseipdb(score, reports, categories_json) -> str | None:
    if score is None:
        return None
    cats = []
    try:
        cats = json.loads(categories_json) if categories_json else []
    except Exception:
        pass
    cat_str = f" ({', '.join(cats[:3])})" if cats else ""
    if score >= 90:
        return f"AbuseIPDB confidence {score}% across {reports} reports{cat_str} — highly notorious"
    elif score >= 50:
        return f"AbuseIPDB confidence {score}% from {reports} reports{cat_str}"
    elif score >= 10:
        return f"AbuseIPDB confidence {score}% from {reports} report(s){cat_str}"
    elif reports and reports > 0:
        return f"low AbuseIPDB score ({score}%) but {reports} report(s) on file"
    return None


def describe_greynoise(classification, name, tags_json, noise, riot) -> str | None:
    if classification is None:
        return None
    tags = []
    try:
        tags = json.loads(tags_json) if tags_json else []
    except Exception:
        pass

    if riot:
        return "GreyNoise identifies this as a known legitimate service (false positive risk)"
    if classification == "malicious":
        known_name = name if (name and name.lower() not in ("unknown", "")) else None
        name_str = f" known as \"{known_name}\"" if known_name else ""
        tag_str  = f" [{', '.join(tags[:3])}]" if tags else ""
        return f"GreyNoise classifies as malicious{name_str}{tag_str}"
    if classification == "benign":
        name_str = f" ({name})" if name else ""
        return f"GreyNoise tags as benign internet scanner{name_str} — likely security research, not targeted"
    if noise:
        return "GreyNoise: seen in background internet noise (mass scanner, not targeted)"
    return "not seen by GreyNoise"


def generate_assessment(row: dict, latest_scan: dict = None) -> str:
    org      = row.get("org") or ""
    isp      = row.get("isp") or ""
    asn      = row.get("asn") or ""
    country  = row.get("country") or "unknown country"
    city     = row.get("city") or ""
    attempts = row.get("attempts") or 1
    vt_mal   = row.get("vt_malicious")
    vt_sus   = row.get("vt_suspicious")
    # New intel sources
    abuse_desc = describe_abuseipdb(
        row.get("abuseipdb_score"), row.get("abuseipdb_reports"),
        row.get("abuseipdb_categories")
    )
    gn_desc = describe_greynoise(
        row.get("greynoise_classification"), row.get("greynoise_name"),
        row.get("greynoise_tags"), row.get("greynoise_noise"), row.get("greynoise_riot")
    )

    host_type, category = classify_host(org, isp, asn)
    behaviour = describe_behaviour(attempts)
    vt_desc   = describe_vt(vt_mal, vt_sus)

    location = f"{city}, {country}" if city else country

    # Build the sentence
    if category == "cloud":
        # Is this a legitimate cloud scanner or a compromised instance?
        if (vt_mal or 0) > 5:
            verb = "Compromised"
        else:
            verb = "Possibly compromised"
        sentence = (
            f"{verb} {host_type} in {location} — "
            f"cloud IPs don't legitimately brute-force SSH. "
            f"Running a {behaviour}; {vt_desc}."
        )

    elif category == "residential":
        sentence = (
            f"Likely a compromised home or small-business device on {host_type} "
            f"in {location}. Owner probably unaware. "
            f"Running a {behaviour}; {vt_desc}."
        )

    elif category == "scanner":
        sentence = (
            f"Dedicated scanning infrastructure ({host_type}) in {location}. "
            f"This is what mass internet scanners look like. "
            f"Running a {behaviour}; {vt_desc}."
        )

    elif category == "corporate":
        sentence = (
            f"Originates from a {host_type} in {location}. "
            f"Could be a compromised internal machine or an employee device. "
            f"Running a {behaviour}; {vt_desc}."
        )

    else:
        sentence = (
            f"Origin unclear — {isp or 'unknown ISP'} in {location}. "
            f"Running a {behaviour}; {vt_desc}."
        )

    # Append AbuseIPDB intel
    if abuse_desc:
        sentence += f" {abuse_desc}."

    # Append GreyNoise intel
    if gn_desc:
        sentence += f" {gn_desc}."

    # Append port intel
    if latest_scan:
        port_note = describe_ports(latest_scan.get("open_ports"))
        if port_note:
            sentence += f" Attacker host has {port_note}."

    return sentence


# ── Backfill ──────────────────────────────────────────────────────────────────

def run_backfill():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    # Ensure column exists
    existing = {row[1] for row in conn.execute("PRAGMA table_info(attackers)")}
    if "ai_assessment" not in existing:
        conn.execute("ALTER TABLE attackers ADD COLUMN ai_assessment TEXT")
        conn.commit()
        log.info("Added ai_assessment column")

    ips = conn.execute(
        "SELECT ip, org, isp, asn, country, city, attempts, "
        "vt_malicious, vt_suspicious, "
        "abuseipdb_score, abuseipdb_reports, abuseipdb_categories, "
        "greynoise_classification, greynoise_name, greynoise_tags, "
        "greynoise_noise, greynoise_riot "
        "FROM attackers ORDER BY attempts DESC"
    ).fetchall()

    log.info(f"Generating assessments for {len(ips)} IPs...")
    for row in ips:
        ip = row["ip"]
        scan = conn.execute(
            "SELECT open_ports FROM scans WHERE ip=? ORDER BY scanned_at DESC LIMIT 1", (ip,)
        ).fetchone()

        assessment = generate_assessment(dict(row), dict(scan) if scan else None)
        conn.execute("UPDATE attackers SET ai_assessment=? WHERE ip=?", (assessment, ip))
        log.info(f"  {ip}: {assessment[:80]}...")

    conn.commit()
    log.info("=== Assessment backfill complete ===")
    conn.close()


if __name__ == "__main__":
    run_backfill()
