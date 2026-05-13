#!/usr/bin/env python3
"""
api.py — RESTful API for ssh_watcher data
Runs on port 8888.

Endpoints:
  GET /api/summary
  GET /api/attackers?limit=N
  GET /api/attackers/<ip>
  GET /api/recent?hours=N
  GET /api/services
  GET /api/countries
  GET /api/vulns
  GET /api/threats
"""

import sqlite3, json
from datetime import datetime, timezone, timedelta
from flask import Flask, jsonify, request, abort

DB_PATH  = "/opt/ssh_watcher/watcher.db"
API_PORT = 8888
app = Flask(__name__)


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def parse_ports(ports_json):
    try:
        return json.loads(ports_json) if ports_json else []
    except (json.JSONDecodeError, TypeError):
        return []


def clamp(val, lo, hi, default):
    try:
        return max(lo, min(int(val), hi))
    except (TypeError, ValueError):
        return default


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/api/summary")
def summary():
    db = get_db()
    return jsonify({
        "unique_ips":      db.execute("SELECT COUNT(*) FROM attackers").fetchone()[0],
        "total_attempts":  db.execute("SELECT COALESCE(SUM(attempts),0) FROM attackers").fetchone()[0],
        "nmap_scans":      db.execute("SELECT COUNT(*) FROM scans").fetchone()[0],
        "ips_with_geo":    db.execute("SELECT COUNT(*) FROM attackers WHERE country IS NOT NULL").fetchone()[0],
        "vt_malicious_ips":db.execute("SELECT COUNT(*) FROM attackers WHERE vt_malicious > 0").fetchone()[0],
        "total_cves":      db.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0],
    })


@app.route("/api/attackers")
def attackers():
    limit = clamp(request.args.get("limit"), 1, 1000, 10)
    db    = get_db()
    rows  = db.execute("""
        SELECT a.ip, a.attempts, a.first_seen, a.last_seen,
               a.country, a.region, a.city, a.lat, a.lon, a.isp, a.org, a.asn,
               a.vt_malicious, a.vt_suspicious, a.vt_harmless, a.vt_reputation,
               COUNT(DISTINCT s.id) as scan_count,
               COUNT(DISTINCT v.cve_id) as vuln_count
        FROM attackers a
        LEFT JOIN scans s ON a.ip = s.ip
        LEFT JOIN vulnerabilities v ON a.ip = v.ip
        GROUP BY a.ip
        ORDER BY a.attempts DESC
        LIMIT ?
    """, (limit,)).fetchall()

    return jsonify([{
        "ip":           r["ip"],
        "attempts":     r["attempts"],
        "first_seen":   r["first_seen"],
        "last_seen":    r["last_seen"],
        "scanned":      r["scan_count"] > 0,
        "country":      r["country"],
        "city":         r["city"],
        "region":       r["region"],
        "lat":          r["lat"],
        "lon":          r["lon"],
        "isp":          r["isp"],
        "org":          r["org"],
        "asn":          r["asn"],
        "vt_malicious":  r["vt_malicious"],
        "vt_suspicious": r["vt_suspicious"],
        "vt_harmless":   r["vt_harmless"],
        "vt_reputation": r["vt_reputation"],
        "vuln_count":    r["vuln_count"],
    } for r in rows])


@app.route("/api/attackers/<ip>")
def attacker_detail(ip):
    db  = get_db()
    row = db.execute("""
        SELECT a.*, COUNT(DISTINCT v.cve_id) as vuln_count
        FROM attackers a
        LEFT JOIN vulnerabilities v ON a.ip = v.ip
        WHERE a.ip = ?
        GROUP BY a.ip
    """, (ip,)).fetchone()

    if not row:
        abort(404, description=f"No data found for IP: {ip}")

    scans = db.execute(
        "SELECT scanned_at, open_ports, os_guess FROM scans WHERE ip=? ORDER BY scanned_at DESC LIMIT 10",
        (ip,)
    ).fetchall()

    vulns = db.execute(
        "SELECT cve_id, cvss, summary FROM vulnerabilities WHERE ip=? ORDER BY cvss DESC NULLS LAST",
        (ip,)
    ).fetchall()

    attempts = db.execute(
        "SELECT ts, log_line FROM attempts WHERE ip=? ORDER BY ts DESC LIMIT 20",
        (ip,)
    ).fetchall()

    return jsonify({
        "ip":         row["ip"],
        "attempts":   row["attempts"],
        "first_seen": row["first_seen"],
        "last_seen":  row["last_seen"],
        "geo": {
            "country": row["country"], "region": row["region"], "city": row["city"],
            "lat": row["lat"], "lon": row["lon"],
            "isp": row["isp"], "org": row["org"], "asn": row["asn"],
        },
        "virustotal": {
            "malicious":  row["vt_malicious"],
            "suspicious": row["vt_suspicious"],
            "harmless":   row["vt_harmless"],
            "reputation": row["vt_reputation"],
            "checked_at": row["vt_checked_at"],
        },
        "vulnerabilities": [
            {"cve_id": v["cve_id"], "cvss": v["cvss"], "summary": v["summary"]}
            for v in vulns
        ],
        "scans": [
            {"scanned_at": s["scanned_at"], "os_guess": s["os_guess"],
             "open_ports": parse_ports(s["open_ports"])}
            for s in scans
        ],
        "recent_attempts": [{"ts": a["ts"], "log_line": a["log_line"]} for a in attempts],
    })


@app.route("/api/vulns")
def vulns():
    """All CVEs across all attacker IPs, sorted by CVSS score."""
    db   = get_db()
    rows = db.execute("""
        SELECT v.ip, v.cve_id, v.cvss, v.summary,
               a.country, a.org, a.attempts, a.vt_malicious
        FROM vulnerabilities v
        JOIN attackers a ON v.ip = a.ip
        ORDER BY v.cvss DESC NULLS LAST, a.attempts DESC
    """).fetchall()

    return jsonify([{
        "ip":          r["ip"],
        "cve_id":      r["cve_id"],
        "cvss":        r["cvss"],
        "summary":     r["summary"],
        "country":     r["country"],
        "org":         r["org"],
        "attempts":    r["attempts"],
        "vt_malicious":r["vt_malicious"],
    } for r in rows])


@app.route("/api/threats")
def threats():
    """Ranked threat summary per IP combining VT + CVE count + attempt volume."""
    db   = get_db()
    rows = db.execute("""
        SELECT a.ip, a.country, a.city, a.org, a.attempts,
               a.vt_malicious, a.vt_suspicious, a.vt_reputation,
               COUNT(v.cve_id) as vuln_count,
               COALESCE(MAX(v.cvss), 0) as max_cvss
        FROM attackers a
        LEFT JOIN vulnerabilities v ON a.ip = v.ip
        GROUP BY a.ip
        ORDER BY a.vt_malicious DESC NULLS LAST, vuln_count DESC, a.attempts DESC
    """).fetchall()

    return jsonify([{
        "ip":          r["ip"],
        "country":     r["country"],
        "city":        r["city"],
        "org":         r["org"],
        "attempts":    r["attempts"],
        "vt_malicious":r["vt_malicious"],
        "vt_suspicious":r["vt_suspicious"],
        "vt_reputation":r["vt_reputation"],
        "vuln_count":  r["vuln_count"],
        "max_cvss":    r["max_cvss"],
    } for r in rows])


@app.route("/api/recent")
def recent():
    hours = clamp(request.args.get("hours"), 1, 720, 24)
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    db    = get_db()
    rows  = db.execute("""
        SELECT a.ip, COUNT(t.id) as c, a.country, a.region, a.city, a.asn, a.org,
               a.vt_malicious, a.vt_reputation, a.ai_assessment
        FROM attempts t JOIN attackers a ON t.ip = a.ip
        WHERE t.ts >= ?
        GROUP BY t.ip ORDER BY c DESC LIMIT 100
    """, (since,)).fetchall()

    return jsonify({
        "hours": hours, "since": since, "count": len(rows),
        "results": [{
            "ip":            r["ip"],
            "attempts":      r["c"],
            "country":       r["country"],
            "city":          r["city"],
            "org":           r["org"],
            "ai_assessment": r["ai_assessment"],
        } for r in rows],
    })


@app.route("/api/services")
def services():
    db     = get_db()
    rows   = db.execute("SELECT open_ports FROM scans WHERE open_ports IS NOT NULL").fetchall()
    counts = {}
    for row in rows:
        for p in parse_ports(row["open_ports"]):
            svc = p.get("service") or "unknown"
            counts[svc] = counts.get(svc, 0) + 1
    ranked = sorted(counts.items(), key=lambda x: x[1], reverse=True)
    return jsonify([{"service": s, "count": c} for s, c in ranked])


@app.route("/api/countries")
def countries():
    db   = get_db()
    rows = db.execute("""
        SELECT country, COUNT(*) as unique_ips, SUM(attempts) as total_attempts
        FROM attackers WHERE country IS NOT NULL
        GROUP BY country ORDER BY total_attempts DESC
    """).fetchall()
    return jsonify([{
        "country": r["country"], "unique_ips": r["unique_ips"],
        "total_attempts": r["total_attempts"],
    } for r in rows])


@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": str(e)}), 404

@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "Internal server error"}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=API_PORT, debug=False)
