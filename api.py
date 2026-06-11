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
from flask import Flask, jsonify, request, abort, render_template_string, g

DB_PATH  = "/opt/ssh_watcher/watcher.db"
API_PORT = 8888
app = Flask(__name__)


def get_db():
    if 'db' not in g:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()


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
        "ip":            row["ip"],
        "attempts":      row["attempts"],
        "first_seen":    row["first_seen"],
        "last_seen":     row["last_seen"],
        "ai_assessment": row["ai_assessment"],
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
        "abuseipdb": {
            "score":      row["abuseipdb_score"],
            "reports":    row["abuseipdb_reports"],
            "checked_at": row["abuseipdb_checked_at"],
        },
        "greynoise": {
            "classification": row["greynoise_classification"],
            "name":           row["greynoise_name"],
            "noise":          row["greynoise_noise"],
            "riot":           row["greynoise_riot"],
            "checked_at":     row["greynoise_checked_at"],
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
    """All CVEs across all attacker IPs, sorted by CVSS score. Supports ?ip= filter."""
    db      = get_db()
    ip_filter = request.args.get("ip")
    if ip_filter:
        rows = db.execute("""
            SELECT v.ip, v.cve_id, v.cvss, v.summary,
                   a.country, a.org, a.attempts, a.vt_malicious
            FROM vulnerabilities v
            JOIN attackers a ON v.ip = a.ip
            WHERE v.ip = ?
            ORDER BY v.cvss DESC NULLS LAST
        """, (ip_filter,)).fetchall()
    else:
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


@app.route("/api/timeline/<path:ip>")
def timeline(ip):
    """Hourly attack counts for a given IP."""
    db   = get_db()
    rows = db.execute("""
        SELECT strftime('%Y-%m-%dT%H:00:00', ts) as hour, COUNT(*) as cnt
        FROM attempts WHERE ip=?
        GROUP BY hour ORDER BY hour
    """, (ip,)).fetchall()
    return jsonify([{"ts": r["hour"], "cnt": r["cnt"]} for r in rows])


@app.route("/api/attackers/<path:ip>/notify", methods=["POST"])
def mark_notified(ip):
    """Mark an IP as Discord-notified so it isn't re-announced."""
    db = get_db()
    db.execute("UPDATE attackers SET discord_notified=1 WHERE ip=?", (ip,))
    db.commit()
    return jsonify({"ok": True})


@app.route("/ip/<path:ip>")
def ip_detail_page(ip):
    """Human-readable IP detail page — dark-themed, linked from Grafana tables."""
    db  = get_db()
    row = db.execute("""
        SELECT a.*, COUNT(DISTINCT v.cve_id) as vuln_count
        FROM attackers a
        LEFT JOIN vulnerabilities v ON a.ip = v.ip
        WHERE a.ip = ?
        GROUP BY a.ip
    """, (ip,)).fetchone()

    if not row:
        return f"<h2>No data for {ip}</h2>", 404

    scans = db.execute(
        "SELECT scanned_at, open_ports, os_guess FROM scans WHERE ip=? ORDER BY scanned_at DESC LIMIT 1",
        (ip,)
    ).fetchall()

    vulns = db.execute(
        "SELECT cve_id, cvss, summary FROM vulnerabilities WHERE ip=? ORDER BY cvss DESC NULLS LAST",
        (ip,)
    ).fetchall()

    attempts_rows = db.execute(
        "SELECT ts, log_line FROM attempts WHERE ip=? ORDER BY ts DESC LIMIT 25",
        (ip,)
    ).fetchall()

    # Build open ports list from latest scan
    ports_html = ""
    os_guess   = ""
    if scans:
        os_guess = scans[0]["os_guess"] or ""
        ports    = parse_ports(scans[0]["open_ports"])
        if ports:
            rows_p = ""
            for p in ports:
                rows_p += f"<tr><td>{p.get('port','')}</td><td>{p.get('proto','')}</td><td>{p.get('service','')}</td><td>{p.get('version','') or ''}</td></tr>"
            ports_html = f"""
            <table class="data-table">
              <thead><tr><th>Port</th><th>Proto</th><th>Service</th><th>Version</th></tr></thead>
              <tbody>{rows_p}</tbody>
            </table>"""
        else:
            ports_html = "<p class='muted'>No open ports found by nmap.</p>"
    else:
        ports_html = "<p class='muted'>No nmap scan data.</p>"

    # Build CVE rows
    def cvss_class(score):
        if score is None: return "cvss-none"
        if score >= 9.0:  return "cvss-critical"
        if score >= 7.0:  return "cvss-high"
        if score >= 4.0:  return "cvss-medium"
        return "cvss-low"

    vulns_html = ""
    for v in vulns:
        score    = v["cvss"]
        score_s  = f"{score:.1f}" if score is not None else "N/A"
        cls      = cvss_class(score)
        summary  = (v["summary"] or "")[:200] + ("…" if len(v["summary"] or "") > 200 else "")
        vulns_html += f"""<tr>
          <td><a class="cve-link" href="https://nvd.nist.gov/vuln/detail/{v['cve_id']}" target="_blank">{v['cve_id']}</a></td>
          <td><span class="cvss-badge {cls}">{score_s}</span></td>
          <td class="summary-cell">{summary}</td>
        </tr>"""

    # Build recent attempts rows
    attempts_html = ""
    for a in attempts_rows:
        attempts_html += f"<tr><td class='ts'>{a['ts'][:19].replace('T',' ')}</td><td class='logline'>{a['log_line']}</td></tr>"

    # Stat helpers
    def stat(label, value, cls=""):
        return f'<div class="stat-card {cls}"><div class="stat-val">{value}</div><div class="stat-label">{label}</div></div>'

    vt_mal   = row["vt_malicious"]  or 0
    abuse    = row["abuseipdb_score"] or 0
    gn_class = row["greynoise_classification"] or "unknown"
    gn_noise = "Yes" if row["greynoise_noise"] else "No"

    vt_cls    = "danger" if vt_mal >= 5 else ("warn" if vt_mal > 0 else "ok")
    abuse_cls = "danger" if abuse >= 80 else ("warn" if abuse >= 30 else "ok")
    gn_cls    = "danger" if gn_class == "malicious" else ("warn" if gn_class not in ("benign","unknown") else "ok")

    location = ", ".join(filter(None, [row["city"], row["region"], row["country"]]))
    assessment = row["ai_assessment"] or "No assessment available."

    vt_harm = row["vt_harmless"] or 0
    vt_sus  = row["vt_suspicious"] or 0
    vt_rep  = row["vt_reputation"]
    vt_rep_s = (f"+{vt_rep}" if vt_rep and vt_rep > 0 else str(vt_rep)) if vt_rep is not None else "N/A"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>IP Detail — {ip}</title>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      background: #111217;
      color: #d0d0d0;
      font-family: 'Inter', system-ui, sans-serif;
      font-size: 14px;
      line-height: 1.6;
      padding: 24px;
    }}
    a {{ color: #6ea6d4; text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
    .chart-wrap {{ background: #1a1d24; border: 1px solid #2a2d35; border-radius: 8px; padding: 16px; }}
    h1 {{ font-size: 1.8rem; font-weight: 700; color: #f0f0f0; margin-bottom: 4px; }}
    h2 {{ font-size: 1rem; font-weight: 600; color: #aaa; text-transform: uppercase;
          letter-spacing: .08em; margin: 28px 0 12px; border-bottom: 1px solid #2a2d35;
          padding-bottom: 6px; }}
    .subtitle {{ color: #888; font-size: .9rem; margin-bottom: 20px; }}
    .header {{ display: flex; align-items: baseline; gap: 16px; margin-bottom: 8px; }}
    .tag {{ background: #1f2229; border: 1px solid #333; border-radius: 4px;
            padding: 2px 8px; font-size: .78rem; color: #aaa; }}

    /* Stats row */
    .stats-row {{ display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 4px; }}
    .stat-card {{
      background: #1a1d24;
      border: 1px solid #2a2d35;
      border-radius: 8px;
      padding: 14px 20px;
      min-width: 120px;
      flex: 1;
    }}
    .stat-card.danger {{ border-color: #d44; }}
    .stat-card.warn   {{ border-color: #c80; }}
    .stat-card.ok     {{ border-color: #2a2d35; }}
    .stat-val  {{ font-size: 1.6rem; font-weight: 700; color: #fff; }}
    .stat-card.danger .stat-val {{ color: #f77; }}
    .stat-card.warn   .stat-val {{ color: #fc6; }}
    .stat-card.ok     .stat-val {{ color: #8f8; }}
    .stat-label {{ font-size: .75rem; color: #777; text-transform: uppercase; letter-spacing: .06em; }}

    /* Assessment box */
    .assessment {{
      background: #16191f;
      border-left: 3px solid #5b8dd9;
      border-radius: 0 8px 8px 0;
      padding: 14px 18px;
      color: #ccc;
      font-size: .95rem;
      line-height: 1.7;
      margin-bottom: 4px;
    }}

    /* VT breakdown */
    .vt-row {{ display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 4px; }}
    .vt-chip {{
      background: #1a1d24;
      border: 1px solid #2a2d35;
      border-radius: 6px;
      padding: 8px 16px;
      font-size: .85rem;
    }}
    .vt-chip span {{ display: block; font-size: 1.1rem; font-weight: 700; }}
    .vt-chip.red span  {{ color: #f77; }}
    .vt-chip.yel span  {{ color: #fc6; }}
    .vt-chip.grn span  {{ color: #8f8; }}
    .vt-chip.neu span  {{ color: #aaa; }}

    /* Tables */
    .data-table {{
      width: 100%;
      border-collapse: collapse;
      font-size: .85rem;
      margin-bottom: 4px;
    }}
    .data-table th {{
      background: #1a1d24;
      color: #888;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: .06em;
      font-size: .75rem;
      padding: 8px 12px;
      text-align: left;
      border-bottom: 1px solid #2a2d35;
    }}
    .data-table td {{
      padding: 7px 12px;
      border-bottom: 1px solid #1e2128;
      vertical-align: top;
    }}
    .data-table tr:hover td {{ background: #1d2029; }}
    .summary-cell {{ color: #aaa; max-width: 500px; }}
    .ts      {{ white-space: nowrap; color: #888; padding-right: 16px; }}
    .logline {{ font-family: monospace; font-size: .8rem; word-break: break-all; }}
    .muted   {{ color: #666; font-style: italic; }}
    .cve-link {{ font-family: monospace; font-size: .85rem; }}

    /* CVSS badges */
    .cvss-badge {{
      display: inline-block;
      padding: 2px 8px;
      border-radius: 4px;
      font-weight: 700;
      font-size: .8rem;
      white-space: nowrap;
    }}
    .cvss-critical {{ background: #5c1010; color: #f99; }}
    .cvss-high     {{ background: #5c3010; color: #fc9; }}
    .cvss-medium   {{ background: #4a4000; color: #fe5; }}
    .cvss-low      {{ background: #1a3a1a; color: #8f8; }}
    .cvss-none     {{ background: #2a2d35; color: #888; }}

    /* External links */
    .ext-links {{ display: flex; gap: 10px; flex-wrap: wrap; margin-top: 8px; }}
    .ext-btn {{
      background: #1f2229;
      border: 1px solid #333;
      border-radius: 6px;
      padding: 6px 14px;
      font-size: .82rem;
      color: #6ea6d4;
      cursor: pointer;
    }}
    .ext-btn:hover {{ background: #272c36; border-color: #6ea6d4; }}
    .section {{ margin-bottom: 8px; }}
  </style>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
</head>
<body>
  <div class="header">
    <h1>{ip}</h1>
    <span class="tag">{row['asn'] or ''}</span>
    <span class="tag">{row['org'] or ''}</span>
  </div>
  <div class="subtitle">📍 {location} &nbsp;·&nbsp; ISP: {row['isp'] or 'unknown'}</div>
  <div class="subtitle">
    First seen: {(row['first_seen'] or '')[:19].replace('T',' ')} UTC &nbsp;·&nbsp;
    Last seen: {(row['last_seen'] or '')[:19].replace('T',' ')} UTC
    {f'&nbsp;·&nbsp; OS guess: <strong>{os_guess}</strong>' if os_guess else ''}
  </div>

  <div class="ext-links">
    <a class="ext-btn" href="https://www.abuseipdb.com/check/{ip}" target="_blank">🔍 AbuseIPDB</a>
    <a class="ext-btn" href="https://www.shodan.io/host/{ip}" target="_blank">🔍 Shodan</a>
    <a class="ext-btn" href="https://www.virustotal.com/gui/ip-address/{ip}" target="_blank">🔍 VirusTotal</a>
    <a class="ext-btn" href="https://viz.greynoise.io/ip/{ip}" target="_blank">🔍 GreyNoise</a>
  </div>

  <h2>Assessment</h2>
  <div class="section">
    <div class="assessment">{assessment}</div>
  </div>

  <h2>Threat Scores</h2>
  <div class="stats-row">
    {stat("Attempts", row['attempts'])}
    {stat("VT Malicious", vt_mal, vt_cls)}
    {stat("AbuseIPDB", f"{abuse}%", abuse_cls)}
    {stat("GreyNoise", gn_class.title(), gn_cls)}
    {stat("Noise", gn_noise)}
    {stat("CVEs Found", row['vuln_count'])}
  </div>

  <h2>VirusTotal Breakdown</h2>
  <div class="vt-row">
    <div class="vt-chip red"><span>{vt_mal}</span>Malicious</div>
    <div class="vt-chip yel"><span>{vt_sus}</span>Suspicious</div>
    <div class="vt-chip grn"><span>{vt_harm}</span>Harmless</div>
    <div class="vt-chip neu"><span>{vt_rep_s}</span>Reputation</div>
  </div>

  <h2>Open Ports (nmap)</h2>
  <div class="section">{ports_html}</div>

  <h2>Vulnerabilities ({row['vuln_count']} CVEs)</h2>
  <div class="section">
  {'<table class="data-table"><thead><tr><th>CVE</th><th>CVSS</th><th>Summary</th></tr></thead><tbody>' + vulns_html + '</tbody></table>' if vulns_html else "<p class='muted'>No CVEs found.</p>"}
  </div>

  <h2>Attack Timeline</h2>
  <div class="section">
    <div class="chart-wrap"><canvas id="timeline-chart" height="80"></canvas></div>
  </div>

  <h2>Recent Login Attempts (last 25)</h2>
  <div class="section">
  {'<table class="data-table"><thead><tr><th>Timestamp</th><th>Log Line</th></tr></thead><tbody>' + attempts_html + '</tbody></table>' if attempts_html else "<p class='muted'>No attempts recorded.</p>"}
  </div>

<script>
fetch('/api/timeline/{ip}')
  .then(r => r.json())
  .then(data => {{
    if (!data.length) return;
    const labels = data.map(d => d.ts.slice(5,16).replace('T',' '));
    const counts = data.map(d => d.cnt);
    new Chart(document.getElementById('timeline-chart'), {{
      type: 'bar',
      data: {{
        labels,
        datasets: [{{
          label: 'Attempts',
          data: counts,
          backgroundColor: 'rgba(91,141,217,0.5)',
          borderColor:     'rgba(91,141,217,1)',
          borderWidth: 1
        }}]
      }},
      options: {{
        responsive: true,
        plugins: {{ legend: {{ display: false }} }},
        scales: {{
          x: {{ ticks: {{ color: '#888', maxRotation: 60, font: {{ size: 10 }} }} }},
          y: {{ ticks: {{ color: '#888' }}, grid: {{ color: '#2a2d35' }}, beginAtZero: true }}
        }}
      }}
    }});
  }});
</script>
</body>
</html>"""
    return html


@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": str(e)}), 404

@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "Internal server error"}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=API_PORT, debug=False)
