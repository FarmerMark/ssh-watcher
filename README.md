# SSH Watcher

Monitors SSH brute-force attempts in real time. Every attacker IP is automatically
enriched with geolocation, nmap port scanning, and five OSINT sources, then
synthesised into a plain-English assessment. All data is exposed through a REST API
and visualised in a Grafana dashboard.

```
auth.log ──► ssh_watcher.py ──► SQLite DB ──► api.py (Flask :8888)
                 │                                      │
                 ▼                                      ▼
          Enrichment pipeline                  Grafana dashboard
          ├── ip-api.com  (geo)                ├── World map
          ├── nmap        (ports/OS)           ├── Top attackers table
          ├── VirusTotal  (reputation)         ├── Threat intelligence
          ├── Shodan      (CVEs)               ├── Heatmap scores
          ├── AbuseIPDB   (abuse score)        ├── Country bar chart
          ├── GreyNoise   (classification)     └── Assessment column
          └── assess.py   (AI summary)
```

## Requirements

- Ubuntu 22.04+ (or Debian equivalent)
- Python 3.10+
- `nmap` (run as root for OS detection)
- Grafana 13.x
- API keys for: VirusTotal, Shodan, AbuseIPDB, GreyNoise

---

## Quick Start (automated)

```bash
git clone <repo-url> /opt/ssh_watcher
cd /opt/ssh_watcher
sudo bash install.sh
```

The installer will prompt for your API keys, install all dependencies, initialise
the database, configure Grafana, and start all services.

---

## Manual Setup

### 1. System packages

```bash
sudo apt update
sudo apt install -y nmap python3 python3-venv python3-pip git

# Install Grafana
sudo apt install -y apt-transport-https software-properties-common
wget -q -O - https://apt.grafana.com/gpg.key | sudo apt-key add -
echo "deb https://apt.grafana.com stable main" | sudo tee /etc/apt/sources.list.d/grafana.list
sudo apt update
sudo apt install -y grafana
```

### 2. Directory and Python environment

```bash
sudo mkdir -p /opt/ssh_watcher
sudo chown ubuntu:ubuntu /opt/ssh_watcher   # or your username

cd /opt/ssh_watcher
python3 -m venv venv
venv/bin/pip install flask shodan requests
```

### 3. Configuration

Copy the example config and fill in your API keys:

```bash
cp config.example.py config.py
nano config.py
```

`config.py` fields:

| Key | Where to get it |
|-----|----------------|
| `VT_API_KEY` | https://www.virustotal.com → Account → API Key |
| `SHODAN_KEY` | https://account.shodan.io |
| `ABUSEIPDB_KEY` | https://www.abuseipdb.com/account/api |
| `GREYNOISE_KEY` | https://viz.greynoise.io → Account → API Access |
| `DISCORD_TOKEN` | https://discord.com/developers/applications → Your App → Bot → Token |
| `DISCORD_CHANNEL_ID` | Right-click the target channel in Discord → Copy Channel ID (requires Developer Mode) |
| `SERVER_URL` | Public URL of your server, e.g. `http://1.2.3.4:8888` — used for IP detail links in Discord notifications |

### 4. Database

Initialise the schema:

```bash
sudo python3 setup_db.py
```

This creates `/opt/ssh_watcher/watcher.db` with all tables and columns,
and sets the correct permissions for Grafana to read it.

### 5. Systemd services

```bash
sudo cp ssh_watcher.service     /etc/systemd/system/
sudo cp ssh_watcher_api.service /etc/systemd/system/

sudo systemctl daemon-reload
sudo systemctl enable --now ssh_watcher
sudo systemctl enable --now ssh_watcher_api

# Verify
sudo systemctl status ssh_watcher ssh_watcher_api
```

### 6. Firewall

Replace `YOUR_IP` with your workstation's IP:

```bash
sudo ufw allow from YOUR_IP to any port 3000 proto tcp
sudo ufw reload
```

The REST API (port 8888) listens on localhost only — no firewall rule needed.

> **Note:** Also update your cloud provider's security group (AWS/GCP/Azure) to
> allow inbound TCP 3000 from your IP.

### 7. Grafana

#### 7a. Configure grafana.ini

```bash
sudo tee -a /etc/grafana/grafana.ini << 'EOF'

[auth.anonymous]
enabled = true
org_role = Editor

[feature_toggles]
grafanaAPIServerWithExperimentalAPIs = false

[plugin.yesoreyeram-infinity-datasource]
allow_local_mode = true
EOF
```

#### 7b. Install Infinity datasource plugin

```bash
sudo grafana-cli --pluginsDir /var/lib/grafana/plugins plugins install yesoreyeram-infinity-datasource
sudo systemctl restart grafana-server
sleep 5
```

#### 7c. Create datasource via API

```bash
curl -s -u admin:admin -X POST http://localhost:3000/api/datasources \
  -H "Content-Type: application/json" \
  -d '{
    "name": "SSH Watcher API",
    "type": "yesoreyeram-infinity-datasource",
    "uid":  "ssh-watcher-api",
    "access": "proxy",
    "url": "",
    "jsonData": {
      "baseUrl": "http://localhost:8888",
      "allowedHosts": ["http://localhost:8888"]
    }
  }'
```

#### 7d. Import dashboard

```bash
DASHBOARD=$(cat dashboard.json)
curl -s -u admin:admin -X POST http://localhost:3000/api/dashboards/db \
  -H "Content-Type: application/json" \
  -d "{\"dashboard\": $DASHBOARD, \"overwrite\": true}"
```

> **Note:** After importing, open each panel in the Grafana UI and click Save.
> Grafana 13 requires UI-injected metadata (`global_query_id`, `url_options`)
> that the API import omits. The panels will show "No data" until this step.

#### 7e. Change admin password

```bash
# Replace with your desired password
curl -s -u admin:admin -X PUT http://localhost:3000/api/user/password \
  -H "Content-Type: application/json" \
  -d '{"oldPassword":"admin","newPassword":"yourpassword","confirmNew":"yourpassword"}'
```

---

## Backfill historical data

To enrich all IPs already in the database (after initial install or import):

```bash
# OSINT enrichment: VT, Shodan, AbuseIPDB, GreyNoise
sudo venv/bin/python backfill_enrich.py

# Regenerate AI assessments
sudo venv/bin/python assess.py
```

> VirusTotal free tier allows 4 requests/minute — backfill adds appropriate delays.

---

## Usage

### Dashboard

```
http://<server-ip>:3000/d/ssh-watcher-v3/ssh-watcher
```

No login required (anonymous access enabled, UFW-restricted to your IP).

### CLI queries

```bash
# Top attackers by attempt volume
python3 query.py --top 10

# All data for a specific IP
python3 query.py --ip 114.217.53.0

# Recent activity (last N hours)
python3 query.py --recent 24

# Services found on attacker hosts
python3 query.py --services

# Breakdown by country
python3 query.py --countries
```

### REST API

Base URL: `http://localhost:8888`

| Endpoint | Description |
|----------|-------------|
| `GET /api/summary` | Counts: IPs, attempts, scans, geo, VT malicious, CVEs |
| `GET /api/attackers?limit=N` | Top attackers with all OSINT fields |
| `GET /api/attackers/<ip>` | Full detail for one IP |
| `GET /api/recent?hours=N` | Activity in last N hours with AI assessments |
| `GET /api/countries` | Attempt breakdown by country |
| `GET /api/services` | Service breakdown from nmap scans |
| `GET /api/vulns` | All CVEs found across attacker IPs |
| `GET /api/threats` | Ranked threat summary (VT + CVE + volume) |

---

## Architecture

### Files

| File | Purpose |
|------|---------|
| `ssh_watcher.py` | Main service — tails auth.log, queues IPs for enrichment |
| `api.py` | Flask REST API on port 8888 |
| `assess.py` | Assessment engine — synthesises OSINT into plain English |
| `backfill.py` | One-shot: imports historical auth.log into DB |
| `backfill_enrich.py` | One-shot: runs OSINT enrichment on all existing IPs |
| `query.py` | CLI tool for quick DB queries |
| `setup_db.py` | Creates/migrates DB schema |
| `dashboard.json` | Grafana dashboard export |
| `ssh_watcher.service` | systemd unit for watcher |
| `ssh_watcher_api.service` | systemd unit for API |
| `install.sh` | Automated installer |

### Database tables

| Table | Contents |
|-------|----------|
| `attackers` | One row per IP — geo, VT, AbuseIPDB, GreyNoise, AI assessment |
| `scans` | nmap results per scan (an IP can be scanned multiple times) |
| `attempts` | Every individual failed login event |
| `vulnerabilities` | CVEs per IP from Shodan |

### Enrichment pipeline (per new IP)

```
1. ip-api.com  → country, city, region, lat, lon, ISP, org, ASN
2. nmap        → open ports, service versions, OS fingerprint
3. VirusTotal  → malicious/suspicious/harmless engine counts, reputation score
4. Shodan      → known CVEs (free tier: CVE IDs; paid: CVSS + summaries)
5. AbuseIPDB   → confidence score (0-100%), total community reports, abuse categories
6. GreyNoise   → classification (malicious/benign/unknown), actor name, noise/riot flags
7. assess.py   → synthesise all sources into one plain-English assessment sentence
```

---

## Maintenance

### Check service health

```bash
sudo systemctl status ssh_watcher ssh_watcher_api grafana-server
```

### View live watcher log

```bash
sudo tail -f /opt/ssh_watcher/watcher.log
```

### Re-run assessment for all IPs (e.g. after updating assess.py)

```bash
sudo venv/bin/python assess.py
```

### Add new OSINT source

1. Add lookup function to `ssh_watcher.py` (follow VT/AbuseIPDB pattern)
2. Add `store_*` and `needs_*` functions
3. Add new DB columns to `setup_db.py` migrations list
4. Call from `scan_worker` after existing steps
5. Update `assess.py` to incorporate new data
6. Add to `backfill_enrich.py` for existing IPs
7. Commit: `sudo git add -A && sudo git commit -m "Add <source> enrichment"`

---

## Troubleshooting

### Service won't start
```bash
sudo journalctl -u ssh_watcher -n 50
sudo journalctl -u ssh_watcher_api -n 50
```

### API returns empty
```bash
curl http://localhost:8888/api/summary   # Should return JSON
sudo systemctl restart ssh_watcher_api
```

### Grafana panels show "No data"
- Disable the new k8s query API: ensure `grafanaAPIServerWithExperimentalAPIs = false` is in `grafana.ini`
- Open each panel in the Grafana UI editor and click Apply/Save to inject required Grafana 13 metadata
- Check datasource: `curl -u admin:<pw> http://localhost:3000/api/datasources`

### Grafana login broken after password change
Grafana 13's CLI password reset is unreliable. Reset directly via SQLite:
```bash
python3 - <<EOF
import hashlib, binascii, subprocess

salt     = "h5gzmD4n2w"   # existing salt — get from DB if different
password = "yournewpassword"
key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 10000, dklen=50)
h   = binascii.hexlify(key).decode()

subprocess.run(['sudo', 'sqlite3', '/var/lib/grafana/grafana.db',
    f"UPDATE user SET password='{h}', salt='{salt}' WHERE login='admin';"])
subprocess.run(['sudo', 'sqlite3', '/var/lib/grafana/grafana.db',
    "DELETE FROM login_attempt;"])
print("Done — restart Grafana")
EOF
sudo systemctl restart grafana-server
```

---

## Security notes

- The watcher runs as `root` (required for nmap OS detection and auth.log read)
- The API runs as `ubuntu` and listens on `0.0.0.0:8888` — restrict with UFW if exposing beyond localhost
- Grafana anonymous access is enabled but UFW-restricted to your IP
- API keys are stored in `config.py` which is gitignored — do not commit keys
