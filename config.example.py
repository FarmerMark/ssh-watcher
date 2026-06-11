# config.py — SSH Watcher API keys and settings
# Copy this file to config.py and fill in your values.
# config.py is gitignored — never commit real keys.

# ── Paths ─────────────────────────────────────────────────────────────────────
AUTH_LOG = "/var/log/auth.log"
DB_PATH  = "/opt/ssh_watcher/watcher.db"
LOG_FILE = "/opt/ssh_watcher/watcher.log"

# ── API Keys ──────────────────────────────────────────────────────────────────
# VirusTotal — https://www.virustotal.com → Account → API Key
VT_API_KEY = "YOUR_VIRUSTOTAL_API_KEY"

# Shodan — https://account.shodan.io
SHODAN_KEY = "YOUR_SHODAN_API_KEY"

# AbuseIPDB — https://www.abuseipdb.com/account/api
ABUSEIPDB_KEY = "YOUR_ABUSEIPDB_API_KEY"

# GreyNoise — https://viz.greynoise.io → Account → API Access
GREYNOISE_KEY = "YOUR_GREYNOISE_API_KEY"

# ── Discord ──────────────────────────────────────────────────────────────────
# Bot token from https://discord.com/developers/applications → Bot → Token
DISCORD_TOKEN      = "YOUR_DISCORD_BOT_TOKEN"
DISCORD_CHANNEL_ID = "YOUR_CHANNEL_ID"

# ── Tuning ────────────────────────────────────────────────────────────────────
RESCAN_HRS   = 24    # Hours before re-scanning same IP
WORKERS      = 3     # Parallel enrichment workers
NMAP_TIMEOUT = 120   # Seconds per nmap scan
API_PORT     = 8888  # REST API port
