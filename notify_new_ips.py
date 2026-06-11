#!/usr/bin/env python3
"""
SSH Watcher — New IP Discord Notifier
Runs every 5 minutes via system cron. No LLM calls. Zero API cost.
Posts directly to Discord using the bot token.
"""

import sqlite3
import urllib.request
import urllib.error
import json
import sys
import os

# Load from config.py if present, else fall back to environment variables
try:
    sys.path.insert(0, os.path.dirname(__file__))
    from config import DISCORD_TOKEN, DISCORD_CHANNEL_ID, DB_PATH
    SERVER_URL = getattr(__import__('config'), 'SERVER_URL', 'http://localhost:8888')
except ImportError:
    DISCORD_TOKEN      = os.environ.get("DISCORD_TOKEN", "")
    DISCORD_CHANNEL_ID = os.environ.get("DISCORD_CHANNEL_ID", "")
    DB_PATH            = "/opt/ssh_watcher/watcher.db"
    SERVER_URL         = os.environ.get("SERVER_URL", "http://localhost:8888")

CHANNEL_ID = DISCORD_CHANNEL_ID
API_URL = f"https://discord.com/api/v10/channels/{CHANNEL_ID}/messages"


def send_discord_message(content: str) -> bool:
    payload = json.dumps({"content": content}).encode("utf-8")
    req = urllib.request.Request(
        API_URL,
        data=payload,
        headers={
            "Authorization": f"Bot {DISCORD_TOKEN}",
            "Content-Type": "application/json",
            "User-Agent": "ssh-watcher-notifier/1.0",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status in (200, 201)
    except urllib.error.HTTPError as e:
        print(f"[notify] Discord HTTP error {e.code}: {e.read().decode()}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"[notify] Discord send error: {e}", file=sys.stderr)
        return False


def main():
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
    except Exception as e:
        print(f"[notify] DB open error: {e}", file=sys.stderr)
        sys.exit(1)

    cur.execute("""
        SELECT ip, country, city, org, attempts,
               abuseipdb_score, vt_malicious, vt_suspicious, ai_assessment
        FROM attackers
        WHERE (discord_notified IS NULL OR discord_notified = 0)
          AND ai_assessment IS NOT NULL
          AND greynoise_checked_at IS NOT NULL
    """)
    rows = cur.fetchall()

    if not rows:
        conn.close()
        return

    for row in rows:
        ip          = row["ip"] or "unknown"
        country     = row["country"] or "?"
        city        = row["city"] or "?"
        org         = row["org"] or "?"
        attempts    = row["attempts"] or 0
        abuse_score = row["abuseipdb_score"] or 0
        vt_mal      = row["vt_malicious"] or 0
        vt_sus      = row["vt_suspicious"] or 0
        assessment  = row["ai_assessment"] or ""

        message = (
            f"🚨 **New SSH Attacker Detected**\n"
            f"**IP:** `{ip}` — [View Details]({SERVER_URL}/ip/{ip})\n"
            f"📍 {city}, {country} — {org}\n"
            f"⚔️ **{attempts}** login attempts\n"
            f"🛡️ AbuseIPDB: **{abuse_score}%** | VT Malicious: **{vt_mal}** | VT Suspicious: **{vt_sus}**\n"
            f"💬 {assessment}"
        )

        if send_discord_message(message):
            cur.execute(
                "UPDATE attackers SET discord_notified = 1 WHERE ip = ?", (ip,)
            )
            conn.commit()
            print(f"[notify] Notified: {ip}")
        else:
            print(f"[notify] Failed to notify: {ip}", file=sys.stderr)

    conn.close()


if __name__ == "__main__":
    main()
