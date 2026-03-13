#!/usr/bin/env python3
# block-api.py — Block Management API for the SOC Dashboard
# Serves on localhost:8089 (proxied by Caddy at /api/blocks/*)
# Install: copy to /var/ossec/active-response/block-api.py
# Run: python3 /var/ossec/active-response/block-api.py
# Systemd: create a service unit or run via screen/tmux

import ipaddress
import json
import logging
import subprocess
import time
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

BANS_FILE = "/var/ossec/active-response/progressive-bans.json"
HOST = "127.0.0.1"
PORT = 8089
# Set to the SOC dashboard origin to restrict cross-origin access
ALLOWED_ORIGIN = "https://soc.your-domain.com"

logging.basicConfig(
    filename="/var/ossec/logs/block-api.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger("block-api")


def load_bans():
    try:
        with open(BANS_FILE) as f:
            return json.load(f)
    except Exception:
        return []


def save_bans(bans):
    with open(BANS_FILE, "w") as f:
        json.dump(bans, f, indent=2)


def format_duration(seconds):
    if seconds >= 86400:
        return f"{seconds // 86400}j"
    if seconds >= 3600:
        return f"{seconds // 3600}h"
    return f"{seconds // 60}min"


def validate_ip(ip_str):
    """Validate that the string is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


class BlockAPIHandler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        logger.info("%s - %s", self.client_address[0], format % args)

    def send_json(self, code, data):
        body = json.dumps(data).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", ALLOWED_ORIGIN)
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", ALLOWED_ORIGIN)
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        path = urlparse(self.path).path.rstrip("/")
        if path == "/blocked":
            self.handle_get_blocked()
        else:
            self.send_json(404, {"error": "Not found"})

    def do_POST(self):
        path = urlparse(self.path).path.rstrip("/")
        if path == "/unblock":
            self.handle_post_unblock()
        else:
            self.send_json(404, {"error": "Not found"})

    def handle_get_blocked(self):
        now = int(time.time())
        bans = load_bans()
        result = []
        for b in bans:
            expires_at = b.get("expires_at", 0)
            banned_at = b.get("banned_at", 0)
            if expires_at <= 0 or expires_at <= now:
                continue  # Not currently banned
            time_remaining = expires_at - now
            duration = b.get("ban_duration_seconds", 0)
            result.append({
                "ip": b.get("ip", ""),
                "offense_count": b.get("offense_count", 1),
                "ban_duration_seconds": duration,
                "ban_duration_label": format_duration(duration),
                "banned_at": banned_at,
                "expires_at": expires_at,
                "time_remaining": time_remaining,
                "reason": b.get("reason", ""),
                "status": "active",
            })
        result.sort(key=lambda x: x["expires_at"], reverse=True)
        self.send_json(200, {"blocked": result, "count": len(result)})

    def handle_post_unblock(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            data = json.loads(body)
            ip = data.get("ip", "").strip()
        except Exception:
            self.send_json(400, {"error": "Invalid JSON body"})
            return

        if not ip or not validate_ip(ip):
            self.send_json(400, {"error": "Invalid IP address"})
            return

        bans = load_bans()
        found = False
        for b in bans:
            if b.get("ip") == ip:
                b["expires_at"] = 0
                b["banned_at"] = 0
                found = True
                break

        if not found:
            self.send_json(404, {"error": "IP not found in ban list"})
            return

        # Remove iptables rules
        subprocess.run(
            ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            ["iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"],
            stderr=subprocess.DEVNULL,
        )

        save_bans(bans)
        logger.info("UNBLOCKED %s via API", ip)
        self.send_json(200, {"success": True, "ip": ip, "message": f"{ip} unblocked successfully"})


if __name__ == "__main__":
    if not os.path.exists(BANS_FILE):
        save_bans([])
    server = HTTPServer((HOST, PORT), BlockAPIHandler)
    logger.info("Block API listening on %s:%d", HOST, PORT)
    print(f"Block API listening on {HOST}:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()

