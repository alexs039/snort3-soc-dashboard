#!/usr/bin/env python3
import fcntl, ipaddress, json, logging, subprocess, time, os, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

BANS_FILE = "/var/ossec/active-response/progressive-bans.json"
HOST = "0.0.0.0"
PORT = 8089
ALLOWED_ORIGIN = "https://shirako.alexis.tokyo-ict.com"
MAX_BODY_SIZE = 4096

logging.basicConfig(filename="/var/ossec/logs/block-api.log", level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("block-api")

def load_bans():
    try:
        with open(BANS_FILE) as f:
            fcntl.flock(f, fcntl.LOCK_SH)
            return json.load(f)
    except Exception:
        return []

def save_bans(bans):
    with open(BANS_FILE, "w") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        json.dump(bans, f, indent=2)
        f.flush()
        os.fsync(f.fileno())

def format_duration(seconds):
    if seconds >= 86400: return f"{seconds // 86400}j"
    if seconds >= 3600: return f"{seconds // 3600}h"
    return f"{seconds // 60}min"

def validate_ip(ip_str):
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

def iptables_drop(ip):
    subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], stderr=subprocess.DEVNULL)
    subprocess.run(["iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"], stderr=subprocess.DEVNULL)
    subprocess.run(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"], stderr=subprocess.DEVNULL)
    subprocess.run(["iptables", "-I", "FORWARD", "-s", ip, "-j", "DROP"], stderr=subprocess.DEVNULL)

def iptables_remove(ip):
    subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], stderr=subprocess.DEVNULL)
    subprocess.run(["iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"], stderr=subprocess.DEVNULL)

def cleanup_expired():
    """Thread qui vérifie toutes les 60s et supprime les règles iptables expirées."""
    while True:
        try:
            now = int(time.time())
            bans = load_bans()
            for b in bans:
                expires_at = b.get("expires_at", 0)
                ip = b.get("ip", "")
                if ip and 0 < expires_at <= now:
                    iptables_remove(ip)
                    logger.info("AUTO-EXPIRED %s", ip)
                    print(f"Auto-expired: {ip}")
        except Exception as e:
            logger.error("Cleanup error: %s", e)
        time.sleep(60)

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
        elif path == "/block":
            self.handle_post_block()
        else:
            self.send_json(404, {"error": "Not found"})

    def handle_post_block(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            if length > MAX_BODY_SIZE:
                self.send_json(413, {"error": "Request body too large"})
                return
            body = self.rfile.read(length)
            data = json.loads(body)
            ip = data.get("ip", "").strip()
            reason = data.get("reason", "Blocage manuel dashboard").strip()[:200]
        except Exception:
            self.send_json(400, {"error": "Invalid JSON body"})
            return

        if not ip or not validate_ip(ip):
            self.send_json(400, {"error": "IP invalide"})
            return

        WHITELIST = {"118.3.231.232", "192.168.0.1", "192.168.0.2", "127.0.0.1"}
        if ip in WHITELIST:
            self.send_json(200, {"success": True, "ip": ip, "whitelisted": True})
            return

        now = int(time.time())
        bans = load_bans()
        entry = next((b for b in bans if b.get("ip") == ip), None)
        if entry is None:
            entry = {'ip': ip, 'offense_count': 0}
            bans.append(entry)
        offense = entry.get('offense_count', 0) + 1
        entry['offense_count'] = offense
        durations = [600, 3600, 86400, 604800]
        duration = durations[min(offense - 1, len(durations) - 1)]
        entry['ban_duration_seconds'] = duration
        entry['banned_at'] = now
        entry['expires_at'] = now + duration
        entry['reason'] = reason

        iptables_drop(ip)
        save_bans(bans)
        logger.info("BLOCKED %s via API (offense #%s, duration %ss)", ip, offense, duration)
        self.send_json(200, {"success": True, "ip": ip, "duration": format_duration(duration)})

    def handle_get_blocked(self):
        now = int(time.time())
        bans = load_bans()
        result = []
        for b in bans:
            expires_at = b.get("expires_at", 0)
            if expires_at <= 0 or expires_at <= now:
                continue
            duration = b.get("ban_duration_seconds", 0)
            result.append({
                "ip": b.get("ip", ""),
                "offense_count": b.get("offense_count", 1),
                "ban_duration_seconds": duration,
                "ban_duration_label": format_duration(duration),
                "banned_at": b.get("banned_at", 0),
                "expires_at": expires_at,
                "time_remaining": expires_at - now,
                "reason": b.get("reason", ""),
                "status": "active",
            })
        result.sort(key=lambda x: x["expires_at"], reverse=True)
        self.send_json(200, {"blocked": result, "count": len(result)})

    def handle_post_unblock(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            if length > MAX_BODY_SIZE:
                self.send_json(413, {"error": "Request body too large"})
                return
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
        iptables_remove(ip)
        save_bans(bans)
        logger.info("UNBLOCKED %s via API", ip)
        self.send_json(200, {"success": True, "ip": ip, "message": f"{ip} unblocked successfully"})

if __name__ == "__main__":
    if not os.path.exists(BANS_FILE):
        save_bans([])
    t = threading.Thread(target=cleanup_expired, daemon=True)
    t.start()
    logger.info("Cleanup thread started")
    server = HTTPServer((HOST, PORT), BlockAPIHandler)
    logger.info("Block API listening on %s:%d", HOST, PORT)
    print(f"Block API listening on {HOST}:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()
