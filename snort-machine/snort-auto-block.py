#!/usr/bin/env python3
import json, subprocess, time, ipaddress

LOG = "/var/log/snort/alert_json.txt"
WHITELIST_IPS = {"118.3.231.232", "192.168.0.1", "192.168.0.2", "127.0.0.1"}
WHITELIST_NETS = [ipaddress.ip_network("192.168.0.0/24")]
BLOCK_KEYWORDS = ["SCAN", "INTRUSION", "MALWARE", "Nmap", "nmap", "brute", "Brute", "attack", "Attack", "exploit", "Exploit"]

def is_whitelisted(ip):
    if ip in WHITELIST_IPS:
        return True
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in WHITELIST_NETS)
    except:
        return False

def is_currently_blocked(ip):
    """Vérifie si l'IP est déjà bloquée via l'API."""
    try:
        result = subprocess.run(
            ["curl", "-s", "http://127.0.0.1:8089/blocked"],
            capture_output=True, text=True, timeout=2
        )
        data = json.loads(result.stdout)
        return any(b["ip"] == ip for b in data.get("blocked", []))
    except:
        return False

def should_block(msg):
    return any(k in msg for k in BLOCK_KEYWORDS)

def tail(f):
    f.seek(0, 2)
    while True:
        line = f.readline()
        if not line:
            time.sleep(0.3)
            continue
        yield line

print("Snort auto-blocker started")
with open(LOG) as f:
    for line in tail(f):
        try:
            d = json.loads(line.strip())
            ip = d.get("src_addr", "")
            msg = d.get("msg", "")
            if ip and not is_whitelisted(ip) and should_block(msg):
                if not is_currently_blocked(ip):
                    subprocess.run([
                        "curl", "-s", "-X", "POST",
                        "http://127.0.0.1:8089/block",
                        "-H", "Content-Type: application/json",
                        "-d", json.dumps({"ip": ip, "reason": f"Auto:{msg[:50]}"})
                    ], capture_output=True, text=True)
                    print(f"BLOCKED {ip} — {msg}")
        except:
            pass
