#!/bin/bash
# snort-drop.sh — Wazuh Active Response script for Snort 3 alerts
# Progressive temporary ban system: 10min → 1h → 24h → 7 days
# Install: /var/ossec/active-response/bin/snort-drop.sh
# Permissions: chmod 750, chown root:wazuh
# Cron cleanup (every 5 min): */5 * * * * /var/ossec/active-response/bin/snort-drop.sh cleanup

LOG="/var/ossec/logs/active-responses.log"
BANS_FILE="/var/ossec/active-response/progressive-bans.json"
TMP=$(mktemp /tmp/ar_input_XXXXXX.json)
trap 'rm -f "$TMP"' EXIT

# Ensure bans file exists
if [ ! -f "$BANS_FILE" ]; then
    echo "[]" > "$BANS_FILE"
fi

# ── CLEANUP MODE ─────────────────────────────────────────────
if [ "$1" = "cleanup" ]; then
    NOW=$(date +%s)
    AR_NOW="$NOW" AR_BANS="$BANS_FILE" AR_LOG="$LOG" \
    /usr/bin/python3 - << 'PYEOF'
import json, subprocess, os
from datetime import datetime
now = int(os.environ.get('AR_NOW', '0'))
log_file = os.environ.get('AR_LOG', '')
bans_file = os.environ.get('AR_BANS', '')
log = open(log_file, 'a')
try:
    with open(bans_file) as f:
        bans = json.load(f)
except Exception:
    bans = []

remaining = []
for b in bans:
    if b.get('expires_at', 0) <= now:
        ip = b.get('ip', '')
        if ip:
            subprocess.run(['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'], stderr=subprocess.DEVNULL)
            subprocess.run(['iptables', '-D', 'FORWARD', '-s', ip, '-j', 'DROP'], stderr=subprocess.DEVNULL)
            log.write(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + ' snort-drop: CLEANUP expired ban for ' + ip + '\n')
        # Keep entry for offense history but clear ban timestamps
        b['expires_at'] = 0
        b['banned_at'] = 0
        remaining.append(b)
    else:
        remaining.append(b)

with open(bans_file, 'w') as f:
    json.dump(remaining, f, indent=2)
log.close()
PYEOF
    exit 0
fi

# ── ACTIVE RESPONSE MODE ──────────────────────────────────────
cat > "$TMP"

PARSED=$(/usr/bin/python3 -c "
import json
with open('$TMP') as f:
    d = json.load(f)
cmd = d.get('command', '')
alert = d.get('parameters', {}).get('alert', {})
ip = alert.get('data', {}).get('src_addr', '')
reason = alert.get('data', {}).get('msg', '') or alert.get('rule', {}).get('description', '')
print(cmd + '|' + ip + '|' + reason.replace('|', ' '))
" 2>> "$LOG")

rm -f "$TMP"

CMD=$(echo "$PARSED" | cut -d'|' -f1)
IP=$(echo "$PARSED" | cut -d'|' -f2)
REASON=$(echo "$PARSED" | cut -d'|' -f3-)

echo "$(date) snort-drop: CMD=$CMD IP=$IP" >> "$LOG"

# Validate IP format (IPv4 or IPv6 basic chars only)
if ! echo "$IP" | grep -qE '^[0-9a-fA-F.:]+$'; then
    echo "$(date) snort-drop: INVALID IP rejected" >> "$LOG"
    exit 1
fi

if [ -z "$IP" ]; then
    exit 1
fi

if [ "$CMD" = "add" ]; then
    NOW=$(date +%s)
    # Pass untrusted data via environment variables to avoid shell injection
    AR_IP="$IP" AR_REASON="$REASON" AR_NOW="$NOW" AR_BANS="$BANS_FILE" AR_LOG="$LOG" \
    /usr/bin/python3 - << 'PYEOF'
import json, subprocess, os
ip = os.environ.get('AR_IP', '')
reason = os.environ.get('AR_REASON', '')[:200]
now = int(os.environ.get('AR_NOW', '0'))
bans_file = os.environ.get('AR_BANS', '')
log_file = os.environ.get('AR_LOG', '')
log = open(log_file, 'a')

try:
    with open(bans_file) as f:
        bans = json.load(f)
except Exception:
    bans = []

entry = next((b for b in bans if b.get('ip') == ip), None)
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

with open(bans_file, 'w') as f:
    json.dump(bans, f, indent=2)

subprocess.run(['iptables', '-I', 'INPUT', '-s', ip, '-j', 'DROP'], stderr=subprocess.DEVNULL)
subprocess.run(['iptables', '-I', 'FORWARD', '-s', ip, '-j', 'DROP'], stderr=subprocess.DEVNULL)

hrs = duration // 3600
mins = (duration % 3600) // 60
dur_str = f'{hrs}h' if hrs else f'{mins}m'
log.write(f'snort-drop: BLOCKED {ip} offense #{offense} for {dur_str} reason: {reason[:80]}\n')
log.close()
PYEOF

elif [ "$CMD" = "delete" ]; then
    AR_IP="$IP" AR_BANS="$BANS_FILE" AR_LOG="$LOG" \
    /usr/bin/python3 - << 'PYEOF'
import json, subprocess, os
ip = os.environ.get('AR_IP', '')
bans_file = os.environ.get('AR_BANS', '')
log_file = os.environ.get('AR_LOG', '')
log = open(log_file, 'a')

try:
    with open(bans_file) as f:
        bans = json.load(f)
except Exception:
    bans = []

for b in bans:
    if b.get('ip') == ip:
        b['expires_at'] = 0
        b['banned_at'] = 0

with open(bans_file, 'w') as f:
    json.dump(bans, f, indent=2)

subprocess.run(['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'], stderr=subprocess.DEVNULL)
subprocess.run(['iptables', '-D', 'FORWARD', '-s', ip, '-j', 'DROP'], stderr=subprocess.DEVNULL)
log.write(f'snort-drop: UNBLOCKED {ip}\n')
log.close()
PYEOF
fi

exit 0
