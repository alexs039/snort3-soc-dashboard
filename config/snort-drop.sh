#!/bin/bash
# snort-drop.sh — Wazuh Active Response script for Snort 3 alerts
# Extracts src_addr from Snort JSON alert and blocks via iptables
# Install: /var/ossec/active-response/bin/snort-drop.sh
# Permissions: chmod 750, chown root:wazuh

LOG="/var/ossec/logs/active-responses.log"
TMP="/tmp/ar_input_$$.json"

# Read JSON input from Wazuh execd via stdin
cat > "$TMP"

# Extract command and source IP using Python
# Note: On Wazuh agent (not manager), use /usr/bin/python3
#       On Wazuh manager, use /var/ossec/framework/python/bin/python3
PARSED=$(/usr/bin/python3 -c "
import json
with open('$TMP') as f:
    d=json.load(f)
cmd=d.get('command','')
ip=d.get('parameters',{}).get('alert',{}).get('data',{}).get('src_addr','')
print(cmd + '|' + ip)
" 2>> "$LOG")

rm -f "$TMP"

CMD=$(echo "$PARSED" | cut -d'|' -f1)
IP=$(echo "$PARSED" | cut -d'|' -f2)

echo "$(date) snort-drop: CMD=$CMD IP=$IP" >> "$LOG"

if [ -z "$IP" ] || [ "$IP" = "" ]; then
    exit 1
fi

if [ "$CMD" = "add" ]; then
    iptables -I INPUT -s "$IP" -j DROP 2>/dev/null
    iptables -I FORWARD -s "$IP" -j DROP 2>/dev/null
    echo "$(date) snort-drop: BLOCKED $IP" >> "$LOG"
elif [ "$CMD" = "delete" ]; then
    iptables -D INPUT -s "$IP" -j DROP 2>/dev/null
    iptables -D FORWARD -s "$IP" -j DROP 2>/dev/null
    echo "$(date) snort-drop: UNBLOCKED $IP" >> "$LOG"
fi

exit 0
