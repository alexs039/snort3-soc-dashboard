#!/bin/sh
WHITELIST="118.3.231.232 192.168.0.2 192.168.0.1"
SRC_IP=$(echo "$4" | jq -r '.data.src_addr // empty')

if [ -z "$SRC_IP" ]; then
  exit 0
fi

for SAFE in $WHITELIST; do
  if [ "$SRC_IP" = "$SAFE" ]; then
    exit 0
  fi
done

curl -s -X POST http://127.0.0.1:8089/block \
  -H "Content-Type: application/json" \
  -d "{\"ip\":\"$SRC_IP\",\"reason\":\"Auto Snort3\"}"
