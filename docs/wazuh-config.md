# Wazuh Configuration Guide

## Agent Configuration (Snort machine — 192.168.0.1)

### Install agent
```bash
WAZUH_MANAGER='192.168.0.2' apt-get install -y wazuh-agent
```

### Configure log collection
Add to `/var/ossec/etc/ossec.conf`:
```xml
<localfile>
    <log_format>json</log_format>
    <location>/var/log/snort/alert_json.txt</location>
</localfile>
```

### Install active response script
```bash
cp config/snort-drop.sh /var/ossec/active-response/bin/
chmod 750 /var/ossec/active-response/bin/snort-drop.sh
chown root:wazuh /var/ossec/active-response/bin/snort-drop.sh
```

## Manager Configuration (Wazuh server — 192.168.0.2)

### Decoder
Copy `config/local_decoder.xml` to `/var/ossec/etc/decoders/local_decoder.xml`

### Rules
Copy `config/local_rules.xml` content into `/var/ossec/etc/rules/local_rules.xml`
(merge with existing rules if any)

### Active Response
Add to `/var/ossec/etc/ossec.conf`:
```xml
<command>
    <name>snort-drop</name>
    <executable>snort-drop.sh</executable>
    <timeout_allowed>yes</timeout_allowed>
</command>

<active-response>
    <command>snort-drop</command>
    <location>defined-agent</location>
    <agent_id>002</agent_id>
    <rules_id>100301</rules_id>
    <timeout>300</timeout>
</active-response>
```

### Whitelist
Add to the `<global>` section:
```xml
<white_list>YOUR_WAZUH_PUBLIC_IP</white_list>
<white_list>192.168.0.2</white_list>
```

### Restart
```bash
systemctl restart wazuh-manager
# On Snort machine:
systemctl restart wazuh-agent
```

## Verification

### Test decoder
```bash
/var/ossec/bin/wazuh-logtest
# Paste a Snort JSON alert, verify srcip is extracted
```

### Test active response
```bash
# On Snort machine:
echo '{"version":1,"command":"add","parameters":{"alert":{"data":{"src_addr":"1.2.3.4"}}}}' | /var/ossec/active-response/bin/snort-drop.sh
iptables -L INPUT -n | grep "1.2.3.4"
# Clean up:
iptables -D INPUT -s 1.2.3.4 -j DROP
```

### Test rules
```bash
grep "100301" /var/ossec/logs/alerts/alerts.json | tail -1
```
