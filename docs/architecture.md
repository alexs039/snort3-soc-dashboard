# Architecture Documentation

## Overview

This project implements a complete Security Operations Center (SOC) pipeline:

```
Internet Traffic → Snort 3 IDS → JSON Alerts → Wazuh Agent → Wazuh Manager → OpenSearch → Dashboard
```

## Components

### 1. Snort 3 IDS (192.168.0.1)

**Role**: Network Intrusion Detection System

- Listens on `ens3` (public interface) in passive IDS mode
- Analyzes all inbound traffic against 53 custom rules + 639 builtin rules
- Outputs alerts in JSON format to `/var/log/snort/alert_json.txt`
- Configuration: `/home/ubuntu/snort3/lua/snort.lua`

**Key config sections**:
- `ips`: Loads rules from `/etc/snort/rules/local.rules`
- `http_inspect`: Enables HTTP sticky buffers (http_uri, http_header, http_method)
- `alert_json`: JSON output with all relevant fields
- `stream_tcp/udp/icmp`: Stateful session tracking
- `wizard`: Automatic protocol detection

### 2. Wazuh Agent (on Snort machine)

**Role**: Log collector and forwarder

- Reads `/var/log/snort/alert_json.txt` with `log_format: json`
- Forwards alerts to Wazuh Manager (192.168.0.2)
- Executes active response scripts when instructed by manager

### 3. Wazuh Manager (192.168.0.2)

**Role**: SIEM — correlation, alerting, active response

- **Decoder** (`local_decoder.xml`): Extracts `srcip` from Snort JSON for active response
- **Rules** (`local_rules.xml`): Classifies alerts by category (Scan, Web Attack, DoS, Malware)
- **Correlation rules**: Detects repeated attacks from same source
- **Active Response**: Sends `snort-drop` command to block attacker IPs

### 4. OpenSearch Indexer (192.168.0.2)

**Role**: Alert storage and search

- Filebeat reads `/var/ossec/logs/alerts/alerts.json` and indexes to OpenSearch
- Index pattern: `wazuh-alerts-4.x-YYYY.MM.DD`
- Dashboard queries: `rule.groups = snort3` filtered

### 5. SOC Dashboard (this project)

**Role**: Visualization and monitoring

- Single HTML file, no build step required
- Connects to OpenSearch via Caddy HTTPS proxy
- Auto-refreshes every 15 seconds
- Geolocation via ip-api.com proxy

## Network Diagram

```
┌─────────────────────────────────────────────────────────┐
│                    INTERNET                              │
└─────────────┬───────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────┐     ┌──────────────────────────┐
│   SNORT IDS (ens3)      │     │   WINDOWS PC (dorei)     │
│   YOUR_SNORT_PUBLIC_IP       │     │   192.168.0.39           │
│                         │     │                          │
│   Snort 3.10.2          │     │   Wazuh Agent 4.14.3     │
│   Wazuh Agent 4.14.3    │     │   Windows EventChannel   │
│   Active Response       │     │                          │
│                         │     │                          │
│   ens4: 192.168.0.1     │     │                          │
└────────────┬────────────┘     └──────────┬───────────────┘
             │    LAN 192.168.0.0/24       │
             ▼                             ▼
┌──────────────────────────────────────────────────────────┐
│              WAZUH SERVER (ens4: 192.168.0.2)            │
│              Public: YOUR_WAZUH_PUBLIC_IP                      │
│                                                          │
│   ┌──────────────┐  ┌────────────────┐  ┌─────────────┐ │
│   │ Wazuh Manager│  │ OpenSearch     │  │ Caddy       │ │
│   │ Port 1514    │  │ Port 9200      │  │ Port 443    │ │
│   │              │  │                │  │             │ │
│   │ - Decoders   │  │ - wazuh-alerts │  │ - /opensearch│
│   │ - Rules      │  │   indexes      │  │ - /geo      │ │
│   │ - Active Resp│  │                │  │ - Dashboard │ │
│   └──────────────┘  └────────────────┘  └─────────────┘ │
│                                                          │
│   ┌──────────────┐  ┌────────────────┐                   │
│   │ Filebeat     │  │ Nginx          │                   │
│   │ alerts→index │  │ Port 8443      │                   │
│   └──────────────┘  │ SOC Dashboard  │                   │
│                     └────────────────┘                   │
└──────────────────────────────────────────────────────────┘
```

## Data Flow

1. **Packet capture**: Snort captures traffic on ens3
2. **Detection**: Snort matches packets against rules, generates JSON alerts
3. **Collection**: Wazuh agent reads JSON file, sends to manager
4. **Decoding**: Wazuh decoder extracts fields (srcip, msg, sid)
5. **Classification**: Wazuh rules assign level and category
6. **Active Response**: Manager triggers IP block on Snort machine
7. **Indexing**: Filebeat sends alerts to OpenSearch
8. **Visualization**: Dashboard queries OpenSearch every 15 seconds
9. **Geolocation**: Dashboard resolves attacker IPs to countries via proxy
