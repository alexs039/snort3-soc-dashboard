# 🛡️ SNORT3 SOC Dashboard

> Security Operations Center Dashboard for Snort 3 IDS integrated with Wazuh SIEM

A real-time security monitoring dashboard that connects to OpenSearch (via Wazuh) to display Snort 3 IDS alerts with geolocation, MITRE ATT&CK mapping, and automated threat classification.

## 🖼️ Features

### Core Monitoring
- **Real-time alert monitoring** — Auto-refreshes every 15 seconds via OpenSearch API
- **3 Dashboard tabs** — Snort IDS, Windows Events, World Attack Map
- **MITRE ATT&CK mapping** — Each alert is mapped to its MITRE technique
- **Threat classification** — Scan/Recon, Web Attack, DoS/DDoS, Malware/C2
- **Severity levels** — Low, Medium, High, Critical with visual indicators

### SOC Analytics (NEW)
- **SOC Overview Panel** — MTTD (Mean Time To Detect), alerts/minute rate, unique attackers, top targeted port, protocol distribution
- **MITRE ATT&CK Heatmap** — Interactive heatmap grid grouped by tactics (Reconnaissance, Initial Access, Execution, etc.) with clickable technique cells
- **Timeline & Trends** — 7-day alert timeline, hourly heatmap (24h), trend indicators comparing today vs yesterday
- **Active Response Log** — Real-time view of blocked IPs with timestamps, reasons, and time remaining before auto-unblock

### Windows Event Analysis (ENHANCED)
- **EventID categorization** — Security (4624, 4625, 4720, 4732, 4648), System (11, 7045, 1001)
- **Login activity panel** — Successful vs failed login tracking
- **User activity tracking** — Which users triggered the most alerts
- **Event categories** — Security, System, Application with counters

### Interactive Features
- **Alert detail panel** — Slide-in side panel with full JSON, MITRE details, geolocation data, copy-to-clipboard
- **Export & Reporting** — CSV export, JSON export, HTML report generation
- **Advanced filtering** — Filter by category, MITRE technique, search by IP/message/SID
- **Sound notifications** — Optional audio alerts for critical events (level 12+)
- **Last updated timestamp** — Real-time counter showing time since last refresh

### World Attack Map (IMPROVED)
- **Better continent outlines** — More accurate continent shapes
- **Animated attack lines** — Visual lines from source to target (Tokyo)
- **Pulsing dots** — Dynamic pulsing effect on attack sources
- **Country labels** — Top 5 attacking countries shown on map
- **Mini stats overlay** — Total attacks, countries count, most active country

### Security & Performance
- **XSS-safe** — All OpenSearch data is sanitized before rendering
- **Content Security Policy** — CSP headers to prevent script injection
- **Lazy-loading** — Map geolocation only when tab is opened
- **Geolocation caching** — Prevents repeated API calls for same IPs
- **Responsive design** — Works on desktop, tablet (1024px+)
- **Smooth animations** — Staggered card animations, smooth transitions

## 🏗️ Architecture

```
[Internet Traffic]
       │
       ▼
[Snort 3 IDS] ──alert_json──▶ [Wazuh Agent]
(192.168.0.1)                       │
       │                            ▼
       │                    [Wazuh Manager] ──▶ [OpenSearch Indexer]
       │                    (192.168.0.2)              │
       │                            │                  ▼
       │                    [Active Response]    [SOC Dashboard]
       │                    (iptables block)    (this project)
       │
[Windows PC] ──wazuh-agent──▶ [Wazuh Manager]
(dorei)
```

## 📋 Prerequisites

| Component | Version | Role |
|-----------|---------|------|
| Snort 3 | 3.10.2 | Network IDS/IPS |
| Wazuh | 4.14.3 | SIEM — log collection & correlation |
| OpenSearch | 2.x | Alert indexing & search |
| Caddy | 2.x | Reverse proxy with TLS |
| Nginx | 1.x | Static file server |

## 🚀 Quick Setup

### 1. Deploy the dashboard

```bash
# On the Wazuh server
mkdir -p /var/www/snort-dashboard
cp index.html /var/www/snort-dashboard/index.html
cp style.css /var/www/snort-dashboard/style.css
cp app.js /var/www/snort-dashboard/app.js
```

### 2. Configure Nginx

```bash
cat > /etc/nginx/sites-available/snort-dashboard << 'EOF'
server {
    listen 8443;
    server_name _;
    root /var/www/snort-dashboard;
    index index.html;

    location / {
        try_files $uri $uri/ =404;
    }
}
EOF

ln -s /etc/nginx/sites-available/snort-dashboard /etc/nginx/sites-enabled/
nginx -t && systemctl restart nginx
```

### 3. Configure Caddy (reverse proxy)

```
https://your-domain.com {
    handle /opensearch/* {
        @blocked not method POST
        respond @blocked 403
        @dangerous path /opensearch/_bulk* /opensearch/_delete*
        respond @dangerous 403
        uri strip_prefix /opensearch
        reverse_proxy https://localhost:9200 {
            transport http {
                tls_insecure_skip_verify
            }
        }
    }
    handle /geo/* {
        uri strip_prefix /geo
        reverse_proxy http://ip-api.com {
            header_up Host ip-api.com
        }
    }
    handle {
        basic_auth {
            your_user $2a$14$your_bcrypt_hash
        }
        reverse_proxy localhost:8443
    }
}
```

### 4. Connect the dashboard

1. Open the dashboard URL in your browser
2. Click the **OFFLINE** badge (top right)
3. Enter your OpenSearch proxy URL, username, and password
4. Click **Connect**

## 📁 Project Structure

```
snort3-soc-dashboard/
├── index.html              # Main HTML file (loads CSS and JS)
├── style.css               # All styles and responsive design
├── app.js                  # Complete dashboard logic and features
├── README.md               # This file
├── LICENSE                  # MIT License
├── docs/
│   ├── architecture.md     # Detailed architecture documentation
│   ├── snort-rules.md      # Snort 3 rules documentation
│   ├── wazuh-config.md     # Wazuh configuration guide
│   └── security.md         # Security hardening notes
├── config/
│   ├── local.rules         # Snort 3 detection rules (53 custom rules)
│   ├── local_rules.xml     # Wazuh correlation rules
│   ├── local_decoder.xml   # Wazuh decoder for Snort alerts
│   ├── Caddyfile           # Caddy reverse proxy config
│   ├── snort-dashboard.nginx # Nginx site config
│   └── snort-drop.sh       # Active response script
└── screenshots/
    └── (add your screenshots here)
```

**Note:** The dashboard now uses separate files for better maintainability:
- `index.html` - Minimal HTML structure
- `style.css` - All CSS including responsive media queries (~260 lines)
- `app.js` - Complete JavaScript with all features (~1070 lines)

No build step required — works by opening `index.html` directly or serving via Nginx.

## 🔒 Security Features

- **XSS Prevention** — All data from OpenSearch is sanitized via `esc()`, `safeIP()`, `safeMsg()` functions
- **Content Security Policy** — Restricts script sources, connections, and fonts
- **Referrer Policy** — `no-referrer` to prevent URL leakage
- **OpenSearch Proxy** — Only POST requests allowed, destructive operations blocked
- **Basic Auth** — Caddy authentication protects dashboard access
- **GDPR Compliance** — IP addresses (personal data under GDPR) are protected behind authentication

## 🎯 Snort 3 Rules (53 custom rules)

| SID Range | Category | Count | Description |
|-----------|----------|-------|-------------|
| 9001xxx | Scan/Recon | 9 | SYN, NULL, XMAS, FIN scans, SSH brute force |
| 9002xxx | Web Attacks | 18 | SQLi, XSS, RFI, LFI, Log4Shell, ShellShock |
| 9003xxx | Malware/C2 | 13 | IRC C2, Cobalt Strike, DNS tunneling, WannaCry |
| 9004xxx | DNS/DGA | 6 | Suspicious TLD queries, DGA detection |
| 9005xxx | TOR | 6 | TOR relay, SOCKS proxy, .onion DNS queries |
| 9006xxx | IPS Demo | 6 | Drop rules for inline mode demonstration |

## 📊 Wazuh Rules

| Rule ID | Level | Description |
|---------|-------|-------------|
| 100300 | 6 | Base Snort 3 alert |
| 100301 | 8 | Scan/Reconnaissance |
| 100302 | 10 | Web Application Attack |
| 100303 | 12 | Malware/C2 Communication |
| 100304 | 10 | DoS/DDoS Attack |
| 100305 | 13 | Correlation: Repeated scan from same source |
| 100306 | 14 | Correlation: Repeated malware from same source |
| 100307 | 13 | TOR Connection Detected |
| 100308 | 11 | Suspicious DNS / DGA |

## 🤖 Active Response

When rule 100301 (Scan/Recon) triggers, Wazuh automatically:
1. Sends the `snort-drop` command to the Snort agent
2. The agent extracts `src_addr` from the alert JSON
3. Blocks the attacker IP via `iptables -I INPUT -s <IP> -j DROP`
4. Automatically unblocks after 300 seconds (5 minutes)

## 📄 License

MIT License — See [LICENSE](LICENSE) file.

## 🎓 Context

This project was developed as part of a TFE (Travail de Fin d'Études) focused on:
> "Integrating OSS SIEM solutions and log analysis in a hands-on environment, building practical skills in security monitoring, incident detection, and analysis."
