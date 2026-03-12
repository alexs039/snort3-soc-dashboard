# Copilot Instructions for Snort3 SOC Dashboard

## Project Context
This is a Security Operations Center (SOC) dashboard that displays Snort 3 IDS alerts from Wazuh/OpenSearch in real-time. It's part of a TFE (thesis) on security monitoring and incident detection.

## Architecture
- Single HTML file (`index.html`) — no build step, vanilla JavaScript
- Connects to OpenSearch via HTTPS proxy for alert data
- Geolocation via ip-api.com proxy
- 3 tabs: Snort IDS, Windows Events, World Attack Map

## Code Standards
- All data from OpenSearch MUST be sanitized with `esc()`, `safeIP()`, `safeMsg()`, `safeSid()`, `safePort()`, `safeProto()` before DOM injection (XSS prevention)
- Never hardcode real IPs, domains, passwords, or API keys
- Use `your-domain.com` / `soc.your-domain.com` as placeholders
- Keep everything in a single `index.html` file
- CSS variables defined in `:root` for theming
- French language for UI labels

## Snort Rules (in config/local.rules)
- Snort 3 syntax: `content:"X", nocase;` (comma, not semicolon for modifiers)
- Sticky buffers: `http_uri` not `http.uri` (underscore, not dot)
- SID ranges: 9001xxx=scans, 9002xxx=intrusions, 9003xxx=malware, 9004xxx=DNS/DGA, 9005xxx=TOR, 9006xxx=IPS

## Wazuh Rules (in config/local_rules.xml)
- Rule IDs: 100300-100308
- Classification by `msg` field prefix: SCAN, INTRUSION HTTP, INTRUSION DOS, MALWARE

## Security Requirements
- Content Security Policy enforced via meta tag
- No localStorage/sessionStorage usage
- OpenSearch proxy restricted to POST only
- Never commit secrets, real IPs, or credentials
