# Snort 3 Rules Documentation

## Rule Syntax (Snort 3)

```
action protocol src_ip src_port -> dst_ip dst_port (options;)
```

### Key differences from Snort 2

| Snort 2 | Snort 3 | Note |
|---------|---------|------|
| `http_uri;` | `http_uri;` | Same (underscore) |
| `http.uri;` | `http_uri;` | Dot syntax is invalid |
| `content:"X"; nocase;` | `content:"X", nocase;` | nocase is a content modifier (comma) |
| `threshold:...` | `detection_filter:...` | threshold removed in Snort 3 |
| `offset:N; depth:N;` | `offset N, depth N;` | Comma-separated modifiers |

## Rules by Section

### Section 1: Port Scans (SID 9001xxx)

| SID | Name | MITRE | Description |
|-----|------|-------|-------------|
| 9001001 | SYN Scan | T1046 | TCP SYN-only flag (nmap -sS) |
| 9001002 | NULL Scan | T1046 | No TCP flags set (nmap -sN) |
| 9001003 | FIN Scan | T1046 | FIN-only flag (nmap -sF) |
| 9001004 | XMAS Scan | T1046 | FIN+PSH+URG flags (nmap -sX) |
| 9001005 | ACK Probe | T1046 | ACK scan for firewall mapping |
| 9001006 | UDP Scan | T1046 | UDP port scanning |
| 9001007 | ICMP Sweep | T1018 | Ping sweep for host discovery |
| 9001009 | Banner Grab | T1046 | Small payload on sensitive ports |
| 9001010 | SSH Brute Force | T1110 | Repeated SYN on port 22 |

### Section 2: Network Intrusions (SID 9002xxx)

| SID | Name | MITRE | CVE |
|-----|------|-------|-----|
| 9002001 | Directory Traversal | T1083 | - |
| 9002002 | SQL Injection (OR) | T1190 | - |
| 9002003 | SQL Injection (UNION) | T1190 | - |
| 9002005 | XSS (script tag) | T1059 | - |
| 9002008 | Command Injection | T1059 | - |
| 9002010 | ShellShock | T1190 | CVE-2014-6271 |
| 9002011 | Log4Shell (header) | T1190 | CVE-2021-44228 |
| 9002012 | Log4Shell (URI) | T1190 | CVE-2021-44228 |
| 9002020 | SYN Flood | T1498 | - |
| 9002025 | EternalBlue | T1210 | CVE-2017-0143 |

### Section 3: Malware / C2 (SID 9003xxx)

| SID | Name | MITRE | Description |
|-----|------|-------|-------------|
| 9003001 | IRC C2 | T1071 | NICK command on port 6667 |
| 9003005 | Cobalt Strike | T1071 | Connection to port 50050 |
| 9003006 | CS Beacon UA | T1071 | MSIE 9.0 User-Agent |
| 9003010 | DNS Exfiltration | T1048 | Mass TXT DNS queries |
| 9003011 | DNS Tunneling | T1071 | Oversized DNS queries (>150 bytes) |
| 9003030 | WannaCry | T1210 | SMB propagation signature |

### Section 4: DNS / DGA Detection (SID 9004xxx)

| SID | Name | MITRE | Description |
|-----|------|-------|-------------|
| 9004001-005 | Suspicious TLD | T1071 | Queries to .xyz, .top, .buzz, .tk, .ml |
| 9004006 | DGA Detection | T1568 | Unusually long DNS queries (>100 bytes) |

### Section 5: TOR Detection (SID 9005xxx)

| SID | Name | MITRE | Description |
|-----|------|-------|-------------|
| 9005001 | TOR Relay | T1090 | Connection to port 9001 |
| 9005002 | TOR Directory | T1090 | Connection to port 9030 |
| 9005003 | TOR SOCKS | T1090 | Connection to port 9050 |
| 9005006 | .onion DNS | T1090 | DNS query for .onion domain |

### Section 6: IPS Demo (SID 9006xxx)

These rules use `drop` instead of `alert` for inline mode demonstration.

| SID | Name | Description |
|-----|------|-------------|
| 9006001 | Drop SYN Scan | Blocks aggressive SYN scans |
| 9006002 | Drop SQLi | Blocks SQL injection attempts |
| 9006003 | Drop XSS | Blocks cross-site scripting |
| 9006004 | Drop Log4Shell | Blocks Log4Shell exploitation |
