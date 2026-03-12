# Security Hardening

## Dashboard Security

### XSS Prevention
All data from OpenSearch is sanitized before DOM injection:

```javascript
function esc(s) {  // HTML entity encoding
    const d = document.createElement('div');
    d.appendChild(document.createTextNode(String(s)));
    return d.innerHTML;
}
function safeIP(ip)    { return esc(String(ip).replace(/[^0-9a-fA-F.:\/]/g, '')); }
function safeMsg(m)    { return esc(String(m).substring(0, 200)); }
function safeSid(s)    { return esc(String(s).replace(/[^0-9:]/g, '')); }
function safePort(p)   { return esc(String(p).replace(/[^0-9]/g, '')); }
function safeProto(p)  { return esc(String(p).replace(/[^A-Za-z0-9]/g, '')); }
```

### Content Security Policy
```html
<meta http-equiv="Content-Security-Policy" content="
    default-src 'self';
    script-src 'self' 'unsafe-inline' 'unsafe-eval';
    style-src 'self' 'unsafe-inline' https://fonts.googleapis.com;
    font-src https://fonts.gstatic.com;
    connect-src https://soc.your-domain.com;
    img-src 'self' data:;
">
```

### Referrer Policy
```html
<meta name="referrer" content="no-referrer">
```

## Proxy Security (Caddy)

### OpenSearch Proxy Restrictions
- Only `POST` method allowed (read-only search)
- Destructive operations blocked: `_bulk`, `_delete`, `_mapping`, `_settings`
- TLS termination handled by Caddy (Let's Encrypt auto-renewal)

### Authentication
- Dashboard protected by Caddy `basic_auth` (bcrypt hashed password)
- OpenSearch has its own authentication (admin user)
- Wazuh API has separate credentials

### Geolocation Proxy
- Proxies HTTP requests to ip-api.com through HTTPS Caddy
- Prevents mixed-content browser warnings
- Rate-limited by ip-api.com (45 requests/minute on free tier)

## GDPR Compliance

### IP Addresses as Personal Data
Under GDPR (CJUE Breyer ruling, 2016), IP addresses are personal data.

**Measures taken:**
1. Dashboard access is authenticated (Caddy basic_auth)
2. OpenSearch access requires separate credentials
3. Data is not transmitted to third parties (geolocation is proxied server-side)
4. Index retention is managed by OpenSearch ILM (Index Lifecycle Management)
5. Processing is justified under Article 6.1.f (legitimate interest: network security)

### Data Minimization
- Only security-relevant fields are displayed
- No user-identifying information beyond IP addresses
- Geolocation data is cached in browser memory only (not persisted)

## Active Response Security

### IP Blocking Script
- Runs as `root:wazuh` with permissions `750`
- Input validated: only valid IP characters accepted
- Temporary blocks (300 seconds default) with automatic unblock
- Whitelist configured in Wazuh to prevent blocking friendly IPs

### Whitelist
Always whitelist these IPs in `/var/ossec/etc/ossec.conf`:
```xml
<white_list>127.0.0.1</white_list>
<white_list>192.168.0.2</white_list>      <!-- Wazuh Manager -->
<white_list>YOUR_WAZUH_PUBLIC_IP</white_list>   <!-- Wazuh public IP -->
```
