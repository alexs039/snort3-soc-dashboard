# 🛡️ SNORT3 SOC Dashboard — Mise à jour 2026-03-18

## 📁 Structure

```
snort-machine/          → Fichiers à déployer sur la machine Snort (192.168.0.1)
wazuh-manager/          → Fichiers à déployer sur le manager Wazuh (192.168.0.2)
dashboard/              → Fichiers du dashboard web
```

## 🚀 Déploiement

### Machine Snort

```bash
# Copier les fichiers
cp block-api.py /home/ubuntu/snort3/lua/
cp snort-auto-block.py /usr/local/bin/
cp block-snort.sh /var/ossec/active-response/bin/
chmod +x /var/ossec/active-response/bin/block-snort.sh

# Services systemd
cp block-api.service /etc/systemd/system/
cp snort-auto-block.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable block-api snort-auto-block
systemctl restart block-api snort-auto-block
```

### Manager Wazuh

```bash
cp Caddyfile /etc/caddy/Caddyfile
cp local_rules.xml /var/ossec/etc/rules/local_rules.xml
systemctl reload caddy
systemctl restart wazuh-manager
```

### Dashboard

```bash
cp index.html /var/www/snort-dashboard/
```

## ✅ Nouveautés

- **block-api.py** : expiration automatique des bans (thread cleanup toutes les 60s), whitelist intégrée
- **snort-auto-block.py** : blocage direct depuis alert_json sans passer par Wazuh, détection Nmap/XMAS/attack
- **snort-auto-block.py** : vérification API avant blocage (fix re-block après unblock manuel)
- **block-snort.sh** : whitelist manager et machine Snort
- **Services systemd** : block-api et snort-auto-block démarrent au boot
- **index.html** : suppression des hash SRI Leaflet (fix carte mondiale)
- **local_rules.xml** : règle 100309 ajoutée pour détecter Nmap/portscan

## 🔒 Whitelist par défaut

- `118.3.231.232` — Machine Windows admin
- `192.168.0.1` — Machine Snort
- `192.168.0.2` — Manager Wazuh
- `192.168.0.0/24` — Réseau interne complet
