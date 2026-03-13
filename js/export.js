/**
 * Data export utilities: CSV, JSON, and HTML report generation.
 */

import { S } from './state.js';
import { filterA, stats, getMitre, formatTime } from './stats.js';
import { esc } from './sanitize.js';
import { MITRE_NAMES } from './constants.js';

/**
 * Exports the currently filtered alerts as a CSV file download.
 * Columns: Heure, Niveau, Message, SID, Source, Destination, Port, Proto, MITRE.
 * @returns {void}
 */
export function exportCSV() {
  const filtered = filterA();
  let csv = "Heure,Niveau,Message,SID,Source,Destination,Port,Proto,MITRE\n";
  filtered.forEach(a => {
    const t     = formatTime(a.timestamp);
    const level = a.rule?.level || "?";
    const msg   = (a.data?.msg || "").replace(/"/g, '""');
    const sid   = a.data?.sid || "?";
    const src   = a.data?.src_addr || "?";
    const dst   = a.data?.dst_addr || "?";
    const port  = a.data?.dst_port || "?";
    const proto = a.data?.proto || "?";
    const mitre = getMitre(a.data?.sid) || "";
    csv += `${t},${level},"${msg}",${sid},${src},${dst},${port},${proto},${mitre}\n`;
  });
  downloadFile(csv, "snort3-alerts-" + Date.now() + ".csv", "text/csv");
}

/**
 * Exports the currently filtered alerts as a JSON file download.
 * @returns {void}
 */
export function exportJSON() {
  const filtered = filterA();
  downloadFile(JSON.stringify(filtered, null, 2), "snort3-alerts-" + Date.now() + ".json", "application/json");
}

/**
 * Generates a self-contained HTML security report summarising all current alerts
 * and triggers a browser download.
 * @returns {void}
 */
export function generateReport() {
  const st = stats(S.alerts);
  const html = `<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>Rapport SOC - ${new Date().toLocaleDateString("fr-FR")}</title>
<style>
body{font-family:Arial,sans-serif;margin:40px;background:#fff;color:#000}
h1{color:#06B6D4;border-bottom:2px solid #06B6D4;padding-bottom:10px}
h2{color:#3B82F6;margin-top:30px}
.stat{display:inline-block;margin:10px 20px 10px 0;padding:10px 20px;background:#f0f9ff;border-left:4px solid #06B6D4}
.stat-label{font-size:12px;color:#64748B;text-transform:uppercase}
.stat-value{font-size:24px;font-weight:bold;color:#06B6D4}
table{width:100%;border-collapse:collapse;margin:20px 0}
th,td{border:1px solid #ddd;padding:8px;text-align:left}
th{background:#06B6D4;color:#fff}
.critical{color:#DC2626;font-weight:bold}
</style>
</head>
<body>
<h1>🛡️ Rapport SOC - Snort3 IDS</h1>
<p><strong>Date:</strong> ${new Date().toLocaleString("fr-FR")}</p>
<p><strong>Période:</strong> Dernières 24 heures</p>

<h2>Statistiques Générales</h2>
<div class="stat"><div class="stat-label">Total Alertes</div><div class="stat-value">${st.total}</div></div>
<div class="stat"><div class="stat-label">Critique/Élevé</div><div class="stat-value ${st.crit > 0 ? 'critical' : ''}">${st.crit}</div></div>
<div class="stat"><div class="stat-label">Sources Uniques</div><div class="stat-value">${st.uniqueAttackers}</div></div>
<div class="stat"><div class="stat-label">MTTD</div><div class="stat-value">${st.mttd}m</div></div>
<div class="stat"><div class="stat-label">Taux</div><div class="stat-value">${st.alertRate}/min</div></div>

<h2>Top Attaquants</h2>
<table>
<tr><th>Adresse IP</th><th>Nombre d'alertes</th></tr>
${st.topSrc.map(([ip, c]) => `<tr><td>${esc(ip)}</td><td>${c}</td></tr>`).join("")}
</table>

<h2>MITRE ATT&CK</h2>
<table>
<tr><th>Technique</th><th>Nom</th><th>Alertes</th></tr>
${st.topMitre.map(([t, c]) => `<tr><td>${esc(t)}</td><td>${esc(MITRE_NAMES[t] || "")}</td><td>${c}</td></tr>`).join("")}
</table>

<p style="margin-top:40px;color:#64748B;font-size:12px">Généré par Snort3 SOC Dashboard</p>
</body>
</html>`;
  downloadFile(html, "rapport-soc-" + Date.now() + ".html", "text/html");
}

/**
 * Triggers a browser file download for the given string content.
 * @param {string} content  - File content as a string
 * @param {string} filename - Suggested download filename
 * @param {string} mimeType - MIME type for the Blob (e.g. 'text/csv')
 * @returns {void}
 */
export function downloadFile(content, filename, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
