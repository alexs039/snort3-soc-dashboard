/**
 * Main render dispatcher.
 * Rebuilds the entire #app DOM on every call, then delegates to the
 * appropriate tab sub-renderer based on S.tab.
 */

import { S } from './state.js';
import { stats, getSev, timeSince, filterA } from './stats.js';
import { renderCfg } from './render-config.js';
import { renderDetailPanel } from './render-detail.js';
import { renderSnort, renderWindows } from './render-snort.js';
import { renderMapTab, renderMap } from './render-map.js';

/**
 * Re-renders the entire application UI into #app.
 * Called after every state mutation. Uses innerHTML for simplicity (no VDOM).
 * All user data is sanitized before injection (esc, safeIP, etc.).
 * @returns {void}
 */
export function render() {
  const st = stats(S.alerts);
  const filtered = filterA();

  const now = new Date();
  const tl  = st.crit > 10 ? "CRITICAL" : st.crit > 3 ? "HIGH" : st.crit > 0 ? "MEDIUM" : "LOW";
  const tc  = { CRITICAL: "#DC2626", HIGH: "#EF4444", MEDIUM: "#F59E0B", LOW: "#10B981" };

  const countries = {};
  S.alerts.forEach(a => {
    const g = S.geoData[a.data?.src_addr];
    if (g) countries[g.country] = (countries[g.country] || 0) + 1;
  });
  const topCountries = Object.entries(countries).sort((a, b) => b[1] - a[1]).slice(0, 6);

  const lastCrit  = S.alerts.find(a => getSev(a.rule?.level || 0) === "critical");
  const threatMsg = lastCrit
    ? (lastCrit.data?.msg || "Menace critique détectée").substring(0, 80)
    : "Aucune menace critique";

  document.getElementById("app").innerHTML = `
    ${S.showConfig ? renderCfg() : ""}
    ${S.detailAlert !== null ? renderDetailPanel(S.detailAlert) : ""}

    <header class="header">
      <div class="header-left">
        <div class="logo">🛡️</div>
        <div>
          <h1>SNORT<span>3</span> SOC</h1>
          <div class="header-sub">Security Operations Center</div>
        </div>
      </div>
      <div class="header-right">
        <div class="threat-pill"
          style="background:${tc[tl]}12;border:1px solid ${tc[tl]}33;color:${tc[tl]}">
          <div style="width:6px;height:6px;border-radius:50%;background:${tc[tl]};${tl === 'CRITICAL' ? 'animation:pulse 1s ease infinite' : ''}"></div>
          ${tl}
        </div>
        <div>
          <div class="clock-date">${now.toLocaleDateString("fr-FR", { weekday: "short", day: "numeric", month: "short", year: "numeric" })}</div>
          <div class="clock-time">${now.toLocaleTimeString("fr-FR")}</div>
          <div style="font-size:8px;color:var(--dim);text-align:right;margin-top:2px">${timeSince(S.lastUpdate)} ago</div>
        </div>
        <div class="status-badge"
          style="background:${S.connected ? 'rgba(16,185,129,.06)' : 'rgba(245,158,11,.06)'};border:1px solid ${S.connected ? 'rgba(16,185,129,.15)' : 'rgba(245,158,11,.15)'}"
          data-action="show-config">
          <div class="status-dot ${S.connected ? 'live' : ''}"
            style="background:${S.connected ? '#10B981' : '#F59E0B'};box-shadow:0 0 8px ${S.connected ? '#10B981' : '#F59E0B'}"></div>
          <span class="status-label" style="color:${S.connected ? '#10B981' : '#F59E0B'}">${S.connected ? "LIVE" : "OFFLINE"}</span>
        </div>
      </div>
    </header>

    <div class="container">
      <!-- TABS -->
      <div class="tabs">
        <button class="tab ${S.tab === 'snort' ? 'active' : ''}" data-action="tab" data-tab="snort">🐷 Snort IDS</button>
        <button class="tab ${S.tab === 'windows' ? 'active' : ''}" data-action="tab" data-tab="windows">🪟 Windows</button>
        <button class="tab ${S.tab === 'map' ? 'active' : ''}" data-action="tab" data-tab="map">🌍 Carte mondiale</button>
      </div>

      ${S.tab === 'snort'   ? renderSnort(st, filtered, tc, tl, threatMsg) : ''}
      ${S.tab === 'windows' ? renderWindows() : ''}
      ${S.tab === 'map'     ? renderMapTab(st, topCountries) : ''}

      <div class="footer">
        <span>
          Snort 3.10.2 · Wazuh 4.14.3 · OpenSearch ·
          ${S.alerts.length} events IDS · ${S.winAlerts.length} events Windows · TFE SOC
        </span>
        <span>
          snort-ids (your-snort-ip) → Wazuh (your-wazuh-ip) → Dashboard ·
          🔊 ${S.soundEnabled ? 'ON' : 'OFF'}
          <button data-action="toggle-sound"
            style="border:none;background:none;color:var(--cyan);cursor:pointer;font-size:10px">Toggle</button>
        </span>
      </div>
    </div>`;

  if (S.tab === 'map') renderMap();
}
