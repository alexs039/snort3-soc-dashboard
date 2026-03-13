/**
 * Renders the Snort IDS dashboard tab and Windows events tab.
 * All interactive elements use data-action attributes — no inline onclick handlers.
 */

import { S } from './state.js';
import { CATS, SEVS, MITRE_TACTICS, MITRE_NAMES, WIN_EVENTS } from './constants.js';
import { esc, safeIP, safeMsg, safeSid, safePort, safeProto } from './sanitize.js';
import { getSev, getCat, getMitre, formatTime, timeSince } from './stats.js';

/**
 * Generates the HTML string for the main Snort IDS dashboard tab.
 * @param {Object}  st         - Statistics object returned by stats()
 * @param {Array}   filtered   - Filtered alert array from filterA()
 * @param {Object}  tc         - Threat level → colour map (e.g. {CRITICAL:'#DC2626',...})
 * @param {string}  tl         - Current threat level label ('CRITICAL'|'HIGH'|'MEDIUM'|'LOW')
 * @param {string}  threatMsg  - Message from the most recent critical alert (max 80 chars)
 * @returns {string} HTML string for the full Snort tab content
 */
export function renderSnort(st, filtered, tc, tl, threatMsg) {
  const mx          = Math.max(...Object.values(st.cats), 1);
  const mxS         = st.topSrc.length ? st.topSrc[0][1] : 1;
  const maxH        = Math.max(...Object.values(st.hourly), 1);
  const totalProto  = st.proto.TCP + st.proto.UDP + st.proto.ICMP || 1;
  const blocked     = S.blockedIPs || [];

  const today    = st.last7Days[6]?.count || 0;
  const yesterday = st.last7Days[5]?.count || 1;
  const trendPct  = ((today - yesterday) / yesterday * 100).toFixed(0);
  const trendUp   = today > yesterday;

  return `
    <!-- THREAT BANNER -->
    <div class="threat-banner ${st.crit === 0 ? 'safe' : ''}">
      <div class="threat-info">
        <span style="font-size:18px">${st.crit > 0 ? '🚨' : '🛡️'}</span>
        <div>
          <div class="threat-text" style="color:${st.crit > 0 ? '#EF4444' : '#10B981'}">${threatMsg}</div>
          <div style="font-size:9px;color:var(--dim);margin-top:2px">
            ${st.total} événements · ${st.topSrc.length} sources · ${Object.keys(S.geoData).length} géolocalisées
          </div>
        </div>
      </div>
      <div class="threat-count" style="color:${st.crit > 0 ? '#EF4444' : '#10B981'}">${st.crit}</div>
    </div>

    <!-- SOC OVERVIEW PANEL -->
    <div class="soc-overview">
      <div class="soc-metric">
        <div class="soc-metric-label">⏱️ MTTD</div>
        <div class="soc-metric-value">${st.mttd}<span style="font-size:12px;color:var(--dim)">min</span></div>
        <div class="soc-metric-sub">Mean Time To Detect</div>
      </div>
      <div class="soc-metric">
        <div class="soc-metric-label">📊 Taux d'alertes</div>
        <div class="soc-metric-value">${st.alertRate}<span style="font-size:12px;color:var(--dim)">/min</span></div>
        <div class="soc-metric-sub">Dernières 50 alertes</div>
      </div>
      <div class="soc-metric">
        <div class="soc-metric-label">👥 Attaquants uniques</div>
        <div class="soc-metric-value">${st.uniqueAttackers}</div>
        <div class="soc-metric-sub">Dernières 24 heures</div>
      </div>
      <div class="soc-metric">
        <div class="soc-metric-label">🎯 Port le plus ciblé</div>
        <div class="soc-metric-value">
          ${st.topPort ? st.topPort.port : '--'}
          <span style="font-size:12px;color:var(--dim)">${st.topPort ? '/' + st.topPort.service : ''}</span>
        </div>
        <div class="soc-metric-sub">${st.topPort ? st.topPort.count + ' attaques' : 'Aucune donnée'}</div>
      </div>
      <div class="soc-metric">
        <div class="soc-metric-label">📡 Distribution protocoles</div>
        <div class="soc-metric-value" style="font-size:14px;color:var(--text)">
          TCP ${Math.round(st.proto.TCP / totalProto * 100)}%
          · UDP ${Math.round(st.proto.UDP / totalProto * 100)}%
          · ICMP ${Math.round(st.proto.ICMP / totalProto * 100)}%
        </div>
        <div class="proto-bar">
          <div class="proto-segment" style="width:${st.proto.TCP / totalProto * 100}%;background:#3B82F6"></div>
          <div class="proto-segment" style="width:${st.proto.UDP / totalProto * 100}%;background:#F59E0B"></div>
          <div class="proto-segment" style="width:${st.proto.ICMP / totalProto * 100}%;background:#8B5CF6"></div>
        </div>
      </div>
    </div>

    <!-- STAT CARDS -->
    <div class="stat-cards">
      <div class="stat-card" style="background:linear-gradient(135deg,rgba(6,182,212,.08),rgba(6,182,212,.02));border-color:rgba(6,182,212,.1)">
        <div class="stat-label">Total</div>
        <div class="stat-value" style="color:var(--cyan)">${st.total}</div>
        <div class="stat-pct">${S.connected ? '⟳ Live 15s' : '○ Offline'}</div>
      </div>
      ${Object.entries(CATS).map(([k, c]) => `
        <div class="stat-card ${S.filter === k ? 'active' : ''}"
          style="background:linear-gradient(135deg,${c.color}10,${c.color}04);border-color:${c.color}15"
          data-action="filter" data-category="${k}">
          <div class="stat-top">
            <span class="stat-label">${c.label}</span>
            <span class="stat-icon">${c.icon}</span>
          </div>
          <div class="stat-value" style="color:${c.color}">${st.cats[k] || 0}</div>
          <div class="stat-pct">${((st.cats[k] || 0) / Math.max(st.total, 1) * 100).toFixed(1)}%</div>
        </div>`).join("")}
    </div>

    <!-- TIMELINE & TRENDS -->
    <div class="grid-3">
      <div class="card">
        <h3 class="card-title"><span class="card-title-icon">📅</span>Timeline 7 jours</h3>
        <div class="timeline-chart">
          ${st.last7Days.map(d => {
            const max = Math.max(...st.last7Days.map(x => x.count), 1);
            return `<div class="timeline-bar"
              style="height:${Math.max((d.count / max) * 100, 2)}%;background:${d.count > max * .7 ? 'var(--red)' : d.count > max * .4 ? 'var(--yellow)' : 'var(--cyan)'}"
              data-tooltip="${d.label}: ${d.count}"></div>`;
          }).join("")}
        </div>
        <div class="timeline-labels">
          ${st.last7Days.map((d, i) => i % 2 === 0 ? `<span>${d.label.split(' ')[0]}</span>` : '').join("")}
        </div>
      </div>
      <div class="card">
        <h3 class="card-title"><span class="card-title-icon">🕐</span>Alertes / Heure</h3>
        <div class="timeline-chart">
          ${Array.from({ length: 24 }, (_, i) => {
            const v = st.hourly[i] || 0;
            return `<div class="timeline-bar"
              style="height:${Math.max((v / maxH) * 100, 2)}%;background:${v > maxH * .7 ? 'var(--red)' : v > maxH * .4 ? 'var(--yellow)' : 'var(--blue)'}"
              data-tooltip="${i}h: ${v} alertes"></div>`;
          }).join("")}
        </div>
        <div class="timeline-labels"><span>0h</span><span>6h</span><span>12h</span><span>18h</span><span>23h</span></div>
      </div>
      <div class="card">
        <h3 class="card-title"><span class="card-title-icon">📈</span>Tendance</h3>
        <div class="trend-indicator"
          style="border-color:${trendUp ? 'rgba(239,68,68,.3)' : 'rgba(16,185,129,.3)'};background:${trendUp ? 'rgba(239,68,68,.08)' : 'rgba(16,185,129,.08)'}">
          <div class="trend-arrow" style="color:${trendUp ? 'var(--red)' : 'var(--green)'}"> ${trendUp ? '↗' : '↘'}</div>
          <div>
            <div class="trend-text">Aujourd'hui vs hier</div>
            <div class="trend-value" style="color:${trendUp ? 'var(--red)' : 'var(--green)'}">
              ${trendUp ? '+' : ''}${trendPct}%
            </div>
          </div>
        </div>
        <div style="margin-top:12px;font-size:10px;color:var(--muted)">Aujourd'hui: ${today} · Hier: ${yesterday}</div>
      </div>
    </div>

    <!-- MITRE HEATMAP & ACTIVE RESPONSE -->
    <div class="grid-2">
      <div class="card" style="grid-column:span 1">
        <h3 class="card-title">
          <span class="card-title-icon">⚔️</span>MITRE ATT&amp;CK Heatmap
          ${S.mitreFilter
            ? `<span style="color:var(--cyan);margin-left:8px">Filtré: ${esc(S.mitreFilter)}</span>
               <button data-action="mitre-clear"
                 style="border:none;background:rgba(255,255,255,.05);color:var(--cyan);cursor:pointer;padding:2px 6px;border-radius:3px;font-size:9px">✕</button>`
            : ''}
        </h3>
        ${renderMITREHeatmap(st.mitreC)}
      </div>
      <div class="card" style="grid-column:span 1">
        <h3 class="card-title">
          <span class="card-title-icon">🚫</span>Active Response — IPs bloquées (${blocked.length})
        </h3>
        ${blocked.length === 0
          ? '<div class="empty-state">Aucune IP bloquée actuellement</div>'
          : blocked.map(b => {
              const g    = S.geoData[b.ip];
              const mins = Math.floor(b.time_remaining / 60);
              const secs = b.time_remaining % 60;
              const timeStr = mins > 0 ? `${mins}m ${secs}s` : `${secs}s`;
              return `
                <div class="response-item">
                  <div class="response-ip">
                    ${safeIP(b.ip)}
                    ${g ? `<div style="font-size:9px;color:var(--dim)">${esc(g.country)}</div>` : ''}
                  </div>
                  <div class="response-reason">${esc((b.reason || '').substring(0, 60))}</div>
                  <div class="response-offense">#${b.offense_count || 1}</div>
                  <div class="response-duration">${esc(b.ban_duration_label || '')}</div>
                  <div class="response-time">
                    <div class="response-badge active">${timeStr}</div>
                  </div>
                  <button class="response-unblock-btn" data-action="unblock" data-ip="${safeIP(b.ip)}">
                    🔓 Débloquer
                  </button>
                </div>`;
            }).join("")}
        ${blocked.length > 0
          ? '<div style="margin-top:8px;font-size:9px;color:var(--dim)">Ban progressif: 10min → 1h → 24h → 7j · <span style="color:var(--orange)">Offense # = prochain ban plus long</span></div>'
          : ''}
      </div>
    </div>

    <!-- TOP SOURCES & LIVE FEED -->
    <div class="grid-2">
      <div class="card">
        <h3 class="card-title"><span class="card-title-icon">🌍</span>Top Attaquants</h3>
        ${st.topSrc.map(([ip, count], i) => {
          const g = S.geoData[ip];
          return `
            <div class="bar-row">
              <div class="bar-header">
                <span class="bar-label" style="${i === 0 ? 'color:#EF4444;font-weight:600' : ''}">
                  ${i === 0 ? '⚠ ' : ''}${safeIP(ip)}
                  ${g ? `<span style="color:var(--dim);font-size:9px">${esc(g.country)}</span>` : ''}
                </span>
                <span class="bar-count" style="color:var(--dim)">${count}</span>
              </div>
              <div class="bar-track">
                <div class="bar-fill" style="width:${(count / mxS) * 100}%;background:${i === 0 ? 'var(--red)' : 'var(--blue)'}"></div>
              </div>
            </div>`;
        }).join("")}
      </div>
      <div class="card">
        <h3 class="card-title">
          <span class="card-title-icon" style="${S.connected ? 'animation:pulse 2s ease infinite' : ''}">📡</span>
          Flux temps réel
        </h3>
        ${S.alerts.slice(0, 7).map((a, i) => {
          const sv  = getSev(a.rule?.level || 0);
          const cat = getCat(a.data?.msg);
          const c   = CATS[cat] || { color: '#6B7280', icon: '📋' };
          const sc  = SEVS[sv];
          const mt  = getMitre(a.data?.sid);
          return `
            <div class="feed-item ${sv}" style="animation:slideIn .3s ease ${i * .04}s both">
              <div class="feed-dot" style="background:${sc.color}"></div>
              <span class="feed-time">${formatTime(a.timestamp)}</span>
              <span style="font-size:12px">${c.icon}</span>
              <span class="feed-msg">
                ${safeMsg(a.data?.msg)}
                ${mt ? `<span class="mitre-tag" data-action="mitre-filter" data-technique="${mt}">${esc(mt)}</span>` : ''}
              </span>
              <span class="feed-src">${safeIP(a.data?.src_addr)}</span>
            </div>`;
        }).join("")}
        ${S.alerts.length === 0 ? '<div class="empty-state">Connectez OpenSearch</div>' : ''}
      </div>
    </div>

    <!-- FILTER & EXPORT BAR -->
    <div class="filter-bar">
      <div class="search-box">
        <span class="search-icon">⌕</span>
        <input class="search-input" type="text"
          placeholder="IP, message, SID, MITRE..."
          value="${S.search}"
          data-action="search">
      </div>
      <button class="filter-btn ${S.filter === 'all' ? 'active' : ''}" data-action="filter" data-category="all">Tout</button>
      ${Object.entries(CATS).map(([k, v]) =>
        `<button class="filter-btn ${S.filter === k ? 'active' : ''}" data-action="filter" data-category="${k}">${v.icon} ${v.label}</button>`
      ).join("")}
      <button class="sort-btn" data-action="toggle-sort">${S.sortDir === "desc" ? "↓ Récent" : "↑ Ancien"}</button>
      <button class="export-btn" data-action="export-csv">📄 CSV</button>
      <button class="export-btn" data-action="export-json">📋 JSON</button>
      <button class="export-btn" data-action="export-report">📊 Rapport</button>
    </div>

    <!-- ALERT TABLE -->
    <div class="table-wrap">
      <div class="table-header">
        <span data-action="toggle-sort">Heure</span>
        <span>Niveau</span>
        <span>Incident</span>
        <span>Source</span>
        <span>Destination</span>
        <span>Port</span>
        <span>Proto</span>
      </div>
      <div class="table-body">
        ${filtered.length === 0
          ? '<div class="empty-state">Aucun événement</div>'
          : filtered.slice(0, 150).map((a, i) => {
              const cat = getCat(a.data?.msg);
              const c   = CATS[cat] || { color: '#6B7280', icon: '📋' };
              const sv  = getSev(a.rule?.level || 0);
              const sc  = SEVS[sv];
              const mt  = getMitre(a.data?.sid);
              const g   = S.geoData[a.data?.src_addr];
              return `
                <div class="table-row ${sv === 'critical' ? 'crit-row' : ''}"
                  style="animation:fadeIn .15s ease ${Math.min(i * .01, .4)}s both"
                  data-action="show-detail" data-index="${i}">
                  <span class="cell-time">${formatTime(a.timestamp)}</span>
                  <span class="cell-sev" style="background:${sc.color}12;color:${sc.color}">${a.rule?.level || '?'}</span>
                  <div class="cell-msg">
                    <div class="cell-msg-text">
                      <span style="color:${c.color};margin-right:4px">${c.icon}</span>${safeMsg(a.data?.msg || a.rule?.description)}
                    </div>
                    <div class="cell-msg-sub">
                      SID ${safeSid(a.data?.sid)}
                      ${mt ? `· <span class="mitre-tag" data-action="mitre-filter" data-technique="${mt}">${esc(mt)}</span>` : ''}
                      ${g ? '· ' + esc(g.code) : ''}
                    </div>
                  </div>
                  <span class="cell-ip">${safeIP(a.data?.src_addr)}</span>
                  <span class="cell-ip dim">${safeIP(a.data?.dst_addr)}</span>
                  <span class="cell-port">${safePort(a.data?.dst_port)}</span>
                  <span class="cell-proto">${safeProto(a.data?.proto)}</span>
                </div>`;
            }).join("")}
      </div>
    </div>`;
}

/**
 * Generates the HTML string for the MITRE ATT&CK heatmap section.
 * Each technique cell uses data-action="mitre-filter" for filtering.
 * @param {Object.<string, number>} mitreC - Map of technique ID → alert count
 * @returns {string} HTML string for the heatmap
 */
export function renderMITREHeatmap(mitreC) {
  let html = '<div class="mitre-heatmap">';
  Object.entries(MITRE_TACTICS).forEach(([tactic, data]) => {
    const techniques = data.techniques.filter(t => mitreC[t] || false);
    if (techniques.length === 0) return;
    const maxCount = Math.max(...techniques.map(t => mitreC[t] || 0), 1);
    html += `
      <div class="mitre-tactic">
        <div class="mitre-tactic-title" style="color:${data.color}">▸ ${esc(tactic)}</div>
        <div class="mitre-techniques">
          ${techniques.map(t => {
            const count     = mitreC[t] || 0;
            const intensity = count / maxCount;
            const bg        = `rgba(139,92,246,${0.1 + intensity * 0.6})`;
            return `
              <div class="mitre-cell ${S.mitreFilter === t ? 'active' : ''}"
                style="background:${bg}"
                data-action="mitre-filter" data-technique="${t}">
                <span class="mitre-cell-id">${esc(t)}</span>
                <span class="mitre-cell-count">${count}</span>
                <span class="mitre-cell-name">${esc((MITRE_NAMES[t] || '').substring(0, 15))}</span>
              </div>`;
          }).join("")}
        </div>
      </div>`;
  });
  html += '</div>';
  return html;
}

/**
 * Generates the HTML string for the Windows Events tab.
 * @returns {string} HTML string for the full Windows tab content
 */
export function renderWindows() {
  const winStats    = {};
  const eventCat    = { Security: 0, System: 0, Application: 0 };
  const loginStats  = { success: 0, failed: 0 };
  const userStats   = {};
  const sevs        = { low: 0, medium: 0, high: 0, critical: 0 };

  S.winAlerts.forEach(a => {
    const desc = a.rule?.description || 'Other';
    winStats[desc] = (winStats[desc] || 0) + 1;
    sevs[getSev(a.rule?.level || 0)]++;

    const evtId = a.data?.win?.system?.eventID;
    const evt   = WIN_EVENTS[evtId];
    if (evt) {
      eventCat[evt.category] = (eventCat[evt.category] || 0) + 1;
      if (evtId === 4624) loginStats.success++;
      if (evtId === 4625) loginStats.failed++;
    }

    const user = a.data?.win?.system?.user || a.agent?.name || 'Unknown';
    userStats[user] = (userStats[user] || 0) + 1;
  });

  const topWin   = Object.entries(winStats).sort((a, b) => b[1] - a[1]).slice(0, 10);
  const topUsers = Object.entries(userStats).sort((a, b) => b[1] - a[1]).slice(0, 8);
  const maxU     = topUsers.length ? topUsers[0][1] : 1;

  return `
    <div class="grid-3" style="margin-bottom:14px">
      <div class="card">
        <h3 class="card-title"><span class="card-title-icon">🪟</span>Catégories Windows</h3>
        ${Object.entries(eventCat).map(([cat, count]) => {
          const color = cat === 'Security' ? '#3B82F6' : cat === 'System' ? '#F59E0B' : '#10B981';
          return `
            <div class="bar-row">
              <div class="bar-header">
                <span class="bar-label">${esc(cat)}</span>
                <span class="bar-count" style="color:${color}">${count}</span>
              </div>
              <div class="bar-track">
                <div class="bar-fill" style="width:${(count / Math.max(...Object.values(eventCat), 1)) * 100}%;background:${color}"></div>
              </div>
            </div>`;
        }).join("")}
      </div>
      <div class="card">
        <h3 class="card-title"><span class="card-title-icon">🔑</span>Activité de connexion</h3>
        <div style="display:flex;gap:20px;margin-bottom:16px">
          <div style="text-align:center;flex:1">
            <div style="font-size:26px;font-weight:800;color:var(--green);font-family:var(--sans)">${loginStats.success}</div>
            <div style="font-size:9px;color:var(--dim);text-transform:uppercase;letter-spacing:1px;margin-top:4px">✅ Réussis</div>
          </div>
          <div style="text-align:center;flex:1">
            <div style="font-size:26px;font-weight:800;color:var(--red);font-family:var(--sans)">${loginStats.failed}</div>
            <div style="font-size:9px;color:var(--dim);text-transform:uppercase;letter-spacing:1px;margin-top:4px">❌ Échoués</div>
          </div>
        </div>
        <div style="font-size:10px;color:var(--muted)">EventID 4624/4625</div>
      </div>
      <div class="card">
        <h3 class="card-title"><span class="card-title-icon">📊</span>Sévérité</h3>
        ${Object.entries(SEVS).map(([k, c]) => `
          <div class="bar-row">
            <div class="bar-header">
              <span class="bar-label">${c.label}</span>
              <span class="bar-count" style="color:${c.color}">${sevs[k]}</span>
            </div>
            <div class="bar-track">
              <div class="bar-fill" style="width:${(sevs[k] / Math.max(S.winAlerts.length, 1)) * 100}%;background:${c.color}"></div>
            </div>
          </div>`).join("")}
      </div>
    </div>

    <div class="grid-2" style="margin-bottom:14px">
      <div class="card">
        <h3 class="card-title"><span class="card-title-icon">👥</span>Activité utilisateurs</h3>
        ${topUsers.map(([user, count]) => `
          <div class="bar-row">
            <div class="bar-header">
              <span class="bar-label">${esc(user.substring(0, 30))}</span>
              <span class="bar-count" style="color:var(--cyan)">${count}</span>
            </div>
            <div class="bar-track">
              <div class="bar-fill" style="width:${(count / maxU) * 100}%;background:var(--cyan)"></div>
            </div>
          </div>`).join("")}
      </div>
      <div class="card">
        <h3 class="card-title"><span class="card-title-icon">📋</span>Top Événements</h3>
        ${topWin.slice(0, 8).map(([desc, count]) => `
          <div style="display:flex;justify-content:space-between;padding:4px 0;border-bottom:1px solid rgba(255,255,255,.03)">
            <span style="font-size:10px;color:var(--muted);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
              ${esc(desc.substring(0, 50))}
            </span>
            <span style="font-size:10px;color:var(--cyan);font-weight:600;margin-left:8px">${count}</span>
          </div>`).join("")}
      </div>
    </div>

    <!-- Windows alerts table -->
    <div class="table-wrap">
      <div class="table-header" style="grid-template-columns:85px 56px 1fr 130px 80px">
        <span>Heure</span><span>Niveau</span><span>Description</span><span>Agent</span><span>Rule ID</span>
      </div>
      <div class="table-body">
        ${S.winAlerts.length === 0
          ? '<div class="empty-state">Aucun événement Windows</div>'
          : S.winAlerts.slice(0, 100).map((a, i) => {
              const sv = getSev(a.rule?.level || 0);
              const sc = SEVS[sv];
              return `
                <div class="table-row"
                  style="grid-template-columns:85px 56px 1fr 130px 80px;animation:fadeIn .15s ease ${Math.min(i * .01, .3)}s both">
                  <span class="cell-time">${formatTime(a.timestamp)}</span>
                  <span class="cell-sev" style="background:${sc.color}12;color:${sc.color}">${a.rule?.level || '?'}</span>
                  <div class="cell-msg">
                    <div class="cell-msg-text">${esc((a.rule?.description || '').substring(0, 80))}</div>
                    <div class="cell-msg-sub">${esc((a.rule?.groups || []).join(', ').substring(0, 50))}</div>
                  </div>
                  <span class="cell-ip">${esc(a.agent?.name || '?')}</span>
                  <span style="font-size:10px;color:var(--dim);text-align:center">${esc(String(a.rule?.id || '?'))}</span>
                </div>`;
            }).join("")}
      </div>
    </div>`;
}
