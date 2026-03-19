/**
 * Renders the world attack map tab using Leaflet.js.
 * All interactive elements use data-action attributes — no inline onclick handlers.
 * The Leaflet map instance is stored at module scope to avoid re-initialization on re-renders.
 */

import { S } from './state.js';
import { COUNTRIES } from './constants.js';
import { esc, safeIP } from './sanitize.js';

/**
 * Module-level Leaflet map instance.
 * Persisted across renders to avoid destroying and recreating the map.
 * @type {L.Map|null}
 */
let leafletMap = null;

/**
 * Module-level Leaflet layer group for attack markers and lines.
 * Cleared and repopulated on each renderMap() call.
 * @type {L.LayerGroup|null}
 */
let leafletAttackLayer = null;

/**
 * Generates the HTML string for the map tab content.
 * Does NOT initialize or update the Leaflet map — call renderMap() after this
 * HTML has been injected into the DOM.
 * @param {Object} st           - Statistics object from stats()
 * @param {Array}  topCountries - Top [country, count] pairs sorted descending
 * @returns {string} HTML string for the map tab
 */
export function renderMapTab(st, topCountries) {
  const mxC = topCountries.length ? topCountries[0][1] : 1;
  const countries = Object.keys(S.geoData).length;
  const totalAttacks = st.total;
  const mostActive = topCountries[0] ? topCountries[0][0] : 'N/A';
  const serverInfo = COUNTRIES[S.config.serverCountry] || COUNTRIES['JP'];

  return `
    <div class="grid-2">
      <div class="card" style="grid-column:span 2">
        <h3 class="card-title"><span class="card-title-icon">🗺️</span>Carte des attaques — Géolocalisation des sources</h3>
        <div class="map-container">
          <div id="worldmap" style="width:100%;height:100%;border-radius:8px"></div>
          <div class="map-stats-overlay">
            <div class="map-stats-item">Total:<span class="map-stats-value">${totalAttacks}</span></div>
            <div class="map-stats-item">Pays:<span class="map-stats-value">${countries}</span></div>
            <div class="map-stats-item">Plus actif:<span class="map-stats-value">${esc(mostActive.substring(0, 12))}</span></div>
          </div>
        </div>
        <div class="map-legend">
          <div class="map-legend-item"><div class="map-legend-dot" style="background:#10B981"></div>Serveur cible (${esc(serverInfo.name)})</div>
          <div class="map-legend-item"><div class="map-legend-dot" style="background:var(--blue)"></div>Faible (1-3)</div>
          <div class="map-legend-item"><div class="map-legend-dot" style="background:var(--yellow)"></div>Moyen (4-10)</div>
          <div class="map-legend-item"><div class="map-legend-dot" style="background:var(--red)"></div>Élevé (11-50)</div>
          <div class="map-legend-item"><div class="map-legend-dot" style="background:var(--crimson)"></div>Critique (50+)</div>
        </div>
      </div>
    </div>
    <div class="grid-2">
      <div class="card">
        <h3 class="card-title"><span class="card-title-icon">🏴</span>Top Pays attaquants</h3>
        ${topCountries.map(([country, count], i) => `
          <div class="bar-row">
            <div class="bar-header">
              <span class="bar-label" style="${i === 0 ? 'color:var(--red);font-weight:600' : ''}">${esc(country)}</span>
              <span class="bar-count" style="color:var(--dim)">${count}</span>
            </div>
            <div class="bar-track">
              <div class="bar-fill" style="width:${(count / mxC) * 100}%;background:${i === 0 ? 'var(--red)' : 'var(--blue)'}"></div>
            </div>
          </div>`).join("")}
        ${topCountries.length === 0 ? '<div style="color:var(--dark);font-size:10px">Géolocalisation en cours...</div>' : ''}
      </div>
      <div class="card">
        <h3 class="card-title"><span class="card-title-icon">📍</span>IPs géolocalisées</h3>
        ${Object.entries(S.geoData).slice(0, 8).map(([ip, g]) => `
          <div style="display:flex;justify-content:space-between;padding:4px 0;border-bottom:1px solid rgba(255,255,255,.03);font-size:10px">
            <span style="color:var(--muted)">${safeIP(ip)}</span>
            <span style="color:var(--dim)">${esc(g.country)} · ${esc((g.org || '').substring(0, 20))}</span>
          </div>`).join("")}
        ${Object.keys(S.geoData).length === 0
          ? '<div style="color:var(--dark);font-size:10px">Connectez OpenSearch pour géolocaliser</div>'
          : ''}
      </div>
    </div>`;
}

/**
 * Initializes (if needed) and updates the Leaflet map with current attack data.
 * Uses requestAnimationFrame to ensure the #worldmap container is in the DOM.
 * Reuses the existing map instance if the container was not replaced since last render.
 * @returns {void}
 */
export function renderMap() {
  requestAnimationFrame(() => {
    const container = document.getElementById('worldmap');
    if (!container) return;

    // If the container was replaced by a re-render, the Leaflet ID is gone — reset
    if (leafletMap && !container._leaflet_id) {
      leafletMap = null;
      leafletAttackLayer = null;
    }

    if (!leafletMap) {
      leafletMap = L.map('worldmap', {
        zoomControl: true,
        scrollWheelZoom: true,
        attributionControl: true,
      }).setView([20, 10], 2);

      L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
        attribution:
          '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors ' +
          '&copy; <a href="https://carto.com/attributions">CARTO</a>',
        subdomains: 'abcd',
        maxZoom: 19,
      }).addTo(leafletMap);

      leafletAttackLayer = L.layerGroup().addTo(leafletMap);
    }

    leafletAttackLayer.clearLayers();

    const serverInfo = COUNTRIES[S.config.serverCountry] || COUNTRIES['JP'];
    const serverLat  = serverInfo.lat;
    const serverLng  = serverInfo.lng;

    const serverIcon = L.divIcon({
      className: '',
      html: '<div class="server-marker"></div>',
      iconSize: [16, 16],
      iconAnchor: [8, 8],
    });
    L.marker([serverLat, serverLng], { icon: serverIcon, zIndexOffset: 1000 })
      .bindPopup(
        `<strong>🎯 TARGET (Serveur) — ${esc(serverInfo.name)}</strong><br>` +
        `<span style="color:#10B981">${esc(S.config.targetName)}</span>`
      )
      .addTo(leafletAttackLayer);

    const srcCount = {};
    S.alerts.forEach(a => {
      const ip = a.data?.src_addr;
      if (ip) srcCount[ip] = (srcCount[ip] || 0) + 1;
    });

    Object.entries(S.geoData).forEach(([ip, geo]) => {
      const count  = srcCount[ip] || 1;
      const color  = count > 50 ? '#DC2626' : count > 10 ? '#EF4444' : count > 3 ? '#F59E0B' : '#3B82F6';
      const radius = Math.min(5 + Math.log(count) * 3, 20);

      L.polyline([[geo.lat, geo.lng], [serverLat, serverLng]], {
        color,
        weight: Math.min(1 + count / 20, 3),
        opacity: 0.5,
      }).addTo(leafletAttackLayer);

      L.circleMarker([geo.lat, geo.lng], {
        radius,
        fillColor: color,
        color,
        weight: 1,
        opacity: 1,
        fillOpacity: 0.7,
      })
        .bindPopup(
          `<strong>${safeIP(ip)}</strong><br>` +
          `${esc(geo.country || '')} · ${esc(geo.code || '')}<br>` +
          `<span style="color:#94A3B8">${esc((geo.org || 'N/A').substring(0, 40))}</span><br>` +
          `<strong style="color:${color}">${count} alerte${count > 1 ? 's' : ''}</strong>`
        )
        .addTo(leafletAttackLayer);
    });
  });
}
