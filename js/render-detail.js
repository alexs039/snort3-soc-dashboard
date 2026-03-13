/**
 * Renders the alert detail side panel.
 * All interactive elements use data-action attributes — no inline onclick handlers.
 */

import { S } from './state.js';
import { SEVS, MITRE_NAMES, PORT_SERVICES } from './constants.js';
import { esc, safeIP, safePort, safeProto, safeSid } from './sanitize.js';
import { getSev, getMitre, timeSince, filterA } from './stats.js';

/**
 * Generates the HTML string for the alert detail panel overlay.
 * Displays full information about the alert at index `idx` in the current
 * filtered alert list (filterA()).
 * @param {number} idx - Index of the alert in filterA() to display
 * @returns {string} HTML string for the detail overlay and panel, or '' if index is invalid
 */
export function renderDetailPanel(idx) {
  const a = filterA()[idx];
  if (!a) return '';

  const sv = getSev(a.rule?.level || 0);
  const sc = SEVS[sv];
  const mt = getMitre(a.data?.sid);
  const g  = S.geoData[a.data?.src_addr];
  const isBlocked = (a.rule?.description || "").includes("BLOCKED");

  return `
    <div class="detail-overlay" data-action="close-detail"></div>
    <div class="detail-panel">
      <div class="detail-header">
        <div class="detail-title">📋 Détail de l'alerte</div>
        <button class="detail-close" data-action="close-detail">×</button>
      </div>
      <div class="detail-body">
        <div class="detail-section">
          <div class="detail-section-title">Informations générales</div>
          ${isBlocked ? '<div class="detail-badge blocked">🚫 IP BLOQUÉE PAR ACTIVE RESPONSE</div>' : ''}
          <div class="detail-field">
            <div class="detail-field-label">Timestamp</div>
            <div class="detail-field-value">${esc(a.timestamp)} (${timeSince(a.timestamp)} ago)</div>
          </div>
          <div class="detail-field">
            <div class="detail-field-label">Sévérité</div>
            <div class="detail-field-value">
              <span class="cell-sev" style="background:${sc.color}12;color:${sc.color};padding:4px 8px">
                ${a.rule?.level || '?'} — ${sc.label}
              </span>
            </div>
          </div>
          <div class="detail-field">
            <div class="detail-field-label">Message</div>
            <div class="detail-field-value">${esc(a.data?.msg || a.rule?.description || 'N/A')}</div>
          </div>
          <div class="detail-field">
            <div class="detail-field-label">SID</div>
            <div class="detail-field-value">${safeSid(a.data?.sid)}</div>
          </div>
          <div class="detail-field">
            <div class="detail-field-label">Catégorie</div>
            <div class="detail-field-value">${esc((a.rule?.groups || []).join(', '))}</div>
          </div>
        </div>

        ${mt ? `
        <div class="detail-section">
          <div class="detail-section-title">MITRE ATT&amp;CK</div>
          <div class="detail-field">
            <div class="detail-field-label">Technique</div>
            <div class="detail-field-value">
              <span class="mitre-tag" style="font-size:11px;padding:4px 10px">${esc(mt)}</span>
              ${esc(MITRE_NAMES[mt] || '')}
            </div>
          </div>
          <div class="detail-field">
            <div class="detail-field-label">Description</div>
            <div class="detail-field-value">
              Technique de la matrice MITRE ATT&amp;CK utilisée pour classifier cette attaque.
            </div>
          </div>
        </div>` : ''}

        <div class="detail-section">
          <div class="detail-section-title">Réseau</div>
          <div class="detail-field">
            <div class="detail-field-label">Adresse source</div>
            <div class="detail-field-value">${safeIP(a.data?.src_addr)}</div>
          </div>
          <div class="detail-field">
            <div class="detail-field-label">Adresse destination</div>
            <div class="detail-field-value">${safeIP(a.data?.dst_addr)}</div>
          </div>
          <div class="detail-field">
            <div class="detail-field-label">Port destination</div>
            <div class="detail-field-value">
              ${safePort(a.data?.dst_port)}
              ${PORT_SERVICES[a.data?.dst_port] ? ' (' + PORT_SERVICES[a.data?.dst_port] + ')' : ''}
            </div>
          </div>
          <div class="detail-field">
            <div class="detail-field-label">Protocole</div>
            <div class="detail-field-value">${safeProto(a.data?.proto)}</div>
          </div>
        </div>

        ${g ? `
        <div class="detail-section">
          <div class="detail-section-title">Géolocalisation</div>
          <div class="detail-field">
            <div class="detail-field-label">Pays</div>
            <div class="detail-field-value">${esc(g.country)} (${esc(g.code)})</div>
          </div>
          <div class="detail-field">
            <div class="detail-field-label">Coordonnées</div>
            <div class="detail-field-value">Lat: ${esc(String(g.lat))}, Lng: ${esc(String(g.lng))}</div>
          </div>
          <div class="detail-field">
            <div class="detail-field-label">Organisation</div>
            <div class="detail-field-value">${esc(g.org || 'N/A')}</div>
          </div>
        </div>` : ''}

        <div class="detail-section">
          <div class="detail-section-title">JSON brut</div>
          <button class="detail-btn" data-action="copy-json">📋 Copier JSON</button>
          <div class="detail-json">${esc(JSON.stringify(a, null, 2))}</div>
        </div>
      </div>
    </div>`;
}
