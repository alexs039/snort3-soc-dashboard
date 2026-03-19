/**
 * Renders the OpenSearch configuration modal.
 * All interactive elements use data-action attributes — no inline onclick handlers.
 */

import { S } from './state.js';
import { COUNTRIES } from './constants.js';
import { esc } from './sanitize.js';

/**
 * Generates the HTML string for the configuration modal overlay.
 * The modal lets the user enter OpenSearch URL, credentials, server country,
 * and target name. All fields use data-action="config-input" for event delegation.
 * Clicking outside the modal (the overlay itself) closes it via data-action="modal-overlay".
 * @returns {string} HTML string for the full modal overlay
 */
export function renderCfg() {
  const countryOptions = Object.entries(COUNTRIES)
    .map(([code, c]) =>
      `<option value="${esc(code)}" ${S.config.serverCountry === code ? 'selected' : ''}>${esc(c.name)}</option>`
    ).join("");

  return `
    <div class="modal-overlay" data-action="modal-overlay">
      <div class="modal">
        <div class="modal-head">
          <h2>⚙ OpenSearch</h2>
          <button class="modal-close" data-action="close-config">×</button>
        </div>
        ${S.connected
          ? `<div class="ok-badge">● Connecté · ${S.alerts.length} alertes Snort · ${S.winAlerts.length} alertes Windows</div>`
          : ''}
        ${S.error ? `<div class="err-badge">✗ ${esc(S.error)}</div>` : ''}
        <div class="modal-field">
          <label class="modal-label">URL OpenSearch</label>
          <input class="modal-input" value="${esc(S.config.url)}"
            data-action="config-input" data-field="url">
        </div>
        <div class="modal-field">
          <label class="modal-label">Utilisateur</label>
          <input class="modal-input" value="${esc(S.config.username)}"
            data-action="config-input" data-field="username">
        </div>
        <div class="modal-field">
          <label class="modal-label">Mot de passe</label>
          <input class="modal-input" type="password" value="${esc(S.config.password)}"
            data-action="config-input" data-field="password">
        </div>
        <div class="modal-field">
          <label class="modal-label">Nom du serveur cible</label>
          <input class="modal-input" value="${esc(S.config.targetName)}"
            data-action="config-input" data-field="targetName">
        </div>
        <div class="modal-field">
          <label class="modal-label">Pays du serveur</label>
          <select class="modal-input" data-action="config-input" data-field="serverCountry" data-rerender="true">
            ${countryOptions}
          </select>
        </div>
        <div class="modal-btns">
          <button class="btn-primary" data-action="connect">Connecter</button>
          <button class="btn-secondary" data-action="close-config">Annuler</button>
        </div>
        <p class="modal-hint">Proxy Caddy → OpenSearch · Snort IDS + Windows via Wazuh agents</p>
      </div>
    </div>`;
}
