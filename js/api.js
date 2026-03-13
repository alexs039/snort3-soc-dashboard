/**
 * API communication layer for OpenSearch, geolocation, and block management.
 * All network calls that read or write data live here.
 */

import { S } from './state.js';
import { getSev } from './stats.js';
import { render } from './render.js';

/** @type {Object.<string, Object>} In-memory geo lookup cache keyed by IP address. */
const geoCache = {};

/**
 * Returns true if the given IP address is a private, loopback, or link-local address.
 * Public IPs return false and are eligible for geo lookup.
 * @param {string} ip - IP address to test
 * @returns {boolean} True if private / reserved, false if public
 * @example isPrivateIP('192.168.1.1') // true
 * @example isPrivateIP('8.8.8.8')     // false
 */
export function isPrivateIP(ip) {
  if (!ip) return true;
  return /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.|169\.254\.|::1$|fc[0-9a-f]{2}:|fd[0-9a-f]{2}:|fe80:)/.test(ip.toLowerCase());
}

/**
 * Looks up geolocation data for a public IP address via the /geo proxy.
 * Results are cached in memory to avoid redundant requests.
 * @param {string} ip - Public IP address to resolve
 * @returns {Promise<Object|null>} ip-api.com response object or null on failure
 */
export async function geoLookup(ip) {
  if (geoCache[ip]) return geoCache[ip];
  try {
    const r = await fetch(`/geo/json/${ip}?fields=country,countryCode,lat,lon,org`);
    if (r.ok) {
      const d = await r.json();
      if (d.lat) { geoCache[ip] = d; return d; }
    }
  } catch (e) {}
  return null;
}

/**
 * Builds the HTTP Basic Authorization header value from current config credentials.
 * @returns {string} Base64-encoded 'Basic <credentials>' header value
 */
export function authH() {
  return "Basic " + btoa(`${S.config.username}:${S.config.password}`);
}

/**
 * Plays a short beep sound to alert the operator of new critical events.
 * Uses the Web Audio API. Safe to call if AudioContext is unavailable.
 * @returns {void}
 */
export function playAlertSound() {
  const audioCtx = new (window.AudioContext || window.webkitAudioContext)();
  const osc = audioCtx.createOscillator();
  const gain = audioCtx.createGain();
  osc.connect(gain);
  gain.connect(audioCtx.destination);
  osc.frequency.value = 800;
  osc.type = 'sine';
  gain.gain.setValueAtTime(0.1, audioCtx.currentTime);
  gain.gain.exponentialRampToValueAtTime(0.01, audioCtx.currentTime + 0.3);
  osc.start(audioCtx.currentTime);
  osc.stop(audioCtx.currentTime + 0.3);
}

/**
 * Fetches the latest Snort IDS and Windows event alerts from OpenSearch.
 * Updates S.alerts, S.winAlerts, S.connected, S.error, and triggers a re-render.
 * Also kicks off geo resolution and blocked-IP refresh.
 * @returns {Promise<void>}
 */
export async function fetchAlerts() {
  if (!S.config.password) return;
  S.loading = true;
  render();
  try {
    const r = await fetch(`${S.config.url}/wazuh-alerts-*/_search`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Authorization": authH() },
      body: JSON.stringify({
        size: 500,
        query: { bool: { must: [{ match: { "rule.groups": "snort3" } }] } },
        sort: [{ timestamp: { order: "desc" } }],
      }),
    });
    if (!r.ok) throw new Error("HTTP " + r.status);
    const d = await r.json();
    if (d.hits?.hits?.length) {
      const oldCount = S.alerts.length;
      S.alerts = d.hits.hits.map(h => h._source);
      if (S.soundEnabled && S.alerts.length > oldCount) {
        const newCrit = S.alerts
          .slice(0, S.alerts.length - oldCount)
          .filter(a => getSev(a.rule?.level || 0) === "critical");
        if (newCrit.length > 0) playAlertSound();
      }
    }

    const r2 = await fetch(`${S.config.url}/wazuh-alerts-*/_search`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Authorization": authH() },
      body: JSON.stringify({
        size: 200,
        query: { bool: { must: [{ match: { "agent.os.platform": "windows" } }] } },
        sort: [{ timestamp: { order: "desc" } }],
      }),
    });
    if (r2.ok) {
      const d2 = await r2.json();
      if (d2.hits?.hits?.length) S.winAlerts = d2.hits.hits.map(h => h._source);
    }

    S.connected = true; S.error = ""; S.lastUpdate = Date.now(); S.loading = false;
    resolveGeo();
    fetchBlockedIPs();
    render();
  } catch (e) {
    S.error = e.message; S.connected = false; S.loading = false; render();
  }
}

/**
 * Resolves geolocation data for the top unresolved public source IPs in S.alerts.
 * Adds results to S.geoData with a 250 ms delay between requests to respect rate limits.
 * Sets S.mapReady = true and triggers a re-render when new data is available.
 * @returns {Promise<void>}
 */
export async function resolveGeo() {
  const ips = {};
  S.alerts.forEach(a => {
    const ip = a.data?.src_addr;
    if (ip && !isPrivateIP(ip) && !S.geoData[ip]) ips[ip] = 1;
  });
  const unique = Object.keys(ips).slice(0, 30);
  for (const ip of unique) {
    const g = await geoLookup(ip);
    if (g) {
      S.geoData[ip] = { lat: g.lat, lng: g.lon, country: g.country, code: g.countryCode, org: g.org };
    }
    await new Promise(r => setTimeout(r, 250));
  }
  if (unique.length > 0) { S.mapReady = true; render(); }
}

/**
 * Fetches the current list of blocked IPs from the block management API.
 * Updates S.blockedIPs. Silently fails if the API is unavailable.
 * @returns {Promise<void>}
 */
export async function fetchBlockedIPs() {
  try {
    const r = await fetch("/api/blocks/blocked");
    if (r.ok) { const d = await r.json(); S.blockedIPs = d.blocked || []; }
  } catch (e) { S.blockedIPs = []; }
}

/**
 * Sends an unblock request for the given IP address to the block API.
 * Refreshes the blocked IP list and re-renders on success.
 * @param {string} ip - IP address to unblock
 * @returns {Promise<void>}
 */
export async function unblockIP(ip) {
  try {
    const r = await fetch("/api/blocks/unblock", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ip }),
    });
    if (r.ok) { await fetchBlockedIPs(); render(); }
    else { S.error = "Erreur lors du déblocage de l'IP"; render(); }
  } catch (e) { S.error = "Erreur réseau: " + e.message; render(); }
}

/**
 * Connects to OpenSearch using the current configuration, then starts the
 * 15-second auto-refresh interval. Hides the config modal on success.
 * @returns {Promise<void>}
 */
export async function connect() {
  S.error = "";
  await fetchAlerts();
  if (S.connected) {
    if (S.refreshInterval) clearInterval(S.refreshInterval);
    S.refreshInterval = setInterval(fetchAlerts, 15000);
  }
  S.showConfig = false;
  render();
}
