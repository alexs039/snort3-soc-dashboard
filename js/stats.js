/**
 * Statistics, filtering, and formatting utilities for alert data.
 */

import { CATS, SEVS, SID_MITRE, PORT_SERVICES } from './constants.js';
import { S } from './state.js';

/**
 * Determines the alert category from the Snort message prefix.
 * @param {string} m - Alert message string (e.g. 'SCAN XMAS')
 * @returns {string} Category key: 'recon' | 'web_attack' | 'dos' | 'malware' | 'other'
 * @example getCat('SCAN XMAS') // 'recon'
 * @example getCat('INTRUSION HTTP SQL Injection') // 'web_attack'
 * @example getCat('MALWARE C2 Beacon') // 'malware'
 */
export function getCat(m) {
  if (!m) return "other";
  if (m.startsWith("SCAN")) return "recon";
  if (m.startsWith("INTRUSION HTTP")) return "web_attack";
  if (m.startsWith("INTRUSION DOS")) return "dos";
  if (m.startsWith("MALWARE")) return "malware";
  return "other";
}

/**
 * Determines the severity level from a Wazuh rule level number.
 * @param {number} l - Wazuh rule level (numeric)
 * @returns {string} Severity key: 'low' | 'medium' | 'high' | 'critical'
 * @example getSev(14) // 'critical'
 * @example getSev(10) // 'high'
 * @example getSev(5)  // 'low'
 */
export function getSev(l) {
  if (l >= 12) return "critical";
  if (l >= 10) return "high";
  if (l >= 8)  return "medium";
  return "low";
}

/**
 * Maps a Snort SID to its corresponding MITRE ATT&CK technique ID.
 * @param {number|string} sid - Snort rule SID
 * @returns {string|null} MITRE technique ID (e.g. 'T1046') or null if not mapped
 * @example getMitre(9001001) // 'T1046'
 * @example getMitre(99999)   // null
 */
export function getMitre(sid) {
  return SID_MITRE[parseInt(sid)] || null;
}

/**
 * Formats a timestamp as a locale time string (fr-FR).
 * @param {string|number} ts - ISO 8601 timestamp string or Unix milliseconds
 * @returns {string} Formatted time string (e.g. '14:35:01') or '--' on error
 * @example formatTime('2024-01-15T14:35:01Z') // '15:35:01'
 */
export function formatTime(ts) {
  try { return new Date(ts).toLocaleTimeString("fr-FR"); } catch (e) { return "--"; }
}

/**
 * Formats a timestamp as a locale date string (fr-FR).
 * @param {string|number} ts - ISO 8601 timestamp string or Unix milliseconds
 * @returns {string} Formatted date string (e.g. '15 janv.') or '--' on error
 */
export function formatDate(ts) {
  try {
    return new Date(ts).toLocaleDateString("fr-FR", { day: "2-digit", month: "short" });
  } catch (e) { return "--"; }
}

/**
 * Returns a human-readable string for the time elapsed since a timestamp.
 * @param {string|number} ts - ISO 8601 timestamp or Unix milliseconds
 * @returns {string} Elapsed time string (e.g. '5s', '3m', '2h', '1j') or '--' on error
 * @example timeSince(Date.now() - 90000) // '1m'
 */
export function timeSince(ts) {
  try {
    const sec = Math.floor((Date.now() - new Date(ts).getTime()) / 1000);
    if (sec < 60) return sec + "s";
    if (sec < 3600) return Math.floor(sec / 60) + "m";
    if (sec < 86400) return Math.floor(sec / 3600) + "h";
    return Math.floor(sec / 86400) + "j";
  } catch (e) { return "--"; }
}

/**
 * Computes comprehensive statistics from an array of Snort/Wazuh alert objects.
 * @param {Array} alerts - Array of Wazuh alert source objects
 * @returns {{
 *   cats: Object, sevs: Object, crit: number, total: number,
 *   topSrc: Array, topMitre: Array, mitreC: Object,
 *   hourly: Object, daily: Object, mttd: string, alertRate: string,
 *   uniqueAttackers: number, topPort: Object|null, proto: Object, last7Days: Array
 * }} Aggregated statistics object
 */
export function stats(alerts) {
  const cats = { recon: 0, web_attack: 0, dos: 0, malware: 0 };
  const sevs = { low: 0, medium: 0, high: 0, critical: 0 };
  const sources = {};
  const mitreC = {};
  const hourly = {};
  const daily = {};
  const ports = {};
  const proto = { TCP: 0, UDP: 0, ICMP: 0 };
  let crit = 0;
  let totalTime = 0;
  let validTimeCount = 0;

  const now = Date.now();
  const last24h = now - 86400000;
  const last50 = alerts.slice(0, 50);

  alerts.forEach(a => {
    const cat = getCat(a.data?.msg);
    if (cats[cat] !== undefined) cats[cat]++;
    const sv = getSev(a.rule?.level || 0);
    sevs[sv]++;
    if (sv === "critical" || sv === "high") crit++;
    const src = String(a.data?.src_addr || "?").replace(/[^0-9a-fA-F.:\/]/g, '');
    sources[src] = (sources[src] || 0) + 1;
    const m = getMitre(a.data?.sid);
    if (m) mitreC[m] = (mitreC[m] || 0) + 1;

    try {
      const ts = new Date(a.timestamp).getTime();
      if (ts > last24h) { totalTime += now - ts; validTimeCount++; }
      const h = new Date(ts).getHours();
      hourly[h] = (hourly[h] || 0) + 1;
      const d = new Date(ts).toLocaleDateString("fr-FR");
      daily[d] = (daily[d] || 0) + 1;
    } catch (e) {}

    const port = a.data?.dst_port;
    if (port) ports[port] = (ports[port] || 0) + 1;
    const p = String(a.data?.proto || "").toUpperCase();
    if (proto[p] !== undefined) proto[p]++;
  });

  const mttd = validTimeCount > 0 ? (totalTime / validTimeCount / 1000 / 60) : 0;

  let alertRate = 0;
  if (last50.length >= 2) {
    try {
      const firstTs = new Date(last50[0].timestamp).getTime();
      const lastTs = new Date(last50[last50.length - 1].timestamp).getTime();
      const diffMin = (firstTs - lastTs) / 1000 / 60;
      if (diffMin > 0) alertRate = last50.length / diffMin;
    } catch (e) {}
  }

  const uniqueAttackers = new Set();
  alerts.forEach(a => {
    try {
      if (new Date(a.timestamp).getTime() > last24h) uniqueAttackers.add(a.data?.src_addr);
    } catch (e) {}
  });

  const topPort = Object.entries(ports).sort((a, b) => b[1] - a[1])[0];

  const last7Days = [];
  for (let i = 6; i >= 0; i--) {
    const d = new Date(now - i * 86400000);
    const key = d.toLocaleDateString("fr-FR");
    last7Days.push({
      date: key,
      count: daily[key] || 0,
      label: d.toLocaleDateString("fr-FR", { day: "2-digit", month: "short" }),
    });
  }

  return {
    cats, sevs, crit, total: alerts.length,
    topSrc: Object.entries(sources).sort((a, b) => b[1] - a[1]).slice(0, 8),
    topMitre: Object.entries(mitreC).sort((a, b) => b[1] - a[1]).slice(0, 6),
    mitreC, hourly, daily,
    mttd: mttd.toFixed(1),
    alertRate: alertRate.toFixed(2),
    uniqueAttackers: uniqueAttackers.size,
    topPort: topPort
      ? { port: topPort[0], count: topPort[1], service: PORT_SERVICES[topPort[0]] || "Unknown" }
      : null,
    proto, last7Days,
  };
}

/**
 * Returns the filtered and sorted subset of S.alerts based on current state
 * (S.filter, S.mitreFilter, S.search, S.sortDir).
 * @returns {Array} Filtered (and optionally reversed) alert array
 */
export function filterA() {
  let f = S.alerts;
  if (S.filter !== "all") f = f.filter(a => getCat(a.data?.msg) === S.filter);
  if (S.mitreFilter) f = f.filter(a => getMitre(a.data?.sid) === S.mitreFilter);
  if (S.search) {
    const s = S.search.toLowerCase();
    f = f.filter(a =>
      (a.data?.msg || "").toLowerCase().includes(s) ||
      (a.data?.src_addr || "").includes(s) ||
      (a.data?.dst_addr || "").includes(s) ||
      (a.data?.sid || "").includes(s) ||
      (getMitre(a.data?.sid) || "").toLowerCase().includes(s)
    );
  }
  return S.sortDir === "desc" ? f : [...f].reverse();
}
