/**
 * Application state singleton for the SNORT3 SOC Dashboard.
 *
 * This object is mutated in place by all modules — never reassign S itself,
 * only mutate its properties (e.g. `S.tab = 'map'`, not `S = {...}`).
 */

/**
 * @typedef {Object} AppConfig
 * @property {string} url           - OpenSearch proxy URL
 * @property {string} username      - OpenSearch username
 * @property {string} password      - OpenSearch password
 * @property {string} serverCountry - ISO 3166-1 alpha-2 country code of the monitored server
 * @property {string} targetName    - Display name for the monitored server
 */

/**
 * @typedef {Object} AppState
 * @property {Array}       alerts         - Snort IDS alert objects from OpenSearch
 * @property {Array}       winAlerts      - Windows event alert objects from OpenSearch
 * @property {string}      filter         - Active category filter ('all' | 'recon' | 'web_attack' | 'dos' | 'malware')
 * @property {string}      search         - Full-text search query applied to the alert table
 * @property {string}      sortDir        - Table sort direction ('asc' | 'desc')
 * @property {string|null} mitreFilter    - Active MITRE ATT&CK technique filter (e.g. 'T1046') or null
 * @property {boolean}     connected      - Whether the last OpenSearch fetch succeeded
 * @property {string}      error          - Last error message (empty string when no error)
 * @property {boolean}     showConfig     - Whether the configuration modal is visible
 * @property {string}      tab            - Active tab ('snort' | 'windows' | 'map')
 * @property {number|null} detailAlert    - Index (in filterA()) of the alert shown in the detail panel, or null
 * @property {AppConfig}   config         - OpenSearch connection configuration
 * @property {number|null} refreshInterval - setInterval ID for auto-refresh, or null
 * @property {Object}      geoData        - Map of IP address → geo object {lat,lng,country,code,org}
 * @property {boolean}     mapReady       - Whether geo data is ready for the Leaflet map
 * @property {number}      lastUpdate     - Unix timestamp (ms) of the last successful data fetch
 * @property {boolean}     soundEnabled   - Whether audio alerts are enabled
 * @property {number}      lastAlertCount - Previous alert count (used to detect new alerts for sound)
 * @property {boolean}     loading        - Whether a data fetch is currently in progress
 * @property {Array}       blockedIPs     - Currently blocked IP entries from the block API
 */

/** @type {AppState} */
export const S = {
  alerts: [], winAlerts: [], filter: "all", search: "", sortDir: "desc", mitreFilter: null,
  connected: false, error: "", showConfig: false, tab: "snort", detailAlert: null,
  config: {
    url: "https://soc.your-domain.com/opensearch",
    username: "", password: "", serverCountry: "JP", targetName: "Serveur",
  },
  refreshInterval: null, geoData: {}, mapReady: false, lastUpdate: Date.now(),
  soundEnabled: false, lastAlertCount: 0, loading: false, blockedIPs: [],
};
