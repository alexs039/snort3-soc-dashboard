/**
 * Event delegation for the SNORT3 SOC Dashboard.
 * Sets up a single click listener and a single input listener on #app.
 * All interactive elements express their intent via data-action (and optional
 * data-* payload attributes) instead of inline onclick handlers.
 */

import { S } from './state.js';
import { render } from './render.js';
import { connect, unblockIP, resolveGeo } from './api.js';
import { exportCSV, exportJSON, generateReport } from './export.js';
import { filterA } from './stats.js';
import { renderMap } from './render-map.js';

/**
 * Walks up the DOM from `startEl` to `root` (exclusive) and returns the first
 * element that has a non-empty dataset.action attribute, or null if none found.
 * @param {Element} startEl - Element to start the upward traversal from
 * @param {Element} root    - Ancestor element to stop at (not included)
 * @returns {Element|null} The first element with a data-action, or null
 */
function findActionTarget(startEl, root) {
  let el = startEl;
  while (el && el !== root) {
    if (el.dataset && el.dataset.action) return el;
    el = el.parentElement;
  }
  return null;
}

/**
 * Handles the resolved data-action dispatched from a click event.
 * @param {string}      action - Value of data-action on the matched element
 * @param {Element}     el     - The element that owns the data-action attribute
 * @param {MouseEvent}  e      - Original click event (used for target checks)
 * @returns {void}
 */
function handleClickAction(action, el, e) {
  switch (action) {

    case 'show-config':
      S.showConfig = true;
      render();
      break;

    case 'close-config':
      S.showConfig = false;
      render();
      break;

    // Close modal only when the bare overlay background is clicked (not its children)
    case 'modal-overlay':
      if (e.target === el) { S.showConfig = false; render(); }
      break;

    case 'tab': {
      const tab = el.dataset.tab;
      if (!tab) break;
      S.tab = tab;
      if (tab === 'map' && !S.mapReady) resolveGeo();
      render();
      if (tab === 'map') renderMap();
      break;
    }

    case 'filter': {
      const cat = el.dataset.category || 'all';
      S.filter = (cat !== 'all' && S.filter === cat) ? 'all' : cat;
      S.mitreFilter = null;
      render();
      break;
    }

    case 'mitre-filter': {
      const technique = el.dataset.technique;
      if (!technique) break;
      S.mitreFilter = S.mitreFilter === technique ? null : technique;
      render();
      break;
    }

    case 'mitre-clear':
      S.mitreFilter = null;
      render();
      break;

    case 'unblock': {
      const ip = el.dataset.ip;
      if (ip) unblockIP(ip);
      break;
    }

    case 'show-detail': {
      const idx = parseInt(el.dataset.index, 10);
      if (!isNaN(idx)) { S.detailAlert = idx; render(); }
      break;
    }

    case 'close-detail':
      S.detailAlert = null;
      render();
      break;

    case 'toggle-sort':
      S.sortDir = S.sortDir === 'desc' ? 'asc' : 'desc';
      render();
      break;

    case 'export-csv':
      exportCSV();
      break;

    case 'export-json':
      exportJSON();
      break;

    case 'export-report':
      generateReport();
      break;

    case 'toggle-sound':
      S.soundEnabled = !S.soundEnabled;
      render();
      break;

    case 'connect':
      connect();
      break;

    case 'copy-json': {
      const a = filterA()[S.detailAlert];
      if (a) {
        navigator.clipboard.writeText(JSON.stringify(a, null, 2))
          .then(() => alert('JSON copié dans le presse-papiers'))
          .catch(() => alert('Erreur lors de la copie'));
      }
      break;
    }

    default:
      break;
  }
}

/**
 * Handles input/change events on delegated form elements (search box, config modal).
 * Elements must carry data-action="search" or data-action="config-input".
 * Config inputs that require an immediate re-render carry data-rerender="true".
 * @param {InputEvent|Event} e - The input or change event
 * @returns {void}
 */
function handleInputAction(e) {
  const el = e.target;
  if (!el || !el.dataset) return;

  switch (el.dataset.action) {
    case 'search':
      S.search = el.value;
      render();
      break;

    case 'config-input': {
      const field = el.dataset.field;
      if (field && field in S.config) {
        S.config[field] = el.value;
        // Re-render immediately for fields that affect the UI (e.g. country dropdown updates the map legend)
        if (el.dataset.rerender === 'true') render();
      }
      break;
    }

    default:
      break;
  }
}

/**
 * Sets up the single delegated click and input event listeners on #app.
 * Must be called once after the DOM is ready (after the initial render).
 * @returns {void}
 */
export function setupEvents() {
  const appEl = document.getElementById('app');
  if (!appEl) return;

  // Click delegation — find the innermost element with a data-action
  appEl.addEventListener('click', (e) => {
    const el = findActionTarget(e.target, appEl);
    if (el) handleClickAction(el.dataset.action, el, e);
  });

  // Input/change delegation — handles search box and config modal fields
  appEl.addEventListener('input', handleInputAction);
  appEl.addEventListener('change', handleInputAction);
}
