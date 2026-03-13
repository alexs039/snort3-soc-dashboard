/**
 * Application entry point for the SNORT3 SOC Dashboard.
 * Imports all modules, performs initial render, sets up event delegation,
 * and starts the clock ticker.
 */

import { S } from './state.js';
import { render } from './render.js';
import { setupEvents } from './events.js';

/**
 * Starts the live clock that updates the date/time display every second
 * without triggering a full re-render.
 * @returns {void}
 */
function startClock() {
  setInterval(() => {
    const cd = document.querySelector(".clock-date");
    const ct = document.querySelector(".clock-time");
    if (cd && ct) {
      const n = new Date();
      cd.textContent = n.toLocaleDateString("fr-FR", {
        weekday: "short", day: "numeric", month: "short", year: "numeric",
      });
      ct.textContent = n.toLocaleTimeString("fr-FR");
    }
  }, 1000);
}

// Show config modal on first load (no credentials saved)
S.showConfig = true;

// Initial render — populates #app so setupEvents can attach to it
render();

// Attach delegated event listeners now that #app has content
setupEvents();

// Start the clock ticker
startClock();
