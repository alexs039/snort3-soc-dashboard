/**
 * XSS sanitization utilities for safe DOM injection.
 * All data received from external sources (OpenSearch, API responses) MUST be
 * sanitized with these functions before being inserted into the DOM.
 */

/**
 * Escapes a value for safe HTML injection by converting special characters to
 * their HTML entity equivalents using a transient text node.
 * @param {*} s - Value to escape
 * @returns {string} HTML-safe escaped string
 * @example esc('<script>alert(1)</script>') // '&lt;script&gt;alert(1)&lt;/script&gt;'
 * @example esc(null) // ''
 */
export function esc(s) {
  if (!s) return '';
  const d = document.createElement('div');
  d.appendChild(document.createTextNode(String(s)));
  return d.innerHTML;
}

/**
 * Sanitizes an IP address for safe HTML display.
 * Strips any character that is not valid in an IPv4 or IPv6 address.
 * @param {*} ip - IP address value to sanitize
 * @returns {string} Sanitized, HTML-escaped IP string (falls back to '?')
 * @example safeIP('192.168.1.1')   // '192.168.1.1'
 * @example safeIP('<script>xss</script>') // ''
 */
export function safeIP(ip) {
  return esc(String(ip || '?').replace(/[^0-9a-fA-F.:\/]/g, ''));
}

/**
 * Sanitizes an alert message for safe HTML display.
 * Truncates to 200 characters and HTML-escapes the result.
 * @param {*} m - Message string to sanitize
 * @returns {string} Sanitized, HTML-escaped message (max 200 chars)
 * @example safeMsg('Hello <world>') // 'Hello &lt;world&gt;'
 */
export function safeMsg(m) {
  return esc(String(m || '').substring(0, 200));
}

/**
 * Sanitizes a Snort SID for safe HTML display.
 * Allows only digits and colons.
 * @param {*} s - SID value to sanitize
 * @returns {string} Sanitized, HTML-escaped SID string (falls back to '?')
 * @example safeSid('9001001') // '9001001'
 * @example safeSid('../../etc') // ''
 */
export function safeSid(s) {
  return esc(String(s || '?').replace(/[^0-9:]/g, ''));
}

/**
 * Sanitizes a network port number for safe HTML display.
 * Allows only digits.
 * @param {*} p - Port value to sanitize
 * @returns {string} Sanitized, HTML-escaped port string (falls back to '?')
 * @example safePort(443)   // '443'
 * @example safePort(';rm') // ''
 */
export function safePort(p) {
  return esc(String(p || '?').replace(/[^0-9]/g, ''));
}

/**
 * Sanitizes a network protocol string for safe HTML display.
 * Allows only alphanumeric characters.
 * @param {*} p - Protocol string to sanitize
 * @returns {string} Sanitized, HTML-escaped protocol string (falls back to '?')
 * @example safeProto('TCP')    // 'TCP'
 * @example safeProto('<evil>') // ''
 */
export function safeProto(p) {
  return esc(String(p || '?').replace(/[^A-Za-z0-9]/g, ''));
}
