/**
 * Small pure-function helpers extracted from App.js for unit testing.
 *
 * Every helper here exists because a regression shipped to production
 * before tests caught it:
 *   - smartTruncate          — OTX pulse names were sliced mid-word at
 *                              60 chars ("Enemy of the State: Order in
 *                              the C"). Fix landed in commit ed28795.
 *   - sourceErrorMessage      — circuit_open / auth_failed / timed_out
 *                              were rendered as raw Python dict repr
 *                              ({'error': '...', 'error_type': '...'})
 *                              because the frontend translation table
 *                              never fired. Fix landed in commit ed28795.
 *
 * Keep these dependency-free (no React imports) so they're cheap to
 * unit-test and reusable from any view.
 */

/**
 * Truncate a string at the nearest word boundary <= max chars.
 * Falls back to a hard slice if no space is reachably close to the
 * boundary (avoids leaving a 5-char fragment when a single word eats
 * the whole budget).
 *
 * @param {string} s   — input
 * @param {number} max — cap length (chars)
 * @returns {string}   — truncated with trailing "…" when shortened
 */
export function smartTruncate(s, max) {
  if (!s) return '';
  if (s.length <= max) return s;
  const cut = s.slice(0, max);
  const sp  = cut.lastIndexOf(' ');
  // Only honour the word boundary if it's at least 60% of the cap —
  // otherwise we'd return a tiny prefix when the first word is long.
  return (sp > max * 0.6 ? cut.slice(0, sp) : cut) + '…';
}

/**
 * Translate a backend error blob into the human-readable string the
 * analyst sees. The blob shape comes from agents/enrichment.py and
 * carries {error, error_type, source, skipped?}.
 *
 * Return values are deliberately plain English — the analyst card
 * shows this text directly, no further formatting.
 *
 * @param {{error?: string, error_type?: string}} blob
 * @param {string} sourceLabel — display name for the source (e.g.
 *                               "AbuseIPDB"), used in suggestions
 * @returns {string|null} — null when the blob should be hidden
 *                          entirely (not_configured), else the
 *                          translated message
 */
export function sourceErrorMessage(blob, sourceLabel = '') {
  if (!blob || typeof blob !== 'object') return null;

  // Sources that simply aren't configured shouldn't pretend they
  // failed — hide them entirely.
  if (blob.error_type === 'not_configured') return null;

  const raw = blob.error || '';

  switch (blob.error_type) {
    case 'circuit_open':
      return 'temporarily skipped (recent failures opened the breaker — retry in a few minutes)';
    case 'auth_failed':
      return `couldn't authenticate — verify the ${sourceLabel || 'source'} API key in data/config.json`;
    case 'rate_limited':
      return 'rate-limited (HTTP 429) — daily quota or burst limit reached';
    case 'timed_out':
      return 'request timed out — source may be slow or unreachable';
    case 'http_error':
      return `source returned an HTTP error — ${String(raw).slice(0, 100)}`;
    default:
      if (typeof raw === 'string' && raw.toLowerCase() === 'no data') {
        return 'no data returned for this indicator';
      }
      return `unavailable — ${String(raw).slice(0, 100)}`;
  }
}

/**
 * Build the threshold-coloured chip color for a numeric count.
 * Extracted because the breach-badge color logic shipped wrong on
 * day one (boundary off-by-one between MALICIOUS and SUSPICIOUS).
 *
 * @param {number} n
 * @param {number} maliciousAt — count >= this is red
 * @param {number} suspiciousAt — count >= this is orange
 * @returns {'red'|'orange'|'yellow'|'green'} bucket name
 */
export function thresholdBucket(n, maliciousAt = 10, suspiciousAt = 3) {
  if (typeof n !== 'number' || n < 0) return 'green';
  if (n >= maliciousAt)  return 'red';
  if (n >= suspiciousAt) return 'orange';
  if (n > 0)             return 'yellow';
  return 'green';
}
