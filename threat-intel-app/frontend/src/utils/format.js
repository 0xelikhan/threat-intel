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


// ─── verdict + threat-level color mapping ────────────────────────────────
// Extracted from App.js levelStyle + verdictStyle so the color->verdict
// contract can be tested in isolation. The actual hex values still
// live in App.js (they're tied to theme tokens); here we expose the
// CATEGORICAL bucket name (red / orange / yellow / blue / grey) since
// tests shouldn't care about exact hex.

const _LEVEL_TO_BUCKET = {
  CRITICAL:      'red',
  HIGH:          'orange',
  MEDIUM:        'yellow',
  LOW:           'blue',
  INFORMATIONAL: 'grey',
};
const _VERDICT_TO_BUCKET = {
  MALICIOUS:   'red',
  SUSPICIOUS:  'orange',
  CLEAN:       'green',
  CLEAN_INFRA: 'blue',   // known-good hosting infra (Cloudflare / cloud CDN / etc.)
  BENIGN:      'green',
  UNKNOWN:     'grey',
  UNDETECTED:  'grey',
};


/**
 * Map a threat_level value to its color bucket. Case-insensitive.
 * Unknown levels fall back to 'grey' (INFORMATIONAL).
 *
 * @param {string} level — CRITICAL / HIGH / MEDIUM / LOW / INFORMATIONAL
 * @returns {'red'|'orange'|'yellow'|'blue'|'grey'}
 */
export function levelBucket(level) {
  if (!level || typeof level !== 'string') return 'grey';
  return _LEVEL_TO_BUCKET[level.toUpperCase()] || 'grey';
}


/**
 * Map a verdict value to its color bucket. Case-insensitive.
 * Unknown verdicts fall back to 'grey'. CLEAN_INFRA is intentionally
 * blue (distinct from CLEAN's green) — surfaces the "this is known
 * infrastructure but the SPECIFIC TRAFFIC may not be safe" nuance.
 *
 * @param {string} verdict
 * @returns {'red'|'orange'|'green'|'blue'|'grey'}
 */
export function verdictBucket(verdict) {
  if (!verdict || typeof verdict !== 'string') return 'grey';
  return _VERDICT_TO_BUCKET[verdict.toUpperCase()] || 'grey';
}


// ─── Token-Jaccard overlap (de-dup helper for prose fields) ──────────────
// The AnalystSummary card uses this to drop paraphrased duplicates
// between summary / analysis_assessment / disposition_reason. Extracted
// here so the de-dup behaviour can be unit-tested without rendering a
// React tree.

const _TOKEN_RE = /[a-z0-9@.-]{4,}/g;

function _tokens(s) {
  if (!s || typeof s !== 'string') return new Set();
  return new Set(s.toLowerCase().match(_TOKEN_RE) || []);
}


/**
 * Token-set overlap ratio between two strings — used by the
 * AnalystSummary de-dup to detect paraphrased duplicates that a
 * strict string-equal check misses.
 *
 *   overlap("user X deleted file Y", "the deletion of Y by user X")
 *   ≈ 0.66 (overlap on user/x/deleted/file/y vs the/deletion/y/user/x)
 *
 * Returns intersection size / min(set_a.size, set_b.size). Range 0..1.
 *
 * @param {string} a
 * @param {string} b
 * @returns {number}
 */
export function tokenOverlap(a, b) {
  if (!a || !b) return 0;
  const setA = _tokens(a);
  const setB = _tokens(b);
  if (!setA.size || !setB.size) return 0;
  let inter = 0;
  for (const t of setA) if (setB.has(t)) inter++;
  return inter / Math.max(1, Math.min(setA.size, setB.size));
}


/**
 * Drop entries from `candidates` whose overlap with `against` exceeds
 * the threshold. Used to de-dup analysis_assessment sentences against
 * the already-rendered summary paragraph.
 *
 * @param {string[]} candidates
 * @param {string|string[]} against — corpus to compare against
 * @param {number} threshold — 0..1, drop when overlap >= this
 * @returns {string[]} filtered list
 */
export function dropOverlapping(candidates, against, threshold = 0.5) {
  if (!Array.isArray(candidates) || !candidates.length) return [];
  const corpus = Array.isArray(against) ? against.filter(Boolean).join(' ')
                                        : (against || '');
  if (!corpus) return candidates.filter(Boolean);
  return candidates.filter(s => s && tokenOverlap(s, corpus) < threshold);
}
