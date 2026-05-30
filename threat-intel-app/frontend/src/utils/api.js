/**
 * Centralized API client — exponential-backoff retry, configurable
 * timeouts, structured error parsing, request-ID extraction, global
 * error event bus for toast subscribers.
 *
 * Usage:
 *   import { apiFetch, onApiError } from '../utils/api';
 *
 *   const data = await apiFetch('/api/analyze', {
 *     method: 'POST',
 *     body: JSON.stringify({...}),
 *     timeout: 300_000,   // 5min for long AI calls; defaults to 30s
 *   });
 *
 *   onApiError(err => showToast(err.message, err.requestId));
 *
 * Errors thrown by apiFetch carry:
 *   err.message      — human-readable, from backend `detail` / `error`
 *   err.error_code   — backend machine slug (Section 5 registry)
 *   err.requestId    — X-Request-ID header for log correlation
 *   err.status       — HTTP status
 *   err.fixHint      — when the backend included one in `fix_hint`
 *
 * Retry policy:
 *   * Network errors + 5xx → 3 attempts total, sleeping 1s, 2s, 4s
 *   * 4xx                  → no retry (deterministic — your fault)
 *   * Timeouts             → counted as a retry trigger
 */

// ─── error event bus ────────────────────────────────────────────────────────
const _listeners = new Set();

export function onApiError(fn) {
  _listeners.add(fn);
  return () => _listeners.delete(fn);
}

function _emit(err) {
  for (const l of _listeners) {
    try { l(err); } catch { /* listener fault is not the request's fault */ }
  }
}


// ─── helpers ─────────────────────────────────────────────────────────────────
function _sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

function _isRetryable(status) {
  // Network error (status 0 from fetch failure) OR 5xx server error.
  return status === 0 || (status >= 500 && status < 600);
}


/**
 * @param {string} url
 * @param {object} [options]
 * @param {string|object|FormData} [options.body]
 * @param {string} [options.method]               — defaults to GET
 * @param {object} [options.headers]
 * @param {number} [options.timeout]              — ms; default 30_000, use 300_000 for AI calls
 * @param {number} [options.maxAttempts]          — default 3
 * @param {boolean} [options.suppressToast]       — set true for fire-and-forget background polls
 */
export async function apiFetch(url, options = {}) {
  const {
    body, method = 'GET', headers = {},
    timeout = 30_000,
    maxAttempts = 3,
    suppressToast = false,
    ...rest
  } = options;

  const init = {
    method,
    headers: { ...(body && typeof body === 'string' ? { 'Content-Type': 'application/json' } : {}),
               ...headers },
    body,
    ...rest,
  };

  // 1s, 2s, 4s — exponential backoff per the spec.
  const backoffs = [1000, 2000, 4000];
  let lastError = null;

  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    const ctrl = new AbortController();
    const tid  = setTimeout(() => ctrl.abort(), timeout);
    try {
      const resp = await fetch(url, { ...init, signal: ctrl.signal });
      clearTimeout(tid);

      const requestId = resp.headers.get('X-Request-ID') || null;

      // Parse body — try JSON, fall back to text.
      let parsed = null;
      const ct = resp.headers.get('content-type') || '';
      if (ct.includes('json')) {
        parsed = await resp.json().catch(() => null);
      } else {
        parsed = await resp.text().catch(() => null);
      }

      if (resp.ok) {
        return parsed;
      }

      // Build a structured error from the response body.
      const detail = parsed && typeof parsed === 'object'
        ? (parsed.detail || parsed.error || parsed.message || `HTTP ${resp.status}`)
        : (parsed || `HTTP ${resp.status}`);
      const err = new Error(detail);
      err.name       = 'ApiError';
      err.status     = resp.status;
      err.error_code = parsed?.error_code || null;
      err.fixHint    = parsed?.fix_hint || parsed?.details?.fix_hint || null;
      err.requestId  = requestId;
      err.body       = parsed;
      err.url        = url;

      if (_isRetryable(resp.status) && attempt + 1 < maxAttempts) {
        await _sleep(backoffs[attempt]);
        lastError = err;
        continue;
      }
      if (!suppressToast) _emit(err);
      throw err;
    } catch (e) {
      clearTimeout(tid);
      // Network failure / abort — retry if attempts remain.
      if (e?.name === 'ApiError') throw e;
      const isAbort = e?.name === 'AbortError';
      const err = new Error(isAbort
        ? `Request timed out after ${Math.round(timeout / 1000)}s`
        : (e?.message || String(e)));
      err.name = 'ApiError';
      err.status = 0;
      err.error_code = isAbort ? 'client_timeout' : 'network_error';
      err.fixHint = isAbort
        ? 'The request took too long. Check your connection or backend availability.'
        : 'Network request failed. Check your connection.';
      err.url = url;
      if (attempt + 1 < maxAttempts) {
        await _sleep(backoffs[attempt]);
        lastError = err;
        continue;
      }
      if (!suppressToast) _emit(err);
      throw err;
    }
  }

  // Defensive — shouldn't reach here, the loop always returns or throws.
  const err = lastError || new Error('Unknown API error');
  if (!suppressToast) _emit(err);
  throw err;
}


// Convenience wrappers — match the most common patterns in App.js so call
// sites can migrate one line at a time without changing call shape.
export const apiGet  = (url, opts = {}) => apiFetch(url, { method: 'GET',  ...opts });
export const apiPost = (url, data, opts = {}) => apiFetch(url, {
  method: 'POST',
  body: typeof data === 'string' || data instanceof FormData ? data : JSON.stringify(data || {}),
  ...opts,
});
