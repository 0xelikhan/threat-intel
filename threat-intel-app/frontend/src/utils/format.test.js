/**
 * Tests for the format utility helpers. Each test corresponds to a
 * past regression so future changes to these helpers can't silently
 * reintroduce the same UX bug.
 */

import {
  smartTruncate, sourceErrorMessage, thresholdBucket,
} from './format';


// ─── smartTruncate ────────────────────────────────────────────────────
describe('smartTruncate', () => {
  test('returns input unchanged when under the cap', () => {
    expect(smartTruncate('short string', 100)).toBe('short string');
  });

  test('breaks at word boundary, never mid-word', () => {
    const long = 'Enemy of the State Order in the Court of King Henry';
    const out  = smartTruncate(long, 30);
    expect(out.endsWith('…')).toBe(true);
    // The cut must land on a whitespace boundary in the source — so
    // the char immediately before the ellipsis should be the last
    // letter of a complete word, not a mid-word slice.
    expect(out).toBe('Enemy of the State Order in…');
    // Reverse-check: every char before the ellipsis must appear
    // contiguously at the start of the original input.
    const trimmed = out.slice(0, -1);
    expect(long.startsWith(trimmed)).toBe(true);
  });

  test('falls back to hard slice when no space is reachably close', () => {
    // First word eats the whole budget — hard-slice with ellipsis.
    const out = smartTruncate('Supercalifragilisticexpialidocious', 10);
    expect(out).toBe('Supercalif…');
  });

  test('handles empty / null without throwing', () => {
    expect(smartTruncate('', 10)).toBe('');
    expect(smartTruncate(null, 10)).toBe('');
    expect(smartTruncate(undefined, 10)).toBe('');
  });
});


// ─── sourceErrorMessage ───────────────────────────────────────────────
describe('sourceErrorMessage', () => {
  test('translates circuit_open to readable phrasing (was the dict-repr leak bug)', () => {
    const blob = {
      error:      'circuit open for mb-api.abuse.ch',
      error_type: 'circuit_open',
      skipped:    true,
    };
    const out = sourceErrorMessage(blob, 'MalwareBazaar');
    // Must NOT include the raw dict braces / quotes
    expect(out).not.toMatch(/[{}]/);
    expect(out).not.toMatch(/'error'/);
    expect(out).toContain('temporarily skipped');
    expect(out).toContain('breaker');
  });

  test('translates auth_failed and includes the source name in the suggestion', () => {
    const blob = { error: 'auth failed (HTTP 401)', error_type: 'auth_failed' };
    const out  = sourceErrorMessage(blob, 'AbuseIPDB');
    expect(out).toContain("couldn't authenticate");
    expect(out).toContain('AbuseIPDB');
    expect(out).toContain('data/config.json');
  });

  test('translates rate_limited / timed_out / http_error', () => {
    expect(sourceErrorMessage({ error_type: 'rate_limited' })).toContain('rate-limited');
    expect(sourceErrorMessage({ error_type: 'timed_out' })).toContain('timed out');
    expect(sourceErrorMessage({ error_type: 'http_error', error: '500 Server Error' }))
      .toContain('HTTP error');
  });

  test('hides not_configured sources entirely (returns null)', () => {
    expect(sourceErrorMessage({ error: 'no key', error_type: 'not_configured' })).toBeNull();
  });

  test('treats "no data" string as a clean miss', () => {
    expect(sourceErrorMessage({ error: 'no data' })).toContain('no data returned');
  });

  test('falls back to a safe unavailable message for unknown error types', () => {
    const out = sourceErrorMessage({ error: 'something weird happened' });
    expect(out).toContain('unavailable');
    expect(out).toContain('something weird happened');
  });

  test('returns null for null / non-object input', () => {
    expect(sourceErrorMessage(null)).toBeNull();
    expect(sourceErrorMessage('string')).toBeNull();
    expect(sourceErrorMessage(undefined)).toBeNull();
  });
});


// ─── thresholdBucket ──────────────────────────────────────────────────
describe('thresholdBucket', () => {
  test.each([
    [0,   'green'],
    [1,   'yellow'],
    [2,   'yellow'],
    [3,   'orange'],
    [9,   'orange'],
    [10,  'red'],
    [100, 'red'],
  ])('count %d -> %s bucket', (n, expected) => {
    expect(thresholdBucket(n)).toBe(expected);
  });

  test('respects custom thresholds', () => {
    expect(thresholdBucket(5,  20, 10)).toBe('yellow');
    expect(thresholdBucket(15, 20, 10)).toBe('orange');
    expect(thresholdBucket(25, 20, 10)).toBe('red');
  });

  test('returns green for negative / non-number input', () => {
    expect(thresholdBucket(-1)).toBe('green');
    expect(thresholdBucket('not a number')).toBe('green');
    expect(thresholdBucket(null)).toBe('green');
  });
});
