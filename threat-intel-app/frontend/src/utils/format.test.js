/**
 * Tests for the format utility helpers. Each test corresponds to a
 * past regression so future changes to these helpers can't silently
 * reintroduce the same UX bug.
 */

import {
  smartTruncate, sourceErrorMessage, thresholdBucket,
  levelBucket, verdictBucket, tokenOverlap, dropOverlapping,
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


// ─── levelBucket ──────────────────────────────────────────────────────
describe('levelBucket', () => {
  test.each([
    ['CRITICAL',      'red'],
    ['HIGH',          'orange'],
    ['MEDIUM',        'yellow'],
    ['LOW',           'blue'],
    ['INFORMATIONAL', 'grey'],
  ])('level %s -> %s', (level, expected) => {
    expect(levelBucket(level)).toBe(expected);
  });

  test('is case-insensitive', () => {
    expect(levelBucket('critical')).toBe('red');
    expect(levelBucket('Medium')).toBe('yellow');
  });

  test('unknown / falsy input falls back to grey', () => {
    expect(levelBucket('NOPE')).toBe('grey');
    expect(levelBucket('')).toBe('grey');
    expect(levelBucket(null)).toBe('grey');
    expect(levelBucket(undefined)).toBe('grey');
  });
});


// ─── verdictBucket ────────────────────────────────────────────────────
describe('verdictBucket', () => {
  test.each([
    ['MALICIOUS',   'red'],
    ['SUSPICIOUS',  'orange'],
    ['CLEAN',       'green'],
    ['BENIGN',      'green'],
    ['UNKNOWN',     'grey'],
    ['UNDETECTED',  'grey'],
  ])('verdict %s -> %s', (v, expected) => {
    expect(verdictBucket(v)).toBe(expected);
  });

  test('CLEAN_INFRA is BLUE not GREEN', () => {
    // Known-good hosting infra (Cloudflare / cloud CDN / etc.) gets its
    // own blue bucket so the analyst can see "known infra, NOT safe
    // traffic" — attackers spin up VMs in these clouds routinely.
    expect(verdictBucket('CLEAN_INFRA')).toBe('blue');
    expect(verdictBucket('CLEAN_INFRA')).not.toBe('green');
  });

  test('case-insensitive', () => {
    expect(verdictBucket('malicious')).toBe('red');
    expect(verdictBucket('Clean_Infra')).toBe('blue');
  });

  test('falsy / unknown input falls back to grey', () => {
    expect(verdictBucket('')).toBe('grey');
    expect(verdictBucket(null)).toBe('grey');
    expect(verdictBucket('NOT_A_VERDICT')).toBe('grey');
  });
});


// ─── tokenOverlap ─────────────────────────────────────────────────────
describe('tokenOverlap', () => {
  test('identical strings overlap 1.0', () => {
    const s = 'user x deleted file y';
    expect(tokenOverlap(s, s)).toBeCloseTo(1.0);
  });

  test('completely disjoint strings overlap 0', () => {
    expect(tokenOverlap('apple banana cherry', 'truck mountain river'))
      .toBe(0);
  });

  test('paraphrased duplicates score > 0.5 (the prose-dup bug case)', () => {
    // The exact wording-shift duplicate the user reported earlier:
    const summary = 'User AGDRYER\\PTADMIN deleted consolehost_history.txt';
    const analysis = 'The deletion of consolehost_history.txt by user AGDRYER\\PTADMIN is not suspicious';
    expect(tokenOverlap(summary, analysis)).toBeGreaterThan(0.5);
  });

  test('partial overlap returns intermediate ratio', () => {
    // ~3 of 5 tokens shared between the two sets
    const r = tokenOverlap('alpha beta gamma delta epsilon',
                            'alpha beta gamma omega lambda');
    expect(r).toBeGreaterThan(0.4);
    expect(r).toBeLessThan(0.8);
  });

  test('returns 0 for null / empty', () => {
    expect(tokenOverlap('', 'anything')).toBe(0);
    expect(tokenOverlap('anything', null)).toBe(0);
    expect(tokenOverlap(null, null)).toBe(0);
  });

  test('ignores tokens shorter than 4 chars', () => {
    // 'a' and 'is' are too short to count; rest are unique tokens
    expect(tokenOverlap('a is foo', 'a is bar')).toBe(0);
  });
});


// ─── dropOverlapping ──────────────────────────────────────────────────
describe('dropOverlapping', () => {
  test('drops candidates whose tokens overlap the corpus by >= threshold', () => {
    const candidates = [
      'The deletion of file Y by user X is not suspicious',  // dup
      'AbuseIPDB reports 0 abuse history for the source IP',  // distinct
    ];
    const corpus = 'User X deleted file Y. Not malicious.';
    const kept = dropOverlapping(candidates, corpus, 0.4);
    expect(kept).toHaveLength(1);
    expect(kept[0]).toContain('AbuseIPDB');
  });

  test('keeps everything when corpus is empty', () => {
    const r = dropOverlapping(['a', 'b'], '', 0.5);
    expect(r).toEqual(['a', 'b']);
  });

  test('accepts an array corpus and joins it', () => {
    const candidates = ['the deletion of file consolehost was performed'];
    const corpus = ['user deleted file consolehost from history'];
    // 'deletion' / 'file' / 'consolehost' tokens overlap; threshold 0.4
    // catches the dup.
    expect(dropOverlapping(candidates, corpus, 0.4)).toEqual([]);
  });

  test('returns [] for empty / non-array candidate input', () => {
    expect(dropOverlapping([], 'corpus')).toEqual([]);
    expect(dropOverlapping(null, 'corpus')).toEqual([]);
  });

  test('drops falsy entries from candidates', () => {
    const r = dropOverlapping(['', null, 'real text'], 'nothing', 0.5);
    expect(r).toEqual(['real text']);
  });
});
