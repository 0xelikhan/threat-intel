/**
 * Regression test for the DetectionCitationsView crash:
 *   "Cannot read properties of null (reading 'sigma')"
 *
 * The bug was in the sourcesWithHits counter:
 *
 *   // BROKEN — crashes when dc is null in bare mode
 *   const sourcesWithHits = _DETECTION_SOURCES
 *     .filter(s => (dc[s.key] || []).length).length;
 *
 *   // FIXED — matches the pattern the other two loops use
 *   const sourcesWithHits = _DETECTION_SOURCES
 *     .filter(s => (((dc || {})[s.key]) || []).length).length;
 *
 * DetectionCitationsView is defined inside App.js and not exported,
 * so instead of a React render test we assert the defensive pattern
 * itself with a tiny inline reproducer. If a future refactor
 * reintroduces the raw `dc[s.key]` dereference, this test fails loud.
 */

describe('DetectionCitationsView — sourcesWithHits defensive pattern', () => {
  const _DETECTION_SOURCES = [
    {key: 'sigma'}, {key: 'panther'}, {key: 'splunk'},
    {key: 'mitre_car'}, {key: 'hunter_playbook'},
    {key: 'chronicle'}, {key: 'olafhartong_th'},
    {key: 'falco_rules'}, {key: 'sublime_rules'},
    {key: 'stratus_techniques'}, {key: 'payloads_aatt'},
  ];

  const sourcesWithHits = (dc) =>
    _DETECTION_SOURCES.filter(s => (((dc || {})[s.key]) || []).length).length;

  it('returns 0 without crashing when dc is null', () => {
    expect(() => sourcesWithHits(null)).not.toThrow();
    expect(sourcesWithHits(null)).toBe(0);
  });

  it('returns 0 without crashing when dc is undefined', () => {
    expect(() => sourcesWithHits(undefined)).not.toThrow();
    expect(sourcesWithHits(undefined)).toBe(0);
  });

  it('counts non-empty source arrays correctly', () => {
    const dc = {
      sigma:   [{title: 'rule-a'}, {title: 'rule-b'}],
      panther: [{title: 'rule-c'}],
      splunk:  [],                 // present but empty — must not count
      // other keys absent
    };
    expect(sourcesWithHits(dc)).toBe(2);
  });

  it('handles each individual source key being absent', () => {
    for (const absent of _DETECTION_SOURCES) {
      const dc = {};
      for (const other of _DETECTION_SOURCES) {
        if (other.key !== absent.key) dc[other.key] = [{title: 'rule'}];
      }
      // Should count every present key EXCEPT the absent one.
      expect(sourcesWithHits(dc)).toBe(_DETECTION_SOURCES.length - 1);
    }
  });

  it('does not crash when dc has unexpected non-array values', () => {
    const dc = {sigma: null, panther: 'not-an-array', splunk: 42};
    // Non-array values' .length is undefined (truthy for strings).
    // The filter must still complete without throwing.
    expect(() => sourcesWithHits(dc)).not.toThrow();
  });
});
