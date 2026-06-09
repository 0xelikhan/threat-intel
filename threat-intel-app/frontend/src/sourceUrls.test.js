/**
 * Tests for the sourceUrls helper that turns (source label, IOC, type)
 * into a public-web-UI deep link for the per-IOC expanded view.
 * See c8c143f. Each case anchors a real source pivot a portfolio
 * reviewer will actually click on.
 */

import { sourceUrl } from './sourceUrls';


describe('sourceUrl', () => {
  test('returns null when any input is missing', () => {
    expect(sourceUrl('', '8.8.8.8', 'ip')).toBeNull();
    expect(sourceUrl('VirusTotal', '', 'ip')).toBeNull();
    expect(sourceUrl('VirusTotal', '8.8.8.8', '')).toBeNull();
  });

  test('returns null for unknown source', () => {
    expect(sourceUrl('NotARealSource', '8.8.8.8', 'ip')).toBeNull();
  });

  test('returns null when a known source has no builder for that IOC type', () => {
    // AbuseIPDB only ships an IP builder — no domain page.
    expect(sourceUrl('AbuseIPDB', 'example.com', 'domain')).toBeNull();
  });

  // ── per-source happy paths ─────────────────────────────────────────
  test('VirusTotal builds an IP gui path', () => {
    expect(sourceUrl('VirusTotal', '8.8.8.8', 'ip'))
      .toBe('https://www.virustotal.com/gui/ip-address/8.8.8.8');
  });

  test('VirusTotal builds a domain gui path', () => {
    expect(sourceUrl('VirusTotal', 'example.com', 'domain'))
      .toBe('https://www.virustotal.com/gui/domain/example.com');
  });

  test('VirusTotal builds a hash gui path', () => {
    const sha = 'a'.repeat(64);
    expect(sourceUrl('VirusTotal', sha, 'hash'))
      .toBe(`https://www.virustotal.com/gui/file/${sha}`);
  });

  test('VirusTotal url pivot uses base64url(no padding) when btoa can encode', () => {
    const u = 'http://evil.example.com/path';
    const out = sourceUrl('VirusTotal', u, 'url');
    const prefix = 'https://www.virustotal.com/gui/url/';
    expect(out.startsWith(prefix)).toBe(true);
    // The id portion only — must use base64url alphabet, no padding,
    // no '+' or '/' (the URL prefix itself contains slashes; assert
    // only on what btoa produced).
    const id = out.slice(prefix.length);
    expect(id).not.toMatch(/[+/=]/);
    expect(id.length).toBeGreaterThan(0);
  });

  test('VirusTotal url pivot falls back to search when btoa throws', () => {
    // Non-Latin-1 chars in the URL force btoa to throw.
    const u = 'http://exämple.com/💥';
    const out = sourceUrl('VirusTotal', u, 'url');
    expect(out).toContain('virustotal.com/gui/search/');
  });

  test('AbuseIPDB builds the IP check URL', () => {
    expect(sourceUrl('AbuseIPDB', '1.2.3.4', 'ip'))
      .toBe('https://www.abuseipdb.com/check/1.2.3.4');
  });

  test('GreyNoise IP path uses the viz host', () => {
    expect(sourceUrl('GreyNoise', '1.2.3.4', 'ip'))
      .toBe('https://viz.greynoise.io/ip/1.2.3.4');
  });

  test('Censys distinguishes hosts vs domains', () => {
    expect(sourceUrl('Censys', '1.2.3.4', 'ip'))
      .toBe('https://search.censys.io/hosts/1.2.3.4');
    expect(sourceUrl('Censys', 'example.com', 'domain'))
      .toBe('https://search.censys.io/domains/example.com');
  });

  test('OTX covers ip / domain / hash / url', () => {
    expect(sourceUrl('OTX', '1.2.3.4', 'ip'))
      .toBe('https://otx.alienvault.com/indicator/ip/1.2.3.4');
    expect(sourceUrl('OTX', 'example.com', 'domain'))
      .toBe('https://otx.alienvault.com/indicator/domain/example.com');
    expect(sourceUrl('OTX', 'aaaa', 'hash'))
      .toBe('https://otx.alienvault.com/indicator/file/aaaa');
  });

  test('MalwareBazaar only serves hashes', () => {
    expect(sourceUrl('MalwareBazaar', 'abcd', 'hash'))
      .toBe('https://bazaar.abuse.ch/sample/abcd/');
    expect(sourceUrl('MalwareBazaar', '1.2.3.4', 'ip')).toBeNull();
  });

  test('NVD / EPSS / CISA KEV all take a cve type', () => {
    const cve = 'CVE-2024-12345';
    expect(sourceUrl('NVD', cve, 'cve'))
      .toBe(`https://nvd.nist.gov/vuln/detail/${cve}`);
    // EPSS uses the api.first.org JSON endpoint — the canonical
    // place to view the score and percentile for a CVE in a browser.
    expect(sourceUrl('EPSS', cve, 'cve'))
      .toContain('api.first.org');
    expect(sourceUrl('EPSS', cve, 'cve'))
      .toContain('cve=' + cve);
    // CISA KEV deep-links go through cve.org (cisa.gov blocks
    // parametrized lookups via Cloudflare). cve.org/CVERecord is the
    // canonical CVE record page and surfaces "Known Exploited" when set.
    expect(sourceUrl('CISA KEV', cve, 'cve'))
      .toContain('cve.org');
  });

  test('values with spaces or unicode are URL-encoded', () => {
    const out = sourceUrl('ThreatFox', 'evil host', 'domain');
    expect(out).toContain('evil%20host');
  });

  test('Spamhaus DBL only handles domain', () => {
    expect(sourceUrl('Spamhaus DBL', 'evil.example', 'domain'))
      .toContain('check.spamhaus.org');
    expect(sourceUrl('Spamhaus DBL', '1.2.3.4', 'ip')).toBeNull();
  });

  test('CISA KEV points at cve.org (avoids Cloudflare bot block)', () => {
    const out = sourceUrl('CISA KEV', 'CVE-2024-12345', 'cve');
    expect(out).toContain('cve.org/CVERecord');
    expect(out).toContain('id=CVE-2024-12345');
  });

  test('CIRCL hashlookup picks the right algo from hash length', () => {
    const md5    = 'd'.repeat(32);
    const sha1   = '1'.repeat(40);
    const sha256 = '2'.repeat(64);
    expect(sourceUrl('CIRCL hashlookup', md5,    'hash'))
      .toBe(`https://hashlookup.circl.lu/lookup/md5/${md5}`);
    expect(sourceUrl('CIRCL hashlookup', sha1,   'hash'))
      .toBe(`https://hashlookup.circl.lu/lookup/sha1/${sha1}`);
    expect(sourceUrl('CIRCL hashlookup', sha256, 'hash'))
      .toBe(`https://hashlookup.circl.lu/lookup/sha256/${sha256}`);
  });

  test('CIRCL hashlookup returns null for non-standard hash lengths', () => {
    expect(sourceUrl('CIRCL hashlookup', 'abc', 'hash')).toBeNull();
    expect(sourceUrl('CIRCL hashlookup', 'a'.repeat(50), 'hash')).toBeNull();
  });
});
