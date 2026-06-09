// Map a (source label, IOC value, IOC type) to the source's public web UI
// pre-filled with that indicator. Returning null means there's no useful
// pivot — the source label renders as plain text instead of a link.
//
// IOC types come straight from the backend pipeline: 'ip' | 'domain' |
// 'url' | 'hash' | 'email' | 'cve'. Anything unrecognised falls through
// to null.

const enc = encodeURIComponent;

// VirusTotal's URL pivot needs base64url(no padding) of the raw URL.
// Modern browsers ship btoa() which only handles latin-1; the call is
// wrapped in try/catch and falls back to a search query on failure.
function vtUrlId(u) {
  try {
    return btoa(u).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  } catch {
    return null;
  }
}

// One row per source label that the backend may surface. Each entry maps
// the type-tag to a builder. If the source has no public per-IOC page
// for a given type, omit it — the link won't render.
const BUILDERS = {
  'VirusTotal': {
    ip:     v => `https://www.virustotal.com/gui/ip-address/${enc(v)}`,
    domain: v => `https://www.virustotal.com/gui/domain/${enc(v)}`,
    hash:   v => `https://www.virustotal.com/gui/file/${enc(v)}`,
    url:    v => {
      const id = vtUrlId(v);
      return id
        ? `https://www.virustotal.com/gui/url/${id}`
        : `https://www.virustotal.com/gui/search/${enc(v)}`;
    },
  },
  'AbuseIPDB':       { ip: v => `https://www.abuseipdb.com/check/${enc(v)}` },
  'IPInfo':          { ip: v => `https://ipinfo.io/${enc(v)}` },
  'GreyNoise':       { ip: v => `https://viz.greynoise.io/ip/${enc(v)}` },
  'Censys': {
    ip:     v => `https://search.censys.io/hosts/${enc(v)}`,
    domain: v => `https://search.censys.io/domains/${enc(v)}`,
  },
  'CrowdSec':        { ip: v => `https://app.crowdsec.net/cti/${enc(v)}` },
  'Criminal IP':     { ip: v => `https://www.criminalip.io/asset/report/${enc(v)}` },
  'DShield · SANS ISC': { ip: v => `https://isc.sans.edu/ipinfo/${enc(v)}` },
  'Feodo Tracker':   { ip: v => `https://feodotracker.abuse.ch/browse/host/${enc(v)}/` },
  'OTX': {
    ip:     v => `https://otx.alienvault.com/indicator/ip/${enc(v)}`,
    domain: v => `https://otx.alienvault.com/indicator/domain/${enc(v)}`,
    hash:   v => `https://otx.alienvault.com/indicator/file/${enc(v)}`,
    url:    v => `https://otx.alienvault.com/indicator/url/${enc(v)}`,
  },
  'Maltiverse': {
    ip:     v => `https://maltiverse.com/ip/${enc(v)}`,
    domain: v => `https://maltiverse.com/hostname/${enc(v)}`,
    url:    v => `https://maltiverse.com/url/${enc(v)}`,
    hash:   v => `https://maltiverse.com/sample/${enc(v)}`,
  },
  'Pulsedive': {
    ip:     v => `https://pulsedive.com/indicator/?ioc=${enc(v)}`,
    domain: v => `https://pulsedive.com/indicator/?ioc=${enc(v)}`,
    url:    v => `https://pulsedive.com/indicator/?ioc=${enc(v)}`,
  },
  'ThreatFox': {
    ip:     v => `https://threatfox.abuse.ch/browse.php?search=ioc%3A${enc(v)}`,
    domain: v => `https://threatfox.abuse.ch/browse.php?search=ioc%3A${enc(v)}`,
    url:    v => `https://threatfox.abuse.ch/browse.php?search=ioc%3A${enc(v)}`,
    hash:   v => `https://threatfox.abuse.ch/browse.php?search=ioc%3A${enc(v)}`,
  },
  'MalwareBazaar':   { hash: v => `https://bazaar.abuse.ch/sample/${enc(v)}/` },
  'URLhaus':         {
    url:    v => `https://urlhaus.abuse.ch/browse.php?search=${enc(v)}`,
    domain: v => `https://urlhaus.abuse.ch/host/${enc(v)}/`,
  },
  'URLhaus payload': { hash: v => `https://bazaar.abuse.ch/sample/${enc(v)}/` },
  'URLScan.io':      { url: v => `https://urlscan.io/search/#${enc(v)}` },
  'Spamhaus DBL':    { domain: v => `https://check.spamhaus.org/results/?query=${enc(v)}` },
  'WHOIS':           {
    domain: v => `https://who.is/whois/${enc(v)}`,
    ip:     v => `https://who.is/whois-ip/ip-address/${enc(v)}`,
  },
  'Hybrid Analysis': { hash: v => `https://www.hybrid-analysis.com/sample/${enc(v)}` },
  'NVD':             { cve:  v => `https://nvd.nist.gov/vuln/detail/${enc(v)}` },
  // FIRST.org renders the user-facing EPSS page at /epss (no /data/queries
  // path — that 404s). The api.first.org JSON endpoint returns the score
  // and percentile for a specific CVE and renders inline in the browser,
  // which is the closest pivot to "show me EPSS for this CVE".
  'EPSS':            { cve:  v => `https://api.first.org/data/v1/epss?cve=${enc(v)}` },
  'CISA KEV':        { cve:  v => `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search=${enc(v)}` },
  'Cert Transparency': { domain: v => `https://crt.sh/?q=${enc(v)}` },
  'Wayback':         { domain: v => `https://web.archive.org/web/*/${enc(v)}` },
};


// Public — returns a URL or null. Source name is the human label the
// backend emits (matches BUILDERS keys verbatim).
export function sourceUrl(sourceName, ioc, iocType) {
  if (!sourceName || !ioc || !iocType) return null;
  const row = BUILDERS[sourceName];
  if (!row) return null;
  const fn = row[iocType];
  return fn ? fn(ioc) : null;
}
