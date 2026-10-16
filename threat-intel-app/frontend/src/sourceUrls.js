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
  'Censys': {
    ip:     v => `https://search.censys.io/hosts/${enc(v)}`,
    domain: v => `https://search.censys.io/domains/${enc(v)}`,
  },
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
  // Spamhaus's check.spamhaus.org/results/?query=... isn't actually a
  // public URL pattern — it 404s/403s consistently. The reliable
  // entry-point is the IP-and-domain reputation centre where the
  // domain goes into a form. Less direct but at least the page loads.
  'Spamhaus DBL':    { domain: v => `https://check.spamhaus.org/results?domain=${enc(v)}` },
  'WHOIS':           {
    domain: v => `https://who.is/whois/${enc(v)}`,
    ip:     v => `https://who.is/whois-ip/ip-address/${enc(v)}`,
  },
  // CIRCL hashlookup serves per-hash JSON at /lookup/{algo}/{hash}. The
  // algorithm is inferred from the hash length (md5=32, sha1=40,
  // sha256=64); other lengths fall through to null so the label stays
  // plain text instead of producing a broken link.
  'CIRCL hashlookup': {
    hash: v => {
      const algo = v.length === 64 ? 'sha256'
                 : v.length === 40 ? 'sha1'
                 : v.length === 32 ? 'md5'
                 : null;
      return algo ? `https://hashlookup.circl.lu/lookup/${algo}/${enc(v)}` : null;
    },
  },
  'NVD':             { cve:  v => `https://nvd.nist.gov/vuln/detail/${enc(v)}` },
  // FIRST.org renders the user-facing EPSS page at /epss (no /data/queries
  // path — that 404s). The api.first.org JSON endpoint returns the score
  // and percentile for a specific CVE and renders inline in the browser,
  // which is the closest pivot to "show me EPSS for this CVE".
  'EPSS':            { cve:  v => `https://api.first.org/data/v1/epss?cve=${enc(v)}` },
  // cisa.gov's KEV catalog page (?search=CVE-...) doesn't accept a query
  // parameter - the search runs client-side after the JSON loads, and
  // a deep-link with ?search=X 403s through Cloudflare anyway. cve.org
  // is the canonical CVE record (always 200, no bot block) and the
  // record page surfaces "Known Exploited" status directly when it
  // applies.
  'CISA KEV':        { cve:  v => `https://www.cve.org/CVERecord?id=${enc(v)}` },
  'Wayback':         { domain: v => `https://web.archive.org/web/*/${enc(v)}` },

  // ─── Phase 1 additions — 28 new TI sources ────────────────────────────
  'YARAify': { hash: v => `https://yaraify.abuse.ch/sample/${enc(v)}/` },
  'Robtex': {
    ip:     v => `https://www.robtex.com/ip-lookup/${enc(v)}`,
    domain: v => `https://www.robtex.com/dns-lookup/${enc(v)}`,
  },
  'Vulners':        { cve: v => `https://vulners.com/cve/${enc(v)}` },
  'PhishTank':      { url: v => `https://www.phishtank.com/phish_search.php?valid=y&active=y&Search=Search` },
  'PhishStats': {
    url:    v => `https://phishstats.info/?s=${enc(v)}`,
    domain: v => `https://phishstats.info/?s=${enc(v)}`,
    ip:     v => `https://phishstats.info/?s=${enc(v)}`,
  },
  'Stalkphish': {
    url:    v => `https://stalkphish.io/search/${enc(v)}`,
    domain: v => `https://stalkphish.io/search/${enc(v)}`,
    ip:     v => `https://stalkphish.io/search/${enc(v)}`,
  },
  'URLdna': {
    url:    v => `https://urldna.io/search?q=${enc(v)}`,
    domain: v => `https://urldna.io/search?q=${enc(v)}`,
  },
  'SecurityTrails': {
    domain: v => `https://securitytrails.com/domain/${enc(v)}`,
    ip:     v => `https://securitytrails.com/list/ip/${enc(v)}`,
  },
  'LeakIX':         { ip: v => `https://leakix.net/host/${enc(v)}` },
  'Netlas':         { ip: v => `https://app.netlas.io/whois/ip/${enc(v)}` },
  'Onyphe': {
    ip:     v => `https://www.onyphe.io/search?q=${enc(v)}`,
    domain: v => `https://www.onyphe.io/search?q=${enc(v)}`,
  },
  'Hunter.how': {
    ip:     v => `https://hunter.how/search?searchValue=${enc(v)}`,
    domain: v => `https://hunter.how/search?searchValue=${enc(v)}`,
  },
  'BinaryEdge': {
    ip:     v => `https://app.binaryedge.io/services/query?query=ip:${enc(v)}`,
    domain: v => `https://app.binaryedge.io/services/query?query=domain:${enc(v)}`,
  },
  'ZoomEye': {
    ip:     v => `https://www.zoomeye.org/searchResult?q=ip:${enc(v)}`,
    domain: v => `https://www.zoomeye.org/searchResult?q=hostname:${enc(v)}`,
  },
  'Validin': {
    ip:     v => `https://app.validin.com/axon/ip/${enc(v)}`,
    domain: v => `https://app.validin.com/axon/domain/${enc(v)}`,
  },
  'EmailRep':       { email: v => `https://emailrep.io/${enc(v)}` },
  'Hudson Rock': {
    email:  v => `https://cavalier.hudsonrock.com/`,
    domain: v => `https://cavalier.hudsonrock.com/`,
    ip:     v => `https://cavalier.hudsonrock.com/`,
  },
  'Hunter.io':      { domain: v => `https://hunter.io/search/${enc(v)}` },
  'Polyswarm': {
    hash:   v => `https://polyswarm.network/scan/results/${enc(v)}`,
    domain: v => `https://polyswarm.network/scan/search?q=${enc(v)}`,
    ip:     v => `https://polyswarm.network/scan/search?q=${enc(v)}`,
  },
  'Intezer':        { hash: v => `https://analyze.intezer.com/analyses/${enc(v)}` },
  'Hybrid Analysis': {
    hash:   v => `https://www.hybrid-analysis.com/sample/${enc(v)}`,
    url:    v => `https://www.hybrid-analysis.com/search?query=${enc(v)}`,
    domain: v => `https://www.hybrid-analysis.com/search?query=${enc(v)}`,
  },
  'Triage': {
    hash:   v => `https://tria.ge/s?q=${enc(v)}`,
    url:    v => `https://tria.ge/s?q=${enc(v)}`,
  },
  'Koodous':        { hash: v => `https://koodous.com/apks/${enc(v)}` },
  'FileScan': {
    hash:   v => `https://www.filescan.io/search?query=${enc(v)}`,
    url:    v => `https://www.filescan.io/search?query=${enc(v)}`,
    domain: v => `https://www.filescan.io/search?query=${enc(v)}`,
    ip:     v => `https://www.filescan.io/search?query=${enc(v)}`,
  },
  'MWDB':           { hash: v => `https://mwdb.cert.pl/file/${enc(v)}` },
  'Joe Sandbox':    {
    hash:   v => `https://jbxcloud.joesecurity.org/search?q=${enc(v)}`,
    url:    v => `https://jbxcloud.joesecurity.org/search?q=${enc(v)}`,
  },
  'Phunter':        { phone: v => `https://www.google.com/search?q=${enc(v)}` },
  'Phoneinfoga':    { phone: v => `https://numverify.com/dashboard` },
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
