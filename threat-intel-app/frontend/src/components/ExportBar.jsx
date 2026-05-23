import React, { useState } from 'react';

// ─── CSV EXPORT UTILITY ──────────────────────────────────────────────────────────

/**
 * Build a flat CSV from analysis result.
 * Columns: type, value, verdict, reason, abuse_score, vt_malicious,
 *          country, org, is_tor, otx_pulses, malware_name, registrar,
 *          shodan_ports, shodan_vulns, whois_created, cert_count,
 *          threat_level, mitre_techniques, analyst_timestamp
 */
export function buildIOCCSV(result) {
  if (!result) return '';

  const { iocs, enrichments, response_summary, threat_level } = result;
  const mitre = (response_summary?.mitre_techniques || []).join(' | ');
  const ts = new Date().toISOString();

  const rows = [];

  // Header
  rows.push([
    'type', 'value', 'verdict', 'reason',
    'abuse_score', 'vt_malicious', 'vt_suspicious',
    'country', 'org', 'is_tor', 'greynoise_class',
    'otx_pulses', 'bgp_rank',
    'malware_name', 'malware_family',
    'registrar', 'whois_created', 'cert_count', 'pulsedive_risk',
    'shodan_ports', 'shodan_vulns',
    'overall_threat_level', 'mitre_techniques', 'analysis_timestamp'
  ].join(','));

  const getAssessment = (value) =>
    response_summary?.ioc_assessments?.find(a => a.ioc === value) || {};

  const q = (v) => {
    if (v == null) return '';
    const s = String(v);
    if (s.includes(',') || s.includes('"') || s.includes('\n')) {
      return `"${s.replace(/"/g, '""')}"`;
    }
    return s;
  };

  // IPs
  (iocs?.ips || []).forEach(ip => {
    const d = enrichments?.ips?.[ip] || {};
    const a = getAssessment(ip);
    rows.push([
      q('ip'), q(ip), q(a.verdict || 'UNKNOWN'), q(a.reason || ''),
      q(d.abuseipdb?.abuseScore ?? ''),
      q(d.virustotal?.malicious ?? ''),
      q(d.virustotal?.suspicious ?? ''),
      q(d.ipinfo?.country || d.abuseipdb?.country || ''),
      q(d.ipinfo?.org || d.abuseipdb?.isp || ''),
      q(d.tor?.isExitNode ? 'TRUE' : 'FALSE'),
      q(d.greynoise?.classification || ''),
      q(d.otx?.pulseCount ?? ''),
      q(d.bgpranking?.rank ?? ''),
      q(''), q(''),
      q(''), q(''), q(''), q(''),
      q((d.shodan?.ports || []).join(' | ')),
      q((d.shodan?.vulns || []).join(' | ')),
      q(threat_level || ''), q(mitre), q(ts)
    ].join(','));
  });

  // Domains
  (iocs?.domains || []).forEach(domain => {
    const d = enrichments?.domains?.[domain] || {};
    const a = getAssessment(domain);
    rows.push([
      q('domain'), q(domain), q(a.verdict || 'UNKNOWN'), q(a.reason || ''),
      q(''), q(d.virustotal?.malicious ?? ''), q(d.virustotal?.suspicious ?? ''),
      q(''), q(''), q(''), q(''),
      q(d.otx?.pulseCount ?? ''), q(''),
      q(''), q(''),
      q(d.whois?.registrar || ''),
      q(d.whois?.created || ''),
      q(d.certTransparency?.totalCerts ?? ''),
      q(d.pulsedive?.risk || ''),
      q(''), q(''),
      q(threat_level || ''), q(mitre), q(ts)
    ].join(','));
  });

  // Hashes
  (iocs?.hashes || []).forEach(hash => {
    const d = enrichments?.hashes?.[hash] || {};
    const a = getAssessment(hash);
    const malwareName = d.malwarebazaar?.malwareName || d.virustotal?.name || '';
    const malwareFamily = d.threatfox?.malware || '';
    rows.push([
      q('hash'), q(hash), q(a.verdict || 'UNKNOWN'), q(a.reason || ''),
      q(''), q(d.virustotal?.malicious ?? ''), q(d.virustotal?.suspicious ?? ''),
      q(''), q(''), q(''), q(''),
      q(d.otx?.pulseCount ?? ''), q(''),
      q(malwareName), q(malwareFamily),
      q(''), q(''), q(''), q(''),
      q(''), q(''),
      q(threat_level || ''), q(mitre), q(ts)
    ].join(','));
  });

  // URLs
  (iocs?.urls || []).forEach(url => {
    const d = enrichments?.urls?.[url] || {};
    const a = getAssessment(url);
    rows.push([
      q('url'), q(url), q(a.verdict || 'UNKNOWN'), q(a.reason || ''),
      q(''), q(d.virustotal?.malicious ?? ''), q(d.virustotal?.suspicious ?? ''),
      q(''), q(''), q(''), q(''),
      q(''), q(''),
      q(''), q(d.urlhaus?.threat || ''),
      q(''), q(''), q(''), q(''),
      q(''), q(''),
      q(threat_level || ''), q(mitre), q(ts)
    ].join(','));
  });

  // Emails
  (iocs?.emails || []).forEach(email => {
    const a = getAssessment(email);
    rows.push([
      q('email'), q(email), q(a.verdict || 'UNKNOWN'), q(a.reason || ''),
      q(''), q(''), q(''),
      q(''), q(''), q(''), q(''),
      q(''), q(''),
      q(''), q(''),
      q(''), q(''), q(''), q(''),
      q(''), q(''),
      q(threat_level || ''), q(mitre), q(ts)
    ].join(','));
  });

  return rows.join('\n');
}


/**
 * Build a plain text IOC list (one per line, defanged).
 */
export function buildIOCPlaintext(result, defang = false) {
  if (!result) return '';

  const d = (v) => defang
    ? v.replace(/\./g, '[.]').replace(/https?:\/\//g, 'hxxp://')
    : v;

  const sections = [];

  if (result.iocs?.ips?.length) {
    sections.push(`# IPs (${result.iocs.ips.length})\n` + result.iocs.ips.map(d).join('\n'));
  }
  if (result.iocs?.domains?.length) {
    sections.push(`# Domains (${result.iocs.domains.length})\n` + result.iocs.domains.map(d).join('\n'));
  }
  if (result.iocs?.hashes?.length) {
    sections.push(`# Hashes (${result.iocs.hashes.length})\n` + result.iocs.hashes.join('\n'));
  }
  if (result.iocs?.urls?.length) {
    sections.push(`# URLs (${result.iocs.urls.length})\n` + result.iocs.urls.map(d).join('\n'));
  }
  if (result.iocs?.emails?.length) {
    sections.push(`# Emails (${result.iocs.emails.length})\n` + result.iocs.emails.join('\n'));
  }

  return sections.join('\n\n');
}


/**
 * Trigger a browser download of any string content.
 */
export function downloadFile(content, filename, mimeType = 'text/plain') {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}


// ─── EXPORT BAR COMPONENT ────────────────────────────────────────────────────────
export default function ExportBar({ result }) {
  const [lastExport, setLastExport] = useState(null);

  if (!result) return null;

  const totalIOCs = Object.values(result.iocs || {}).flat().length;
  const ts = new Date().toISOString().replace(/[:.]/g, '-').substring(0, 19);
  const baseName = `threat-intel-${ts}`;

  const btn = (label, onClick, color = '#4a9eff') => ({
    onClick: () => { onClick(); setLastExport(label); setTimeout(() => setLastExport(null), 2000); },
    style: {
      background: lastExport === label ? `${color}22` : '#0d1526',
      border: `1px solid ${lastExport === label ? color : '#1e3a5f'}`,
      color: lastExport === label ? color : '#718096',
      padding: '7px 14px', borderRadius: '4px', cursor: 'pointer',
      fontSize: '11px', letterSpacing: '1px', fontFamily: 'Courier New',
      transition: 'all 0.15s', display: 'flex', alignItems: 'center', gap: '6px'
    }
  });

  const exports = [
    {
      label: '⬇ CSV (full)',
      desc: 'All IOCs with enrichment data',
      action: () => downloadFile(buildIOCCSV(result), `${baseName}.csv`, 'text/csv'),
      color: '#51cf66'
    },
    {
      label: '⬇ Plain list',
      desc: 'One IOC per line',
      action: () => downloadFile(buildIOCPlaintext(result, false), `${baseName}-iocs.txt`),
      color: '#74c0fc'
    },
    {
      label: '⬇ Defanged',
      desc: 'Safe for Slack / tickets',
      action: () => downloadFile(buildIOCPlaintext(result, true), `${baseName}-defanged.txt`),
      color: '#74c0fc'
    },
    {
      label: '⬇ STIX 2.1',
      desc: 'Machine-readable bundle',
      action: () => {
        if (result.stix_bundle) {
          downloadFile(JSON.stringify(result.stix_bundle, null, 2), `${baseName}.stix.json`, 'application/json');
        } else if (result.runId) {
          window.open(`${process.env.REACT_APP_API_URL?.replace('/analyze', '')}/export/stix/${result.runId}`, '_blank');
        }
      },
      color: '#cc5de8'
    },
    {
      label: '⬇ Sigma YAML',
      desc: 'Detection rule',
      action: () => result.sigma_rule && downloadFile(result.sigma_rule, `${baseName}.sigma.yml`, 'text/yaml'),
      color: '#ffa94d',
      disabled: !result.sigma_rule
    },
    {
      label: '⬇ KQL',
      desc: 'Sentinel query',
      action: () => result.kql_query && downloadFile(result.kql_query, `${baseName}.kql`, 'text/plain'),
      color: '#ffa94d',
      disabled: !result.kql_query
    },
  ];

  return (
    <div style={{ background: '#0d1526', border: '1px solid #1e3a5f', borderRadius: '8px', padding: '14px 16px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
        <div style={{ fontSize: '10px', color: '#4a9eff', letterSpacing: '3px' }}>EXPORT</div>
        <div style={{ fontSize: '11px', color: '#4a5568' }}>{totalIOCs} IOCs · {new Date().toLocaleString()}</div>
      </div>

      <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
        {exports.map(({ label, desc, action, color, disabled }) => {
          const b = btn(label, action, color);
          return (
            <button
              key={label}
              {...b}
              disabled={disabled}
              title={desc}
              style={{ ...b.style, opacity: disabled ? 0.3 : 1, cursor: disabled ? 'not-allowed' : 'pointer' }}
            >
              {lastExport === label ? '✓ saved' : label}
            </button>
          );
        })}
      </div>

      <div style={{ marginTop: '10px', fontSize: '11px', color: '#4a5568', display: 'flex', gap: '16px', flexWrap: 'wrap' }}>
        <span>CSV — paste into Excel or import into MISP</span>
        <span>STIX — import into OpenCTI, MISP, or any TI platform</span>
        <span>Defanged — safe to share in tickets, email, Slack</span>
      </div>
    </div>
  );
}
