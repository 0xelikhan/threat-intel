import React, { useState, useRef } from 'react';

const LEVEL_STYLES = {
  CRITICAL: { bg: '#1a0505', border: '#ff2d2d', text: '#ff6b6b', label: '⬛ CRITICAL' },
  HIGH:     { bg: '#1a0e05', border: '#ff8c00', text: '#ffa94d', label: '🔴 HIGH' },
  MEDIUM:   { bg: '#1a1a05', border: '#ffd700', text: '#ffe566', label: '🟡 MEDIUM' },
  LOW:      { bg: '#05121a', border: '#00b4d8', text: '#90e0ef', label: '🔵 LOW' },
  INFORMATIONAL: { bg: '#0a0e1a', border: '#4a5568', text: '#a0aec0', label: '⚪ INFO' }
};

function Section({ title, children }) {
  return (
    <div style={{ marginBottom: '24px', breakInside: 'avoid' }}>
      <div style={{ fontSize: '11px', letterSpacing: '3px', color: '#4a9eff', borderBottom: '1px solid #1e3a5f', paddingBottom: '6px', marginBottom: '12px', textTransform: 'uppercase' }}>{title}</div>
      {children}
    </div>
  );
}

function IOCTable({ iocs }) {
  const typeColors = { ips: '#4a9eff', domains: '#51cf66', urls: '#ffa94d', hashes: '#cc5de8', emails: '#f06595' };
  const rows = [];
  Object.entries(iocs).forEach(([type, list]) => {
    list.forEach(ioc => rows.push({ ioc, type: type.slice(0, -1).toUpperCase(), color: typeColors[type] }));
  });
  if (!rows.length) return <div style={{ color: '#4a5568', fontSize: '12px' }}>No IOCs extracted.</div>;
  return (
    <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px' }}>
      <thead>
        <tr style={{ borderBottom: '1px solid #1e3a5f' }}>
          {['TYPE', 'INDICATOR'].map(h => <th key={h} style={{ textAlign: 'left', padding: '6px 10px', color: '#718096', fontWeight: 'normal', letterSpacing: '1px', fontSize: '10px' }}>{h}</th>)}
        </tr>
      </thead>
      <tbody>
        {rows.map(({ ioc, type, color }, i) => (
          <tr key={i} style={{ borderBottom: '1px solid #0d1a30', background: i % 2 === 0 ? 'transparent' : '#060d1a' }}>
            <td style={{ padding: '7px 10px', minWidth: '80px' }}>
              <span style={{ background: `${color}22`, border: `1px solid ${color}66`, color, padding: '2px 6px', borderRadius: '3px', fontSize: '10px', fontFamily: 'Courier New', letterSpacing: '1px' }}>{type}</span>
            </td>
            <td style={{ padding: '7px 10px', fontFamily: 'Courier New', color: '#c8d6e5', wordBreak: 'break-all' }}>{ioc}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function VerdictRow({ assessment }) {
  const colors = { MALICIOUS: '#ff6b6b', SUSPICIOUS: '#ffa94d', CLEAN: '#51cf66', UNKNOWN: '#74c0fc' };
  const c = colors[assessment.verdict] || colors.UNKNOWN;
  return (
    <div style={{ display: 'flex', gap: '12px', alignItems: 'flex-start', padding: '8px 0', borderBottom: '1px solid #0d1a30' }}>
      <span style={{ background: `${c}22`, border: `1px solid ${c}66`, color: c, padding: '2px 6px', borderRadius: '3px', fontSize: '10px', fontFamily: 'Courier New', minWidth: '80px', textAlign: 'center' }}>{assessment.verdict}</span>
      <div>
        <div style={{ fontFamily: 'Courier New', fontSize: '12px', color: '#e2e8f0', wordBreak: 'break-all' }}>{assessment.ioc}</div>
        {assessment.reason && <div style={{ fontSize: '12px', color: '#718096', marginTop: '2px' }}>{assessment.reason}</div>}
      </div>
    </div>
  );
}

function EnrichmentHighlights({ enrichments }) {
  const highlights = [];

  // Pull notable data from each IP
  if (enrichments.ips) {
    Object.entries(enrichments.ips).forEach(([ip, data]) => {
      if (data.abuseipdb?.abuseScore > 0) highlights.push({ ioc: ip, source: 'AbuseIPDB', finding: `Abuse score: ${data.abuseipdb.abuseScore}% (${data.abuseipdb.totalReports} reports)` });
      if (data.tor?.isExitNode) highlights.push({ ioc: ip, source: 'Tor', finding: 'Confirmed Tor exit node' });
      if (data.virustotal?.malicious > 0) highlights.push({ ioc: ip, source: 'VirusTotal', finding: `${data.virustotal.malicious} engines flagged as malicious` });
      if (data.otx?.pulseCount > 0) highlights.push({ ioc: ip, source: 'OTX', finding: `Found in ${data.otx.pulseCount} OTX threat pulses` });
      if (data.greynoise?.classification && data.greynoise.classification !== 'unknown') highlights.push({ ioc: ip, source: 'GreyNoise', finding: `Classification: ${data.greynoise.classification} — ${data.greynoise.name || 'Unknown scanner'}` });
    });
  }

  if (enrichments.domains) {
    Object.entries(enrichments.domains).forEach(([domain, data]) => {
      if (data.virustotal?.malicious > 0) highlights.push({ ioc: domain, source: 'VirusTotal', finding: `${data.virustotal.malicious} malicious engines` });
      if (data.otx?.pulseCount > 0) highlights.push({ ioc: domain, source: 'OTX', finding: `In ${data.otx.pulseCount} OTX pulses` });
      if (data.certTransparency?.totalCerts > 50) highlights.push({ ioc: domain, source: 'Cert Transparency', finding: `${data.certTransparency.totalCerts} SSL certs — ${data.certTransparency.subdomains?.length} unique subdomains` });
      if (data.whois?.privacyProtected) highlights.push({ ioc: domain, source: 'WHOIS', finding: `Privacy-protected registration via ${data.whois?.registrar || 'unknown registrar'}` });
    });
  }

  if (enrichments.hashes) {
    Object.entries(enrichments.hashes).forEach(([hash, data]) => {
      if (data.malwarebazaar?.malwareName) highlights.push({ ioc: hash.substring(0, 16) + '...', source: 'MalwareBazaar', finding: `Malware family: ${data.malwarebazaar.malwareName}` });
      if (data.virustotal?.malicious > 0) highlights.push({ ioc: hash.substring(0, 16) + '...', source: 'VirusTotal', finding: `${data.virustotal.malicious} AV engines — ${data.virustotal.name || 'unknown file'}` });
    });
  }

  if (!highlights.length) return <div style={{ fontSize: '12px', color: '#4a5568' }}>No significant findings from threat intelligence APIs.</div>;

  return (
    <div>
      {highlights.map((h, i) => (
        <div key={i} style={{ display: 'flex', gap: '10px', padding: '7px 0', borderBottom: '1px solid #0d1a30', fontSize: '12px', alignItems: 'flex-start' }}>
          <span style={{ background: '#1a3a6e', border: '1px solid #4a9eff33', color: '#74c0fc', padding: '1px 6px', borderRadius: '3px', fontSize: '10px', fontFamily: 'Courier New', minWidth: '90px', textAlign: 'center', letterSpacing: '1px' }}>{h.source}</span>
          <div>
            <span style={{ fontFamily: 'Courier New', color: '#4a9eff', marginRight: '6px' }}>{h.ioc}</span>
            <span style={{ color: '#c8d6e5' }}>{h.finding}</span>
          </div>
        </div>
      ))}
    </div>
  );
}

function ReportView({ result }) {
  const [analystName, setAnalystName] = useState('');
  const [notes, setNotes] = useState('');
  const reportRef = useRef(null);

  if (!result) {
    return (
      <div style={{ background: '#0d1526', border: '1px solid #1e3a5f', borderRadius: '8px', padding: '40px', textAlign: 'center' }}>
        <div style={{ fontSize: '32px', marginBottom: '12px', opacity: 0.3 }}>📋</div>
        <div style={{ color: '#4a5568', fontSize: '14px' }}>No investigation loaded. Run an analysis first, then return here to view the report.</div>
      </div>
    );
  }

  const { iocs, enrichments, analysis, timestamp } = result;
  const levelStyle = LEVEL_STYLES[analysis?.threatLevel] || LEVEL_STYLES.INFORMATIONAL;
  const date = new Date(timestamp);

  const printReport = () => {
    const printContent = reportRef.current.innerHTML;
    const w = window.open('', '_blank');
    w.document.write(`
      <html><head><title>Investigation Report</title>
      <style>
        body { font-family: 'Courier New', monospace; background: #0a0e1a; color: #c8d6e5; padding: 40px; }
        * { box-sizing: border-box; }
        table { border-collapse: collapse; width: 100%; }
        @media print { body { background: white; color: #1a1a2e; } }
      </style></head>
      <body>${printContent}</body></html>
    `);
    w.document.close();
    setTimeout(() => w.print(), 500);
  };

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
        <div style={{ fontSize: '11px', color: '#4a9eff', letterSpacing: '3px' }}>INVESTIGATION REPORT</div>
        <button onClick={printReport} style={{ background: '#1a3a6e', border: '1px solid #4a9eff', color: '#74c0fc', padding: '8px 18px', borderRadius: '4px', cursor: 'pointer', fontSize: '11px', letterSpacing: '2px', fontFamily: 'Courier New' }}>⎙ PRINT / SAVE PDF</button>
      </div>

      <div ref={reportRef} style={{ background: '#0d1526', border: '1px solid #1e3a5f', borderRadius: '8px', padding: '32px' }}>
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '28px', paddingBottom: '20px', borderBottom: '2px solid #1e3a5f' }}>
          <div>
            <div style={{ fontSize: '20px', color: '#e2e8f0', fontWeight: 'bold', letterSpacing: '3px', marginBottom: '4px' }}>THREAT INTELLIGENCE</div>
            <div style={{ fontSize: '12px', color: '#4a5568', letterSpacing: '2px' }}>INVESTIGATION REPORT</div>
          </div>
          <div style={{ textAlign: 'right', fontSize: '12px', color: '#718096' }}>
            <div>DATE: {date.toLocaleDateString()}</div>
            <div>TIME: {date.toLocaleTimeString()}</div>
            <div style={{ marginTop: '4px', fontFamily: 'Courier New' }}>ID: {timestamp.replace(/[^0-9]/g, '').substring(0, 14)}</div>
          </div>
        </div>

        {/* Analyst metadata */}
        <Section title="Report Metadata">
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
            <div>
              <div style={{ fontSize: '11px', color: '#4a5568', marginBottom: '4px' }}>ANALYST NAME</div>
              <input
                value={analystName}
                onChange={e => setAnalystName(e.target.value)}
                placeholder="Enter your name..."
                style={{ background: '#060d1a', border: '1px solid #1e3a5f', color: '#c8d6e5', padding: '8px 12px', borderRadius: '4px', fontFamily: 'Courier New', fontSize: '13px', outline: 'none', width: '100%' }}
              />
            </div>
            <div>
              <div style={{ fontSize: '11px', color: '#4a5568', marginBottom: '4px' }}>TICKET / CASE REF</div>
              <input
                placeholder="Enter ticket or case number..."
                style={{ background: '#060d1a', border: '1px solid #1e3a5f', color: '#c8d6e5', padding: '8px 12px', borderRadius: '4px', fontFamily: 'Courier New', fontSize: '13px', outline: 'none', width: '100%' }}
              />
            </div>
          </div>
        </Section>

        {/* Threat level */}
        {analysis && (
          <Section title="Executive Summary">
            <div style={{ background: levelStyle.bg, border: `1px solid ${levelStyle.border}`, borderRadius: '6px', padding: '16px 20px', marginBottom: '12px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '10px' }}>
                <span style={{ fontSize: '20px', color: levelStyle.text, fontFamily: 'Courier New', fontWeight: 'bold', letterSpacing: '3px' }}>{levelStyle.label}</span>
              </div>
              <div style={{ fontSize: '14px', color: '#c8d6e5', lineHeight: '1.7' }}>{analysis.summary}</div>
            </div>
            {analysis.attackPatterns?.length > 0 && (
              <div style={{ fontSize: '12px', color: '#718096' }}>
                Possible patterns: <span style={{ color: '#ffa94d' }}>{analysis.attackPatterns.join(' · ')}</span>
              </div>
            )}
          </Section>
        )}

        {/* IOC inventory */}
        <Section title={`IOC Inventory (${Object.values(iocs).flat().length} total)`}>
          <IOCTable iocs={iocs} />
        </Section>

        {/* Threat intelligence highlights */}
        {enrichments && Object.keys(enrichments).length > 0 && (
          <Section title="Threat Intelligence Highlights">
            <EnrichmentHighlights enrichments={enrichments} />
          </Section>
        )}

        {/* IOC verdicts */}
        {analysis?.iocAssessments?.length > 0 && (
          <Section title="IOC Verdicts">
            {analysis.iocAssessments.map((a, i) => <VerdictRow key={i} assessment={a} />)}
          </Section>
        )}

        {/* Key findings */}
        {analysis?.keyFindings?.length > 0 && (
          <Section title="Key Findings">
            {analysis.keyFindings.map((f, i) => (
              <div key={i} style={{ display: 'flex', gap: '10px', padding: '7px 0', borderBottom: '1px solid #0d1a30', fontSize: '13px', color: '#c8d6e5' }}>
                <span style={{ color: '#4a9eff', minWidth: '20px', fontSize: '12px' }}>{i + 1}.</span>{f}
              </div>
            ))}
          </Section>
        )}

        {/* MITRE */}
        {analysis?.mitreTechniques?.length > 0 && (
          <Section title="MITRE ATT&CK Techniques">
            <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
              {analysis.mitreTechniques.map((t, i) => (
                <span key={i} style={{ background: '#1a2744', border: '1px solid #2d3f6b', color: '#74c0fc', padding: '5px 12px', borderRadius: '4px', fontSize: '12px', fontFamily: 'Courier New' }}>{t}</span>
              ))}
            </div>
          </Section>
        )}

        {/* Recommended actions */}
        {analysis?.recommendedActions?.length > 0 && (
          <Section title="Recommended Actions">
            {analysis.recommendedActions.map((a, i) => (
              <div key={i} style={{ display: 'flex', gap: '10px', padding: '8px 0', borderBottom: '1px solid #0d1a30', fontSize: '13px', color: '#c8d6e5' }}>
                <span style={{ color: '#51cf66', minWidth: '24px', fontWeight: 'bold' }}>{i + 1}.</span>{a}
              </div>
            ))}
          </Section>
        )}

        {/* Analyst notes */}
        <Section title="Analyst Notes">
          <textarea
            value={notes}
            onChange={e => setNotes(e.target.value)}
            placeholder="Add your own observations, context, or follow-up items here..."
            style={{ width: '100%', background: '#060d1a', border: '1px solid #1e3a5f', color: '#c8d6e5', padding: '12px', borderRadius: '6px', fontFamily: 'Courier New', fontSize: '13px', resize: 'vertical', outline: 'none', lineHeight: '1.6', minHeight: '80px' }}
          />
        </Section>

        {/* Footer */}
        <div style={{ borderTop: '1px solid #1e3a5f', paddingTop: '16px', display: 'flex', justifyContent: 'space-between', fontSize: '10px', color: '#4a5568', letterSpacing: '1px' }}>
          <div>THREAT INTEL PLATFORM · GENERATED {date.toISOString()}</div>
          <div>CONFIDENTIAL — INTERNAL USE ONLY</div>
        </div>
      </div>
    </div>
  );
}

// Skip re-render when props are shallowly equal — the top-level views all
// receive a heavy `result` / `analysisResult` prop plus stable callbacks.
export default React.memo(ReportView);
