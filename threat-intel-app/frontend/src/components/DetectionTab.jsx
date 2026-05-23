import React, { useState, useEffect } from 'react';

const TACTIC_COLORS = {
  'Initial Access': '#ff6b6b', 'Execution': '#ffa94d', 'Persistence': '#ffe566',
  'Privilege Escalation': '#ff8c00', 'Defense Evasion': '#cc5de8',
  'Credential Access': '#f06595', 'Discovery': '#74c0fc', 'Lateral Movement': '#63e6be',
  'Collection': '#a9e34b', 'Command and Control': '#4dabf7', 'Exfiltration': '#da77f2', 'Impact': '#ff6b6b',
};
const FLAGS = { 'Russia': '🇷🇺', 'China': '🇨🇳', 'North Korea': '🇰🇵', 'US/UK': '🇺🇸', 'Eastern Europe': '🌍', 'Unknown': '❓' };

const S = {
  panel: { background: '#0d1526', border: '1px solid #1e3a5f', borderRadius: '8px', padding: '20px' },
  label: { fontSize: '10px', color: '#4a9eff', letterSpacing: '2px', textTransform: 'uppercase', marginBottom: '8px', display: 'block' },
  input: { width: '100%', background: '#060d1a', border: '1px solid #1e3a5f', color: '#c8d6e5', padding: '10px 14px', borderRadius: '6px', fontFamily: 'Courier New', fontSize: '13px', outline: 'none', marginBottom: '10px' },
  btn: (active) => ({ background: active ? '#1a3a6e' : '#0d1526', border: `1px solid ${active ? '#4a9eff' : '#2d3748'}`, color: active ? '#74c0fc' : '#718096', padding: '8px 16px', borderRadius: '4px', cursor: 'pointer', fontSize: '11px', letterSpacing: '1px', fontFamily: 'Courier New', transition: 'all 0.15s' }),
  code: { background: '#060d1a', border: '1px solid #1e3a5f', borderRadius: '6px', padding: '16px', fontFamily: 'Courier New', fontSize: '12px', color: '#c8d6e5', whiteSpace: 'pre-wrap', overflowX: 'auto', lineHeight: '1.7', maxHeight: '500px', overflowY: 'auto' },
  tag: (c) => ({ background: `${c}22`, border: `1px solid ${c}66`, color: c, padding: '2px 8px', borderRadius: '3px', fontSize: '10px', fontFamily: 'Courier New', display: 'inline-block' }),
  card: { background: '#0a1220', border: '1px solid #1e3a5f', borderRadius: '6px', padding: '12px', marginBottom: '8px', cursor: 'pointer' },
};

const call = (action, body) =>
  fetch('/api/detection', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ action, ...body }) })
    .then(r => r.json()).then(d => d.result);

// ─── MITRE BROWSER ────────────────────────────────────────────────────────────────
function MitreBrowser({ analysisResult }) {
  const [query, setQuery]       = useState('');
  const [results, setResults]   = useState([]);
  const [selected, setSelected] = useState(null);
  const [loading, setLoading]   = useState(false);

  const search = async (q) => {
    if (q.length < 2) { setResults([]); return; }
    setLoading(true);
    const r = await call('mitre', { query: q }).catch(() => []);
    setResults(r || []);
    setLoading(false);
  };

  useEffect(() => { const t = setTimeout(() => search(query), 300); return () => clearTimeout(t); }, [query]);

  useEffect(() => {
    const techs = analysisResult?.response_summary?.mitre_techniques || analysisResult?.mitre_techniques || [];
    if (techs.length) setQuery(techs[0].split(' ')[0]);
  }, [analysisResult]);

  return (
    <div style={S.panel}>
      <div style={{ fontWeight: 'bold', color: '#e2e8f0', marginBottom: '16px', fontSize: '13px' }}>MITRE ATT&CK BROWSER</div>
      <input style={S.input} value={query} onChange={e => setQuery(e.target.value)} placeholder="Search by ID (T1566), name, or tactic..." />

      {/* Quick-fill from analysis */}
      {(() => {
        const techs = analysisResult?.response_summary?.mitre_techniques || analysisResult?.mitre_techniques || [];
        if (!techs.length) return null;
        return (
          <div style={{ marginBottom: '12px', display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
            <span style={{ fontSize: '10px', color: '#4a5568', alignSelf: 'center' }}>FROM ANALYSIS:</span>
            {techs.map(t => (
              <button key={t} style={S.btn(false)} onClick={() => setQuery(t.split(' ')[0])} >
                {t.split(' ')[0]}
              </button>
            ))}
          </div>
        );
      })()}

      <div style={{ display: 'grid', gridTemplateColumns: selected ? '1fr 1fr' : '1fr', gap: '12px' }}>
        <div style={{ maxHeight: '480px', overflowY: 'auto' }}>
          {loading && <div style={{ color: '#4a5568', fontSize: '12px', padding: '12px' }}>Searching...</div>}
          {results.map(tech => (
            <div key={tech.id} style={{ ...S.card, borderColor: selected?.id === tech.id ? '#4a9eff' : '#1e3a5f' }} onClick={() => setSelected(selected?.id === tech.id ? null : tech)}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                <span style={{ color: '#4a9eff', fontSize: '12px', minWidth: '80px', fontFamily: 'Courier New' }}>{tech.id}</span>
                <span style={{ fontSize: '13px', color: '#e2e8f0' }}>{tech.name}</span>
              </div>
              <span style={S.tag(TACTIC_COLORS[tech.tactic] || '#718096')}>{tech.tactic}</span>
            </div>
          ))}
        </div>

        {selected && (
          <div style={{ background: '#060d1a', border: '1px solid #1e3a5f', borderRadius: '6px', padding: '16px', maxHeight: '480px', overflowY: 'auto' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '10px' }}>
              <div>
                <div style={{ color: '#4a9eff', fontSize: '13px', fontFamily: 'Courier New' }}>{selected.id}</div>
                <div style={{ color: '#e2e8f0', fontSize: '15px', fontWeight: 'bold' }}>{selected.name}</div>
              </div>
              <button onClick={() => setSelected(null)} style={S.btn(false)}>✕</button>
            </div>
            <span style={S.tag(TACTIC_COLORS[selected.tactic] || '#718096')}>{selected.tactic}</span>
            <div style={{ marginTop: '12px', fontSize: '13px', color: '#c8d6e5', lineHeight: '1.6' }}>{selected.description}</div>
            {selected.detection && (
              <div style={{ marginTop: '12px' }}>
                <div style={S.label}>Detection Guidance</div>
                <div style={{ fontSize: '12px', color: '#51cf66', background: '#0a1a0a', border: '1px solid #1a3a1a', borderRadius: '4px', padding: '10px', lineHeight: '1.6' }}>{selected.detection}</div>
              </div>
            )}
            <a href={`https://attack.mitre.org/techniques/${selected.id.replace('.', '/')}/`} target="_blank" rel="noreferrer" style={{ display: 'block', marginTop: '10px', fontSize: '11px', color: '#4a9eff' }}>
              View on MITRE ATT&CK →
            </a>
          </div>
        )}
      </div>
    </div>
  );
}

// ─── THREAT ACTORS ────────────────────────────────────────────────────────────────
function ThreatActors({ analysisResult }) {
  const [actors, setActors]     = useState([]);
  const [loading, setLoading]   = useState(false);
  const [searched, setSearched] = useState(false);
  const [selected, setSelected] = useState(null);

  const match = async () => {
    const techs = analysisResult?.response_summary?.mitre_techniques || analysisResult?.mitre_techniques || [];
    if (!techs.length) return;
    setLoading(true);
    const r = await call('actors', { mitreTechniques: techs }).catch(() => []);
    setActors(r || []);
    setSearched(true);
    setLoading(false);
  };

  const scoreColor = s => s >= 60 ? '#ff6b6b' : s >= 35 ? '#ffa94d' : '#74c0fc';

  return (
    <div style={S.panel}>
      <div style={{ fontWeight: 'bold', color: '#e2e8f0', marginBottom: '8px', fontSize: '13px' }}>THREAT ACTOR PROFILES</div>
      <div style={{ fontSize: '12px', color: '#718096', marginBottom: '16px' }}>
        Matches identified MITRE techniques against known APT group TTPs.
      </div>
      {!analysisResult && <div style={{ color: '#ffa94d', fontSize: '12px', marginBottom: '12px' }}>⚠ Run an analysis first.</div>}
      {analysisResult && !searched && (
        <button style={S.btn(true)} onClick={match} disabled={loading}>
          {loading ? '⟳ MATCHING...' : '🔍 MATCH THREAT ACTORS'}
        </button>
      )}
      {searched && !actors.length && <div style={{ color: '#718096', fontSize: '12px', marginTop: '8px' }}>No strong matches for the identified techniques.</div>}
      {actors.map(actor => (
        <div key={actor.name} style={{ ...S.card, borderColor: selected?.name === actor.name ? '#4a9eff' : '#1e3a5f' }} onClick={() => setSelected(selected?.name === actor.name ? null : actor)}>
          <div style={{ display: 'flex', gap: '10px', alignItems: 'center', marginBottom: '6px' }}>
            <span style={{ fontSize: '18px' }}>{FLAGS[actor.origin] || '❓'}</span>
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: '14px', color: '#e2e8f0', fontWeight: 'bold' }}>{actor.name}</div>
              <div style={{ fontSize: '11px', color: '#718096' }}>{actor.origin} · {actor.sponsor}</div>
            </div>
            <div style={{ textAlign: 'right' }}>
              <div style={{ fontSize: '18px', fontWeight: 'bold', color: scoreColor(actor.score), fontFamily: 'Courier New' }}>{actor.score}%</div>
              <div style={{ fontSize: '10px', color: '#4a5568' }}>TTP MATCH</div>
            </div>
          </div>
          <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
            {actor.matchedTechniques.map(t => <span key={t} style={S.tag('#ffa94d')}>{t}</span>)}
            {actor.sectors?.slice(0, 3).map(s => <span key={s} style={S.tag('#4a5568')}>{s}</span>)}
          </div>
          {selected?.name === actor.name && (
            <div style={{ marginTop: '12px', paddingTop: '12px', borderTop: '1px solid #1e3a5f' }}>
              <div style={{ fontSize: '12px', color: '#c8d6e5', marginBottom: '8px', lineHeight: '1.6' }}>Sectors: {actor.sectors?.join(', ')}</div>
              {actor.campaigns?.length > 0 && (
                <div>
                  <div style={S.label}>Known Campaigns</div>
                  <div style={{ display: 'flex', gap: '5px', flexWrap: 'wrap' }}>
                    {actor.campaigns.map(c => <span key={c} style={S.tag('#4a9eff')}>{c}</span>)}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

// ─── SIGMA GENERATOR ─────────────────────────────────────────────────────────────
function SigmaGenerator({ analysisResult }) {
  const [loading, setLoading] = useState(false);
  const [rule, setRule]       = useState('');
  const [copied, setCopied]   = useState(false);

  const generate = async () => {
    if (!analysisResult) return;
    setLoading(true);
    const r = await call('sigma', {
      iocs: analysisResult.iocs,
      analysis: analysisResult.response_summary || analysisResult.investigation,
    }).catch(() => '# Error generating rule');
    setRule(r || '# No rule generated');
    setLoading(false);
  };

  const copy = () => { navigator.clipboard.writeText(rule); setCopied(true); setTimeout(() => setCopied(false), 2000); };

  return (
    <div style={S.panel}>
      <div style={{ fontWeight: 'bold', color: '#e2e8f0', marginBottom: '8px', fontSize: '13px' }}>SIGMA RULE GENERATOR</div>
      <div style={{ fontSize: '12px', color: '#718096', marginBottom: '16px' }}>Generates a production-ready Sigma YAML rule from your investigation findings.</div>
      {!analysisResult && <div style={{ color: '#ffa94d', fontSize: '12px', marginBottom: '12px' }}>⚠ Run an analysis first.</div>}
      <button style={S.btn(true)} onClick={generate} disabled={!analysisResult || loading}>
        {loading ? '⟳ GENERATING...' : '⚡ GENERATE SIGMA RULE'}
      </button>
      {rule && (
        <div style={{ marginTop: '16px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px' }}>
            <div style={S.label}>Generated Rule</div>
            <div style={{ display: 'flex', gap: '6px' }}>
              <button style={S.btn(false)} onClick={copy}>{copied ? '✓ COPIED' : 'COPY YAML'}</button>
              <button style={S.btn(false)} onClick={() => { const b = new Blob([rule], {type:'text/yaml'}); const u = URL.createObjectURL(b); const a = document.createElement('a'); a.href=u; a.download='detection.sigma.yml'; a.click(); }}>⬇ DOWNLOAD</button>
            </div>
          </div>
          <div style={S.code}>{rule}</div>
          <div style={{ marginTop: '6px', fontSize: '11px', color: '#4a5568' }}>⚠ Review and validate before deploying to production.</div>
        </div>
      )}
    </div>
  );
}

// ─── KQL BUILDER ─────────────────────────────────────────────────────────────────
function KQLBuilder({ analysisResult }) {
  const [loading, setLoading] = useState(false);
  const [query, setQuery]     = useState('');
  const [copied, setCopied]   = useState(false);

  const generate = async () => {
    if (!analysisResult) return;
    setLoading(true);
    const r = await call('kql', {
      iocs: analysisResult.iocs,
      analysis: analysisResult.response_summary || analysisResult.investigation,
    }).catch(() => '// Error generating KQL');
    setQuery(r || '// No query generated');
    setLoading(false);
  };

  const copy = () => { navigator.clipboard.writeText(query); setCopied(true); setTimeout(() => setCopied(false), 2000); };

  return (
    <div style={S.panel}>
      <div style={{ fontWeight: 'bold', color: '#e2e8f0', marginBottom: '8px', fontSize: '13px' }}>KQL QUERY BUILDER</div>
      <div style={{ fontSize: '12px', color: '#718096', marginBottom: '16px' }}>Generates a Microsoft Sentinel KQL analytics rule ready to paste into your workspace.</div>
      {!analysisResult && <div style={{ color: '#ffa94d', fontSize: '12px', marginBottom: '12px' }}>⚠ Run an analysis first.</div>}
      <button style={S.btn(true)} onClick={generate} disabled={!analysisResult || loading}>
        {loading ? '⟳ GENERATING...' : '⚡ GENERATE KQL RULE'}
      </button>
      {query && (
        <div style={{ marginTop: '16px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px' }}>
            <div style={S.label}>Generated KQL</div>
            <div style={{ display: 'flex', gap: '6px' }}>
              <button style={S.btn(false)} onClick={copy}>{copied ? '✓ COPIED' : 'COPY KQL'}</button>
              <button style={S.btn(false)} onClick={() => { const b = new Blob([query], {type:'text/plain'}); const u = URL.createObjectURL(b); const a = document.createElement('a'); a.href=u; a.download='detection.kql'; a.click(); }}>⬇ DOWNLOAD</button>
            </div>
          </div>
          <div style={S.code}>{query}</div>
          <div style={{ marginTop: '6px', fontSize: '11px', color: '#4a5568' }}>Paste into Sentinel → Analytics → Create rule → Set rule logic.</div>
        </div>
      )}
    </div>
  );
}

// ─── MAIN TAB ────────────────────────────────────────────────────────────────────
export default function DetectionTab({ analysisResult }) {
  const [tab, setTab] = useState('mitre');
  const tabs = [{ id: 'mitre', label: 'MITRE ATT&CK' }, { id: 'actors', label: 'THREAT ACTORS' }, { id: 'sigma', label: 'SIGMA RULE' }, { id: 'kql', label: 'KQL BUILDER' }];
  return (
    <div>
      <div style={{ display: 'flex', gap: '6px', marginBottom: '16px', flexWrap: 'wrap' }}>
        {tabs.map(t => (
          <button key={t.id} style={S.btn(tab === t.id)} onClick={() => setTab(t.id)}>{t.label}</button>
        ))}
      </div>
      {tab === 'mitre'  && <MitreBrowser analysisResult={analysisResult} />}
      {tab === 'actors' && <ThreatActors analysisResult={analysisResult} />}
      {tab === 'sigma'  && <SigmaGenerator analysisResult={analysisResult} />}
      {tab === 'kql'    && <KQLBuilder analysisResult={analysisResult} />}
    </div>
  );
}
