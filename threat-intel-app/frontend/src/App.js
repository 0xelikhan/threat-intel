import React, { useState, useEffect, useCallback } from 'react';
import {
  Search, Shield, Activity, Target, Map, FileText,
  Settings, Share2, Wrench, Upload, ChevronRight,
  AlertTriangle, CheckCircle, XCircle, Info, Clock,
  TrendingUp, Globe, Database, Zap, Eye, Hash,
  BarChart2, Bell, RefreshCw, Download, Filter,
  ChevronDown, ChevronUp, Radio, Cpu, Lock
} from 'lucide-react';

import ToolsTab      from './components/ToolsTab';
import DetectionTab  from './components/DetectionTab';
import ReportView    from './components/ReportView';
import MapTab        from './components/MapTab';
import PivotGraph    from './components/PivotGraph';
import ExportBar     from './components/ExportBar';
import SettingsPage  from './components/SettingsPage';
import HistoryPanel  from './components/HistoryPanel';
import AgentPipeline from './components/AgentPipeline';
import GTIScorePanel from './components/GTIScorePanel';

// ─── EXACT OPENCTI DARK THEME TOKENS ────────────────────────────────────────
// Sourced directly from OpenCTI ThemeDark.ts (MIT License)
// github.com/OpenCTI-Platform/opencti
const T = {
  // ── Backgrounds (exact from ThemeDark.ts) ──────────────────────────────────
  bg0:    '#070d19',   // THEME_DARK_DEFAULT_BACKGROUND / THEME_DARK_DEFAULT_NAV
  bg1:    '#070d19',   // body / sidebar — same deepest navy
  bg2:    '#09101e',   // THEME_DARK_DEFAULT_PAPER — card surfaces
  bg3:    '#0f1d34',   // drawer / dialog background
  bg4:    '#253348',   // leftBar.header.itemBackground / leftBar.hover
  bg5:    '#0c1524',   // background.secondary — elevated inputs
  bg6:    '#0d182a',   // designSystem.background.bg2
  bg7:    '#1c2f49',   // designSystem.background.bg4 — deep accent

  // ── Accent background ──────────────────────────────────────────────────────
  accent: '#0f1e38',   // THEME_DARK_DEFAULT_ACCENT — code blocks, highlights

  // ── Borders (exact from ThemeDark.ts designSystem.border) ─────────────────
  b1: '#2b3447',       // designSystem.border.main — primary border
  b2: '#424751',       // designSystem.border.border1 / border.secondary
  b3: '#1c253a',       // designSystem.border.border2
  b4: '#252a35',       // border.main (legacy)

  // ── Primary accent — OpenCTI blue (NOT orange — their actual primary) ──────
  primary:    '#0fbcff',   // THEME_DARK_DEFAULT_PRIMARY
  primaryDim: '#0fbcff18',
  primaryMid: '#0fbcff44',
  primaryLight:'#b2ecff',  // primary.light

  // ── Secondary accent — green ───────────────────────────────────────────────
  secondary:  '#00f18d',   // THEME_DARK_DEFAULT_SECONDARY / EE_COLOR
  secondaryDim:'#00f18d18',

  // ── Severity colors (exact from ThemeDark.ts palette.severity) ────────────
  critical: '#EE3838',
  high:     '#E6700F',
  medium:   '#E1B823',
  low:      '#16AD34',
  info:     '#1565c0',
  clean:    '#17AB1F',   // success.main

  // ── Error / warning / success ──────────────────────────────────────────────
  error:   '#F14337',    // error.main
  warn:    '#E6700F',    // warn.main
  success: '#17AB1F',    // success.main

  // ── Text (exact from ThemeDark.ts) ────────────────────────────────────────
  t1: '#F2F2F3',    // THEME_DARK_DEFAULT_TEXT / leftBar.text / text.secondary
  t2: '#AFB0B6',    // text.light
  t3: '#848592',    // text.tertiary
  t4: '#75829A',    // text.disabled

  // ── Fonts (exact from ThemeDark.ts typography) ────────────────────────────
  font:    '"IBM Plex Sans", sans-serif',
  fontH:   '"Geologica", sans-serif',   // headings font
  mono:    '"IBM Plex Mono", monospace',

  // ── Gradient ──────────────────────────────────────────────────────────────
  gradient: 'linear-gradient(100.35deg, #070D19 0%, #08101d 100%)',
};

// Severity level config — maps to ThemeDark.ts palette.severity exactly
const SEVERITY = {
  CRITICAL:      { c: '#EE3838', bg: '#EE383818', label: 'CRITICAL' },
  HIGH:          { c: '#E6700F', bg: '#E6700F18', label: 'HIGH' },
  MEDIUM:        { c: '#E1B823', bg: '#E1B82318', label: 'MEDIUM' },
  LOW:           { c: '#16AD34', bg: '#16AD3418', label: 'LOW' },
  INFORMATIONAL: { c: '#1565c0', bg: '#1565c018', label: 'INFO' },
  CLEAN:         { c: '#17AB1F', bg: '#17AB1F18', label: 'CLEAN' },
};

// Inject fonts + global styles
const _style = document.createElement('style');
_style.textContent = `
  @import url('https://fonts.googleapis.com/css2?family=Geologica:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans:wght@300;400;500;600;700&display=swap');
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  html, body, #root { height: 100%; }
  body { background: linear-gradient(100deg, #070D19 0%, #08101D 100%); background-attachment: fixed; color: ${T.t1}; font-family: ${T.font}; font-size: 13px; -webkit-font-smoothing: antialiased; }
  ::-webkit-scrollbar { width: 4px; height: 4px; }
  ::-webkit-scrollbar-track { background: ${T.bg0}; }
  ::-webkit-scrollbar-thumb { background: ${T.b2}; border-radius: 4px; }
  button { cursor: pointer; border: none; background: none; font-family: inherit; color: inherit; }
  input, textarea, select { font-family: inherit; }
  @keyframes fadeIn { from { opacity:0; transform: translateY(4px); } to { opacity:1; transform:none; } }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.35} }
  @keyframes spin { to { transform: rotate(360deg); } }
  @keyframes countUp { from { opacity:0; transform:translateY(8px); } to { opacity:1; transform:none; } }
  .fade { animation: fadeIn .2s ease; }
  .number { font-variant-numeric: tabular-nums; font-feature-settings: 'tnum'; }
`;
document.head.appendChild(_style);

// ─── LEVEL META — maps to ThemeDark.ts palette.severity exactly ──────────────
const LEVELS = {
  CRITICAL:      { c: '#EE3838', bg: '#EE383818', label: 'CRITICAL' },
  HIGH:          { c: '#E6700F', bg: '#E6700F18', label: 'HIGH' },
  MEDIUM:        { c: '#E1B823', bg: '#E1B82318', label: 'MEDIUM' },
  LOW:           { c: '#16AD34', bg: '#16AD3418', label: 'LOW' },
  INFORMATIONAL: { c: '#1565c0', bg: '#1565c018', label: 'INFO' },
};

// ─── SMALL HELPERS ────────────────────────────────────────────────────────────
const Tag = ({ children, color = T.primary, small }) => (
  <span style={{
    background: `${color}18`, border: `1px solid ${color}44`,
    color, padding: small ? '1px 6px' : '2px 8px',
    borderRadius: '3px', fontSize: small ? '10px' : '11px',
    fontFamily: T.mono, fontWeight: 500, letterSpacing: '0.04em',
    display: 'inline-block', whiteSpace: 'nowrap',
  }}>{children}</span>
);

const ThreatBadge = ({ level, small }) => {
  const m = LEVELS[level] || LEVELS.INFORMATIONAL;
  return <Tag color={m.c} small={small}>{m.label}</Tag>;
};

const SectionTitle = ({ children, action }) => (
  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center',
    marginBottom: '10px' }}>
    <div style={{ fontSize: '11px', fontWeight: 600, color: T.t3,
      letterSpacing: '0.1em', textTransform: 'uppercase' }}>{children}</div>
    {action}
  </div>
);

const Card = ({ children, style, noPad }) => (
  <div style={{ background: T.bg2, border: `1px solid ${T.b1}`, borderRadius: '4px',
    padding: noPad ? 0 : '14px', ...style }}>
    {children}
  </div>
);

// ─── STAT CARD (OpenCTI top row style) ────────────────────────────────────────
function StatCard({ icon: Icon, label, value, delta, color = T.primary, sub }) {
  return (
    <Card style={{ flex: 1, minWidth: '120px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <div style={{ fontSize: '10px', fontWeight: 600, color: T.t3,
            letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: '6px' }}>
            {label}
          </div>
          <div className="number" style={{ fontSize: '28px', fontWeight: 700,
            color: T.t1, lineHeight: 1, letterSpacing: '-0.02em' }}>
            {value ?? '—'}
          </div>
          {delta !== undefined && (
            <div style={{ marginTop: '5px', display: 'flex', alignItems: 'center', gap: '4px' }}>
              <TrendingUp size={10} color={color} />
              <span style={{ fontSize: '11px', color, fontWeight: 500 }}>
                +{delta} <span style={{ color: T.t3, fontWeight: 400 }}>(24h)</span>
              </span>
            </div>
          )}
          {sub && <div style={{ fontSize: '11px', color: T.t3, marginTop: '4px' }}>{sub}</div>}
        </div>
        <div style={{ width: '32px', height: '32px', borderRadius: '6px',
          background: `${color}18`, border: `1px solid ${color}33`,
          display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <Icon size={15} color={color} />
        </div>
      </div>
    </Card>
  );
}

// ─── VERDICT ICON ─────────────────────────────────────────────────────────────
const VIcon = ({ verdict, size = 13 }) => {
  const cfg = { MALICIOUS: [XCircle, T.critical], SUSPICIOUS: [AlertTriangle, T.medium],
    CLEAN: [CheckCircle, T.clean], UNKNOWN: [Info, T.info] };
  const [I, c] = cfg[verdict] || cfg.UNKNOWN;
  return <I size={size} color={c} />;
};

// ─── IOC ROW ──────────────────────────────────────────────────────────────────
const IOCRow = ({ ioc, verdict, reason, type }) => (
  <div style={{ display: 'flex', alignItems: 'flex-start', gap: '10px',
    padding: '8px 0', borderBottom: `1px solid ${T.b1}` }}>
    <VIcon verdict={verdict} />
    <div style={{ flex: 1, minWidth: 0 }}>
      <div style={{ fontFamily: T.mono, fontSize: '11px', color: T.t1,
        wordBreak: 'break-all', lineHeight: 1.5 }}>{ioc}</div>
      {reason && <div style={{ fontSize: '11px', color: T.t3, marginTop: '2px' }}>{reason}</div>}
    </div>
    <div style={{ display: 'flex', gap: '6px', flexShrink: 0 }}>
      <Tag color={T.t3} small>{type}</Tag>
      <Tag color={verdict === 'MALICIOUS' ? T.critical : verdict === 'SUSPICIOUS' ? T.medium : T.clean} small>
        {verdict}
      </Tag>
    </div>
  </div>
);

// ─── ENRICHMENT ACCORDION ─────────────────────────────────────────────────────
const EnrichAccordion = ({ label, data }) => {
  const [open, setOpen] = useState(false);
  if (!data || typeof data !== 'object') return null;
  const entries = Object.entries(data).filter(([k, v]) =>
    k !== 'cached' && v != null && v !== '' && !(Array.isArray(v) && !v.length));
  if (!entries.length) return null;
  return (
    <div style={{ marginBottom: '3px' }}>
      <button onClick={() => setOpen(o => !o)} style={{
        width: '100%', display: 'flex', justifyContent: 'space-between',
        alignItems: 'center', background: T.bg3, border: `1px solid ${T.b1}`,
        borderRadius: '3px', padding: '6px 10px', fontSize: '11px', color: T.t2,
      }}>
        <span style={{ fontFamily: T.mono, color: T.primary, fontSize: '10px',
          letterSpacing: '0.06em' }}>{label.toUpperCase()}</span>
        {open ? <ChevronUp size={11} /> : <ChevronDown size={11} />}
      </button>
      {open && (
        <div style={{ background: T.bg2, border: `1px solid ${T.b1}`, borderTop: 'none',
          borderRadius: '0 0 3px 3px', padding: '8px 10px' }}>
          {entries.slice(0, 12).map(([k, v]) => (
            <div key={k} style={{ display: 'flex', justifyContent: 'space-between',
              gap: '10px', fontSize: '11px', padding: '2px 0',
              borderBottom: `1px solid ${T.b1}` }}>
              <span style={{ color: T.t3, minWidth: '80px', flexShrink: 0 }}>{k}</span>
              <span style={{ color: T.t1, fontFamily: T.mono, fontSize: '10px',
                textAlign: 'right', wordBreak: 'break-all' }}>
                {Array.isArray(v) ? v.slice(0, 4).join(', ') : String(v).substring(0, 150)}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

// ─── ANALYZE TAB ──────────────────────────────────────────────────────────────
function AnalyzeTab({ onResult, result }) {
  const [log, setLog]       = useState('');
  const [label, setLabel]   = useState('');
  const [drag, setDrag]     = useState(false);
  const [subTab, setSubTab] = useState('assessment');

  const handleFile = useCallback(f => {
    if (!f) return;
    const r = new FileReader();
    r.onload = e => setLog(e.target.result);
    r.readAsText(f);
  }, []);

  const analysis = result?.response_summary || result?.investigation;
  const lm = analysis ? (LEVELS[analysis.threat_level || analysis.threatLevel] || LEVELS.INFORMATIONAL) : null;
  const totalIocs = result?.iocs ? Object.values(result.iocs).flat().length : 0;

  return (
    <div style={{ display: 'grid', gridTemplateColumns: result ? '360px 1fr' : '520px',
      gap: '16px', alignItems: 'start', justifyContent: result ? undefined : 'center' }}>

      {/* Input panel */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
        {/* Drop zone */}
        <div onDragOver={e => { e.preventDefault(); setDrag(true); }}
          onDragLeave={() => setDrag(false)}
          onDrop={e => { e.preventDefault(); setDrag(false); handleFile(e.dataTransfer.files[0]); }}
          onClick={() => document.getElementById('fi').click()}
          style={{ background: drag ? `${T.primary}10` : T.bg2,
            border: `1px dashed ${drag ? T.primary : T.b2}`,
            borderRadius: '4px', padding: '16px', textAlign: 'center',
            cursor: 'pointer', transition: 'all .15s' }}>
          <Upload size={18} color={drag ? T.primary : T.t3} style={{ margin: '0 auto 6px', display: 'block' }} />
          <div style={{ fontSize: '12px', color: T.t2 }}>Drop log file or click to browse</div>
          <div style={{ fontSize: '10px', color: T.t3, marginTop: '2px' }}>.log .txt .csv .json</div>
          <input id="fi" type="file" accept=".log,.txt,.csv,.json" style={{ display: 'none' }}
            onChange={e => handleFile(e.target.files[0])} />
        </div>

        <textarea value={log} onChange={e => setLog(e.target.value)}
          placeholder={"Paste log content, alert text, or raw IOCs...\n\nExtracts: IPs · Domains · Hashes · URLs · Emails"}
          style={{ background: T.bg2, border: `1px solid ${T.b1}`, borderRadius: '4px',
            padding: '12px', color: T.t1, fontFamily: T.mono, fontSize: '11px',
            lineHeight: 1.7, resize: 'vertical', outline: 'none', height: '160px' }} />

        <input value={label} onChange={e => setLabel(e.target.value)}
          placeholder="Case label — INC-2024-001 (optional)"
          style={{ background: T.bg2, border: `1px solid ${T.b1}`, borderRadius: '4px',
            padding: '9px 12px', color: T.t1, fontSize: '12px', outline: 'none', width: '100%' }} />

        <AgentPipeline logText={log} label={label} onComplete={onResult} />

        {/* IOC summary */}
        {result?.iocs && totalIocs > 0 && (
          <Card>
            <SectionTitle>Extracted IOCs ({totalIocs})</SectionTitle>
            {Object.entries(result.iocs).map(([type, list]) => !list?.length ? null : (
              <div key={type} style={{ marginBottom: '8px' }}>
                <div style={{ fontSize: '10px', color: T.t3, fontFamily: T.mono,
                  textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: '4px' }}>
                  {type} ({list.length})
                </div>
                {list.map(ioc => (
                  <div key={ioc} style={{ fontSize: '10px', color: T.t2, fontFamily: T.mono,
                    padding: '1px 0', wordBreak: 'break-all' }}>{ioc}</div>
                ))}
              </div>
            ))}
          </Card>
        )}
      </div>

      {/* Results panel */}
      {result && analysis && (
        <div className="fade" style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
          {/* Threat level banner */}
          <div style={{ background: lm.bg, border: `1px solid ${lm.c}44`,
            borderRadius: '4px', borderLeft: `3px solid ${lm.c}`, padding: '14px 16px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
              <span style={{ fontSize: '10px', fontWeight: 600, color: T.t3,
                letterSpacing: '0.1em', textTransform: 'uppercase' }}>Threat Assessment</span>
              <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                {analysis.confidence !== undefined && (
                  <span style={{ fontSize: '11px', color: T.t3 }}>
                    confidence <span style={{ color: lm.c, fontWeight: 600 }}>
                      {(analysis.confidence * 100).toFixed(0)}%
                    </span>
                  </span>
                )}
                <ThreatBadge level={analysis.threat_level || analysis.threatLevel} />
              </div>
            </div>
            <p style={{ fontSize: '12px', color: T.t1, lineHeight: 1.65 }}>{analysis.summary}</p>
          </div>

          {/* Sub tabs */}
          <div style={{ display: 'flex', gap: '2px', background: T.bg0,
            padding: '3px', borderRadius: '4px', border: `1px solid ${T.b1}` }}>
            {[['assessment','Assessment'], ['iocs','IOC Verdicts'], ['enrichments','Enrichments']].map(([id,lbl]) => (
              <button key={id} onClick={() => setSubTab(id)} style={{
                flex: 1, padding: '6px', borderRadius: '3px', fontSize: '11px',
                background: subTab === id ? T.bg3 : 'none',
                color: subTab === id ? T.t1 : T.t3,
                border: subTab === id ? `1px solid ${T.b2}` : '1px solid transparent',
                fontWeight: subTab === id ? 500 : 400, transition: 'all .12s',
              }}>{lbl}</button>
            ))}
          </div>

          <div style={{ maxHeight: '62vh', overflowY: 'auto',
            display: 'flex', flexDirection: 'column', gap: '10px' }}>
            {subTab === 'assessment' && <>
              {/* Chain of thought */}
              {analysis.chain_of_thought?.length > 0 && (
                <Card>
                  <SectionTitle>Investigation Reasoning</SectionTitle>
                  {analysis.chain_of_thought.map((s, i) => (
                    <div key={i} style={{ display: 'flex', gap: '10px', padding: '6px 0',
                      borderBottom: `1px solid ${T.b1}`, fontSize: '12px', color: T.t2 }}>
                      <span style={{ color: T.primary, fontFamily: T.mono, fontSize: '10px', flexShrink: 0 }}>
                        {String(i+1).padStart(2,'0')}
                      </span>{s}
                    </div>
                  ))}
                </Card>
              )}
              {/* Key findings */}
              {analysis.key_findings?.length > 0 && (
                <Card>
                  <SectionTitle>Key Findings</SectionTitle>
                  {analysis.key_findings.map((f, i) => (
                    <div key={i} style={{ display: 'flex', gap: '8px', padding: '6px 0',
                      borderBottom: `1px solid ${T.b1}`, fontSize: '12px', color: T.t2 }}>
                      <ChevronRight size={12} color={T.primary} style={{ flexShrink: 0, marginTop: '2px' }} />
                      {f}
                    </div>
                  ))}
                </Card>
              )}
              {/* MITRE */}
              {analysis.mitre_techniques?.length > 0 && (
                <Card>
                  <SectionTitle>MITRE ATT&CK</SectionTitle>
                  <div style={{ display: 'flex', gap: '5px', flexWrap: 'wrap' }}>
                    {analysis.mitre_techniques.map((t, i) => <Tag key={i}>{t}</Tag>)}
                  </div>
                </Card>
              )}
              {/* Threat actors */}
              {analysis.matched_actors?.length > 0 && (
                <Card>
                  <SectionTitle>Attribution</SectionTitle>
                  {analysis.matched_actors.slice(0, 4).map(a => (
                    <div key={a.name} style={{ display: 'flex', justifyContent: 'space-between',
                      alignItems: 'center', padding: '7px 0', borderBottom: `1px solid ${T.b1}` }}>
                      <div>
                        <div style={{ fontSize: '12px', fontWeight: 500, color: T.t1 }}>{a.name}</div>
                        <div style={{ fontSize: '10px', color: T.t3 }}>{a.origin} · {a.sponsor}</div>
                      </div>
                      <Tag color={T.high} small>{a.score}% match</Tag>
                    </div>
                  ))}
                </Card>
              )}
              {/* Recommended actions */}
              {analysis.recommended_actions?.length > 0 && (
                <Card>
                  <SectionTitle>Recommended Actions</SectionTitle>
                  {analysis.recommended_actions.map((a, i) => (
                    <div key={i} style={{ display: 'flex', gap: '10px', padding: '6px 0',
                      borderBottom: `1px solid ${T.b1}`, fontSize: '12px', color: T.t2 }}>
                      <span style={{ color: T.secondary, fontFamily: T.mono, fontSize: '10px', flexShrink: 0 }}>
                        {String(i+1).padStart(2,'0')}
                      </span>{a}
                    </div>
                  ))}
                </Card>
              )}
            </>}

            {subTab === 'iocs' && (
              <Card>
                <SectionTitle>IOC Verdicts ({analysis.ioc_assessments?.length || 0})</SectionTitle>
                {(analysis.ioc_assessments || []).map((a, i) => <IOCRow key={i} {...a} />)}
              </Card>
            )}

            {subTab === 'enrichments' && result.enrichments && (
              Object.entries(result.enrichments).map(([iocType, iocMap]) =>
                Object.entries(iocMap || {}).map(([ioc, data]) => (
                  <Card key={ioc}>
                    <div style={{ fontFamily: T.mono, fontSize: '11px', color: T.primary,
                      wordBreak: 'break-all', marginBottom: '8px', fontWeight: 500 }}>
                      {iocType === 'ips' ? '◎' : iocType === 'domains' ? '◉' : iocType === 'hashes' ? '◈' : '◆'} {ioc}
                    </div>
                    {Object.entries(data).filter(([k]) => k !== 'cached')
                      .map(([src, d]) => <EnrichAccordion key={src} label={src} data={d} />)}
                  </Card>
                ))
              )
            )}
          </div>
        </div>
      )}
    </div>
  );
}

// ─── SETUP SCREEN ─────────────────────────────────────────────────────────────
const SetupScreen = ({ onGo }) => (
  <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center',
    justifyContent: 'center', height: '60vh', gap: '20px', textAlign: 'center' }}>
    <div style={{ width: '60px', height: '60px', borderRadius: '12px',
      background: `${T.primary}18`, border: `1px solid ${T.primary}44`,
      display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <Shield size={24} color={T.primary} />
    </div>
    <div>
      <div style={{ fontSize: '22px', fontWeight: 700, color: T.t1, marginBottom: '6px' }}>
        Threat Intelligence Platform
      </div>
      <div style={{ fontSize: '13px', color: T.t3 }}>Configure your API keys to begin.</div>
    </div>
    <button onClick={onGo} style={{ background: `${T.primary}18`, border: `1px solid ${T.primary}55`,
      color: T.primary, padding: '10px 24px', borderRadius: '4px', fontSize: '13px',
      fontWeight: 500, display: 'flex', alignItems: 'center', gap: '7px' }}>
      <Settings size={14} /> Open Settings
    </button>
  </div>
);

// ─── SIDEBAR NAV ITEMS ────────────────────────────────────────────────────────
const NAV = [
  { id: 'dashboard', icon: BarChart2,  tip: 'Dashboard' },
  { id: 'analyze',   icon: Search,     tip: 'Analyze' },
  { id: 'gti',       icon: Activity,   tip: 'GTI Score' },
  { id: 'detection', icon: Target,     tip: 'Detection' },
  { id: 'map',       icon: Globe,      tip: 'Geo Map' },
  { id: 'pivot',     icon: Share2,     tip: 'Pivot Graph' },
  { id: 'report',    icon: FileText,   tip: 'Report' },
  { id: 'tools',     icon: Wrench,     tip: 'Tools' },
];
const NAV_BOTTOM = [
  { id: 'history',  icon: Clock,    tip: 'History' },
  { id: 'settings', icon: Settings, tip: 'Settings' },
];

// ─── MINI DASHBOARD ───────────────────────────────────────────────────────────
function Dashboard({ result, history, onNavigate }) {
  const totalRuns    = history.length;
  const criticalRuns = history.filter(h => h.threatLevel === 'CRITICAL').length;
  const highRuns     = history.filter(h => h.threatLevel === 'HIGH').length;
  const totalIocs    = history.reduce((acc, h) => acc + (h.iocCount || 0), 0);

  const recentMitre = result?.mitre_techniques?.slice(0, 8) || [];
  const actors      = result?.response_summary?.matched_actors?.slice(0, 5) || [];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
      {/* Stat row */}
      <div style={{ display: 'flex', gap: '10px' }}>
        <StatCard icon={Eye}      label="Analyses"  value={totalRuns}    color={T.primary} delta={Math.min(totalRuns,3)} />
        <StatCard icon={AlertTriangle} label="Critical"  value={criticalRuns} color={T.critical} />
        <StatCard icon={Zap}      label="High Risk" value={highRuns}     color={T.high} />
        <StatCard icon={Hash}     label="IOCs Seen" value={totalIocs}    color={T.blue} />
        <StatCard icon={Radio}    label="Feeds"     value={3}            sub="MITRE · CISA · Anomali" color={T.green} />
        <StatCard icon={Database} label="Cached"    value="24h"          sub="enrichment TTL" color={T.purple} />
      </div>

      {/* Recent history + MITRE coverage */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '10px' }}>
        {/* Recent investigations */}
        <Card style={{ gridColumn: 'span 1' }}>
          <SectionTitle action={
            <button onClick={() => onNavigate('analyze')} style={{ fontSize: '10px', color: T.primary }}>
              New analysis →
            </button>
          }>Recent Investigations</SectionTitle>
          {history.length === 0 && (
            <div style={{ fontSize: '12px', color: T.t3, padding: '12px 0' }}>
              No analyses yet. Run something.
            </div>
          )}
          {[...history].reverse().slice(0, 8).map((h, i) => {
            const lm = LEVELS[h.threatLevel] || LEVELS.INFORMATIONAL;
            return (
              <div key={h.runId || i} style={{ display: 'flex', justifyContent: 'space-between',
                alignItems: 'center', padding: '7px 0', borderBottom: `1px solid ${T.b1}`,
                cursor: 'pointer' }}>
                <div style={{ minWidth: 0, flex: 1 }}>
                  <div style={{ fontSize: '12px', color: T.t1, overflow: 'hidden',
                    textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {h.label || 'Untitled'}
                  </div>
                  <div style={{ fontSize: '10px', color: T.t3, marginTop: '1px' }}>
                    {h.iocCount} IOCs · {new Date(h.timestamp).toLocaleTimeString()}
                  </div>
                </div>
                <Tag color={lm.c} small>{lm.label}</Tag>
              </div>
            );
          })}
        </Card>

        {/* MITRE techniques from last analysis */}
        <Card>
          <SectionTitle>Active TTPs</SectionTitle>
          {recentMitre.length === 0 && (
            <div style={{ fontSize: '12px', color: T.t3, padding: '12px 0' }}>
              Run an analysis to see technique coverage.
            </div>
          )}
          {recentMitre.map((t, i) => {
            const parts = t.split(' - ');
            return (
              <div key={i} style={{ display: 'flex', justifyContent: 'space-between',
                alignItems: 'center', padding: '6px 0', borderBottom: `1px solid ${T.b1}` }}>
                <div>
                  <div style={{ fontSize: '11px', fontFamily: T.mono, color: T.primary }}>{parts[0]}</div>
                  <div style={{ fontSize: '11px', color: T.t2 }}>{parts[1] || ''}</div>
                </div>
                <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: T.primary, flexShrink: 0 }} />
              </div>
            );
          })}
          {recentMitre.length === 0 && (
            <>
              {['T1566 - Phishing','T1059.001 - PowerShell','T1003.001 - LSASS Memory'].map((t,i) => (
                <div key={i} style={{ display: 'flex', justifyContent: 'space-between',
                  padding: '6px 0', borderBottom: `1px solid ${T.b1}`, opacity: 0.3 }}>
                  <span style={{ fontFamily: T.mono, fontSize: '10px', color: T.t3 }}>{t}</span>
                </div>
              ))}
            </>
          )}
        </Card>

        {/* Attribution */}
        <Card>
          <SectionTitle>Threat Actors</SectionTitle>
          {actors.length === 0 && (
            <div style={{ fontSize: '12px', color: T.t3, padding: '12px 0' }}>
              Attribution appears after analysis.
            </div>
          )}
          {actors.map(a => (
            <div key={a.name} style={{ padding: '7px 0', borderBottom: `1px solid ${T.b1}` }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
                <span style={{ fontSize: '12px', fontWeight: 500, color: T.t1 }}>{a.name}</span>
                <Tag color={T.warn} small>{a.score}%</Tag>
              </div>
              <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
                {(a.matchedTechniques || []).slice(0, 4).map(t => (
                  <Tag key={t} color={T.t3} small>{t}</Tag>
                ))}
              </div>
              {/* Mini score bar */}
              <div style={{ marginTop: '5px', height: '3px', background: T.b1, borderRadius: '99px', overflow: 'hidden' }}>
                <div style={{ width: `${a.score}%`, height: '100%', background: T.primary, borderRadius: '99px' }} />
              </div>
            </div>
          ))}
          {/* Placeholder actors when empty */}
          {actors.length === 0 && (
            ['APT29 (Cozy Bear)', 'Lazarus Group', 'FIN7'].map(name => (
              <div key={name} style={{ padding: '7px 0', borderBottom: `1px solid ${T.b1}`, opacity: 0.25 }}>
                <span style={{ fontSize: '12px', color: T.t3 }}>{name}</span>
              </div>
            ))
          )}
        </Card>
      </div>

      {/* IOC type breakdown */}
      {result?.iocs && (
        <Card>
          <SectionTitle>IOC Breakdown — Last Analysis</SectionTitle>
          <div style={{ display: 'flex', gap: '10px' }}>
            {Object.entries(result.iocs).filter(([,v]) => v?.length > 0).map(([type, list]) => {
              const colors = { ips: T.high, domains: T.secondary, hashes: '#B286FF', urls: T.primary, emails: '#F2BE3A' };
              const c = colors[type] || T.t3;
              return (
                <div key={type} style={{ flex: 1, background: `${c}10`,
                  border: `1px solid ${c}33`, borderRadius: '4px', padding: '10px 12px' }}>
                  <div style={{ fontSize: '20px', fontWeight: 700, color: c,
                    fontVariantNumeric: 'tabular-nums' }}>{list.length}</div>
                  <div style={{ fontSize: '10px', color: T.t3, textTransform: 'uppercase',
                    letterSpacing: '0.08em', marginTop: '2px' }}>{type}</div>
                </div>
              );
            })}
          </div>
        </Card>
      )}
    </div>
  );
}

// ─── HISTORY SIDE PANEL ───────────────────────────────────────────────────────
function HistorySidePanel({ history, currentRunId, onSelect, onClose }) {
  return (
    <div style={{ width: '280px', height: '100%', background: T.bg0,
      borderRight: `1px solid ${T.b1}`, display: 'flex', flexDirection: 'column' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center',
        padding: '12px 14px', borderBottom: `1px solid ${T.b1}` }}>
        <span style={{ fontSize: '11px', fontWeight: 600, color: T.t3,
          letterSpacing: '0.1em', textTransform: 'uppercase' }}>Investigation History</span>
        <button onClick={onClose} style={{ color: T.t3, fontSize: '16px' }}>×</button>
      </div>
      <div style={{ flex: 1, overflowY: 'auto', padding: '8px' }}>
        <HistoryPanel onSelect={onSelect} currentRunId={currentRunId} />
      </div>
    </div>
  );
}

// ─── MAIN APP ─────────────────────────────────────────────────────────────────
export default function App() {
  const [tab, setTab]           = useState('dashboard');
  const [result, setResult]     = useState(null);
  const [configured, setCfg]    = useState(null);
  const [aiProvider, setAiProv] = useState('');
  const [showHistory, setShowH] = useState(false);
  const [searchVal, setSearch]  = useState('');
  const [history, setHistory]   = useState([]);
  const [tooltip, setTooltip]   = useState(null);

  useEffect(() => {
    fetch('/api/health')
      .then(r => r.json())
      .then(d => { setCfg(d.configured); setAiProv(d.ai_provider || ''); })
      .catch(() => setCfg(false));
    fetch('/api/history')
      .then(r => r.json())
      .then(d => setHistory(d.history || []))
      .catch(() => {});
  }, [result]);

  const handleResult = (data) => {
    setResult(data);
    setHistory(h => [{ runId: data.runId, label: data.label || 'Untitled',
      timestamp: data.timestamp || new Date().toISOString(),
      threatLevel: data.threat_level || 'UNKNOWN', iocCount: Object.values(data.iocs || {}).flat().length,
    }, ...h].slice(0, 25));
  };

  // Sidebar nav item
  const NavItem = ({ id, icon: Icon, tip, bottom }) => {
    const active = tab === id;
    const hasDot = ['gti','pivot','report','map','detection'].includes(id) && result;
    return (
      <div style={{ position: 'relative' }}
        onMouseEnter={() => setTooltip(id)} onMouseLeave={() => setTooltip(null)}>
        <button onClick={() => setTab(id)} style={{
          width: '44px', height: '44px', borderRadius: '6px', margin: '2px auto',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          background: active ? `${T.primary}18` : 'none',
          border: active ? `1px solid ${T.primary}44` : '1px solid transparent',
          color: active ? T.primary : T.t3,
          transition: 'all .12s', position: 'relative',
        }}>
          <Icon size={17} />
          {hasDot && (
            <div style={{ position: 'absolute', top: '7px', right: '7px',
              width: '6px', height: '6px', borderRadius: '50%',
              background: T.green, border: `1px solid ${T.bg0}` }} />
          )}
        </button>
        {tooltip === id && (
          <div style={{ position: 'absolute', left: '52px', top: '50%', transform: 'translateY(-50%)',
            background: T.bg3, border: `1px solid ${T.b2}`, borderRadius: '4px',
            padding: '4px 10px', fontSize: '11px', color: T.t1, whiteSpace: 'nowrap',
            zIndex: 1000, pointerEvents: 'none',
            boxShadow: '0 4px 12px rgba(0,0,0,0.4)' }}>
            {tip}
          </div>
        )}
      </div>
    );
  };

  return (
    <div style={{ display: 'flex', height: '100vh', background: T.bg1, overflow: 'hidden' }}>
      {/* ── Left sidebar ── */}
      <div style={{ width: '52px', background: T.bg0, borderRight: `1px solid ${T.b1}`,
        display: 'flex', flexDirection: 'column', alignItems: 'center',
        padding: '8px 0', flexShrink: 0, zIndex: 50 }}>
        {/* Logo */}
        <div style={{ width: '32px', height: '32px', borderRadius: '7px',
          background: `${T.primary}20`, border: `1px solid ${T.primary}44`,
          display: 'flex', alignItems: 'center', justifyContent: 'center', marginBottom: '12px' }}>
          <Shield size={16} color={T.primary} />
        </div>

        {/* Top nav items */}
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', width: '100%', padding: '0 4px' }}>
          {NAV.map(n => <NavItem key={n.id} {...n} />)}
        </div>

        {/* Bottom nav */}
        <div style={{ display: 'flex', flexDirection: 'column', width: '100%', padding: '0 4px', gap: '2px' }}>
          {/* History toggle */}
          <div style={{ position: 'relative' }}
            onMouseEnter={() => setTooltip('histToggle')} onMouseLeave={() => setTooltip(null)}>
            <button onClick={() => setShowH(h => !h)} style={{
              width: '44px', height: '44px', borderRadius: '6px', margin: '0 auto',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              background: showHistory ? `${T.primary}18` : 'none',
              border: showHistory ? `1px solid ${T.primary}44` : '1px solid transparent',
              color: showHistory ? T.primary : T.t3, transition: 'all .12s',
            }}>
              <Clock size={17} />
            </button>
            {tooltip === 'histToggle' && (
              <div style={{ position: 'absolute', left: '52px', top: '50%', transform: 'translateY(-50%)',
                background: T.bg3, border: `1px solid ${T.b2}`, borderRadius: '4px',
                padding: '4px 10px', fontSize: '11px', color: T.t1, whiteSpace: 'nowrap', zIndex: 1000 }}>
                History
              </div>
            )}
          </div>
          <NavItem id="settings" icon={Settings} tip="Settings" />
        </div>
      </div>

      {/* ── History panel (slides in) ── */}
      {showHistory && (
        <HistorySidePanel
          history={history}
          currentRunId={result?.runId}
          onSelect={data => { setResult(data); setTab('analyze'); setShowH(false); }}
          onClose={() => setShowH(false)}
        />
      )}

      {/* ── Main area ── */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0 }}>
        {/* Top bar */}
        <div style={{ height: '46px', background: T.bg0, borderBottom: `1px solid ${T.b1}`,
          display: 'flex', alignItems: 'center', gap: '10px',
          padding: '0 16px', flexShrink: 0 }}>
          {/* Search */}
          <div style={{ flex: 1, maxWidth: '420px', position: 'relative' }}>
            <Search size={13} color={T.t3} style={{ position: 'absolute', left: '10px',
              top: '50%', transform: 'translateY(-50%)', pointerEvents: 'none' }} />
            <input value={searchVal} onChange={e => setSearch(e.target.value)}
              placeholder="Search the platform..."
              style={{ width: '100%', background: T.bg2, border: `1px solid ${T.b1}`,
                borderRadius: '4px', padding: '7px 12px 7px 32px',
                color: T.t1, fontSize: '12px', outline: 'none' }} />
          </div>

          <div style={{ flex: 1 }} />

          {/* Status indicators */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', fontSize: '11px' }}>
            {aiProvider && (
              <Tag color={aiProvider === 'azure' ? T.primary : T.t3} small>
                {aiProvider === 'azure' ? '⟁ Azure OpenAI' : '◎ OpenAI'}
              </Tag>
            )}
            <div style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
              <div style={{ width: '7px', height: '7px', borderRadius: '50%',
                background: configured ? T.secondary : T.medium,
                animation: configured ? 'none' : 'pulse 2s infinite' }} />
              <span style={{ color: configured ? T.secondary : T.medium, fontWeight: 500 }}>
                {configured ? 'Ready' : 'Setup required'}
              </span>
            </div>

            <button style={{ color: T.t3, display: 'flex', alignItems: 'center', gap: '4px', fontSize: '11px' }}>
              <Bell size={13} />
            </button>
            <button style={{ color: T.t3, display: 'flex', alignItems: 'center', gap: '4px', fontSize: '11px' }}
              onClick={() => window.location.reload()}>
              <RefreshCw size={13} />
            </button>
            <button style={{ color: T.t3, display: 'flex', alignItems: 'center', gap: '4px', fontSize: '11px' }}>
              <Cpu size={13} />
            </button>
          </div>
        </div>

        {/* Content */}
        <div style={{ flex: 1, overflowY: 'auto', padding: '16px 20px' }}>
          {tab === 'analyze' && configured === false && (
            <SetupScreen onGo={() => setTab('settings')} />
          )}

          {(tab !== 'analyze' || configured !== false) && (
            <div className="fade">
              {tab === 'dashboard'  && <Dashboard result={result} history={history} onNavigate={setTab} />}
              {tab === 'analyze'   && <AnalyzeTab onResult={handleResult} result={result} />}
              {tab === 'gti'       && <GTIScorePanel result={result} />}
              {tab === 'detection' && <DetectionTab analysisResult={result} />}
              {tab === 'map'       && <MapTab result={result} />}
              {tab === 'pivot'     && <PivotGraph result={result} />}
              {tab === 'report'    && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                  <ReportView result={result} />
                  {result && <ExportBar result={result} />}
                </div>
              )}
              {tab === 'tools'     && <ToolsTab />}
              {tab === 'settings'  && <SettingsPage onConfigured={() => { setCfg(true); setTab('dashboard'); }} />}
            </div>
          )}
        </div>

        {/* Status bar */}
        <div style={{ height: '24px', background: T.bg0, borderTop: `1px solid ${T.b1}`,
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          padding: '0 16px', fontSize: '10px', color: T.t4, flexShrink: 0 }}>
          <span>ThreatIntel Platform v3.0 · {history.length} investigations this session</span>
          <span style={{ fontFamily: T.mono }}>
            {result
              ? `Last: ${new Date(result.timestamp || Date.now()).toLocaleTimeString()}`
              : 'No analysis loaded'}
          </span>
        </div>
      </div>
    </div>
  );
}
