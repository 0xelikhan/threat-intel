import React, { useState, useCallback, useRef, useEffect } from 'react';
import {
  Upload, ChevronDown, ChevronRight, Copy, Check, Printer, Search,
  Activity, Database, Layers, Zap, Globe, Network, Shield, FileText,
  ArrowUpRight, AlertCircle, X, FileSearch,
} from 'lucide-react';

import MapTab        from './components/MapTab';
import PivotGraph    from './components/PivotGraph';
import ExportBar     from './components/ExportBar';
import AgentPipeline from './components/AgentPipeline';

// MUI-based primitives (adapted from OpenCTI's Tag.tsx + theme) — every chip,
// card, code-block, copy button now renders through MUI components that inherit
// the OpenCTI styling overrides defined in theme.js.
import {
  Box, Typography, Stack,
  Paper          as MuiPaper,
  Drawer         as MuiDrawer,
  IconButton     as MuiIconButton,
  Tabs           as MuiTabs,
  Tab            as MuiTab,
  Button         as MuiButton,
  TextField      as MuiTextField,
  Table          as MuiTable,
  TableHead      as MuiTableHead,
  TableBody      as MuiTableBody,
  TableRow       as MuiTableRow,
  TableCell      as MuiTableCell,
  TableContainer as MuiTableContainer,
} from '@mui/material';
import { alpha as muiAlpha } from '@mui/material/styles';
import {
  Tag        as MuiTag,
  VerdictTag as MuiVerdictTag,
  TypeTag    as MuiTypeTag,
  Card       as MuiCard,
  Block      as MuiBlock,
  CodeBlock  as MuiCodeBlock,
  CopyBtn    as MuiCopyBtn,
} from './components/ui';

/* ─── design tokens ─────────────────────────────────────────────────────────── */
const t = {
  // surfaces
  bg:        '#0a0e16',
  surface:   '#10141f',
  raised:    '#161b29',
  sidebar:   '#080b13',
  hover:     'rgba(255,255,255,0.025)',

  // borders
  line:      'rgba(255,255,255,0.06)',
  lineHi:    'rgba(255,255,255,0.1)',
  lineStr:   'rgba(255,255,255,0.14)',

  // text
  fg:        '#e8eaed',
  fgMute:    '#9aa3b4',
  fgDim:     '#5b6478',
  fgGhost:   '#3a4153',

  // accent — cyan to match logo
  cy:        '#00b8d4',
  cyDim:     'rgba(0,184,212,0.1)',
  cyLine:    'rgba(0,184,212,0.3)',
  cyWash:    'rgba(0,184,212,0.04)',

  // semantic
  red:       '#ef4444',
  redDim:    'rgba(239,68,68,0.1)',
  red2:      'rgba(239,68,68,0.04)',
  orange:    '#f97316',
  orangeDim: 'rgba(249,115,22,0.1)',
  orange2:   'rgba(249,115,22,0.04)',
  yellow:    '#eab308',
  yellowDim: 'rgba(234,179,8,0.1)',
  yellow2:   'rgba(234,179,8,0.04)',
  green:     '#10b981',
  greenDim:  'rgba(16,185,129,0.1)',
  blue:      '#3b82f6',
  blueDim:   'rgba(59,130,246,0.1)',
  purple:    '#a855f7',
  purpleDim: 'rgba(168,85,247,0.1)',
};

const levelStyle = {
  CRITICAL:      { fg:t.red,    bg:t.red2,    line:t.redDim    },
  HIGH:          { fg:t.orange, bg:t.orange2, line:t.orangeDim },
  MEDIUM:        { fg:t.yellow, bg:t.yellow2, line:t.yellowDim },
  LOW:           { fg:t.blue,   bg:'rgba(59,130,246,0.04)', line:t.blueDim },
  INFORMATIONAL: { fg:t.fgMute, bg:t.bg,      line:t.line      },
};

const verdictStyle = {
  MALICIOUS:  t.red,
  SUSPICIOUS: t.orange,
  CLEAN:      t.green,
  BENIGN:     t.green,
  UNKNOWN:    t.fgDim,
  UNDETECTED: t.fgDim,
};

const iocTypeStyle = {
  ips:     { fg:'#60a5fa', label:'ip'     },
  domains: { fg:'#34d399', label:'domain' },
  hashes:  { fg:'#c084fc', label:'hash'   },
  urls:    { fg:'#fb923c', label:'url'    },
  emails:  { fg:'#f87171', label:'email'  },
};

/* ─── primitives ─────────────────────────────────────────────────────────────── */

const ChevButton = ({ open, onClick, label, count, accent=t.fg }) => (
  <button onClick={onClick} style={{
    width:'100%', background:'transparent', border:'none', cursor:'pointer',
    padding:'12px 18px', display:'flex', alignItems:'center', gap:8,
    color:t.fg, fontSize:13, fontWeight:500, textAlign:'left', borderRadius:0,
  }}>
    {open ? <ChevronDown size={14} color={t.fgMute}/> : <ChevronRight size={14} color={t.fgMute}/>}
    <span style={{ flex:1, color:accent, fontWeight:600 }}>{label}</span>
    {count != null && <span style={{ color:t.fgDim, fontSize:12, fontVariantNumeric:'tabular-nums' }}>{count}</span>}
  </button>
);

// Thin wrapper → MuiCard (renders via MUI Card + CardHeader, inherits OpenCTI theme)
function Card({ title, accent, children, defaultOpen=true, badge, noPad=false }) {
  return (
    <MuiCard title={title} accent={accent} badge={badge} defaultOpen={defaultOpen} noPad={noPad}>
      {children}
    </MuiCard>
  );
}

// Thin wrappers → MuiTag (renders via MUI Chip with alpha bg per OpenCTI's Tag.tsx)
function Chip({ children, color=t.fgMute, soft, mono, size='sm' }) {
  // mono prop preserved via sx override for code-style chips (rare)
  return (
    <MuiTag
      label={children}
      color={color}
      sx={mono ? { fontFamily: '"IBM Plex Mono", monospace' } : undefined}
    />
  );
}

const Verdict = ({ verdict, size }) =>
  <MuiVerdictTag verdict={verdict} size={size}/>;

const TypeTag = ({ type }) =>
  <MuiTypeTag type={type}/>;

// Thin wrapper → MuiCopyBtn (renders MUI IconButton with check-confirmation)
function CopyBtn({ text, label='Copy' }) {
  return <MuiCopyBtn text={text} label={label}/>;
}

/* ─── dial ─────────────────────────────────────────────────────────────────── */
function Dial({ score, color, size=80 }) {
  const cx=size/2, cy=size/2, r=size*0.38, sweep=240, sa=-210;
  const pt = a => ({ x:cx+r*Math.cos((a-90)*Math.PI/180), y:cy+r*Math.sin((a-90)*Math.PI/180) });
  const s=pt(sa), e=pt(sa+sweep), se=score>0?pt(sa+(score/100)*sweep):null;
  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} style={{ overflow:'visible', flexShrink:0 }}>
      <path d={`M${s.x} ${s.y}A${r} ${r} 0 1 1 ${e.x} ${e.y}`} fill="none" stroke={t.raised} strokeWidth={size*0.075} strokeLinecap="round"/>
      {se && <path d={`M${s.x} ${s.y}A${r} ${r} 0 ${(score/100)*sweep>180?1:0} 1 ${se.x} ${se.y}`}
        fill="none" stroke={color} strokeWidth={size*0.075} strokeLinecap="round"/>}
      <text x={cx} y={cy-1} textAnchor="middle" dominantBaseline="middle"
        fill={color} fontSize={size*0.27} fontWeight="700">{score}</text>
      <text x={cx} y={cy+size*0.18} textAnchor="middle" fill={t.fgGhost} fontSize={size*0.1}>/100</text>
    </svg>
  );
}

/* ─── pre-flight banner — shows triage findings INSTANTLY before AI runs ─────── */
function PreFlight({ result }) {
  if (!result) return null;
  // Hide the banner once the AI verdict has landed — full analysis takes over
  const hasVerdict = result?.response_summary?.threat_level
    && Object.keys(result?.response_summary?.analyst_summary || {}).length > 0;
  if (hasVerdict) return null;

  const iocs = result.iocs || {};
  const counts = Object.fromEntries(Object.entries(iocs).map(([k, v]) => [k, (v || []).length]));
  const totalIOCs = Object.values(counts).reduce((a, b) => a + b, 0);

  // Pull triage trace entry for alert_type + elapsed_ms
  const triageTrace = (result.agent_trace || []).find(tr => tr.agent === 'triage');
  const alertType = triageTrace?.alert_type || 'unknown';
  const fastPath  = triageTrace?.ai_skipped;
  const triageMs  = triageTrace?.elapsed_ms;

  // Detect which downstream stage is in progress
  const stagesSeen = new Set((result.agent_trace || []).map(tr => tr.agent));
  const inProgress = !stagesSeen.has('response') ? (
    !stagesSeen.has('investigation') ? (
      !stagesSeen.has('enrichment') ? 'enrichment' : 'investigation'
    ) : 'response'
  ) : null;

  // Build heuristic-flag chips from cross_refs (these are KNOWN before AI runs)
  const cr = result?.cross_refs || result?.response_summary?.cross_refs || {};
  const flags = [];
  for (const k of (cr.kev || []).slice(0, 3)) {
    flags.push({
      label: `KEV: ${k.cve}`,
      color: k.ransomware_use ? t.red : t.orange,
      detail: k.ransomware_use ? 'ransomware-use' : 'actively exploited',
    });
  }
  for (const r of (cr.rmm_abuse || []).slice(0, 2)) {
    flags.push({
      label: `RMM: ${r.binary}`,
      color: t.red,
      detail: `abused by ${(r.groups || []).slice(0, 2).join(', ')}`,
    });
  }
  for (const l of (cr.lolbas || []).slice(0, 2)) {
    flags.push({ label: `LOLBAS: ${l.name}`, color: t.orange, detail: '' });
  }
  for (const d of (cr.loldrivers || []).slice(0, 1)) {
    flags.push({ label: `LOLDriver: ${d.value}`, color: t.red, detail: 'BYOVD candidate' });
  }
  for (const k of (cr.phishing_kits || []).slice(0, 2)) {
    flags.push({ label: `Kit: ${k.kit}`, color: t.red, detail: '' });
  }
  for (const p of (cr.suspicious_paths || []).slice(0, 2)) {
    flags.push({ label: `Path: ${p.label.split(' — ')[0]}`, color: t.orange, detail: '' });
  }

  const stageLabel = {
    enrichment:    'Enriching IOCs against threat intel sources…',
    investigation: 'AI analyst is reasoning over the evidence…',
    response:      'Generating detection rules and analyst handoff…',
  }[inProgress];

  const typeBadgeColor = {
    phishing:      t.red,
    ransomware:    t.red,
    malware:       t.orange,
    c2:            t.orange,
    exploitation:  t.red,
  }[alertType] || t.cy;

  return (
    <MuiPaper elevation={0} sx={{
      border: theme => `1px solid ${muiAlpha('#ffffff', 0.12)}`,
      borderLeft: theme => `3px solid ${theme.palette.primary.main}`,
      borderRadius: '4px',
      p: '14px 16px',
      mb: 1.75,
    }}>
      {/* Top line: detected type + IOC counts + triage timing */}
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.25, flexWrap: 'wrap',
        mb: flags.length ? 1.5 : 1 }}>
        <MuiTag label={alertType !== 'unknown' ? alertType : 'analyzing…'} color={typeBadgeColor}/>
        <Typography sx={{ fontSize: 12, color: 'text.tertiary' }}>
          {totalIOCs > 0
            ? Object.entries(counts).filter(([, n]) => n > 0)
                .map(([k, n]) => `${n} ${k.slice(0, -1)}${n > 1 ? 's' : ''}`).join(' · ')
            : 'no IOCs extracted — log-content analysis'}
        </Typography>
        {triageMs != null && (
          <Typography sx={{ fontSize: 11, color: 'text.tertiary', ml: 'auto' }}>
            triage {triageMs}ms{fastPath ? ' · fast-path' : ''}
          </Typography>
        )}
      </Box>

      {/* Heuristic flags */}
      {flags.length > 0 && (
        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.75, mb: 1.5 }}>
          {flags.map((f, i) => (
            <Box key={i} sx={{
              backgroundColor: 'background.secondary',
              border: `1px solid ${muiAlpha(f.color, 0.25)}`,
              borderLeft: `2px solid ${f.color}`,
              borderRadius: '4px', px: 1.125, py: '4px',
              fontSize: 11, color: 'text.primary',
            }}>
              <Box component="span" sx={{ color: f.color, fontWeight: 600 }}>{f.label}</Box>
              {f.detail && <Box component="span" sx={{ color: 'text.tertiary' }}> · {f.detail}</Box>}
            </Box>
          ))}
        </Box>
      )}

      {/* In-progress indicator */}
      {inProgress && stageLabel && (
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, fontSize: 12, color: 'text.tertiary' }}>
          <Box component="span" sx={{
            display: 'inline-block', width: 6, height: 6, borderRadius: 99,
            backgroundColor: 'primary.main', animation: 'pulse 1.4s ease-in-out infinite',
          }}/>
          {stageLabel}
        </Box>
      )}
    </MuiPaper>
  );
}

/* ─── critical signal banners ─────────────────────────────────────────────────── */
function SignalBanners({ result }) {
  const banners = [];
  const enr = result?.enrichments || {};

  // Same-day domain registrations — top phishing signal
  for (const [domain, d] of Object.entries(enr.domains || {})) {
    const nrd = d?.heuristics?.nrd;
    if (nrd?.is_same_day) {
      banners.push({
        kind: 'critical',
        title: 'Domain registered TODAY',
        text:  `${domain} was registered ${nrd.age_hours}h ago (${nrd.created}). This is a high-confidence phishing signal — legitimate businesses don't operate from same-day domains.`,
      });
    } else if (nrd?.is_this_week) {
      banners.push({
        kind: 'high',
        title: 'Domain registered this week',
        text:  `${domain} is ${nrd.age_days} days old (${nrd.created}). New domains under one week are common in active phishing campaigns.`,
      });
    }
    // Spamhaus DBL listing — independent confirmation
    if (d?.spamhaus_dbl?.hit) {
      const v = d.spamhaus_dbl.verdict;
      banners.push({
        kind: v === 'phishing' || v === 'malware' || v === 'botnet' ? 'critical' : 'high',
        title: `Spamhaus DBL · ${d.spamhaus_dbl.label}`,
        text:  `${domain} is listed on Spamhaus DBL (code ${d.spamhaus_dbl.code}). Independent confirmation from an authoritative blocklist.`,
      });
    }
  }

  // IPs reported as malicious today
  for (const [ip, d] of Object.entries(enr.ips || {})) {
    const recent = d?.abuseipdb?.recent_activity;
    if (recent?.is_active_today && (d?.abuseipdb?.abuseScore || 0) >= 50) {
      banners.push({
        kind: 'high',
        title: 'IP active in attacks within last 24h',
        text:  `${ip} was last reported ${recent.hours_since_last_report}h ago by AbuseIPDB · score ${d.abuseipdb.abuseScore}%.`,
      });
    }
    // Bulletproof / abuse-friendly hoster
    const asn = d?.asn_reputation;
    if (asn?.severity === 'high') {
      banners.push({
        kind: 'high',
        title: `IP hosted on bulletproof / abuse-friendly ASN`,
        text:  `${ip} → ${asn.hits?.[0]?.description || 'flagged ASN'}. Hosters in this category routinely refuse abuse takedowns.`,
      });
    }
  }

  // KEV with ransomware use
  for (const k of result?.response_summary?.cross_refs?.kev || []) {
    if (k.ransomware_use) {
      banners.push({
        kind: 'critical',
        title: `${k.cve} is actively exploited in ransomware`,
        text:  `${k.vendor} ${k.product} — ${k.name}. Patch required per CISA KEV.`,
      });
    }
  }

  // RMM tool detected — heavy abuse-by-ransomware signal
  for (const r of result?.response_summary?.cross_refs?.rmm_abuse || []) {
    banners.push({
      kind: 'high',
      title: `RMM tool detected: ${r.binary}`,
      text:  `${r.vendor} — abused by ${(r.groups || []).slice(0, 3).join(', ')}. Verify whether install was authorized by IT and review parent process / install source.`,
    });
  }

  if (!banners.length) return null;

  return (
    <Stack spacing={1} sx={{ mb: 1.75 }}>
      {banners.map((b, i) => {
        const isCritical = b.kind === 'critical';
        const color = isCritical ? '#F14337' : '#E6700F';
        return (
          <MuiPaper key={i} elevation={0} sx={{
            backgroundColor: muiAlpha(color, 0.1),
            border: `1px solid ${muiAlpha(color, 0.3)}`,
            borderLeft: `3px solid ${color}`,
            borderRadius: '4px',
            p: '12px 14px',
            display: 'flex', gap: 1.5, alignItems: 'flex-start',
          }}>
            <AlertCircle size={16} color={color} style={{ flexShrink: 0, marginTop: 1 }}/>
            <Box>
              <Typography sx={{ color, fontWeight: 600, fontSize: 13, mb: 0.375 }}>{b.title}</Typography>
              <Typography sx={{ color: 'text.primary', fontSize: 12, lineHeight: 1.6 }}>{b.text}</Typography>
            </Box>
          </MuiPaper>
        );
      })}
    </Stack>
  );
}

/* ─── overview metrics ───────────────────────────────────────────────────────── */
function Overview({ result }) {
  const rs = result?.response_summary;
  if (!rs) return null;
  const lc = levelStyle[rs.threat_level] || levelStyle.INFORMATIONAL;
  const total = Object.values(result.iocs||{}).flat().length;
  const mitre = rs.mitre_techniques?.length || 0;
  const conf  = Math.round((rs.confidence||0)*100);
  const ts    = rs.timestamp ? new Date(rs.timestamp) : new Date();

  const Metric = ({ label, value, color }) => (
    <MuiPaper elevation={0} sx={{
      flex: 1, p: '14px 16px',
      border: `1px solid ${muiAlpha('#ffffff', 0.12)}`,
      borderRadius: '4px',
    }}>
      <Typography sx={{ color: 'text.tertiary', fontSize: 11, fontWeight: 500, mb: 0.75 }}>
        {label}
      </Typography>
      <Typography sx={{
        color: color || 'text.primary',
        fontSize: 22, fontWeight: 600, lineHeight: 1.1,
        fontVariantNumeric: 'tabular-nums',
      }}>{value}</Typography>
    </MuiPaper>
  );

  return (
    <Box sx={{ mb: 1.75 }}>
      <Box sx={{
        display: 'flex', alignItems: 'baseline', justifyContent: 'space-between', mb: 1.25,
      }}>
        <Typography sx={{
          fontSize: 18, fontWeight: 600, color: 'text.primary', letterSpacing: '-0.01em',
        }}>
          Investigation results
        </Typography>
        <Typography sx={{
          fontSize: 12, color: 'text.tertiary', fontVariantNumeric: 'tabular-nums',
        }}>
          {ts.toLocaleString()}
        </Typography>
      </Box>
      <Box sx={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 1.25 }}>
        <Metric label="Threat level" value={rs.threat_level} color={lc.fg}/>
        <Metric label="Confidence" value={`${conf}%`}
          color={conf >= 70 ? '#17AB1F' : conf >= 40 ? '#E1B823' : '#F14337'}/>
        <Metric label="Indicators" value={total} color="#0fbcff"/>
        <Metric label="MITRE TTPs" value={mitre} color="#B286FF"/>
      </Box>
    </Box>
  );
}

/* ─── GTI ────────────────────────────────────────────────────────────────────── */
function GTI({ result }) {
  const gti = result?.gti_scores || {};
  const sorted = Object.entries(gti).sort(([,a],[,b])=>b.score-a.score);
  const top = sorted[0]?.[1];
  const total = Object.values(result?.iocs||{}).flat().length;
  if (!sorted.length) return null;

  const dist = { critical:0, high:0, elevated:0, suspicious:0, clean:0 };
  const distC = { critical:t.red, high:t.orange, elevated:t.yellow, suspicious:'#f59e0b', clean:t.green };
  sorted.forEach(([,d]) => {
    if (d.score>=85) dist.critical++;
    else if (d.score>=65) dist.high++;
    else if (d.score>=45) dist.elevated++;
    else if (d.score>=25) dist.suspicious++;
    else dist.clean++;
  });

  return (
    <Card title="Threat scoring" accent={t.cy} badge={top?`${top.score}/100`:null}>
      <div style={{ display:'grid', gridTemplateColumns:'auto 1fr', gap:24, marginBottom:18,
        paddingBottom:16, borderBottom:`1px solid ${t.line}` }}>
        {top && (
          <div style={{ display:'flex', alignItems:'center', gap:14 }}>
            <Dial score={top.score} color={top.color} size={80}/>
            <div>
              <div style={{ fontSize:11, color:t.fgDim, marginBottom:4 }}>Highest scoring indicator</div>
              <div style={{ fontSize:18, fontWeight:600, color:top.color, marginBottom:6 }}>{top.label}</div>
              <Verdict verdict={top.verdict}/>
            </div>
          </div>
        )}
        <div style={{ display:'flex', flexDirection:'column', justifyContent:'center' }}>
          <div style={{ fontSize:11, color:t.fgDim, marginBottom:8 }}>Score distribution</div>
          {Object.entries(dist).map(([lbl,cnt])=>(
            <div key={lbl} style={{ display:'flex', gap:10, alignItems:'center', marginBottom:4 }}>
              <div style={{ width:72, fontSize:11, color:t.fgMute, textTransform:'capitalize' }}>{lbl}</div>
              <div style={{ flex:1, background:t.raised, borderRadius:99, height:6, overflow:'hidden' }}>
                {cnt>0 && <div style={{ width:`${Math.min(100,cnt*16)}%`, height:'100%',
                  background:distC[lbl], borderRadius:99, transition:'width .4s' }}/>}
              </div>
              <span style={{ width:18, fontSize:11, color:cnt>0?distC[lbl]:t.fgGhost, fontWeight:600,
                textAlign:'right', fontVariantNumeric:'tabular-nums' }}>{cnt}</span>
            </div>
          ))}
        </div>
      </div>

      <div style={{ display:'flex', gap:8, flexWrap:'wrap', marginBottom:16 }}>
        <div style={{ display:'flex', alignItems:'center', gap:7, background:t.raised,
          border:`1px solid ${t.line}`, borderRadius:6, padding:'6px 11px' }}>
          <span style={{ width:6, height:6, borderRadius:99, background:t.purple }}/>
          <span style={{ fontSize:11, color:t.fg, fontWeight:500 }}>STIX 2.1</span>
          <span style={{ fontSize:11, color:t.fgDim }}>· {total} indicators</span>
          {result?.runId && <a href={`/api/export/stix/${result.runId}`} target="_blank" rel="noreferrer"
            style={{ color:t.purple, fontSize:11, display:'inline-flex', alignItems:'center', gap:2, marginLeft:2 }}>
            export <ArrowUpRight size={11}/>
          </a>}
        </div>
        <div style={{ display:'flex', alignItems:'center', gap:7, background:t.raised,
          border:`1px solid ${t.line}`, borderRadius:6, padding:'6px 11px' }}>
          <span style={{ width:6, height:6, borderRadius:99, background:t.cy }}/>
          <span style={{ fontSize:11, color:t.fg, fontWeight:500 }}>TAXII feeds</span>
          <span style={{ fontSize:11, color:t.fgDim }}>
            · VT, AbuseIPDB, OTX, ThreatFox, MalwareBazaar, GreyNoise, URLScan, Shodan
          </span>
        </div>
      </div>

      <div style={{ fontSize:11, color:t.fgDim, marginBottom:6 }}>Per-indicator score</div>
      <div style={{ background:t.raised, borderRadius:6, border:`1px solid ${t.line}`, overflow:'hidden' }}>
        {sorted.map(([ioc,d], i)=>(
          <div key={ioc} style={{ display:'flex', gap:12, alignItems:'center', padding:'10px 14px',
            borderTop: i>0?`1px solid ${t.line}`:'none' }}>
            <Dial score={d.score} color={d.color} size={38}/>
            <div style={{ flex:1, minWidth:0 }}>
              <div style={{ fontSize:12, color:t.fg, fontFamily:'JetBrains Mono',
                wordBreak:'break-all', marginBottom:3 }}>
                {ioc.length>58?ioc.slice(0,55)+'…':ioc}
              </div>
              <div style={{ fontSize:11, color:t.fgMute }}>
                {d.label}
                {d.contributing_factors?.slice(0,1).map((f,i)=>
                  <span key={i} style={{ color:t.fgDim }}> · {f}</span>
                )}
              </div>
            </div>
            <Verdict verdict={d.verdict} size="xs"/>
          </div>
        ))}
      </div>
    </Card>
  );
}

/* ─── assessment ────────────────────────────────────────────────────────────── */
function Assessment({ rs }) {
  const lc = levelStyle[rs.threat_level] || levelStyle.INFORMATIONAL;
  return (
    <Card title="AI assessment" accent={t.cy} badge={rs.threat_level?.toLowerCase()}>
      <div style={{ background:lc.bg, border:`1px solid ${lc.line}`, borderRadius:6,
        padding:'14px 16px', marginBottom:14 }}>
        <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:8 }}>
          <div style={{ display:'flex', alignItems:'center', gap:8 }}>
            <span style={{ width:8, height:8, borderRadius:99, background:lc.fg }}/>
            <span style={{ color:lc.fg, fontWeight:600, fontSize:13 }}>{rs.threat_level}</span>
          </div>
          {typeof rs.confidence==='number' && (
            <span style={{ fontSize:12, color:t.fgMute }}>
              Confidence <span style={{ color:rs.confidence>=0.7?t.green:rs.confidence>=0.4?t.yellow:t.red, fontWeight:600 }}>
                {Math.round(rs.confidence*100)}%
              </span>
            </span>
          )}
        </div>
        <p style={{ fontSize:13, color:t.fg, lineHeight:1.7, margin:0 }}>{rs.summary}</p>
      </div>

      {rs.chain_of_thought?.length>0 && (
        <Block title="Reasoning chain">
          {rs.chain_of_thought.map((s,i) => (
            <li key={i} style={{ display:'flex', gap:10, padding:'6px 0',
              borderTop: i>0?`1px solid ${t.line}`:'none', fontSize:13, color:t.fg, lineHeight:1.6 }}>
              <span style={{ color:t.cy, minWidth:18, fontWeight:600, fontVariantNumeric:'tabular-nums' }}>{i+1}</span>
              <span>{s}</span>
            </li>
          ))}
        </Block>
      )}

      {rs.key_findings?.length>0 && (
        <Block title="Key findings">
          {rs.key_findings.map((f,i) => (
            <li key={i} style={{ display:'flex', gap:10, padding:'6px 0',
              borderTop: i>0?`1px solid ${t.line}`:'none', fontSize:13, color:t.fg, lineHeight:1.6 }}>
              <span style={{ color:t.orange, minWidth:6 }}>›</span>
              <span>{f}</span>
            </li>
          ))}
        </Block>
      )}

      {rs.ioc_assessments?.length>0 && (
        <Block title="Indicator verdicts">
          {rs.ioc_assessments.map((a,i) => (
            <li key={i} style={{ display:'flex', gap:10, padding:'7px 0',
              borderTop: i>0?`1px solid ${t.line}`:'none', alignItems:'flex-start' }}>
              <div style={{ minWidth:90 }}><Verdict verdict={a.verdict} size="xs"/></div>
              <div style={{ flex:1, minWidth:0 }}>
                <div style={{ fontFamily:'JetBrains Mono', fontSize:12, color:t.fg, wordBreak:'break-all' }}>
                  {a.ioc}
                </div>
                {a.reason && <div style={{ fontSize:12, color:t.fgMute, marginTop:3, lineHeight:1.5 }}>
                  {a.reason}
                </div>}
              </div>
            </li>
          ))}
        </Block>
      )}

      {rs.mitre_techniques?.length>0 && (
        <Block title="MITRE ATT&CK">
          <div style={{ display:'flex', gap:6, flexWrap:'wrap' }}>
            {rs.mitre_techniques.map((t_,i) => {
              const id = t_.split(' ')[0];
              return (
                <a key={i} href={`https://attack.mitre.org/techniques/${id.includes('.')?id.replace('.','/'):id}/`}
                  target="_blank" rel="noreferrer"
                  style={{ background:t.blueDim, border:`1px solid ${t.blue}30`, color:t.blue,
                    padding:'3px 9px', borderRadius:5, fontSize:11, fontFamily:'JetBrains Mono',
                    textDecoration:'none', display:'inline-flex', alignItems:'center', gap:4 }}>
                  {t_}
                </a>
              );
            })}
          </div>
        </Block>
      )}

      {rs.matched_actors?.length>0 && (
        <Block title="Threat actor attribution">
          {rs.matched_actors.slice(0,5).map((a,i) => (
            <div key={i} style={{ padding:'10px 0',
              borderTop: i>0?`1px solid ${t.line}`:'none', display:'grid',
              gridTemplateColumns:'1fr auto', gap:12, alignItems:'start' }}>
              <div>
                <div style={{ display:'flex', alignItems:'center', gap:8, marginBottom:4 }}>
                  <span style={{ fontSize:13, color:t.fg, fontWeight:600 }}>{a.name}</span>
                  {a.mitre_id && <Chip color={t.fgDim} mono size="xs">{a.mitre_id}</Chip>}
                </div>
                {(a.origin || a.sponsor) && (
                  <div style={{ fontSize:11, color:t.fgMute, marginBottom:4 }}>
                    {[a.origin, a.sponsor].filter(Boolean).join(' · ')}
                  </div>
                )}
                {a.aliases?.length>0 && (
                  <div style={{ fontSize:11, color:t.fgDim, marginBottom:4 }}>
                    aka {a.aliases.slice(0,4).join(', ')}
                  </div>
                )}
                {a.description && (
                  <div style={{ fontSize:12, color:t.fgMute, lineHeight:1.5, marginTop:5 }}>
                    {a.description.slice(0, 200)}{a.description.length>200?'…':''}
                  </div>
                )}
              </div>
              <div style={{ textAlign:'right' }}>
                <div style={{ fontSize:18, color:t.orange, fontWeight:600, fontVariantNumeric:'tabular-nums' }}>
                  {a.score}%
                </div>
                <div style={{ fontSize:10, color:t.fgDim }}>TTP match</div>
              </div>
            </div>
          ))}
        </Block>
      )}

      {rs.recommended_actions?.length>0 && (
        <Block title="Recommended actions">
          {rs.recommended_actions.map((a,i) => (
            <li key={i} style={{ display:'flex', gap:10, padding:'6px 0',
              borderTop: i>0?`1px solid ${t.line}`:'none', fontSize:13, color:t.fg, lineHeight:1.6 }}>
              <span style={{ color:t.green, minWidth:18, fontWeight:600, fontVariantNumeric:'tabular-nums' }}>{i+1}</span>
              <span>{a}</span>
            </li>
          ))}
        </Block>
      )}
    </Card>
  );
}

// Thin wrapper → MuiBlock (renders MUI Box with subtle border + tertiary label)
const Block = ({ title, children }) => (
  <MuiBlock title={title}>
    <Box component="ul" sx={{ margin:0, padding:0, listStyle:'none' }}>{children}</Box>
  </MuiBlock>
);

/* ─── analyst hand-off (disposition, clear/escalate, client email, IR playbook) ── */
function AnalystSummary({ rs }) {
  const a = rs?.analyst_summary;
  if (!a || (!a.disposition && !a.client_email)) return null;

  const dispColor = a.disposition === 'CLEAR' ? t.green
    : a.disposition === 'ESCALATE' ? t.red
    : t.yellow;

  return (
    <Card title="Analyst hand-off" accent={t.cy} badge={a.disposition?.toLowerCase()} defaultOpen={true}>
      {/* Disposition banner */}
      {a.disposition && (
        <div style={{ background:t.raised, border:`1px solid ${dispColor}40`,
          borderLeft:`3px solid ${dispColor}`, borderRadius:6, padding:'12px 14px', marginBottom:12 }}>
          <div style={{ display:'flex', alignItems:'center', gap:8, marginBottom:6 }}>
            <span style={{ width:8, height:8, borderRadius:99, background:dispColor }}/>
            <span style={{ color:dispColor, fontWeight:600, fontSize:13 }}>
              Recommended disposition: {a.disposition}
            </span>
          </div>
          {a.disposition_reason && (
            <p style={{ fontSize:13, color:t.fg, lineHeight:1.7, margin:0 }}>{a.disposition_reason}</p>
          )}
        </div>
      )}

      {/* Clear justification (always show — explains why or why not) */}
      {a.clear_justification && (
        <Block title="Why this can / cannot be cleared">
          <li style={{ listStyle:'none', padding:'4px 0', fontSize:13, color:t.fg, lineHeight:1.7 }}>
            {a.clear_justification}
          </li>
        </Block>
      )}

      {/* Escalation steps */}
      {a.escalation_steps?.length > 0 && a.disposition !== 'CLEAR' && (
        <Block title="If escalating · steps for Tier 2">
          {a.escalation_steps.map((s,i) => (
            <li key={i} style={{ display:'flex', gap:10, padding:'6px 0',
              borderTop: i>0?`1px solid ${t.line}`:'none', fontSize:13, color:t.fg, lineHeight:1.6 }}>
              <span style={{ color:t.red, minWidth:18, fontWeight:600 }}>{i+1}</span>
              <span>{s}</span>
            </li>
          ))}
        </Block>
      )}

      {/* Client email — the big copy-able paragraph */}
      {a.client_email?.body && (
        <div style={{ marginTop:8 }}>
          <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:6 }}>
            <div style={{ fontSize:11, color:t.fgDim, fontWeight:500 }}>Client notification email</div>
            <CopyBtn text={`Subject: ${a.client_email.subject || ''}\n\n${a.client_email.body}`} label="Copy email"/>
          </div>
          <div style={{ background:t.raised, border:`1px solid ${t.line}`, borderRadius:6, padding:14 }}>
            {a.client_email.subject && (
              <div style={{ paddingBottom:10, marginBottom:10, borderBottom:`1px solid ${t.line}` }}>
                <span style={{ fontSize:11, color:t.fgDim, marginRight:8 }}>Subject:</span>
                <span style={{ fontSize:13, color:t.fg, fontWeight:600 }}>{a.client_email.subject}</span>
              </div>
            )}
            <div style={{ fontSize:13, color:t.fg, lineHeight:1.8, whiteSpace:'pre-wrap' }}>
              {a.client_email.body}
            </div>
          </div>
        </div>
      )}
    </Card>
  );
}

/* ─── Chat with RECON · conversational follow-up on the investigation ───────── */
function ChatWithRecon({ result }) {
  const [messages, setMessages] = useState([]);
  const [input, setInput]       = useState('');
  const [sending, setSending]   = useState(false);
  const [error, setError]       = useState(null);
  const scrollRef = useRef(null);

  const runId = result?.runId;
  const rs    = result?.response_summary || {};
  const questions = rs.probing_questions || [];
  const classification = rs.verdict_classification;

  // Load history when run changes
  useEffect(() => {
    if (!runId) return;
    fetch(`/api/chat/${runId}`)
      .then(r => r.ok ? r.json() : { messages: [] })
      .then(d => setMessages(d.messages || []))
      .catch(() => setMessages([]));
  }, [runId]);

  // Auto-scroll on new message
  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior:'smooth' });
  }, [messages, sending]);

  const send = async (msgOverride) => {
    const text = (msgOverride ?? input).trim();
    if (!text || !runId || sending) return;
    setSending(true); setError(null);
    if (!msgOverride) setInput('');

    // Push user message immediately + an empty assistant placeholder we'll fill via stream
    setMessages(m => [
      ...m,
      { role:'user', content:text, timestamp:new Date().toISOString() },
      { role:'assistant', content:'', tool_calls:[], _streaming:true,
        timestamp:new Date().toISOString() },
    ]);

    try {
      const resp = await fetch(`/api/chat/${runId}`, {
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({ message: text }),
      });
      if (!resp.ok) {
        const errBody = await resp.json().catch(() => ({}));
        throw new Error(errBody.detail || errBody.error || `HTTP ${resp.status}`);
      }

      // Stream SSE events, append text tokens + tool-call records to the assistant message
      const reader = resp.body.getReader();
      const dec = new TextDecoder();
      let buf = '';
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += dec.decode(value, { stream:true });
        const lines = buf.split('\n');
        buf = lines.pop();
        for (const line of lines) {
          if (!line.startsWith('data: ')) continue;
          const payload = line.slice(6).trim();
          if (payload === '[DONE]') break;
          try {
            const ev = JSON.parse(payload);
            if (ev.event === 'token') {
              setMessages(m => {
                const copy = [...m];
                const last = copy[copy.length - 1];
                if (last && last.role === 'assistant') {
                  copy[copy.length - 1] = { ...last, content: (last.content || '') + ev.text };
                }
                return copy;
              });
            } else if (ev.event === 'tool_call') {
              setMessages(m => {
                const copy = [...m];
                const last = copy[copy.length - 1];
                if (last && last.role === 'assistant') {
                  copy[copy.length - 1] = {
                    ...last,
                    tool_calls: [...(last.tool_calls || []), {
                      tool: ev.tool, args: ev.args, summary: ev.summary,
                    }],
                  };
                }
                return copy;
              });
            } else if (ev.event === 'done') {
              setMessages(m => {
                const copy = [...m];
                const last = copy[copy.length - 1];
                if (last && last.role === 'assistant') {
                  copy[copy.length - 1] = { ...last, _streaming:false };
                }
                return copy;
              });
            } else if (ev.event === 'error') {
              throw new Error(ev.error);
            }
          } catch (e) { /* skip malformed lines */ }
        }
      }
    } catch (e) {
      setError(e.message);
      // Roll back the placeholder assistant message on error
      setMessages(m => m[m.length-1]?._streaming ? m.slice(0, -1) : m);
    } finally { setSending(false); }
  };

  if (!runId) return null;
  const isAmbiguous = classification === 'AMBIGUOUS';
  const accent = isAmbiguous ? '#E6700F' : '#0fbcff';
  const banner = isAmbiguous
    ? 'RECON needs more context to commit to a verdict — pick a question or ask anything'
    : 'Investigation guidance — what a senior analyst would check next. Click any to chat.';

  return (
    <Card title="Ask RECON" accent={accent} defaultOpen
      badge={questions.length > 0 ? `${questions.length} suggested checks` : null}>
      <Typography sx={{ fontSize:12, color:'text.tertiary', mb:1.5, lineHeight:1.55 }}>
        {banner}
      </Typography>

      {/* Investigation-guidance question cards (teaching tool) */}
      {questions.length > 0 && messages.length === 0 && (
        <Box sx={{ mb:1.75 }}>
          <Box sx={{ display:'flex', alignItems:'center', gap:0.75, mb:1 }}>
            <Box sx={{ width:4, height:4, borderRadius:99, backgroundColor:accent }}/>
            <Typography variant="caption" sx={{
              fontSize:11, color:'text.tertiary', fontWeight:500,
              textTransform:'uppercase', letterSpacing:'0.06em',
            }}>
              {isAmbiguous ? 'Probing questions' : 'Things to verify · click to ask'}
            </Typography>
          </Box>
          <Stack spacing={1}>
            {questions.map((q, i) => (
              <MuiPaper key={i} onClick={() => send(q.question)} elevation={0}
                sx={{
                  p:'11px 14px', cursor:'pointer',
                  border: `1px solid ${muiAlpha('#ffffff', 0.12)}`,
                  borderLeft: `3px solid ${accent}`,
                  borderRadius: '4px',
                  backgroundColor: 'background.secondary',
                  transition: 'background-color 0.15s',
                  '&:hover': { backgroundColor: muiAlpha('#ffffff', 0.04) },
                }}>
                <Typography sx={{ fontSize:13, fontWeight:500, mb:0.75, lineHeight:1.5 }}>
                  {q.question}
                </Typography>
                {q.why_asking && (
                  <Typography sx={{ fontSize:11, color:'text.tertiary', mb:0.75,
                    fontStyle:'italic', lineHeight:1.5 }}>
                    why: {q.why_asking}
                  </Typography>
                )}
                {(q.if_yes_means || q.if_no_means) && (
                  <Box sx={{ display:'flex', flexDirection:'column', gap:0.4, fontSize:11,
                    pt:0.75, borderTop: `1px solid ${muiAlpha('#ffffff', 0.06)}` }}>
                    {q.if_yes_means && (
                      <Box><Box component="span" sx={{ color:'success.main', fontWeight:500 }}>if yes →</Box>{' '}
                        <Box component="span" sx={{ color:'text.tertiary' }}>{q.if_yes_means}</Box></Box>
                    )}
                    {q.if_no_means && (
                      <Box><Box component="span" sx={{ color:'error.main', fontWeight:500 }}>if no →</Box>{' '}
                        <Box component="span" sx={{ color:'text.tertiary' }}>{q.if_no_means}</Box></Box>
                    )}
                  </Box>
                )}
              </MuiPaper>
            ))}
          </Stack>
        </Box>
      )}

      {/* Conversation history (scrollable) */}
      <Box ref={scrollRef} sx={{
        maxHeight: 480, overflowY: 'auto', mb: 1.5,
        backgroundColor: messages.length ? 'background.default' : 'transparent',
        border: messages.length ? `1px solid ${muiAlpha('#ffffff', 0.12)}` : 'none',
        borderRadius: '4px',
        p: messages.length ? '12px 14px' : 0,
      }}>
        {messages.map((m, i) => {
          const isUser = m.role === 'user';
          return (
            <Box key={i} sx={{
              display:'flex', gap:1.25, mb:1.75,
              flexDirection: isUser ? 'row-reverse' : 'row',
            }}>
              <Box sx={{
                width:28, height:28, borderRadius:'50%', flexShrink:0,
                backgroundColor: isUser ? muiAlpha('#B286FF', 0.16) : muiAlpha('#0fbcff', 0.16),
                border: `1px solid ${isUser ? muiAlpha('#B286FF', 0.4) : muiAlpha('#0fbcff', 0.4)}`,
                display:'flex', alignItems:'center', justifyContent:'center',
                fontSize:11, fontWeight:700,
                color: isUser ? '#B286FF' : '#0fbcff',
              }}>
                {isUser ? 'You' : 'AI'}
              </Box>
              <MuiPaper elevation={0} sx={{
                maxWidth:'78%',
                backgroundColor: isUser ? muiAlpha('#B286FF', 0.12) : 'background.accent',
                border: `1px solid ${isUser ? muiAlpha('#B286FF', 0.2) : muiAlpha('#ffffff', 0.12)}`,
                borderRadius: '4px',
                p:'10px 12px', fontSize:13, color:'text.primary', lineHeight:1.6,
                whiteSpace:'pre-wrap', wordBreak:'break-word',
              }}>
                {!isUser && m._streaming && !m.content && (!m.tool_calls || m.tool_calls.length === 0) && (
                  <Box component="span" sx={{ color:'text.tertiary', fontStyle:'italic',
                    display:'inline-flex', alignItems:'center', gap:0.75 }}>
                    <Box component="span" sx={{
                      display:'inline-block', width:5, height:5, borderRadius:99,
                      backgroundColor:'primary.main',
                      animation:'pulse 1.2s ease-in-out infinite',
                    }}/>
                    RECON is thinking…
                  </Box>
                )}
                {m.content}
                {!isUser && m._streaming && m.content && (
                  <Box component="span" sx={{
                    display:'inline-block', width:6, height:14, ml:0.25, mb:'-2px',
                    backgroundColor:'primary.main',
                    animation:'pulse 0.9s ease-in-out infinite',
                    verticalAlign:'middle',
                  }}/>
                )}
                {!isUser && m.tool_calls?.length > 0 && (
                  <Box sx={{ mt:1.25, pt:1,
                    borderTop:`1px solid ${muiAlpha('#ffffff', 0.06)}` }}>
                    <Typography variant="caption" sx={{
                      fontSize:10, color:'text.tertiary', mb:0.625,
                      letterSpacing:'0.04em', display:'block',
                    }}>
                      RECON checked
                    </Typography>
                    {m.tool_calls.map((tc, j) => (
                      <Box key={j} sx={{ fontSize:11, color:'text.tertiary', py:'2px',
                        fontFamily:'"IBM Plex Mono", monospace', wordBreak:'break-all' }}>
                        <Box component="span" sx={{ color:'primary.main' }}>{tc.tool}</Box>
                        <span> → </span>
                        <Box component="span" sx={{ color:'text.primary' }}>{tc.summary}</Box>
                      </Box>
                    ))}
                  </Box>
                )}
              </MuiPaper>
            </Box>
          );
        })}
      </Box>

      {/* Input row */}
      <Stack direction="row" spacing={1}>
        <MuiTextField
          multiline rows={2} fullWidth variant="outlined"
          value={input} onChange={e => setInput(e.target.value)}
          onKeyDown={e => {
            if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) { e.preventDefault(); send(); }
          }}
          placeholder='Ask anything — "Is this likely a vulnerability scanner?", "Look up this hash in sandbox"…'
          sx={{ flex:1, '& .MuiOutlinedInput-input': { fontSize:13, lineHeight:1.5 } }}
        />
        <MuiButton variant="contained"
          onClick={() => send()} disabled={sending || !input.trim()}
          sx={{ alignSelf:'stretch', minWidth:64 }}>
          Send
        </MuiButton>
      </Stack>
      <Typography sx={{ fontSize:10, color:'text.tertiary', mt:0.75, textAlign:'right' }}>
        ⌘↵ to send
      </Typography>
      {error && (
        <Box sx={{
          mt:1, p:'8px 12px',
          backgroundColor: muiAlpha('#F14337', 0.1),
          border:`1px solid ${muiAlpha('#F14337', 0.4)}`,
          borderRadius:'4px',
          color:'error.main', fontSize:12,
        }}>
          {error}
        </Box>
      )}
    </Card>
  );
}

/* ─── IR playbook (NIST 800-61) ───────────────────────────────────────────────── */
function IRPlaybook({ rs }) {
  const p = rs?.analyst_summary?.ir_playbook;
  if (!p) return null;
  const phases = [
    ['Identification', p.phase_identification, t.cy],
    ['Containment',    p.phase_containment,    t.orange],
    ['Eradication',    p.phase_eradication,    t.red],
    ['Recovery',       p.phase_recovery,       t.green],
    ['Lessons learned',p.phase_lessons,        t.purple],
  ].filter(([, steps]) => steps?.length > 0);
  if (!phases.length) return null;

  return (
    <Card title="Incident response playbook" accent={t.cy}
      badge="NIST 800-61" defaultOpen={false}>
      <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fit,minmax(280px,1fr))', gap:10 }}>
        {phases.map(([label, steps, color]) => (
          <div key={label} style={{ background:t.raised, border:`1px solid ${t.line}`,
            borderLeft:`3px solid ${color}`, borderRadius:6, padding:'12px 14px' }}>
            <div style={{ fontSize:12, fontWeight:600, color, marginBottom:8 }}>{label}</div>
            <ol style={{ margin:0, paddingLeft:18, fontSize:12, color:t.fg, lineHeight:1.7 }}>
              {steps.map((s, i) => <li key={i} style={{ marginBottom:5 }}>{s}</li>)}
            </ol>
          </div>
        ))}
      </div>
    </Card>
  );
}

/* ─── email analysis (when input is an EML) ───────────────────────────────────── */
function EmailAnalysis({ result }) {
  const e = result?.email_analysis;
  if (!e || !e.subject && !e.from) return null;

  const auth = e.auth_results || {};
  const authChip = (label, value) => {
    if (!value) return null;
    const ok = value === 'pass';
    const color = ok ? t.green : t.red;
    return <Chip color={color} soft={`${color}14`} size="xs">{label}: {value}</Chip>;
  };

  return (
    <Card title="Email analysis" accent={t.orange} badge={`${e.attachments?.length || 0} attachments`}>
      {/* Headers */}
      <div style={{ background:t.raised, border:`1px solid ${t.line}`, borderRadius:6,
        padding:'12px 14px', marginBottom:10, fontSize:12, lineHeight:1.8 }}>
        {e.subject && <div><span style={{ color:t.fgDim, marginRight:8 }}>Subject:</span>
          <span style={{ color:t.fg, fontWeight:500 }}>{e.subject}</span></div>}
        {e.from && <div><span style={{ color:t.fgDim, marginRight:8 }}>From:</span>
          <span style={{ color:t.fg, fontFamily:'JetBrains Mono', fontSize:11 }}>{e.from}</span></div>}
        {e.to?.length > 0 && <div><span style={{ color:t.fgDim, marginRight:8 }}>To:</span>
          <span style={{ color:t.fg, fontFamily:'JetBrains Mono', fontSize:11 }}>
            {Array.isArray(e.to) ? e.to.join(', ') : e.to}</span></div>}
        {e.return_path && e.return_path !== e.from && (
          <div><span style={{ color:t.fgDim, marginRight:8 }}>Return-Path:</span>
            <span style={{ color:t.red, fontFamily:'JetBrains Mono', fontSize:11 }}>{e.return_path}</span></div>
        )}
        {e.date && <div><span style={{ color:t.fgDim, marginRight:8 }}>Date:</span>
          <span style={{ color:t.fgMute }}>{e.date}</span></div>}
      </div>

      {/* Auth + signals */}
      <div style={{ display:'flex', gap:6, flexWrap:'wrap', marginBottom:12 }}>
        {authChip('SPF',   auth.spf)}
        {authChip('DKIM',  auth.dkim)}
        {authChip('DMARC', auth.dmarc)}
      </div>

      {e.phishing_signals?.length > 0 && (
        <Block title="Phishing signals">
          {e.phishing_signals.map((s, i) => (
            <li key={i} style={{ display:'flex', gap:10, padding:'5px 0',
              borderTop: i>0?`1px solid ${t.line}`:'none', listStyle:'none' }}>
              <AlertCircle size={13} color={t.red} style={{ flexShrink:0, marginTop:2 }}/>
              <span style={{ fontSize:12, color:t.fg }}>{s}</span>
            </li>
          ))}
        </Block>
      )}

      {/* Attachments */}
      {e.attachments?.length > 0 && (
        <Block title={`Attachments (${e.attachments.length})`}>
          {e.attachments.map((a, i) => (
            <li key={i} style={{ padding:'6px 0', listStyle:'none',
              borderTop: i>0?`1px solid ${t.line}`:'none' }}>
              <div style={{ fontSize:12, color:t.fg, marginBottom:2 }}>{a.filename || '(no name)'}</div>
              <div style={{ fontSize:11, color:t.fgMute }}>
                {a.content_type} · {a.size ? `${(a.size/1024).toFixed(1)} KB` : ''}
              </div>
              {a.sha256 && <div style={{ fontSize:10, color:t.fgDim, fontFamily:'JetBrains Mono',
                wordBreak:'break-all', marginTop:2 }}>sha256: {a.sha256}</div>}
            </li>
          ))}
        </Block>
      )}

      {e.urls?.length > 0 && (
        <Block title={`Embedded URLs (${e.urls.length})`}>
          {e.urls.slice(0, 20).map((u, i) => (
            <li key={i} style={{ padding:'4px 0', listStyle:'none', fontSize:11,
              color:t.fg, fontFamily:'JetBrains Mono', wordBreak:'break-all',
              borderTop: i>0?`1px solid ${t.line}`:'none' }}>{u}</li>
          ))}
        </Block>
      )}
    </Card>
  );
}

/* ─── CTI framework analysis (Diamond Model / Kill Chain / Pyramid / Admiralty) ─── */
function CTIFramework({ rs }) {
  const dm = rs?.diamond_model || {};
  const kc = rs?.kill_chain || {};
  const pop = rs?.pyramid_of_pain || [];
  const evid = rs?.evidence_ratings || [];
  const hasAny = Object.keys(dm).length || Object.values(kc).some(v=>v) || pop.length || evid.length;
  if (!hasAny) return null;

  // Kill Chain stages in canonical order
  const stages = [
    ['reconnaissance',        'Reconnaissance'],
    ['weaponization',         'Weaponization'],
    ['delivery',              'Delivery'],
    ['exploitation',          'Exploitation'],
    ['installation',          'Installation'],
    ['command_and_control',   'Command & Control'],
    ['actions_on_objectives', 'Actions on Objectives'],
  ];

  // Pyramid of Pain colour scale — higher = more painful for attacker (better detection target)
  const popOrder = ['TTPs', 'tools', 'host_artifacts', 'network', 'domains', 'ips', 'hashes'];
  const popColor = { TTPs:t.red, tools:t.orange, host_artifacts:'#fb923c', network:t.yellow,
                     domains:t.cy, ips:t.blue, hashes:t.fgMute };
  const popMap = Object.fromEntries((pop || []).map(p => [p.level, p]));

  // Admiralty code colour by source reliability letter
  const admColor = { A:t.green, B:'#34d399', C:t.yellow, D:t.orange, E:t.red, F:t.fgMute };

  return (
    <Card title="CTI framework analysis" accent={t.purple}
      badge="Diamond · Kill Chain · Pyramid · Admiralty">

      {/* ── Diamond Model ─── 4-vertex layout ────────────────────────────── */}
      {Object.keys(dm).length > 0 && (
        <Block title="Diamond Model · adversary, capability, infrastructure, victim">
          <li style={{ listStyle:'none', padding:0 }}>
            <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:8, marginTop:4 }}>
              {[
                ['adversary',      'Adversary',      t.red],
                ['capability',     'Capability',     t.orange],
                ['infrastructure', 'Infrastructure', t.cy],
                ['victim',         'Victim',         t.purple],
              ].map(([k, label, color]) => {
                const v = dm[k] || {};
                return (
                  <div key={k} style={{ background:t.raised, border:`1px solid ${t.line}`,
                    borderLeft:`3px solid ${color}`, borderRadius:6, padding:'10px 12px' }}>
                    <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', marginBottom:6 }}>
                      <span style={{ fontSize:10, color, fontWeight:600, letterSpacing:'0.05em' }}>{label.toUpperCase()}</span>
                      {v.confidence && <Chip color={color} soft={`${color}14`} size="xs">{v.confidence}</Chip>}
                    </div>
                    <div style={{ fontSize:12, color:t.fg, fontWeight:500, marginBottom:4 }}>{v.value || '—'}</div>
                    {v.rationale && <div style={{ fontSize:11, color:t.fgMute, lineHeight:1.55 }}>{v.rationale}</div>}
                  </div>
                );
              })}
            </div>
            {dm.meta_features && (dm.meta_features.phase || dm.meta_features.methodology) && (
              <div style={{ marginTop:8, fontSize:11, color:t.fgMute, padding:'6px 10px',
                background:t.bg, borderRadius:4, border:`1px solid ${t.line}` }}>
                <span style={{ color:t.fgDim }}>meta:</span> {dm.meta_features.phase || '—'}
                {dm.meta_features.methodology && <> · {dm.meta_features.methodology}</>}
              </div>
            )}
          </li>
        </Block>
      )}

      {/* ── Kill Chain — horizontal stage strip ──────────────────────────── */}
      {Object.values(kc).some(v => v) && (
        <Block title="Cyber Kill Chain · Lockheed Martin 7-stage mapping">
          <li style={{ listStyle:'none', padding:0 }}>
            <div style={{ display:'flex', gap:6, marginTop:4, overflowX:'auto' }}>
              {stages.map(([key, label], i) => {
                const evidence = kc[key];
                const hit = evidence && evidence !== 'null' && evidence !== null;
                return (
                  <div key={key} style={{ flex:'1 1 0', minWidth:90,
                    background: hit ? `${t.orange}14` : t.raised,
                    border:`1px solid ${hit ? t.orange : t.line}`,
                    borderTop:`3px solid ${hit ? t.orange : t.line}`,
                    borderRadius:5, padding:'8px 10px' }}>
                    <div style={{ fontSize:10, color: hit?t.orange:t.fgDim, fontWeight:600,
                      marginBottom:4, lineHeight:1.3 }}>
                      {String(i + 1).padStart(2, '0')} · {label}
                    </div>
                    <div style={{ fontSize:10, color: hit?t.fg:t.fgGhost, lineHeight:1.5 }}>
                      {hit ? evidence : '—'}
                    </div>
                  </div>
                );
              })}
            </div>
          </li>
        </Block>
      )}

      {/* ── Pyramid of Pain ──────────────────────────────────────────────── */}
      {pop.length > 0 && (
        <Block title="Pyramid of Pain · prioritize detections by attacker cost-to-change">
          <li style={{ listStyle:'none', padding:0 }}>
            <div style={{ marginTop:6 }}>
              {popOrder.map((lvl, i) => {
                const entry = popMap[lvl];
                const indicators = entry?.indicators || [];
                const hasInd = indicators.length > 0 && !(indicators.length === 1 && (!indicators[0] || indicators[0] === '<observed TTP>'));
                const widthPct = 100 - (i * 12);  // narrower at top
                const color = popColor[lvl];
                const labelMap = { TTPs:'TTPs (months)', tools:'Tools (months)',
                                   host_artifacts:'Host artifacts (weeks)', network:'Network artifacts (days)',
                                   domains:'Domains (hours)', ips:'IPs (minutes)', hashes:'Hashes (seconds)' };
                return (
                  <div key={lvl} style={{ display:'flex', alignItems:'center', gap:10, marginBottom:3 }}>
                    <div style={{ width:`${widthPct}%`, maxWidth:480, marginLeft:'auto', marginRight:0,
                      background: hasInd ? `${color}20` : t.raised,
                      border:`1px solid ${hasInd ? color : t.line}`, borderRadius:4,
                      padding:'5px 10px', display:'flex', justifyContent:'space-between',
                      alignItems:'center', gap:8 }}>
                      <span style={{ fontSize:11, color: hasInd?color:t.fgDim, fontWeight:600,
                        whiteSpace:'nowrap' }}>{labelMap[lvl]}</span>
                      {hasInd && (
                        <span style={{ fontSize:10, color:t.fg, fontFamily:'JetBrains Mono',
                          textAlign:'right', overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>
                          {indicators.slice(0,3).join(', ')}
                        </span>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
            <div style={{ marginTop:8, fontSize:11, color:t.fgMute, fontStyle:'italic' }}>
              Focus detections on the top half (host artifacts, tools, TTPs) — they take attackers
              weeks to months to replace; hashes/IPs they swap in seconds.
            </div>
          </li>
        </Block>
      )}

      {/* ── Admiralty Code — evidence reliability ratings ───────────────── */}
      {evid.length > 0 && (
        <Block title="Admiralty Code · NATO STANAG 2511 evidence reliability">
          {evid.map((e, i) => {
            const c = admColor[e.source_reliability?.[0]?.toUpperCase()] || t.fgMute;
            return (
              <li key={i} style={{ padding:'7px 0', listStyle:'none',
                borderTop: i>0?`1px solid ${t.line}`:'none' }}>
                <div style={{ display:'flex', alignItems:'center', gap:8, marginBottom:3 }}>
                  <Chip color={c} soft={`${c}14`}>{e.rating || '?'}</Chip>
                  <span style={{ fontSize:11, color:t.fgMute }}>
                    source={e.source_reliability || '?'} · cred={e.info_credibility || '?'}
                  </span>
                </div>
                <div style={{ fontSize:12, color:t.fg, marginBottom:2 }}>{e.evidence}</div>
                {e.rationale && <div style={{ fontSize:11, color:t.fgMute, lineHeight:1.5 }}>{e.rationale}</div>}
              </li>
            );
          })}
        </Block>
      )}
    </Card>
  );
}

/* ─── intel cross-references (KEV / LOLBAS / Atomic) ──────────────────────────── */
function CrossRefs({ rs }) {
  const cr = rs?.cross_refs || {};
  const atomic = rs?.atomic_examples || [];
  const kev = cr.kev || [];
  const lolbas = cr.lolbas || [];
  const kits = cr.phishing_kits || [];
  const drivers = cr.loldrivers || [];
  const rmm = cr.rmm_abuse || [];
  const paths = cr.suspicious_paths || [];
  if (!kev.length && !lolbas.length && !atomic.length && !kits.length && !drivers.length && !rmm.length && !paths.length) return null;

  return (
    <Card title="Threat intel cross-references" accent={t.cy}
      badge={`${kev.length} KEV · ${lolbas.length} LOLBAS · ${kits.length} kit · ${atomic.length} TTP`}>
      {kits.length > 0 && (
        <Block title={`Phishing-kit fingerprints (${kits.length})`}>
          {kits.map((k,i) => (
            <li key={i} style={{ padding:'8px 0', borderTop: i>0?`1px solid ${t.line}`:'none', listStyle:'none' }}>
              <div style={{ display:'flex', alignItems:'center', gap:8, marginBottom:4, flexWrap:'wrap' }}>
                <Chip color={t.red} soft={t.redDim}>{k.kit}</Chip>
                <span style={{ fontSize:11, color:t.fgDim }}>{k.patterns_matched} pattern{k.patterns_matched>1?'s':''}</span>
              </div>
              {k.url && <div style={{ fontSize:11, color:t.fg, fontFamily:'JetBrains Mono',
                wordBreak:'break-all', lineHeight:1.5 }}>{k.url}</div>}
            </li>
          ))}
        </Block>
      )}

      {kev.length > 0 && (
        <Block title={`Actively exploited CVEs · CISA KEV (${kev.length})`}>
          {kev.map((k,i) => {
            const epss = k.epss;
            const epssColor = epss?.tier === 'critical' ? t.red
              : epss?.tier === 'high' ? t.orange
              : epss?.tier === 'medium' ? t.yellow : t.fgMute;
            return (
              <li key={i} style={{ padding:'8px 0', borderTop: i>0?`1px solid ${t.line}`:'none', listStyle:'none' }}>
                <div style={{ display:'flex', alignItems:'center', gap:8, marginBottom:4, flexWrap:'wrap' }}>
                  <span style={{ fontFamily:'JetBrains Mono', fontSize:12, color:t.red, fontWeight:600 }}>{k.cve}</span>
                  <Chip color={t.fgMute} size="xs">{k.vendor}</Chip>
                  <Chip color={t.fgMute} size="xs">{k.product}</Chip>
                  {k.ransomware_use && <Chip color={t.red} soft={t.redDim} size="xs">ransomware</Chip>}
                  {epss && <Chip color={epssColor} soft={`${epssColor}14`} size="xs">
                    EPSS {epss.epss_percent}% · {epss.tier}
                  </Chip>}
                  {k.date_added && <span style={{ fontSize:11, color:t.fgDim, marginLeft:'auto' }}>
                    added {k.date_added}
                  </span>}
                </div>
                <div style={{ fontSize:12, color:t.fg, marginBottom:3 }}>{k.name}</div>
                {k.description && <div style={{ fontSize:11, color:t.fgMute, lineHeight:1.55 }}>{k.description}</div>}
                {k.required_action && (
                  <div style={{ fontSize:11, color:t.orange, marginTop:5 }}>
                    Required action: {k.required_action.slice(0, 180)}
                  </div>
                )}
              </li>
            );
          })}
        </Block>
      )}

      {lolbas.length > 0 && (
        <Block title={`Living-off-the-land binaries · LOLBAS (${lolbas.length})`}>
          {lolbas.map((l,i) => (
            <li key={i} style={{ padding:'8px 0', borderTop: i>0?`1px solid ${t.line}`:'none', listStyle:'none' }}>
              <div style={{ display:'flex', alignItems:'center', gap:8, marginBottom:4, flexWrap:'wrap' }}>
                <span style={{ fontFamily:'JetBrains Mono', fontSize:12, color:t.orange, fontWeight:600 }}>{l.name}</span>
                {l.categories?.slice(0,4).map(c => <Chip key={c} color={t.fgMute} size="xs">{c}</Chip>)}
                {l.url && <a href={l.url} target="_blank" rel="noreferrer"
                  style={{ marginLeft:'auto', fontSize:11, color:t.cy, display:'inline-flex', alignItems:'center', gap:2 }}>
                  details <ArrowUpRight size={11}/>
                </a>}
              </div>
              {l.description && <div style={{ fontSize:11, color:t.fgMute, lineHeight:1.55 }}>{l.description}</div>}
              {l.examples?.length>0 && (
                <ul style={{ margin:'5px 0 0 14px', padding:0, fontSize:11, color:t.fgDim, lineHeight:1.6 }}>
                  {l.examples.slice(0,2).map((e,j) => <li key={j}>{e}</li>)}
                </ul>
              )}
            </li>
          ))}
        </Block>
      )}

      {rmm.length > 0 && (
        <Block title={`Remote-management tools detected · RMM abuse (${rmm.length})`}>
          {rmm.map((r,i) => (
            <li key={i} style={{ padding:'8px 0', borderTop: i>0?`1px solid ${t.line}`:'none', listStyle:'none' }}>
              <div style={{ display:'flex', alignItems:'center', gap:8, marginBottom:4, flexWrap:'wrap' }}>
                <span style={{ fontFamily:'JetBrains Mono', fontSize:12, color:t.orange, fontWeight:600 }}>{r.binary}</span>
                <Chip color={t.fgMute} size="xs">{r.vendor}</Chip>
                {r.groups?.slice(0, 4).map(g => <Chip key={g} color={t.red} soft={t.redDim} size="xs">{g}</Chip>)}
              </div>
              <div style={{ fontSize:11, color:t.fgMute, lineHeight:1.55 }}>{r.description}</div>
            </li>
          ))}
        </Block>
      )}

      {paths.length > 0 && (
        <Block title={`Suspicious filesystem paths (${paths.length})`}>
          {paths.map((p,i) => (
            <li key={i} style={{ padding:'6px 0', borderTop: i>0?`1px solid ${t.line}`:'none', listStyle:'none',
              fontSize:12, color:t.fg }}>
              <span style={{ color:t.orange }}>›</span> {p.label}
            </li>
          ))}
        </Block>
      )}

      {drivers.length > 0 && (
        <Block title={`Vulnerable drivers · LOLDrivers (${drivers.length})`}>
          {drivers.map((d,i) => (
            <li key={i} style={{ padding:'8px 0', borderTop: i>0?`1px solid ${t.line}`:'none', listStyle:'none' }}>
              <div style={{ display:'flex', alignItems:'center', gap:8, marginBottom:4, flexWrap:'wrap' }}>
                <span style={{ fontFamily:'JetBrains Mono', fontSize:12, color:t.red, fontWeight:600 }}>{d.value}</span>
                <Chip color={d.category==='malicious'?t.red:t.orange}
                  soft={d.category==='malicious'?t.redDim:t.orangeDim} size="xs">{d.category}</Chip>
                <Chip color={t.fgMute} size="xs">match: {d.match_type}</Chip>
                {d.mitre && <Chip color={t.blue} soft={t.blueDim} size="xs">{d.mitre}</Chip>}
                {d.ref && <a href={d.ref} target="_blank" rel="noreferrer"
                  style={{ marginLeft:'auto', fontSize:11, color:t.cy, display:'inline-flex', alignItems:'center', gap:2 }}>
                  reference <ArrowUpRight size={11}/>
                </a>}
              </div>
              {d.tags?.length>0 && (
                <div style={{ fontSize:11, color:t.fgMute, marginTop:3 }}>
                  Tags: {d.tags.join(', ')}
                </div>
              )}
            </li>
          ))}
        </Block>
      )}

      {atomic.length > 0 && (
        <Block title={`Attack examples · Atomic Red Team (${atomic.length} techniques)`}>
          {atomic.map((a,i) => (
            <li key={i} style={{ padding:'10px 0', borderTop: i>0?`1px solid ${t.line}`:'none', listStyle:'none' }}>
              <div style={{ fontSize:12, color:t.fg, fontWeight:600, marginBottom:6 }}>
                <span style={{ color:t.blue, fontFamily:'JetBrains Mono', marginRight:8 }}>
                  {a.technique.split(' ')[0]}
                </span>
                {a.technique.split(' - ').slice(1).join(' - ')}
              </div>
              {a.tests.map((tst,j) => (
                <div key={j} style={{ marginBottom:6, paddingLeft:8, borderLeft:`2px solid ${t.line}` }}>
                  <div style={{ fontSize:11, color:t.fg, marginBottom:3 }}>{tst.name}</div>
                  {tst.command && (
                    <pre style={{ background:t.bg, border:`1px solid ${t.line}`, borderRadius:4,
                      padding:'6px 9px', fontSize:11, color:t.cy, fontFamily:'JetBrains Mono',
                      margin:'2px 0', whiteSpace:'pre-wrap', wordBreak:'break-all', maxHeight:80, overflow:'auto' }}>
                      {tst.command.split('\n')[0].slice(0, 200)}
                    </pre>
                  )}
                </div>
              ))}
            </li>
          ))}
        </Block>
      )}
    </Card>
  );
}

/* ─── detection rules (multi-SIEM) — MUI Tabs + CodeBlock ─────────────────── */
function Detection({ result }) {
  const sigma = result?.sigma_rule;
  const kql   = result?.kql_query;
  const valid = result?.response_summary?.sigma_valid;
  const mitre = result?.response_summary?.mitre_techniques || [];
  const siem  = result?.response_summary?.siem_queries || {};
  const tabs = [
    sigma                  && { id:'sigma',       label:'Sigma',                 content:sigma,                  badge: valid===true?'validated':valid===false?'invalid':null },
    kql                    && { id:'kql',         label:'KQL · Sentinel',        content:kql },
    siem.splunk_spl        && { id:'spl',         label:'Splunk SPL',            content:siem.splunk_spl },
    siem.elastic_eql       && { id:'eql',         label:'Elastic EQL',           content:siem.elastic_eql },
    siem.chronicle_yara_l  && { id:'yaral',       label:'Chronicle YARA-L',      content:siem.chronicle_yara_l },
    siem.crowdstrike_fql   && { id:'fql',         label:'CrowdStrike Falcon',    content:siem.crowdstrike_fql },
  ].filter(Boolean);
  const [active, setActive] = useState(tabs[0]?.id);
  if (!tabs.length) return null;

  const cur = tabs.find(x => x.id === (active || tabs[0]?.id)) || tabs[0];

  return (
    <Card title="Detection content & hunt queries" accent={t.cy} badge={`${tabs.length} platforms`}>
      {mitre.length > 0 && (
        <Box sx={{ display:'flex', gap:0.75, flexWrap:'wrap', mb:1.75, alignItems:'center' }}>
          <Typography sx={{ fontSize:11, color:'text.tertiary' }}>Coverage:</Typography>
          {mitre.map((t_, i) => {
            const id = t_.split(' ')[0];
            return (
              <MuiTag key={i} label={id} color="#0fbcff"
                onClick={() => window.open(`https://attack.mitre.org/techniques/${id.includes('.') ? id.replace('.','/') : id}/`, '_blank')}
                sx={{ fontFamily:'"IBM Plex Mono", monospace' }}/>
            );
          })}
        </Box>
      )}

      {/* MUI Tabs strip — inherits indicator color + lowercase styling from theme */}
      <MuiTabs value={cur.id} onChange={(_, v) => setActive(v)} variant="scrollable" scrollButtons="auto"
        sx={{ minHeight:36, mb:1.25, borderBottom: `1px solid ${muiAlpha('#ffffff', 0.12)}` }}>
        {tabs.map(tab => <MuiTab key={tab.id} value={tab.id} label={tab.label} sx={{ minHeight:36, py:0 }}/>)}
      </MuiTabs>

      <Box sx={{ display:'flex', justifyContent:'space-between', alignItems:'center', mb:1 }}>
        <Box sx={{ display:'flex', alignItems:'center', gap:1 }}>
          <Typography sx={{ fontSize:12, color:'text.primary', fontWeight:600 }}>{cur.label}</Typography>
          {cur.badge === 'validated' && <MuiVerdictTag verdict="CLEAN" size="small"/>}
          {cur.badge === 'invalid'   && <MuiVerdictTag verdict="MALICIOUS" size="small"/>}
        </Box>
        <CopyBtn text={cur.content}/>
      </Box>
      <MuiCodeBlock>{cur.content}</MuiCodeBlock>
    </Card>
  );
}

/* ─── JA3/JA4 network detection ──────────────────────────────────────────────── */
function NetworkDetection({ result }) {
  const fps = result?.response_summary?.ja_fingerprints || [];
  const sigma = result?.response_summary?.ja_sigma_snippet;
  const kql   = result?.response_summary?.ja_kql_snippet;
  if (!fps.length) return null;
  return (
    <Card title="Network detection · JA3 / JA4 fingerprints" accent={t.purple}
      badge={`${fps.length} C2 framework${fps.length===1?'':'s'}`} defaultOpen={false}>
      <div style={{ fontSize:12, color:t.fgMute, marginBottom:12, lineHeight:1.6 }}>
        TLS handshake fingerprints for known C2 frameworks relevant to this alert. Hunt these
        in your Zeek / Suricata / EDR network logs to catch the C2 channel itself, not just the IOC.
      </div>
      <div style={{ background:t.raised, border:`1px solid ${t.line}`, borderRadius:6, overflow:'hidden', marginBottom:12 }}>
        <table style={{ width:'100%', borderCollapse:'collapse', fontSize:12 }}>
          <thead>
            <tr style={{ background:t.bg }}>
              {['Framework','JA3','JA4','Notes'].map(h => (
                <th key={h} style={{ padding:'8px 10px', textAlign:'left', color:t.fgDim,
                  fontWeight:500, fontSize:11, borderBottom:`1px solid ${t.line}` }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {fps.map((f, i) => (
              <tr key={i} style={{ borderBottom:`1px solid ${t.line}` }}>
                <td style={{ padding:'7px 10px', color:t.fg, fontWeight:500 }}>{f.framework}</td>
                <td style={{ padding:'7px 10px', fontFamily:'JetBrains Mono', fontSize:11, color:t.cy }}>{f.ja3 || '—'}</td>
                <td style={{ padding:'7px 10px', fontFamily:'JetBrains Mono', fontSize:11, color:t.purple }}>{f.ja4 || '—'}</td>
                <td style={{ padding:'7px 10px', fontSize:11, color:t.fgMute, maxWidth:280 }}>{f.notes}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {sigma && (
        <div style={{ marginBottom:12 }}>
          <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:6 }}>
            <span style={{ fontSize:12, fontWeight:600, color:t.fg }}>Sigma — JA3/JA4 selection</span>
            <CopyBtn text={sigma}/>
          </div>
          <pre style={{ background:t.bg, border:`1px solid ${t.line}`, borderRadius:5, padding:12,
            fontSize:11, color:t.fg, fontFamily:'JetBrains Mono', whiteSpace:'pre-wrap',
            maxHeight:200, overflowY:'auto', margin:0, lineHeight:1.65 }}>{sigma}</pre>
        </div>
      )}
      {kql && (
        <div>
          <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:6 }}>
            <span style={{ fontSize:12, fontWeight:600, color:t.fg }}>KQL — let statements for Sentinel</span>
            <CopyBtn text={kql}/>
          </div>
          <pre style={{ background:t.bg, border:`1px solid ${t.line}`, borderRadius:5, padding:12,
            fontSize:11, color:t.fg, fontFamily:'JetBrains Mono', whiteSpace:'pre-wrap',
            maxHeight:200, overflowY:'auto', margin:0, lineHeight:1.65 }}>{kql}</pre>
        </div>
      )}
    </Card>
  );
}

/* ─── URLScan live submission ────────────────────────────────────────────────── */
function URLScanLive({ result }) {
  const urls = result?.iocs?.urls || [];
  const [target, setTarget] = useState(urls[0] || '');
  const [submission, setSubmission] = useState(null);

  // Update default target when URLs change
  useEffect(() => {
    if (urls[0] && !target) setTarget(urls[0]);
  }, [urls, target]);

  const submit = async () => {
    if (!target) return;
    setSubmission({ state: 'submitting', url: target });
    try {
      const r = await fetch('/api/urlscan/submit', {
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({ url: target, visibility:'unlisted' }),
      });
      const d = await r.json();
      if (!r.ok) throw new Error(d.detail || d.error || `HTTP ${r.status}`);
      setSubmission({ state:'polling', url:target, uuid:d.uuid, result_url:d.result_url });
    } catch (e) {
      setSubmission({ state:'error', url:target, error:e.message });
    }
  };

  // Poll until ready or 3 minutes elapsed
  useEffect(() => {
    if (submission?.state !== 'polling' || !submission?.uuid) return;
    let attempts = 0;
    const poll = async () => {
      attempts++;
      try {
        const r = await fetch(`/api/urlscan/result/${submission.uuid}`);
        const d = await r.json();
        if (d.ready) {
          setSubmission(s => ({ ...s, state:'done', report:d }));
        } else if (attempts > 18) { // ~3 min
          setSubmission(s => ({ ...s, state:'timeout' }));
        }
      } catch (e) {}
    };
    const interval = setInterval(poll, 10000);
    poll();
    return () => clearInterval(interval);
  }, [submission?.state, submission?.uuid]);

  if (!urls.length) return null;
  return (
    <Card title="Live URL scan · URLScan.io" accent={t.cy} defaultOpen={false}
      badge={`${urls.length} URL${urls.length===1?'':'s'} available`}>
      <div style={{ display:'flex', gap:8, marginBottom:12 }}>
        <select value={target} onChange={e => setTarget(e.target.value)}
          style={{ flex:1, background:t.raised, border:`1px solid ${t.line}`, color:t.fg,
            padding:'7px 10px', borderRadius:5, fontSize:12, fontFamily:'JetBrains Mono' }}>
          {urls.map(u => <option key={u} value={u}>{u.length>80 ? u.slice(0,77)+'…' : u}</option>)}
        </select>
        <button onClick={submit} disabled={submission?.state === 'submitting' || submission?.state === 'polling'}
          style={{ background:t.cyDim, border:`1px solid ${t.cyLine}`, color:t.cy,
            padding:'7px 14px', borderRadius:5, cursor:'pointer', fontSize:12, fontWeight:600,
            opacity: (submission?.state === 'submitting' || submission?.state === 'polling') ? 0.6 : 1 }}>
          Submit
        </button>
      </div>

      {submission?.state === 'submitting' && <div style={{ fontSize:12, color:t.fgMute }}>Submitting to URLScan…</div>}
      {submission?.state === 'polling'    && <div style={{ fontSize:12, color:t.cy }}>Scan in progress — polling every 10s (typically 30–60s)…</div>}
      {submission?.state === 'timeout'    && <div style={{ fontSize:12, color:t.orange }}>Scan still processing after 3 min. View it directly: <a href={submission.result_url} target="_blank" rel="noreferrer" style={{ color:t.cy }}>{submission.result_url}</a></div>}
      {submission?.state === 'error'      && <div style={{ fontSize:12, color:t.red }}>{submission.error}</div>}

      {submission?.state === 'done' && submission.report && (() => {
        const r = submission.report;
        const verdictColor = r.verdict === 'malicious' ? t.red
          : r.verdict === 'suspicious' ? t.orange : t.green;
        return (
          <div style={{ background:t.raised, border:`1px solid ${t.line}`,
            borderLeft:`3px solid ${verdictColor}`, borderRadius:6, padding:'14px 16px' }}>
            <div style={{ display:'flex', justifyContent:'space-between', alignItems:'flex-start', marginBottom:12, gap:12 }}>
              <div>
                <div style={{ display:'flex', alignItems:'center', gap:8, marginBottom:4 }}>
                  <Chip color={verdictColor} soft={`${verdictColor}14`}>verdict: {r.verdict}</Chip>
                  {r.score != null && <Chip color={t.orange} size="xs">score {r.score}</Chip>}
                  {r.country && <Chip color={t.fgMute} size="xs">{r.country}</Chip>}
                </div>
                {r.page_title && <div style={{ fontSize:13, color:t.fg, fontWeight:500, marginBottom:4 }}>{r.page_title}</div>}
                <div style={{ fontSize:11, color:t.fgMute, fontFamily:'JetBrains Mono', wordBreak:'break-all' }}>{r.final_url}</div>
              </div>
              <a href={r.report_url} target="_blank" rel="noreferrer"
                style={{ fontSize:11, color:t.cy, display:'inline-flex', alignItems:'center', gap:3, flexShrink:0 }}>
                full report <ArrowUpRight size={11}/>
              </a>
            </div>
            {r.screenshot && (
              <a href={r.screenshot} target="_blank" rel="noreferrer">
                <img src={r.screenshot} alt="URLScan screenshot"
                  style={{ width:'100%', maxWidth:560, borderRadius:4, border:`1px solid ${t.line}`,
                    display:'block', marginBottom:12 }}/>
              </a>
            )}
            <div style={{ display:'grid', gridTemplateColumns:'repeat(2,1fr)', gap:8, fontSize:11 }}>
              {r.ip      && <div><span style={{ color:t.fgDim }}>IP:</span> <span style={{ color:t.fg, fontFamily:'JetBrains Mono' }}>{r.ip}</span></div>}
              {r.asnname && <div><span style={{ color:t.fgDim }}>ASN:</span> <span style={{ color:t.fg }}>{r.asnname}</span></div>}
              {r.server  && <div><span style={{ color:t.fgDim }}>Server:</span> <span style={{ color:t.fg }}>{r.server}</span></div>}
              {r.urls_loaded != null && <div><span style={{ color:t.fgDim }}>Page loaded:</span> <span style={{ color:t.fg }}>{r.urls_loaded} URLs / {r.requests} requests</span></div>}
            </div>
            {r.categories?.length > 0 && (
              <div style={{ display:'flex', gap:4, flexWrap:'wrap', marginTop:8 }}>
                {r.categories.map(c => <Chip key={c} color={t.fgMute} size="xs">{c}</Chip>)}
              </div>
            )}
          </div>
        );
      })()}
    </Card>
  );
}

/* ─── enrichments ─────────────────────────────────────────────────────────────── */
function Enrichments({ enrichments }) {
  if (!enrichments || !Object.keys(enrichments).length) return null;
  return (
    <Card title="Raw enrichment data" accent={t.fgMute} defaultOpen={false}>
      {Object.entries(enrichments).map(([iocType, iocMap])=>
        Object.entries(iocMap||{}).map(([ioc, data])=>(
          <div key={ioc} style={{ marginBottom:16 }}>
            <div style={{ display:'flex', alignItems:'center', gap:8, marginBottom:8 }}>
              <TypeTag type={iocType}/>
              <span style={{ fontSize:12, color:t.fg, fontFamily:'JetBrains Mono', wordBreak:'break-all' }}>{ioc}</span>
            </div>
            <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fill,minmax(240px,1fr))', gap:6 }}>
              {Object.entries(data).filter(([k])=>k!=='cached').map(([src,srcData])=>{
                if (!srcData||typeof srcData!=='object') return null;
                const entries=Object.entries(srcData).filter(([,v])=>v!==null&&v!==undefined&&v!==''&&!(Array.isArray(v)&&!v.length));
                if (!entries.length) return null;
                return (
                  <div key={src} style={{ background:t.raised, border:`1px solid ${t.line}`, borderRadius:5, padding:10 }}>
                    <div style={{ fontSize:11, color:t.cy, fontWeight:600, marginBottom:6 }}>{src}</div>
                    {entries.slice(0,6).map(([k,v])=>(
                      <div key={k} style={{ display:'flex', justifyContent:'space-between', fontSize:11,
                        padding:'2px 0', gap:8 }}>
                        <span style={{ color:t.fgDim, flexShrink:0 }}>{k}</span>
                        <span style={{ color:t.fg, textAlign:'right', wordBreak:'break-all', maxWidth:140,
                          fontFamily:'JetBrains Mono' }}>
                          {Array.isArray(v)?v.slice(0,4).join(', '):String(v).slice(0,80)}
                        </span>
                      </div>
                    ))}
                  </div>
                );
              })}
            </div>
          </div>
        ))
      )}
    </Card>
  );
}

/* ─── report ──────────────────────────────────────────────────────────────────── */
function Report({ result }) {
  const ref = useRef(null);
  const [analyst, setAnalyst] = useState('');
  const [notes, setNotes]     = useState('');
  if (!result) return null;
  const rs   = result.response_summary || {};
  const lc   = levelStyle[rs.threat_level] || levelStyle.INFORMATIONAL;
  const ts   = rs.timestamp ? new Date(rs.timestamp) : new Date();
  const iocs = result.iocs || {};
  const total = Object.values(iocs).flat().length;

  const print = () => {
    const w = window.open('','_blank');
    w.document.write(`<html><head><title>RECON Investigation Report</title>
      <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
      <style>body{font-family:Inter,system-ui,sans-serif;background:#0a0e16;color:#e8eaed;padding:48px;font-size:13px;line-height:1.7}
      pre{background:#10141f;padding:14px;border-radius:6px;font-size:11px;white-space:pre-wrap;word-break:break-all;font-family:'JetBrains Mono',monospace}
      table{border-collapse:collapse;width:100%}td,th{padding:6px 10px;text-align:left;border-bottom:1px solid rgba(255,255,255,0.06)}
      @media print{body{background:#fff;color:#111;padding:24px}}
      </style></head><body>${ref.current.innerHTML}</body></html>`);
    w.document.close(); setTimeout(()=>w.print(),400);
  };

  const inputStyle = { background:t.raised, border:`1px solid ${t.line}`, color:t.fg,
    padding:'8px 11px', borderRadius:5, fontSize:13, outline:'none', width:'100%',
    boxSizing:'border-box', fontFamily:'inherit', transition:'border-color .15s' };

  return (
    <Card title="Investigation report" accent={t.purple} defaultOpen={false} badge={`${total} indicators`}>
      <div style={{ display:'flex', justifyContent:'flex-end', marginBottom:14 }}>
        <button onClick={print} data-recon-print style={{ background:t.purpleDim, border:`1px solid ${t.purple}40`,
          color:t.purple, padding:'7px 14px', borderRadius:5, cursor:'pointer', fontSize:12, fontWeight:500,
          display:'inline-flex', alignItems:'center', gap:6 }}>
          <Printer size={12}/>Print / Save PDF
        </button>
      </div>

      <div ref={ref} style={{ background:t.bg, border:`1px solid ${t.line}`, borderRadius:6, padding:28 }}>
        <header style={{ display:'flex', justifyContent:'space-between', alignItems:'flex-end',
          marginBottom:22, paddingBottom:16, borderBottom:`1px solid ${t.line}` }}>
          <div>
            <h1 style={{ fontSize:20, color:t.fg, fontWeight:700, letterSpacing:'-0.02em', margin:0 }}>
              Threat intelligence report
            </h1>
            <div style={{ fontSize:12, color:t.fgDim, marginTop:4 }}>RECON Platform</div>
          </div>
          <div style={{ textAlign:'right', fontSize:12, color:t.fgMute }}>
            <div style={{ fontVariantNumeric:'tabular-nums' }}>{ts.toLocaleDateString()}</div>
            <div style={{ fontVariantNumeric:'tabular-nums' }}>{ts.toLocaleTimeString()}</div>
          </div>
        </header>

        <div style={{ marginBottom:18 }}>
          <label style={{ fontSize:12, color:t.fgDim, display:'block', marginBottom:6 }}>Analyst</label>
          <input value={analyst} onChange={e=>setAnalyst(e.target.value)} placeholder="Your name" style={inputStyle}/>
        </div>

        <div style={{ background:lc.bg, border:`1px solid ${lc.line}`, borderRadius:6,
          padding:'14px 16px', marginBottom:20 }}>
          <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:8 }}>
            <div style={{ display:'flex', alignItems:'center', gap:8 }}>
              <span style={{ width:8, height:8, borderRadius:99, background:lc.fg }}/>
              <span style={{ color:lc.fg, fontWeight:600, fontSize:13 }}>{rs.threat_level}</span>
            </div>
            <span style={{ fontSize:12, color:t.fgMute }}>
              Confidence {Math.round((rs.confidence||0)*100)}%
            </span>
          </div>
          <p style={{ fontSize:13, color:t.fg, lineHeight:1.7, margin:0 }}>{rs.summary}</p>
        </div>

        <h3 style={{ fontSize:13, color:t.fgMute, fontWeight:500, margin:'0 0 8px 0' }}>
          Indicator inventory · {total}
        </h3>
        <table style={{ width:'100%', borderCollapse:'collapse', fontSize:12, marginBottom:20 }}>
          <thead>
            <tr>
              {['Type','Indicator','Verdict','Reason'].map(h=>(
                <th key={h} style={{ padding:'8px 10px', textAlign:'left', color:t.fgDim,
                  fontWeight:500, fontSize:11, borderBottom:`1px solid ${t.lineHi}` }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {Object.entries(iocs).flatMap(([type,list])=>(list||[]).map((ioc)=>{
              const a = rs.ioc_assessments?.find(x=>x.ioc===ioc);
              return (
                <tr key={ioc} style={{ borderBottom:`1px solid ${t.line}` }}>
                  <td style={{ padding:'8px 10px' }}><TypeTag type={type}/></td>
                  <td style={{ padding:'8px 10px', fontFamily:'JetBrains Mono', color:t.fg, wordBreak:'break-all' }}>{ioc}</td>
                  <td style={{ padding:'8px 10px' }}>{a&&<Verdict verdict={a.verdict} size="xs"/>}</td>
                  <td style={{ padding:'8px 10px', fontSize:11, color:t.fgMute, maxWidth:240 }}>{a?.reason||''}</td>
                </tr>
              );
            }))}
          </tbody>
        </table>

        {rs.mitre_techniques?.length>0 && (
          <>
            <h3 style={{ fontSize:13, color:t.fgMute, fontWeight:500, margin:'0 0 8px 0' }}>MITRE ATT&amp;CK</h3>
            <div style={{ display:'flex', gap:4, flexWrap:'wrap', marginBottom:20 }}>
              {rs.mitre_techniques.map((t_,i)=>(
                <span key={i} style={{ background:t.blueDim, border:`1px solid ${t.blue}30`, color:t.blue,
                  padding:'3px 8px', borderRadius:4, fontSize:11, fontFamily:'JetBrains Mono' }}>{t_}</span>
              ))}
            </div>
          </>
        )}

        {result.sigma_rule && (
          <>
            <h3 style={{ fontSize:13, color:t.fgMute, fontWeight:500, margin:'0 0 8px 0' }}>Sigma detection rule</h3>
            <pre style={{ background:t.raised, border:`1px solid ${t.line}`, borderRadius:5, padding:12,
              fontSize:11, color:t.fg, fontFamily:'JetBrains Mono', maxHeight:200, overflowY:'auto',
              margin:'0 0 20px 0', whiteSpace:'pre-wrap', lineHeight:1.6 }}>{result.sigma_rule}</pre>
          </>
        )}

        {rs.recommended_actions?.length>0 && (
          <>
            <h3 style={{ fontSize:13, color:t.fgMute, fontWeight:500, margin:'0 0 8px 0' }}>Recommended actions</h3>
            <ol style={{ paddingLeft:20, marginBottom:20 }}>
              {rs.recommended_actions.map((a,i)=>(
                <li key={i} style={{ fontSize:13, color:t.fg, lineHeight:1.7, marginBottom:4 }}>{a}</li>
              ))}
            </ol>
          </>
        )}

        <h3 style={{ fontSize:13, color:t.fgMute, fontWeight:500, margin:'0 0 8px 0' }}>Analyst notes</h3>
        <textarea value={notes} onChange={e=>setNotes(e.target.value)}
          placeholder="Add observations, context, or follow-up items..."
          style={{ ...inputStyle, resize:'vertical', lineHeight:1.7, minHeight:90 }}/>

        <div style={{ borderTop:`1px solid ${t.line}`, paddingTop:14, marginTop:20,
          display:'flex', justifyContent:'space-between', fontSize:11, color:t.fgDim }}>
          <span style={{ fontVariantNumeric:'tabular-nums' }}>{ts.toISOString()}</span>
          <span>Confidential — Internal use only</span>
        </div>
      </div>
    </Card>
  );
}

/* ─── sidebar ─────────────────────────────────────────────────────────────────
 * Adapted from OpenCTI (AGPL-3.0) — LeftBar.jsx pattern.
 * Uses MUI Drawer with the OpenCTI nav width/styling, hosting the input area
 * (drop zone + textarea + AgentPipeline) and the extracted-IOCs panel.
 */
function Sidebar({ onResult, onPartialResult, currentResult }) {
  const [logText, setLogText] = useState('');
  const [dragOver, setDragOver] = useState(false);

  const handleFile = useCallback(file => {
    if (!file) return;
    const r = new FileReader();
    r.onload = e => setLogText(e.target.result);
    r.readAsText(file);
  }, []);

  // Cmd/Ctrl+Enter triggers analysis via the AgentPipeline's button
  useEffect(() => {
    const handler = (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') {
        const btn = document.querySelector('[data-recon-analyze]');
        btn?.click();
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, []);

  const iocs = currentResult?.iocs || {};
  const hasIOCs = Object.values(iocs).some(l=>l?.length>0);

  const SIDEBAR_WIDTH = 320;

  return (
    <MuiDrawer
      variant="permanent"
      anchor="left"
      sx={{
        width: SIDEBAR_WIDTH, flexShrink: 0,
        '& .MuiDrawer-paper': {
          width: SIDEBAR_WIDTH, boxSizing: 'border-box',
          display: 'flex', flexDirection: 'column',
          overflowX: 'hidden',
        },
      }}
    >
      {/* Logo header */}
      <Box sx={{
        p: '18px 14px 16px',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        borderBottom: `1px solid ${muiAlpha('#ffffff', 0.12)}`,
      }}>
        <Box component="img" src="/logo.png" alt="RECON"
          sx={{ width: '100%', maxWidth: 200, height: 'auto', display: 'block',
            filter: 'drop-shadow(0 0 18px rgba(15,188,255,0.35))' }}/>
      </Box>

      {/* Input area + pipeline */}
      <Box sx={{ p: '18px 16px 16px', flex: 1, overflowY: 'auto' }}>
        <Typography variant="caption" sx={{
          display: 'block', mb: 1.25, fontSize: 11, fontWeight: 500,
          color: 'text.tertiary', textTransform: 'uppercase', letterSpacing: '0.06em',
        }}>
          New investigation
        </Typography>

        {/* Drop zone */}
        <Box
          onDragOver={e=>{e.preventDefault();setDragOver(true);}}
          onDragLeave={()=>setDragOver(false)}
          onDrop={e=>{e.preventDefault();setDragOver(false);handleFile(e.dataTransfer.files[0]);}}
          onClick={()=>document.getElementById('sidebarFile').click()}
          sx={{
            border: theme => `1.5px dashed ${dragOver ? theme.palette.primary.main : muiAlpha('#ffffff', 0.12)}`,
            borderRadius: '4px',
            p: '18px 12px',
            textAlign: 'center', cursor: 'pointer',
            backgroundColor: dragOver ? muiAlpha('#0fbcff', 0.08) : 'transparent',
            mb: 1.25,
            transition: 'all .15s',
          }}
        >
          <Upload size={18} color={dragOver ? '#0fbcff' : '#848592'}
            style={{ margin: '0 auto 6px', display: 'block' }}/>
          <Typography sx={{
            color: dragOver ? 'primary.main' : 'text.secondary',
            fontSize: 12, fontWeight: 500,
          }}>
            Drop a file
          </Typography>
          <Typography sx={{ color: 'text.tertiary', fontSize: 11, mt: 0.25 }}>
            .log .txt .csv .json .eml
          </Typography>
          <input id="sidebarFile" type="file" accept=".log,.txt,.csv,.json,.eml"
            style={{ display: 'none' }} onChange={e=>handleFile(e.target.files[0])}/>
        </Box>

        {/* Textarea with clear button */}
        <Box sx={{ position: 'relative', mb: 1.25 }}>
          <Box component="textarea"
            value={logText} onChange={e=>setLogText(e.target.value)}
            placeholder="Or paste alert text, IOCs, log lines, EML headers..."
            sx={{
              width: '100%',
              backgroundColor: 'background.secondary',
              border: `1px solid ${muiAlpha('#ffffff', 0.12)}`,
              color: 'text.primary',
              p: '10px 12px',
              borderRadius: '4px',
              fontFamily: '"IBM Plex Mono", monospace',
              fontSize: 12,
              resize: 'vertical',
              outline: 'none',
              lineHeight: 1.6,
              minHeight: 128,
              boxSizing: 'border-box',
              '&:focus': { borderColor: 'primary.main' },
            }}/>
          {logText && (
            <MuiIconButton
              onClick={()=>setLogText('')}
              title="Clear input"
              size="small"
              sx={{ position: 'absolute', top: 4, right: 4, color: 'text.tertiary',
                '&:hover': { color: 'text.primary' } }}
            >
              <X size={14}/>
            </MuiIconButton>
          )}
        </Box>

        <AgentPipeline logText={logText} label=""
          onComplete={onResult}
          onPartial={onPartialResult}
          onStart={()=>onResult(null)}/>

        {/* Extracted indicators */}
        {hasIOCs && (
          <Box sx={{ mt: 2.25 }}>
            <Typography variant="caption" sx={{
              display: 'block', mb: 1.25, fontSize: 11, fontWeight: 500,
              color: 'text.tertiary', textTransform: 'uppercase', letterSpacing: '0.06em',
            }}>
              Extracted indicators
            </Typography>
            <Box sx={{
              backgroundColor: 'background.secondary',
              border: `1px solid ${muiAlpha('#ffffff', 0.12)}`,
              borderRadius: '4px',
              p: '10px 12px',
            }}>
              {Object.entries(iocs).map(([type, list]) =>
                list?.length > 0 && (
                  <Box key={type} sx={{ mb: 1.25 }}>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.75, mb: 0.625 }}>
                      <TypeTag type={type}/>
                      <Typography sx={{ fontSize: 11, color: 'text.tertiary' }}>{list.length}</Typography>
                    </Box>
                    {list.map(ioc => (
                      <Box key={ioc} sx={{
                        fontSize: 11, color: 'text.primary',
                        fontFamily: '"IBM Plex Mono", monospace',
                        wordBreak: 'break-all', overflowWrap: 'anywhere',
                        padding: '1px 0', lineHeight: 1.5, minWidth: 0,
                      }}>{ioc}</Box>
                    ))}
                  </Box>
                )
              )}
            </Box>
          </Box>
        )}
      </Box>

      {/* Footer */}
      <Box sx={{
        p: '12px 16px',
        borderTop: `1px solid ${muiAlpha('#ffffff', 0.12)}`,
        fontSize: 11, color: 'text.disabled',
        display: 'flex', justifyContent: 'space-between',
      }}>
        <span>RECON v1.0</span>
        <span style={{ fontVariantNumeric: 'tabular-nums' }}>
          <Box component="kbd" sx={{
            backgroundColor: 'background.accent',
            border: `1px solid ${muiAlpha('#ffffff', 0.12)}`,
            borderRadius: '3px',
            p: '1px 5px', fontSize: 10,
            fontFamily: '"IBM Plex Mono", monospace',
          }}>⌘</Box>{' '}
          <Box component="kbd" sx={{
            backgroundColor: 'background.accent',
            border: `1px solid ${muiAlpha('#ffffff', 0.12)}`,
            borderRadius: '3px',
            p: '1px 5px', fontSize: 10,
            fontFamily: '"IBM Plex Mono", monospace',
          }}>↵</Box>
        </span>
      </Box>
    </MuiDrawer>
  );
}

/* ─── empty state (minimal — analyst pastes into the sidebar to begin) ───────── */
function Empty() {
  return null;
}

/* ─── IOC pivot (cross-run sightings) ────────────────────────────────────────── */
function IOCPivot({ result }) {
  const pivots = result?.ioc_pivot || [];
  if (!pivots.length) return null;
  return (
    <Card title="Cross-investigation pivot" accent={t.orange}
      badge={`${pivots.length} indicator${pivots.length===1?'':'s'} seen before`}>
      <div style={{ fontSize:12, color:t.fgMute, marginBottom:10, lineHeight:1.6 }}>
        These indicators have appeared in previous investigations during this session. Consider whether the
        cases are related — same actor, same campaign, or rolling reinvestigation.
      </div>
      {pivots.map((p, i) => (
        <div key={i} style={{ padding:'10px 0', borderTop: i>0?`1px solid ${t.line}`:'none' }}>
          <div style={{ display:'flex', alignItems:'center', gap:8, marginBottom:4 }}>
            <TypeTag type={p.type}/>
            <span style={{ fontFamily:'JetBrains Mono', fontSize:12, color:t.fg, wordBreak:'break-all' }}>{p.ioc}</span>
          </div>
          <div style={{ display:'flex', gap:6, flexWrap:'wrap', marginLeft:24 }}>
            {p.sightings.map((s, j) => {
              const c = (levelStyle[s.threat_level] || levelStyle.INFORMATIONAL).fg;
              const url = `${window.location.pathname}#run/${s.run_id}`;
              const when = new Date(s.timestamp);
              const ago = (() => {
                const m = Math.round((Date.now() - when.getTime()) / 60000);
                return m < 60 ? `${m}m ago` : m < 1440 ? `${Math.round(m/60)}h ago` : `${Math.round(m/1440)}d ago`;
              })();
              return (
                <a key={j} href={url} style={{ background:t.raised, border:`1px solid ${t.line}`,
                  borderLeft:`2px solid ${c}`, borderRadius:4, padding:'4px 9px', fontSize:11, color:t.fg,
                  textDecoration:'none', display:'inline-flex', gap:6, alignItems:'center' }}>
                  <span style={{ color:c, fontWeight:600 }}>{s.threat_level}</span>
                  <span style={{ color:t.fgDim }}>· {ago}</span>
                  <span style={{ color:t.fgGhost, fontFamily:'JetBrains Mono' }}>{s.run_id.slice(0,8)}</span>
                </a>
              );
            })}
          </div>
        </div>
      ))}
    </Card>
  );
}

/* ─── bulk IOC table view ─────────────────────────────────────────────────────── */
function BulkTable({ result }) {
  const iocs = result?.iocs || {};
  const rs   = result?.response_summary || {};
  const gti  = result?.gti_scores || {};
  const enr  = result?.enrichments || {};

  const rows = [];
  for (const [type, list] of Object.entries(iocs)) {
    for (const ioc of list || []) {
      const a   = rs.ioc_assessments?.find(x => x.ioc === ioc);
      const g   = gti[ioc] || {};
      const d   = (enr[type] || {})[ioc] || {};
      const meta = [];
      if (d.virustotal?.malicious != null) meta.push(`VT ${d.virustotal.malicious}`);
      if (d.abuseipdb?.abuseScore)         meta.push(`Abuse ${d.abuseipdb.abuseScore}%`);
      if (d.greynoise?.classification)     meta.push(`GN ${d.greynoise.classification}`);
      if (d.tor?.isExitNode)               meta.push('Tor');
      if (d.heuristics?.nrd?.is_same_day)  meta.push('reg-today');
      if (d.heuristics?.dga?.flagged)      meta.push('DGA');
      if (d.local_feeds?.hit)              meta.push('blocklist');
      rows.push({
        type, ioc,
        verdict: a?.verdict || g.verdict || 'UNKNOWN',
        score:   g.score,
        country: d.ipinfo?.country || '',
        reason:  a?.reason || g.label || '',
        meta:    meta.join(' · '),
      });
    }
  }
  rows.sort((a, b) => (b.score || 0) - (a.score || 0));

  const exportCSV = () => {
    const cols = ['type','ioc','verdict','score','country','reason','flags'];
    const q = v => `"${String(v ?? '').replace(/"/g, '""')}"`;
    const lines = [cols.join(',')].concat(rows.map(r =>
      [r.type, r.ioc, r.verdict, r.score ?? '', r.country, r.reason, r.meta].map(q).join(',')
    ));
    const blob = new Blob([lines.join('\n')], { type:'text/csv' });
    const url  = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = `recon-bulk-${Date.now()}.csv`; a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <Card title={`Bulk indicator matrix · ${rows.length} indicators`} accent={t.cy}>
      <Box sx={{ display:'flex', justifyContent:'flex-end', mb:1.25 }}>
        <MuiButton size="small" variant="outlined" onClick={exportCSV} sx={{ height:26 }}>Export CSV</MuiButton>
      </Box>
      <MuiTableContainer component={Box} sx={{
        backgroundColor: 'background.secondary',
        border: `1px solid ${muiAlpha('#ffffff', 0.12)}`,
        borderRadius: '4px',
      }}>
        <MuiTable size="small">
          <MuiTableHead>
            <MuiTableRow>
              {['Type','Indicator','Verdict','Score','Country','Signals','Reason'].map(h =>
                <MuiTableCell key={h}>{h}</MuiTableCell>
              )}
            </MuiTableRow>
          </MuiTableHead>
          <MuiTableBody>
            {rows.map((r, i) => {
              const c = verdictStyle[r.verdict] || t.fgMute;
              return (
                <MuiTableRow key={`${r.type}-${r.ioc}-${i}`} hover>
                  <MuiTableCell><TypeTag type={r.type}/></MuiTableCell>
                  <MuiTableCell sx={{
                    fontFamily:'"IBM Plex Mono", monospace',
                    wordBreak:'break-all', maxWidth:260,
                  }}>{r.ioc}</MuiTableCell>
                  <MuiTableCell><Verdict verdict={r.verdict} size="small"/></MuiTableCell>
                  <MuiTableCell sx={{ color:c, fontWeight:600, fontVariantNumeric:'tabular-nums' }}>
                    {r.score ?? '—'}
                  </MuiTableCell>
                  <MuiTableCell sx={{ color:'text.tertiary', fontSize:11 }}>{r.country || '—'}</MuiTableCell>
                  <MuiTableCell sx={{ color:'warning.main', fontSize:11 }}>{r.meta || '—'}</MuiTableCell>
                  <MuiTableCell sx={{ color:'text.tertiary', fontSize:11, maxWidth:280 }}>{r.reason || '—'}</MuiTableCell>
                </MuiTableRow>
              );
            })}
          </MuiTableBody>
        </MuiTable>
      </MuiTableContainer>
    </Card>
  );
}

/* ─── send-to-webhook button (Slack / Teams / TheHive / generic) ──────────────── */
function SendToWebhook({ result, available }) {
  const [open, setOpen] = useState(false);
  const [status, setStatus] = useState(null);
  const targets = Object.entries(available || {}).filter(([, ok]) => ok);
  if (!result?.runId || !targets.length) return null;

  const send = async (target) => {
    setStatus({ target, state: 'sending' });
    try {
      const r = await fetch(`/api/webhook/${target}/${result.runId}`, { method: 'POST' });
      const data = await r.json();
      setStatus({ target, state: r.ok && data.ok !== false ? 'ok' : 'err', detail: data });
      setTimeout(() => setStatus(null), 3000);
    } catch (e) {
      setStatus({ target, state: 'err', detail: e.message });
      setTimeout(() => setStatus(null), 3000);
    }
    setOpen(false);
  };

  const targetLabels = {
    slack:   'Slack',
    teams:   'Microsoft Teams',
    thehive: 'TheHive',
    opencti: 'OpenCTI (report + observables)',
    generic: 'Webhook',
  };

  return (
    <div style={{ position:'relative' }}>
      <button onClick={() => setOpen(o => !o)} style={{ background:t.surface, border:`1px solid ${t.line}`,
        color:t.fgMute, padding:'6px 12px', borderRadius:6, cursor:'pointer', fontSize:12,
        display:'inline-flex', alignItems:'center', gap:6 }}>
        <ArrowUpRight size={12}/>Send to…
      </button>
      {open && (
        <div style={{ position:'absolute', top:'100%', right:0, marginTop:4,
          background:t.surface, border:`1px solid ${t.lineHi}`, borderRadius:6,
          boxShadow:'0 8px 24px rgba(0,0,0,0.4)', zIndex:50, minWidth:170, padding:4 }}>
          {targets.map(([target]) => (
            <button key={target} onClick={() => send(target)}
              style={{ width:'100%', background:'transparent', border:'none', color:t.fg,
                padding:'8px 12px', textAlign:'left', cursor:'pointer', fontSize:13, borderRadius:4 }}
              onMouseEnter={e => e.currentTarget.style.background = t.hover}
              onMouseLeave={e => e.currentTarget.style.background = 'transparent'}>
              {targetLabels[target] || target}
            </button>
          ))}
        </div>
      )}
      {status && (
        <div style={{ position:'absolute', top:'calc(100% + 8px)', right:0,
          background:t.raised, border:`1px solid ${status.state==='ok'?t.green:status.state==='err'?t.red:t.cy}40`,
          borderRadius:5, padding:'7px 11px', fontSize:11, color:status.state==='ok'?t.green:status.state==='err'?t.red:t.cy,
          whiteSpace:'nowrap' }}>
          {status.state === 'sending' && `Sending to ${status.target}…`}
          {status.state === 'ok'      && `Sent to ${status.target}`}
          {status.state === 'err'     && `Failed: ${status.detail?.error || 'unknown'}`}
        </div>
      )}
    </div>
  );
}

/* ─── YARA file scanner section ───────────────────────────────────────────────── */
function FileScanner() {
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [file, setFile] = useState(null);                  // keep file ref for resubmit
  const [submission, setSubmission] = useState(null);      // {job_id, state, summary, submitted_at}

  const scan = async (uploaded) => {
    if (!uploaded) return;
    setScanning(true); setError(null); setResult(null); setSubmission(null); setFile(uploaded);
    const form = new FormData();
    form.append('file', uploaded);
    try {
      const resp = await fetch('/api/scan-file', { method:'POST', body: form });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.detail || `HTTP ${resp.status}`);
      setResult(data);
    } catch (e) {
      setError(e.message);
    } finally { setScanning(false); }
  };

  const detonate = async () => {
    if (!file) return;
    setError(null);
    const form = new FormData();
    form.append('file', file);
    try {
      const resp = await fetch('/api/sandbox/submit', { method:'POST', body: form });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.detail || `HTTP ${resp.status}`);
      setSubmission({ job_id: data.job_id, state: 'IN_QUEUE', submitted_at: data.submitted_at });
    } catch (e) { setError(e.message); }
  };

  // Poll submission status every 30s until terminal state
  useEffect(() => {
    if (!submission?.job_id) return;
    if (['SUCCESS', 'ERROR'].includes(submission.state)) return;
    const poll = async () => {
      try {
        const r = await fetch(`/api/sandbox/job/${submission.job_id}`);
        const d = await r.json();
        setSubmission(s => ({ ...s, ...d }));
      } catch (e) {}
    };
    const t = setInterval(poll, 30000);
    poll();
    return () => clearInterval(t);
  }, [submission?.job_id, submission?.state]);

  const hasReport = result?.sandbox && Object.keys(result.sandbox).length > 0;

  return (
    <Card title="YARA file scanner" accent={t.purple} defaultOpen={false}
      badge="binary analysis">
      <div style={{ display:'flex', alignItems:'center', gap:10, marginBottom:result?14:0 }}>
        <label htmlFor="yaraFile" style={{
          flex:1, padding:'12px 14px', background:t.raised, border:`1.5px dashed ${t.line}`,
          borderRadius:6, cursor:'pointer', display:'flex', alignItems:'center', gap:10,
          color:t.fgMute, fontSize:13 }}>
          <FileSearch size={16} color={t.purple}/>
          {scanning ? 'Scanning…' : 'Drop or click to scan a file (≤ 50 MB)'}
          <input id="yaraFile" type="file" style={{ display:'none' }}
            onChange={e => scan(e.target.files[0])} disabled={scanning}/>
        </label>
      </div>
      {error && <div style={{ color:t.red, fontSize:12, marginBottom:10 }}>{error}</div>}
      {result && (
        <>
          <div style={{ background:t.raised, border:`1px solid ${t.line}`, borderRadius:6,
            padding:'10px 12px', marginBottom:10 }}>
            <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:8 }}>
              <span style={{ fontSize:13, fontWeight:600, color:t.fg }}>{result.filename}</span>
              <span style={{ fontSize:11, color:t.fgDim }}>{(result.size/1024).toFixed(1)} KB</span>
            </div>
            {['md5','sha1','sha256'].map(k => (
              <div key={k} style={{ display:'flex', gap:8, fontSize:11, padding:'2px 0' }}>
                <span style={{ color:t.fgDim, minWidth:50 }}>{k}</span>
                <span style={{ color:t.fg, fontFamily:'JetBrains Mono', wordBreak:'break-all' }}>
                  {result.hashes[k]}
                </span>
              </div>
            ))}
          </div>
          {result.loldrivers_hit && (
            <div style={{ background:t.redDim, border:`1px solid ${t.red}40`, borderLeft:`3px solid ${t.red}`,
              borderRadius:6, padding:'10px 12px', marginBottom:10 }}>
              <div style={{ fontSize:12, color:t.red, fontWeight:600, marginBottom:4 }}>
                ⚠ Known vulnerable/malicious driver (LOLDrivers)
              </div>
              <div style={{ fontSize:11, color:t.fg }}>
                Category: {result.loldrivers_hit.category} · MITRE: {result.loldrivers_hit.mitre}
              </div>
            </div>
          )}

          {/* Cloud sandbox lookup — Hybrid Analysis / ANY.RUN */}
          {result.sandbox && Object.entries(result.sandbox).map(([name, sb]) => {
            const verdict = (sb.verdict || '').toLowerCase();
            const color = verdict.includes('mali') || verdict.includes('high') ? t.red
              : verdict.includes('suspic') || verdict.includes('medium') ? t.orange
              : verdict.includes('clean') || verdict.includes('benign') || verdict.includes('no_specific') ? t.green
              : t.fgMute;
            const label = name === 'hybrid_analysis' ? 'Hybrid Analysis (CrowdStrike Falcon Sandbox)' : 'ANY.RUN';
            return (
              <div key={name} style={{ background:t.raised, border:`1px solid ${t.line}`,
                borderLeft:`3px solid ${color}`, borderRadius:6, padding:'12px 14px', marginBottom:10 }}>
                <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:6 }}>
                  <span style={{ fontSize:12, fontWeight:600, color:t.fg }}>{label}</span>
                  {sb.url && <a href={sb.url} target="_blank" rel="noreferrer"
                    style={{ fontSize:11, color:t.cy, display:'inline-flex', alignItems:'center', gap:2 }}>
                    view report <ArrowUpRight size={11}/>
                  </a>}
                </div>
                <div style={{ display:'flex', gap:8, flexWrap:'wrap', marginBottom:6 }}>
                  <Chip color={color} soft={`${color}14`}>verdict: {sb.verdict || 'unknown'}</Chip>
                  {sb.threat_score != null && <Chip color={t.orange} size="xs">score {sb.threat_score}</Chip>}
                  {sb.malware_family && (Array.isArray(sb.malware_family) ? sb.malware_family[0] : sb.malware_family) &&
                    <Chip color={t.red} soft={t.redDim} size="xs">
                      {Array.isArray(sb.malware_family) ? sb.malware_family[0] : sb.malware_family}
                    </Chip>}
                  {sb.av_detect != null && <Chip color={t.fgMute} size="xs">AV {sb.av_detect}%</Chip>}
                </div>
                {sb.mitre?.length > 0 && (
                  <div style={{ fontSize:11, color:t.fgMute }}>
                    MITRE: {sb.mitre.filter(Boolean).slice(0, 6).join(' · ')}
                  </div>
                )}
                {sb.tags?.length > 0 && (
                  <div style={{ display:'flex', gap:4, flexWrap:'wrap', marginTop:5 }}>
                    {sb.tags.slice(0, 8).map(tag => <Chip key={tag} color={t.fgDim} size="xs">{tag}</Chip>)}
                  </div>
                )}
              </div>
            );
          })}
          {/* No existing sandbox report → offer to detonate */}
          {result.sha256 && !hasReport && !submission && (
            <div style={{ background:t.raised, border:`1px dashed ${t.line}`, borderRadius:6,
              padding:'12px 14px', marginBottom:10, display:'flex', justifyContent:'space-between',
              alignItems:'center', gap:10 }}>
              <div>
                <div style={{ fontSize:12, color:t.fg, fontWeight:500 }}>No existing sandbox report</div>
                <div style={{ fontSize:11, color:t.fgMute, marginTop:2 }}>
                  Submit to Hybrid Analysis for fresh detonation (typically 3–10 minutes).
                </div>
              </div>
              <button onClick={detonate} style={{ background:t.cyDim, border:`1px solid ${t.cyLine}`,
                color:t.cy, padding:'7px 14px', borderRadius:5, cursor:'pointer', fontSize:12, fontWeight:600 }}>
                Detonate sample
              </button>
            </div>
          )}

          {/* Submission in progress */}
          {submission && (
            <div style={{ background:t.raised, border:`1px solid ${
              submission.state === 'SUCCESS' ? t.green
              : submission.state === 'ERROR'  ? t.red
              : t.cy}40`,
              borderLeft:`3px solid ${
                submission.state === 'SUCCESS' ? t.green
                : submission.state === 'ERROR'  ? t.red
                : t.cy}`,
              borderRadius:6, padding:'12px 14px', marginBottom:10 }}>
              <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:6 }}>
                <span style={{ fontSize:12, color:t.fg, fontWeight:600 }}>
                  Hybrid Analysis · {submission.filename || 'sample'}
                </span>
                <Chip color={
                  submission.state === 'SUCCESS' ? t.green
                  : submission.state === 'ERROR'  ? t.red
                  : t.cy}>{submission.state}</Chip>
              </div>
              {submission.state === 'IN_QUEUE'    && <div style={{ fontSize:11, color:t.fgMute }}>Queued for detonation…</div>}
              {submission.state === 'IN_PROGRESS' && <div style={{ fontSize:11, color:t.fgMute }}>Detonating in Windows 10 sandbox… polling every 30s</div>}
              {submission.state === 'ERROR'      && <div style={{ fontSize:11, color:t.red }}>{submission.error || 'Submission error'}</div>}
              {submission.state === 'SUCCESS' && submission.summary && (
                <>
                  <div style={{ display:'flex', gap:6, flexWrap:'wrap', marginTop:8 }}>
                    <Chip color={t.fg}>verdict: {submission.summary.verdict}</Chip>
                    {submission.summary.threat_score != null && <Chip color={t.orange} size="xs">score {submission.summary.threat_score}</Chip>}
                    {submission.summary.malware_family && <Chip color={t.red} size="xs">
                      {Array.isArray(submission.summary.malware_family)
                        ? submission.summary.malware_family[0]
                        : submission.summary.malware_family}
                    </Chip>}
                  </div>
                  {submission.summary.url && <a href={submission.summary.url} target="_blank" rel="noreferrer"
                    style={{ fontSize:11, color:t.cy, marginTop:8, display:'inline-flex', alignItems:'center', gap:2 }}>
                    View full report <ArrowUpRight size={11}/>
                  </a>}
                </>
              )}
            </div>
          )}

          {result.yara_matches?.length > 0 ? (
            <Block title={`YARA matches (${result.yara_matches.length})`}>
              {result.yara_matches.map((m,i) => (
                <li key={i} style={{ padding:'7px 0', listStyle:'none',
                  borderTop: i>0?`1px solid ${t.line}`:'none' }}>
                  <div style={{ fontSize:12, color:t.fg, fontFamily:'JetBrains Mono', marginBottom:3 }}>
                    {m.rule}
                  </div>
                  {m.description && <div style={{ fontSize:11, color:t.fgMute, lineHeight:1.5 }}>{m.description}</div>}
                  <div style={{ display:'flex', gap:6, marginTop:4, flexWrap:'wrap' }}>
                    {m.tags?.map(tag => <Chip key={tag} color={t.fgMute} size="xs">{tag}</Chip>)}
                    {m.author && <span style={{ fontSize:10, color:t.fgDim }}>by {m.author}</span>}
                  </div>
                </li>
              ))}
            </Block>
          ) : (
            <div style={{ fontSize:12, color:t.green, padding:'8px 0' }}>
              No YARA matches — file is clean against {result.yara_matches?.length === 0 ? 'all loaded rules' : 'available rules'}.
            </div>
          )}
        </>
      )}
    </Card>
  );
}

/* ─── app ─────────────────────────────────────────────────────────────────────── */
export default function App() {
  const [result, setResult] = useState(null);
  const [view, setView] = useState('detail'); // 'detail' | 'table'
  const [webhooks, setWebhooks] = useState({});
  const rs = result?.response_summary;

  // Stream merge — each stage of the pipeline pushes a partial result;
  // we shallow-merge into the existing result so sections render as data arrives.
  const mergePartial = useCallback((partial) => {
    if (!partial) return;
    setResult(prev => (prev ? { ...prev, ...partial } : partial));
  }, []);

  // Fetch which webhook destinations are configured on the backend
  useEffect(() => {
    fetch('/api/health')
      .then(r => r.json())
      .then(d => setWebhooks(d.webhooks || {}))
      .catch(() => {});
  }, []);

  // Auto-detect bulk: 12+ indicators → default to table view
  const totalIOCs = Object.values(result?.iocs || {}).flat().length;
  const isBulk = totalIOCs >= 12;
  useEffect(() => {
    if (result && isBulk && view === 'detail') setView('table');
  }, [result, isBulk]); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <div style={{ display:'flex', minHeight:'100vh', background:t.bg, color:t.fg }}>
      <Sidebar onResult={setResult} onPartialResult={mergePartial} currentResult={result}/>

      <main style={{ flex:1, padding:'24px 28px 48px', overflowY:'auto', minWidth:0 }}>
        {/* Top toolbar: view toggle + outbound actions only */}
        {result && (
          <div style={{ display:'flex', justifyContent:'space-between', gap:8, marginBottom:14, alignItems:'center' }}>
            {/* Left: view toggle */}
            <div style={{ display:'flex', background:t.surface, border:`1px solid ${t.line}`, borderRadius:6, padding:2 }}>
              {[['detail', 'Detail'], ['table', 'Table']].map(([id, label]) => (
                <button key={id} onClick={() => setView(id)}
                  style={{ background: view === id ? t.raised : 'transparent', border:'none',
                    color: view === id ? t.fg : t.fgMute, padding:'5px 14px', borderRadius:4,
                    cursor:'pointer', fontSize:12, fontWeight:500 }}>
                  {label}
                  {id === 'table' && isBulk && <span style={{ marginLeft:5, color:t.cy, fontSize:10 }}>·{totalIOCs}</span>}
                </button>
              ))}
            </div>
            {/* Right: send to webhook if any configured */}
            <SendToWebhook result={result} available={webhooks}/>
          </div>
        )}

        {!result && <Empty/>}

        {result && view === 'table' && (
          <>
            <PreFlight result={result}/>
            <Overview result={result}/>
            <SignalBanners result={result}/>
            <IOCPivot result={result}/>
            <BulkTable result={result}/>
            <Card title="Geographic distribution" accent={t.cy} noPad><MapTab result={result}/></Card>
            <div style={{ marginBottom:16 }}><ExportBar result={result}/></div>
          </>
        )}

        {result && view === 'detail' && (
          <>
            <PreFlight result={result}/>
            <Overview result={result}/>
            <SignalBanners result={result}/>
            <IOCPivot result={result}/>
            <AnalystSummary rs={rs || {}}/>
            <ChatWithRecon result={result}/>
            <EmailAnalysis result={result}/>
            <GTI result={result}/>
            <Assessment rs={rs || {}}/>
            <CrossRefs rs={rs || {}}/>
            <Detection result={result}/>
            <NetworkDetection result={result}/>
            <URLScanLive result={result}/>
            <IRPlaybook rs={rs || {}}/>

            <Card title="Geographic distribution" accent={t.cy} noPad>
              <MapTab result={result}/>
            </Card>

            <Card title="Pivot graph" accent={t.cy} noPad>
              <div style={{ padding:'14px 16px' }}><PivotGraph result={result}/></div>
            </Card>

            <Enrichments enrichments={result.enrichments}/>
            <Report result={result}/>
            <FileScanner/>
            <div style={{ marginBottom:16 }}><ExportBar result={result}/></div>
          </>
        )}

        {/* Empty-state file scanner: lets analysts scan a file without running the pipeline first */}
        {!result && (
          <div style={{ marginTop:32 }}>
            <FileScanner/>
          </div>
        )}
      </main>

      <style>{`
        @keyframes pulse{0%,100%{opacity:1}50%{opacity:.5}}
        @keyframes spin{from{transform:rotate(0deg)}to{transform:rotate(360deg)}}
        ::-webkit-scrollbar{width:6px;height:6px}
        ::-webkit-scrollbar-track{background:transparent}
        ::-webkit-scrollbar-thumb{background:${t.lineHi};border-radius:3px}
        ::-webkit-scrollbar-thumb:hover{background:${t.lineStr}}
        button:focus-visible,input:focus-visible,textarea:focus-visible{
          outline:2px solid ${t.cyLine};outline-offset:1px;
        }
        textarea:focus,input:focus{border-color:${t.cyLine} !important}
        a{color:inherit;transition:opacity .15s}
        a:hover{opacity:.8}
        h1,h2,h3,h4{margin:0}
      `}</style>
    </div>
  );
}
