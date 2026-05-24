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
  Menu           as MuiMenu,
  MenuItem       as MuiMenuItem,
  ToggleButton   as MuiToggleButton,
  ToggleButtonGroup as MuiToggleButtonGroup,
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

/* ─── design tokens — exact values from OpenCTI ThemeDark.ts ────────────────
 * Adapted from OpenCTI (AGPL-3.0). Every legacy inline-styled element now
 * inherits the precise OpenCTI palette by referencing this token object.
 */
const t = {
  // surfaces  (matches OpenCTI background.default / paper / nav / accent / secondary)
  bg:        '#070d19',           // THEME_DARK_DEFAULT_BACKGROUND
  surface:   '#09101e',           // THEME_DARK_DEFAULT_PAPER
  raised:    '#0C1524',           // background.secondary
  sidebar:   '#070d19',           // THEME_DARK_DEFAULT_NAV
  hover:     'rgba(255,255,255,0.025)',

  // borders  (matches OpenCTI border.paper / border.main)
  line:      'rgba(255,255,255,0.12)',   // border.paper
  lineHi:    'rgba(255,255,255,0.15)',   // table cell borders
  lineStr:   '#252A35',                  // border.main

  // text  (matches OpenCTI text.primary / tertiary / disabled)
  fg:        '#F2F2F3',           // THEME_DARK_DEFAULT_TEXT
  fgMute:    '#AFB0B6',           // text.light
  fgDim:     '#848592',           // text.tertiary
  fgGhost:   '#75829A',           // text.disabled

  // accent — primary cyan (matches OpenCTI primary.main)
  cy:        '#0fbcff',           // THEME_DARK_DEFAULT_PRIMARY
  cyDim:     'rgba(15,188,255,0.1)',
  cyLine:    'rgba(15,188,255,0.3)',
  cyWash:    'rgba(15,188,255,0.04)',

  // semantic  (matches OpenCTI severity palette)
  red:       '#F14337',           // error.main / severity.critical-ish
  redDim:    'rgba(241,67,55,0.1)',
  red2:      'rgba(241,67,55,0.04)',
  orange:    '#E6700F',           // warn.main / severity.high
  orangeDim: 'rgba(230,112,15,0.1)',
  orange2:   'rgba(230,112,15,0.04)',
  yellow:    '#E1B823',            // severity.medium
  yellowDim: 'rgba(225,184,35,0.1)',
  yellow2:   'rgba(225,184,35,0.04)',
  green:     '#17AB1F',            // success.main / severity.low
  greenDim:  'rgba(23,171,31,0.1)',
  blue:      '#1565c0',            // severity.info
  blueDim:   'rgba(21,101,192,0.1)',
  purple:    '#B286FF',            // ai.main
  purpleDim: 'rgba(178,134,255,0.1)',
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

/* ─── clarifying questions (spec §5 — Phase 1 → Phase 2 re-analysis) ────────
 * When the AI flags critical unknowns it can't infer from enrichment, render
 * them as a form. Submitting POSTs to /api/analyze/clarify/{runId} which
 * re-runs the investigation with the analyst's answers appended.
 */
function ClarifyingQuestions({ result, onResult }) {
  const questions = result?.clarifying_questions || [];
  const [answers, setAnswers]   = useState({});
  const [submitting, setSubmitting] = useState(false);
  const [error, setError]       = useState(null);

  if (!questions.length) return null;

  const submit = async () => {
    const runId = result?.runId;
    if (!runId) return;
    const filled = Object.fromEntries(
      Object.entries(answers).filter(([, v]) => (v || '').trim())
    );
    if (Object.keys(filled).length === 0) {
      setError('Answer at least one question before re-running');
      return;
    }
    setSubmitting(true); setError(null);
    try {
      const r = await fetch(`/api/analyze/clarify/${runId}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ answers: filled }),
      });
      const d = await r.json();
      if (!r.ok) throw new Error(d.detail || `HTTP ${r.status}`);
      onResult?.(d);
    } catch (e) {
      setError(e.message);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Card title="AI needs more context · clarifying questions" accent="#E1B823"
      badge={`${questions.length} questions`} defaultOpen>
      <Typography sx={{ fontSize: 12, color: 'text.tertiary', mb: 1.5, lineHeight: 1.6 }}>
        These answers would materially change the assessment. Fill in what you know
        and submit to re-run the investigation with your context.
      </Typography>
      {questions.map((q, i) => {
        const qText = typeof q === 'string' ? q : (q.question || `Question ${i + 1}`);
        return (
          <Box key={i} sx={{ mb: 1.5 }}>
            <Typography sx={{ fontSize: 12, color: 'text.primary', mb: 0.5, fontWeight: 500 }}>
              {qText}
            </Typography>
            {typeof q === 'object' && q.why_asking && (
              <Typography sx={{ fontSize: 11, color: 'text.tertiary', mb: 0.75, fontStyle: 'italic' }}>
                {q.why_asking}
              </Typography>
            )}
            <MuiTextField
              value={answers[qText] || ''}
              onChange={e => setAnswers(a => ({ ...a, [qText]: e.target.value }))}
              size="small"
              fullWidth
              placeholder="Your answer (plain text)"
            />
          </Box>
        );
      })}
      {error && (
        <Typography sx={{ color: 'error.main', fontSize: 12, mb: 1 }}>{error}</Typography>
      )}
      {result?.context_impact && (
        <Box sx={{ mt: 1.5, p: 1.5,
          backgroundColor: muiAlpha('#16AD34', 0.08),
          border: `1px solid ${muiAlpha('#16AD34', 0.25)}`,
          borderRadius: '4px',
        }}>
          <Typography sx={{ fontSize: 11, color: 'success.main', fontWeight: 600, mb: 0.5,
            textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Context impact (re-analysis)
          </Typography>
          <Typography sx={{ fontSize: 12, color: 'text.primary', lineHeight: 1.6 }}>
            {result.context_impact}
          </Typography>
        </Box>
      )}
      <Stack direction="row" spacing={1} sx={{ mt: 1.5 }}>
        <MuiButton variant="contained" size="small"
          disabled={submitting} onClick={submit}>
          {submitting ? 'Re-investigating…' : 'Re-run with my answers'}
        </MuiButton>
      </Stack>
    </Card>
  );
}

/* ─── suppressed IOCs (MISP warninglist matches) ─────────────────────────────
 * Spec §4 — show analysts exactly what was filtered out before enrichment so
 * they can spot false-negative filters (e.g., a Tor exit IP swallowed by a
 * datacenter list).
 */
function SuppressedIOCs({ result }) {
  const sup = result?.suppressed_iocs || {};
  const total = Object.values(sup).reduce((n, arr) => n + (arr?.length || 0), 0);
  if (!total) return null;
  return (
    <Card title="Filtered as benign · MISP warninglists" accent="#848592"
      badge={`${total} suppressed`} defaultOpen={false}>
      <Typography sx={{ fontSize: 12, color: 'text.tertiary', mb: 1.5, lineHeight: 1.6 }}>
        These IOCs were extracted from the input but matched a MISP warninglist
        (known-good service, datacenter range, public DNS, top-1M domain, etc.) so
        they were removed before enrichment. Verify nothing important was dropped.
      </Typography>
      {Object.entries(sup).map(([type, items]) => items?.length > 0 && (
        <Box key={type} sx={{ mb: 1.5 }}>
          <Stack direction="row" alignItems="center" spacing={1} sx={{ mb: 0.75 }}>
            <TypeTag type={type === 'ips' ? 'ips' : type === 'domains' ? 'domains' : type === 'hashes' ? 'hashes' : 'urls'}/>
            <Typography sx={{ fontSize: 11, color: 'text.tertiary' }}>{items.length}</Typography>
          </Stack>
          <MuiPaper elevation={0} sx={{
            backgroundColor: '#0C1524',
            border: `1px solid ${muiAlpha('#ffffff', 0.12)}`,
            borderRadius: '4px', overflow: 'hidden',
          }}>
            {items.map((entry, i) => (
              <Box key={i} sx={{
                display: 'grid', gridTemplateColumns: '1fr auto',
                gap: 1.25, p: '6px 10px',
                borderTop: i > 0 ? `1px solid ${muiAlpha('#ffffff', 0.06)}` : 'none',
              }}>
                <Box sx={{
                  fontFamily: '"IBM Plex Mono", monospace', fontSize: 12,
                  color: 'text.primary', wordBreak: 'break-all',
                }}>{entry.ioc}</Box>
                <Typography sx={{ fontSize: 11, color: 'text.tertiary',
                  textAlign: 'right', whiteSpace: 'nowrap',
                  overflow: 'hidden', textOverflow: 'ellipsis', maxWidth: 320 }}>
                  {entry.reason}
                </Typography>
              </Box>
            ))}
          </MuiPaper>
        </Box>
      ))}
    </Card>
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
    <Card title="Threat scoring" accent="#0fbcff" badge={top ? `${top.score}/100` : null}>
      <Box sx={{
        display: 'grid', gridTemplateColumns: 'auto 1fr', gap: 3, mb: 2.25,
        pb: 2, borderBottom: `1px solid ${muiAlpha('#ffffff', 0.06)}`,
      }}>
        {top && (
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.75 }}>
            <Dial score={top.score} color={top.color} size={80}/>
            <Box>
              <Typography sx={{ fontSize: 11, color: 'text.tertiary', mb: 0.5 }}>
                Highest scoring indicator
              </Typography>
              <Typography sx={{ fontSize: 18, fontWeight: 600, color: top.color, mb: 0.75 }}>
                {top.label}
              </Typography>
              <Verdict verdict={top.verdict}/>
            </Box>
          </Box>
        )}
        <Box sx={{ display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
          <Typography sx={{ fontSize: 11, color: 'text.tertiary', mb: 1 }}>
            Score distribution
          </Typography>
          {Object.entries(dist).map(([lbl, cnt]) => (
            <Box key={lbl} sx={{ display: 'flex', gap: 1.25, alignItems: 'center', mb: 0.5 }}>
              <Box sx={{ width: 72, fontSize: 11, color: 'text.tertiary', textTransform: 'capitalize' }}>
                {lbl}
              </Box>
              <Box sx={{
                flex: 1, backgroundColor: 'background.secondary',
                borderRadius: 99, height: 6, overflow: 'hidden',
              }}>
                {cnt > 0 && (
                  <Box sx={{
                    width: `${Math.min(100, cnt * 16)}%`, height: '100%',
                    backgroundColor: distC[lbl], borderRadius: 99,
                    transition: 'width .4s',
                  }}/>
                )}
              </Box>
              <Box sx={{
                width: 18, fontSize: 11,
                color: cnt > 0 ? distC[lbl] : 'text.disabled',
                fontWeight: 600, textAlign: 'right', fontVariantNumeric: 'tabular-nums',
              }}>{cnt}</Box>
            </Box>
          ))}
        </Box>
      </Box>

      <Stack direction="row" spacing={1} sx={{ flexWrap: 'wrap', mb: 2 }}>
        <MuiPaper elevation={0} sx={{
          display: 'flex', alignItems: 'center', gap: 0.875,
          backgroundColor: 'background.secondary',
          border: `1px solid ${muiAlpha('#ffffff', 0.12)}`,
          borderRadius: '4px', p: '6px 11px',
        }}>
          <Box sx={{ width: 6, height: 6, borderRadius: 99, backgroundColor: '#B286FF' }}/>
          <Typography sx={{ fontSize: 11, color: 'text.primary', fontWeight: 500 }}>STIX 2.1</Typography>
          <Typography sx={{ fontSize: 11, color: 'text.tertiary' }}>· {total} indicators</Typography>
          {result?.runId && (
            <Box component="a" href={`/api/export/stix/${result.runId}`} target="_blank" rel="noreferrer"
              sx={{ color: '#B286FF', fontSize: 11, display: 'inline-flex',
                alignItems: 'center', gap: 0.25, ml: 0.25 }}>
              export <ArrowUpRight size={11}/>
            </Box>
          )}
        </MuiPaper>
        <MuiPaper elevation={0} sx={{
          display: 'flex', alignItems: 'center', gap: 0.875,
          backgroundColor: 'background.secondary',
          border: `1px solid ${muiAlpha('#ffffff', 0.12)}`,
          borderRadius: '4px', p: '6px 11px',
        }}>
          <Box sx={{ width: 6, height: 6, borderRadius: 99, backgroundColor: 'primary.main' }}/>
          <Typography sx={{ fontSize: 11, color: 'text.primary', fontWeight: 500 }}>TAXII feeds</Typography>
          <Typography sx={{ fontSize: 11, color: 'text.tertiary' }}>
            · VT, AbuseIPDB, OTX, ThreatFox, MalwareBazaar, GreyNoise, URLScan, Shodan
          </Typography>
        </MuiPaper>
      </Stack>

      <Typography sx={{ fontSize: 11, color: 'text.tertiary', mb: 0.75 }}>Per-indicator score</Typography>
      <MuiPaper elevation={0} sx={{
        backgroundColor: 'background.secondary',
        borderRadius: '4px',
        border: `1px solid ${muiAlpha('#ffffff', 0.12)}`,
        overflow: 'hidden',
      }}>
        {sorted.map(([ioc, d], i) => (
          <Box key={ioc} sx={{
            display: 'flex', gap: 1.5, alignItems: 'center', p: '10px 14px',
            borderTop: i > 0 ? `1px solid ${muiAlpha('#ffffff', 0.06)}` : 'none',
          }}>
            <Dial score={d.score} color={d.color} size={38}/>
            <Box sx={{ flex: 1, minWidth: 0 }}>
              <Typography sx={{
                fontSize: 12, color: 'text.primary',
                fontFamily: '"IBM Plex Mono", monospace',
                wordBreak: 'break-all', mb: 0.375,
              }}>
                {ioc.length > 58 ? ioc.slice(0, 55) + '…' : ioc}
              </Typography>
              <Typography sx={{ fontSize: 11, color: 'text.tertiary' }}>
                {d.label}
                {d.contributing_factors?.slice(0, 1).map((f, i) =>
                  <Box component="span" key={i} sx={{ color: 'text.disabled' }}> · {f}</Box>
                )}
              </Typography>
            </Box>
            <Verdict verdict={d.verdict} size="small"/>
          </Box>
        ))}
      </MuiPaper>
    </Card>
  );
}

/* ─── assessment ────────────────────────────────────────────────────────────── */
function Assessment({ rs }) {
  const lc = levelStyle[rs.threat_level] || levelStyle.INFORMATIONAL;
  return (
    <Card title="AI assessment" accent="#0fbcff" badge={rs.threat_level?.toLowerCase()}>
      <MuiPaper elevation={0} sx={{
        backgroundColor: lc.bg,
        border: `1px solid ${lc.line}`,
        borderRadius: '4px', p: '14px 16px', mb: 1.75,
      }}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <Box sx={{ width: 8, height: 8, borderRadius: 99, backgroundColor: lc.fg }}/>
            <Typography sx={{ color: lc.fg, fontWeight: 600, fontSize: 13 }}>{rs.threat_level}</Typography>
          </Box>
          {typeof rs.confidence === 'number' && (
            <Typography sx={{ fontSize: 12, color: 'text.tertiary' }}>
              Confidence{' '}
              <Box component="span" sx={{
                color: rs.confidence >= 0.7 ? 'success.main'
                     : rs.confidence >= 0.4 ? '#E1B823'
                     : 'error.main',
                fontWeight: 600,
              }}>
                {Math.round(rs.confidence * 100)}%
              </Box>
            </Typography>
          )}
        </Box>
        <Typography sx={{ fontSize: 13, color: 'text.primary', lineHeight: 1.7 }}>{rs.summary}</Typography>
      </MuiPaper>

      {rs.chain_of_thought?.length > 0 && (
        <Block title="Reasoning chain">
          {rs.chain_of_thought.map((s, i) => (
            <Box component="li" key={i} sx={{
              display: 'flex', gap: 1.25, py: 0.75,
              borderTop: i > 0 ? `1px solid ${muiAlpha('#ffffff', 0.06)}` : 'none',
              fontSize: 13, color: 'text.primary', lineHeight: 1.6,
            }}>
              <Box component="span" sx={{ color: 'primary.main', minWidth: 18,
                fontWeight: 600, fontVariantNumeric: 'tabular-nums' }}>{i + 1}</Box>
              <span>{s}</span>
            </Box>
          ))}
        </Block>
      )}

      {rs.key_findings?.length > 0 && (
        <Block title="Key findings">
          {rs.key_findings.map((f, i) => (
            <Box component="li" key={i} sx={{
              display: 'flex', gap: 1.25, py: 0.75,
              borderTop: i > 0 ? `1px solid ${muiAlpha('#ffffff', 0.06)}` : 'none',
              fontSize: 13, color: 'text.primary', lineHeight: 1.6,
            }}>
              <Box component="span" sx={{ color: 'warning.main', minWidth: 6 }}>›</Box>
              <span>{f}</span>
            </Box>
          ))}
        </Block>
      )}

      {rs.ioc_assessments?.length > 0 && (
        <Block title="Indicator verdicts">
          {rs.ioc_assessments.map((a, i) => (
            <Box component="li" key={i} sx={{
              display: 'flex', gap: 1.25, py: 0.875,
              borderTop: i > 0 ? `1px solid ${muiAlpha('#ffffff', 0.06)}` : 'none',
              alignItems: 'flex-start',
            }}>
              <Box sx={{ minWidth: 90 }}><Verdict verdict={a.verdict} size="small"/></Box>
              <Box sx={{ flex: 1, minWidth: 0 }}>
                <Box sx={{
                  fontFamily: '"IBM Plex Mono", monospace', fontSize: 12,
                  color: 'text.primary', wordBreak: 'break-all',
                }}>{a.ioc}</Box>
                {a.reason && (
                  <Typography sx={{ fontSize: 12, color: 'text.tertiary',
                    mt: 0.375, lineHeight: 1.5 }}>{a.reason}</Typography>
                )}
              </Box>
            </Box>
          ))}
        </Block>
      )}

      {rs.mitre_techniques?.length > 0 && (
        <Block title="MITRE ATT&CK">
          <Box sx={{ display: 'flex', gap: 0.75, flexWrap: 'wrap' }}>
            {rs.mitre_techniques.map((t_, i) => {
              const id = t_.split(' ')[0];
              return (
                <MuiTag key={i} label={t_} color="#0fbcff"
                  onClick={() => window.open(`https://attack.mitre.org/techniques/${id.includes('.') ? id.replace('.','/') : id}/`, '_blank')}
                  sx={{ fontFamily: '"IBM Plex Mono", monospace' }}/>
              );
            })}
          </Box>
        </Block>
      )}

      {rs.matched_actors?.length > 0 && (
        <Block title="Threat actor attribution">
          {rs.matched_actors.slice(0, 5).map((a, i) => (
            <Box key={i} sx={{
              py: 1.25,
              borderTop: i > 0 ? `1px solid ${muiAlpha('#ffffff', 0.06)}` : 'none',
              display: 'grid', gridTemplateColumns: '1fr auto', gap: 1.5, alignItems: 'start',
            }}>
              <Box>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5 }}>
                  <Typography sx={{ fontSize: 13, color: 'text.primary', fontWeight: 600 }}>{a.name}</Typography>
                  {a.mitre_id && <MuiTag label={a.mitre_id} color="#848592"
                    sx={{ fontFamily: '"IBM Plex Mono", monospace' }}/>}
                </Box>
                {(a.origin || a.sponsor) && (
                  <Typography sx={{ fontSize: 11, color: 'text.tertiary', mb: 0.5 }}>
                    {[a.origin, a.sponsor].filter(Boolean).join(' · ')}
                  </Typography>
                )}
                {a.aliases?.length > 0 && (
                  <Typography sx={{ fontSize: 11, color: 'text.disabled', mb: 0.5 }}>
                    aka {a.aliases.slice(0, 4).join(', ')}
                  </Typography>
                )}
                {a.description && (
                  <Typography sx={{ fontSize: 12, color: 'text.tertiary', lineHeight: 1.5, mt: 0.625 }}>
                    {a.description.slice(0, 200)}{a.description.length > 200 ? '…' : ''}
                  </Typography>
                )}
              </Box>
              <Box sx={{ textAlign: 'right' }}>
                <Typography sx={{ fontSize: 18, color: 'warning.main', fontWeight: 600,
                  fontVariantNumeric: 'tabular-nums' }}>{a.score}%</Typography>
                <Typography sx={{ fontSize: 10, color: 'text.disabled' }}>TTP match</Typography>
              </Box>
            </Box>
          ))}
        </Block>
      )}

      {rs.recommended_actions?.length > 0 && (
        <Block title="Recommended actions">
          {rs.recommended_actions.map((a, i) => (
            <Box component="li" key={i} sx={{
              display: 'flex', gap: 1.25, py: 0.75,
              borderTop: i > 0 ? `1px solid ${muiAlpha('#ffffff', 0.06)}` : 'none',
              fontSize: 13, color: 'text.primary', lineHeight: 1.6,
            }}>
              <Box component="span" sx={{ color: 'success.main', minWidth: 18,
                fontWeight: 600, fontVariantNumeric: 'tabular-nums' }}>{i + 1}</Box>
              <span>{a}</span>
            </Box>
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

  const dispColor = a.disposition === 'CLEAR'    ? '#17AB1F'
                  : a.disposition === 'ESCALATE' ? '#F14337'
                  :                                '#E1B823';

  return (
    <Card title="Analyst hand-off" accent="#0fbcff" badge={a.disposition?.toLowerCase()} defaultOpen>
      {/* Disposition banner */}
      {a.disposition && (
        <MuiPaper elevation={0} sx={{
          backgroundColor: 'background.secondary',
          border: `1px solid ${muiAlpha(dispColor, 0.25)}`,
          borderLeft: `3px solid ${dispColor}`,
          borderRadius: '4px', p: '12px 14px', mb: 1.5,
        }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.75 }}>
            <Box sx={{ width: 8, height: 8, borderRadius: 99, backgroundColor: dispColor }}/>
            <Typography sx={{ color: dispColor, fontWeight: 600, fontSize: 13 }}>
              Recommended disposition: {a.disposition}
            </Typography>
          </Box>
          {a.disposition_reason && (
            <Typography sx={{ fontSize: 13, color: 'text.primary', lineHeight: 1.7 }}>
              {a.disposition_reason}
            </Typography>
          )}
        </MuiPaper>
      )}

      {/* Clear justification */}
      {a.clear_justification && (
        <Block title="Why this can / cannot be cleared">
          <Typography component="li" sx={{ listStyle: 'none', py: 0.5, fontSize: 13,
            color: 'text.primary', lineHeight: 1.7 }}>
            {a.clear_justification}
          </Typography>
        </Block>
      )}

      {/* Escalation steps */}
      {a.escalation_steps?.length > 0 && a.disposition !== 'CLEAR' && (
        <Block title="If escalating · steps for Tier 2">
          {a.escalation_steps.map((s, i) => (
            <Box component="li" key={i} sx={{
              display: 'flex', gap: 1.25, py: 0.75,
              borderTop: i > 0 ? `1px solid ${muiAlpha('#ffffff', 0.06)}` : 'none',
              fontSize: 13, color: 'text.primary', lineHeight: 1.6,
            }}>
              <Box component="span" sx={{ color: 'error.main', minWidth: 18, fontWeight: 600 }}>
                {i + 1}
              </Box>
              <span>{s}</span>
            </Box>
          ))}
        </Block>
      )}

      {/* Client email — the big copy-able paragraph */}
      {a.client_email?.body && (
        <Box sx={{ mt: 1 }}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 0.75 }}>
            <Typography sx={{ fontSize: 11, color: 'text.tertiary', fontWeight: 500,
              textTransform: 'uppercase', letterSpacing: '0.06em' }}>
              Client notification email
            </Typography>
            <CopyBtn text={`Subject: ${a.client_email.subject || ''}\n\n${a.client_email.body}`}
              label="Copy email"/>
          </Box>
          <MuiPaper elevation={0} sx={{
            backgroundColor: 'background.secondary',
            border: `1px solid ${muiAlpha('#ffffff', 0.12)}`,
            borderRadius: '4px', p: 1.75,
          }}>
            {a.client_email.subject && (
              <Box sx={{
                pb: 1.25, mb: 1.25,
                borderBottom: `1px solid ${muiAlpha('#ffffff', 0.06)}`,
              }}>
                <Box component="span" sx={{ fontSize: 11, color: 'text.tertiary', mr: 1 }}>
                  Subject:
                </Box>
                <Box component="span" sx={{ fontSize: 13, color: 'text.primary', fontWeight: 600 }}>
                  {a.client_email.subject}
                </Box>
              </Box>
            )}
            <Typography sx={{ fontSize: 13, color: 'text.primary', lineHeight: 1.8,
              whiteSpace: 'pre-wrap' }}>
              {a.client_email.body}
            </Typography>
          </MuiPaper>
        </Box>
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
    <Card title="Incident response playbook" accent="#0fbcff"
      badge="NIST 800-61" defaultOpen={false}>
      <Box sx={{
        display:'grid', gridTemplateColumns:'repeat(auto-fit, minmax(280px, 1fr))', gap:1.25,
      }}>
        {phases.map(([label, steps, color]) => (
          <MuiPaper key={label} elevation={0} sx={{
            backgroundColor:'background.secondary',
            border: `1px solid ${muiAlpha('#ffffff', 0.12)}`,
            borderLeft: `3px solid ${color}`,
            borderRadius:'4px', p:'12px 14px',
          }}>
            <Typography sx={{ fontSize:12, fontWeight:600, color, mb:1,
              textTransform:'uppercase', letterSpacing:'0.04em' }}>{label}</Typography>
            <Box component="ol" sx={{ m:0, pl:2.25, fontSize:12,
              color:'text.primary', lineHeight:1.7 }}>
              {steps.map((s, i) => <li key={i} style={{ marginBottom:5 }}>{s}</li>)}
            </Box>
          </MuiPaper>
        ))}
      </Box>
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
    return <MuiTag key={label} label={`${label}: ${value}`} color={ok ? '#16AD34' : '#EE3838'}/>;
  };
  const borderTop = (i) => i > 0 ? `1px solid ${muiAlpha('#ffffff', 0.06)}` : 'none';
  const monoSx = { fontFamily: '"IBM Plex Mono", monospace' };

  return (
    <Card title="Email analysis" accent="#E6700F" badge={`${e.attachments?.length || 0} attachments`}>
      {/* Headers */}
      <MuiPaper elevation={0} sx={{
        backgroundColor: '#0C1524',
        border: `1px solid ${muiAlpha('#ffffff', 0.12)}`,
        borderRadius: '4px', p: '12px 14px', mb: 1.25,
        fontSize: 12, lineHeight: 1.8,
      }}>
        {e.subject && (
          <Box>
            <Box component="span" sx={{ color: 'text.disabled', mr: 1 }}>Subject:</Box>
            <Box component="span" sx={{ color: 'text.primary', fontWeight: 500 }}>{e.subject}</Box>
          </Box>
        )}
        {e.from && (
          <Box>
            <Box component="span" sx={{ color: 'text.disabled', mr: 1 }}>From:</Box>
            <Box component="span" sx={{ color: 'text.primary', ...monoSx, fontSize: 11 }}>{e.from}</Box>
          </Box>
        )}
        {e.to?.length > 0 && (
          <Box>
            <Box component="span" sx={{ color: 'text.disabled', mr: 1 }}>To:</Box>
            <Box component="span" sx={{ color: 'text.primary', ...monoSx, fontSize: 11 }}>
              {Array.isArray(e.to) ? e.to.join(', ') : e.to}
            </Box>
          </Box>
        )}
        {e.return_path && e.return_path !== e.from && (
          <Box>
            <Box component="span" sx={{ color: 'text.disabled', mr: 1 }}>Return-Path:</Box>
            <Box component="span" sx={{ color: 'error.main', ...monoSx, fontSize: 11 }}>{e.return_path}</Box>
          </Box>
        )}
        {e.date && (
          <Box>
            <Box component="span" sx={{ color: 'text.disabled', mr: 1 }}>Date:</Box>
            <Box component="span" sx={{ color: 'text.tertiary' }}>{e.date}</Box>
          </Box>
        )}
      </MuiPaper>

      {/* Auth + signals */}
      <Stack direction="row" spacing={0.75} flexWrap="wrap" sx={{ mb: 1.5 }}>
        {authChip('SPF', auth.spf)}
        {authChip('DKIM', auth.dkim)}
        {authChip('DMARC', auth.dmarc)}
      </Stack>

      {e.phishing_signals?.length > 0 && (
        <Block title="Phishing signals">
          {e.phishing_signals.map((s, i) => (
            <Box component="li" key={i} sx={{
              display: 'flex', gap: 1.25, py: 0.625, listStyle: 'none', borderTop: borderTop(i),
            }}>
              <AlertCircle size={13} color="#EE3838" style={{ flexShrink: 0, marginTop: 2 }}/>
              <Box component="span" sx={{ fontSize: 12, color: 'text.primary' }}>{s}</Box>
            </Box>
          ))}
        </Block>
      )}

      {/* Attachments */}
      {e.attachments?.length > 0 && (
        <Block title={`Attachments (${e.attachments.length})`}>
          {e.attachments.map((a, i) => (
            <Box component="li" key={i} sx={{
              py: 0.75, listStyle: 'none', borderTop: borderTop(i),
            }}>
              <Typography sx={{ fontSize: 12, color: 'text.primary', mb: 0.25 }}>{a.filename || '(no name)'}</Typography>
              <Typography sx={{ fontSize: 11, color: 'text.tertiary' }}>
                {a.content_type} · {a.size ? `${(a.size / 1024).toFixed(1)} KB` : ''}
              </Typography>
              {a.sha256 && (
                <Box sx={{
                  fontSize: 10, color: 'text.disabled', ...monoSx,
                  wordBreak: 'break-all', mt: 0.25,
                }}>sha256: {a.sha256}</Box>
              )}
            </Box>
          ))}
        </Block>
      )}

      {e.urls?.length > 0 && (
        <Block title={`Embedded URLs (${e.urls.length})`}>
          {e.urls.slice(0, 20).map((u, i) => (
            <Box component="li" key={i} sx={{
              py: 0.5, listStyle: 'none', fontSize: 11,
              color: 'text.primary', ...monoSx,
              wordBreak: 'break-all', borderTop: borderTop(i),
            }}>{u}</Box>
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

  const borderTop = (i) => i > 0 ? `1px solid ${muiAlpha('#ffffff', 0.06)}` : 'none';
  const monoSx = { fontFamily: '"IBM Plex Mono", monospace' };

  return (
    <Card title="CTI framework analysis" accent="#B286FF"
      badge="Diamond · Kill Chain · Pyramid · Admiralty">

      {/* ── Diamond Model ─── 4-vertex layout ────────────────────────────── */}
      {Object.keys(dm).length > 0 && (
        <Block title="Diamond Model · adversary, capability, infrastructure, victim">
          <Box component="li" sx={{ listStyle: 'none', p: 0 }}>
            <Box sx={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 1, mt: 0.5 }}>
              {[
                ['adversary',      'Adversary',      '#EE3838'],
                ['capability',     'Capability',     '#E6700F'],
                ['infrastructure', 'Infrastructure', '#0fbcff'],
                ['victim',         'Victim',         '#B286FF'],
              ].map(([k, label, color]) => {
                const v = dm[k] || {};
                return (
                  <MuiPaper key={k} elevation={0} sx={{
                    backgroundColor: '#0C1524',
                    border: `1px solid ${muiAlpha('#ffffff', 0.12)}`,
                    borderLeft: `3px solid ${color}`,
                    borderRadius: '4px', p: '10px 12px',
                  }}>
                    <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 0.75 }}>
                      <Box component="span" sx={{ fontSize: 10, color, fontWeight: 600, letterSpacing: '0.05em' }}>
                        {label.toUpperCase()}
                      </Box>
                      {v.confidence && <MuiTag label={v.confidence} color={color}/>}
                    </Box>
                    <Typography sx={{ fontSize: 12, color: 'text.primary', fontWeight: 500, mb: 0.5 }}>
                      {v.value || '—'}
                    </Typography>
                    {v.rationale && (
                      <Typography sx={{ fontSize: 11, color: 'text.tertiary', lineHeight: 1.55 }}>
                        {v.rationale}
                      </Typography>
                    )}
                  </MuiPaper>
                );
              })}
            </Box>
            {dm.meta_features && (dm.meta_features.phase || dm.meta_features.methodology) && (
              <Box sx={{
                mt: 1, fontSize: 11, color: 'text.tertiary', p: '6px 10px',
                backgroundColor: '#070d19', borderRadius: '4px',
                border: `1px solid ${muiAlpha('#ffffff', 0.12)}`,
              }}>
                <Box component="span" sx={{ color: 'text.disabled' }}>meta:</Box> {dm.meta_features.phase || '—'}
                {dm.meta_features.methodology && <> · {dm.meta_features.methodology}</>}
              </Box>
            )}
          </Box>
        </Block>
      )}

      {/* ── Kill Chain — horizontal stage strip ──────────────────────────── */}
      {Object.values(kc).some(v => v) && (
        <Block title="Cyber Kill Chain · Lockheed Martin 7-stage mapping">
          <Box component="li" sx={{ listStyle: 'none', p: 0 }}>
            <Box sx={{ display: 'flex', gap: 0.75, mt: 0.5, overflowX: 'auto' }}>
              {stages.map(([key, label], i) => {
                const evidence = kc[key];
                const hit = evidence && evidence !== 'null' && evidence !== null;
                return (
                  <MuiPaper key={key} elevation={0} sx={{
                    flex: '1 1 0', minWidth: 90,
                    backgroundColor: hit ? muiAlpha('#E6700F', 0.08) : '#0C1524',
                    border: `1px solid ${hit ? '#E6700F' : muiAlpha('#ffffff', 0.12)}`,
                    borderTop: `3px solid ${hit ? '#E6700F' : muiAlpha('#ffffff', 0.12)}`,
                    borderRadius: '4px', p: '8px 10px',
                  }}>
                    <Box sx={{
                      fontSize: 10, color: hit ? 'warning.main' : 'text.disabled', fontWeight: 600,
                      mb: 0.5, lineHeight: 1.3,
                    }}>
                      {String(i + 1).padStart(2, '0')} · {label}
                    </Box>
                    <Box sx={{
                      fontSize: 10, color: hit ? 'text.primary' : muiAlpha('#ffffff', 0.25),
                      lineHeight: 1.5,
                    }}>
                      {hit ? evidence : '—'}
                    </Box>
                  </MuiPaper>
                );
              })}
            </Box>
          </Box>
        </Block>
      )}

      {/* ── Pyramid of Pain ──────────────────────────────────────────────── */}
      {pop.length > 0 && (
        <Block title="Pyramid of Pain · prioritize detections by attacker cost-to-change">
          <Box component="li" sx={{ listStyle: 'none', p: 0 }}>
            <Box sx={{ mt: 0.75 }}>
              {popOrder.map((lvl, i) => {
                const entry = popMap[lvl];
                const indicators = entry?.indicators || [];
                const hasInd = indicators.length > 0 && !(indicators.length === 1 && (!indicators[0] || indicators[0] === '<observed TTP>'));
                const widthPct = 100 - (i * 12);
                const color = popColor[lvl];
                const labelMap = { TTPs: 'TTPs (months)', tools: 'Tools (months)',
                                   host_artifacts: 'Host artifacts (weeks)', network: 'Network artifacts (days)',
                                   domains: 'Domains (hours)', ips: 'IPs (minutes)', hashes: 'Hashes (seconds)' };
                return (
                  <Box key={lvl} sx={{ display: 'flex', alignItems: 'center', gap: 1.25, mb: 0.375 }}>
                    <Box sx={{
                      width: `${widthPct}%`, maxWidth: 480, ml: 'auto', mr: 0,
                      backgroundColor: hasInd ? muiAlpha(color, 0.12) : '#0C1524',
                      border: `1px solid ${hasInd ? color : muiAlpha('#ffffff', 0.12)}`,
                      borderRadius: '4px', p: '5px 10px',
                      display: 'flex', justifyContent: 'space-between',
                      alignItems: 'center', gap: 1,
                    }}>
                      <Box component="span" sx={{
                        fontSize: 11, color: hasInd ? color : 'text.disabled',
                        fontWeight: 600, whiteSpace: 'nowrap',
                      }}>{labelMap[lvl]}</Box>
                      {hasInd && (
                        <Box component="span" sx={{
                          fontSize: 10, color: 'text.primary', ...monoSx,
                          textAlign: 'right', overflow: 'hidden',
                          textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                        }}>
                          {indicators.slice(0, 3).join(', ')}
                        </Box>
                      )}
                    </Box>
                  </Box>
                );
              })}
            </Box>
            <Typography sx={{ mt: 1, fontSize: 11, color: 'text.tertiary', fontStyle: 'italic' }}>
              Focus detections on the top half (host artifacts, tools, TTPs) — they take attackers
              weeks to months to replace; hashes/IPs they swap in seconds.
            </Typography>
          </Box>
        </Block>
      )}

      {/* ── Admiralty Code — evidence reliability ratings ───────────────── */}
      {evid.length > 0 && (
        <Block title="Admiralty Code · NATO STANAG 2511 evidence reliability">
          {evid.map((e, i) => {
            const c = admColor[e.source_reliability?.[0]?.toUpperCase()] || '#848592';
            return (
              <Box component="li" key={i} sx={{
                py: 0.875, listStyle: 'none', borderTop: borderTop(i),
              }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.375 }}>
                  <MuiTag label={e.rating || '?'} color={c}/>
                  <Typography sx={{ fontSize: 11, color: 'text.tertiary' }}>
                    source={e.source_reliability || '?'} · cred={e.info_credibility || '?'}
                  </Typography>
                </Box>
                <Typography sx={{ fontSize: 12, color: 'text.primary', mb: 0.25 }}>{e.evidence}</Typography>
                {e.rationale && (
                  <Typography sx={{ fontSize: 11, color: 'text.tertiary', lineHeight: 1.5 }}>{e.rationale}</Typography>
                )}
              </Box>
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

  const borderTop = (i) => i > 0 ? `1px solid ${muiAlpha('#ffffff', 0.06)}` : 'none';
  const monoSx = { fontFamily: '"IBM Plex Mono", monospace' };

  return (
    <Card title="Threat intel cross-references" accent="#0fbcff"
      badge={`${kev.length} KEV · ${lolbas.length} LOLBAS · ${kits.length} kit · ${atomic.length} TTP`}>
      {kits.length > 0 && (
        <Block title={`Phishing-kit fingerprints (${kits.length})`}>
          {kits.map((k, i) => (
            <Box component="li" key={i} sx={{ py: 1, borderTop: borderTop(i), listStyle: 'none' }}>
              <Stack direction="row" alignItems="center" spacing={1} flexWrap="wrap" sx={{ mb: 0.5 }}>
                <MuiTag label={k.kit} color="#EE3838"/>
                <Typography sx={{ fontSize: 11, color: 'text.disabled' }}>
                  {k.patterns_matched} pattern{k.patterns_matched > 1 ? 's' : ''}
                </Typography>
              </Stack>
              {k.url && (
                <Box sx={{ ...monoSx, fontSize: 11, color: 'text.primary',
                  wordBreak: 'break-all', lineHeight: 1.5 }}>{k.url}</Box>
              )}
            </Box>
          ))}
        </Block>
      )}

      {kev.length > 0 && (
        <Block title={`Actively exploited CVEs · CISA KEV (${kev.length})`}>
          {kev.map((k, i) => {
            const epss = k.epss;
            const epssColor = epss?.tier === 'critical' ? '#EE3838'
              : epss?.tier === 'high' ? '#E6700F'
              : epss?.tier === 'medium' ? '#E1B823' : '#848592';
            return (
              <Box component="li" key={i} sx={{ py: 1, borderTop: borderTop(i), listStyle: 'none' }}>
                <Stack direction="row" alignItems="center" spacing={1} flexWrap="wrap" sx={{ mb: 0.5 }}>
                  <Box component="span" sx={{ ...monoSx, fontSize: 12, color: 'error.main', fontWeight: 600 }}>{k.cve}</Box>
                  <MuiTag label={k.vendor} color="#848592"/>
                  <MuiTag label={k.product} color="#848592"/>
                  {k.ransomware_use && <MuiTag label="ransomware" color="#EE3838"/>}
                  {epss && <MuiTag label={`EPSS ${epss.epss_percent}% · ${epss.tier}`} color={epssColor}/>}
                  {k.date_added && (
                    <Typography sx={{ fontSize: 11, color: 'text.disabled', ml: 'auto !important' }}>
                      added {k.date_added}
                    </Typography>
                  )}
                </Stack>
                <Typography sx={{ fontSize: 12, color: 'text.primary', mb: 0.375 }}>{k.name}</Typography>
                {k.description && (
                  <Typography sx={{ fontSize: 11, color: 'text.tertiary', lineHeight: 1.55 }}>{k.description}</Typography>
                )}
                {k.required_action && (
                  <Typography sx={{ fontSize: 11, color: 'warning.main', mt: 0.625 }}>
                    Required action: {k.required_action.slice(0, 180)}
                  </Typography>
                )}
              </Box>
            );
          })}
        </Block>
      )}

      {lolbas.length > 0 && (
        <Block title={`Living-off-the-land binaries · LOLBAS (${lolbas.length})`}>
          {lolbas.map((l, i) => (
            <Box component="li" key={i} sx={{ py: 1, borderTop: borderTop(i), listStyle: 'none' }}>
              <Stack direction="row" alignItems="center" spacing={1} flexWrap="wrap" sx={{ mb: 0.5 }}>
                <Box component="span" sx={{ ...monoSx, fontSize: 12, color: 'warning.main', fontWeight: 600 }}>{l.name}</Box>
                {l.categories?.slice(0, 4).map(c => <MuiTag key={c} label={c} color="#848592"/>)}
                {l.url && (
                  <Box component="a" href={l.url} target="_blank" rel="noreferrer"
                    sx={{
                      ml: 'auto !important', fontSize: 11, color: 'primary.main',
                      display: 'inline-flex', alignItems: 'center', gap: 0.25,
                      textDecoration: 'none', '&:hover': { textDecoration: 'underline' },
                    }}>
                    details <ArrowUpRight size={11}/>
                  </Box>
                )}
              </Stack>
              {l.description && (
                <Typography sx={{ fontSize: 11, color: 'text.tertiary', lineHeight: 1.55 }}>{l.description}</Typography>
              )}
              {l.examples?.length > 0 && (
                <Box component="ul" sx={{ m: '5px 0 0 14px', p: 0, fontSize: 11, color: 'text.disabled', lineHeight: 1.6 }}>
                  {l.examples.slice(0, 2).map((e, j) => <li key={j}>{e}</li>)}
                </Box>
              )}
            </Box>
          ))}
        </Block>
      )}

      {rmm.length > 0 && (
        <Block title={`Remote-management tools detected · RMM abuse (${rmm.length})`}>
          {rmm.map((r, i) => (
            <Box component="li" key={i} sx={{ py: 1, borderTop: borderTop(i), listStyle: 'none' }}>
              <Stack direction="row" alignItems="center" spacing={1} flexWrap="wrap" sx={{ mb: 0.5 }}>
                <Box component="span" sx={{ ...monoSx, fontSize: 12, color: 'warning.main', fontWeight: 600 }}>{r.binary}</Box>
                <MuiTag label={r.vendor} color="#848592"/>
                {r.groups?.slice(0, 4).map(g => <MuiTag key={g} label={g} color="#EE3838"/>)}
              </Stack>
              <Typography sx={{ fontSize: 11, color: 'text.tertiary', lineHeight: 1.55 }}>{r.description}</Typography>
            </Box>
          ))}
        </Block>
      )}

      {paths.length > 0 && (
        <Block title={`Suspicious filesystem paths (${paths.length})`}>
          {paths.map((p, i) => (
            <Box component="li" key={i} sx={{
              py: 0.75, borderTop: borderTop(i), listStyle: 'none',
              fontSize: 12, color: 'text.primary',
            }}>
              <Box component="span" sx={{ color: 'warning.main' }}>›</Box> {p.label}
            </Box>
          ))}
        </Block>
      )}

      {drivers.length > 0 && (
        <Block title={`Vulnerable drivers · LOLDrivers (${drivers.length})`}>
          {drivers.map((d, i) => (
            <Box component="li" key={i} sx={{ py: 1, borderTop: borderTop(i), listStyle: 'none' }}>
              <Stack direction="row" alignItems="center" spacing={1} flexWrap="wrap" sx={{ mb: 0.5 }}>
                <Box component="span" sx={{ ...monoSx, fontSize: 12, color: 'error.main', fontWeight: 600 }}>{d.value}</Box>
                <MuiTag label={d.category} color={d.category === 'malicious' ? '#EE3838' : '#E6700F'}/>
                <MuiTag label={`match: ${d.match_type}`} color="#848592"/>
                {d.mitre && <MuiTag label={d.mitre} color="#0fbcff"/>}
                {d.ref && (
                  <Box component="a" href={d.ref} target="_blank" rel="noreferrer"
                    sx={{
                      ml: 'auto !important', fontSize: 11, color: 'primary.main',
                      display: 'inline-flex', alignItems: 'center', gap: 0.25,
                      textDecoration: 'none', '&:hover': { textDecoration: 'underline' },
                    }}>
                    reference <ArrowUpRight size={11}/>
                  </Box>
                )}
              </Stack>
              {d.tags?.length > 0 && (
                <Typography sx={{ fontSize: 11, color: 'text.tertiary', mt: 0.375 }}>
                  Tags: {d.tags.join(', ')}
                </Typography>
              )}
            </Box>
          ))}
        </Block>
      )}

      {atomic.length > 0 && (
        <Block title={`Attack examples · Atomic Red Team (${atomic.length} techniques)`}>
          {atomic.map((a, i) => (
            <Box component="li" key={i} sx={{ py: 1.25, borderTop: borderTop(i), listStyle: 'none' }}>
              <Box sx={{ fontSize: 12, color: 'text.primary', fontWeight: 600, mb: 0.75 }}>
                <Box component="span" sx={{ color: 'info.main', ...monoSx, mr: 1 }}>
                  {a.technique.split(' ')[0]}
                </Box>
                {a.technique.split(' - ').slice(1).join(' - ')}
              </Box>
              {a.tests.map((tst, j) => (
                <Box key={j} sx={{ mb: 0.75, pl: 1, borderLeft: `2px solid ${muiAlpha('#ffffff', 0.12)}` }}>
                  <Typography sx={{ fontSize: 11, color: 'text.primary', mb: 0.375 }}>{tst.name}</Typography>
                  {tst.command && (
                    <Box component="pre" sx={{
                      backgroundColor: '#070d19',
                      border: `1px solid ${muiAlpha('#ffffff', 0.12)}`,
                      borderRadius: '4px',
                      p: '6px 9px', fontSize: 11, color: 'primary.main', ...monoSx,
                      my: '2px', whiteSpace: 'pre-wrap', wordBreak: 'break-all',
                      maxHeight: 80, overflow: 'auto',
                    }}>
                      {tst.command.split('\n')[0].slice(0, 200)}
                    </Box>
                  )}
                </Box>
              ))}
            </Box>
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
    <Card title="Detection content & hunt queries" accent="#0fbcff" badge={`${tabs.length} platforms`}>
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
    <Card title="Network detection · JA3 / JA4 fingerprints" accent="#B286FF"
      badge={`${fps.length} C2 framework${fps.length === 1 ? '' : 's'}`} defaultOpen={false}>
      <Typography sx={{ fontSize: 12, color: 'text.tertiary', mb: 1.5, lineHeight: 1.6 }}>
        TLS handshake fingerprints for known C2 frameworks relevant to this alert. Hunt these
        in your Zeek / Suricata / EDR network logs to catch the C2 channel itself, not just the IOC.
      </Typography>
      <MuiTableContainer component={MuiPaper} elevation={0} sx={{
        backgroundColor: '#0C1524',
        border: `1px solid ${muiAlpha('#ffffff', 0.12)}`,
        borderRadius: '4px', overflow: 'hidden', mb: 1.5,
      }}>
        <MuiTable size="small" sx={{ fontSize: 12 }}>
          <MuiTableHead>
            <MuiTableRow sx={{ backgroundColor: '#070d19' }}>
              {['Framework', 'JA3', 'JA4', 'Notes'].map(h => (
                <MuiTableCell key={h} sx={{
                  color: 'text.disabled', fontWeight: 500, fontSize: 11,
                  borderBottom: `1px solid ${muiAlpha('#ffffff', 0.12)}`,
                }}>{h}</MuiTableCell>
              ))}
            </MuiTableRow>
          </MuiTableHead>
          <MuiTableBody>
            {fps.map((f, i) => (
              <MuiTableRow key={i}>
                <MuiTableCell sx={{ color: 'text.primary', fontWeight: 500 }}>{f.framework}</MuiTableCell>
                <MuiTableCell sx={{
                  fontFamily: '"IBM Plex Mono", monospace', fontSize: 11, color: 'primary.main',
                }}>{f.ja3 || '—'}</MuiTableCell>
                <MuiTableCell sx={{
                  fontFamily: '"IBM Plex Mono", monospace', fontSize: 11, color: '#B286FF',
                }}>{f.ja4 || '—'}</MuiTableCell>
                <MuiTableCell sx={{ fontSize: 11, color: 'text.tertiary', maxWidth: 280 }}>{f.notes}</MuiTableCell>
              </MuiTableRow>
            ))}
          </MuiTableBody>
        </MuiTable>
      </MuiTableContainer>
      {sigma && (
        <Box sx={{ mb: 1.5 }}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 0.75 }}>
            <Typography sx={{ fontSize: 12, fontWeight: 600, color: 'text.primary' }}>
              Sigma — JA3/JA4 selection
            </Typography>
            <CopyBtn text={sigma}/>
          </Box>
          <MuiCodeBlock maxHeight={200}>{sigma}</MuiCodeBlock>
        </Box>
      )}
      {kql && (
        <Box>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 0.75 }}>
            <Typography sx={{ fontSize: 12, fontWeight: 600, color: 'text.primary' }}>
              KQL — let statements for Sentinel
            </Typography>
            <CopyBtn text={kql}/>
          </Box>
          <MuiCodeBlock maxHeight={200}>{kql}</MuiCodeBlock>
        </Box>
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
  const monoSx = { fontFamily: '"IBM Plex Mono", monospace' };
  const busy = submission?.state === 'submitting' || submission?.state === 'polling';
  return (
    <Card title="Live URL scan · URLScan.io" accent="#0fbcff" defaultOpen={false}
      badge={`${urls.length} URL${urls.length === 1 ? '' : 's'} available`}>
      <Stack direction="row" spacing={1} sx={{ mb: 1.5 }}>
        <MuiTextField
          select
          SelectProps={{ native: true }}
          value={target}
          onChange={e => setTarget(e.target.value)}
          size="small"
          fullWidth
          sx={{ '& .MuiInputBase-input': { ...monoSx, fontSize: 12 } }}
        >
          {urls.map(u => (
            <option key={u} value={u}>{u.length > 80 ? u.slice(0, 77) + '…' : u}</option>
          ))}
        </MuiTextField>
        <MuiButton variant="contained" size="small" onClick={submit} disabled={busy}
          sx={{ minWidth: 100 }}>
          Submit
        </MuiButton>
      </Stack>

      {submission?.state === 'submitting' && (
        <Typography sx={{ fontSize: 12, color: 'text.tertiary' }}>Submitting to URLScan…</Typography>
      )}
      {submission?.state === 'polling' && (
        <Typography sx={{ fontSize: 12, color: 'primary.main' }}>
          Scan in progress — polling every 10s (typically 30–60s)…
        </Typography>
      )}
      {submission?.state === 'timeout' && (
        <Typography sx={{ fontSize: 12, color: 'warning.main' }}>
          Scan still processing after 3 min. View it directly:{' '}
          <Box component="a" href={submission.result_url} target="_blank" rel="noreferrer"
            sx={{ color: 'primary.main', textDecoration: 'none', '&:hover': { textDecoration: 'underline' } }}>
            {submission.result_url}
          </Box>
        </Typography>
      )}
      {submission?.state === 'error' && (
        <Typography sx={{ fontSize: 12, color: 'error.main' }}>{submission.error}</Typography>
      )}

      {submission?.state === 'done' && submission.report && (() => {
        const r = submission.report;
        const verdictColor = r.verdict === 'malicious' ? '#EE3838'
          : r.verdict === 'suspicious' ? '#E6700F' : '#16AD34';
        return (
          <MuiPaper elevation={0} sx={{
            backgroundColor: '#0C1524',
            border: `1px solid ${muiAlpha('#ffffff', 0.12)}`,
            borderLeft: `3px solid ${verdictColor}`,
            borderRadius: '4px', p: '14px 16px',
          }}>
            <Box sx={{
              display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start',
              mb: 1.5, gap: 1.5,
            }}>
              <Box>
                <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 0.5 }} flexWrap="wrap">
                  <MuiTag label={`verdict: ${r.verdict}`} color={verdictColor}/>
                  {r.score != null && <MuiTag label={`score ${r.score}`} color="#E6700F"/>}
                  {r.country && <MuiTag label={r.country} color="#848592"/>}
                </Stack>
                {r.page_title && (
                  <Typography sx={{ fontSize: 13, color: 'text.primary', fontWeight: 500, mb: 0.5 }}>
                    {r.page_title}
                  </Typography>
                )}
                <Box sx={{ fontSize: 11, color: 'text.tertiary', ...monoSx, wordBreak: 'break-all' }}>
                  {r.final_url}
                </Box>
              </Box>
              <Box component="a" href={r.report_url} target="_blank" rel="noreferrer"
                sx={{
                  fontSize: 11, color: 'primary.main',
                  display: 'inline-flex', alignItems: 'center', gap: 0.375,
                  flexShrink: 0, textDecoration: 'none',
                  '&:hover': { textDecoration: 'underline' },
                }}>
                full report <ArrowUpRight size={11}/>
              </Box>
            </Box>
            {r.screenshot && (
              <Box component="a" href={r.screenshot} target="_blank" rel="noreferrer">
                <Box component="img" src={r.screenshot} alt="URLScan screenshot"
                  sx={{
                    width: '100%', maxWidth: 560, borderRadius: '4px',
                    border: `1px solid ${muiAlpha('#ffffff', 0.12)}`,
                    display: 'block', mb: 1.5,
                  }}/>
              </Box>
            )}
            <Box sx={{ display: 'grid', gridTemplateColumns: 'repeat(2,1fr)', gap: 1, fontSize: 11 }}>
              {r.ip && (
                <Box>
                  <Box component="span" sx={{ color: 'text.disabled' }}>IP:</Box>{' '}
                  <Box component="span" sx={{ color: 'text.primary', ...monoSx }}>{r.ip}</Box>
                </Box>
              )}
              {r.asnname && (
                <Box>
                  <Box component="span" sx={{ color: 'text.disabled' }}>ASN:</Box>{' '}
                  <Box component="span" sx={{ color: 'text.primary' }}>{r.asnname}</Box>
                </Box>
              )}
              {r.server && (
                <Box>
                  <Box component="span" sx={{ color: 'text.disabled' }}>Server:</Box>{' '}
                  <Box component="span" sx={{ color: 'text.primary' }}>{r.server}</Box>
                </Box>
              )}
              {r.urls_loaded != null && (
                <Box>
                  <Box component="span" sx={{ color: 'text.disabled' }}>Page loaded:</Box>{' '}
                  <Box component="span" sx={{ color: 'text.primary' }}>
                    {r.urls_loaded} URLs / {r.requests} requests
                  </Box>
                </Box>
              )}
            </Box>
            {r.categories?.length > 0 && (
              <Stack direction="row" spacing={0.5} flexWrap="wrap" sx={{ mt: 1 }}>
                {r.categories.map(c => <MuiTag key={c} label={c} color="#848592"/>)}
              </Stack>
            )}
          </MuiPaper>
        );
      })()}
    </Card>
  );
}

/* ─── enrichments ─────────────────────────────────────────────────────────────── */
function Enrichments({ enrichments }) {
  if (!enrichments || !Object.keys(enrichments).length) return null;
  const monoSx = { fontFamily: '"IBM Plex Mono", monospace' };
  return (
    <Card title="Raw enrichment data" accent="#848592" defaultOpen={false}>
      {Object.entries(enrichments).map(([iocType, iocMap]) =>
        Object.entries(iocMap || {}).map(([ioc, data]) => (
          <Box key={ioc} sx={{ mb: 2 }}>
            <Stack direction="row" alignItems="center" spacing={1} sx={{ mb: 1 }}>
              <TypeTag type={iocType}/>
              <Box component="span" sx={{
                fontSize: 12, color: 'text.primary', ...monoSx, wordBreak: 'break-all',
              }}>{ioc}</Box>
            </Stack>
            <Box sx={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fill, minmax(240px, 1fr))',
              gap: 0.75,
            }}>
              {Object.entries(data).filter(([k]) => k !== 'cached').map(([src, srcData]) => {
                if (!srcData || typeof srcData !== 'object') return null;
                const entries = Object.entries(srcData).filter(
                  ([, v]) => v !== null && v !== undefined && v !== '' && !(Array.isArray(v) && !v.length)
                );
                if (!entries.length) return null;
                return (
                  <MuiPaper key={src} elevation={0} sx={{
                    backgroundColor: '#0C1524',
                    border: `1px solid ${muiAlpha('#ffffff', 0.12)}`,
                    borderRadius: '4px', p: 1.25,
                  }}>
                    <Typography sx={{ fontSize: 11, color: 'primary.main', fontWeight: 600, mb: 0.75 }}>
                      {src}
                    </Typography>
                    {entries.slice(0, 6).map(([k, v]) => (
                      <Box key={k} sx={{
                        display: 'flex', justifyContent: 'space-between',
                        fontSize: 11, py: 0.25, gap: 1,
                      }}>
                        <Box component="span" sx={{ color: 'text.disabled', flexShrink: 0 }}>{k}</Box>
                        <Box component="span" sx={{
                          color: 'text.primary', textAlign: 'right',
                          wordBreak: 'break-all', maxWidth: 140, ...monoSx,
                        }}>
                          {Array.isArray(v) ? v.slice(0, 4).join(', ') : String(v).slice(0, 80)}
                        </Box>
                      </Box>
                    ))}
                  </MuiPaper>
                );
              })}
            </Box>
          </Box>
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

  return (
    <Card title="Investigation report" accent="#B286FF" defaultOpen={false} badge={`${total} indicators`}>
      <Box sx={{ display: 'flex', justifyContent: 'flex-end', mb: 1.75 }}>
        <MuiButton onClick={print} data-recon-print variant="outlined" size="small"
          startIcon={<Printer size={12}/>} sx={{ color: '#B286FF', borderColor: muiAlpha('#B286FF', 0.4) }}>
          Print / Save PDF
        </MuiButton>
      </Box>

      <Box ref={ref} sx={{
        backgroundColor: '#070d19',
        border: `1px solid ${muiAlpha('#ffffff', 0.12)}`,
        borderRadius: '4px', p: 3.5,
      }}>
        <Box component="header" sx={{
          display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end',
          mb: 2.75, pb: 2, borderBottom: `1px solid ${muiAlpha('#ffffff', 0.12)}`,
        }}>
          <Box>
            <Typography component="h1" sx={{
              fontSize: 20, color: 'text.primary', fontWeight: 700, letterSpacing: '-0.02em',
            }}>Threat intelligence report</Typography>
            <Typography sx={{ fontSize: 12, color: 'text.disabled', mt: 0.5 }}>RECON Platform</Typography>
          </Box>
          <Box sx={{ textAlign: 'right', fontSize: 12, color: 'text.tertiary' }}>
            <Box sx={{ fontVariantNumeric: 'tabular-nums' }}>{ts.toLocaleDateString()}</Box>
            <Box sx={{ fontVariantNumeric: 'tabular-nums' }}>{ts.toLocaleTimeString()}</Box>
          </Box>
        </Box>

        <Box sx={{ mb: 2.25 }}>
          <Typography component="label" sx={{
            fontSize: 12, color: 'text.disabled', display: 'block', mb: 0.75,
          }}>Analyst</Typography>
          <MuiTextField value={analyst} onChange={e => setAnalyst(e.target.value)}
            placeholder="Your name" size="small" fullWidth/>
        </Box>

        <MuiPaper elevation={0} sx={{
          backgroundColor: lc.bg,
          border: `1px solid ${lc.line}`,
          borderRadius: '4px', p: '14px 16px', mb: 2.5,
        }}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <Box sx={{ width: 8, height: 8, borderRadius: 99, backgroundColor: lc.fg }}/>
              <Typography sx={{ color: lc.fg, fontWeight: 600, fontSize: 13 }}>{rs.threat_level}</Typography>
            </Box>
            <Typography sx={{ fontSize: 12, color: 'text.tertiary' }}>
              Confidence {Math.round((rs.confidence || 0) * 100)}%
            </Typography>
          </Box>
          <Typography sx={{ fontSize: 13, color: 'text.primary', lineHeight: 1.7 }}>{rs.summary}</Typography>
        </MuiPaper>

        <Typography variant="h3" sx={{ fontSize:13, color:'text.tertiary', fontWeight:500, mb:1 }}>
          Indicator inventory · {total}
        </Typography>
        <MuiTable size="small" sx={{ mb:2.5 }}>
          <MuiTableHead>
            <MuiTableRow>
              {['Type','Indicator','Verdict','Reason'].map(h =>
                <MuiTableCell key={h}>{h}</MuiTableCell>
              )}
            </MuiTableRow>
          </MuiTableHead>
          <MuiTableBody>
            {Object.entries(iocs).flatMap(([type,list]) => (list||[]).map(ioc => {
              const a = rs.ioc_assessments?.find(x => x.ioc === ioc);
              return (
                <MuiTableRow key={ioc} hover>
                  <MuiTableCell><TypeTag type={type}/></MuiTableCell>
                  <MuiTableCell sx={{ fontFamily:'"IBM Plex Mono", monospace',
                    wordBreak:'break-all' }}>{ioc}</MuiTableCell>
                  <MuiTableCell>{a && <Verdict verdict={a.verdict} size="small"/>}</MuiTableCell>
                  <MuiTableCell sx={{ fontSize:11, color:'text.tertiary', maxWidth:240 }}>
                    {a?.reason || ''}
                  </MuiTableCell>
                </MuiTableRow>
              );
            }))}
          </MuiTableBody>
        </MuiTable>

        {rs.mitre_techniques?.length > 0 && (
          <>
            <Typography variant="h3" sx={{ fontSize:13, color:'text.tertiary', fontWeight:500, mb:1 }}>
              MITRE ATT&amp;CK
            </Typography>
            <Box sx={{ display:'flex', gap:0.5, flexWrap:'wrap', mb:2.5 }}>
              {rs.mitre_techniques.map((t_, i) => (
                <MuiTag key={i} label={t_} color="#0fbcff"
                  sx={{ fontFamily:'"IBM Plex Mono", monospace' }}/>
              ))}
            </Box>
          </>
        )}

        {result.sigma_rule && (
          <>
            <Typography variant="h3" sx={{ fontSize:13, color:'text.tertiary', fontWeight:500, mb:1 }}>
              Sigma detection rule
            </Typography>
            <Box sx={{ mb:2.5 }}>
              <MuiCodeBlock maxHeight={200}>{result.sigma_rule}</MuiCodeBlock>
            </Box>
          </>
        )}

        {rs.recommended_actions?.length > 0 && (
          <>
            <Typography variant="h3" sx={{
              fontSize: 13, color: 'text.tertiary', fontWeight: 500, mb: 1,
            }}>Recommended actions</Typography>
            <Box component="ol" sx={{ pl: 2.5, mb: 2.5 }}>
              {rs.recommended_actions.map((a, i) => (
                <Box component="li" key={i} sx={{
                  fontSize: 13, color: 'text.primary', lineHeight: 1.7, mb: 0.5,
                }}>{a}</Box>
              ))}
            </Box>
          </>
        )}

        <Typography variant="h3" sx={{
          fontSize: 13, color: 'text.tertiary', fontWeight: 500, mb: 1,
        }}>Analyst notes</Typography>
        <MuiTextField value={notes} onChange={e => setNotes(e.target.value)}
          placeholder="Add observations, context, or follow-up items..."
          multiline minRows={4} fullWidth size="small"
          sx={{ '& .MuiInputBase-input': { lineHeight: 1.7 } }}/>

        <Box sx={{
          borderTop: `1px solid ${muiAlpha('#ffffff', 0.12)}`,
          pt: 1.75, mt: 2.5,
          display: 'flex', justifyContent: 'space-between',
          fontSize: 11, color: 'text.disabled',
        }}>
          <Box component="span" sx={{ fontVariantNumeric: 'tabular-nums' }}>{ts.toISOString()}</Box>
          <Box component="span">Confidential — Internal use only</Box>
        </Box>
      </Box>
    </Card>
  );
}

/* ─── sidebar ─────────────────────────────────────────────────────────────────
 * Adapted from OpenCTI (AGPL-3.0) — LeftBar.jsx pattern.
 * Uses MUI Drawer with the OpenCTI nav width/styling, hosting the input area
 * (drop zone + textarea + AgentPipeline) and the extracted-IOCs panel.
 */
function Sidebar({ onResult, onPartialResult, currentResult, onScanFile, scanState }) {
  const [logText, setLogText] = useState('');
  const [dragOver, setDragOver] = useState(false);

  const handleFile = useCallback(file => {
    if (!file) return;
    onScanFile?.(file);
  }, [onScanFile]);

  // Cmd/Ctrl+Enter triggers analysis via the AgentPipeline's button
  // Spec §9 keyboard shortcuts
  useEffect(() => {
    const handler = (e) => {
      const inField = ['INPUT', 'TEXTAREA'].includes(document.activeElement?.tagName);
      // Ctrl+Enter — submit analysis (works even while typing)
      if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') {
        e.preventDefault();
        document.querySelector('[data-recon-analyze]')?.click();
      }
      // Ctrl+N — clear textarea + result for new investigation
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'n') {
        e.preventDefault();
        setLogText('');
        onResult(null);
      }
      // Ctrl+S — trigger Print/Save PDF on the Report card if present
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 's') {
        const btn = document.querySelector('[data-recon-print]');
        if (btn) { e.preventDefault(); btn.click(); }
      }
      // ? — toggle shortcut help (only when not typing in a field)
      if (e.key === '?' && !inField) {
        e.preventDefault();
        window.dispatchEvent(new CustomEvent('recon:toggle-shortcuts'));
      }
      // Escape — close shortcut help / clear focus
      if (e.key === 'Escape') {
        window.dispatchEvent(new CustomEvent('recon:close-overlays'));
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [onResult]);

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
        {/* YARA file scanner drop zone — dropping a file runs /api/scan-file */}
        <Box
          onDragOver={e => { e.preventDefault(); setDragOver(true); }}
          onDragLeave={() => setDragOver(false)}
          onDrop={e => {
            e.preventDefault(); setDragOver(false);
            if (scanState?.scanning) return;
            handleFile(e.dataTransfer.files[0]);
          }}
          onClick={() => !scanState?.scanning && document.getElementById('sidebarFile').click()}
          sx={{
            display: 'flex', alignItems: 'center', gap: 1.25,
            p: '12px 14px',
            backgroundColor: dragOver ? muiAlpha('#B286FF', 0.08) : 'background.secondary',
            border: `1.5px dashed ${dragOver ? '#B286FF' : muiAlpha('#ffffff', 0.12)}`,
            borderRadius: '4px',
            cursor: scanState?.scanning ? 'wait' : 'pointer',
            color: 'text.tertiary', fontSize: 13,
            mb: 1.25,
            transition: 'all .15s',
            '&:hover': { borderColor: scanState?.scanning ? undefined : muiAlpha('#B286FF', 0.5) },
          }}
        >
          <FileSearch size={16} color="#B286FF" style={{ flexShrink: 0 }}/>
          <Box sx={{ flex: 1, minWidth: 0 }}>
            <Typography sx={{
              color: dragOver ? '#B286FF' : 'text.primary',
              fontSize: 12, fontWeight: 500,
            }}>
              {scanState?.scanning ? 'Scanning…' : 'Drop a file to scan with YARA'}
            </Typography>
            <Typography sx={{ color: 'text.tertiary', fontSize: 11, mt: 0.25 }}>
              binary analysis · sandbox lookup · ≤ 50 MB
            </Typography>
          </Box>
          <input id="sidebarFile" type="file"
            style={{ display: 'none' }} disabled={scanState?.scanning}
            onChange={e => handleFile(e.target.files[0])}/>
        </Box>
        {scanState?.error && (
          <Typography sx={{ color: 'error.main', fontSize: 11, mb: 1.25, mt: -0.5 }}>
            {scanState.error}
          </Typography>
        )}
        {scanState?.result && !scanState.scanning && (
          <Typography sx={{ color: 'success.main', fontSize: 11, mb: 1.25, mt: -0.5 }}>
            Scanned {scanState.result.filename} — see YARA file scanner panel below
          </Typography>
        )}

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
    <Card title="Cross-investigation pivot" accent="#E6700F"
      badge={`${pivots.length} indicator${pivots.length === 1 ? '' : 's'} seen before`}>
      <Typography sx={{ fontSize: 12, color: 'text.tertiary', mb: 1.25, lineHeight: 1.6 }}>
        These indicators have appeared in previous investigations during this session. Consider whether the
        cases are related — same actor, same campaign, or rolling reinvestigation.
      </Typography>
      {pivots.map((p, i) => (
        <Box key={i} sx={{
          py: 1.25,
          borderTop: i > 0 ? `1px solid ${muiAlpha('#ffffff', 0.06)}` : 'none',
        }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5 }}>
            <TypeTag type={p.type}/>
            <Box sx={{
              fontFamily: '"IBM Plex Mono", monospace',
              fontSize: 12, color: 'text.primary', wordBreak: 'break-all',
            }}>{p.ioc}</Box>
          </Box>
          <Box sx={{ display: 'flex', gap: 0.75, flexWrap: 'wrap', ml: 3 }}>
            {p.sightings.map((s, j) => {
              const c = (levelStyle[s.threat_level] || levelStyle.INFORMATIONAL).fg;
              const url = `${window.location.pathname}#run/${s.run_id}`;
              const when = new Date(s.timestamp);
              const ago = (() => {
                const m = Math.round((Date.now() - when.getTime()) / 60000);
                return m < 60 ? `${m}m ago` : m < 1440 ? `${Math.round(m/60)}h ago` : `${Math.round(m/1440)}d ago`;
              })();
              return (
                <Box key={j} component="a" href={url} sx={{
                  backgroundColor: 'background.secondary',
                  border: `1px solid ${muiAlpha('#ffffff', 0.12)}`,
                  borderLeft: `2px solid ${c}`,
                  borderRadius: '4px', px: 1.125, py: 0.5,
                  fontSize: 11, color: 'text.primary',
                  textDecoration: 'none', display: 'inline-flex', gap: 0.75, alignItems: 'center',
                }}>
                  <Box component="span" sx={{ color: c, fontWeight: 600 }}>{s.threat_level}</Box>
                  <Box component="span" sx={{ color: 'text.tertiary' }}>· {ago}</Box>
                  <Box component="span" sx={{ color: 'text.disabled',
                    fontFamily: '"IBM Plex Mono", monospace' }}>{s.run_id.slice(0, 8)}</Box>
                </Box>
              );
            })}
          </Box>
        </Box>
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
    <Card title={`Bulk indicator matrix · ${rows.length} indicators`} accent="#0fbcff">
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
  const anchorRef = useRef(null);
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
    <Box sx={{ position:'relative' }}>
      <MuiButton ref={anchorRef} onClick={() => setOpen(o => !o)}
        variant="outlined" size="small"
        startIcon={<ArrowUpRight size={12}/>}>
        Send to…
      </MuiButton>
      <MuiMenu anchorEl={anchorRef.current} open={open} onClose={() => setOpen(false)}
        anchorOrigin={{ vertical:'bottom', horizontal:'right' }}
        transformOrigin={{ vertical:'top', horizontal:'right' }}>
        {targets.map(([target]) => (
          <MuiMenuItem key={target} onClick={() => send(target)} sx={{ fontSize: 13 }}>
            {targetLabels[target] || target}
          </MuiMenuItem>
        ))}
      </MuiMenu>
      {status && (
        <Box sx={{
          position:'absolute', top:'calc(100% + 8px)', right:0,
          backgroundColor:'background.secondary',
          border: theme => `1px solid ${muiAlpha(
            status.state==='ok' ? theme.palette.success.main
            : status.state==='err' ? theme.palette.error.main
            : theme.palette.primary.main, 0.4)}`,
          borderRadius:'4px', p:'7px 11px', fontSize:11,
          color: status.state==='ok' ? 'success.main'
               : status.state==='err' ? 'error.main' : 'primary.main',
          whiteSpace:'nowrap',
        }}>
          {status.state === 'sending' && `Sending to ${status.target}…`}
          {status.state === 'ok'      && `Sent to ${status.target}`}
          {status.state === 'err'     && `Failed: ${status.detail?.error || 'unknown'}`}
        </Box>
      )}
    </Box>
  );
}

/* ─── YARA file scan results panel ─────────────────────────────────────────────
 * Display-only. Upload happens in the left sidebar (drop zone). This card only
 * renders when there's a scan result to show.
 * --------------------------------------------------------------------------- */
function FileScanner({ scanning, result, error, submission, onDetonate }) {
  const detonate = onDetonate;
  if (!result && !error && !scanning) return null;

  const hasReport = result?.sandbox && Object.keys(result.sandbox).length > 0;

  return (
    <Card title="YARA file scan" accent="#B286FF" defaultOpen
      badge={result?.filename || (scanning ? 'scanning…' : 'binary analysis')}>
      {scanning && !result && (
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, color: '#B286FF', fontSize: 12 }}>
          <FileSearch size={14}/>Scanning file with YARA + sandbox lookup…
        </Box>
      )}
      {error && (
        <Box sx={{ color: 'error.main', fontSize: 12, mb: 1.25, mt: 1.25 }}>{error}</Box>
      )}
      {result && (() => {
        const monoSx = { fontFamily: '"IBM Plex Mono", monospace' };
        const stateColor = (s) => s === 'SUCCESS' ? '#16AD34' : s === 'ERROR' ? '#EE3838' : '#0fbcff';
        return (
        <>
          <MuiPaper elevation={0} sx={{
            backgroundColor: '#0C1524',
            border: `1px solid ${muiAlpha('#ffffff', 0.12)}`,
            borderRadius: '4px', p: '10px 12px', mb: 1.25,
          }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1 }}>
              <Typography sx={{ fontSize: 13, fontWeight: 600, color: 'text.primary' }}>{result.filename}</Typography>
              <Typography sx={{ fontSize: 11, color: 'text.disabled' }}>{(result.size / 1024).toFixed(1)} KB</Typography>
            </Box>
            {['md5', 'sha1', 'sha256'].map(k => (
              <Box key={k} sx={{ display: 'flex', gap: 1, fontSize: 11, py: 0.25 }}>
                <Box component="span" sx={{ color: 'text.disabled', minWidth: 50 }}>{k}</Box>
                <Box component="span" sx={{ color: 'text.primary', ...monoSx, wordBreak: 'break-all' }}>
                  {result.hashes[k]}
                </Box>
              </Box>
            ))}
          </MuiPaper>
          {result.loldrivers_hit && (
            <MuiPaper elevation={0} sx={{
              backgroundColor: muiAlpha('#EE3838', 0.08),
              border: `1px solid ${muiAlpha('#EE3838', 0.25)}`,
              borderLeft: `3px solid #EE3838`,
              borderRadius: '4px', p: '10px 12px', mb: 1.25,
            }}>
              <Typography sx={{ fontSize: 12, color: 'error.main', fontWeight: 600, mb: 0.5 }}>
                ⚠ Known vulnerable/malicious driver (LOLDrivers)
              </Typography>
              <Typography sx={{ fontSize: 11, color: 'text.primary' }}>
                Category: {result.loldrivers_hit.category} · MITRE: {result.loldrivers_hit.mitre}
              </Typography>
            </MuiPaper>
          )}

          {/* Cloud sandbox lookup — Hybrid Analysis / ANY.RUN */}
          {result.sandbox && Object.entries(result.sandbox).map(([name, sb]) => {
            const verdict = (sb.verdict || '').toLowerCase();
            const color = verdict.includes('mali') || verdict.includes('high') ? '#EE3838'
              : verdict.includes('suspic') || verdict.includes('medium') ? '#E6700F'
              : verdict.includes('clean') || verdict.includes('benign') || verdict.includes('no_specific') ? '#16AD34'
              : '#848592';
            const label = name === 'hybrid_analysis' ? 'Hybrid Analysis (CrowdStrike Falcon Sandbox)' : 'ANY.RUN';
            return (
              <MuiPaper key={name} elevation={0} sx={{
                backgroundColor: '#0C1524',
                border: `1px solid ${muiAlpha('#ffffff', 0.12)}`,
                borderLeft: `3px solid ${color}`,
                borderRadius: '4px', p: '12px 14px', mb: 1.25,
              }}>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 0.75 }}>
                  <Typography sx={{ fontSize: 12, fontWeight: 600, color: 'text.primary' }}>{label}</Typography>
                  {sb.url && (
                    <Box component="a" href={sb.url} target="_blank" rel="noreferrer" sx={{
                      fontSize: 11, color: 'primary.main',
                      display: 'inline-flex', alignItems: 'center', gap: 0.25,
                      textDecoration: 'none', '&:hover': { textDecoration: 'underline' },
                    }}>view report <ArrowUpRight size={11}/></Box>
                  )}
                </Box>
                <Stack direction="row" spacing={1} flexWrap="wrap" sx={{ mb: 0.75 }}>
                  <MuiTag label={`verdict: ${sb.verdict || 'unknown'}`} color={color}/>
                  {sb.threat_score != null && <MuiTag label={`score ${sb.threat_score}`} color="#E6700F"/>}
                  {sb.malware_family && (Array.isArray(sb.malware_family) ? sb.malware_family[0] : sb.malware_family) && (
                    <MuiTag color="#EE3838"
                      label={Array.isArray(sb.malware_family) ? sb.malware_family[0] : sb.malware_family}/>
                  )}
                  {sb.av_detect != null && <MuiTag label={`AV ${sb.av_detect}%`} color="#848592"/>}
                </Stack>
                {sb.mitre?.length > 0 && (
                  <Typography sx={{ fontSize: 11, color: 'text.tertiary' }}>
                    MITRE: {sb.mitre.filter(Boolean).slice(0, 6).join(' · ')}
                  </Typography>
                )}
                {sb.tags?.length > 0 && (
                  <Stack direction="row" spacing={0.5} flexWrap="wrap" sx={{ mt: 0.625 }}>
                    {sb.tags.slice(0, 8).map(tag => <MuiTag key={tag} label={tag} color="#848592"/>)}
                  </Stack>
                )}
              </MuiPaper>
            );
          })}
          {/* No existing sandbox report → offer to detonate */}
          {result.sha256 && !hasReport && !submission && (
            <MuiPaper elevation={0} sx={{
              backgroundColor: '#0C1524',
              border: `1px dashed ${muiAlpha('#ffffff', 0.12)}`,
              borderRadius: '4px', p: '12px 14px', mb: 1.25,
              display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 1.25,
            }}>
              <Box>
                <Typography sx={{ fontSize: 12, color: 'text.primary', fontWeight: 500 }}>
                  No existing sandbox report
                </Typography>
                <Typography sx={{ fontSize: 11, color: 'text.tertiary', mt: 0.25 }}>
                  Submit to Hybrid Analysis for fresh detonation (typically 3–10 minutes).
                </Typography>
              </Box>
              <MuiButton variant="contained" size="small" onClick={detonate}>Detonate sample</MuiButton>
            </MuiPaper>
          )}

          {/* Submission in progress */}
          {submission && (
            <MuiPaper elevation={0} sx={{
              backgroundColor: '#0C1524',
              border: `1px solid ${muiAlpha(stateColor(submission.state), 0.25)}`,
              borderLeft: `3px solid ${stateColor(submission.state)}`,
              borderRadius: '4px', p: '12px 14px', mb: 1.25,
            }}>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 0.75 }}>
                <Typography sx={{ fontSize: 12, color: 'text.primary', fontWeight: 600 }}>
                  Hybrid Analysis · {submission.filename || 'sample'}
                </Typography>
                <MuiTag label={submission.state} color={stateColor(submission.state)}/>
              </Box>
              {submission.state === 'IN_QUEUE' && (
                <Typography sx={{ fontSize: 11, color: 'text.tertiary' }}>Queued for detonation…</Typography>
              )}
              {submission.state === 'IN_PROGRESS' && (
                <Typography sx={{ fontSize: 11, color: 'text.tertiary' }}>
                  Detonating in Windows 10 sandbox… polling every 30s
                </Typography>
              )}
              {submission.state === 'ERROR' && (
                <Typography sx={{ fontSize: 11, color: 'error.main' }}>
                  {submission.error || 'Submission error'}
                </Typography>
              )}
              {submission.state === 'SUCCESS' && submission.summary && (
                <>
                  <Stack direction="row" spacing={0.75} flexWrap="wrap" sx={{ mt: 1 }}>
                    <MuiTag label={`verdict: ${submission.summary.verdict}`} color="#16AD34"/>
                    {submission.summary.threat_score != null && (
                      <MuiTag label={`score ${submission.summary.threat_score}`} color="#E6700F"/>
                    )}
                    {submission.summary.malware_family && (
                      <MuiTag color="#EE3838"
                        label={Array.isArray(submission.summary.malware_family)
                          ? submission.summary.malware_family[0]
                          : submission.summary.malware_family}/>
                    )}
                  </Stack>
                  {submission.summary.url && (
                    <Box component="a" href={submission.summary.url} target="_blank" rel="noreferrer" sx={{
                      fontSize: 11, color: 'primary.main', mt: 1,
                      display: 'inline-flex', alignItems: 'center', gap: 0.25,
                      textDecoration: 'none', '&:hover': { textDecoration: 'underline' },
                    }}>View full report <ArrowUpRight size={11}/></Box>
                  )}
                </>
              )}
            </MuiPaper>
          )}

          {result.yara_matches?.length > 0 ? (
            <Block title={`YARA matches (${result.yara_matches.length})`}>
              {result.yara_matches.map((m, i) => (
                <Box component="li" key={i} sx={{
                  py: 0.875, listStyle: 'none',
                  borderTop: i > 0 ? `1px solid ${muiAlpha('#ffffff', 0.06)}` : 'none',
                }}>
                  <Box sx={{ fontSize: 12, color: 'text.primary', ...monoSx, mb: 0.375 }}>{m.rule}</Box>
                  {m.description && (
                    <Typography sx={{ fontSize: 11, color: 'text.tertiary', lineHeight: 1.5 }}>{m.description}</Typography>
                  )}
                  <Stack direction="row" spacing={0.75} flexWrap="wrap" alignItems="center" sx={{ mt: 0.5 }}>
                    {m.tags?.map(tag => <MuiTag key={tag} label={tag} color="#848592"/>)}
                    {m.author && (
                      <Box component="span" sx={{ fontSize: 10, color: 'text.disabled' }}>by {m.author}</Box>
                    )}
                  </Stack>
                </Box>
              ))}
            </Block>
          ) : (
            <Typography sx={{ fontSize: 12, color: 'success.main', py: 1 }}>
              No YARA matches — file is clean against {result.yara_matches?.length === 0 ? 'all loaded rules' : 'available rules'}.
            </Typography>
          )}
        </>
        );
      })()}
    </Card>
  );
}

/* ─── app ─────────────────────────────────────────────────────────────────────── */
export default function App() {
  const [result, setResult] = useState(null);
  const [view, setView] = useState('detail'); // 'detail' | 'table'
  const [webhooks, setWebhooks] = useState({});
  const rs = result?.response_summary;

  // YARA file-scan state, lifted from FileScanner so the sidebar drop zone shares it.
  const [scanState, setScanState] = useState({
    scanning: false, result: null, error: null, file: null, submission: null,
  });

  const scanFile = useCallback(async (uploaded) => {
    if (!uploaded) return;
    setScanState({ scanning: true, result: null, error: null, file: uploaded, submission: null });
    const form = new FormData();
    form.append('file', uploaded);
    try {
      const resp = await fetch('/api/scan-file', { method: 'POST', body: form });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.detail || `HTTP ${resp.status}`);
      setScanState(s => ({ ...s, scanning: false, result: data }));
    } catch (e) {
      setScanState(s => ({ ...s, scanning: false, error: e.message }));
    }
  }, []);

  const detonateFile = useCallback(async () => {
    if (!scanState.file) return;
    setScanState(s => ({ ...s, error: null }));
    const form = new FormData();
    form.append('file', scanState.file);
    try {
      const resp = await fetch('/api/sandbox/submit', { method: 'POST', body: form });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.detail || `HTTP ${resp.status}`);
      setScanState(s => ({
        ...s,
        submission: { job_id: data.job_id, state: 'IN_QUEUE', submitted_at: data.submitted_at },
      }));
    } catch (e) {
      setScanState(s => ({ ...s, error: e.message }));
    }
  }, [scanState.file]);

  // Poll sandbox submission until terminal state
  useEffect(() => {
    const sub = scanState.submission;
    if (!sub?.job_id) return;
    if (['SUCCESS', 'ERROR'].includes(sub.state)) return;
    const poll = async () => {
      try {
        const r = await fetch(`/api/sandbox/job/${sub.job_id}`);
        const d = await r.json();
        setScanState(s => ({ ...s, submission: { ...s.submission, ...d } }));
      } catch (_) {}
    };
    const t = setInterval(poll, 30000);
    poll();
    return () => clearInterval(t);
  }, [scanState.submission?.job_id, scanState.submission?.state]);

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
    <Box sx={{
      display: 'flex', minHeight: '100vh',
      backgroundColor: 'background.default',
      color: 'text.primary',
    }}>
      <Sidebar
        onResult={setResult}
        onPartialResult={mergePartial}
        currentResult={result}
        onScanFile={scanFile}
        scanState={scanState}
      />

      <Box component="main" sx={{
        flex: 1, p: '24px 28px 48px', overflowY: 'auto', minWidth: 0,
      }}>
        {/* Top toolbar: view toggle + outbound actions only */}
        {result && (
          <Stack direction="row" justifyContent="space-between" alignItems="center" spacing={1} sx={{ mb: 1.75 }}>
            <MuiToggleButtonGroup
              value={view}
              exclusive
              size="small"
              onChange={(_, v) => v && setView(v)}
              sx={{ height: 32 }}
            >
              <MuiToggleButton value="detail" sx={{ px: 1.75, fontSize: 12, textTransform: 'none' }}>
                Detail
              </MuiToggleButton>
              <MuiToggleButton value="table" sx={{ px: 1.75, fontSize: 12, textTransform: 'none' }}>
                Table
                {isBulk && (
                  <Box component="span" sx={{ ml: 0.625, color: 'primary.main', fontSize: 10 }}>
                    ·{totalIOCs}
                  </Box>
                )}
              </MuiToggleButton>
            </MuiToggleButtonGroup>
            <SendToWebhook result={result} available={webhooks}/>
          </Stack>
        )}

        {!result && <Empty/>}

        {result && view === 'table' && (
          <>
            <PreFlight result={result}/>
            <Overview result={result}/>
            <SignalBanners result={result}/>
            <SuppressedIOCs result={result}/>
            <IOCPivot result={result}/>
            <BulkTable result={result}/>
            <Card title="Geographic distribution" accent="#0fbcff" noPad><MapTab result={result}/></Card>
            <Box sx={{ mb: 2 }}><ExportBar result={result}/></Box>
          </>
        )}

        {result && view === 'detail' && (
          <>
            <PreFlight result={result}/>
            <Overview result={result}/>
            <SignalBanners result={result}/>
            <SuppressedIOCs result={result}/>
            <ClarifyingQuestions result={result} onResult={setResult}/>
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

            <Card title="Geographic distribution" accent="#0fbcff" noPad>
              <MapTab result={result}/>
            </Card>

            <Card title="Pivot graph" accent="#0fbcff" noPad>
              <Box sx={{ p: '14px 16px' }}><PivotGraph result={result}/></Box>
            </Card>

            <Enrichments enrichments={result.enrichments}/>
            <Report result={result}/>
            {/* YARA scan results auto-appear here when sidebar drop runs a scan */}
            <FileScanner {...scanState} onDetonate={detonateFile}/>
            <Box sx={{ mb: 2 }}><ExportBar result={result}/></Box>
          </>
        )}

        {/* YARA scan results in empty state — only if sidebar drop already ran */}
        {!result && (scanState.result || scanState.scanning || scanState.error) && (
          <Box sx={{ mt: 4 }}>
            <FileScanner {...scanState} onDetonate={detonateFile}/>
          </Box>
        )}
      </Box>

      {/* Global keyframes — MUI CssBaseline doesn't include @keyframes */}
      <style>{`
        @keyframes pulse{0%,100%{opacity:1}50%{opacity:.5}}
        @keyframes spin{from{transform:rotate(0deg)}to{transform:rotate(360deg)}}
        a{color:inherit;transition:opacity .15s}
        a:hover{opacity:.8}
      `}</style>
    </Box>
  );
}
