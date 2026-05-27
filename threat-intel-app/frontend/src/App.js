import React, { useState, useCallback, useRef, useEffect } from 'react';
import {
  Upload, ChevronDown, ChevronRight, Copy, Check, Printer, Search,
  Activity, Database, Layers, Zap, Globe, Network, Shield, FileText,
  ArrowUpRight, AlertCircle, X, FileSearch, Mail, Hash, Link2,
} from 'lucide-react';

import MapTab            from './components/MapTab';
import PivotGraph        from './components/PivotGraph';
import AgentPipeline     from './components/AgentPipeline';
import FileScannerView   from './components/FileScannerView';
import EmailComposerView from './components/EmailComposerView';

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
  CardDefaultOpenContext,
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

// Thin wrapper → MuiCard (renders via MUI Card + CardHeader, inherits OpenCTI theme).
// defaultOpen is forwarded as-is (undefined when omitted) so the Card can inherit
// the open/closed default from CardDefaultOpenContext (e.g. collapse-all on result).
function Card({ title, accent, children, defaultOpen, badge, noPad=false }) {
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

/* ─── geopolitical context (spec §7) ─────────────────────────────────────────
 * Country attribution + risk scoring + false-flag detection. Surfaces
 * suspected nation-state activity and warns when actor attribution doesn't
 * match infrastructure country.
 */
function GeopoliticalContext({ result, bare }) {
  const gp = result?.geopolitical;
  if (!gp || gp.error || (!gp.countries?.length && !gp.attribution)) return null;
  const riskColor = (n) => n >= 25 ? '#EE3838' : n >= 15 ? '#E6700F' : n >= 10 ? '#E1B823' : '#16AD34';

  const body = (
    <>
      {gp.false_flag && (
        <MuiPaper elevation={0} sx={{
          backgroundColor: muiAlpha('#EE3838', 0.08),
          border: `1px solid ${muiAlpha('#EE3838', 0.4)}`,
          borderLeft: '3px solid #EE3838',
          borderRadius: '4px', p: '10px 12px', mb: 1.5,
        }}>
          <Typography sx={{ fontSize: 12, fontWeight: 600, color: 'error.main', mb: 0.5 }}>
            ⚠ {gp.false_flag.warning}
          </Typography>
          <Typography sx={{ fontSize: 11, color: 'text.primary' }}>
            Actor country: <strong>{gp.false_flag.actor_country}</strong>{' '}
            · Infrastructure observed in: {gp.false_flag.infrastructure_countries.join(', ')}
          </Typography>
          <Typography sx={{ fontSize: 11, color: 'text.tertiary', mt: 0.5, lineHeight: 1.5 }}>
            {gp.false_flag.rationale}
          </Typography>
        </MuiPaper>
      )}

      {gp.attribution && (
        <Box sx={{ mb: 1.5 }}>
          <Typography sx={{ fontSize: 11, color: 'text.tertiary', fontWeight: 600,
            textTransform: 'uppercase', letterSpacing: '0.06em', mb: 0.5 }}>
            Threat actor attribution
          </Typography>
          <MuiPaper elevation={0} sx={{
            backgroundColor: '#0C1524',
            border: `1px solid ${muiAlpha('#ffffff', 0.12)}`,
            borderRadius: '4px', p: '10px 12px',
          }}>
            <Typography sx={{ fontSize: 12, color: 'text.primary' }}>
              <strong>{gp.attribution.actor}</strong>
              {gp.attribution.country && <> · country of origin: <strong>{gp.attribution.country}</strong></>}
              {gp.attribution.confidence != null && (
                <Box component="span" sx={{ ml: 1, color: 'text.tertiary' }}>
                  · confidence: {Math.round((gp.attribution.confidence || 0) * 100)}%
                </Box>
              )}
            </Typography>
          </MuiPaper>
        </Box>
      )}

      {(gp.countries || []).length > 0 && (
        <Box>
          <Typography sx={{ fontSize: 11, color: 'text.tertiary', fontWeight: 600,
            textTransform: 'uppercase', letterSpacing: '0.06em', mb: 0.75 }}>
            Infrastructure by country
          </Typography>
          {gp.countries.map((c, i) => (
            <MuiPaper key={i} elevation={0} sx={{
              backgroundColor: '#0C1524',
              border: `1px solid ${muiAlpha('#ffffff', 0.12)}`,
              borderLeft: `3px solid ${riskColor(c.risk_score)}`,
              borderRadius: '4px', p: '10px 12px', mb: 0.75,
            }}>
              <Stack direction="row" alignItems="center" spacing={1} sx={{ mb: 0.5 }}>
                <Typography sx={{ fontSize: 13, fontWeight: 600, color: 'text.primary' }}>
                  {c.country}
                </Typography>
                <Typography sx={{ fontSize: 11, color: 'text.tertiary' }}>
                  · {c.ip_count} IP{c.ip_count === 1 ? '' : 's'}
                </Typography>
                {c.is_high_risk && (
                  <MuiTag label="high risk" color={riskColor(c.risk_score)}/>
                )}
                {c.known_apts?.length > 0 && (
                  <Box component="span" sx={{ ml: 'auto !important', fontSize: 10, color: 'text.disabled' }}>
                    Known APTs: {c.known_apts.slice(0, 3).join(', ')}
                  </Box>
                )}
              </Stack>
              {c.asns?.length > 0 && (
                <Typography sx={{ fontSize: 11, color: 'text.tertiary',
                  fontFamily: '"IBM Plex Mono", monospace' }}>
                  ASNs: {c.asns.join(', ')}
                </Typography>
              )}
              {c.isps?.length > 0 && (
                <Typography sx={{ fontSize: 11, color: 'text.tertiary' }}>
                  ISPs: {c.isps.slice(0, 3).join(', ')}
                </Typography>
              )}
            </MuiPaper>
          ))}
        </Box>
      )}
    </>
  );
  if (bare) return body;
  return (
    <Card title="Geopolitical context · nation-state attribution" accent="#E6700F"
      badge={`${gp.country_count || 0} countries · ${gp.high_risk_count || 0} high-risk`}>
      {body}
    </Card>
  );
}

/* ─── deep sandbox behavioral analysis (spec §6) ──────────────────────────────
 * Renders the rich sandbox report for any hash that came back from Hybrid
 * Analysis / ANY.RUN: collapsible process tree, network connections grouped by
 * protocol, file-system writes flagged for persistence, registry persistence,
 * dropped files, mutexes, MITRE, and auto-synthesized Sigma/YARA stubs.
 */
function ProcessTreeNode({ node, depth = 0 }) {
  const [open, setOpen] = useState(depth < 2);
  const suspicious = node.suspicious_parent || node.suspicious_child;
  const monoSx = { fontFamily: '"IBM Plex Mono", monospace' };
  return (
    <Box sx={{ ml: depth * 1.5, mt: depth ? 0.5 : 0 }}>
      <Box
        onClick={() => (node.children || []).length && setOpen(o => !o)}
        sx={{
          display: 'flex', alignItems: 'baseline', gap: 0.75, py: 0.375, px: 1,
          backgroundColor: suspicious ? muiAlpha('#EE3838', 0.08) : 'transparent',
          border: suspicious ? `1px solid ${muiAlpha('#EE3838', 0.25)}` : 'none',
          borderLeft: suspicious ? '3px solid #EE3838' : `2px solid ${muiAlpha('#ffffff', 0.06)}`,
          borderRadius: '3px',
          cursor: (node.children || []).length ? 'pointer' : 'default',
        }}
      >
        <Box component="span" sx={{ ...monoSx, fontSize: 11,
          color: suspicious ? 'error.main' : 'text.primary', fontWeight: 600,
        }}>{node.name || '(unknown)'}</Box>
        <Box component="span" sx={{ ...monoSx, fontSize: 10, color: 'text.disabled' }}>
          pid={node.pid}
        </Box>
        {node.cmdline && (
          <Box component="span" sx={{ ...monoSx, fontSize: 10, color: 'text.tertiary',
            overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1 }}>
            {node.cmdline.slice(0, 200)}
          </Box>
        )}
      </Box>
      {open && (node.children || []).map((ch, i) => (
        <ProcessTreeNode key={i} node={ch} depth={depth + 1}/>
      ))}
    </Box>
  );
}

function SandboxBehavioral({ result }) {
  const hashes = result?.enrichments?.hashes || {};
  const rows = Object.entries(hashes)
    .map(([h, p]) => ({ hash: h, deep: p?.sandbox_deep }))
    .filter(r => r.deep && r.deep.process_tree);
  if (!rows.length) return null;

  const monoSx = { fontFamily: '"IBM Plex Mono", monospace' };

  return (
    <Card title="Sandbox behavioral analysis · process tree + IOCs" accent="#EE3838"
      badge={`${rows.length} sample${rows.length === 1 ? '' : 's'}`} defaultOpen={false}>
      {rows.map(({ hash, deep }) => (
        <Box key={hash} sx={{ mb: 2.5 }}>
          <Stack direction="row" alignItems="center" spacing={1} sx={{ mb: 1.25 }} flexWrap="wrap">
            <TypeTag type="hashes"/>
            <Box sx={{ ...monoSx, fontSize: 11, color: 'text.primary',
              wordBreak: 'break-all' }}>{hash}</Box>
            <Box component="a" href={deep.report_url} target="_blank" rel="noreferrer"
              sx={{ ml: 'auto !important', fontSize: 11, color: 'primary.main',
                textDecoration: 'none', '&:hover': { textDecoration: 'underline' } }}>
              full {deep.source} report ↗
            </Box>
          </Stack>
          <Stack direction="row" spacing={0.75} flexWrap="wrap" sx={{ mb: 1.5 }}>
            <MuiTag label={`verdict: ${deep.verdict}`}
              color={deep.verdict === 'MALICIOUS' ? '#EE3838' : '#848592'}/>
            {deep.threat_score != null && <MuiTag label={`score ${deep.threat_score}`} color="#E6700F"/>}
            {deep.malware_family && <MuiTag label={deep.malware_family} color="#EE3838"/>}
            {deep.environment && <MuiTag label={deep.environment} color="#848592"/>}
          </Stack>

          {(deep.process_tree || []).length > 0 && (
            <Box sx={{ mb: 1.5 }}>
              <Typography sx={{ fontSize: 11, color: 'text.tertiary', fontWeight: 600,
                textTransform: 'uppercase', letterSpacing: '0.06em', mb: 0.75 }}>
                Process tree
              </Typography>
              <MuiPaper elevation={0} sx={{
                backgroundColor: '#0C1524',
                border: `1px solid ${muiAlpha('#ffffff', 0.12)}`,
                borderRadius: '4px', p: 1,
              }}>
                {deep.process_tree.map((root, i) => (
                  <ProcessTreeNode key={i} node={root}/>
                ))}
              </MuiPaper>
            </Box>
          )}

          {(deep.network?.dns?.length || 0) > 0 && (
            <Box sx={{ mb: 1.5 }}>
              <Typography sx={{ fontSize: 11, color: 'text.tertiary', fontWeight: 600,
                textTransform: 'uppercase', letterSpacing: '0.06em', mb: 0.5 }}>
                Network · DNS / HTTP
              </Typography>
              <MuiPaper elevation={0} sx={{
                backgroundColor: '#0C1524',
                border: `1px solid ${muiAlpha('#ffffff', 0.12)}`,
                borderRadius: '4px', p: 1,
              }}>
                {deep.network.dns.slice(0, 10).map((r, i) => (
                  <Box key={i} sx={{ ...monoSx, fontSize: 11, py: 0.125,
                    color: 'text.primary', wordBreak: 'break-all' }}>
                    {r.domain} <Box component="span" sx={{ color: 'text.tertiary' }}>
                      → {r.ip} {r.country ? `· ${r.country}` : ''}
                    </Box>
                  </Box>
                ))}
                {deep.network.http.slice(0, 5).map((req, i) => (
                  <Box key={`http${i}`} sx={{ ...monoSx, fontSize: 11, py: 0.125,
                    color: 'text.primary', wordBreak: 'break-all', mt: 0.25 }}>
                    {req.method} <Box component="span" sx={{ color: 'primary.main' }}>{req.url}</Box>
                  </Box>
                ))}
              </MuiPaper>
            </Box>
          )}

          {(deep.registry || []).filter(r => r.persistence).length > 0 && (
            <Box sx={{ mb: 1.5 }}>
              <Typography sx={{ fontSize: 11, color: 'warning.main', fontWeight: 600,
                textTransform: 'uppercase', letterSpacing: '0.06em', mb: 0.5 }}>
                Registry persistence
              </Typography>
              {deep.registry.filter(r => r.persistence).slice(0, 8).map((r, i) => (
                <Box key={i} sx={{ ...monoSx, fontSize: 11, color: 'text.primary',
                  py: 0.125, wordBreak: 'break-all' }}>
                  {r.path}{r.value_name ? `\\${r.value_name}` : ''}
                  {r.value && <Box component="span" sx={{ color: 'text.tertiary' }}> = {r.value}</Box>}
                </Box>
              ))}
            </Box>
          )}

          {(deep.mutexes || []).length > 0 && (
            <Box sx={{ mb: 1.5 }}>
              <Typography sx={{ fontSize: 11, color: 'text.tertiary', fontWeight: 600,
                textTransform: 'uppercase', letterSpacing: '0.06em', mb: 0.5 }}>
                Mutex names
              </Typography>
              <Stack direction="row" spacing={0.5} flexWrap="wrap">
                {deep.mutexes.slice(0, 10).map((m, i) => (
                  <MuiTag key={i} label={m} color="#B286FF"
                    sx={{ ...monoSx, fontFamily: '"IBM Plex Mono", monospace' }}/>
                ))}
              </Stack>
            </Box>
          )}

          {(deep.detections || []).length > 0 && (
            <Box>
              <Typography sx={{ fontSize: 11, color: 'success.main', fontWeight: 600,
                textTransform: 'uppercase', letterSpacing: '0.06em', mb: 0.5 }}>
                Auto-synthesized detection opportunities
              </Typography>
              {deep.detections.map((d, i) => (
                <Box key={i} component="pre" sx={{
                  ...monoSx, fontSize: 10, m: 0, mb: 0.75,
                  backgroundColor: '#070d19',
                  border: `1px solid ${muiAlpha('#ffffff', 0.12)}`,
                  borderRadius: '4px', p: '8px 10px',
                  color: 'text.primary', whiteSpace: 'pre-wrap',
                  maxHeight: 200, overflow: 'auto',
                }}>
                  {`# ${d.type.toUpperCase()} · ${d.trigger}\n${d.stub}`}
                </Box>
              ))}
            </Box>
          )}
        </Box>
      ))}
    </Card>
  );
}

/* ─── honeypot / deception intelligence (spec §5) ────────────────────────────
 * Per-IP rollup of: GreyNoise RIOT (known-good infra), Shodan InternetDB,
 * DShield SANS ISC, StopForumSpam, Emerging Threats blocklist, Project
 * Honeypot HTTP:BL. Each source returns flagged + summary.
 */
function HoneypotActivity({ result }) {
  const ips = result?.enrichments?.ips || {};
  const rows = Object.entries(ips)
    .map(([ip, payload]) => ({ ip, dec: payload?.deception }))
    .filter(r => r.dec && (r.dec.flagged_count > 0 || r.dec.greynoise_riot?.is_known_good));
  if (!rows.length) return null;

  return (
    <Card title="Honeypot activity · deception intel" accent="#EE3838"
      badge={`${rows.length} IP${rows.length === 1 ? '' : 's'} with hits`}>
      <Typography sx={{ fontSize: 12, color: 'text.tertiary', mb: 1.5, lineHeight: 1.6 }}>
        Cross-checked against GreyNoise RIOT, Shodan InternetDB, DShield SANS ISC,
        StopForumSpam, Emerging Threats compromised IPs, and Project Honeypot HTTP:BL.
      </Typography>
      {rows.map(({ ip, dec }) => {
        const sources = [
          dec.greynoise_riot?.is_known_good   && { name: 'GreyNoise RIOT — known-good',  good: true,  detail: dec.greynoise_riot.name },
          dec.shodan_internetdb?.vuln_count   && { name: 'Shodan InternetDB',            good: false, detail: `${dec.shodan_internetdb.vuln_count} CVE${dec.shodan_internetdb.vuln_count === 1 ? '' : 's'} on ${dec.shodan_internetdb.ports?.length || 0} open ports` },
          dec.dshield?.flagged                && { name: 'DShield · SANS ISC',           good: false, detail: dec.dshield.summary },
          dec.stopforumspam?.flagged          && { name: 'StopForumSpam',                good: false, detail: dec.stopforumspam.summary },
          dec.emerging_threats?.flagged       && { name: 'Emerging Threats blocklist',   good: false, detail: dec.emerging_threats.summary },
          dec.project_honeypot?.flagged       && { name: 'Project Honeypot HTTP:BL',     good: false, detail: dec.project_honeypot.classification },
        ].filter(Boolean);
        return (
          <MuiPaper key={ip} elevation={0} sx={{
            backgroundColor: '#0C1524',
            border: `1px solid ${muiAlpha('#ffffff', 0.12)}`,
            borderRadius: '4px', p: '10px 12px', mb: 0.75,
          }}>
            <Stack direction="row" alignItems="center" spacing={1} sx={{ mb: 0.75 }} flexWrap="wrap">
              <TypeTag type="ips"/>
              <Box sx={{
                fontFamily: '"IBM Plex Mono", monospace', fontSize: 12,
                color: 'text.primary',
              }}>{ip}</Box>
              <Box component="span" sx={{
                ml: 'auto !important', fontSize: 11, color: 'text.tertiary',
              }}>
                {dec.flagged_count} of {dec.sources_consulted} sources flagged
              </Box>
            </Stack>
            {sources.map((s, i) => (
              <Box key={i} sx={{
                display: 'grid', gridTemplateColumns: 'auto 1fr',
                gap: 1, py: 0.375, alignItems: 'baseline',
                borderTop: i > 0 ? `1px solid ${muiAlpha('#ffffff', 0.04)}` : 'none',
              }}>
                <Box component="span" sx={{
                  fontSize: 11, fontWeight: 600,
                  color: s.good ? 'success.main' : 'error.main',
                  whiteSpace: 'nowrap',
                }}>{s.name}</Box>
                <Box component="span" sx={{ fontSize: 11, color: 'text.tertiary' }}>
                  {s.detail || ''}
                </Box>
              </Box>
            ))}
          </MuiPaper>
        );
      })}
    </Card>
  );
}

/* ─── log translation (spec §4) ──────────────────────────────────────────────
 * AI identifies the format and extracts every security-relevant field. Lets
 * analysts verify the parser caught everything before trusting the analysis.
 */
function LogTranslation({ result, bare }) {
  const lt = result?.log_translation;
  if (!lt || lt.error) return null;
  const fields = lt.extracted_fields || {};
  const anomalies = lt.anomalies || [];
  if (!Object.keys(fields).length && !anomalies.length) return null;
  const monoSx = { fontFamily: '"IBM Plex Mono", monospace' };
  const body = (
    <>
      {lt.normalized_summary && (
        <Typography sx={{ fontSize: 12, color: 'text.primary', mb: 1.5,
          lineHeight: 1.6, fontStyle: 'italic' }}>
          {lt.normalized_summary}
        </Typography>
      )}
      {Object.keys(fields).length > 0 && (
        <Box sx={{ mb: 1.5 }}>
          <Typography sx={{ fontSize: 11, color: 'text.tertiary', fontWeight: 600,
            textTransform: 'uppercase', letterSpacing: '0.06em', mb: 0.75 }}>
            Extracted fields ({Object.keys(fields).length})
          </Typography>
          <MuiPaper elevation={0} sx={{
            backgroundColor: '#0C1524',
            border: `1px solid ${muiAlpha('#ffffff', 0.12)}`,
            borderRadius: '4px', overflow: 'hidden',
          }}>
            {Object.entries(fields).map(([k, v], i) => (
              <Box key={k} sx={{
                display: 'grid', gridTemplateColumns: '180px 1fr', gap: 1.5,
                p: '5px 12px',
                borderTop: i > 0 ? `1px solid ${muiAlpha('#ffffff', 0.04)}` : 'none',
              }}>
                <Box sx={{ fontSize: 11, color: 'text.disabled' }}>{k}</Box>
                <Box sx={{ ...monoSx, fontSize: 11, color: 'text.primary',
                  wordBreak: 'break-all' }}>
                  {typeof v === 'object' ? JSON.stringify(v) : String(v)}
                </Box>
              </Box>
            ))}
          </MuiPaper>
        </Box>
      )}
      {anomalies.length > 0 && (
        <Box>
          <Typography sx={{ fontSize: 11, color: 'warning.main', fontWeight: 600,
            textTransform: 'uppercase', letterSpacing: '0.06em', mb: 0.75 }}>
            Anomalies flagged ({anomalies.length})
          </Typography>
          {anomalies.map((a, i) => (
            <MuiPaper key={i} elevation={0} sx={{
              backgroundColor: muiAlpha('#E6700F', 0.08),
              border: `1px solid ${muiAlpha('#E6700F', 0.25)}`,
              borderLeft: '3px solid #E6700F',
              borderRadius: '4px', p: '8px 12px', mb: 0.5,
            }}>
              <Typography sx={{ fontSize: 12, color: 'text.primary', fontWeight: 500 }}>
                {a.field || a.name || 'anomaly'}
              </Typography>
              {a.value && (
                <Box sx={{ ...monoSx, fontSize: 11, color: 'text.tertiary',
                  mt: 0.25, wordBreak: 'break-all' }}>{String(a.value).slice(0, 200)}</Box>
              )}
              {a.reason && (
                <Typography sx={{ fontSize: 11, color: 'warning.main', mt: 0.5 }}>
                  {a.reason}
                </Typography>
              )}
            </MuiPaper>
          ))}
        </Box>
      )}
    </>
  );
  if (bare) return body;
  return (
    <Card title="Logs" accent="#16AD34"
      badge={`${lt.detected_format} · ${Math.round((lt.confidence || 0) * 100)}%`}
      defaultOpen={false}>
      {body}
    </Card>
  );
}

/* ─── infrastructure intel (spec §3 OSINT expansion) ─────────────────────────
 * Surfaces the new OSINT layer added to enrichment.py: BGP ranking, DNS record
 * enumeration, VT graph relationships, MalwareBazaar similar samples, Google
 * Safe Browsing. Each IOC's `osint` payload renders as its own panel.
 */
function InfrastructureIntel({ result }) {
  const enr = result?.enrichments || {};
  const rows = [];
  for (const cat of ['ips', 'domains', 'hashes']) {
    for (const [ioc, payload] of Object.entries(enr[cat] || {})) {
      const osint = payload?.osint;
      if (osint && Object.keys(osint).length) {
        rows.push({ ioc, type: cat, osint });
      }
    }
  }
  const gp = result?.geopolitical;
  const hasGeo = !!(gp && !gp.error && (gp.countries?.length || gp.attribution));
  if (!rows.length && !hasGeo) return null;

  const monoSx = { fontFamily: '"IBM Plex Mono", monospace' };

  return (
    <Card title="OSINT" accent="#0fbcff"
      badge={`${rows.length} IOC${rows.length === 1 ? '' : 's'}`} defaultOpen={false}>
      <Typography sx={{ fontSize: 12, color: 'text.tertiary', mb: 1.5, lineHeight: 1.6 }}>
        Free OSINT — BGP ranking, DNS records, VT graph relationships,
        MalwareBazaar pivot, Google Safe Browsing. Surfaces infrastructure
        connections that traditional enrichment misses.
      </Typography>
      {rows.map(({ ioc, type, osint }) => (
        <Box key={ioc} sx={{ mb: 2 }}>
          <Stack direction="row" alignItems="center" spacing={1} sx={{ mb: 1 }}>
            <TypeTag type={type}/>
            <Box sx={{ ...monoSx, fontSize: 12, color: 'text.primary',
              wordBreak: 'break-all' }}>{ioc}</Box>
          </Stack>

          {osint.bgp_ranking && (
            <MuiPaper elevation={0} sx={{
              backgroundColor: '#0C1524',
              border: `1px solid ${muiAlpha('#ffffff', 0.12)}`,
              borderRadius: '4px', p: '8px 12px', mb: 0.75,
            }}>
              <Typography sx={{ fontSize: 11, color: 'text.tertiary', fontWeight: 600,
                textTransform: 'uppercase', letterSpacing: '0.06em', mb: 0.5 }}>
                BGP ranking · CIRCL
              </Typography>
              <Typography sx={{ fontSize: 12, color: 'text.primary' }}>
                AS{osint.bgp_ranking.asn} — {osint.bgp_ranking.asn_description}
                {osint.bgp_ranking.country && <> · {osint.bgp_ranking.country}</>}
              </Typography>
              {osint.bgp_ranking.rank != null && (
                <Typography sx={{ fontSize: 11, color: 'text.tertiary' }}>
                  rank {osint.bgp_ranking.rank} (lower = worse reputation)
                </Typography>
              )}
            </MuiPaper>
          )}

          {osint.dns_records && (
            <MuiPaper elevation={0} sx={{
              backgroundColor: '#0C1524',
              border: `1px solid ${muiAlpha('#ffffff', 0.12)}`,
              borderRadius: '4px', p: '8px 12px', mb: 0.75,
            }}>
              <Typography sx={{ fontSize: 11, color: 'text.tertiary', fontWeight: 600,
                textTransform: 'uppercase', letterSpacing: '0.06em', mb: 0.75 }}>
                DNS records · {osint.dns_records.total_records}
              </Typography>
              {Object.entries(osint.dns_records.records || {}).map(([rt, vals]) => (
                <Box key={rt} sx={{ display: 'grid', gridTemplateColumns: '40px 1fr', gap: 1, py: 0.25 }}>
                  <Typography sx={{ ...monoSx, fontSize: 11, color: 'primary.main', fontWeight: 600 }}>
                    {rt}
                  </Typography>
                  <Box sx={{ ...monoSx, fontSize: 11, color: 'text.primary', wordBreak: 'break-all' }}>
                    {vals.join(', ')}
                  </Box>
                </Box>
              ))}
            </MuiPaper>
          )}

          {osint.vt_graph && (
            <MuiPaper elevation={0} sx={{
              backgroundColor: '#0C1524',
              border: `1px solid ${muiAlpha('#ffffff', 0.12)}`,
              borderRadius: '4px', p: '8px 12px', mb: 0.75,
            }}>
              <Typography sx={{ fontSize: 11, color: 'text.tertiary', fontWeight: 600,
                textTransform: 'uppercase', letterSpacing: '0.06em', mb: 0.75 }}>
                VirusTotal graph · pivot points
              </Typography>
              {Object.entries(osint.vt_graph).map(([rel, items]) => (
                <Box key={rel} sx={{ mb: 0.5 }}>
                  <Typography sx={{ fontSize: 11, color: 'primary.main', mb: 0.25 }}>{rel}</Typography>
                  {(items || []).map((it, i) => (
                    <Box key={i} sx={{ ...monoSx, fontSize: 11, color: 'text.primary',
                      pl: 1, wordBreak: 'break-all' }}>
                      {it.id} <Box component="span" sx={{ color: 'text.tertiary' }}>· {it.type}</Box>
                    </Box>
                  ))}
                </Box>
              ))}
            </MuiPaper>
          )}

          {osint.mb_similar && (
            <MuiPaper elevation={0} sx={{
              backgroundColor: '#0C1524',
              border: `1px solid ${muiAlpha('#ffffff', 0.12)}`,
              borderRadius: '4px', p: '8px 12px', mb: 0.75,
            }}>
              <Typography sx={{ fontSize: 11, color: 'text.tertiary', fontWeight: 600,
                textTransform: 'uppercase', letterSpacing: '0.06em', mb: 0.5 }}>
                MalwareBazaar similar · family {osint.mb_similar.family}
              </Typography>
              {(osint.mb_similar.samples || []).slice(0, 6).map((s, i) => (
                <Box key={i} sx={{ ...monoSx, fontSize: 11, color: 'text.primary',
                  py: 0.125, wordBreak: 'break-all' }}>
                  {s.sha256} <Box component="span" sx={{ color: 'text.tertiary' }}>
                    · {s.file_type} · {s.first_seen}
                  </Box>
                </Box>
              ))}
            </MuiPaper>
          )}

          {osint.google_safebrowsing && (
            <MuiPaper elevation={0} sx={{
              backgroundColor: '#0C1524',
              border: `1px solid ${muiAlpha(osint.google_safebrowsing.verdict === 'MALICIOUS' ? '#EE3838' : '#16AD34', 0.4)}`,
              borderLeft: `3px solid ${osint.google_safebrowsing.verdict === 'MALICIOUS' ? '#EE3838' : '#16AD34'}`,
              borderRadius: '4px', p: '8px 12px',
            }}>
              <Typography sx={{ fontSize: 11, color: 'text.tertiary', fontWeight: 600,
                textTransform: 'uppercase', letterSpacing: '0.06em', mb: 0.5 }}>
                Google Safe Browsing
              </Typography>
              <Typography sx={{ fontSize: 12, color: 'text.primary' }}>
                {osint.google_safebrowsing.verdict} · {osint.google_safebrowsing.match_count} matches
                {osint.google_safebrowsing.threat_types?.length > 0 && (
                  <> · {osint.google_safebrowsing.threat_types.join(', ')}</>
                )}
              </Typography>
            </MuiPaper>
          )}
        </Box>
      ))}
      {hasGeo && (
        <Box sx={{ mt: rows.length ? 2 : 0, pt: rows.length ? 2 : 0,
          borderTop: rows.length ? `1px solid ${muiAlpha('#ffffff', 0.08)}` : 'none' }}>
          <Typography sx={{ fontSize: 11, fontWeight: 600, color: 'text.tertiary',
            textTransform: 'uppercase', letterSpacing: '0.06em', mb: 1.25 }}>
            Geopolitical context
          </Typography>
          <GeopoliticalContext result={result} bare/>
        </Box>
      )}
    </Card>
  );
}

/* ─── transparent confidence breakdown (spec §2) ──────────────────────────────
 * Per-IOC deterministic score independent of the AI assessment. Renders a
 * visual bar + verdict chip + expandable list of every contributing factor.
 */
function ConfidenceBreakdown({ result, bare }) {
  const scores = result?.confidence_scores || {};
  const [openIoc, setOpenIoc] = useState(null);
  const ids = Object.keys(scores).filter(k => k && !k.startsWith('_'));
  if (!ids.length) return null;

  const verdictColor = {
    CRITICAL: '#EE3838', HIGH: '#E6700F', MEDIUM: '#E1B823',
    LOW: '#0fbcff', CLEAN: '#16AD34',
  };
  const sorted = ids
    .map(k => ({ ioc: k, ...scores[k] }))
    .sort((a, b) => (b.score || 0) - (a.score || 0));

  const body = (
    <>
      <Typography sx={{ fontSize: 12, color: 'text.tertiary', mb: 1.5, lineHeight: 1.6 }}>
        Each IOC gets a deterministic 0–100 score computed independently of the
        AI assessment. Expand any row to see every contributing factor and the
        evidence that triggered it.
      </Typography>
      {sorted.map(({ ioc, type, score, verdict, factors }) => {
        const open = openIoc === ioc;
        const color = verdictColor[verdict] || '#848592';
        return (
          <MuiPaper key={ioc} elevation={0} sx={{
            backgroundColor: '#0C1524',
            border: `1px solid ${muiAlpha('#ffffff', 0.12)}`,
            borderLeft: `3px solid ${color}`,
            borderRadius: '4px', mb: 0.75,
          }}>
            <Box
              onClick={() => setOpenIoc(open ? null : ioc)}
              sx={{
                display: 'grid',
                gridTemplateColumns: 'auto 1fr auto auto auto',
                gap: 1.5, p: '10px 12px', cursor: 'pointer',
                alignItems: 'center',
              }}
            >
              <TypeTag type={type === 'hash' ? 'hashes' : type === 'ip' ? 'ips' : 'domains'}/>
              <Box sx={{
                fontFamily: '"IBM Plex Mono", monospace', fontSize: 12,
                color: 'text.primary', wordBreak: 'break-all', overflow: 'hidden',
              }}>{ioc}</Box>
              <Box sx={{ width: 120, height: 6, backgroundColor: '#070d19', borderRadius: 3, overflow: 'hidden' }}>
                <Box sx={{
                  width: `${score}%`, height: '100%', backgroundColor: color,
                  transition: 'width .25s',
                }}/>
              </Box>
              <Typography sx={{
                fontSize: 13, fontWeight: 600, color, minWidth: 32,
                fontVariantNumeric: 'tabular-nums', textAlign: 'right',
              }}>{score}</Typography>
              <MuiTag label={verdict} color={color}/>
            </Box>
            {open && (
              <Box sx={{ borderTop: `1px solid ${muiAlpha('#ffffff', 0.06)}`, p: '8px 12px' }}>
                {(factors || []).length === 0 && (
                  <Typography sx={{ fontSize: 12, color: 'text.tertiary' }}>
                    No contributing factors — score derived entirely from neutral signals.
                  </Typography>
                )}
                {(factors || []).map((f, i) => (
                  <Box key={i} sx={{
                    display: 'grid', gridTemplateColumns: '1fr auto',
                    gap: 1, py: 0.625,
                    borderTop: i > 0 ? `1px solid ${muiAlpha('#ffffff', 0.04)}` : 'none',
                  }}>
                    <Box>
                      <Typography sx={{ fontSize: 12, color: 'text.primary', fontWeight: 500 }}>
                        {f.factor}
                        <Box component="span" sx={{
                          ml: 1, fontSize: 10, color: 'text.disabled',
                          textTransform: 'uppercase', letterSpacing: '0.05em',
                        }}>{f.category}</Box>
                      </Typography>
                      <Typography sx={{ fontSize: 11, color: 'text.tertiary',
                        fontFamily: '"IBM Plex Mono", monospace', mt: 0.25,
                        wordBreak: 'break-all',
                      }}>{f.evidence}</Typography>
                    </Box>
                    <Typography sx={{
                      fontSize: 13, fontWeight: 600,
                      color: f.points > 0 ? 'warning.main' : 'success.main',
                      fontVariantNumeric: 'tabular-nums',
                      whiteSpace: 'nowrap',
                    }}>{f.points > 0 ? `+${f.points}` : f.points}</Typography>
                  </Box>
                ))}
              </Box>
            )}
          </MuiPaper>
        );
      })}
    </>
  );
  if (bare) return body;
  return (
    <Card title="Confidence breakdown · transparent scoring" accent="#0fbcff"
      badge={`${ids.length} scored`}>
      {body}
    </Card>
  );
}

/* ─── behavioral indicators (spec §1) ────────────────────────────────────────
 * Pattern-matched TTPs extracted from the raw input — PowerShell tradecraft,
 * LOLBin abuse, persistence, lateral movement, credential access, C2. Each
 * indicator carries the MITRE technique it represents plus a plain-English
 * reason it is suspicious.
 */
function BehavioralIndicators({ result }) {
  const bi = result?.behavioral_indicators || {};
  const cats = bi.categories || {};
  const total = bi.total || 0;
  if (!total && !(bi.decoded_payloads || []).length) return null;

  const sevColor = {
    CRITICAL: '#EE3838', HIGH: '#E6700F', MEDIUM: '#E1B823', LOW: '#0fbcff',
  };
  const catLabel = {
    powershell:  'PowerShell tradecraft',
    lolbin:      'Windows LOLBin abuse',
    persistence: 'Persistence mechanisms',
    lateral:     'Lateral movement',
    credentials: 'Credential access',
    c2:          'C2 communication',
  };

  return (
    <Card title="Behavioral indicators · MITRE-mapped TTPs" accent="#B286FF"
      badge={`${total} signals · ${(bi.techniques || []).length} techniques`}>
      <Typography sx={{ fontSize: 12, color: 'text.tertiary', mb: 1.5, lineHeight: 1.6 }}>
        Pattern-matched directly from the raw input — captures attacker tradecraft
        that wouldn't show up via IOC enrichment alone. Each hit is mapped to the
        specific MITRE ATT&CK technique it represents.
      </Typography>
      <Box sx={{ mb: 1.75 }}>
        <Typography sx={{ fontSize: 11, color: 'text.tertiary', fontWeight: 600,
          textTransform: 'uppercase', letterSpacing: '0.06em', mb: 0.75 }}>
          Decoded base64 payloads
        </Typography>
        {(bi.decoded_payloads || []).length > 0 ? (
          bi.decoded_payloads.map((p, i) => (
            <Box key={i} component="pre" sx={{
              fontFamily: '"IBM Plex Mono", monospace', fontSize: 11,
              backgroundColor: '#070d19', border: `1px solid ${muiAlpha('#ffffff', 0.12)}`,
              borderRadius: '4px', p: '8px 10px', m: 0, mb: 0.75,
              whiteSpace: 'pre-wrap', wordBreak: 'break-all',
              color: 'primary.main', maxHeight: 120, overflow: 'auto',
            }}>{p}</Box>
          ))
        ) : (
          <Typography sx={{ fontSize: 12, color: 'text.disabled', fontStyle: 'italic' }}>
            None — no readable base64-encoded content found.
          </Typography>
        )}
      </Box>
      {Object.entries(cats).map(([cat, hits]) => (
        <Box key={cat} sx={{ mb: 1.75 }}>
          <Stack direction="row" alignItems="center" spacing={1} sx={{ mb: 0.75 }}>
            <Typography sx={{ fontSize: 11, color: 'text.tertiary', fontWeight: 600,
              textTransform: 'uppercase', letterSpacing: '0.06em' }}>
              {catLabel[cat] || cat}
            </Typography>
            <Typography sx={{ fontSize: 11, color: 'text.disabled' }}>{hits.length}</Typography>
          </Stack>
          {hits.map((h, i) => (
            <MuiPaper key={i} elevation={0} sx={{
              backgroundColor: '#0C1524',
              border: `1px solid ${muiAlpha('#ffffff', 0.12)}`,
              borderLeft: `3px solid ${sevColor[h.severity] || '#848592'}`,
              borderRadius: '4px', p: '10px 12px', mb: 0.75,
            }}>
              <Stack direction="row" alignItems="center" spacing={1} sx={{ mb: 0.5 }} flexWrap="wrap">
                <Typography sx={{ fontSize: 12, fontWeight: 600, color: 'text.primary' }}>
                  {h.name}
                </Typography>
                <Box component="a" href={`https://attack.mitre.org/techniques/${(h.mitre || '').replace('.', '/')}/`}
                  target="_blank" rel="noreferrer"
                  sx={{
                    fontFamily: '"IBM Plex Mono", monospace', fontSize: 11,
                    color: 'primary.main', textDecoration: 'none',
                    '&:hover': { textDecoration: 'underline' },
                  }}>
                  {h.mitre}{h.mitre_name ? ` · ${h.mitre_name}` : ''}
                </Box>
                <Box component="span" sx={{
                  ml: 'auto !important', fontSize: 10, color: sevColor[h.severity] || '#848592',
                  fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em',
                }}>{h.severity}</Box>
              </Stack>
              <Typography sx={{ fontSize: 11, color: 'text.tertiary', lineHeight: 1.55, mb: 0.5 }}>
                {h.explanation}
              </Typography>
              <Box sx={{
                fontFamily: '"IBM Plex Mono", monospace', fontSize: 11,
                color: 'text.primary',
                backgroundColor: '#070d19',
                border: `1px solid ${muiAlpha('#ffffff', 0.06)}`,
                borderRadius: '3px',
                p: '4px 8px',
                wordBreak: 'break-all',
              }}>{h.match}</Box>
            </MuiPaper>
          ))}
        </Box>
      ))}
    </Card>
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
// Triage: log normalization + MISP-warninglist false-positive filtering, fused.
function Triage({ result }) {
  const lt = result?.log_translation;
  const hasLogs = !!(lt && !lt.error &&
    (Object.keys(lt.extracted_fields || {}).length || (lt.anomalies || []).length));
  const sup = result?.suppressed_iocs || {};
  const hasSup = Object.values(sup).reduce((n, a) => n + (a?.length || 0), 0) > 0;
  if (!hasLogs && !hasSup) return null;
  const Label = ({ children }) => (
    <Typography sx={{ fontSize: 11, fontWeight: 600, color: 'text.tertiary',
      textTransform: 'uppercase', letterSpacing: '0.06em', mb: 1.25 }}>{children}</Typography>
  );
  return (
    <Card title="Triage" accent="#16AD34" defaultOpen={false}>
      {hasLogs && (
        <>
          <Label>Log normalization</Label>
          <LogTranslation result={result} bare/>
        </>
      )}
      {hasSup && (
        <Box sx={{ mt: hasLogs ? 2 : 0, pt: hasLogs ? 2 : 0,
          borderTop: hasLogs ? `1px solid ${muiAlpha('#ffffff', 0.08)}` : 'none' }}>
          <Label>Filtered as benign · MISP warninglists</Label>
          <SuppressedIOCs result={result} bare/>
        </Box>
      )}
    </Card>
  );
}

function SuppressedIOCs({ result, bare }) {
  const sup = result?.suppressed_iocs || {};
  const total = Object.values(sup).reduce((n, arr) => n + (arr?.length || 0), 0);
  if (!total) return null;
  const body = (
    <>
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
    </>
  );
  if (bare) return body;
  return (
    <Card title="Filtered as benign · MISP warninglists" accent="#848592"
      badge={`${total} suppressed`} defaultOpen={false}>
      {body}
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
// Matches every variant of the boilerplate the backend emits when the AI
// call fails or no OpenAI key is configured. Used to suppress entire UI
// sections that would otherwise just display these placeholder strings.
const AI_FAILURE_TEXT = /(openai\s*key\s*not\s*configured|review\s*enrichment\s*data\s*manually|automated\s*ai\s*analysis\s*unavailable|configure\s*openai)/i;
const isAIFailureText = (v) => {
  try { return AI_FAILURE_TEXT.test(String(v ?? '')); }
  catch { return false; }
};


function Overview({ result, bare }) {
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

  const metrics = (
    <Box sx={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 1.25 }}>
      <Metric label="Threat level" value={rs.threat_level} color={lc.fg}/>
      <Metric label="Confidence" value={`${conf}%`}
        color={conf >= 70 ? '#17AB1F' : conf >= 40 ? '#E1B823' : '#F14337'}/>
      <Metric label="Indicators" value={total} color="#0fbcff"/>
      <Metric label="MITRE TTPs" value={mitre} color="#B286FF"/>
    </Box>
  );
  if (bare) return metrics;
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
      {metrics}
    </Box>
  );
}

/* ─── GTI ────────────────────────────────────────────────────────────────────── */
function GTI({ result }) {
  const gti = result?.gti_scores || {};
  const sorted = Object.entries(gti).sort(([,a],[,b])=>b.score-a.score);
  const top = sorted[0]?.[1];
  const total = Object.values(result?.iocs||{}).flat().length;
  // Fused headline card: shows investigation metrics + threat score; render
  // whenever there's an investigation result, even if no GTI scores.
  if (!sorted.length && !result?.response_summary) return null;

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
    <Card title="Investigation results" accent="#0fbcff" badge={top ? `${top.score}/100` : null} defaultOpen>
      {/* Investigation metrics (threat level / confidence / indicators / MITRE) */}
      <Overview result={result} bare/>

      {sorted.length > 0 && (
        <Typography sx={{ fontSize: 11, fontWeight: 600, color: 'text.tertiary',
          textTransform: 'uppercase', letterSpacing: '0.06em', mt: 2.25, mb: 1.25,
          pt: 2, borderTop: `1px solid ${muiAlpha('#ffffff', 0.08)}` }}>
          Threat score
        </Typography>
      )}
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

      {Object.keys(result?.confidence_scores || {}).filter(k => k && !k.startsWith('_')).length > 0 && (
        <Box sx={{ mt: 2.25, pt: 2, borderTop: `1px solid ${muiAlpha('#ffffff', 0.08)}` }}>
          <Typography sx={{ fontSize: 11, fontWeight: 600, color: 'text.tertiary',
            textTransform: 'uppercase', letterSpacing: '0.06em', mb: 1.25 }}>
            Per-indicator confidence breakdown
          </Typography>
          <ConfidenceBreakdown result={result} bare/>
        </Box>
      )}
    </Card>
  );
}

/* ─── assessment ────────────────────────────────────────────────────────────── */
function Assessment({ rs }) {   // currently unused — kept for reuse
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

      {(() => {
        const chain = (rs.chain_of_thought || []).filter(s => !isAIFailureText(s));
        if (!chain.length) return null;
        return (
          <Block title="Reasoning chain">
            {chain.map((s, i) => (
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
        );
      })()}

      {(() => {
        const findings = (rs.key_findings || []).filter(f => !isAIFailureText(f));
        if (!findings.length) return null;
        return (
          <Block title="Key findings">
            {findings.map((f, i) => (
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
        );
      })()}

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

    </Card>
  );
}

// Thin wrapper → MuiBlock (renders MUI Box with subtle border + tertiary label)
const Block = ({ title, children }) => (
  <MuiBlock title={title}>
    <Box component="ul" sx={{ margin:0, padding:0, listStyle:'none' }}>{children}</Box>
  </MuiBlock>
);

/* ─── analyst hand-off (disposition, clear/escalate, IR playbook) ──────────── */
function AnalystSummary({ rs }) {
  const a = rs?.analyst_summary;
  if (!a || !a.disposition) return null;

  const dispColor = a.disposition === 'CLEAR'    ? '#17AB1F'
                  : a.disposition === 'ESCALATE' ? '#F14337'
                  :                                '#E1B823';

  return (
    <Card title="Summary" accent="#0fbcff" badge={a.disposition?.toLowerCase()} defaultOpen>
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

      {/* Client notification email removed — pending integration of dedicated
          email-generator repo from a fellow analyst. */}
    </Card>
  );
}

/* ─── Chat with RECON · conversational follow-up on the investigation ───────── */
// Evergreen investigation prompts shown when the backend didn't return any
// AI-generated probing_questions. Same shape as the AI ones so the click-to-
// ask handler treats them identically.
const FALLBACK_QUESTIONS = [
  { question: "Are there other endpoints or accounts showing the same behavior right now?",
    why_asking: "Single-host detections are usually FP; a pattern across multiple hosts points to active intrusion." },
  { question: "What did this user / process do in the 30 minutes before this alert fired?",
    why_asking: "Preceding activity often reveals the initial access vector and intent." },
  { question: "Has this user, host, or IOC appeared in any prior investigation in the last 90 days?",
    why_asking: "Repeat sightings imply long-dwell or a recurring TTP from the same actor." },
  { question: "Is the observed activity consistent with this user's normal role and working hours?",
    why_asking: "Out-of-baseline activity (timezone, app, command) is the strongest signal of compromise vs. expected admin work." },
  { question: "What persistence, lateral-movement, or exfil indicators showed up after this event?",
    why_asking: "Confirms whether the alert is isolated or part of an active kill-chain in progress." },
];


function ChatWithRecon({ result, bare }) {
  const [messages, setMessages] = useState([]);
  const [input, setInput]       = useState('');
  const [sending, setSending]   = useState(false);
  const [error, setError]       = useState(null);
  const [pendingQuestion, setPendingQuestion] = useState(null);
  const scrollRef = useRef(null);
  const textareaRef = useRef(null);

  const runId = result?.runId;
  const rs    = result?.response_summary || {};
  // Use the AI-generated probing questions when the investigation produced
  // any; otherwise fall back to a generic-but-evergreen set so the analyst
  // always has clickable starting points (helps when the AI omits the field).
  // Ask RECON only surfaces probing questions that carry an if-yes / if-no
  // verdict path (the actionable ones). Plain clarifying questions and the
  // generic fallback set are intentionally omitted.
  const questions = (rs.probing_questions || []).filter(q => q && (q.if_yes_means || q.if_no_means));
  const usingFallback = false;
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

  // Click-to-ask: the question text appears as a synthetic AI message; the
  // analyst types their finding in the regular input. On submit we send the
  // backend a composed prompt that includes both so the AI knows what was
  // being answered, but the local chat shows just the analyst's raw answer.
  const askQuestion = (q) => {
    if (!q || sending) return;
    setPendingQuestion(q);
    setMessages(m => [
      ...m,
      { role: 'assistant',
        content: q.question,
        _from_card: true,
        _question_meta: q,
        timestamp: new Date().toISOString() },
    ]);
    setTimeout(() => textareaRef.current?.focus(), 50);
  };

  const send = async (msgOverride) => {
    const rawText = (msgOverride ?? input).trim();
    if (!rawText || !runId || sending) return;
    setSending(true); setError(null);
    if (!msgOverride) setInput('');

    // If the analyst is answering a question that was clicked from the cards,
    // compose a richer prompt for the backend but keep the local chat clean.
    let backendText = rawText;
    if (pendingQuestion) {
      const q = pendingQuestion;
      backendText =
        `RECON asked: ${q.question}\n\n` +
        `My investigation found: ${rawText}\n\n` +
        (q.if_yes_means ? `(If the answer is yes, that means: ${q.if_yes_means})\n` : '') +
        (q.if_no_means  ? `(If the answer is no, that means: ${q.if_no_means})\n` : '') +
        `\nGiven what I found, what's the interpretation and what should I check next?`;
      setPendingQuestion(null);
    }

    // Push user message immediately + an empty assistant placeholder we'll fill via stream
    setMessages(m => [
      ...m,
      { role:'user', content:rawText, timestamp:new Date().toISOString() },
      { role:'assistant', content:'', tool_calls:[], _streaming:true,
        timestamp:new Date().toISOString() },
    ]);

    try {
      const resp = await fetch(`/api/chat/${runId}`, {
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({ message: backendText }),
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
    : null;

  const body = (
    <>
      {banner && (
        <Typography sx={{ fontSize:12, color:'text.tertiary', mb:1.5, lineHeight:1.55 }}>
          {banner}
        </Typography>
      )}

      {/* Investigation-guidance question cards — always visible so the analyst
          can pick a new one mid-conversation. */}
      {questions.length > 0 && (
        <Box sx={{ mb:1.75 }}>
          <Box sx={{ display:'flex', alignItems:'center', gap:0.75, mb:1 }}>
            <Box sx={{ width:4, height:4, borderRadius:99, backgroundColor:accent }}/>
            <Typography variant="caption" sx={{
              fontSize:11, color:'text.tertiary', fontWeight:500,
              textTransform:'uppercase', letterSpacing:'0.06em',
            }}>
              {usingFallback
                ? 'Investigation starting points · click one to ask RECON'
                : (isAmbiguous ? 'Probing questions' : 'Things to verify · click — RECON asks, you answer')}
            </Typography>
          </Box>
          <Stack spacing={1}>
            {questions.map((q, i) => (
              <MuiPaper key={i} onClick={() => askQuestion(q)} elevation={0}
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

      {/* Answering-a-question banner */}
      {pendingQuestion && (
        <Box sx={{
          mb: 1, p: '8px 12px',
          backgroundColor: muiAlpha(accent, 0.08),
          border: `1px solid ${muiAlpha(accent, 0.4)}`,
          borderLeft: `3px solid ${accent}`,
          borderRadius: '4px',
          display: 'flex', alignItems: 'flex-start', gap: 1, justifyContent: 'space-between',
        }}>
          <Box sx={{ flex: 1, minWidth: 0 }}>
            <Typography sx={{ fontSize: 10, color: 'text.tertiary', fontWeight: 600,
              textTransform: 'uppercase', letterSpacing: '0.06em', mb: 0.25 }}>
              Answering RECON's question
            </Typography>
            <Typography sx={{ fontSize: 12, color: 'text.primary', lineHeight: 1.5 }}>
              {pendingQuestion.question}
            </Typography>
          </Box>
          <MuiIconButton size="small" onClick={() => {
            setPendingQuestion(null);
            // Also drop the synthetic AI bubble we just added if it's still the last one
            setMessages(m => {
              const last = m[m.length - 1];
              return last?._from_card ? m.slice(0, -1) : m;
            });
          }} title="Cancel and clear the question"
            sx={{ color: 'text.tertiary', '&:hover': { color: 'text.primary' } }}>
            <X size={14}/>
          </MuiIconButton>
        </Box>
      )}

      {/* Input row */}
      <Stack direction="row" spacing={1}>
        <MuiTextField
          inputRef={textareaRef}
          multiline rows={2} fullWidth variant="outlined"
          value={input} onChange={e => setInput(e.target.value)}
          onKeyDown={e => {
            if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) { e.preventDefault(); send(); }
          }}
          placeholder={pendingQuestion
            ? 'Type what you found when checking this — RECON will interpret your answer…'
            : 'Ask anything — "Is this likely a vulnerability scanner?", "Look up this hash in sandbox"…'}
          sx={{ flex:1, '& .MuiOutlinedInput-input': { fontSize:13, lineHeight:1.5 } }}
        />
        <MuiButton variant="contained"
          onClick={() => send()} disabled={sending || !input.trim()}
          sx={{ alignSelf:'stretch', minWidth:64 }}>
          {pendingQuestion ? 'Answer' : 'Send'}
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
    </>
  );
  if (bare) return body;
  return (
    <Card title="Ask RECON" accent={accent}
      badge={questions.length > 0
        ? `${questions.length} ${usingFallback ? 'starter questions' : 'suggested checks'}`
        : null}>
      {body}
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
  const rs    = result?.response_summary || {};
  const mitre = rs.mitre_techniques || [];
  // On-demand generation state — detection content is generated from the
  // Detection card via /api/detection rather than auto-generated every run.
  const [g, setG] = useState(null);      // { sigma, kql, spl, sigma_valid }
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState(null);
  const [active, setActive] = useState(null);

  // Prefer on-demand generated content; fall back to any auto content (legacy).
  const sigma = g?.sigma ?? result?.sigma_rule;
  const kql   = g?.kql   ?? result?.kql_query;
  const siem  = result?.response_summary?.siem_queries || {};
  const sigmaValid = g ? g.sigma_valid : rs.sigma_valid;
  const tabs = [
    sigma                  && { id:'sigma',       label:'Sigma',                 content:sigma,                  badge: sigmaValid===true?'validated':sigmaValid===false?'invalid':null },
    kql                    && { id:'kql',         label:'KQL · Sentinel',        content:kql },
    (g?.spl || siem.splunk_spl) && { id:'spl',    label:'Splunk SPL',            content:g?.spl || siem.splunk_spl },
    siem.elastic_eql       && { id:'eql',         label:'Elastic EQL',           content:siem.elastic_eql },
    siem.chronicle_yara_l  && { id:'yaral',       label:'Chronicle YARA-L',      content:siem.chronicle_yara_l },
    siem.crowdstrike_fql   && { id:'fql',         label:'CrowdStrike Falcon',    content:siem.crowdstrike_fql },
  ].filter(Boolean);

  const generate = async () => {
    setLoading(true); setErr(null);
    try {
      const analysis = { threatLevel: rs.threat_level, summary: rs.summary, mitreTechniques: mitre };
      const base = { iocs: result?.iocs || {}, analysis };
      const post = (action) => fetch('/api/detection', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...base, action }),
      }).then(r => r.json());
      const [sg, kq] = await Promise.all([post('sigma'), post('kql')]);
      setG({ sigma: sg.result, kql: kq.result, spl: sg.splunk_spl, sigma_valid: sg.valid });
      setActive('sigma');
    } catch (e) { setErr(e.message || 'Generation failed'); }
    finally { setLoading(false); }
  };

  // Nothing generated yet → show the on-demand generate button.
  if (!tabs.length) {
    return (
      <Card title="Detection Rules" accent="#0fbcff">
        <Typography sx={{ fontSize: 12, color: 'text.tertiary', mb: 1.5, lineHeight: 1.6 }}>
          Generate a validated Sigma rule, a Microsoft Sentinel KQL analytics rule, and a
          Splunk SPL query for this alert's IOCs and MITRE techniques — on demand, so
          investigations stay fast.
        </Typography>
        <MuiButton variant="contained" onClick={generate} disabled={loading}
          sx={{ textTransform: 'none' }}>
          {loading ? 'Generating…' : 'Generate detection content'}
        </MuiButton>
        {err && (
          <Typography sx={{ fontSize: 12, color: 'error.main', mt: 1 }}>{err}</Typography>
        )}
      </Card>
    );
  }

  const cur = tabs.find(x => x.id === (active || tabs[0]?.id)) || tabs[0];

  return (
    <Card title="Detection Rules" accent="#0fbcff" badge={`${tabs.length} platforms`}>
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

/* ─── sidebar scanner input — unified pill with leading icon + submit ────── */
function ScannerInput({ icon, placeholder, value, onChange, onSubmit, disabled, submitLabel, sx }) {
  const trimmed = (value || '').trim();
  const ready = !!trimmed && !disabled;
  return (
    <Box sx={{
      display: 'flex', alignItems: 'stretch',
      backgroundColor: 'background.secondary',
      border: `1px solid ${muiAlpha('#ffffff', 0.12)}`,
      borderRadius: '4px',
      overflow: 'hidden',
      transition: 'border-color .15s',
      '&:focus-within': { borderColor: 'primary.main' },
      ...sx,
    }}>
      <Box sx={{
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        px: 1, color: ready ? 'primary.main' : 'text.tertiary',
        transition: 'color .15s',
      }}>
        {icon}
      </Box>
      <Box component="input" type="text"
        value={value}
        disabled={disabled}
        onChange={e => onChange(e.target.value)}
        onKeyDown={e => {
          if (e.key === 'Enter' && trimmed) onSubmit(trimmed);
        }}
        placeholder={placeholder}
        sx={{
          flex: 1, minWidth: 0,
          backgroundColor: 'transparent',
          border: 'none',
          color: 'text.primary',
          p: '8px 4px 8px 0',
          fontFamily: '"IBM Plex Mono", monospace',
          fontSize: 11,
          outline: 'none',
          '&::placeholder': { color: 'text.tertiary' },
          '&:disabled': { opacity: 0.5 },
        }}
      />
      <Box component="button"
        disabled={!ready}
        onClick={() => onSubmit(trimmed)}
        sx={{
          backgroundColor: ready ? muiAlpha('#0fbcff', 0.12) : 'transparent',
          borderLeft: `1px solid ${muiAlpha('#ffffff', 0.08)}`,
          border: 'none',
          borderLeftStyle: 'solid',
          borderLeftWidth: '1px',
          borderLeftColor: muiAlpha('#ffffff', 0.08),
          color: ready ? 'primary.main' : 'text.tertiary',
          fontSize: 11, fontWeight: 600,
          px: 1.5,
          cursor: ready ? 'pointer' : 'default',
          textTransform: 'uppercase', letterSpacing: '0.05em',
          transition: 'all .15s',
          '&:hover:not(:disabled)': {
            backgroundColor: muiAlpha('#0fbcff', 0.2),
          },
        }}>
        {submitLabel}
      </Box>
    </Box>
  );
}


/* ─── sidebar ─────────────────────────────────────────────────────────────────
 * Adapted from OpenCTI (AGPL-3.0) — LeftBar.jsx pattern.
 * Uses MUI Drawer with the OpenCTI nav width/styling, hosting the input area
 * (drop zone + textarea + AgentPipeline) and the extracted-IOCs panel.
 */
function Sidebar({ onResult, onPartialResult, currentResult, onScanFile, onScanHash, onScanUrl, scanState, onHome, onOpenEmail, emailActive }) {
  const [logText, setLogText] = useState('');
  const [dragOver, setDragOver] = useState(false);
  const [hashInput, setHashInput] = useState('');
  const [urlInput, setUrlInput]   = useState('');

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
      {/* Logo header — click to fully reset: clears the main view (scan /
          email / result) and every sidebar input. */}
      <Box
        onClick={() => {
          setLogText('');
          setHashInput('');
          setUrlInput('');
          setDragOver(false);
          onHome?.();
        }}
        title="Back to main — clears everything"
        sx={{
          p: '18px 14px 16px',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          borderBottom: `1px solid ${muiAlpha('#ffffff', 0.12)}`,
          cursor: 'pointer',
          transition: 'opacity .15s',
          '&:hover': { opacity: 0.8 },
        }}
      >
        <Box component="img" src="/logo.png" alt="RECON"
          sx={{ width: '100%', maxWidth: 200, height: 'auto', display: 'block',
            filter: 'drop-shadow(0 0 18px rgba(15,188,255,0.35))' }}/>
      </Box>

      {/* Input area + pipeline */}
      <Box sx={{ p: '18px 16px 16px', flex: 1, overflowY: 'auto' }}>
        {/* Comprehensive file-analyzer drop zone — POSTs /api/scan/file.
            When scanning starts the main view auto-replaces the analysis
            output with the scanner result panel until dismissed. */}
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
              {scanState?.scanning ? 'Analyzing…' : 'File Analyzer'}
            </Typography>
            <Typography sx={{ color: 'text.tertiary', fontSize: 11, mt: 0.25 }}>
              ≤ 50 MB
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

        {/* Email composer entry point — opens the dedicated composer view */}
        <Box
          onClick={() => onOpenEmail?.()}
          sx={{
            display: 'flex', alignItems: 'center', gap: 1.25,
            p: '12px 14px',
            backgroundColor: emailActive ? muiAlpha('#0fbcff', 0.1) : 'background.secondary',
            border: `1px solid ${emailActive ? muiAlpha('#0fbcff', 0.5) : muiAlpha('#ffffff', 0.12)}`,
            borderRadius: '4px',
            cursor: 'pointer',
            mb: 1.25,
            transition: 'all .15s',
            '&:hover': {
              borderColor: muiAlpha('#0fbcff', 0.5),
              backgroundColor: muiAlpha('#0fbcff', 0.06),
            },
          }}
        >
          <Mail size={16} color="#0fbcff" style={{ flexShrink: 0 }}/>
          <Typography sx={{
            color: emailActive ? '#0fbcff' : 'text.primary',
            fontSize: 12, fontWeight: 500, flex: 1, minWidth: 0,
          }}>
            Email
          </Typography>
        </Box>

        {/* Textarea with clear button */}
        <Box sx={{ position: 'relative', mb: 1.25 }}>
          <Box component="textarea"
            value={logText} onChange={e=>setLogText(e.target.value)}
            placeholder="Paste to Analyze"
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

        {/* Hash / URL input groups — unified pill with leading icon + inline
            submit button. Button glows primary when input is non-empty. */}
        {/* Hash lookup removed — paste hashes into Analyze (same enrichment). */}
        <ScannerInput
          icon={<Link2 size={13}/>}
          placeholder="Scan URL"
          value={urlInput}
          onChange={setUrlInput}
          onSubmit={(v) => { onScanUrl?.(v); setUrlInput(''); }}
          disabled={scanState?.scanning}
          submitLabel="Fetch"
          sx={{ mb: 1.25 }}
        />

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


/* ─── app ─────────────────────────────────────────────────────────────────────── */
export default function App() {
  const [result, setResult] = useState(null);
  const [view, setView] = useState('detail'); // 'detail' | 'table'
  const [webhooks, setWebhooks] = useState({});
  // Bumped on "go home" (logo) to remount the Sidebar — this clears its local
  // input state AND the AgentPipeline's internal trace/pipeline, which would
  // otherwise linger under the Scan URL input after returning home.
  const [homeNonce, setHomeNonce] = useState(0);
  const rs = result?.response_summary;

  // Comprehensive file-analyzer state — lifted from FileScannerView so the
  // sidebar can drive scans (file drop / hash lookup / URL fetch). When
  // there's active scan state, the main view shows the scanner results
  // instead of the analysis view.
  const [scanState, setScanState] = useState({
    scanning: false, result: null, error: null, progressStep: 0,
  });
  // Email composer takeover — when truthy, main view shows the composer.
  // Holds optional { log, parsed } seed so the analyze/scanner pipelines
  // can pre-populate the composer with the current investigation context.
  const [emailState, setEmailState] = useState(null);
  // Show scanner whenever there's scan activity in flight or a result on hand
  const showScanner = scanState.scanning || scanState.result || scanState.error;
  const clearScan = useCallback(() => {
    setScanState({ scanning: false, result: null, error: null, progressStep: 0 });
  }, []);
  const scanProgressTimer = useRef(null);

  const startScanProgress = useCallback(() => {
    setScanState(s => ({ ...s, progressStep: 0 }));
    let step = 0;
    scanProgressTimer.current = setInterval(() => {
      step = Math.min(step + 1, 9); // ANALYSIS_STEPS.length - 1
      setScanState(s => ({ ...s, progressStep: step }));
    }, 700);
  }, []);
  const stopScanProgress = useCallback(() => {
    if (scanProgressTimer.current) {
      clearInterval(scanProgressTimer.current);
      scanProgressTimer.current = null;
    }
    setScanState(s => ({ ...s, progressStep: 10 }));
  }, []);

  const _runScan = useCallback(async (fetchFn) => {
    // Any new scan immediately switches the main view to the scanner —
    // clear analyze + email state so the user lands on the action they
    // just triggered, not whatever was on screen before.
    setEmailState(null);
    setResult(null);
    setScanState({ scanning: true, result: null, error: null, progressStep: 0 });
    startScanProgress();
    try {
      const resp = await fetchFn();
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.detail || `HTTP ${resp.status}`);
      setScanState(s => ({ ...s, scanning: false, result: data }));

      // If the backend kicked off AI in the background, poll GET /api/scan/{sha256}
      // until ai_pending flips false. The UI re-renders each time we set the result
      // so the analyst sees verdict / triage / deep / summary pop in as they finish.
      const sha = data?.hashes?.sha256;
      if (sha && data.ai_pending) {
        let tries = 0;
        const poll = async () => {
          tries += 1;
          if (tries > 60) return;   // ~3 min cap (60 × 3s) — bail rather than spin forever
          try {
            const r = await fetch(`/api/scan/by-hash/${sha}`);
            if (r.ok) {
              const fresh = await r.json();
              setScanState(s => ({ ...s, result: fresh }));
              if (fresh.ai_pending === false) return;
            }
          } catch (_) {}
          setTimeout(poll, 3000);
        };
        setTimeout(poll, 3000);
      }
    } catch (e) {
      setScanState(s => ({ ...s, scanning: false, error: e.message }));
    } finally {
      stopScanProgress();
    }
  }, [startScanProgress, stopScanProgress]);

  const scanFile = useCallback((uploaded) => {
    if (!uploaded) return;
    const form = new FormData();
    form.append('file', uploaded);
    return _runScan(() => fetch('/api/scan/file', { method: 'POST', body: form }));
  }, [_runScan]);

  const scanHash = useCallback((hash) => {
    if (!hash) return;
    return _runScan(() => fetch('/api/scan/hash', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ hash: hash.trim() }),
    }));
  }, [_runScan]);

  const scanUrl = useCallback((url) => {
    if (!url) return;
    return _runScan(() => fetch('/api/scan/url', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: url.trim() }),
    }));
  }, [_runScan]);

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
        key={homeNonce}
        onResult={(r) => {
          // Starting (r=null) or finishing an Analyze run dismisses the
          // file scanner view so the analysis result owns the main area.
          clearScan();
          setEmailState(null);
          setResult(r);
        }}
        onPartialResult={mergePartial}
        currentResult={result}
        onScanFile={scanFile}
        onScanHash={scanHash}
        onScanUrl={scanUrl}
        scanState={scanState}
        onHome={() => { clearScan(); setEmailState(null); setResult(null); setHomeNonce(n => n + 1); }}
        onOpenEmail={() => {
          // Pre-populate from whatever's on screen: the file-scanner result
          // wins if visible, otherwise the analysis result, otherwise blank.
          const scanSummary = scanState?.result?.ai_analyst?.deep?.executive_summary
            || scanState?.result?.ai_summary;
          const ctx = scanSummary
            ? { log: scanSummary }
            : (result?.raw_input ? { log: result.raw_input } : { log: '' });
          clearScan();
          setEmailState(ctx);
        }}
        emailActive={!!emailState}
      />

      {/* Main view priority: email composer > file scanner > analysis */}
      {emailState && (
        <EmailComposerView
          initialLog={emailState.log || ''}
          initialParsed={emailState.parsed || null}
          onClose={() => setEmailState(null)}
        />
      )}
      {!emailState && showScanner && (
        <Box sx={{ flex: 1, minWidth: 0, position: 'relative' }}>
          {/* Close button to dismiss scanner and return to the analysis view */}
          <MuiIconButton onClick={clearScan}
            title="Close scan results"
            sx={{
              position: 'absolute', top: 12, right: 16, zIndex: 2,
              color: 'text.tertiary', '&:hover': { color: 'text.primary' },
            }}>
            <X size={16}/>
          </MuiIconButton>
          <FileScannerView
            external={scanState}
            onScanFile={scanFile}
            onScanHash={scanHash}
            onScanUrl={scanUrl}
            onComposeEmail={(scanResult) => {
              // Build a synthetic "alert log" that captures the scanner's key
              // findings so the composer parser has something to extract from.
              const lines = [];
              if (scanResult?.filename)        lines.push(`AssetName: ${scanResult.filename}`);
              if (scanResult?.verdict)        lines.push(`Verdict: ${scanResult.verdict}`);
              if (scanResult?.hashes?.sha256) lines.push(`Hash: ${scanResult.hashes.sha256}`);
              const cls = scanResult?.ai_analyst?.deep?.malware_classification?.category
                       || scanResult?.ai_analyst?.triage?.classification;
              if (cls)                        lines.push(`ThreatName: ${cls}`);
              const summary = scanResult?.ai_analyst?.deep?.execution_narrative
                          || scanResult?.ai_analyst?.triage?.summary;
              if (summary)                    lines.push(`Message: ${summary}`);
              setEmailState({ log: lines.join('\n'), parsed: null });
            }}
          />
        </Box>
      )}
      {!emailState && !showScanner && (

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
            <Stack direction="row" spacing={1} alignItems="center">
              {/* Compose-email lives in the left sidebar ("Email"); no duplicate here. */}
              <SendToWebhook result={result} available={webhooks}/>
            </Stack>
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
          </>
        )}

        {result && view === 'detail' && (
          <>
            <PreFlight result={result}/>
            <SignalBanners result={result}/>
            {/* Collapsible detail stack, keyed by run so each new investigation
                resets to collapsed. Headline cards (Investigation results, Summary)
                are open by default; the rest collapse. */}
            <CardDefaultOpenContext.Provider value={false} key={result.runId || 'detail'}>
            <GTI result={result}/>                {/* Investigation results + threat score + confidence (open) */}
            <AnalystSummary rs={rs || {}}/>        {/* Summary (open) */}
            <ChatWithRecon result={result}/>       {/* Ask RECON — probing questions */}
            <Triage result={result}/>              {/* Logs + MISP-filtered IOCs, fused */}
            <BehavioralIndicators result={result}/>
            <InfrastructureIntel result={result}/> {/* OSINT — includes geopolitical context */}
            <HoneypotActivity result={result}/>
            <SandboxBehavioral result={result}/>
            <EmailAnalysis result={result}/>
            <CrossRefs rs={rs || {}}/>
            <NetworkDetection result={result}/>
            <URLScanLive result={result}/>

            <Card title="Graphs" accent="#0fbcff" noPad>
              <MapTab result={result}/>
              <Box sx={{ p: '14px 16px', borderTop: `1px solid ${muiAlpha('#ffffff', 0.08)}` }}>
                <PivotGraph result={result}/>
              </Box>
            </Card>

            <Detection result={result}/>          {/* Detection Rules — on-demand, at bottom */}
            </CardDefaultOpenContext.Provider>
          </>
        )}
      </Box>
      )}

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
