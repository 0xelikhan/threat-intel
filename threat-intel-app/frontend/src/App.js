import React, { useState, useCallback, useRef, useEffect, lazy, Suspense } from 'react';
import {
  ArrowUpRight, AlertCircle, ChevronRight, X, FileSearch, Mail, Activity,
} from 'lucide-react';

import AgentPipeline     from './components/AgentPipeline';
import URLScanLive       from './components/URLScanLive';
import ErrorBoundary     from './components/ErrorBoundary';
import ToastHost         from './components/Toast';
import {
  SkeletonLazyFallback, SkeletonAnalyze,
} from './components/Skeleton';

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
import { sourceUrl } from './sourceUrls';

// Code-split the three heaviest workspaces so they only load when the
// analyst actually opens them. FileScannerView is the densest view in the
// app (~600 lines + analyst-report sections), EmailComposerView pulls the
// rendered-email iframe pipeline, and MapTab pulls Leaflet + its CSS.
// Cuts the initial bundle the cold-load analyst pays for.
const FileScannerView   = lazy(() => import('./components/FileScannerView'));
const EmailComposerView = lazy(() => import('./components/EmailComposerView'));
const MapTab            = lazy(() => import('./components/MapTab'));
const LoginPage         = lazy(() => import('./components/LoginPage'));

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

function SandboxBehavioral({ result, bare }) {
  const hashes = result?.enrichments?.hashes || {};
  const rows = Object.entries(hashes)
    .map(([h, p]) => ({ hash: h, deep: p?.sandbox_deep }))
    .filter(r => r.deep && r.deep.process_tree);
  if (!rows.length) return null;

  const monoSx = { fontFamily: '"IBM Plex Mono", monospace' };

  const body = (
    <>
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
    </>
  );
  if (bare) return body;
  return (
    <Card title="Sandbox behavioral analysis · process tree + IOCs" accent="#EE3838"
      badge={`${rows.length} sample${rows.length === 1 ? '' : 's'}`} defaultOpen={false}>
      {body}
    </Card>
  );
}

/* ─── honeypot / deception intelligence (spec §5) ────────────────────────────
 * Per-IP rollup of: GreyNoise RIOT (known-good infra), DShield SANS ISC,
 * StopForumSpam, Emerging Threats blocklist, Project Honeypot HTTP:BL.
 * Each source returns flagged + summary.
 */
function HoneypotActivity({ result, bare }) {
  const ips = result?.enrichments?.ips || {};
  const rows = Object.entries(ips)
    .map(([ip, payload]) => ({ ip, dec: payload?.deception, full: payload }))
    .filter(r => r.dec && (r.dec.flagged_count > 0 || r.dec.greynoise_riot?.is_known_good));
  if (!rows.length) return null;

  const monoSx = { fontFamily: '"IBM Plex Mono", monospace' };

  // Per-source rich-detail renderer. Each branch returns null when the
  // source didn't run or had no data; the parent only emits rows for
  // sources that actually produced something.
  const renderSource = (key, payload) => {
    if (!payload) return null;
    switch (key) {
      case 'greynoise_riot': {
        if (!payload.is_known_good) return null;
        return {
          name: 'GreyNoise RIOT', good: true,
          headline: 'known-good infrastructure',
          rows: [
            payload.name        && ['Service',     payload.name],
            payload.category    && ['Category',    payload.category],
            payload.trust_level && ['Trust level', String(payload.trust_level)],
            payload.description && ['Description', payload.description],
            payload.last_updated && ['Last updated', payload.last_updated.slice(0, 10)],
          ].filter(Boolean),
        };
      }
      case 'dshield': {
        if (!payload.flagged) return null;
        return {
          name: 'DShield · SANS ISC', good: false,
          headline: payload.summary,
          rows: [
            payload.attack_count != null && ['Attacks', String(payload.attack_count)],
            payload.report_count != null && ['Reports', String(payload.report_count)],
            payload.threat_level && ['Threat level', String(payload.threat_level)],
            payload.comment && ['Comment', payload.comment],
          ].filter(Boolean),
        };
      }
      case 'stopforumspam': {
        if (!payload.flagged) return null;
        return {
          name: 'StopForumSpam', good: false,
          headline: payload.summary,
          rows: [
            payload.appears    != null && ['Reports',    String(payload.appears)],
            payload.frequency  != null && ['Frequency',  String(payload.frequency)],
            payload.confidence != null && ['Confidence', String(payload.confidence)],
            payload.last_seen          && ['Last seen',  payload.last_seen.slice(0, 10)],
          ].filter(Boolean),
        };
      }
      case 'emerging_threats': {
        if (!payload.flagged) return null;
        return {
          name: 'Emerging Threats blocklist', good: false,
          headline: 'On the ET compromised-ips list',
          rows: [
            payload.source && ['Source list', payload.source],
          ].filter(Boolean),
        };
      }
      case 'project_honeypot': {
        if (!payload.flagged) return null;
        return {
          name: 'Project Honeypot HTTP:BL', good: false,
          headline: payload.classification || '',
          rows: [
            payload.last_seen_days != null && ['Last seen',   `${payload.last_seen_days} day${payload.last_seen_days === 1 ? '' : 's'} ago`],
            payload.threat_score   != null && ['Threat score', `${payload.threat_score} / 255`],
            payload.classification && ['Classification', payload.classification],
          ].filter(Boolean),
        };
      }
      default:
        return null;
    }
  };

  const body = (
    <>
      <Typography sx={{ fontSize: 12, color: 'text.tertiary', mb: 1.5, lineHeight: 1.6 }}>
        Cross-checked against GreyNoise RIOT, DShield SANS ISC, StopForumSpam,
        Emerging Threats compromised IPs, and Project Honeypot HTTP:BL.
      </Typography>
      {rows.map(({ ip, dec, full }) => {
        // ── Per-IP context (ASN / country / ISP / AbuseIPDB) — already
        // enriched by the analyze pipeline, surfaced here so the analyst
        // sees the IP's identity alongside the deception findings.
        const ipinfo  = full?.ipinfo || {};
        const abuse   = full?.abuseipdb || {};
        const country = ipinfo.country || abuse.countryCode || '';
        const asn     = ipinfo.asn || ipinfo.org || '';
        const isp     = ipinfo.org || abuse.isp || '';
        const city    = ipinfo.city || '';
        const region  = ipinfo.region || '';
        const usage   = abuse.usageType || '';
        const abuseScore = abuse.abuseConfidenceScore;
        const recentReports = abuse.totalReports;
        const lastReportedAt = abuse.lastReportedAt;
        const headerChips = [
          country && { label: country, color: '#848592' },
          asn && { label: asn, color: '#848592' },
          usage && { label: usage, color: '#848592' },
          abuseScore != null && abuseScore > 0 && {
            label: `AbuseIPDB ${abuseScore}%`,
            color: abuseScore >= 75 ? '#EE3838'
              : abuseScore >= 25 ? '#E6700F' : '#E1B823',
          },
        ].filter(Boolean);

        const renderedSources = [
          renderSource('greynoise_riot',    dec.greynoise_riot),
          renderSource('dshield',           dec.dshield),
          renderSource('stopforumspam',     dec.stopforumspam),
          renderSource('emerging_threats',  dec.emerging_threats),
          renderSource('project_honeypot',  dec.project_honeypot),
        ].filter(Boolean);

        return (
          <MuiPaper key={ip} elevation={0} sx={{
            backgroundColor: '#0C1524',
            border: `1px solid ${muiAlpha('#ffffff', 0.12)}`,
            borderRadius: '4px', p: '12px 14px', mb: 1,
          }}>
            {/* Header — IP + identity context + flag count + pivots */}
            <Stack direction="row" alignItems="center" spacing={1}
              sx={{ mb: 1 }} flexWrap="wrap">
              <TypeTag type="ips"/>
              <Box sx={{ ...monoSx, fontSize: 12.5, color: 'text.primary',
                fontWeight: 600 }}>{ip}</Box>
              {headerChips.map((c, i) => (
                <Box key={i} sx={{
                  fontSize: 10.5, fontWeight: 500, color: c.color,
                  border: `1px solid ${muiAlpha(c.color, 0.4)}`,
                  backgroundColor: muiAlpha(c.color, 0.08),
                  borderRadius: '3px', px: 0.75, py: '1px',
                }}>{c.label}</Box>
              ))}
              <Box component="span" sx={{
                ml: 'auto !important', fontSize: 11, color: 'text.tertiary',
              }}>
                {dec.flagged_count} of {dec.sources_consulted} sources flagged
              </Box>
            </Stack>

            {/* Secondary identity line — ISP / city / abuse history */}
            {(isp || city || recentReports || lastReportedAt) && (
              <Stack direction="row" spacing={2} sx={{ mb: 1,
                fontSize: 11, color: 'text.tertiary',
                flexWrap: 'wrap', rowGap: 0.25 }}>
                {isp && <Box>ISP: <Box component="span" sx={{ color: 'text.primary' }}>{isp}</Box></Box>}
                {city && <Box>Location: <Box component="span" sx={{ color: 'text.primary' }}>{[city, region, country].filter(Boolean).join(', ')}</Box></Box>}
                {recentReports != null && recentReports > 0 && (
                  <Box>AbuseIPDB reports: <Box component="span" sx={{ color: 'text.primary' }}>{recentReports}</Box></Box>
                )}
                {lastReportedAt && (
                  <Box>Last reported: <Box component="span" sx={{ color: 'text.primary' }}>{String(lastReportedAt).slice(0, 10)}</Box></Box>
                )}
              </Stack>
            )}

            {/* Pivot links */}
            <Stack direction="row" spacing={1.25} sx={{ mb: renderedSources.length ? 1 : 0,
              flexWrap: 'wrap', rowGap: 0.5 }}>
              <Box component="a" target="_blank" rel="noreferrer"
                href={`https://www.abuseipdb.com/check/${ip}`}
                sx={{ fontSize: 10.5, color: '#0fbcff', textDecoration: 'none',
                  '&:hover': { textDecoration: 'underline' } }}>
                AbuseIPDB ↗
              </Box>
              <Box component="a" target="_blank" rel="noreferrer"
                href={`https://www.virustotal.com/gui/ip-address/${ip}`}
                sx={{ fontSize: 10.5, color: '#0fbcff', textDecoration: 'none',
                  '&:hover': { textDecoration: 'underline' } }}>
                VirusTotal ↗
              </Box>
              <Box component="a" target="_blank" rel="noreferrer"
                href={`https://isc.sans.edu/ipinfo.html?ip=${ip}`}
                sx={{ fontSize: 10.5, color: '#0fbcff', textDecoration: 'none',
                  '&:hover': { textDecoration: 'underline' } }}>
                DShield ↗
              </Box>
              <Box component="a" target="_blank" rel="noreferrer"
                href={`https://www.greynoise.io/viz/ip/${ip}`}
                sx={{ fontSize: 10.5, color: '#0fbcff', textDecoration: 'none',
                  '&:hover': { textDecoration: 'underline' } }}>
                GreyNoise ↗
              </Box>
            </Stack>

            {/* Per-source rich detail */}
            {renderedSources.map((s, i) => (
              <Box key={i} sx={{
                py: 0.875,
                borderTop: i > 0 ? `1px solid ${muiAlpha('#ffffff', 0.06)}` : 'none',
              }}>
                <Stack direction="row" alignItems="baseline" spacing={1}
                  flexWrap="wrap" sx={{ rowGap: 0.25 }}>
                  <Box component="span" sx={{
                    fontSize: 11.5, fontWeight: 700,
                    color: s.good ? 'success.main' : 'error.main',
                    whiteSpace: 'nowrap',
                  }}>{s.name}</Box>
                  {s.headline && (
                    <Box component="span" sx={{ fontSize: 11, color: 'text.tertiary' }}>
                      {s.headline}
                    </Box>
                  )}
                </Stack>
                {s.rows.length > 0 && (
                  <Box sx={{ mt: 0.5, pl: 1.25,
                    borderLeft: `2px solid ${muiAlpha(s.good ? '#16AD34' : '#EE3838', 0.25)}`,
                    display: 'grid',
                    gridTemplateColumns: 'minmax(110px, max-content) 1fr',
                    columnGap: 1.25, rowGap: 0.25,
                  }}>
                    {s.rows.map(([k, v], j) => (
                      <React.Fragment key={j}>
                        <Box component="span" sx={{ fontSize: 10.5,
                          color: 'text.disabled',
                          textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                          {k}
                        </Box>
                        <Box component="span" sx={{ fontSize: 11.5,
                          color: 'text.primary', wordBreak: 'break-word',
                          ...(/^(Open ports|CVEs|Hostnames)$/.test(k) ? monoSx : {}) }}>
                          {v}
                        </Box>
                      </React.Fragment>
                    ))}
                  </Box>
                )}
              </Box>
            ))}
          </MuiPaper>
        );
      })}
    </>
  );
  if (bare) return body;
  return (
    <Card title="Honeypot activity · deception intel" accent="#EE3838"
      badge={`${rows.length} IP${rows.length === 1 ? '' : 's'} with hits`}>
      {body}
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
      {/* normalized_summary moved to the top of the Summary card (Plain-English
          summary block) so it's the first thing the analyst sees, not buried
          inside the Triage > Logs sub-section. */}
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
// Does this result have any OSINT/infrastructure content to show? Mirrors
// InfrastructureIntel's render guard so the Triage wrapper can decide whether
// to render the embedded "OSINT" section + label.
function hasOsintContent(result) {
  // Geopolitical context now lives under the Geolocation card, and
  // URL detonation lifts to the top of Triage on URL-bearing alerts —
  // neither contributes to OSINT-presence anymore.
  const enr = result?.enrichments || {};
  const hasRows = ['ips', 'domains', 'hashes'].some(cat =>
    Object.values(enr[cat] || {}).some(p => p?.osint && Object.keys(p.osint).length));
  const hasHoneypot = Object.values(enr.ips || {})
    .some(p => p?.deception && (p.deception.flagged_count > 0 || p.deception.greynoise_riot?.is_known_good));
  // JA3 / JA4 fingerprints live under Detection Rules now, not OSINT.
  return hasRows || hasHoneypot;
}

function InfrastructureIntel({ result, bare, hideUrlscan = false, hideGeopolitical = true }) {
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
  // hideGeopolitical (default true) lets the Geolocation card own the
  // geopolitical block so it doesn't compete with the actual map.
  const hasGeo = !hideGeopolitical
    && !!(gp && !gp.error && (gp.countries?.length || gp.attribution));
  const hasHoneypot = Object.values(result?.enrichments?.ips || {})
    .some(p => p?.deception && (p.deception.flagged_count > 0 || p.deception.greynoise_riot?.is_known_good));
  // When URL detonation has been lifted to its own top-of-Triage section,
  // suppress the duplicate inside OSINT so it doesn't render twice.
  const hasUrlscan = !hideUrlscan && !!(result?.iocs?.urls || []).length;
  if (!rows.length && !hasGeo && !hasHoneypot && !hasUrlscan) return null;

  const monoSx = { fontFamily: '"IBM Plex Mono", monospace' };
  const Label = ({ children }) => (
    <Typography sx={{ fontSize: 11, fontWeight: 600, color: 'text.tertiary',
      textTransform: 'uppercase', letterSpacing: '0.06em', mb: 1.25 }}>{children}</Typography>
  );
  const divSx = (show) => ({ mt: show ? 2 : 0, pt: show ? 2 : 0,
    borderTop: show ? `1px solid ${muiAlpha('#ffffff', 0.08)}` : 'none' });

  const body = (
    <>
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
        <Box sx={divSx(rows.length)}>
          <Label>Geopolitical context</Label>
          <GeopoliticalContext result={result} bare/>
        </Box>
      )}
      {hasHoneypot && (
        <Box sx={divSx(rows.length || hasGeo)}>
          <Label>IP reputation · deception networks</Label>
          <HoneypotActivity result={result} bare/>
        </Box>
      )}
      {/* JA3/JA4 network detection lives under the Detection Rules card
          now — Sigma + KQL snippets belong with the other detection
          content, not OSINT. */}
      {hasUrlscan && (
        <Box sx={divSx(rows.length || hasGeo || hasHoneypot)}>
          <Label>Live URL detonation · URLScan.io</Label>
          <URLScanLive result={result} bare/>
        </Box>
      )}
    </>
  );
  if (bare) return body;
  return (
    <Card title="OSINT" accent="#0fbcff"
      badge={`${rows.length} IOC${rows.length === 1 ? '' : 's'}`} defaultOpen={false}>
      {body}
    </Card>
  );
}

// Recommended actions from the AI investigation — flat list of imperative
// strings. Restored after being dropped in c56e28b — Behavior was left as
// pure observation with no "so what." Filters out the well-known fallback
// strings the backend emits when the AI call fails so we don't render
// useless placeholders ("Review enrichment data manually." etc.).
const _AI_FALLBACK_ACTIONS = new Set([
  'Review enrichment data manually.',
  'Configure OpenAI API key for AI analysis.',
]);
function RecommendedActions({ rs, bare }) {
  const items = (rs?.recommended_actions || [])
    .filter(a => typeof a === 'string' && a.trim() && !_AI_FALLBACK_ACTIONS.has(a.trim()));
  if (!items.length) return null;
  const body = (
    <Box component="ol" sx={{ pl: 0, m: 0, listStyle: 'none' }}>
      {items.map((a, i) => (
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
    </Box>
  );
  if (bare) return body;
  return <Card title="Recommended actions" accent="#16AD34">{body}</Card>;
}

// Senior-analyst context paragraph. Stored as a string on rs.analyst_notes
// per investigation.py:865 — render as a soft prose block, not a textarea.
function AnalystNotes({ rs, bare }) {
  const notes = (rs?.analyst_notes || '').trim();
  if (!notes) return null;
  const body = (
    <Typography sx={{ fontSize: 13, color: 'text.primary', lineHeight: 1.7,
      whiteSpace: 'pre-wrap', fontStyle: 'italic',
      borderLeft: `2px solid ${muiAlpha('#0fbcff', 0.5)}`, pl: 1.5, py: 0.5,
    }}>{notes}</Typography>
  );
  if (bare) return body;
  return <Card title="Analyst notes" accent="#0fbcff">{body}</Card>;
}

/* ─── suppressed IOCs (MISP warninglist matches) ─────────────────────────────
 * Spec §4 — show analysts exactly what was filtered out before enrichment so
 * they can spot false-negative filters (e.g., a Tor exit IP swallowed by a
 * datacenter list).
 */
// Triage: log normalization + MISP-warninglist false-positive filtering +
// OSINT + behavioral signals + AI recommendations, all in one card. Folded
// here because the standalone Behavior card hid itself in too many cases —
// keeping the content in a section the analyst will actually open makes the
// TTPs / cross-refs / sandbox findings discoverable.
function Triage({ result, rs }) {
  const lt = result?.log_translation;
  const hasLogs = !!(lt && !lt.error &&
    (Object.keys(lt.extracted_fields || {}).length || (lt.anomalies || []).length));
  const sup = result?.suppressed_iocs || {};
  const hasSup = Object.values(sup).reduce((n, a) => n + (a?.length || 0), 0) > 0;
  const hasOsint = hasOsintContent(result);

  const bi = result?.behavioral_indicators || {};
  const hasBehavior = !!((bi.total || 0) || (bi.decoded_payloads || []).length);
  const cr = rs?.cross_refs || {};
  const hasCross = !!((cr.kev || []).length || (cr.lolbas || []).length ||
    (rs?.atomic_examples || []).length || (cr.phishing_kits || []).length ||
    (cr.loldrivers || []).length || (cr.rmm_abuse || []).length ||
    (cr.suspicious_paths || []).length);
  // URL detonation gets its own top-of-Triage section whenever the
  // alert contained URLs — analysts want the URLScan verdict + screenshot
  // ahead of everything else.
  const hasUrlscan = !!(result?.iocs?.urls || []).length;
  const hasSandbox = Object.values(result?.enrichments?.hashes || {})
    .some(p => p?.sandbox_deep && p.sandbox_deep.process_tree);

  const recActions = (rs?.recommended_actions || [])
    .filter(a => typeof a === 'string' && a.trim() && !_AI_FALLBACK_ACTIONS.has(a.trim()));
  const hasRec = recActions.length > 0;
  const hasNotes = !!(rs?.analyst_notes || '').trim();

  if (!hasLogs && !hasSup && !hasOsint && !hasBehavior
      && !hasCross && !hasSandbox && !hasRec && !hasNotes
      && !hasUrlscan) return null;

  const Label = ({ children }) => (
    <Typography sx={{ fontSize: 11, fontWeight: 600, color: 'text.tertiary',
      textTransform: 'uppercase', letterSpacing: '0.06em', mb: 1.25 }}>{children}</Typography>
  );
  // `prevShown` tracks whether *any* section above has rendered, so the divider
  // is correctly drawn (or omitted) without a manual cascade for each section.
  let prevShown = false;
  const divSx = () => ({ mt: prevShown ? 2 : 0, pt: prevShown ? 2 : 0,
    borderTop: prevShown ? `1px solid ${muiAlpha('#ffffff', 0.08)}` : 'none' });
  const Section = ({ show, label, children }) => {
    if (!show) return null;
    const sx = divSx();
    prevShown = true;
    return <Box sx={sx}><Label>{label}</Label>{children}</Box>;
  };

  // Section order mirrors a SOC/MDR analyst's mental walkthrough:
  //  1. Normalise the raw log so the rest of the card has a shared baseline.
  //  2. Did anything immediately match known-bad? (KEV / LOLBAS / kits)
  //  3. What tradecraft is in play? + how to defend (TTPs + D3FEND).
  //  4. Runtime behaviour if we have it (sandbox process tree).
  //  5. Infrastructure context (OSINT — BGP, DNS, VT graph).
  //  6. What did the FP filter strip? (MISP — audit trail, lowest urgency).
  //  7. What to do next (AI recommended actions).
  //  8. Senior-analyst context paragraph (analyst notes).
  return (
    <Card title="Triage" accent="#0fbcff" defaultOpen={false}>
      {/* URL detonation ALWAYS sits at the top of Triage when the alert
          contained URLs — analysts want the URLScan verdict + screenshot
          before anything else. Hidden if no URLs were extracted. */}
      <Section show={hasUrlscan}  label="Live URL detonation · URLScan.io">
        <URLScanLive result={result} bare/></Section>
      <Section show={hasLogs}     label="Log normalization">
        <LogTranslation result={result} bare/></Section>
      <Section show={hasCross}    label="Threat-intel cross-references">
        <CrossRefs rs={rs} bare/></Section>
      <Section show={hasSandbox}  label="Sandbox detonation · process tree">
        <SandboxBehavioral result={result} bare/></Section>
      <Section show={hasOsint} label="OSINT">
        <InfrastructureIntel result={result} bare hideUrlscan/></Section>
      <Section show={hasSup}      label="Filtered as benign · MISP warninglists">
        <SuppressedIOCs result={result} bare/></Section>
      <Section show={hasRec}      label="Recommended actions">
        <RecommendedActions rs={rs} bare/></Section>
      <Section show={hasNotes}    label="Analyst notes">
        <AnalystNotes rs={rs} bare/></Section>
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

  // Helper — build a one-line "context tail" with WHOIS + hosting info
  // we have for a domain so the banner text quotes the same data the
  // analyst would otherwise have to dig for in the per-domain card.
  const _domainContext = (d) => {
    const bits = [];
    const w = d?.whois;
    if (w && !w.error) {
      if (w.registrar) bits.push(`registrar ${w.registrar}`);
      if (w.registrant_country) bits.push(w.registrant_country);
    }
    // ASN of the A-record IP — flag Cloudflare / known abused hosters
    // explicitly. Falls back to the generic ASN description when not
    // recognised. Looks at the first A record returned by dns_records.
    const aRecords = d?.osint?.dns_records?.records?.A || [];
    const firstIp = aRecords[0] || '';
    if (firstIp) {
      const ipInfo = (result?.enrichments?.ips || {})[firstIp];
      const asnDesc = (ipInfo?.bgp_ranking?.asn_description
                   || ipInfo?.ipinfo?.org || '').toString();
      const knownAbused = /cloudflare|namecheap|porkbun|hostinger|fastly|akamai|hetzner|digitalocean|vultr|linode/i;
      if (knownAbused.test(asnDesc)) {
        const provider = asnDesc.match(knownAbused)[0].toLowerCase();
        bits.push(`hosted on ${provider} (${firstIp})`);
      } else if (asnDesc) {
        bits.push(`hosted on ${asnDesc.slice(0, 40)} (${firstIp})`);
      } else {
        bits.push(`resolves to ${firstIp}`);
      }
    }
    return bits.length ? ` · ${bits.join(' · ')}` : '';
  };

  // Recently-registered domains, three tiers by age
  for (const [domain, d] of Object.entries(enr.domains || {})) {
    const nrd = d?.heuristics?.nrd;
    const ctx = _domainContext(d);
    if (nrd?.is_same_day) {
      banners.push({
        kind: 'critical',
        title: 'Domain registered TODAY',
        text:  `${domain} was registered ${nrd.age_hours}h ago (${nrd.created})${ctx}. This is a high-confidence phishing signal — legitimate businesses don't operate from same-day domains.`,
      });
    } else if (nrd?.is_this_week) {
      banners.push({
        kind: 'high',
        title: 'Domain registered this week',
        text:  `${domain} is ${nrd.age_days} days old (${nrd.created})${ctx}. New domains under one week are common in active phishing campaigns.`,
      });
    } else if (nrd?.is_nrd && nrd?.age_days != null && nrd.age_days < 30) {
      // 7–29 days — still flag, slightly lower urgency. CDN-fronted
      // newly-registered domains are a textbook clickfix / phishing
      // pattern (mentioned by analyst feedback).
      banners.push({
        kind: 'medium',
        title: 'Newly-registered domain',
        text:  `${domain} is ${nrd.age_days} days old (${nrd.created})${ctx}. NRDs under 30 days are commonly used for short-lived phishing pages, especially when fronted by a CDN.`,
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
        const color = b.kind === 'critical' ? '#F14337'
                    : b.kind === 'medium'   ? '#E1B823'
                    :                          '#E6700F';
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

// Thin wrapper for MuiBlock (renders an MUI Box with subtle border + tertiary
// label) used by several cards for in-card grouping.
const Block = ({ title, children }) => (
  <MuiBlock title={title}>
    <Box component="ul" sx={{ margin:0, padding:0, listStyle:'none' }}>{children}</Box>
  </MuiBlock>
);

// Per-IOC threat-score tier metadata. Brackets are the same as the legacy
// GTI card so nothing shifts category, just rendered more prominently.
const SCORE_TIERS = [
  { min: 85, name: 'CRITICAL',   color: '#EE3838' },
  { min: 65, name: 'HIGH',       color: '#E6700F' },
  { min: 45, name: 'ELEVATED',   color: '#E1B823' },
  { min: 25, name: 'SUSPICIOUS', color: '#F59E0B' },
  { min: 0,  name: 'CLEAN',      color: '#16AD34' },
];
const tierFor = (score) =>
  SCORE_TIERS.find(t => (score || 0) >= t.min) || SCORE_TIERS[SCORE_TIERS.length - 1];

// Threat-score block — one prominent dial showing the worst-scoring indicator,
// a tier chip below it, a per-tier distribution mini-chart so the analyst sees
// at a glance "one bad IOC vs a pattern", and a compact per-IOC list sorted
// by score. Rendered inside the Summary card.
function ThreatScore({ result }) {
  const gti = result?.gti_scores || {};
  const sorted = Object.entries(gti).sort(([,a],[,b]) => (b.score || 0) - (a.score || 0));
  if (!sorted.length) return null;

  const top = sorted[0][1];
  const topTier = tierFor(top.score);
  const dist = { CRITICAL: 0, HIGH: 0, ELEVATED: 0, SUSPICIOUS: 0, CLEAN: 0 };
  sorted.forEach(([,d]) => { dist[tierFor(d.score).name] += 1; });
  const maxBar = Math.max(1, ...Object.values(dist));

  return (
    <>
      <Block title={`Threat score · ${sorted.length} indicators scored`}>
        <Box sx={{
          display: 'grid', gap: 2.5, alignItems: 'center',
          gridTemplateColumns: { xs: '1fr', md: 'auto 1fr' },
          py: 0.5,
        }}>
          {/* Big dial + tier label */}
          <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 1 }}>
            <Dial score={top.score} color={topTier.color} size={120}/>
            <Box sx={{
              px: 1.25, py: 0.25, borderRadius: '3px',
              backgroundColor: muiAlpha(topTier.color, 0.18),
              border: `1px solid ${muiAlpha(topTier.color, 0.4)}`,
              fontSize: 11, fontWeight: 700, color: topTier.color,
              letterSpacing: '0.1em', fontFamily: '"IBM Plex Mono", monospace',
            }}>
              {topTier.name}
            </Box>
            <Typography sx={{ fontSize: 10, color: 'text.disabled',
              textTransform: 'uppercase', letterSpacing: '0.06em' }}>
              worst indicator
            </Typography>
          </Box>

          {/* Distribution bars + top-IOC reference */}
          <Box>
            <Typography sx={{ fontSize: 10, color: 'text.disabled',
              textTransform: 'uppercase', letterSpacing: '0.06em', mb: 0.75 }}>
              Tier distribution
            </Typography>
            {SCORE_TIERS.map(tr => (
              <Box key={tr.name} sx={{
                display: 'grid', gridTemplateColumns: '90px 1fr 24px',
                gap: 1.25, alignItems: 'center', mb: 0.5,
              }}>
                <Typography sx={{ fontSize: 11, color: dist[tr.name] > 0 ? tr.color : 'text.disabled',
                  fontWeight: dist[tr.name] > 0 ? 600 : 400 }}>
                  {tr.name.charAt(0) + tr.name.slice(1).toLowerCase()}
                </Typography>
                <Box sx={{
                  height: 6, borderRadius: 99, backgroundColor: 'background.secondary',
                  overflow: 'hidden',
                }}>
                  {dist[tr.name] > 0 && (
                    <Box sx={{
                      width: `${(dist[tr.name] / maxBar) * 100}%`,
                      height: '100%', backgroundColor: tr.color, borderRadius: 99,
                      transition: 'width .35s',
                    }}/>
                  )}
                </Box>
                <Typography sx={{
                  fontSize: 11, fontWeight: 600,
                  color: dist[tr.name] > 0 ? tr.color : 'text.disabled',
                  textAlign: 'right', fontVariantNumeric: 'tabular-nums',
                }}>{dist[tr.name]}</Typography>
              </Box>
            ))}
            <Box sx={{ mt: 1.5, pt: 1, borderTop: `1px solid ${muiAlpha('#ffffff', 0.06)}` }}>
              <Typography sx={{ fontSize: 11, color: 'text.tertiary', mb: 0.25 }}>
                Highest-scoring indicator
              </Typography>
              <Typography sx={{ fontSize: 13, color: topTier.color, fontWeight: 600,
                fontFamily: '"IBM Plex Mono", monospace', wordBreak: 'break-all' }}>
                {top.label}
              </Typography>
            </Box>
          </Box>
        </Box>
      </Block>

      {/* Per-indicator list — click a row to expand the per-source breakdown
          so the analyst sees WHICH TI source said what (VirusTotal ratio,
          AbuseIPDB abuse %, Maltiverse classification + tags, GreyNoise
          classification, OTX pulses, etc.) without leaving the Summary. */}
      <Block title="Per-indicator score · click to expand sources">
        <PerIndicatorList sorted={sorted} result={result}/>
      </Block>
    </>
  );
}

// Compact source-verdict row for the expanded view. One per TI source that
// said something useful about this IOC. When sourceUrls.js knows a deep
// link for (source, ioc, iocType), the source label becomes a clickable
// anchor that opens the source's web UI prefilled with the indicator.
function SourceVerdict({ source, label, color = '#0fbcff', ioc, iocType }) {
  const href = sourceUrl(source, ioc, iocType);
  const labelEl = href ? (
    <Box
      component="a"
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      title={`Open ${source} for ${ioc}`}
      sx={{
        display: 'inline-flex', alignItems: 'center', gap: 0.375,
        fontSize: 10, fontWeight: 600,
        color: 'primary.main',
        textTransform: 'uppercase', letterSpacing: '0.06em',
        textDecoration: 'none', cursor: 'pointer',
        transition: 'color 0.15s ease',
        // Show the link affordance only on the row's hover — keeps the
        // resting state clean, makes the icon a directional cue when the
        // analyst is scanning.
        '& .recon-src-arrow': {
          opacity: 0, transform: 'translate(-2px, 1px)',
          transition: 'opacity 0.15s ease, transform 0.15s ease',
        },
        '&:hover': {
          color: 'primary.light',
          textDecoration: 'underline',
          '& .recon-src-arrow': { opacity: 1, transform: 'translate(0, 1px)' },
        },
      }}
    >
      {source}
      <ArrowUpRight className="recon-src-arrow" size={10}/>
    </Box>
  ) : (
    <Typography sx={{
      fontSize: 10, color: 'text.tertiary',
      textTransform: 'uppercase', letterSpacing: '0.06em',
      fontWeight: 600,
    }}>
      {source}
    </Typography>
  );
  return (
    <Box sx={{
      display: 'grid', gridTemplateColumns: '100px 1fr',
      gap: 1, py: 0.5, alignItems: 'baseline',
      borderRadius: '3px',
      px: 0.5, mx: -0.5,
      transition: 'background-color 0.12s ease',
      '&:hover': { backgroundColor: muiAlpha('#ffffff', 0.025) },
    }}>
      {labelEl}
      <Typography sx={{
        fontSize: 11, color, lineHeight: 1.5,
        fontFamily: '"IBM Plex Mono", monospace',
        // break-word respects word boundaries for natural prose (OTX pulse
        // names, AI summaries) but still breaks long unbroken tokens
        // (hashes, URLs) when they don't fit the column.
        wordBreak: 'break-word',
        overflowWrap: 'anywhere',
      }}>
        {label}
      </Typography>
    </Box>
  );
}

// Pull a normalized list of {source, label, color} entries from the
// per-IOC enrichment payload. Each TI source that returned something
// useful contributes one row; sources that errored or had nothing to
// say are skipped. The label is what the analyst reads at a glance.
function _ocSources(result, ioc, type) {
  const enr = result?.enrichments || {};
  // Backend emits ioc_type as 'ip' | 'domain' | 'url' | 'file' (file for
  // hashes — historical name). The enrichment buckets are plural; map
  // each ioc_type to its bucket. Falls through to a no-op for unknown
  // types so the row stays clickable-but-empty rather than crashing.
  const bucket =
      type === 'ip'     ? enr.ips
    : type === 'domain' ? enr.domains
    : type === 'hash'   ? enr.hashes
    : type === 'file'   ? enr.hashes
    : type === 'url'    ? enr.urls
    : type === 'email'  ? enr.emails
    : type === 'cve'    ? enr.cves
    : null;
  const d = bucket?.[ioc] || {};
  const out = [];
  const red = '#EE3838', orange = '#E6700F', yellow = '#E1B823',
        green = '#16AD34', cyan = '#0fbcff', tert = '#848592';

  // VirusTotal — show ratio + popular family/name when available.
  if (d.virustotal && !d.virustotal.error) {
    const v = d.virustotal;
    const mal = v.malicious ?? 0;
    const susp = v.suspicious ?? 0;
    const total = (v.harmless ?? 0) + (v.undetected ?? 0) + mal + susp;
    const flagged = mal + susp;
    if (total) {
      const c = mal >= 5 ? red : mal >= 1 ? orange : susp >= 3 ? yellow : green;
      const extra = v.name ? ` · ${v.name}` : v.popular_family ? ` · ${v.popular_family}` : '';
      out.push({ source: 'VirusTotal', label: `${flagged}/${total} flagged${extra}`, color: c });
    } else if (v.reputation != null) {
      out.push({ source: 'VirusTotal', label: `reputation ${v.reputation}`,
                 color: v.reputation < 0 ? orange : tert });
    }
  }

  // AbuseIPDB — abuse confidence %.
  if (d.abuseipdb && !d.abuseipdb.error) {
    const a = d.abuseipdb;
    const score = a.abuseScore ?? a.abuse_confidence ?? null;
    if (score != null) {
      const c = score >= 75 ? red : score >= 25 ? orange : score > 0 ? yellow : green;
      const reports = a.totalReports ? ` · ${a.totalReports} reports` : '';
      out.push({ source: 'AbuseIPDB', label: `${score}% confidence${reports}`, color: c });
    }
  }

  // MISP feeds — community-curated hash matches (CIRCL OSINT / DigitalSide /
  // Botvrij). A hit here means the hash is in a published MISP event, which
  // is high-signal corroborating evidence.
  if (d.misp_feeds && d.misp_feeds.matched_feeds?.length > 0) {
    const feeds = d.misp_feeds.matched_feeds.slice(0, 3).join(', ');
    out.push({ source: 'MISP Feeds',
               label: `matched in ${feeds}`, color: red });
  }

  // OTX — pulse count + a top pulse name when present. Even when the
  // count is 0 we still emit a row so the analyst sees that OTX WAS
  // queried and confirmed no community attribution; without this, the
  // common case (no hits) makes OTX silently disappear from the source
  // list and people think the integration is broken.
  if (d.otx && !d.otx.error) {
    const pulses = d.otx.pulseCount ?? d.otx.pulse_count ?? 0;
    if (pulses > 0) {
      const top = (d.otx.relatedPulses || d.otx.pulses || [])[0];
      // Cap the pulse-name suffix at 140 chars and cut at the nearest word
      // boundary so it never truncates mid-word ('… Enemy of the State: Order
      // in the C' was the analyst complaint). The container wraps to a second
      // line so 140 still fits cleanly.
      const _trunc = (s, max) => {
        if (!s || s.length <= max) return s || '';
        const cut = s.slice(0, max);
        const sp  = cut.lastIndexOf(' ');
        return (sp > max * 0.6 ? cut.slice(0, sp) : cut) + '…';
      };
      const topStr = top ? _trunc(String(top), 140) : '';
      out.push({ source: 'OTX',
                 label: `${pulses} pulse${pulses === 1 ? '' : 's'}${topStr ? ` · ${topStr}` : ''}`,
                 color: pulses >= 5 ? red : pulses >= 1 ? orange : tert });
    } else {
      out.push({ source: 'OTX',
                 label: 'no community pulses for this indicator',
                 color: tert });
    }
  }

  // GreyNoise — classification.
  if (d.greynoise && !d.greynoise.error) {
    const g = d.greynoise;
    const cls = g.classification || g.label || (g.is_known_good ? 'benign' : '');
    if (cls) {
      const c = /malicious/i.test(cls) ? red
              : /benign|known/i.test(cls) ? green
              : /suspicious/i.test(cls) ? orange : tert;
      const extra = g.name ? ` · ${g.name}` : '';
      out.push({ source: 'GreyNoise', label: `${cls}${extra}`, color: c });
    }
  }

  // Maltiverse — classification + tags.
  if (d.maltiverse && !d.maltiverse.error) {
    const m = d.maltiverse;
    const cls = m.classification || '';
    if (cls && cls !== 'neutral') {
      const c = /malicious/i.test(cls) ? red
              : /suspicious/i.test(cls) ? orange
              : /benign/i.test(cls) ? green : tert;
      const tags = (m.tag || []).slice(0, 3).join(', ');
      out.push({ source: 'Maltiverse', label: `${cls}${tags ? ` · ${tags}` : ''}`, color: c });
    }
  }

  // ThreatFox — malware family + first seen.
  if (d.threatfox && !d.threatfox.error) {
    const t = d.threatfox;
    const malware = t.malware || t.malware_alias || '';
    if (malware) {
      const seen = t.first_seen ? ` · first seen ${String(t.first_seen).slice(0,10)}` : '';
      out.push({ source: 'ThreatFox', label: `${malware}${seen}`, color: red });
    }
  }

  // MalwareBazaar — file-family lookup (hashes).
  if (d.malwarebazaar && !d.malwarebazaar.error) {
    const mb = d.malwarebazaar;
    const family = mb.malwareName || mb.signature || mb.malware_family || '';
    if (family) out.push({ source: 'MalwareBazaar', label: family, color: red });
  }

  // URLScan — verdict + first scan.
  if (d.urlscan && !d.urlscan.error) {
    const u = d.urlscan;
    const verdict = u.verdict || u.score_verdict || '';
    if (verdict) {
      const c = /malicious/i.test(verdict) ? red
              : /suspicious/i.test(verdict) ? orange
              : /benign|safe/i.test(verdict) ? green : tert;
      out.push({ source: 'URLScan.io', label: verdict, color: c });
    }
  }

  // Pulsedive — risk level.
  if (d.pulsedive && !d.pulsedive.error) {
    const p = d.pulsedive;
    const risk = p.risk || p.score_label || '';
    if (risk && risk !== 'none') {
      const c = /critical|high/i.test(risk) ? red
              : /medium|moderate/i.test(risk) ? orange
              : /low/i.test(risk) ? yellow : tert;
      out.push({ source: 'Pulsedive', label: `risk ${risk}`, color: c });
    }
  }

  // Spamhaus DBL — domain blocklist.
  if (d.spamhaus_dbl?.hit) {
    out.push({ source: 'Spamhaus DBL', label: `${d.spamhaus_dbl.verdict || 'listed'}${d.spamhaus_dbl.code ? ` · ${d.spamhaus_dbl.code}` : ''}`, color: red });
  }

  // Criminal IP — inbound/outbound threat scoring.
  if (d.criminal_ip && !d.criminal_ip.error) {
    const cip = d.criminal_ip;
    const inb = cip.inbound_score, outb = cip.outbound_score;
    if (inb || outb) {
      const worst = [inb, outb].find(s => s === 'critical' || s === 'dangerous')
                 || [inb, outb].find(s => s === 'moderate')
                 || inb || outb;
      const c = /critical|dangerous/i.test(worst) ? red
              : /moderate/i.test(worst)           ? orange
              : /low/i.test(worst)                ? yellow
              : /safe/i.test(worst)               ? green : tert;
      const flags = [];
      if (cip.is_tor) flags.push('TOR');
      if (cip.is_vpn || cip.is_anonymous_vpn) flags.push('VPN');
      if (cip.is_proxy) flags.push('proxy');
      if (cip.is_scanner) flags.push('scanner');
      out.push({
        source: 'Criminal IP',
        label: `inbound ${inb || '?'} · outbound ${outb || '?'}${flags.length ? ` · ${flags.join(', ')}` : ''}`,
        color: c,
      });
    }
  }

  // URLhaus URL hit — abuse.ch malware-distribution database.
  if (d.urlhaus_url && !d.urlhaus_url.error) {
    const u = d.urlhaus_url;
    out.push({
      source: 'URLhaus',
      label: `${u.threat || 'malware-distribution'}${u.url_status ? ` · ${u.url_status}` : ''}`,
      color: red,
    });
  }

  // URLhaus payload hit — same database, payload (hash) endpoint.
  if (d.urlhaus_payload && !d.urlhaus_payload.error) {
    const u = d.urlhaus_payload;
    out.push({
      source: 'URLhaus payload',
      label: `${u.signature || 'malware'}${u.url_count ? ` · ${u.url_count} URLs` : ''}`,
      color: red,
    });
  }

  // CIRCL hashlookup — known-good (NIST NSRL) file detection.
  if (d.circl_hashlookup && !d.circl_hashlookup.error) {
    const h = d.circl_hashlookup;
    if (h.verdict === 'CLEAN') {
      out.push({
        source: 'CIRCL hashlookup',
        label: `known-good${h.ProductName ? ` · ${h.ProductName}` : ''}${h.FileName ? ` · ${h.FileName}` : ''}`,
        color: green,
      });
    } else if (h.trust != null) {
      out.push({
        source: 'CIRCL hashlookup',
        label: `trust ${h.trust}${h.FileName ? ` · ${h.FileName}` : ''}`,
        color: tert,
      });
    }
  }

  // NVD CVE — score + severity + description summary.
  if (d.nvd && !d.nvd.error && d.nvd.found) {
    const n = d.nvd;
    const score = n.cvss_v3_score;
    const sev = (n.cvss_v3_severity || '').toUpperCase();
    const c = sev === 'CRITICAL' ? red
            : sev === 'HIGH'     ? orange
            : sev === 'MEDIUM'   ? yellow
            :                       tert;
    out.push({
      source: 'NVD',
      label: `CVSS ${score ?? '?'} ${sev || 'unrated'}${n.affected_products?.length ? ` · ${n.affected_products.slice(0,2).join(', ')}` : ''}`,
      color: c,
    });
  }

  // EPSS — exploitation probability percentile.
  if (d.epss && !d.epss.error && d.epss.found) {
    const e = d.epss;
    const c = e.score >= 0.7 ? red
            : e.score >= 0.1 ? orange
            :                   tert;
    out.push({
      source: 'EPSS',
      label: `${e.score_pct ?? 0}% probability · ${e.percentile_pct ?? 0} percentile`,
      color: c,
    });
  }

  // CISA KEV — actively exploited check.
  if (d.cisa_kev && !d.cisa_kev.error) {
    const k = d.cisa_kev;
    if (k.in_kev) {
      out.push({
        source: 'CISA KEV',
        label: `ACTIVELY EXPLOITED · added ${k.date_added || '?'}${k.ransomware_use ? ' · ransomware use' : ''}`,
        color: red,
      });
    } else {
      out.push({
        source: 'CISA KEV',
        label: 'not in KEV catalog',
        color: green,
      });
    }
  }

  // URLScan screenshot — prior public scan for this URL.
  if (d.urlscan_screenshot && !d.urlscan_screenshot.error
      && d.urlscan_screenshot.found) {
    const u = d.urlscan_screenshot;
    const c = u.malicious ? red : u.score >= 50 ? orange : cyan;
    const dateStr = u.scan_date ? ` · scanned ${String(u.scan_date).slice(0, 10)}` : '';
    out.push({
      source: 'URLScan screenshot',
      label: `${u.malicious ? 'malicious' : 'archived scan'}${dateStr}`,
      color: c,
    });
  }

  // WHOIS — registrar + age + registrant. Domain age is the single
  // strongest FP-vs-real signal: < 30 d is highly suspicious, < 1 d is
  // near-certain phishing/C2 staging. Show it color-coded by age band.
  if (d.whois && typeof d.whois === 'object' && !d.whois.error) {
    const w = d.whois;
    const bits = [];
    if (w.registrar) bits.push(w.registrar);
    if (w.age_days != null) bits.push(`${w.age_days}d old`);
    if (w.registrant_org) bits.push(w.registrant_org);
    else if (w.registrant_country) bits.push(w.registrant_country);
    if (w.privacy_protected) bits.push('privacy protected');
    if (bits.length) {
      const age = w.age_days;
      const c = age == null ? tert
              : age < 1   ? red
              : age < 30  ? orange
              : age < 180 ? yellow
              :             green;
      out.push({ source: 'WHOIS', label: bits.join(' · '), color: c });
    }
  }

  // ─── SOURCE STATUS PASS ────────────────────────────────────────────────
  // The blocks above only push a row when a source returned USEFUL data
  // (no error AND non-empty). That meant a source which returned an
  // error (auth failure, rate limit, circuit-breaker-open, timeout) was
  // silently hidden — the analyst couldn't tell whether the source ran
  // and said clean, vs ran and got blocked, vs never ran at all. The
  // complaint that triggered this: an IP with 100% AbuseIPDB confidence
  // didn't show because the AbuseIPDB call had errored out and the
  // frontend hid the failure rather than surfacing it.
  //
  // This pass walks every source key on the enrichment dict and appends
  // a dim status row for any source that errored (so the analyst knows
  // to retry or check their API key configuration).
  const _sourceLabels = {
    virustotal: 'VirusTotal',          abuseipdb: 'AbuseIPDB',
    otx: 'OTX',                         greynoise: 'GreyNoise',
    maltiverse: 'Maltiverse',           threatfox: 'ThreatFox',
    malwarebazaar: 'MalwareBazaar',     urlscan: 'URLScan.io',
    pulsedive: 'Pulsedive',             spamhaus_dbl: 'Spamhaus DBL',
    criminal_ip: 'Criminal IP',         urlhaus_url: 'URLhaus',
    urlhaus_payload: 'URLhaus payload', circl_hashlookup: 'CIRCL hashlookup',
    nvd: 'NVD',                          epss: 'EPSS',
    hybrid_analysis: 'Hybrid Analysis',
    whois: 'WHOIS',                      ipinfo: 'IPInfo',
    censys: 'Censys',                    crowdsec: 'CrowdSec',
    feodo_tracker: 'Feodo Tracker',
    misp_feeds: 'MISP Feeds',
  };
  const _surfaced = new Set(out.map(r => r.source));
  for (const [key, blob] of Object.entries(d || {})) {
    const label = _sourceLabels[key];
    if (!label || _surfaced.has(label)) continue;
    if (!blob || typeof blob !== 'object') continue;
    const err = blob.error;
    if (!err) continue;
    // Sources that simply aren't configured shouldn't pretend they
    // failed — skip them entirely so the per-IOC panel only shows
    // sources that ACTUALLY attempted to run.
    if (blob.error_type === 'not_configured') continue;
    // Translate the remaining error_type values to readable phrasing
    let status;
    if (blob.error_type === 'circuit_open') {
      status = `temporarily skipped (recent failures opened the breaker — retry in a few minutes)`;
    } else if (blob.error_type === 'auth_failed') {
      status = `couldn't authenticate — verify the ${label} API key in data/config.json`;
    } else if (blob.error_type === 'rate_limited') {
      status = `rate-limited (HTTP 429) — daily quota or burst limit reached`;
    } else if (blob.error_type === 'timed_out') {
      status = `request timed out — source may be slow or unreachable`;
    } else if (blob.error_type === 'http_error') {
      status = `source returned an HTTP error — ${String(err).slice(0, 100)}`;
    } else if (typeof err === 'string' && err.toLowerCase() === 'no data') {
      status = `no data returned for this indicator`;
    } else {
      status = `unavailable — ${String(err).slice(0, 100)}`;
    }
    out.push({ source: label, label: status, color: tert });
  }

  return out;
}

function PerIndicatorList({ sorted, result }) {
  const [openIoc, setOpenIoc] = useState(null);
  return sorted.map(([ioc, d], i) => {
    const tr = tierFor(d.score);
    // Backend field is `ioc_type`; tolerate `type` as a fallback for any
    // older runs cached in memory before this commit.
    const iocType = d.ioc_type || d.type;
    const sources = _ocSources(result, ioc, iocType);
    // Inline breach + screenshot summaries — surfaced PROMINENTLY in the
    // row (not buried behind the expand toggle) since both directly
    // influence threat-level reasoning.
    const enrBucket =
        iocType === 'ip'     ? result?.enrichments?.ips
      : iocType === 'domain' ? result?.enrichments?.domains
      : iocType === 'url'    ? result?.enrichments?.urls
      : iocType === 'email'  ? result?.enrichments?.emails
      :                         null;
    const enrData = enrBucket?.[ioc] || {};
    const urlScreenshot = enrData?.urlscan_screenshot;
    const expandable = sources.length > 0
                       || (d.contributing_factors || []).length > 1
                       || (urlScreenshot && urlScreenshot.found);
    const open = openIoc === ioc;
    return (
      <Box key={ioc} sx={{
        borderTop: i > 0 ? `1px solid ${muiAlpha('#ffffff', 0.06)}` : 'none',
      }}>
        <Box
          onClick={() => expandable && setOpenIoc(open ? null : ioc)}
          sx={{
            display: 'flex', gap: 1.5, alignItems: 'center', py: 0.875,
            cursor: expandable ? 'pointer' : 'default',
            transition: 'background-color .14s ease',
            // Slightly more pronounced hover when the row is expandable, and a
            // persistent tint while open so the analyst always knows which
            // indicator they're inspecting in a long list.
            backgroundColor: open ? muiAlpha('#ffffff', 0.025) : 'transparent',
            '&:hover': expandable
              ? { backgroundColor: open
                    ? muiAlpha('#ffffff', 0.03)
                    : muiAlpha('#ffffff', 0.022) }
              : undefined,
          }}
        >
          <Dial score={d.score} color={tr.color} size={38}/>
          <Box sx={{ flex: 1, minWidth: 0 }}>
            <Typography sx={{
              fontSize: 12, color: 'text.primary',
              fontFamily: '"IBM Plex Mono", monospace',
              wordBreak: 'break-all', mb: 0.25,
            }}>
              {ioc.length > 58 ? ioc.slice(0, 55) + '…' : ioc}
            </Typography>
            {d.contributing_factors?.[0] && (
              <Typography sx={{ fontSize: 11, color: 'text.tertiary' }}>
                {d.contributing_factors[0]}
                {expandable && !open && (
                  <Box component="span" sx={{ color: 'primary.main', ml: 0.75, fontSize: 10 }}>
                    · {sources.length} source{sources.length === 1 ? '' : 's'}
                  </Box>
                )}
              </Typography>
            )}
          </Box>
          <Verdict verdict={d.verdict} size="small"/>
          {expandable && (
            <Box sx={{
              color: 'text.tertiary',
              display: 'flex', alignItems: 'center',
              transition: 'transform 0.18s ease, color 0.18s ease',
              transform: open ? 'rotate(90deg)' : 'rotate(0deg)',
              ...(open && { color: 'primary.main' }),
            }}>
              <ChevronRight size={14}/>
            </Box>
          )}
        </Box>

        {open && (
          <Box sx={{
            ml: '54px', mb: 1, mr: 1, p: '10px 14px',
            backgroundColor: muiAlpha('#ffffff', 0.025),
            border: `1px solid ${muiAlpha('#ffffff', 0.08)}`,
            borderLeft: `2px solid ${muiAlpha(tr.color || '#0fbcff', 0.4)}`,
            borderRadius: '4px',
          }}>
            {sources.length > 0 ? (
              sources.map((s, j) => (
                <SourceVerdict key={j} source={s.source} label={s.label} color={s.color}
                  ioc={ioc} iocType={iocType}/>
              ))
            ) : (
              <Typography sx={{ fontSize: 11, color: 'text.tertiary', fontStyle: 'italic' }}>
                No source-level enrichment data available for this indicator.
              </Typography>
            )}
            {/* URLScan screenshot — embed the thumbnail inline so the analyst
                sees what the page looks like without visiting it. The link
                opens the full scan in a new tab. */}
            {urlScreenshot?.found && urlScreenshot?.screenshot_url && (
              <Box sx={{
                mt: 1.25, pt: 1,
                borderTop: `1px solid ${muiAlpha('#ffffff', 0.06)}`,
              }}>
                <Stack direction="row" alignItems="center" spacing={1} sx={{ mb: 0.75 }}>
                  <Typography sx={{
                    fontSize: 10, color: 'text.disabled',
                    textTransform: 'uppercase', letterSpacing: '0.06em',
                  }}>
                    URLScan archive
                  </Typography>
                  {urlScreenshot.scan_url && (
                    <Typography
                      component="a"
                      href={urlScreenshot.scan_url}
                      target="_blank"
                      rel="noopener noreferrer"
                      sx={{ fontSize: 10, color: 'primary.main', textDecoration: 'none',
                        '&:hover': { textDecoration: 'underline' } }}>
                      open full scan ↗
                    </Typography>
                  )}
                </Stack>
                <Box
                  component="a"
                  href={urlScreenshot.scan_url || urlScreenshot.screenshot_url}
                  target="_blank"
                  rel="noopener noreferrer"
                  sx={{
                    display: 'block',
                    border: `1px solid ${muiAlpha('#ffffff', 0.1)}`,
                    borderRadius: 1, overflow: 'hidden',
                    backgroundColor: '#070d19',
                    maxWidth: 480,
                  }}>
                  <Box component="img"
                    src={urlScreenshot.screenshot_url}
                    alt={`Screenshot of ${ioc}`}
                    loading="lazy"
                    onError={(e) => { e.currentTarget.style.display = 'none'; }}
                    sx={{
                      display: 'block', width: '100%', height: 'auto',
                      maxHeight: 320,
                    }}/>
                </Box>
              </Box>
            )}
            {(d.contributing_factors || []).length > 1 && (
              <Box sx={{
                mt: 1.25, pt: 1,
                borderTop: `1px solid ${muiAlpha('#ffffff', 0.06)}`,
              }}>
                <Typography sx={{
                  fontSize: 10, color: 'text.disabled',
                  textTransform: 'uppercase', letterSpacing: '0.06em', mb: 0.5,
                }}>
                  All contributing factors
                </Typography>
                {d.contributing_factors.map((f, j) => (
                  <Typography key={j} sx={{ fontSize: 11, color: 'text.tertiary',
                    lineHeight: 1.5, py: 0.125 }}>
                    · {f}
                  </Typography>
                ))}
              </Box>
            )}
          </Box>
        )}
      </Box>
    );
  });
}

// Attribution chip — when the response agent matched threat-actor TTPs, show
// the canonical Microsoft name with origin + every alias the analyst might
// see in vendor reports (CrowdStrike/FireEye/MITRE/Microsoft). Aliases hide
// behind a click so the chip stays compact when there are 12 of them.
function AttributionChip({ actor }) {
  // All hooks must run before any early return. Keep state + effect at
  // the top so hook order stays consistent across renders.
  const [activeTab, setActiveTab]   = useState(null);
  // MalwareBazaar hashes per malware-typed software, fetched lazily when
  // the Hunt-for tab is opened. Keyed by family name. Each value is
  // either {loading: true}, {error: '...'}, or {hashes: [...]}.
  const [mbHashes, setMbHashes]     = useState({});

  const display = actor?.ms_name || actor?.name || '';
  const aliases = ((actor && actor.aliases) || []).filter(a => a && a !== display);
  const evByTech = Array.isArray(actor?.evidence_by_technique)
    ? actor.evidence_by_technique : [];
  const evidenceCount = evByTech.reduce((n, t) => n + (t.evidence?.length || 0), 0);
  const hasEvidence = evidenceCount > 0;
  const huntTtps = (actor && actor.ttps_to_look_for) || {};
  const huntBefore = Array.isArray(huntTtps.before) ? huntTtps.before : [];
  const huntAfter  = Array.isArray(huntTtps.after)  ? huntTtps.after  : [];
  const huntProcs  = Array.isArray(huntTtps.process_names) ? huntTtps.process_names : [];
  const huntSw     = Array.isArray(huntTtps.software)      ? huntTtps.software      : [];
  const hasHunt    = huntBefore.length + huntAfter.length + huntProcs.length + huntSw.length > 0;

  // Tab model — one tab visible at a time so the chip never sprawls.
  const tabs = [
    hasEvidence && { id: 'evidence', label: `Log evidence · ${evidenceCount}` },
    hasHunt     && { id: 'hunt',     label: 'Hunt for' },
    aliases.length > 0
                 && { id: 'aliases',  label: `Aliases · ${aliases.length}` },
  ].filter(Boolean);
  const showEvidence = activeTab === 'evidence';
  const showHunt     = activeTab === 'hunt';
  const showAliases  = activeTab === 'aliases';

  // Strip MITRE-style markdown links + Citation footnotes so the
  // "how they attack" narrative renders as clean prose.
  const cleanProse = (s) => (s || '')
    .replace(/\[([^\]]+)\]\([^)]+\)/g, '$1')
    .replace(/\(Citation:\s*[^)]+\)/g, '')
    .replace(/\s+/g, ' ')
    .trim();
  const playbook = cleanProse(actor?.description || '');

  // Malware-typed software entries — these are the rows we want hash
  // pivots for. Filenames that look like Windows-native binaries get
  // skipped per analyst request (no Ping.exe / net.exe / tasklist.exe
  // hash pulls because those aren't worth a MalwareBazaar query).
  const _NATIVE_WIN_BIN = /^(?:ping|net1?|netstat|nslookup|tasklist|cmd|powershell|pwsh|wmic|cscript|wscript|certutil|bitsadmin|mshta|rundll32|regsvr32|reg|schtasks|whoami|ipconfig|arp|route|hostname|systeminfo|dsquery|find|findstr|attrib)(?:\.exe)?$/i;
  const _isNativeWin = (name) => _NATIVE_WIN_BIN.test(name || '');
  const malwareSw = (huntSw || []).filter(s => {
    const isMal = (s.type || '').toLowerCase().includes('malware')
      || (s.labels || []).some(l => /malware/i.test(l));
    return isMal && !_isNativeWin(s.name || '');
  });

  // Fire the MalwareBazaar lookup the first time the Hunt tab opens.
  // Each family is fetched once and cached in component state for the
  // lifetime of this chip render.
  useEffect(() => {
    if (!showHunt || malwareSw.length === 0) return;
    let cancelled = false;
    malwareSw.forEach(s => {
      const fam = (s.name || '').trim();
      if (!fam || mbHashes[fam]) return;
      setMbHashes(m => ({ ...m, [fam]: { loading: true } }));
      fetch(`/api/attribution/hashes?family=${encodeURIComponent(fam)}&limit=8`)
        .then(r => r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`)))
        .then(data => {
          if (cancelled) return;
          if (data?.error) {
            setMbHashes(m => ({ ...m, [fam]: { error: data.error } }));
          } else {
            setMbHashes(m => ({ ...m, [fam]: { hashes: data?.hashes || [] } }));
          }
        })
        .catch(e => {
          if (cancelled) return;
          setMbHashes(m => ({ ...m, [fam]: {
            error: `MalwareBazaar request failed: ${e.message}`
          } }));
        });
    });
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [showHunt, malwareSw.length]);

  // Now safe to bail — all hooks have already run.
  if (!actor) return null;

  return (
    <Box sx={{
      display: 'flex', flexDirection: 'column', gap: 0.75,
      backgroundColor: muiAlpha('#0fbcff', 0.05),
      border: `1px solid ${muiAlpha('#0fbcff', 0.25)}`,
      borderLeft: `3px solid #0fbcff`,
      borderRadius: '4px', p: '10px 14px', mb: 1.5, maxWidth: '100%',
    }}>
      {/* Header — name, country, score. Compact, no aliases counter here. */}
      <Stack direction="row" alignItems="center" spacing={1} flexWrap="wrap">
        <Typography sx={{ fontSize: 10, color: 'text.tertiary', fontWeight: 600,
          textTransform: 'uppercase', letterSpacing: '0.07em' }}>
          Possible attribution
        </Typography>
        <Typography sx={{ fontSize: 14, color: 'primary.main', fontWeight: 600 }}>
          {display}
        </Typography>
        {actor.origin && (
          <Typography sx={{ fontSize: 11, color: 'text.tertiary' }}>· {actor.origin}</Typography>
        )}
        {typeof actor.score === 'number' && (
          <Typography sx={{ fontSize: 11, color: 'text.tertiary' }}>
            · {actor.score}% TTP overlap
          </Typography>
        )}
      </Stack>

      {/* Single tab strip — click to reveal one section at a time. */}
      {tabs.length > 0 && (
        <Stack direction="row" spacing={0.75} flexWrap="wrap"
          sx={{ rowGap: 0.5 }}>
          {tabs.map(t => {
            const on = activeTab === t.id;
            return (
              <Box key={t.id}
                onClick={() => setActiveTab(on ? null : t.id)}
                sx={{
                  cursor: 'pointer', userSelect: 'none',
                  fontSize: 11, fontWeight: 500,
                  px: 1, py: '3px', borderRadius: '4px',
                  color: on ? '#0fbcff' : 'text.tertiary',
                  backgroundColor: on
                    ? muiAlpha('#0fbcff', 0.14)
                    : muiAlpha('#ffffff', 0.03),
                  border: `1px solid ${on
                    ? muiAlpha('#0fbcff', 0.4)
                    : muiAlpha('#ffffff', 0.1)}`,
                  '&:hover': { color: '#0fbcff' },
                }}>
                {t.label}
              </Box>
            );
          })}
        </Stack>
      )}

      {/* Aliases */}
      {showAliases && (
        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.4 }}>
          {aliases.map(a => (
            <Box key={a} sx={{
              fontFamily: '"IBM Plex Mono", monospace', fontSize: 11,
              color: 'text.primary',
              backgroundColor: muiAlpha('#ffffff', 0.04),
              border: `1px solid ${muiAlpha('#ffffff', 0.08)}`,
              borderRadius: '3px', px: 0.75, py: '2px',
            }}>{a}</Box>
          ))}
        </Box>
      )}

      {/* Log evidence — only render entries that actually have evidence
          attached. No "X additional techniques matched but no evidence"
          footer; that was noise. */}
      {showEvidence && hasEvidence && (
        <Stack spacing={0.75}>
          {evByTech.filter(t => (t.evidence?.length || 0) > 0).map((t, i) => (
            <Box key={i}>
              <Stack direction="row" alignItems="baseline" spacing={0.75}>
                <Box component="span" sx={{
                  fontFamily: '"IBM Plex Mono", monospace', fontSize: 11,
                  color: '#0fbcff', fontWeight: 600,
                }}>
                  {t.id}
                </Box>
                {t.name && (
                  <Typography sx={{ fontSize: 11.5, color: 'text.primary' }}>
                    {t.name}
                  </Typography>
                )}
              </Stack>
              <Stack spacing={0.4} sx={{ pl: 1.25, mt: 0.25,
                borderLeft: `2px solid ${muiAlpha('#0fbcff', 0.2)}` }}>
                {(t.evidence || []).map((e, j) => (
                  <Typography key={j} sx={{ fontSize: 12,
                    color: 'text.primary', lineHeight: 1.55 }}>
                    {e.text}
                  </Typography>
                ))}
              </Stack>
            </Box>
          ))}
        </Stack>
      )}

      {/* Hunt guidance — three blocks now:
            1. How they attack (playbook narrative from MITRE/MISP)
            2. Processes / binaries (red mono chips)
            3. Malware hashes from MalwareBazaar (lazy-fetched on tab open) */}
      {showHunt && hasHunt && (
        <Stack spacing={1.25}>
          {playbook && (
            <Box>
              <Typography sx={{ fontSize: 10, color: 'text.tertiary',
                fontWeight: 600, textTransform: 'uppercase',
                letterSpacing: '0.07em', mb: 0.5 }}>
                How {display} typically attacks
              </Typography>
              <Typography sx={{ fontSize: 12.5, color: 'text.primary',
                lineHeight: 1.65 }}>
                {playbook}
              </Typography>
            </Box>
          )}

          {huntProcs.length > 0 && (
            <Box>
              <Typography sx={{ fontSize: 10, color: 'text.tertiary',
                fontWeight: 600, textTransform: 'uppercase',
                letterSpacing: '0.07em', mb: 0.5 }}>
                Processes / binaries
              </Typography>
              <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.4 }}>
                {huntProcs.map((p, i) => (
                  <Box key={i} sx={{
                    fontFamily: '"IBM Plex Mono", monospace', fontSize: 11,
                    color: '#EE3838',
                    backgroundColor: muiAlpha('#EE3838', 0.08),
                    border: `1px solid ${muiAlpha('#EE3838', 0.3)}`,
                    borderRadius: '3px', px: 0.75, py: '2px',
                  }}>{p}</Box>
                ))}
              </Box>
            </Box>
          )}

          {malwareSw.length > 0 && (
            <Box>
              <Typography sx={{ fontSize: 10, color: 'text.tertiary',
                fontWeight: 600, textTransform: 'uppercase',
                letterSpacing: '0.07em', mb: 0.5 }}>
                Malware hashes (MalwareBazaar)
              </Typography>
              <Stack spacing={0.75}>
                {malwareSw.map((s, i) => {
                  const fam = (s.name || '').trim();
                  const state = mbHashes[fam] || { loading: true };
                  return (
                    <Box key={i} sx={{
                      p: '8px 10px', borderRadius: '4px',
                      backgroundColor: muiAlpha('#EE3838', 0.04),
                      border: `1px solid ${muiAlpha('#EE3838', 0.2)}`,
                    }}>
                      <Stack direction="row" alignItems="baseline"
                        spacing={0.75} flexWrap="wrap" sx={{ rowGap: 0.25,
                          mb: 0.5 }}>
                        <Box component="a"
                          href={s.id ? `https://attack.mitre.org/software/${s.id}/` : undefined}
                          target="_blank" rel="noreferrer"
                          sx={{ fontFamily: '"IBM Plex Mono", monospace',
                            fontSize: 11.5, color: '#EE3838',
                            textDecoration: 'none', fontWeight: 600,
                            '&:hover': { textDecoration: 'underline' } }}>
                          {fam}
                        </Box>
                        <Box component="span" sx={{ fontSize: 10,
                          color: 'text.disabled',
                          textTransform: 'lowercase' }}>
                          {s.type || 'malware'}
                        </Box>
                      </Stack>
                      {state.loading && (
                        <Typography sx={{ fontSize: 11, color: 'text.tertiary',
                          fontStyle: 'italic' }}>
                          Querying MalwareBazaar for samples…
                        </Typography>
                      )}
                      {state.error && (
                        <Typography sx={{ fontSize: 11, color: 'warning.main',
                          fontStyle: 'italic' }}>
                          ⚠ {state.error}
                        </Typography>
                      )}
                      {state.hashes && state.hashes.length === 0 && (
                        <Typography sx={{ fontSize: 11, color: 'text.disabled',
                          fontStyle: 'italic' }}>
                          No samples currently listed on MalwareBazaar for "{fam}".
                        </Typography>
                      )}
                      {state.hashes && state.hashes.length > 0 && (
                        <Stack spacing={0.5}>
                          {state.hashes.slice(0, 6).map((h, j) => (
                            <Box key={j}>
                              <Box component="a"
                                href={`https://bazaar.abuse.ch/sample/${h.sha256}/`}
                                target="_blank" rel="noreferrer"
                                sx={{ fontFamily: '"IBM Plex Mono", monospace',
                                  fontSize: 10.5, color: 'text.primary',
                                  textDecoration: 'none', wordBreak: 'break-all',
                                  '&:hover': { color: '#EE3838',
                                               textDecoration: 'underline' } }}>
                                {h.sha256}
                              </Box>
                              {(h.file_name || h.file_type || h.first_seen) && (
                                <Typography sx={{ fontSize: 10,
                                  color: 'text.tertiary', mt: 0.1,
                                  fontFamily: '"IBM Plex Mono", monospace' }}>
                                  {[h.file_name, h.file_type, h.first_seen]
                                    .filter(Boolean).join(' · ')}
                                </Typography>
                              )}
                            </Box>
                          ))}
                          <Box component="a"
                            href={`https://bazaar.abuse.ch/browse.php?search=${encodeURIComponent(fam)}`}
                            target="_blank" rel="noreferrer"
                            sx={{ fontSize: 10, color: '#0fbcff',
                              textDecoration: 'none', mt: 0.25,
                              '&:hover': { textDecoration: 'underline' } }}>
                            View all MalwareBazaar samples for {fam} →
                          </Box>
                        </Stack>
                      )}
                    </Box>
                  );
                })}
              </Stack>
            </Box>
          )}
        </Stack>
      )}
    </Box>
  );
}

function AnalystSummary({ result, rs, onFeedbackStart, onFeedbackPartial, onFeedbackComplete }) {
  const a = rs?.analyst_summary;
  // The Summary card is the new front-page for an investigation, so we show
  // it whenever there's *any* AI output OR per-IOC scoring — not just when
  // a disposition exists. The threat-score block carries the card when the
  // AI hasn't returned a verdict yet.
  const hasGti = !!result?.gti_scores && Object.keys(result.gti_scores).length > 0;
  const hasDisposition = !!(a && a.disposition);
  if (!hasGti && !hasDisposition) return null;

  const dispColor = a?.disposition === 'CLEAR'    ? '#17AB1F'
                  : a?.disposition === 'ESCALATE' ? '#F14337'
                  :                                  '#E1B823';
  const summary = (rs?.summary || '').trim();
  // Attribution gate — precision-style score (matched / N_alert_techniques)
  // is now ≥ 60% AND at least 3 techniques matched. Single-technique
  // matches that hit "100% precision" against an APT are noise; the
  // 3-match floor weeds those out. Analyst context that pushes overlap
  // above the threshold (via re-analyze with feedback) is honoured
  // automatically because matched_actors re-runs each investigation.
  const topActor = (rs?.matched_actors || []).find(
    a => typeof a?.score === 'number'
      && a.score >= 60
      && (a.matchedTechniques?.length || 0) >= 3
  ) || null;
  // Plain-English summary from log_translator — written like an MDR analyst
  // briefing note (what / context / verdict / recommendation). Top of the
  // card so the analyst gets the human-readable read before the dial.
  const plainEnglish = (result?.log_translation?.normalized_summary || '').trim();

  // Summary structure rebuilt for prose flow:
  //   1. Disposition rendered as a coloured chip + reason — visually
  //      separate from the AI prose so we don't have to bolt
  //      "Recommended action: X — Y" into the middle of the paragraph.
  //   2. Plain-English + AI summary fused into ONE flowing paragraph,
  //      with aggressive de-dupe so the two AI calls don't repeat each
  //      other's content.
  //   3. Enrichment-summary line rendered as a small mono footer
  //      underneath, not as a trailing prose sentence.
  const dispReason = (a?.disposition_reason || '').trim();
  const enrichLine = (rs?.enrichment_summary?.line || '').trim();
  const _toks = (s) => new Set((s.toLowerCase().match(/[a-z0-9@.-]{4,}/g) || []));
  const _overlap = (x, y) => {
    if (!x || !y) return 0;
    const a_ = _toks(x), b_ = _toks(y);
    if (!a_.size || !b_.size) return 0;
    const inter = [...a_].filter(t => b_.has(t)).length;
    return inter / Math.max(1, Math.min(a_.size, b_.size));
  };
  // Drop overlapping pieces — plainEnglish vs summary, summary vs
  // dispReason. Threshold 50% catches paraphrased duplicates the old
  // 60% threshold missed.
  let _summary    = summary;
  let _dispReason = dispReason;
  if (_overlap(plainEnglish, _summary)    >= 0.5) _summary = '';
  if (_overlap(plainEnglish, _dispReason) >= 0.5) _dispReason = '';
  if (_overlap(_summary, _dispReason)     >= 0.5) {
    // Keep whichever is longer — usually disp_reason is denser/more useful.
    if ((_summary || '').length > (_dispReason || '').length) _dispReason = '';
    else _summary = '';
  }
  const _ensurePeriod = (s) => {
    const t = (s || '').trim();
    if (!t) return '';
    return /[.!?]$/.test(t) ? t : t + '.';
  };
  const combined = [
    _ensurePeriod(plainEnglish),
    _ensurePeriod(_summary),
    _ensurePeriod(_dispReason),
  ].filter(Boolean).join(' ');

  return (
    <Card title="Summary" accent="#0fbcff" badge={a?.disposition?.toLowerCase()} defaultOpen>
      {/* Order per analyst request:
            1. Threat score (top — the empirical headline)
            2. Possible attribution (only shows when TTP overlap ≥ 75%)
            3. Disposition pill (when set) — visual separator, not prose
            4. Flowing AI prose paragraph (plain-English + AI summary +
               disposition reason, de-duplicated)
            5. Enrichment-summary mono footer
            6. Confirmed facts / analyst assessment split
            7. Log correlation (when multi-log input was submitted)        */}
      {hasGti && <ThreatScore result={result}/>}

      {topActor && <AttributionChip actor={topActor}/>}

      {hasDisposition && (
        <Stack direction="row" alignItems="center" spacing={1}
          sx={{ mb: 1.25 }}>
          <Box sx={{
            fontSize: 11, fontWeight: 700, color: dispColor,
            backgroundColor: muiAlpha(dispColor, 0.12),
            border: `1px solid ${muiAlpha(dispColor, 0.4)}`,
            borderRadius: '4px', px: 1, py: '3px',
            textTransform: 'uppercase', letterSpacing: '0.06em',
          }}>
            Recommended action · {a.disposition}
          </Box>
        </Stack>
      )}

      {combined && (
        <Typography sx={{
          fontSize: 13.5, color: 'text.primary', lineHeight: 1.75,
          mb: 1.5, wordBreak: 'break-word',
          ...(hasDisposition ? { borderLeft: `3px solid ${dispColor}`,
                                  pl: 1.5 } : {}),
        }}>
          {combined}
        </Typography>
      )}

      {enrichLine && (
        <Typography sx={{
          fontFamily: '"IBM Plex Mono", monospace',
          fontSize: 11, color: 'text.tertiary', lineHeight: 1.55,
          mb: 1.5, pl: hasDisposition ? 1.5 : 0,
          borderLeft: hasDisposition
            ? `3px solid ${muiAlpha(dispColor, 0.3)}`
            : 'none',
        }}>
          {enrichLine}
        </Typography>
      )}

      {/* When this run was re-analysed with analyst feedback, surface
          the analyst's exact statement above the train-on-FP form so
          the AI analysis (above) and the analyst's input (here) are
          visually separated rather than running together. */}
      {rs?.analyst_feedback && (
        <Box sx={{ mt: 2,
          backgroundColor: muiAlpha('#B286FF', 0.06),
          border: `1px solid ${muiAlpha('#B286FF', 0.30)}`,
          borderLeft: '3px solid #B286FF',
          borderRadius: '4px',
          p: '10px 14px' }}>
          <Typography sx={{ fontSize: 10.5, fontWeight: 700, color: '#B286FF',
            textTransform: 'uppercase', letterSpacing: '0.08em', mb: 0.5 }}>
            Analyst feedback applied
          </Typography>
          <Typography sx={{ fontSize: 12.5, color: 'text.primary',
            lineHeight: 1.55, fontStyle: 'italic',
            whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
            “{rs.analyst_feedback}”
          </Typography>
        </Box>
      )}

      {/* Train-on-false-positives inline form — pinned directly under
          the AI analysis so the analyst can correct a wrong verdict
          without scrolling further. Renders nothing when there's no
          raw_input on the result (e.g. hash-only lookups). */}
      <FeedbackInline
        result={result}
        onStart={onFeedbackStart}
        onPartial={onFeedbackPartial}
        onComplete={onFeedbackComplete}
      />

      {/* PRINCIPLE 7 — Confirmed facts vs analyst assessment.
          Cross-field de-dup: when the AI ignored its prompt and put the
          same paraphrased verdict in BOTH `summary` (rendered in the
          combined paragraph above) AND `analysis_assessment` (rendered
          below), drop the duplicates from analysis_assessment. Catches
          the wording-shift dupes a strict string-equal check misses
          (e.g. "the deletion of X by user Y is not suspicious" vs
          "user Y deleted X, not malicious"). */}
      {(() => {
        const confirmed = rs?.confirmed_facts || [];
        const analysis_ = (rs?.analysis_assessment || []).filter(s => {
          if (!s) return false;
          // Drop assessment sentences whose tokens overlap any of the
          // already-rendered prose (combined paragraph + dispReason +
          // confirmed facts) by >= 50%.
          const compareAgainst = [combined, _dispReason, dispReason,
                                  ...confirmed].filter(Boolean).join(' ');
          return _overlap(s, compareAgainst) < 0.5;
        });
        if (!confirmed.length && !analysis_.length) return null;
        return <ConfirmedVsAnalysis confirmed={confirmed} analysis={analysis_} />;
      })()}

      {/* Log Correlation card retired — the AI now reasons about
          relationships between events inside an alert directly in the
          main analysis paragraph above instead of producing a separate
          correlation object. Kept the LogCorrelationCard definition
          below in case we revive multi-log later, but never invoked. */}

      {/* Calibration: every analyst override is a training signal. */}
      <VerdictOverride result={result} rs={rs} />
    </Card>
  );
}

/* ─── analyst override — POSTs to /api/calibration/override ────────────
   Drives the calibration log used to spot prompt regressions.
   Surfaced as a quiet link under the summary so analysts who agree
   with the AI never see a visible "DISAGREE?" button shouting at them. */
function VerdictOverride({ result, rs }) {
  const [open, setOpen]       = React.useState(false);
  const [level, setLevel]     = React.useState('');
  const [reason, setReason]   = React.useState('');
  const [submitting, setSub]  = React.useState(false);
  const [saved, setSaved]     = React.useState(null);  // null | record | {error}

  const aiLevel = rs?.threat_level || '';
  if (!aiLevel) return null;

  const submit = async () => {
    if (!level || level === aiLevel) return;
    setSub(true); setSaved(null);
    try {
      const r = await fetch('/api/calibration/override', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          raw_input:            result?.raw_input || '',
          ai_threat_level:      aiLevel,
          ai_confidence:        rs?.confidence ?? null,
          ai_summary:           rs?.summary || '',
          analyst_threat_level: level,
          analyst_reason:       reason,
          alert_type:           rs?.alert_type || null,
        }),
      }).then(x => x.json());
      setSaved(r?.saved ? r.record : { error: r?.detail || 'save failed' });
      if (r?.saved) { setOpen(false); setLevel(''); setReason(''); }
    } catch (e) {
      setSaved({ error: String(e) });
    }
    setSub(false);
  };

  const LEVELS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL'];

  if (!open) {
    return (
      <Box sx={{ mt: 1.25, fontSize: 11, color: 'text.tertiary' }}>
        {saved && !saved.error && (
          <Box component="span" sx={{ color: '#5be584', mr: 1 }}>
            ✓ Override saved for calibration
          </Box>
        )}
        {saved?.error && (
          <Box component="span" sx={{ color: '#ff8a8a', mr: 1 }}>
            ⚠ {String(saved.error).slice(0, 80)}
          </Box>
        )}
        <Box component="span"
          onClick={() => setOpen(true)}
          sx={{ cursor: 'pointer', textDecoration: 'underline',
                '&:hover': { color: 'primary.main' } }}>
          Disagree with this verdict?
        </Box>
      </Box>
    );
  }

  return (
    <Box sx={{ mt: 1.5, p: '10px 12px', borderRadius: '4px',
      border: `1px solid ${muiAlpha('#ffffff', 0.12)}`,
      backgroundColor: muiAlpha('#ffffff', 0.02) }}>
      <Box sx={{ fontSize: 11, color: 'text.tertiary', mb: 0.75 }}>
        AI rated this <b>{aiLevel}</b>. Your verdict:
      </Box>
      <Stack direction="row" spacing={0.5} sx={{ mb: 1, flexWrap: 'wrap' }}>
        {LEVELS.map(L => (
          <Box key={L}
            onClick={() => setLevel(L)}
            sx={{ px: 1, py: 0.375, fontSize: 10, cursor: 'pointer',
              borderRadius: '3px', fontFamily: '"IBM Plex Mono", monospace',
              border: `1px solid ${level === L ? '#0fbcff' : muiAlpha('#ffffff', 0.12)}`,
              backgroundColor: level === L ? muiAlpha('#0fbcff', 0.12) : 'transparent',
              color: level === L ? '#0fbcff' : 'text.secondary' }}>
            {L}
          </Box>
        ))}
      </Stack>
      <Box component="textarea"
        value={reason}
        onChange={e => setReason(e.target.value)}
        placeholder="Why? (optional — e.g. 'Known internal RMM, not C2')"
        rows={2}
        sx={{ width: '100%', boxSizing: 'border-box',
          fontSize: 11, p: 1, fontFamily: '"IBM Plex Mono", monospace',
          backgroundColor: '#0b0d12', color: 'text.primary',
          border: `1px solid ${muiAlpha('#ffffff', 0.12)}`,
          borderRadius: '3px', resize: 'vertical', mb: 1 }} />
      <Stack direction="row" spacing={1}>
        <Box component="button"
          onClick={submit}
          disabled={submitting || !level || level === aiLevel}
          sx={{ px: 1.5, py: 0.5, fontSize: 10, cursor: 'pointer',
            border: '1px solid #0fbcff', backgroundColor: muiAlpha('#0fbcff', 0.12),
            color: '#0fbcff', borderRadius: '3px',
            fontFamily: '"IBM Plex Mono", monospace',
            '&:disabled': { opacity: 0.4, cursor: 'not-allowed' } }}>
          {submitting ? 'SAVING...' : 'SAVE OVERRIDE'}
        </Box>
        <Box component="button"
          onClick={() => { setOpen(false); setLevel(''); setReason(''); }}
          sx={{ px: 1.5, py: 0.5, fontSize: 10, cursor: 'pointer',
            border: `1px solid ${muiAlpha('#ffffff', 0.12)}`,
            backgroundColor: 'transparent', color: 'text.secondary',
            borderRadius: '3px',
            fontFamily: '"IBM Plex Mono", monospace' }}>
          CANCEL
        </Box>
      </Stack>
    </Box>
  );
}

// WhyThisRating removed — the AI's threat_level field was producing
// internally contradictory output (badge MEDIUM, prose "This alert is
// INFORMATIONAL.") and the analyst-facing surface added more confusion
// than value. The combined Summary block in AnalystSummary already
// conveys the rating in plain English via the AI's summary + the
// recommended-disposition tail.

/* ─── Confirmed vs Analysis — PRINCIPLE 7 two-tier split
       Confirmed = statements directly traceable to enrichment data
       Analysis  = analyst inferences clearly labeled as assessment
       Rendered as two visually distinct sections so analysts know exactly
       what is evidence and what is interpretation.                       */
function ConfirmedVsAnalysis({ confirmed, analysis }) {
  const hasConfirmed = Array.isArray(confirmed) && confirmed.filter(Boolean).length > 0;
  const hasAnalysis  = Array.isArray(analysis)  && analysis.filter(Boolean).length > 0;
  if (!hasConfirmed && !hasAnalysis) return null;

  const Section = ({ title, color, items, label }) => (
    <Box sx={{ mt: 1, p: '10px 12px', borderRadius: '4px',
      backgroundColor: muiAlpha(color, 0.05),
      border: `1px solid ${muiAlpha(color, 0.22)}`,
      borderLeft: `3px solid ${color}` }}>
      <Stack direction="row" alignItems="center" spacing={0.75} sx={{ mb: 0.75 }}>
        <Box sx={{ width: 5, height: 5, borderRadius: 99, backgroundColor: color }}/>
        <Typography sx={{ fontSize: 11, fontWeight: 700, color,
          textTransform: 'uppercase', letterSpacing: '0.07em' }}>
          {title}
        </Typography>
        {label && (
          <Typography sx={{ fontSize: 10, color: 'text.tertiary', fontStyle: 'italic' }}>
            · {label}
          </Typography>
        )}
      </Stack>
      <Stack spacing={0.5} component="ul" sx={{ m: 0, pl: 2.25, listStyle: 'none' }}>
        {items.map((item, i) => (
          <Typography
            key={i}
            component="li"
            sx={{ fontSize: 12.5, color: 'text.primary', lineHeight: 1.55,
              position: 'relative',
              '&::before': {
                content: '"›"', color, position: 'absolute', left: -14, fontWeight: 700,
              } }}>
            {String(item)}
          </Typography>
        ))}
      </Stack>
    </Box>
  );

  return (
    <Box sx={{ mb: 1.5 }}>
      {hasConfirmed && (
        <Section
          title="Confirmed"
          color="#17AB1F"
          items={confirmed.filter(Boolean)}
          label="directly supported by enrichment data"
        />
      )}
      {hasAnalysis && (
        <Section
          title="Analysis"
          color="#E1B823"
          items={analysis.filter(Boolean)}
          label="analyst assessment, not confirmed fact"
        />
      )}
    </Box>
  );
}


/* ─── Log Correlation — only renders when multi-log input was detected.
       Shows a chronological timeline + plain-English explanation of how
       the events submitted together connect.                              */
function LogCorrelationCard({ multiLog, correlation }) {
  const count = multiLog?.log_count || (multiLog?.segments?.length || 0);
  if (!count || count < 2) return null;
  const anchors = Array.isArray(multiLog?.anchors) ? multiLog.anchors : [];
  const segments = Array.isArray(multiLog?.segments) ? multiLog.segments : [];
  const related = !!correlation && correlation.related !== false;
  const accent = related ? '#B286FF' : '#848592';
  const timeline = Array.isArray(correlation?.chronological_timeline)
    ? correlation.chronological_timeline : [];
  const shared = Array.isArray(correlation?.shared_elements)
    ? correlation.shared_elements.filter(Boolean) : [];
  const combined = (correlation?.combined_picture || '').trim();
  const rationale = (correlation?.rationale || '').trim();

  return (
    <Box sx={{ mt: 1.5, mb: 1.5, p: '12px 14px', borderRadius: '4px',
      backgroundColor: muiAlpha(accent, 0.05),
      border: `1px solid ${muiAlpha(accent, 0.25)}`,
      borderLeft: `3px solid ${accent}` }}>
      <Stack direction="row" alignItems="center" spacing={1} sx={{ mb: 1 }}>
        <Box sx={{ width: 6, height: 6, borderRadius: 99, backgroundColor: accent }}/>
        <Typography sx={{ fontSize: 11, fontWeight: 700, color: accent,
          textTransform: 'uppercase', letterSpacing: '0.07em' }}>
          Log Correlation
        </Typography>
        <Typography sx={{ fontSize: 11, color: 'text.tertiary' }}>
          · {count} log entries submitted together
        </Typography>
      </Stack>

      {!correlation && (
        <Typography sx={{ fontSize: 12.5, color: 'text.tertiary',
          fontStyle: 'italic', lineHeight: 1.55 }}>
          AI correlation is still computing — the relationship analysis will
          appear here when the investigation finishes.
        </Typography>
      )}

      {correlation && !related && (
        <Typography sx={{ fontSize: 12.5, color: 'text.primary',
          lineHeight: 1.55 }}>
          No clear relationship detected between the submitted logs.
          {rationale && <> {rationale}</>}
        </Typography>
      )}

      {related && shared.length > 0 && (
        <Box sx={{ mb: 1 }}>
          <Typography sx={{ fontSize: 10, color: 'text.tertiary', fontWeight: 600,
            textTransform: 'uppercase', letterSpacing: '0.06em', mb: 0.5 }}>
            Shared elements
          </Typography>
          <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
            {shared.map((s, i) => (
              <Box key={i} sx={{
                fontSize: 11, px: 1, py: '2px', borderRadius: '4px',
                backgroundColor: muiAlpha(accent, 0.12),
                border: `1px solid ${muiAlpha(accent, 0.3)}`,
                color: 'text.primary',
              }}>{String(s)}</Box>
            ))}
          </Box>
        </Box>
      )}

      {related && (timeline.length > 0 || anchors.length > 0) && (
        <Box sx={{ mb: 1 }}>
          <Typography sx={{ fontSize: 10, color: 'text.tertiary', fontWeight: 600,
            textTransform: 'uppercase', letterSpacing: '0.06em', mb: 0.5 }}>
            Timeline (chronological)
          </Typography>
          <Stack spacing={0.5}>
            {(timeline.length > 0 ? timeline : anchors.map((a, i) => ({
                when: a.timestamp || `Log #${i + 1}`,
                event: [a.event_id && `Event ${a.event_id}`,
                        a.user && `user ${a.user}`,
                        a.host && `host ${a.host}`,
                        a.process && `process ${a.process}`]
                       .filter(Boolean).join(' · ') || `Log #${i + 1}`,
                log_index: i + 1,
              }))).map((t, i) => (
              <Stack key={i} direction="row" spacing={1} alignItems="flex-start">
                <Box sx={{ width: 18, fontSize: 10, color: accent,
                  fontWeight: 700, pt: '2px' }}>
                  #{t.log_index ?? (i + 1)}
                </Box>
                <Typography sx={{ fontFamily: '"IBM Plex Mono", monospace',
                  fontSize: 11, color: 'text.tertiary', minWidth: 130 }}>
                  {t.when || '—'}
                </Typography>
                <Typography sx={{ fontSize: 12, color: 'text.primary', flex: 1,
                  lineHeight: 1.55 }}>
                  {t.event || '—'}
                </Typography>
              </Stack>
            ))}
          </Stack>
        </Box>
      )}

      {related && combined && (
        <Box sx={{ mt: 1, pt: 1, borderTop: `1px solid ${muiAlpha('#ffffff', 0.06)}` }}>
          <Typography sx={{ fontSize: 10, color: 'text.tertiary', fontWeight: 600,
            textTransform: 'uppercase', letterSpacing: '0.06em', mb: 0.5 }}>
            Combined picture
          </Typography>
          <Typography sx={{ fontSize: 12.5, color: 'text.primary',
            lineHeight: 1.6, whiteSpace: 'pre-wrap' }}>
            {combined}
          </Typography>
        </Box>
      )}

      {/* When the AI didn't return a related/timeline/combined block but
          the platform DID detect multiple logs, we still show the per-log
          anchor list so the analyst sees what was submitted. */}
      {(!correlation || (!combined && timeline.length === 0)) && segments.length > 1 && (
        <Box sx={{ mt: 1, pt: 1, borderTop: `1px solid ${muiAlpha('#ffffff', 0.06)}` }}>
          <Typography sx={{ fontSize: 10, color: 'text.tertiary', fontWeight: 600,
            textTransform: 'uppercase', letterSpacing: '0.06em', mb: 0.5 }}>
            Submitted logs
          </Typography>
          <Stack spacing={0.25}>
            {segments.slice(0, 8).map((_seg, i) => {
              const a = anchors[i] || {};
              const parts = [
                a.timestamp,
                a.event_id && `Event ${a.event_id}`,
                a.user && `user ${a.user}`,
                a.host && `host ${a.host}`,
              ].filter(Boolean);
              return (
                <Typography key={i} sx={{ fontSize: 11.5,
                  color: 'text.primary', lineHeight: 1.55 }}>
                  <Box component="span" sx={{ color: accent, fontWeight: 700, mr: 0.75 }}>
                    #{i + 1}
                  </Box>
                  {parts.length > 0 ? parts.join(' · ') : '(no recognised anchors)'}
                </Typography>
              );
            })}
          </Stack>
        </Box>
      )}
    </Box>
  );
}


/* ─── Inline feedback form rendered INSIDE the Summary card, directly
       under the AI prose. Re-uses the /api/analyze SSE flow with
       analystFeedback set so the investigation prompt prepends an
       "ANALYST VERDICT AND CONTEXT" block as the highest-weight input;
       streamed result replaces the visible analysis via onPartial /
       onComplete. No Card wrapper, no explanatory copy — just a clear
       header strip + input + button so the feedback surface sits flush
       in the Summary without taking the analyst out of context.       */
function FeedbackInline({ result, onStart, onPartial, onComplete }) {
  const [statement, setStatement] = useState('');
  const [sending, setSending]     = useState(false);
  const [error, setError]         = useState(null);
  const originalLog = result?.raw_input || '';
  if (!originalLog) return null;

  const submit = async () => {
    const trimmed = statement.trim();
    if (!trimmed) return;
    setSending(true); setError(null);
    onStart?.();
    try {
      const resp = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          logText:         originalLog,
          inputType:       'log',
          label:           result?.label || '',
          analystFeedback: trimmed,
        }),
      });
      if (!resp.ok) {
        const err = await resp.json().catch(() => ({ error: 'analysis failed' }));
        throw new Error(err.error || err.detail || `HTTP ${resp.status}`);
      }
      const reader = resp.body.getReader();
      const dec = new TextDecoder();
      let buf = '';
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += dec.decode(value, { stream: true });
        const lines = buf.split('\n');
        buf = lines.pop();
        for (const line of lines) {
          if (!line.startsWith('data: ')) continue;
          const raw = line.slice(6).trim();
          if (raw === '[DONE]') break;
          try {
            const ev = JSON.parse(raw);
            if (ev.event === 'partial_result' && ev.result) onPartial?.(ev.result);
            if (ev.event === 'complete') {
              onComplete?.(ev.result);
              setSending(false);
              setStatement('');
            }
            if (ev.event === 'error') {
              setError(ev.error || 'analysis failed');
              setSending(false);
            }
          } catch {}
        }
      }
    } catch (e) {
      setError(e.message || 'analysis failed');
      setSending(false);
    }
  };

  return (
    <Box sx={{ mt: 2, pt: 1.5,
      borderTop: `1px solid ${muiAlpha('#ffffff', 0.08)}` }}>
      <Typography sx={{ fontSize: 11, fontWeight: 700, color: '#B286FF',
        textTransform: 'uppercase', letterSpacing: '0.07em', mb: 1 }}>
        Train on false positives
      </Typography>
      {/* The 'Analysis was updated based on your previous feedback' banner
          used to live here, but the verbatim 'Analyst feedback applied'
          block in AnalystSummary now carries that signal. */}
      <Stack direction="row" spacing={1} alignItems="stretch">
        <MuiTextField
          multiline rows={2} fullWidth variant="outlined" size="small"
          value={statement} onChange={e => setStatement(e.target.value)}
          disabled={sending}
          onKeyDown={e => {
            if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) {
              e.preventDefault(); submit();
            }
          }}
          placeholder='e.g. "This is our internal vuln scanner, not malicious traffic."'
          sx={{ flex: 1,
            '& .MuiOutlinedInput-input': { fontSize: 13, lineHeight: 1.5 },
            '& .MuiOutlinedInput-root': {
              backgroundColor: muiAlpha('#B286FF', 0.04),
            },
            '& .MuiOutlinedInput-notchedOutline': {
              borderColor: muiAlpha('#B286FF', 0.4),
            },
          }}
        />
        <MuiButton variant="contained"
          onClick={submit}
          disabled={sending || !statement.trim()}
          sx={{ alignSelf: 'stretch', minWidth: 110,
            backgroundColor: '#B286FF',
            '&:hover': { backgroundColor: '#9061f0' },
            '&.Mui-disabled': { backgroundColor: muiAlpha('#B286FF', 0.3) },
          }}>
          {sending ? 'Re-analyzing…' : 'Re-analyze'}
        </MuiButton>
      </Stack>
      {error && (
        <Box sx={{ mt: 1, p: '8px 12px',
          backgroundColor: muiAlpha('#F14337', 0.1),
          border: `1px solid ${muiAlpha('#F14337', 0.4)}`,
          borderRadius: '4px',
          color: 'error.main', fontSize: 12 }}>
          {error}
        </Box>
      )}
    </Box>
  );
}


/* ─── Chat with RECON · conversational follow-up on the investigation.
       The feedback-on-false-positives flow lives in <TrainOnFalsePositive>
       above the Summary now; the chat is chat-only.                      */
function ChatWithRecon({ result, bare,
                          onFeedbackStart, onFeedbackPartial, onFeedbackComplete }) {
  const [messages, setMessages] = useState([]);
  const [input, setInput]       = useState('');
  const [sending, setSending]   = useState(false);
  const [error, setError]       = useState(null);
  const [pendingQuestion, setPendingQuestion] = useState(null);
  const scrollRef = useRef(null);
  const textareaRef = useRef(null);

  const runId = result?.runId;
  const rs    = result?.response_summary || {};
  // Surface every AI-generated probing question the investigation produced —
  // don't drop the plain ones for lacking if_yes/if_no metadata; the render
  // below already hides those chips when they're missing. We keep zero
  // hardcoded fallbacks here so the analyst only ever sees questions specific
  // to whatever they uploaded.
  const questions = (rs.probing_questions || []).filter(q => q && q.question);

  // ─── Feedback mode (folded into the chat input as a selectable toggle) ──
  // When feedbackMode is on, the same Send button submits the chat input as
  // analyst feedback — re-running /api/analyze with the original raw log
  // plus the analyst statement, and replacing the visible analysis result.
  // Toggle sits to the LEFT of the Send button so the analyst can train the
  // AI on false positives without leaving the chat surface.
  const [feedbackMode, setFeedbackMode]     = useState(false);
  const [feedbackSending, setFeedbackSending] = useState(false);
  const feedbackUpdated = !!rs?.analyst_feedback;
  const originalLog = result?.raw_input || '';

  const submitFeedback = async (statement) => {
    const trimmed = (statement || '').trim();
    if (!trimmed || !originalLog) return;
    setFeedbackSending(true);
    setError(null);
    onFeedbackStart?.();
    try {
      const resp = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          logText: originalLog,
          inputType: 'log',
          label: result?.label || '',
          analystFeedback: trimmed,
        }),
      });
      if (!resp.ok) {
        const err = await resp.json().catch(() => ({ error: 'Unknown error' }));
        throw new Error(err.error || err.detail || `HTTP ${resp.status}`);
      }
      const reader = resp.body.getReader();
      const dec = new TextDecoder();
      let buf = '';
      while (true) {
        const { done: d, value } = await reader.read();
        if (d) break;
        buf += dec.decode(value, { stream: true });
        const lines = buf.split('\n');
        buf = lines.pop();
        for (const line of lines) {
          if (!line.startsWith('data: ')) continue;
          const raw = line.slice(6).trim();
          if (raw === '[DONE]') break;
          try {
            const ev = JSON.parse(raw);
            if (ev.event === 'partial_result' && ev.result) onFeedbackPartial?.(ev.result);
            if (ev.event === 'complete') {
              onFeedbackComplete?.(ev.result);
              setFeedbackSending(false);
              setMessages(m => [
                ...m,
                { role: 'assistant',
                  content: 'Got it — re-ran the analysis with your context.',
                  _from_card: true,
                  timestamp: new Date().toISOString() },
              ]);
            }
            if (ev.event === 'error') {
              setError(ev.error || 'analysis failed');
              setFeedbackSending(false);
            }
          } catch {}
        }
      }
    } catch (e) {
      setError(e.message);
      setFeedbackSending(false);
    }
  };

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
    if (!rawText || sending || feedbackSending) return;
    // Feedback-mode short-circuit — submit the chat input as analyst feedback
    // instead of a chat message and replace the analysis result.
    if (feedbackMode && originalLog) {
      if (!msgOverride) setInput('');
      setMessages(m => [
        ...m,
        { role: 'user', content: rawText, _feedback: true,
          timestamp: new Date().toISOString() },
        { role: 'assistant', content: 'Re-analyzing with your context as ground truth…',
          _streaming: true, _from_card: true,
          timestamp: new Date().toISOString() },
      ]);
      await submitFeedback(rawText);
      setMessages(m => {
        const copy = [...m];
        for (let i = copy.length - 1; i >= 0; i--) {
          if (copy[i]?._streaming) {
            copy[i] = { ...copy[i], _streaming: false };
            break;
          }
        }
        return copy;
      });
      setFeedbackMode(false);
      return;
    }
    if (!runId) return;
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
        let streamError = null;
        for (const line of lines) {
          if (!line.startsWith('data: ')) continue;
          const payload = line.slice(6).trim();
          if (payload === '[DONE]') break;
          // Parse the event first. The inner try used to wrap the whole
          // event handling block — including `throw new Error(ev.error)`
          // — which meant backend error events got silently swallowed
          // and the chat looked frozen with the analyst's message stuck
          // mid-stream.
          let ev = null;
          try { ev = JSON.parse(payload); } catch { continue; }
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
                // If the stream finished with no text AND no tool calls,
                // surface a fallback so the bubble doesn't sit empty.
                const hasContent = (last.content || '').trim().length > 0;
                const hasTools   = (last.tool_calls || []).length > 0;
                copy[copy.length - 1] = {
                  ...last,
                  content: hasContent
                    ? last.content
                    : (hasTools
                        ? 'I ran the checks above but didn\'t produce a written reply — try asking again or rephrasing.'
                        : 'No reply came back. Try sending the message again.'),
                  _streaming: false,
                };
              }
              return copy;
            });
          } else if (ev.event === 'error') {
            streamError = ev.error || 'chat stream failed';
            break;
          }
        }
        if (streamError) throw new Error(streamError);
      }
    } catch (e) {
      setError(e.message || 'chat stream failed');
      // Roll back the placeholder assistant message on error
      setMessages(m => m[m.length-1]?._streaming ? m.slice(0, -1) : m);
    } finally { setSending(false); }
  };

  if (!runId) return null;
  // All cards on the analyze view share the same cyan accent.
  const accent = '#0fbcff';

  const body = (
    <>
      {/* Small purple chip when this run was re-analysed with analyst
          feedback. No header text — just the quoted statement so the
          analyst sees what was applied. */}
      {feedbackUpdated && (
        <Typography sx={{
          fontSize: 12, color: '#B286FF', lineHeight: 1.55,
          mb: 1, fontStyle: 'italic', whiteSpace: 'pre-wrap',
          borderLeft: `3px solid #B286FF`,
          backgroundColor: muiAlpha('#B286FF', 0.05),
          p: '8px 12px', borderRadius: '4px',
        }}>
          “{rs.analyst_feedback}”
        </Typography>
      )}

      {/* Investigation-guidance question cards, always visible so the analyst
          can pick a new one mid-conversation. */}
      {questions.length > 0 && (
        <Box sx={{ mb:1.75 }}>
          <Box sx={{ display:'flex', alignItems:'center', gap:0.75, mb:1 }}>
            <Box sx={{ width:4, height:4, borderRadius:99, backgroundColor:accent }}/>
            <Typography variant="caption" sx={{
              fontSize:11, color:'text.tertiary', fontWeight:500,
              textTransform:'uppercase', letterSpacing:'0.06em',
            }}>
              Things to verify, click and RECON asks, you answer
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

      {/* Train-on-false-positives toggle removed — the feedback workflow
          lives in <TrainOnFalsePositive> directly under the Summary card
          so it doesn't get buried at the bottom of a long chat. This
          card stays chat-only. */}

      {/* Input row — chat-only after the feedback split. */}
      <Stack direction="row" spacing={1}>
        <MuiTextField
          inputRef={textareaRef}
          multiline rows={2} fullWidth variant="outlined"
          value={input} onChange={e => setInput(e.target.value)}
          disabled={feedbackSending}
          onKeyDown={e => {
            if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) { e.preventDefault(); send(); }
          }}
          placeholder={feedbackMode
            ? 'If the AI analysis is wrong, teach it what is right.'
            : (pendingQuestion
              ? 'Type what you found when checking this — RECON will interpret your answer…'
              : 'Ask anything — "Is this likely a vulnerability scanner?", "Look up this hash in sandbox"…')}
          sx={{ flex:1,
            '& .MuiOutlinedInput-input': { fontSize:13, lineHeight:1.5 },
            ...(feedbackMode ? {
              '& .MuiOutlinedInput-root': {
                backgroundColor: muiAlpha('#B286FF', 0.04),
              },
              '& .MuiOutlinedInput-notchedOutline': {
                borderColor: muiAlpha('#B286FF', 0.4),
              },
            } : {}),
          }}
        />
        <MuiButton variant="contained"
          onClick={() => send()}
          disabled={(sending || feedbackSending) || !input.trim()}
          sx={{ alignSelf:'stretch', minWidth:96,
            ...(feedbackMode ? {
              backgroundColor: '#B286FF',
              '&:hover': { backgroundColor: '#9061f0' },
            } : {}),
          }}>
          {feedbackSending ? 'Re-analyzing…'
            : feedbackMode ? 'Re-analyze'
            : pendingQuestion ? 'Answer'
            : 'Send'}
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
      badge={questions.length > 0 ? `${questions.length} suggested checks` : null}>
      {body}
    </Card>
  );
}

/* ─── email analysis (when input is an EML) ───────────────────────────────────── */
function EmailAnalysis({ result }) {
  const e = result?.email_analysis;
  if (!e || (!e.subject && !e.from)) return null;

  const auth = e.auth_results || {};
  const authChip = (label, value) => {
    if (!value) return null;
    const ok = value === 'pass';
    return <MuiTag key={label} label={`${label}: ${value}`} color={ok ? '#16AD34' : '#EE3838'}/>;
  };
  const borderTop = (i) => i > 0 ? `1px solid ${muiAlpha('#ffffff', 0.06)}` : 'none';
  const monoSx = { fontFamily: '"IBM Plex Mono", monospace' };

  return (
    <Card title="Email analysis" accent="#0fbcff" badge={`${e.attachments?.length || 0} attachments`}>
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

/* ─── intel cross-references (KEV / LOLBAS / Atomic) ──────────────────────────── */
function CrossRefs({ rs, bare }) {
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

  const body = (
    <>
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
    </>
  );
  if (bare) return body;
  return (
    <Card title="Threat intel cross-references" accent="#0fbcff"
      badge={`${kev.length} KEV · ${lolbas.length} LOLBAS · ${kits.length} kit · ${atomic.length} TTP`}>
      {body}
    </Card>
  );
}

/* ─── detection rules (multi-SIEM) — MUI Tabs + CodeBlock ─────────────────── */
function Detection({ result }) {
  const rs    = result?.response_summary || {};
  const mitre = rs.mitre_techniques || [];
  // On-demand generation state — detection content is generated from the
  // Detection card via /api/detection rather than auto-generated every run.
  // Now fans out to every supported platform (Sigma, KQL, Splunk SPL,
  // Elastic EQL, Snort/Suricata, Chronicle YARA-L, CrowdStrike FQL, YARA)
  // in parallel on click.
  const [g, setG] = useState(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState(null);
  const [active, setActive] = useState(null);

  // Prefer on-demand generated content; fall back to any auto content (legacy).
  const sigma = g?.sigma ?? result?.sigma_rule;
  const kql   = g?.kql   ?? result?.kql_query;
  const siem  = result?.response_summary?.siem_queries || {};
  const sigmaValid = g ? g.sigma_valid : rs.sigma_valid;
  const tabs = [
    sigma                                            && { id:'sigma',    label:'Sigma',              content:sigma, badge: sigmaValid===true?'validated':sigmaValid===false?'invalid':null },
    kql                                              && { id:'kql',      label:'KQL · Sentinel',     content:kql },
    (g?.spl || siem.splunk_spl)                      && { id:'spl',      label:'Splunk SPL',         content:g?.spl || siem.splunk_spl },
    (g?.eql || siem.elastic_eql)                     && { id:'eql',      label:'Elastic EQL',        content:g?.eql || siem.elastic_eql },
    (g?.suricata)                                    && { id:'suricata', label:'Snort / Suricata',   content:g.suricata },
    (g?.yaral || siem.chronicle_yara_l)              && { id:'yaral',    label:'Chronicle YARA-L',   content:g?.yaral || siem.chronicle_yara_l },
    (g?.fql || siem.crowdstrike_fql)                 && { id:'fql',      label:'CrowdStrike Falcon', content:g?.fql || siem.crowdstrike_fql },
    g?.yara                                          && { id:'yara',     label:'YARA',               content:g.yara },
  ].filter(Boolean);

  const generate = async () => {
    setLoading(true); setErr(null);
    try {
      const analysis = {
        threatLevel:     rs.threat_level,
        summary:         rs.summary,
        mitreTechniques: mitre,
        malwareFamily:   rs.malware_family || result?.malware_family,
      };
      const base = { iocs: result?.iocs || {}, analysis };
      const post = (action) => fetch('/api/detection', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...base, action }),
      }).then(r => r.json()).catch(() => ({ result: '', error: 'request failed' }));

      // Fire every detection-rule format in parallel. The YARA call is
      // only useful when we have a malware family — backend returns a
      // generic rule otherwise, which we skip on the frontend.
      const familyKnown = !!analysis.malwareFamily;
      const calls = {
        sigma:    post('sigma'),
        kql:      post('kql'),
        spl:      post('splunk_spl'),
        eql:      post('elastic_eql'),
        suricata: post('suricata'),
        yaral:    post('chronicle_yara_l'),
        fql:      post('crowdstrike_fql'),
        ...(familyKnown ? { yara: post('yara') } : {}),
      };
      const keys = Object.keys(calls);
      const out  = await Promise.all(Object.values(calls));
      const next = {};
      keys.forEach((k, i) => {
        const v = out[i] || {};
        if (k === 'sigma') {
          next.sigma = v.result; next.sigma_valid = v.valid;
          // Backend's sigma path also returns a piggy-backed SPL — only
          // overwrite if the dedicated SPL call didn't succeed.
          if (v.splunk_spl && !next.spl) next.spl = v.splunk_spl;
        } else if (k === 'spl' && v.result) {
          next.spl = v.result;
        } else if (v.result) {
          next[k] = v.result;
        }
      });
      setG(next);
      setActive(next.sigma ? 'sigma' : Object.keys(next).find(k => next[k]) || 'sigma');
    } catch (e) { setErr(e.message || 'Generation failed'); }
    finally { setLoading(false); }
  };

  // Nothing generated yet → show the on-demand generate button.
  if (!tabs.length) {
    return (
      <Card title="Detection Rules" accent="#0fbcff">
        <MuiButton variant="contained" onClick={generate} disabled={loading}
          sx={{ textTransform: 'none' }}>
          {loading ? 'Generating…' : 'Generate Detection Rules'}
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
      {/* JA3 / JA4 TLS fingerprints — moved out of OSINT into Detection
          Rules since they ARE detection rules (Sigma + KQL snippets
          analysts can append to their existing rules). Renders nothing
          when no relevant frameworks were matched. */}
      {(result?.response_summary?.ja_fingerprints || []).length > 0 && (
        <Box sx={{ mt: 2, pt: 2, borderTop: `1px solid ${muiAlpha('#ffffff', 0.08)}` }}>
          <NetworkDetection result={result} bare/>
        </Box>
      )}
    </Card>
  );
}

/* ─── JA3/JA4 network detection ──────────────────────────────────────────────── */
function NetworkDetection({ result, bare }) {
  const fps = result?.response_summary?.ja_fingerprints || [];
  const sigma = result?.response_summary?.ja_sigma_snippet;
  const kql   = result?.response_summary?.ja_kql_snippet;
  if (!fps.length) return null;
  const body = (
    <>
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
    </>
  );
  if (bare) return body;
  return (
    <Card title="Network detection · JA3 / JA4 fingerprints" accent="#B286FF"
      badge={`${fps.length} C2 framework${fps.length === 1 ? '' : 's'}`} defaultOpen={false}>
      {body}
    </Card>
  );
}


/* ─── sidebar ─────────────────────────────────────────────────────────────────
 * Adapted from OpenCTI (AGPL-3.0) — LeftBar.jsx pattern.
 * Uses MUI Drawer with the OpenCTI nav width/styling, hosting the input area
 * (drop zone + textarea + AgentPipeline) and the extracted-IOCs panel.
 */
function Sidebar({ onResult, onPartialResult, onAnalyzing, currentResult, onScanFile, onScanHash, onScanUrl, scanState, onHome, onOpenEmail, emailActive, onOpenAnalyze, analyzeAvailable, analyzeActive, authUser, onLogout }) {
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
      {/* Logo header — click to fully reset: clears the main view (scan /
          email / result) and every sidebar input. */}
      <Box
        onClick={() => {
          setLogText('');
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
            setLogText('');
            handleFile(e.dataTransfer.files[0]);
          }}
          onClick={() => {
            if (scanState?.scanning) return;
            setLogText('');
            document.getElementById('sidebarFile').click();
          }}
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

        {/* Back-to-Analysis pill — only shown when there's a completed or
            in-flight analysis AND the main view is currently taken over by
            another workspace (Email or File Analyzer). Single click bounces
            the analyst back to the analysis result without losing it. */}
        {analyzeAvailable && !analyzeActive && (
          <Box
            onClick={() => onOpenAnalyze?.()}
            sx={{
              display: 'flex', alignItems: 'center', gap: 1.25,
              p: '12px 14px',
              backgroundColor: 'background.secondary',
              border: `1px solid ${muiAlpha('#ffffff', 0.12)}`,
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
            <Activity size={16} color="#0fbcff" style={{ flexShrink: 0 }}/>
            <Typography sx={{
              color: 'text.primary', fontSize: 12, fontWeight: 500,
              flex: 1, minWidth: 0,
            }}>
              {scanState?.scanning ? 'Analysis (in progress)' : 'Analysis'}
            </Typography>
            <Typography sx={{ fontSize: 10, color: 'text.tertiary',
              textTransform: 'uppercase', letterSpacing: '0.06em' }}>
              open
            </Typography>
          </Box>
        )}

        {/* Email composer entry point — opens the dedicated composer view */}
        <Box
          onClick={() => { setLogText(''); onOpenEmail?.(); }}
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

        {/* Single textarea — accepts a log on its own OR a log mixed with
            analyst commentary ("This is from a scheduled scan", "User was on
            sanctioned RMM tool during this window", etc.). The investigation
            prompt sees the full block as raw_input and reasons over the
            commentary in context. No separate context field. */}
        <Box sx={{ position: 'relative', mb: 1.25 }}>
          <Box component="textarea"
            value={logText} onChange={e=>setLogText(e.target.value)}
            placeholder="Paste a log or describe what you saw"
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

        {/* Hash + URL lookups now live inside the Analyze textarea — the
            AgentPipeline button detects a bare URL and routes to
            /api/scan/url, otherwise it runs the log-analysis pipeline. */}

        <AgentPipeline logText={logText} label=""
          onComplete={(r) => { onAnalyzing?.(false); onResult(r); }}
          onPartial={(p) => { onAnalyzing?.(false); onPartialResult(p); }}
          onStart={() => { onResult(null); onAnalyzing?.(true); }}
          onScanUrl={(url) => { onScanUrl?.(url); setLogText(''); }}/>

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

      {/* Signed-in footer — username + Logout. Pinned to the bottom of the
          sidebar so it doesn't scroll out of reach when the IOC list is long. */}
      {authUser && (
        <Box sx={{
          borderTop: `1px solid ${muiAlpha('#ffffff', 0.12)}`,
          p: '10px 14px',
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          flexShrink: 0,
        }}>
          <Typography sx={{
            fontSize: 11, color: 'text.tertiary',
            fontFamily: '"IBM Plex Mono", monospace',
            overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
          }}>
            {authUser}
          </Typography>
          <Box component="button" onClick={onLogout} sx={{
            background: 'none', border: 'none', cursor: 'pointer',
            color: 'text.tertiary', fontSize: 11, fontFamily: 'inherit',
            textTransform: 'uppercase', letterSpacing: '0.06em',
            '&:hover': { color: 'primary.main' },
          }}>
            Logout
          </Box>
        </Box>
      )}
    </MuiDrawer>
  );
}

/* ─── empty state (minimal — analyst pastes into the sidebar to begin) ───────── */
function Empty() {
  return null;
}

// Suspense fallback for the lazy-loaded workspaces (FileScannerView,
// EmailComposerView, MapTab). Renders a layout-matching skeleton card
// instead of a centered "loading…" so the surrounding layout stays put
// AND the analyst sees that something is loading where the real chunk
// will mount. Per the no-spinner rule, this is now a shimmer-card.
function LazyFallback({ height = 120 }) {
  return <SkeletonLazyFallback height={height}/>;
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
  // Auth gate: 'checking' on mount while /api/auth/me resolves, then
  // 'in' (render the app) or 'out' (render LoginPage). Any subsequent 401
  // from a fetch flips this back to 'out' via window['recon:401'].
  const [authState, setAuthState] = useState('checking');
  const [authUser,  setAuthUser]  = useState(null);

  useEffect(() => {
    let alive = true;
    fetch('/api/auth/me', { credentials: 'include' })
      .then(r => r.ok ? r.json() : null)
      .then(d => {
        if (!alive) return;
        if (d?.user) { setAuthUser(d.user); setAuthState('in'); }
        else { setAuthState('out'); }
      })
      .catch(() => alive && setAuthState('out'));
    // Global 401 -> bounce to login. Any fetch that hits an auth-protected
    // endpoint with a stale cookie can dispatch this event to log the user
    // out without each call site needing its own handler.
    const onUnauth = () => { setAuthUser(null); setAuthState('out'); };
    window.addEventListener('recon:unauthenticated', onUnauth);
    return () => { alive = false; window.removeEventListener('recon:unauthenticated', onUnauth); };
  }, []);

  const onAuthed = useCallback((user) => {
    setAuthUser(user);
    setAuthState('in');
  }, []);

  if (authState === 'checking') {
    // Auth probe is sub-200ms in steady state; render a minimal skeleton
    // outline instead of a centered "loading…" so first paint matches the
    // shell layout the analyst will see post-auth.
    return (
      <Box sx={{ minHeight: '100vh', backgroundColor: 'background.default',
        p: 3, display: 'flex', flexDirection: 'column', gap: 1.5 }}>
        <SkeletonLazyFallback height={48} label="auth"/>
        <Box sx={{ display: 'grid', gridTemplateColumns: '260px 1fr', gap: 2 }}>
          <SkeletonLazyFallback height={420}/>
          <SkeletonLazyFallback height={420}/>
        </Box>
      </Box>
    );
  }
  if (authState === 'out') {
    return (
      <ErrorBoundary label="Login">
        <Suspense fallback={<LazyFallback height={300}/>}>
          <LoginPage onAuthed={onAuthed}/>
        </Suspense>
        <ToastHost/>
      </ErrorBoundary>
    );
  }

  // Outermost ErrorBoundary so a crash anywhere in AppMain still renders the
  // toast surface + a recovery panel instead of a blank white screen.
  // ToastHost sits OUTSIDE the boundary so API errors during a crash still
  // surface as notifications.
  return (
    <>
      <ErrorBoundary label="RECON">
        <AppMain authUser={authUser} setAuthState={setAuthState}/>
      </ErrorBoundary>
      <ToastHost/>
    </>
  );
}

function AppMain({ authUser, setAuthState }) {
  const [result, setResult] = useState(null);
  // True between AgentPipeline onStart and the first onPartial / onComplete.
  // Drives the SkeletonAnalyze layout in the main view so analysts see WHERE
  // results will land while waiting on the first stream event.
  const [analyzing, setAnalyzing] = useState(false);
  const [view, setView] = useState('detail'); // 'detail' | 'table'
  const [webhooks, setWebhooks] = useState({});
  // Bumped on "go home" (logo) to remount the Sidebar — this clears its local
  // input state AND the AgentPipeline's internal trace/pipeline, which would
  // otherwise linger under the Analyze input after returning home.
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
    // clear the email composer so the new action owns the canvas. The
    // analyze result is intentionally PRESERVED so the analyst can
    // return to it via the "Analysis" sidebar pill while the scan runs.
    // A fresh Analyze run wipes the prior result through AgentPipeline's
    // onStart hook below, so we never accumulate stale state.
    setEmailState(null);
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
        onAnalyzing={setAnalyzing}
        currentResult={result}
        onScanFile={scanFile}
        onScanHash={scanHash}
        onScanUrl={scanUrl}
        scanState={scanState}
        onHome={() => { clearScan(); setEmailState(null); setResult(null); setHomeNonce(n => n + 1); }}
        onOpenEmail={() => {
          // Open the email composer with a blank slate. The analyze
          // result is intentionally PRESERVED so the analyst can come
          // back to it via the "Analysis" sidebar pill — only a fresh
          // Analyze run wipes the prior result (via AgentPipeline's
          // onStart hook). The scanner gets dismissed because it doesn't
          // share state with anything else.
          clearScan();
          setEmailState({ log: '', parsed: null });
        }}
        emailActive={!!emailState}
        // "Analysis" sidebar pill: available whenever there's an analyze
        // result OR an analyze run is in flight (we still want the click
        // to land you on the live progress). Active means the main view is
        // currently rendering analysis (not email and not scanner), so the
        // pill hides itself to avoid a no-op click.
        analyzeAvailable={!!result}
        analyzeActive={!emailState && !showScanner}
        onOpenAnalyze={() => {
          // Dismiss the email composer and the file scanner so the analyze
          // view owns the main area again. The analysis result itself is
          // preserved (it lives in `result`) so we just need to clear the
          // overlays.
          setEmailState(null);
          clearScan();
        }}
        authUser={authUser}
        onLogout={async () => {
          try {
            await fetch('/api/auth/logout', { method: 'POST', credentials: 'include' });
          } catch { /* logout is best-effort — even if the request fails, we drop client-side */ }
          setAuthState('out');
        }}
      />

      {/* Main view priority: email composer > file scanner > analysis */}
      {emailState && (
        <ErrorBoundary label="Email Composer">
          <Suspense fallback={<LazyFallback/>}>
            <EmailComposerView
              initialLog={emailState.log || ''}
              initialParsed={emailState.parsed || null}
              onClose={() => setEmailState(null)}
            />
          </Suspense>
        </ErrorBoundary>
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
          <ErrorBoundary label="File Scanner">
            <Suspense fallback={<LazyFallback/>}>
              <FileScannerView
                external={scanState}
                onScanFile={scanFile}
                onScanHash={scanHash}
                onScanUrl={scanUrl}
              />
            </Suspense>
          </ErrorBoundary>
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

        {/* Layout-matching skeleton while the analyze pipeline is running and
            no partial result has merged yet. Once the first partial arrives,
            the real cards take over instantly via mergePartial. */}
        {!result && analyzing && <SkeletonAnalyze/>}
        {!result && !analyzing && <Empty/>}

        {result && view === 'table' && (
          <>
            <PreFlight result={result}/>
            <SignalBanners result={result}/>
            <SuppressedIOCs result={result}/>
            <IOCPivot result={result}/>
            <BulkTable result={result}/>
            {(result?.iocs?.ips || []).length > 0 && (
              <Card title="Geolocation" accent="#0fbcff" noPad>
                <ErrorBoundary label="Geolocation map">
                  <Suspense fallback={<LazyFallback height={260}/>}>
                    <MapTab result={result}/>
                  </Suspense>
                </ErrorBoundary>
                {/* Geopolitical context — country + ASN breakdown +
                    nation-state attribution hints. Rolled into the
                    Geolocation card so geographic signals live in one
                    place. Renders nothing when there's no data. */}
                {(() => {
                  const gp = result?.geopolitical;
                  const has = !!(gp && !gp.error
                    && (gp.countries?.length || gp.attribution));
                  if (!has) return null;
                  return (
                    <Box sx={{ p: 2,
                      borderTop: `1px solid ${muiAlpha('#ffffff', 0.08)}` }}>
                      <ErrorBoundary label="Geopolitical context">
                        <GeopoliticalContext result={result} bare/>
                      </ErrorBoundary>
                    </Box>
                  );
                })()}
              </Card>
            )}
          </>
        )}

        {result && view === 'detail' && (
          <>
            <PreFlight result={result}/>
            <SignalBanners result={result}/>
            {/* Collapsible detail stack, keyed by run so each new investigation
                resets to collapsed. Card order mirrors a SOC/MDR analyst's
                actual triage flow: verdict first, then evidence, then the
                outgoing artefacts (detection rules), then the interactive
                follow-up tools (Geolocation, Ask RECON). */}
            <CardDefaultOpenContext.Provider value={false} key={result.runId || 'detail'}>
            {/* Card order (analyst-flow):
                1. Summary  — verdict + threat score + train-on-false-positives
                              (the feedback form is inline at the bottom of Summary
                              so the analyst sees the verdict and the correction
                              surface together)
                2. Ask RECON — interactive probing questions
                3. Triage    — deep evidence dive
                4. Geolocation — map (only when IPs are present)
                5. Detection  — SIEM-ready rules
                EmailAnalysis still slots in when an EML is present. */}
            <ErrorBoundary label="Summary">
              <AnalystSummary
                result={result} rs={rs || {}}
                onFeedbackStart={() => setAnalyzing(true)}
                onFeedbackPartial={mergePartial}
                onFeedbackComplete={(r) => { setAnalyzing(false); setResult(r); }}
              />
            </ErrorBoundary>
            <ErrorBoundary label="Ask RECON">
              <ChatWithRecon
                result={result}
                onFeedbackStart={() => setAnalyzing(true)}
                onFeedbackPartial={mergePartial}
                onFeedbackComplete={(r) => { setAnalyzing(false); setResult(r); }}
              />
            </ErrorBoundary>
            <ErrorBoundary label="Triage detail"><Triage result={result} rs={rs || {}}/></ErrorBoundary>
            <ErrorBoundary label="Email analysis"><EmailAnalysis result={result}/></ErrorBoundary>
            {(result?.iocs?.ips || []).length > 0 && (
              <Card title="Geolocation" accent="#0fbcff" noPad>
                <ErrorBoundary label="Geolocation map">
                  <Suspense fallback={<LazyFallback height={260}/>}>
                    <MapTab result={result}/>
                  </Suspense>
                </ErrorBoundary>
                {/* Geopolitical context — country + ASN breakdown +
                    nation-state attribution hints. Rolled into the
                    Geolocation card so geographic signals live in one
                    place. Renders nothing when there's no data. */}
                {(() => {
                  const gp = result?.geopolitical;
                  const has = !!(gp && !gp.error
                    && (gp.countries?.length || gp.attribution));
                  if (!has) return null;
                  return (
                    <Box sx={{ p: 2,
                      borderTop: `1px solid ${muiAlpha('#ffffff', 0.08)}` }}>
                      <ErrorBoundary label="Geopolitical context">
                        <GeopoliticalContext result={result} bare/>
                      </ErrorBoundary>
                    </Box>
                  );
                })()}
              </Card>
            )}
            <Detection result={result}/>
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
