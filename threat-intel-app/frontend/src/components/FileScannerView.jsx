/**
 * Adapted from OpenCTI (AGPL-3.0) github.com/OpenCTI-Platform/opencti
 *
 * RECON File Scanner — single-page scrollable analyst report (spec §3).
 *
 * Layout: sticky header at top (filename + classification + verdict +
 * action buttons) → 15 stacked sections flowing down → sticky right-side
 * section navigator on desktop. No tabs anywhere. Every Paper / Chip /
 * Typography pulls from theme.palette so the page matches the rest of
 * RECON's OpenCTI-derived aesthetic.
 */
import React, { useState, useRef, useEffect, useMemo, useCallback } from 'react';
import {
  Box, Stack, Typography, Paper as MuiPaper,
  Button as MuiButton, Chip as MuiChip, TextField as MuiTextField,
  IconButton as MuiIconButton, Table as MuiTable, TableHead, TableBody,
  TableRow, TableCell, Tooltip, LinearProgress,
} from '@mui/material';
import { alpha as muiAlpha, useTheme } from '@mui/material/styles';
import { Skeleton, SkeletonFileScanner } from './Skeleton';
import URLScanLive from './URLScanLive';
import {
  FileSearch, Copy, Check, Search, Download,
  ArrowUpRight, AlertTriangle, Shield, Play, Plus,
  FileText, ChevronRight, RotateCcw,
} from 'lucide-react';

// ─── verdict / severity color helper (uses theme tokens) ──────────────────────
const verdictColor = (theme, v) => ({
  MALICIOUS:   theme.palette.severity?.critical || '#EE3838',
  SUSPICIOUS:  theme.palette.severity?.high     || '#E6700F',
  LOW:         theme.palette.severity?.medium   || '#E1B823',
  CLEAN:       theme.palette.severity?.low      || '#16AD34',
  UNKNOWN:     theme.palette.text?.tertiary     || '#848592',
}[v] || theme.palette.text?.tertiary || '#848592');

const ANALYSIS_STEPS = [
  'Receiving file',
  'Detecting file type',
  'Computing hashes',
  'Extracting strings',
  'Analyzing structure',
  'Running YARA rules',
  'Correlating threat intel',
  'AI triage',
  'AI deep analysis',
  'Building report',
];

// File analyzer sections in display order. Hunting Leads, Recommended
// Actions, Notes & Refinement, Format-Specific and standalone YARA were
// removed per analyst request — YARA now lives inside Detection Content.
const SECTIONS = [
  { id: 'verdict',     label: 'AI Verdict' },
  { id: 'technical',   label: 'Technical Assessment' },
  { id: 'narrative',   label: 'Execution Narrative' },
  { id: 'findings',    label: 'Key Findings' },
  { id: 'identity',    label: 'File Identity' },
  { id: 'ti',          label: 'Threat Intelligence' },
  { id: 'caps',        label: 'Behavioral Capabilities' },
  { id: 'strings',     label: 'Strings & IOCs' },
  { id: 'detect',      label: 'Detection Content' },
];

const monoSx = { fontFamily: '"IBM Plex Mono", monospace' };


// ─── tiny utilities ───────────────────────────────────────────────────────────
function CopyBtn({ text, label = 'Copy' }) {
  const [copied, setCopied] = useState(false);
  return (
    <Tooltip title={copied ? 'Copied' : label}>
      <MuiIconButton size="small" onClick={(e) => {
        e.stopPropagation();
        navigator.clipboard.writeText(text || '');
        setCopied(true);
        setTimeout(() => setCopied(false), 1500);
      }} sx={{ p: 0.5, color: copied ? 'success.main' : 'text.tertiary',
        '&:hover': { color: 'primary.main' } }}>
        {copied ? <Check size={12}/> : <Copy size={12}/>}
      </MuiIconButton>
    </Tooltip>
  );
}

function downloadText(name, text) {
  const blob = new Blob([text], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = name; a.click();
  URL.revokeObjectURL(url);
}


// ─── RECON-styled card wrapper (collapsible) ─────────────────────────────────
// Mirrors the log-analysis Card pattern: clickable header with chevron, body
// renders inside an MUI Collapse. `defaultOpen` controls the initial state;
// `summary` is a small right-aligned indicator the analyst can read at a
// glance without expanding (e.g. "3 matches", "MALICIOUS", "clean").
//
// The expand / collapse state lives in component state and persists for the
// lifetime of the result (until a new file is scanned).
function SectionCard({
  id,
  label,
  accent,
  children,
  sx,
  defaultPad = true,
  defaultOpen = true,
  summary = null,
}) {
  const theme = useTheme();
  const [open, setOpen] = useState(defaultOpen);
  return (
    <Box id={`section-${id}`} sx={{ scrollMarginTop: 88 }}>
      <Box
        onClick={() => setOpen(o => !o)}
        sx={{
          display: 'flex', alignItems: 'center', cursor: 'pointer',
          gap: 1, mb: 1, pl: 0.5, userSelect: 'none',
          '&:hover .recon-section-label': { color: accent || 'text.primary' },
        }}
      >
        <Box sx={{
          color: accent || 'text.tertiary',
          transform: open ? 'rotate(90deg)' : 'rotate(0deg)',
          transition: 'transform 0.18s ease',
          display: 'flex', alignItems: 'center',
        }}>
          <ChevronRight size={12}/>
        </Box>
        <Typography
          className="recon-section-label"
          sx={{
            fontSize: 10, color: accent || 'text.tertiary', fontWeight: 600,
            textTransform: 'uppercase', letterSpacing: '0.1em',
            transition: 'color 0.18s ease',
          }}
        >
          {label}
        </Typography>
        {summary != null && summary !== '' && (
          <Typography sx={{
            fontSize: 10, color: 'text.tertiary', fontWeight: 500,
            ml: 'auto', pr: 0.5,
            textTransform: 'none', letterSpacing: '0.02em',
          }}>
            {summary}
          </Typography>
        )}
      </Box>
      {open && (
        <MuiPaper elevation={0} sx={{
          backgroundColor: theme.palette.background.paper,
          border: `1px solid ${muiAlpha('#ffffff', 0.08)}`,
          borderLeft: accent ? `3px solid ${accent}` : `1px solid ${muiAlpha('#ffffff', 0.08)}`,
          borderRadius: '4px',
          p: defaultPad ? 2 : 0,
          ...sx,
        }}>{children}</MuiPaper>
      )}
    </Box>
  );
}


// ─── 0. URL Reputation Report (URL scans only) ───────────────────────────────
// Analyst-decision-first layout. Aggregate header tells you "should I clear
// this" before the per-source detail. Sources are grouped by purpose
// (Reputation / Identity / Infrastructure) so you scan top-down rather than
// hunting through a flat list. Each source renders its actual fields in a
// structured row layout — never a raw JSON dump.
function _defangHost(h) {
  return (h || '').replace(/\./g, '[.]');
}
function _defangUrl(u) {
  if (!u) return '';
  return u.replace(/^https?:\/\//i, m => m.toLowerCase().startsWith('https') ? 'hxxps://' : 'hxxp://')
          .replace(/\./g, '[.]');
}
function _formatDate(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (isNaN(d)) return iso;
  return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

// One detail row inside a source card. Stack-style: label on top in
// dim caps, value below in primary text. Reads cleaner than the old
// 140px-label-grid layout on long values (URLs, name-server lists).
function ReportField({ label, value, mono = false, color }) {
  if (value == null || value === '') return null;
  return (
    <Box sx={{ py: 0.5,
      '&:not(:last-child)': {
        borderBottom: `1px solid ${muiAlpha('#ffffff', 0.04)}`,
      },
    }}>
      <Typography sx={{
        fontSize: 9.5, color: 'text.disabled', fontWeight: 600,
        textTransform: 'uppercase', letterSpacing: '0.08em',
        mb: 0.25,
      }}>{label}</Typography>
      <Typography sx={{
        fontSize: 12, color: color || 'text.primary',
        wordBreak: 'break-all', lineHeight: 1.4,
        fontFamily: mono ? '"IBM Plex Mono", monospace' : undefined,
      }}>{value}</Typography>
    </Box>
  );
}

// One collapsible source card. Header is always visible (chevron + title +
// optional count + status pill); body collapses. Default closed so the
// analyst opens only the sources they want to investigate — verdict
// drivers in the top panel already summarise the why.
function CollapsibleSource({
  title, status, statusColor = '#848592', count,
  defaultOpen = false, children,
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <MuiPaper elevation={0} sx={{
      backgroundColor: '#0C1524',
      border: `1px solid ${muiAlpha('#ffffff', 0.10)}`,
      borderLeft: `3px solid ${muiAlpha(statusColor, 0.7)}`,
      borderRadius: '4px',
      overflow: 'hidden',
    }}>
      <Box onClick={() => setOpen(o => !o)} sx={{
        display: 'flex', alignItems: 'center', gap: 1.25,
        p: '9px 14px',
        cursor: 'pointer', userSelect: 'none',
        '&:hover': { backgroundColor: muiAlpha('#ffffff', 0.025) },
      }}>
        <Box sx={{
          color: 'text.tertiary', opacity: 0.55,
          transform: open ? 'rotate(90deg)' : 'rotate(0deg)',
          transition: 'transform 0.18s ease',
          display: 'flex', alignItems: 'center',
        }}>
          <ChevronRight size={11}/>
        </Box>
        <Typography sx={{
          fontSize: 11.5, color: 'text.primary', fontWeight: 600,
          textTransform: 'uppercase', letterSpacing: '0.06em', flex: 1,
        }}>
          {title}
        </Typography>
        {count != null && (
          <Typography sx={{ fontSize: 10.5, color: 'text.tertiary' }}>
            {count}
          </Typography>
        )}
        {status && (
          <Box sx={{
            px: 0.875, py: 0.25,
            backgroundColor: muiAlpha(statusColor, 0.18),
            color: statusColor,
            border: `1px solid ${muiAlpha(statusColor, 0.4)}`,
            borderRadius: '3px',
            fontSize: 9.5, fontWeight: 700,
            textTransform: 'uppercase', letterSpacing: '0.06em',
            whiteSpace: 'nowrap',
          }}>
            {status}
          </Box>
        )}
      </Box>
      {open && (
        <Box sx={{
          p: '10px 14px 12px 14px',
          borderTop: `1px solid ${muiAlpha('#ffffff', 0.06)}`,
        }}>
          {children}
        </Box>
      )}
    </MuiPaper>
  );
}

function GroupHeader({ children }) {
  return (
    <Typography sx={{
      fontSize: 10, color: 'text.disabled', fontWeight: 600,
      textTransform: 'uppercase', letterSpacing: '0.12em',
      mb: 1.25, mt: 0.5,
    }}>{children}</Typography>
  );
}

function UrlReputationReport({ result }) {
  const url    = result.source_url || '';
  let host = '';
  try { host = new URL(url).hostname; } catch { host = ''; }

  const dom = result?.enrichments?.domains?.[host] || {};
  const urlEnr = result?.enrichments?.urls?.[url] || {};

  const vt          = dom.virustotal || urlEnr.virustotal || null;
  const urlscan     = dom.urlscan    || urlEnr.urlscan    || null;
  const whois       = dom.whois || null;
  const crt         = dom.certTransparency || null;
  const otx         = dom.otx || null;
  const pulsedive   = dom.pulsedive || null;
  const maltiverse  = dom.maltiverse || null;
  const spamhaus    = dom.spamhaus_dbl || null;
  const dnsRecords  = dom.osint?.dns_records || null;
  const bgp         = dom.osint?.bgp_ranking || null;
  const safeBrowse  = dom.osint?.google_safebrowsing || null;
  const wayback     = dom.wayback || null;

  // ── Aggregate verdict + top drivers ──────────────────────────────────────
  // Counts a source as "responded" only when it returned data. Picks the
  // 2-3 strongest drivers behind the verdict so the analyst sees the why
  // without expanding anything.
  const drivers = [];
  let signalCount = 0;
  if (vt && !vt.error) {
    signalCount++;
    const mal = vt.malicious ?? 0;
    const susp = vt.suspicious ?? 0;
    const total = (vt.harmless ?? 0) + (vt.undetected ?? 0) + mal + susp;
    if (mal > 0) drivers.push({ text: `VirusTotal ${mal}/${total || '?'} flagged malicious`, weight: mal * 10, color: '#EE3838' });
    else if (susp > 0) drivers.push({ text: `VirusTotal ${susp} engines suspicious`, weight: 5, color: '#E6700F' });
    else if (total > 0) drivers.push({ text: `VirusTotal clean (0/${total})`, weight: -5, color: '#16AD34' });
  }
  if (otx && !otx.error && (otx.pulseCount > 0 || otx.pulse_count > 0)) {
    signalCount++;
    const c = otx.pulseCount ?? otx.pulse_count ?? 0;
    drivers.push({ text: `OTX ${c} threat pulse${c === 1 ? '' : 's'}`, weight: c * 3, color: c >= 3 ? '#EE3838' : '#E6700F' });
  }
  if (spamhaus?.hit) {
    signalCount++;
    drivers.push({ text: `Spamhaus DBL listed (${spamhaus.verdict || 'malicious'})`, weight: 30, color: '#EE3838' });
  }
  if (maltiverse && !maltiverse.error) {
    signalCount++;
    if (/malicious/i.test(maltiverse.classification || '')) {
      drivers.push({ text: `Maltiverse malicious${maltiverse.tag?.length ? ` (${maltiverse.tag.slice(0,2).join(', ')})` : ''}`, weight: 20, color: '#EE3838' });
    }
  }
  if (safeBrowse?.verdict && safeBrowse.verdict !== 'CLEAN') {
    signalCount++;
    drivers.push({ text: `Google Safe Browsing: ${safeBrowse.verdict}`, weight: 25, color: '#EE3838' });
  }
  if (whois && !whois.error && whois.age_days != null) {
    signalCount++;
    if (whois.age_days < 1)   drivers.push({ text: `Domain registered today (${whois.age_days}d old)`, weight: 30, color: '#EE3838' });
    else if (whois.age_days < 30) drivers.push({ text: `Newly-registered domain (${whois.age_days}d old)`, weight: 15, color: '#E6700F' });
    else if (whois.age_days > 365 * 3) drivers.push({ text: `Long-established domain (${Math.floor(whois.age_days / 365)}y old)`, weight: -8, color: '#16AD34' });
  }
  if (urlscan) signalCount++;
  if (crt && (crt.totalCerts || 0) > 0) signalCount++;
  if (dnsRecords) signalCount++;
  if (bgp) signalCount++;

  // Evidence-driven verdict — the previous "50 baseline" math meant a
  // single clean driver (VirusTotal 0/56) scored 45/100 SUSPICIOUS, which
  // is wrong. Now the verdict follows what the drivers actually say: if
  // there is no malicious evidence, the URL is CLEAN (or UNKNOWN when no
  // source returned data). Score is purely informational alongside.
  const positives = drivers.filter(d => d.weight > 0).reduce((s, d) => s + d.weight, 0);
  const negatives = drivers.filter(d => d.weight < 0).reduce((s, d) => s + d.weight, 0);
  const hasMalSignal   = positives > 0;
  const hasCleanSignal = negatives < 0;
  const strongMal      = drivers.some(d => d.weight >= 25);
  const weakMal        = drivers.some(d => d.weight >= 10 && d.weight < 25);
  const score = hasMalSignal
    ? Math.max(0, Math.min(100, positives + 20 + negatives))
    : (hasCleanSignal ? Math.max(0, 10 + negatives) : 0);
  const verdict = strongMal
    ? { label: 'MALICIOUS',  color: '#EE3838' }
    : weakMal
      ? { label: 'SUSPICIOUS', color: '#E6700F' }
      : hasMalSignal
        ? { label: 'WATCH',  color: '#E1B823' }
        : hasCleanSignal
          ? { label: 'CLEAN',   color: '#16AD34' }
          : { label: 'UNKNOWN', color: '#848592' };
  const topDrivers = [...drivers].sort((a, b) => Math.abs(b.weight) - Math.abs(a.weight)).slice(0, 3);

  // Headline-row factoids previously lived here but they're now rendered
  // in the top-of-page URL identity banner in the URL-scan branch. Keep
  // an empty list so the factoids-block render below short-circuits and
  // doesn't paint a duplicate.
  const factoids = [];

  // ── helpers for per-source status pills ─────────────────────────────────
  const sourceState = (data, malicious) => {
    if (!data || data.error || (typeof data === 'object' && Object.keys(data).length === 0))
      return { status: data?.error ? 'error' : 'no data', color: '#848592' };
    if (malicious === true)  return { status: 'malicious', color: '#EE3838' };
    if (malicious === false) return { status: 'clean',     color: '#16AD34' };
    return { status: 'ok', color: '#0fbcff' };
  };

  // ── render ──────────────────────────────────────────────────────────────
  return (
    <Box>
      {/* Headline panel — verdict pill with inline score, host on its own
          row, URL clamped to two lines so a marketing tracker-laden URL
          can't push the whole panel 4 lines tall. */}
      <MuiPaper elevation={0} sx={{
        backgroundColor: '#09253d',
        border: `1px solid ${muiAlpha(verdict.color, 0.35)}`,
        borderLeft: `3px solid ${verdict.color}`,
        borderRadius: '4px', p: '14px 18px', mb: 2,
      }}>
        <Stack direction="row" alignItems="center" spacing={1.25}
          sx={{ mb: host || url ? 1.25 : 0 }} flexWrap="wrap">
          <Box sx={{
            display: 'inline-flex', alignItems: 'baseline', gap: 1,
            px: 1.25, py: 0.5,
            backgroundColor: muiAlpha(verdict.color, 0.15),
            border: `1px solid ${muiAlpha(verdict.color, 0.5)}`,
            borderRadius: '3px',
          }}>
            <Typography sx={{ fontSize: 13, fontWeight: 700,
              color: verdict.color, letterSpacing: '0.05em' }}>
              {verdict.label}
            </Typography>
            <Typography sx={{ fontSize: 12, color: verdict.color,
              ...monoSx, opacity: 0.85 }}>
              {score}/100
            </Typography>
          </Box>
          <Typography sx={{ fontSize: 11, color: 'text.tertiary' }}>
            {signalCount} source{signalCount === 1 ? '' : 's'} responded
          </Typography>
        </Stack>
        {host && (
          <Typography sx={{ fontSize: 13, color: 'text.primary',
            fontWeight: 500, ...monoSx, mb: 0.25, wordBreak: 'break-all' }}>
            {_defangHost(host)}
          </Typography>
        )}
        <Typography sx={{ ...monoSx, fontSize: 11, color: 'text.disabled',
          wordBreak: 'break-all',
          display: '-webkit-box',
          WebkitLineClamp: 2,
          WebkitBoxOrient: 'vertical',
          overflow: 'hidden' }}>
          {_defangUrl(url)}
        </Typography>
        {topDrivers.length > 0 && (
          <Box sx={{ mt: 1.5, pt: 1.5,
            borderTop: `1px solid ${muiAlpha('#ffffff', 0.08)}` }}>
            <Stack spacing={0.5}>
              {topDrivers.map((d, i) => (
                <Stack key={i} direction="row" alignItems="center" spacing={1}>
                  <Box sx={{ width: 5, height: 5, borderRadius: 99,
                    backgroundColor: d.color, flexShrink: 0 }}/>
                  <Typography sx={{ fontSize: 12, color: 'text.primary' }}>
                    {d.text}
                  </Typography>
                </Stack>
              ))}
            </Stack>
          </Box>
        )}

        {/* Headline factoids — WHOIS registration date + last Wayback
            snapshot so the analyst can place the domain in time without
            scrolling to the per-source cards below. */}
        {factoids.length > 0 && (
          <Box sx={{ mt: topDrivers.length ? 1.5 : 1.5,
            pt: topDrivers.length ? 1.5 : 0,
            borderTop: topDrivers.length
              ? `1px solid ${muiAlpha('#ffffff', 0.08)}` : 'none' }}>
            <Box sx={{
              display: 'grid',
              gridTemplateColumns: { xs: '1fr', sm: 'repeat(2, 1fr)' },
              gap: '6px 18px',
            }}>
              {factoids.map((f, i) => (
                <Box key={i}>
                  <Typography sx={{ fontSize: 10, color: 'text.disabled',
                    fontWeight: 600, textTransform: 'uppercase',
                    letterSpacing: '0.07em' }}>
                    {f.label}
                  </Typography>
                  <Typography sx={{ fontSize: 12, color: 'text.primary',
                    ...monoSx, wordBreak: 'break-word' }}>
                    {f.value}
                  </Typography>
                </Box>
              ))}
            </Box>
          </Box>
        )}
      </MuiPaper>

      {/* ── REPUTATION group ───────────────────────────────────────────── */}
      <GroupHeader>Reputation</GroupHeader>
      <Stack spacing={1.25} sx={{ mb: 2.5 }}>
        {/* VirusTotal */}
        {(() => {
          const mal = vt?.malicious ?? 0;
          const susp = vt?.suspicious ?? 0;
          const harm = vt?.harmless ?? 0;
          const undet = vt?.undetected ?? 0;
          const total = mal + susp + harm + undet;
          const st = sourceState(vt, mal > 0 ? true : total > 0 ? false : null);
          return (
            <CollapsibleSource title="VirusTotal"
              status={total ? `${mal}/${total} flagged` : st.status}
              statusColor={st.color}>
              {vt && !vt.error && total > 0 ? (
                <Box>
                  <ReportField label="Detection ratio" value={`${mal + susp} / ${total}`} mono
                    color={st.color}/>
                  <ReportField label="Breakdown" mono
                    value={`${mal} malicious · ${susp} suspicious · ${harm} harmless · ${undet} undetected`}/>
                  {vt.reputation != null && <ReportField label="Community" mono
                    value={String(vt.reputation)}/>}
                  {vt.categories && Object.values(vt.categories).length > 0 && (
                    <ReportField label="Categories"
                      value={[...new Set(Object.values(vt.categories))].slice(0, 4).join(', ')}/>
                  )}
                  {vt.creation_date && (
                    <ReportField label="VT first seen" value={_formatDate(
                      typeof vt.creation_date === 'number'
                        ? new Date(vt.creation_date * 1000).toISOString()
                        : vt.creation_date)}/>
                  )}
                </Box>
              ) : (
                <Typography sx={{ fontSize: 12, color: 'text.tertiary', fontStyle: 'italic' }}>
                  {vt?.error ? `error: ${vt.error}` : 'No data returned for this URL.'}
                </Typography>
              )}
            </CollapsibleSource>
          );
        })()}

        {/* OTX */}
        {(() => {
          const c = otx?.pulseCount ?? otx?.pulse_count ?? 0;
          const st = sourceState(otx, c > 0 ? true : null);
          const status = otx?.error ? 'error' : c > 0 ? `${c} pulses` : 'no pulses';
          return (
            <CollapsibleSource title="AlienVault OTX"
              status={status} statusColor={st.color}>
              {c > 0 ? (
                <Box>
                  <ReportField label="Pulse count" value={`${c}`} mono color={st.color}/>
                  {Array.isArray(otx.relatedPulses) && otx.relatedPulses.length > 0 && (
                    <ReportField label="Recent pulses"
                      value={otx.relatedPulses.slice(0, 3).join(' · ')}/>
                  )}
                </Box>
              ) : (
                <Typography sx={{ fontSize: 12, color: 'text.tertiary', fontStyle: 'italic' }}>
                  {otx?.error ? `error: ${otx.error}` : 'No threat intelligence pulses found.'}
                </Typography>
              )}
            </CollapsibleSource>
          );
        })()}

        {/* Maltiverse */}
        {(() => {
          const cls = maltiverse?.classification || '';
          const isBad = /malicious|suspicious/i.test(cls);
          const st = sourceState(maltiverse, isBad);
          return (
            <CollapsibleSource title="Maltiverse"
              status={cls || st.status} statusColor={st.color}>
              {maltiverse && !maltiverse.error && cls ? (
                <Box>
                  <ReportField label="Classification" value={cls} color={st.color}/>
                  {maltiverse.tag?.length > 0 && (
                    <ReportField label="Tags" value={maltiverse.tag.slice(0, 6).join(', ')}/>
                  )}
                  {maltiverse.blacklist?.length > 0 && (
                    <ReportField label="Blacklists"
                      value={maltiverse.blacklist.slice(0, 4).join(', ')}/>
                  )}
                  {maltiverse.first_seen && (
                    <ReportField label="First seen" value={_formatDate(maltiverse.first_seen)}/>
                  )}
                </Box>
              ) : (
                <Typography sx={{ fontSize: 12, color: 'text.tertiary', fontStyle: 'italic' }}>
                  {maltiverse?.error ? `error: ${maltiverse.error}` : 'No data returned.'}
                </Typography>
              )}
            </CollapsibleSource>
          );
        })()}

        {/* Spamhaus DBL */}
        {spamhaus && (
          <CollapsibleSource title="Spamhaus DBL"
            status={spamhaus.hit ? 'listed' : 'clean'}
            statusColor={spamhaus.hit ? '#EE3838' : '#16AD34'}>
            {spamhaus.hit ? (
              <Box>
                <ReportField label="Verdict" value={spamhaus.verdict || 'listed'} color="#EE3838"/>
                {spamhaus.code && <ReportField label="DNSBL code" value={spamhaus.code} mono/>}
                {spamhaus.label && <ReportField label="Label" value={spamhaus.label}/>}
              </Box>
            ) : (
              <Typography sx={{ fontSize: 12, color: 'text.tertiary', fontStyle: 'italic' }}>
                Domain not on the Spamhaus blocklist.
              </Typography>
            )}
          </CollapsibleSource>
        )}

        {/* Pulsedive (only when something to show) */}
        {pulsedive && !pulsedive.error && pulsedive.risk && pulsedive.risk !== 'none' && (
          <CollapsibleSource title="Pulsedive"
            status={`risk ${pulsedive.risk}`}
            statusColor={/critical|high/i.test(pulsedive.risk) ? '#EE3838'
              : /medium|moderate/i.test(pulsedive.risk) ? '#E6700F' : '#E1B823'}>
            <ReportField label="Risk level" value={pulsedive.risk}/>
            {pulsedive.threats?.length > 0 && (
              <ReportField label="Threats" value={pulsedive.threats.slice(0, 4).join(', ')}/>
            )}
          </CollapsibleSource>
        )}

        {/* Google Safe Browsing (only when something to show) */}
        {safeBrowse?.verdict && (
          <CollapsibleSource title="Google Safe Browsing"
            status={safeBrowse.verdict}
            statusColor={safeBrowse.verdict === 'MALICIOUS' ? '#EE3838' : '#16AD34'}>
            <ReportField label="Verdict" value={safeBrowse.verdict}/>
            {safeBrowse.threat_types?.length > 0 && (
              <ReportField label="Threat types" value={safeBrowse.threat_types.join(', ')}/>
            )}
            <ReportField label="Matches" mono value={String(safeBrowse.match_count || 0)}/>
          </CollapsibleSource>
        )}
      </Stack>

      {/* ── IDENTITY group ─────────────────────────────────────────────── */}
      <GroupHeader>Identity</GroupHeader>
      <Stack spacing={1.25} sx={{ mb: 2.5 }}>
        {/* WHOIS — the big one. */}
        {(() => {
          const age = whois?.age_days;
          const ageColor = age == null ? '#848592'
            : age < 1   ? '#EE3838'
            : age < 30  ? '#E6700F'
            : age < 180 ? '#E1B823'
            :             '#16AD34';
          const st = whois && !whois.error
            ? { status: age != null ? `${age}d old` : 'ok', color: ageColor }
            : sourceState(whois, null);
          return (
            <CollapsibleSource title="WHOIS" status={st.status} statusColor={st.color}>
              {whois && !whois.error ? (
                <Box>
                  {whois.registrar && <ReportField label="Registrar" value={whois.registrar}/>}
                  {whois.registrant_org && (
                    <ReportField label="Registrant" value={whois.registrant_org}/>
                  )}
                  {whois.registrant_country && (
                    <ReportField label="Country" value={whois.registrant_country} mono/>
                  )}
                  {whois.privacy_protected && (
                    <ReportField label="Privacy" value="Redacted / withheld" color="#E1B823"/>
                  )}
                  {whois.created && (
                    <ReportField label="Created"
                      value={`${_formatDate(whois.created)}${age != null ? ` (${age}d ago)` : ''}`}
                      color={ageColor}/>
                  )}
                  {whois.updated && (
                    <ReportField label="Updated" value={_formatDate(whois.updated)}/>
                  )}
                  {whois.expires && (
                    <ReportField label="Expires"
                      value={`${_formatDate(whois.expires)}${whois.days_to_expiry != null ? ` (${whois.days_to_expiry}d)` : ''}`}/>
                  )}
                  {whois.registrant_email && (
                    <ReportField label="Emails" value={whois.registrant_email} mono/>
                  )}
                  {whois.name_servers?.length > 0 && (
                    <ReportField label="Name servers"
                      value={whois.name_servers.join(' · ')} mono/>
                  )}
                  {whois.status?.length > 0 && (
                    <ReportField label="Status" value={whois.status.slice(0, 3).join(' · ')} mono/>
                  )}
                </Box>
              ) : (
                <Typography sx={{ fontSize: 12, color: 'text.tertiary', fontStyle: 'italic' }}>
                  {whois?.error ? `error: ${whois.error}` : 'No WHOIS data returned.'}
                </Typography>
              )}
            </CollapsibleSource>
          );
        })()}

        {/* Certificate Transparency */}
        {crt && (
          <CollapsibleSource title="Certificate Transparency"
            status={`${crt.totalCerts || 0} cert${(crt.totalCerts || 0) === 1 ? '' : 's'}`}
            statusColor="#0fbcff"
            count={crt.subdomains?.length ? `${crt.subdomains.length} subdomains` : null}>
            {crt.subdomains?.length > 0 && (
              <Box>
                <ReportField label="Subdomains" value={crt.subdomains.slice(0, 6).join(' · ')} mono/>
              </Box>
            )}
            {Array.isArray(crt.recent) && crt.recent.length > 0 && (
              <Box sx={{ mt: crt.subdomains?.length > 0 ? 1 : 0 }}>
                <Typography sx={{ fontSize: 9.5, color: 'text.disabled', fontWeight: 600,
                  textTransform: 'uppercase', letterSpacing: '0.08em', mb: 0.5 }}>
                  Recent certificates
                </Typography>
                {crt.recent.slice(0, 4).map((c, i) => (
                  <Box key={i} sx={{ py: 0.5,
                    borderTop: i > 0 ? `1px solid ${muiAlpha('#ffffff', 0.05)}` : 'none' }}>
                    <Typography sx={{ ...monoSx, fontSize: 11, color: 'text.primary' }}>
                      {c.name_value || c.common_name || '?'}
                    </Typography>
                    <Typography sx={{ fontSize: 10, color: 'text.tertiary' }}>
                      {c.issuer_name && <>{c.issuer_name} · </>}
                      {c.not_before && `from ${_formatDate(c.not_before)}`}
                      {c.not_after  && ` · to ${_formatDate(c.not_after)}`}
                    </Typography>
                  </Box>
                ))}
              </Box>
            )}
          </CollapsibleSource>
        )}

        {/* Passive DNS (DNS records) */}
        {dnsRecords?.total_records > 0 && (
          <CollapsibleSource title="DNS Records"
            status={`${dnsRecords.total_records} record${dnsRecords.total_records === 1 ? '' : 's'}`}
            statusColor="#0fbcff">
            {Object.entries(dnsRecords.records || {}).slice(0, 6).map(([rt, vals]) => (
              <ReportField key={rt} label={rt} value={(vals || []).join(', ')} mono/>
            ))}
          </CollapsibleSource>
        )}

        {/* Wayback archive presence */}
        {wayback && (wayback.has_snapshots != null || wayback.first_snapshot) && (
          <CollapsibleSource title="Wayback Machine"
            status={wayback.has_snapshots ? `${wayback.snapshot_count || ''} snapshots`.trim() : 'no snapshots'}
            statusColor={wayback.has_snapshots ? '#16AD34' : '#E6700F'}>
            {wayback.first_snapshot && (
              <ReportField label="First snapshot" value={_formatDate(wayback.first_snapshot)}/>
            )}
            {wayback.last_snapshot && (
              <ReportField label="Last snapshot" value={_formatDate(wayback.last_snapshot)}/>
            )}
            {!wayback.first_snapshot && !wayback.last_snapshot && (
              <Typography sx={{ fontSize: 12, color: 'text.tertiary', fontStyle: 'italic' }}>
                No snapshots archived for this URL.
              </Typography>
            )}
          </CollapsibleSource>
        )}
      </Stack>

      {/* ── INFRASTRUCTURE group ───────────────────────────────────────── */}
      {(urlscan || bgp) && (
        <>
          <GroupHeader>Infrastructure</GroupHeader>
          <Stack spacing={1.25} sx={{ mb: 2.5 }}>
            {/* URLScan.io */}
            {urlscan && (
              <CollapsibleSource title="URLScan.io"
                status={urlscan.total ? `${urlscan.total} scans` : 'no scans'}
                statusColor={urlscan.total ? '#0fbcff' : '#848592'}>
                {urlscan.total ? (
                  <Box>
                    {urlscan.last_scan_date && (
                      <ReportField label="Last scan" value={_formatDate(urlscan.last_scan_date)}/>
                    )}
                    {urlscan.malicious != null && (
                      <ReportField label="Malicious" value={String(urlscan.malicious)} mono
                        color={urlscan.malicious > 0 ? '#EE3838' : '#16AD34'}/>
                    )}
                    {urlscan.last_scan_url && (
                      <ReportField label="Report" value={urlscan.last_scan_url} mono/>
                    )}
                  </Box>
                ) : (
                  <Typography sx={{ fontSize: 12, color: 'text.tertiary', fontStyle: 'italic' }}>
                    No scans found for this domain.
                  </Typography>
                )}
              </CollapsibleSource>
            )}

            {/* BGP ranking */}
            {bgp && (
              <CollapsibleSource title="BGP / ASN (CIRCL)"
                status={bgp.rank != null ? `rank ${bgp.rank}` : 'ok'}
                statusColor="#0fbcff">
                {bgp.asn && <ReportField label="ASN" value={`AS${bgp.asn} · ${bgp.asn_description || ''}`}/>}
                {bgp.country && <ReportField label="Country" value={bgp.country} mono/>}
                {bgp.rank != null && (
                  <ReportField label="Rank" value={`${bgp.rank} (lower = worse reputation)`} mono/>
                )}
              </CollapsibleSource>
            )}
          </Stack>
        </>
      )}
    </Box>
  );
}


// Collapsible wrapper that pulls the malware-analysis sections together when
// a URL scan downloaded something with file-level signal (YARA hit, TI hit,
// or AI verdict MALICIOUS/SUSPICIOUS). Lets the analyst decide whether to
// dive into the downloaded-payload detail without forcing it on every URL.
function UrlFileAnalysisExpander({ result, onRefreshScan, autoOpen = false }) {
  const [open, setOpen] = useState(autoOpen);
  return (
    <MuiPaper elevation={0} sx={{
      backgroundColor: 'background.paper',
      border: `1px solid ${muiAlpha('#ffffff', 0.10)}`,
      borderRadius: '4px', overflow: 'hidden',
    }}>
      <Box onClick={() => setOpen(o => !o)} sx={{
        display: 'flex', alignItems: 'center', gap: 1.25, p: '12px 16px',
        cursor: 'pointer',
        '&:hover': { backgroundColor: muiAlpha('#ffffff', 0.02) },
      }}>
        <Box sx={{ width: 3, height: 14, backgroundColor: '#E6700F', borderRadius: 0.5 }}/>
        <Typography sx={{ fontSize: 12, color: 'text.primary', fontWeight: 600,
          textTransform: 'uppercase', letterSpacing: '0.06em' }}>
          Downloaded payload analysis
        </Typography>
        <Typography sx={{ fontSize: 11, color: 'text.tertiary', ml: 'auto !important' }}>
          {result.verdict || 'analysis'} · click to {open ? 'collapse' : 'expand'}
        </Typography>
        <ChevronRight size={14} color="#848592" style={{
          transition: 'transform .15s',
          transform: open ? 'rotate(90deg)' : 'none',
        }}/>
      </Box>
      {open && (
        <Box sx={{ p: '12px 16px 16px',
          borderTop: `1px solid ${muiAlpha('#ffffff', 0.08)}` }}>
          <Stack spacing={2.25}>
            <VerdictBanner result={result}/>
            <TechnicalAssessment result={result}/>
            <ExecutionNarrative result={result}/>
            <KeyFindings result={result}/>
            <FileIdentity result={result}/>
            <ThreatIntelSection result={result}/>
            <CapabilitiesSection result={result}/>
            <StringsSection result={result}/>
            <YaraSection result={result}/>
            <FormatSection result={result}/>
            <Anomalies result={result}/>
            <DetectionContent result={result}/>
            <HuntingLeads result={result}/>
            <ActionsSection result={result}/>
            <NotesAndRefinement result={result} onRefreshScan={onRefreshScan}/>
          </Stack>
        </Box>
      )}
    </MuiPaper>
  );
}


// ─── 1. AI Verdict Banner ─────────────────────────────────────────────────────
function VerdictBanner({ result }) {
  const theme = useTheme();
  const v = result.verdict || 'UNKNOWN';
  const triage = result.ai_analyst?.triage;
  const deep = result.ai_analyst?.deep;
  const cls = deep?.malware_classification?.category || triage?.classification || 'Unknown';
  const cls_conf = deep?.malware_classification?.confidence ?? triage?.confidence ?? null;
  const soph = deep?.sophistication_level?.level;
  const actor = deep?.threat_actor;
  const c = verdictColor(theme, v);
  const exec_text = deep?.executive_summary || result.ai_summary;

  return (
    <SectionCard id="verdict" label="AI Verdict" accent={c} defaultOpen={true}
      summary={result.verdict || null} sx={{
      background: `linear-gradient(135deg, ${muiAlpha(c, 0.08)} 0%, ${theme.palette.background.paper} 60%)`,
    }}>
      <Stack direction="row" alignItems="center" spacing={2} sx={{ mb: exec_text ? 1.5 : 0 }} flexWrap="wrap">
        <Box sx={{ ...monoSx, fontSize: 22, fontWeight: 700, color: c, lineHeight: 1 }}>
          {cls.toUpperCase()}
        </Box>
        <MuiChip label={v} size="small" sx={{
          backgroundColor: muiAlpha(c, 0.18), color: c, fontWeight: 600,
          fontSize: 11, height: 22,
        }}/>
        {cls_conf != null && (
          <Typography sx={{ fontSize: 12, color: 'text.tertiary' }}>
            confidence {Math.round(cls_conf * 100)}%
          </Typography>
        )}
        {soph && (
          <MuiChip label={soph} size="small" variant="outlined" sx={{
            fontSize: 11, height: 22, color: 'text.secondary',
            borderColor: muiAlpha('#ffffff', 0.18),
          }}/>
        )}
        {actor?.name && (
          <Typography sx={{ fontSize: 12, color: 'text.primary' }}>
            attributed: <Box component="span" sx={{ color: c, fontWeight: 600 }}>{actor.name}</Box>
            {actor.confidence != null && ` (${Math.round((actor.confidence || 0) * 100)}%)`}
          </Typography>
        )}
        <Box sx={{ ml: 'auto !important' }}>
          {exec_text && <CopyBtn text={exec_text} label="Copy executive summary"/>}
        </Box>
      </Stack>
      {exec_text && (
        <Typography sx={{ fontSize: 15, color: 'text.primary', lineHeight: 1.65 }}>
          {exec_text}
        </Typography>
      )}
      {!deep && !triage && (
        <AILoading text="AI analysis in progress…"/>
      )}
    </SectionCard>
  );
}


// ─── 2. Technical Assessment ─────────────────────────────────────────────────
function TechnicalAssessment({ result }) {
  const deep = result.ai_analyst?.deep;
  if (!deep && !result.ai_analyst) return null;
  const tech = deep?.technical_summary;
  const soph = deep?.sophistication_level;
  const vec  = deep?.infection_vector;
  return (
    <SectionCard id="technical" label="Technical Assessment" defaultOpen={false}
      summary={result?.ai_analyst?.deep?.technical_summary ? 'AI assessment' : null}>
      {!tech && <AILoading text="Synthesizing technical assessment…"/>}
      {tech && (
        <>
          <Typography sx={{ fontSize: 13, color: 'text.primary',
            lineHeight: 1.7, whiteSpace: 'pre-wrap' }}>
            {tech}
          </Typography>
          {(soph || vec) && (
            <Box sx={{ mt: 1.75, pt: 1.5,
              borderTop: `1px solid ${muiAlpha('#ffffff', 0.06)}`,
              display: 'grid', gridTemplateColumns: { xs: '1fr', md: '1fr 1fr' },
              gap: 1.5 }}>
              {soph && (
                <Box>
                  <Typography sx={{ fontSize: 10, color: 'text.tertiary',
                    textTransform: 'uppercase', letterSpacing: '0.06em', mb: 0.5 }}>
                    Sophistication
                  </Typography>
                  <Typography sx={{ fontSize: 13, color: 'text.primary', fontWeight: 600 }}>
                    {soph.level}
                  </Typography>
                  {soph.reasoning && (
                    <Typography sx={{ fontSize: 11, color: 'text.tertiary', mt: 0.5, lineHeight: 1.55 }}>
                      {soph.reasoning}
                    </Typography>
                  )}
                </Box>
              )}
              {vec && (
                <Box>
                  <Typography sx={{ fontSize: 10, color: 'text.tertiary',
                    textTransform: 'uppercase', letterSpacing: '0.06em', mb: 0.5 }}>
                    Infection vector
                  </Typography>
                  <Stack direction="row" alignItems="center" spacing={1}>
                    <ArrowUpRight size={13} color="#0fbcff"/>
                    <Typography sx={{ fontSize: 13, color: 'text.primary' }}>{vec}</Typography>
                  </Stack>
                </Box>
              )}
            </Box>
          )}
        </>
      )}
    </SectionCard>
  );
}


// ─── 3. Execution Narrative ──────────────────────────────────────────────────
function ExecutionNarrative({ result }) {
  const text = result.ai_analyst?.deep?.execution_narrative;
  if (!text && !result.ai_analyst) return null;
  return (
    <SectionCard id="narrative" label="Execution Narrative" accent="#B286FF" defaultOpen={false}
      summary={result?.ai_analyst?.deep?.execution_narrative ? 'narrative ready' : null}
      sx={{
      backgroundColor: muiAlpha('#B286FF', 0.04),
    }}>
      <Stack direction="row" alignItems="center" spacing={1} sx={{ mb: 1.25 }}>
        <Play size={14} color="#B286FF"/>
        <Typography sx={{ fontSize: 12, color: '#B286FF', fontWeight: 600,
          textTransform: 'uppercase', letterSpacing: '0.06em' }}>
          What this malware does
        </Typography>
      </Stack>
      {!text && <AILoading text="Walking through the execution path…"/>}
      {text && (
        <Typography sx={{ fontSize: 14, color: 'text.primary',
          lineHeight: 1.75, fontStyle: 'italic',
          whiteSpace: 'pre-wrap' }}>
          {text}
        </Typography>
      )}
    </SectionCard>
  );
}


// ─── 4. Key Findings (anomalies fused in) ────────────────────────────────────
function KeyFindings({ result }) {
  const deep = result.ai_analyst?.deep || {};
  const findings = (deep.key_findings || []).map(f => ({
    kind: 'finding',
    title: f.title || (typeof f === 'string' ? f : 'Finding'),
    body:  f.explanation || '',
  }));
  // Anomalies used to live in their own card; per analyst request they
  // now render inside Key Findings as anomaly-flagged rows.
  const anomalies = (deep.anomalies || []).map(a => ({
    kind: 'anomaly',
    title: a.observation || (typeof a === 'string' ? a : 'Anomaly'),
    body: [a.expected && `expected: ${a.expected}`,
           a.implication && `→ ${a.implication}`]
          .filter(Boolean).join('  ·  '),
  }));
  const items = [...findings, ...anomalies];
  if (!items.length && !result.ai_analyst) return null;
  const findingsCount = findings.length;
  const anomalyCount  = anomalies.length;
  return (
    <SectionCard id="findings" label="Key Findings" defaultOpen={false}
      summary={items.length
        ? `${findingsCount} finding${findingsCount === 1 ? '' : 's'}`
          + (anomalyCount ? ` · ${anomalyCount} anomaly${anomalyCount === 1 ? '' : 'ies'}` : '')
        : null}>
      {!items.length && <AILoading text="Identifying analytical insights…"/>}
      {items.map((f, i) => (
        <Box key={i} sx={{
          display: 'grid', gridTemplateColumns: '32px 1fr',
          gap: 1.5, py: 1.25,
          borderTop: i > 0 ? `1px solid ${muiAlpha('#ffffff', 0.06)}` : 'none',
        }}>
          {f.kind === 'anomaly' ? (
            <AlertTriangle size={14} color="#E6700F" style={{ marginTop: 2 }}/>
          ) : (
            <Typography sx={{ ...monoSx, fontSize: 14, color: 'primary.main',
              fontWeight: 600, fontVariantNumeric: 'tabular-nums' }}>
              {String(i + 1).padStart(2, '0')}
            </Typography>
          )}
          <Box>
            <Typography sx={{ fontSize: 13, color: 'text.primary', fontWeight: 600,
              mb: f.body ? 0.5 : 0 }}>
              {f.title}
              {f.kind === 'anomaly' && (
                <Box component="span" sx={{
                  ml: 1, fontSize: 9, fontWeight: 600, color: '#E6700F',
                  textTransform: 'uppercase', letterSpacing: '0.07em',
                }}>anomaly</Box>
              )}
            </Typography>
            {f.body && (
              <Typography sx={{ fontSize: 12, color: 'text.tertiary', lineHeight: 1.6 }}>
                {f.body}
              </Typography>
            )}
          </Box>
        </Box>
      ))}
    </SectionCard>
  );
}


// ─── 5. File Identity ────────────────────────────────────────────────────────
function FileIdentity({ result }) {
  const theme = useTheme();
  const t = result.type || {};
  const h = result.hashes || {};
  const e = result.entropy || {};
  const pe = result.format_specific?.pe;
  const sig = pe?.signature?.present;
  const eColor = e.overall > 7.5 ? theme.palette.severity?.critical
    : e.overall > 6.5 ? theme.palette.severity?.medium
    : theme.palette.severity?.low;
  const rows = [
    ['Detected type',  t.detected_mime, t.detected_desc],
    ['Claimed type',   `.${t.claimed_ext} · ${t.claimed_mime}`,
                       t.mismatch ? '⚠ mismatch — possible masquerading' : null],
    ['Size',           result.size != null ? `${result.size.toLocaleString()} bytes (${(result.size/1024).toFixed(1)} KB)` : '—'],
    ['Entropy',        `${e.overall ?? '—'} / 8 · ${e.band?.replace(/_/g, ' ') || '—'}`],
    ...(pe?.timestamp?.iso ? [['Compiled', pe.timestamp.iso,
      pe.timestamp.flags?.length ? `⚠ ${pe.timestamp.flags.join(', ')}` : null]] : []),
    ...(pe ? [['Digital signature', sig ? 'Authenticode present' : 'unsigned',
      sig ? null : '⚠ no Authenticode signature']] : []),
    ...(pe?.imphash ? [['imphash', pe.imphash]] : []),
  ];
  return (
    <SectionCard id="identity" label="File Identity" defaultOpen={false}
      summary={h.sha256 ? `SHA-256 ${String(h.sha256).slice(0, 12)}…` : 'metadata'}>
      <Box sx={{ display: 'grid', gridTemplateColumns: '160px 1fr', gap: '8px 16px' }}>
        {rows.map(([k, v, sub]) => (
          <React.Fragment key={k}>
            <Typography sx={{ fontSize: 11, color: 'text.tertiary',
              textTransform: 'uppercase', letterSpacing: '0.06em' }}>{k}</Typography>
            <Box>
              <Typography sx={{ fontSize: 13, color: 'text.primary' }}>{v}</Typography>
              {sub && (
                <Typography sx={{ fontSize: 11, color: 'warning.main', mt: 0.25 }}>{sub}</Typography>
              )}
            </Box>
          </React.Fragment>
        ))}
      </Box>

      {/* Entropy visualization */}
      <Box sx={{ mt: 2 }}>
        <Box sx={{
          height: 6, borderRadius: 99, overflow: 'hidden',
          backgroundColor: muiAlpha('#ffffff', 0.06),
          position: 'relative',
        }}>
          <Box sx={{
            position: 'absolute', left: 0, top: 0, bottom: 0,
            width: `${Math.min(100, ((e.overall || 0) / 8) * 100)}%`,
            backgroundColor: eColor, transition: 'width .3s',
          }}/>
        </Box>
      </Box>

      {/* Hashes — all in IBM Plex Mono with copy buttons */}
      <Box sx={{ mt: 2, pt: 1.5,
        borderTop: `1px solid ${muiAlpha('#ffffff', 0.06)}` }}>
        <Typography sx={{ fontSize: 11, color: 'text.tertiary', fontWeight: 600,
          textTransform: 'uppercase', letterSpacing: '0.06em', mb: 1 }}>
          Hashes
        </Typography>
        {[['MD5', h.md5], ['SHA-1', h.sha1], ['SHA-256', h.sha256],
          ['SHA-512', h.sha512], ['TLSH', h.tlsh], ['ssdeep', h.ssdeep]]
          .filter(([, v]) => v)
          .map(([k, v]) => (
            <Box key={k} sx={{
              display: 'grid', gridTemplateColumns: '70px 1fr 32px',
              gap: 1, alignItems: 'center', py: 0.375,
            }}>
              <Typography sx={{ fontSize: 10, color: 'text.disabled',
                textTransform: 'uppercase' }}>{k}</Typography>
              <Typography sx={{ ...monoSx, fontSize: 11, color: 'text.primary',
                wordBreak: 'break-all' }}>{v}</Typography>
              <CopyBtn text={v}/>
            </Box>
          ))}
      </Box>
    </SectionCard>
  );
}


// ─── 6. Threat Intelligence (per-source expandable) ──────────────────────────
function ThreatIntelSection({ result }) {
  // useMemo'd so the deps array on `sources` doesn't see a fresh
  // identity every render when result.threat_intel is undefined.
  const ti = useMemo(() => result.threat_intel || {}, [result.threat_intel]);
  const [openSource, setOpenSource] = useState(null);

  const sources = useMemo(() => {
    // For each source: produce a summary string OR 'None' if there's nothing
    // useful to display (no data / error / empty result). Empty/errored
    // sources still appear in the list so the analyst sees coverage.
    const order = [
      ['VirusTotal',      ti.virustotal,
        (d) => d?.found ? `${d.detection_ratio}${d.malware_family ? ' · '+d.malware_family : ''}` : null],
      ['MalwareBazaar',   ti.malwarebazaar,
        (d) => d?.found ? d.malware_family || 'match' : null],
      ['Hybrid Analysis', ti.hybrid_analysis,
        (d) => d?.found ? `${d.verdict} · score ${d.threat_score}` : null],
      ['ANY.RUN',         ti.anyrun,
        (d) => d?.found ? d.verdict : null],
      ['Feed cache',      ti.feed_cache,
        (d) => d?.hit_count ? `${d.hit_count} hits` : null],
      ['Scan history',    ti.scan_history,
        (d) => {
          if (!d) return null;
          const n = (d.exact?.length || 0) + (d.imphash?.length || 0)
                  + (d.tlsh_similar?.length || 0) + (d.ssdeep_similar?.length || 0);
          return n ? `${n} similar files` : null;
        }],
      ['Domain pivots',   ti.domain_intel,
        (d) => d?.domains?.length ? `${d.domains.length} domains` : null],
    ];
    return order;
  }, [ti]);

  // Top-level summary indicator — how many TI sources returned an actual hit.
  const hitCount = sources.reduce((n, [, d, fn]) => n + (d && fn(d) ? 1 : 0), 0);
  return (
    <SectionCard id="ti" label="Threat Intelligence" defaultPad={false}
      defaultOpen={false}
      summary={hitCount > 0 ? `${hitCount} source hit${hitCount > 1 ? 's' : ''}` : 'no hits'}>
      {sources.map(([name, data, summarize], i) => {
        const open = openSource === name;
        const summary = data ? summarize(data) : null;
        const hasError = data?.error;
        const hasData  = !!summary && !hasError;
        const chipColor = hasData ? 'error.main' : 'text.disabled';
        return (
          <Box key={name}
            onClick={() => hasData && setOpenSource(open ? null : name)}
            sx={{
              cursor: hasData ? 'pointer' : 'default',
              borderTop: i > 0 ? `1px solid ${muiAlpha('#ffffff', 0.06)}` : 'none',
              '&:hover': hasData ? { backgroundColor: muiAlpha('#ffffff', 0.02) } : undefined,
            }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.25, p: '12px 16px' }}>
              <Box sx={{ width: 6, height: 6, borderRadius: 99,
                backgroundColor: hasData ? 'error.main' : muiAlpha('#ffffff', 0.15) }}/>
              <Typography sx={{ fontSize: 13, color: hasData ? 'text.primary' : 'text.tertiary',
                fontWeight: 500 }}>
                {name}
              </Typography>
              <Typography sx={{ fontSize: 11, color: chipColor, ml: 'auto',
                fontStyle: hasData ? 'normal' : 'italic' }}>
                {hasData ? summary : 'None'}
              </Typography>
              {hasData && (
                <ChevronRight size={14} color="#848592" style={{
                  transition: 'transform .15s',
                  transform: open ? 'rotate(90deg)' : 'none',
                }}/>
              )}
            </Box>
            {open && hasData && (
              <Box sx={{ p: '0 16px 14px 28px',
                backgroundColor: muiAlpha('#ffffff', 0.02) }}>
                <Box component="pre" sx={{ ...monoSx, fontSize: 11,
                  color: 'text.primary', whiteSpace: 'pre-wrap',
                  wordBreak: 'break-all', m: 0, maxHeight: 320, overflow: 'auto',
                }}>{JSON.stringify(data, null, 2)}</Box>
              </Box>
            )}
          </Box>
        );
      })}
    </SectionCard>
  );
}


// ─── 7. Behavioral Capabilities + MITRE ──────────────────────────────────────
function CapabilitiesSection({ result }) {
  const cap = result.capabilities || {};
  if (!cap.tags?.length && !cap.mitre_techniques?.length) return null;
  return (
    <SectionCard id="caps" label="Behavioral Capabilities"
      defaultOpen={false}
      summary={(cap.tags?.length || 0) + (cap.mitre_techniques?.length || 0) > 0
        ? `${cap.tags?.length || 0} caps · ${cap.mitre_techniques?.length || 0} MITRE`
        : 'none'}>
      {cap.tags?.length > 0 && (
        <Box>
          <Typography sx={{ fontSize: 11, color: 'text.tertiary', fontWeight: 600,
            textTransform: 'uppercase', letterSpacing: '0.06em', mb: 1 }}>
            Identified capabilities
          </Typography>
          <Box sx={{
            display: 'flex', flexWrap: 'wrap', gap: 0.75, mb: 2,
            minWidth: 0,   // allow shrinking inside grid/flex parents
          }}>
            {cap.tags.map(t => {
              const matched = (cap.mitre_techniques || []).find(m => m.label === t);
              const tip = matched ? `${matched.id} · ${matched.explanation}` : t;
              return (
                <Tooltip key={t} title={tip}>
                  <MuiChip label={t} size="small" sx={{
                    maxWidth: '100%',
                    backgroundColor: muiAlpha('#EE3838', 0.16),
                    color: 'error.main', fontWeight: 500, fontSize: 11,
                    '& .MuiChip-label': {
                      whiteSpace: 'normal',
                      overflowWrap: 'anywhere',
                    },
                  }}/>
                </Tooltip>
              );
            })}
          </Box>
        </Box>
      )}
      {cap.mitre_techniques?.length > 0 && (
        <Box sx={{ pt: cap.tags?.length ? 1.5 : 0,
          borderTop: cap.tags?.length ? `1px solid ${muiAlpha('#ffffff', 0.06)}` : 'none' }}>
          <Typography sx={{ fontSize: 11, color: 'text.tertiary', fontWeight: 600,
            textTransform: 'uppercase', letterSpacing: '0.06em', mb: 1 }}>
            MITRE ATT&CK
          </Typography>
          {cap.mitre_techniques.map((m, i) => (
            <Box key={i} sx={{
              display: 'grid', gridTemplateColumns: '80px 1fr auto',
              gap: 1.5, alignItems: 'baseline', py: 0.625,
              borderTop: i > 0 ? `1px solid ${muiAlpha('#ffffff', 0.04)}` : 'none',
            }}>
              <Box component="a" href={m.attack_url} target="_blank" rel="noreferrer"
                sx={{ ...monoSx, fontSize: 12, color: 'primary.main',
                  textDecoration: 'none', '&:hover': { textDecoration: 'underline' } }}>
                {m.id}
              </Box>
              <Box>
                <Typography sx={{ fontSize: 12, color: 'text.primary', fontWeight: 500 }}>
                  {m.label || m.name}
                </Typography>
                {m.explanation && (
                  <Typography sx={{ fontSize: 11, color: 'text.tertiary', mt: 0.25 }}>
                    {m.explanation}
                  </Typography>
                )}
              </Box>
              <MuiChip label={m.tactic} size="small" variant="outlined" sx={{
                height: 18, fontSize: 9, color: 'text.tertiary',
                borderColor: muiAlpha('#ffffff', 0.18),
              }}/>
            </Box>
          ))}
        </Box>
      )}
    </SectionCard>
  );
}


// ─── 8. Strings + IOCs ───────────────────────────────────────────────────────
function StringsSection({ result }) {
  const [query, setQuery] = useState('');
  // useMemo'd so downstream useMemo / useCallback deps arrays don't
  // see a fresh `|| {}` / `|| []` identity on every parent render.
  const iocs = useMemo(() => result.iocs || {}, [result.iocs]);
  const sus  = useMemo(() => result.suspicious_strings || [], [result.suspicious_strings]);
  const ti   = useMemo(() => result.threat_intel || {}, [result.threat_intel]);

  const verdictForIoc = useCallback((ioc) => {
    // Quick verdict overlay from feed_cache hits for known IPs/domains
    const hit = (ti.feed_cache?.hits || []).find(h => h.ioc === ioc);
    if (hit) return 'SUSPICIOUS';
    return null;
  }, [ti]);

  const groups = useMemo(() => ({
    'Network indicators':
      [...(iocs.ips || []).map(v => ({ v, t: 'ip', verdict: verdictForIoc(v) })),
       ...(iocs.domains || []).map(v => ({ v, t: 'domain', verdict: verdictForIoc(v) })),
       ...(iocs.urls || []).map(v => ({ v, t: 'url', verdict: verdictForIoc(v) })),
       ...(iocs.emails || []).map(v => ({ v, t: 'email' }))],
    'File system paths':    (iocs.paths || []).map(v => ({ v, t: 'path' })),
    'Hashes in file':       (iocs.hashes || []).map(v => ({ v, t: 'hash' })),
    'Commands & scripts':   [],
    'Encoded content':      (iocs.decoded_payloads || []).map(v => ({ v, t: 'decoded' })),
    'Suspicious patterns':  sus.map(s => ({ v: s.match, t: s.pattern })),
  }), [iocs, sus, verdictForIoc]);

  const q = query.trim().toLowerCase();
  const verdictColorMap = {
    MALICIOUS: '#EE3838', SUSPICIOUS: '#E6700F', CLEAN: '#16AD34',
  };

  const totalStrings = Object.values(groups).reduce((n, g) => n + g.length, 0);
  return (
    <SectionCard id="strings" label="Strings & IOCs"
      defaultOpen={false}
      summary={totalStrings > 0 ? `${totalStrings} indicator${totalStrings !== 1 ? 's' : ''}` : 'none'}>
      <MuiTextField size="small" fullWidth
        value={query} onChange={e => setQuery(e.target.value)}
        placeholder="Filter strings…"
        InputProps={{ startAdornment: <Search size={13} style={{ marginRight: 6, color: '#848592' }}/> }}
        sx={{ mb: 1.5, '& .MuiInputBase-input': { fontSize: 12 } }}/>
      {Object.entries(groups).map(([title, items]) => {
        const filtered = q ? items.filter(i => (i.v || '').toLowerCase().includes(q)) : items;
        if (!filtered.length) return null;
        return (
          <Box key={title} sx={{ mb: 1.75 }}>
            <Typography sx={{ fontSize: 10, color: 'text.tertiary', fontWeight: 600,
              textTransform: 'uppercase', letterSpacing: '0.06em', mb: 0.5 }}>
              {title} · {filtered.length}
            </Typography>
            <Box sx={{
              backgroundColor: muiAlpha('#ffffff', 0.02),
              border: `1px solid ${muiAlpha('#ffffff', 0.06)}`,
              borderRadius: '4px', maxHeight: 220, overflow: 'auto',
            }}>
              {filtered.slice(0, 60).map((item, i) => (
                <Box key={i} sx={{
                  display: 'grid', gridTemplateColumns: 'auto 1fr auto 32px',
                  gap: 1, p: '4px 10px', alignItems: 'baseline',
                  borderTop: i > 0 ? `1px solid ${muiAlpha('#ffffff', 0.04)}` : 'none',
                }}>
                  <Typography sx={{ fontSize: 9, color: 'text.disabled',
                    textTransform: 'uppercase', minWidth: 36 }}>{item.t}</Typography>
                  <Typography sx={{ ...monoSx, fontSize: 11, color: 'text.primary',
                    // Decoded payloads can be a multi-line hex dump for binary
                    // content — preserve newlines so the dump stays readable.
                    ...(item.t === 'decoded'
                      ? { whiteSpace: 'pre-wrap', overflowX: 'auto' }
                      : { wordBreak: 'break-all' }) }}>{item.v}</Typography>
                  {item.verdict ? (
                    <MuiChip label={item.verdict} size="small" sx={{
                      height: 16, fontSize: 9,
                      backgroundColor: muiAlpha(verdictColorMap[item.verdict] || '#848592', 0.18),
                      color: verdictColorMap[item.verdict] || 'text.disabled',
                    }}/>
                  ) : <Box/>}
                  <CopyBtn text={item.v}/>
                </Box>
              ))}
            </Box>
          </Box>
        );
      })}
    </SectionCard>
  );
}


// ─── 9. YARA Analysis ────────────────────────────────────────────────────────
function YaraSection({ result }) {
  const matches = (result.yara_matches || []).filter(m => m && !m.error);
  const ai = result.ai_yara || {};
  const [openRule, setOpenRule] = useState(null);
  if (!matches.length && !ai.rule) return null;
  return (
    <SectionCard id="yara" label="YARA Analysis"
      defaultOpen={false}
      summary={matches.length > 0
        ? `${matches.length} match${matches.length > 1 ? 'es' : ''}`
        : 'no matches'}>
      <Typography sx={{ fontSize: 11, color: 'text.tertiary', fontWeight: 600,
        textTransform: 'uppercase', letterSpacing: '0.06em', mb: 1 }}>
        Matched rules · {matches.length}
      </Typography>
      {matches.length === 0 && (
        <Typography sx={{ fontSize: 12, color: 'text.tertiary' }}>
          No YARA rules matched this file.
        </Typography>
      )}
      {matches.map((m, i) => {
        const open = openRule === i;
        return (
          <Box key={i}
            onClick={() => setOpenRule(open ? null : i)}
            sx={{
              cursor: m.matched_strings?.length ? 'pointer' : 'default',
              p: '8px 12px',
              borderTop: i > 0 ? `1px solid ${muiAlpha('#ffffff', 0.04)}` : 'none',
              '&:hover': { backgroundColor: muiAlpha('#ffffff', 0.02) },
            }}>
            <Stack direction="row" alignItems="center" spacing={1} flexWrap="wrap">
              <Typography sx={{ ...monoSx, fontSize: 12, color: 'text.primary', fontWeight: 600 }}>
                {m.rule}
              </Typography>
              {m.source && (
                <MuiChip label={m.source} size="small" sx={{ height: 16, fontSize: 9,
                  backgroundColor: muiAlpha('#848592', 0.18) }}/>
              )}
              <Typography sx={{ fontSize: 11, color: 'text.tertiary', ml: 'auto !important' }}>
                {m.author || ''}
                {m.matched_strings?.length ? ` · ${m.matched_strings.length} strings` : ''}
              </Typography>
            </Stack>
            {m.description && (
              <Typography sx={{ fontSize: 11, color: 'text.tertiary', mt: 0.5 }}>
                {m.description}
              </Typography>
            )}
            {open && m.matched_strings?.length > 0 && (
              <Box sx={{ ...monoSx, fontSize: 10, color: 'text.primary', mt: 0.75,
                backgroundColor: muiAlpha('#000000', 0.3),
                border: `1px solid ${muiAlpha('#ffffff', 0.06)}`,
                borderRadius: '3px', p: '6px 10px',
              }}>
                {m.matched_strings.map((s, j) => (
                  <Box key={j}>
                    <Box component="span" sx={{ color: 'primary.main' }}>{s.id}</Box>
                    {s.offset != null ? ` @ 0x${s.offset.toString(16)}: ` : ': '}
                    {s.matched}
                  </Box>
                ))}
              </Box>
            )}
          </Box>
        );
      })}

      {/* AI-generated rule */}
      {ai.rule && (
        <Box sx={{ mt: 2, pt: 1.5,
          borderTop: `1px solid ${muiAlpha('#ffffff', 0.06)}` }}>
          <Stack direction="row" alignItems="center" spacing={1} sx={{ mb: 0.75 }}>
            <Typography sx={{ fontSize: 11, color: 'text.tertiary', fontWeight: 600,
              textTransform: 'uppercase', letterSpacing: '0.06em' }}>
              AI-generated custom rule for this file
            </Typography>
            <Box component="span" sx={{ fontSize: 10,
              color: ai.valid ? 'success.main' : 'error.main' }}>
              {ai.valid ? '✓ validated' : '✗ failed validation'}
            </Box>
          </Stack>
          <Box component="pre" sx={{ ...monoSx, fontSize: 11, m: 0,
            backgroundColor: muiAlpha('#000000', 0.3),
            border: `1px solid ${muiAlpha('#ffffff', 0.06)}`,
            borderRadius: '4px', p: 1.25, maxHeight: 280, overflow: 'auto',
            color: 'text.primary', whiteSpace: 'pre-wrap',
          }}>{ai.rule}</Box>
          <Stack direction="row" spacing={1} sx={{ mt: 0.75 }}>
            <CopyBtn text={ai.rule}/>
            <MuiButton size="small" variant="outlined"
              startIcon={<Download size={12}/>}
              onClick={() => downloadText(
                `recon_${(result.hashes?.sha256 || 'sample').slice(0, 8)}.yar`, ai.rule
              )}>
              Download .yar
            </MuiButton>
            <MuiButton size="small" variant="outlined"
              startIcon={<Plus size={12}/>}
              onClick={async () => {
                try {
                  const r = await fetch('/api/scan/rules', {
                    method: 'POST', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                      name: `recon_${(result.hashes?.sha256 || 'sample').slice(0, 12)}`,
                      rule: ai.rule,
                    }),
                  });
                  const d = await r.json();
                  alert(r.ok ? `Saved as ${d.name}.yar` : `Failed: ${JSON.stringify(d)}`);
                } catch (e) { alert(`Failed: ${e.message}`); }
              }}>
              Save to library
            </MuiButton>
          </Stack>
        </Box>
      )}
    </SectionCard>
  );
}


// ─── 10. Format-Specific Analysis ────────────────────────────────────────────
function FormatSection({ result }) {
  const fs = result.format_specific || {};
  const pe = fs.pe, off = fs.office, pdf = fs.pdf, ar = fs.archive, sc = fs.script;
  if (!pe && !off && !pdf && !ar && !sc) return null;
  return (
    <SectionCard id="format" label="Format-Specific Analysis"
      defaultOpen={false}
      summary={[pe && 'PE', off && 'Office', pdf && 'PDF', ar && 'Archive', sc && 'Script']
        .filter(Boolean).join(' · ') || null}>
      {pe && <PEDetails pe={pe}/>}
      {off && <OfficeDetails office={off}/>}
      {pdf && <PdfDetails pdf={pdf}/>}
      {ar && <ArchiveDetails archive={ar}/>}
      {sc && <ScriptDetails script={sc}/>}
    </SectionCard>
  );
}

function PEDetails({ pe }) {
  return (
    <Box>
      {pe.flagged_imports && Object.keys(pe.flagged_imports).length > 0 && (
        <Box sx={{ mb: 2 }}>
          <Typography sx={{ fontSize: 11, color: 'warning.main', fontWeight: 600,
            textTransform: 'uppercase', letterSpacing: '0.06em', mb: 0.75 }}>
            High-risk imports
          </Typography>
          {Object.entries(pe.flagged_imports).map(([cat, fns]) => (
            <Box key={cat} sx={{ mb: 0.75 }}>
              <Typography sx={{ fontSize: 11, color: 'warning.main', fontWeight: 600, mb: 0.25 }}>
                {cat}
              </Typography>
              <Typography sx={{ ...monoSx, fontSize: 11, color: 'text.primary' }}>
                {fns.join(', ')}
              </Typography>
            </Box>
          ))}
        </Box>
      )}
      {pe.sections?.length > 0 && (
        <Box>
          <Typography sx={{ fontSize: 11, color: 'text.tertiary', fontWeight: 600,
            textTransform: 'uppercase', letterSpacing: '0.06em', mb: 0.75 }}>
            Sections
          </Typography>
          <MuiTable size="small">
            <TableHead>
              <TableRow>
                {['Name', 'VAddr', 'VSize', 'RSize', 'Entropy', 'Flags'].map(h => (
                  <TableCell key={h} sx={{ fontSize: 10, color: 'text.disabled' }}>{h}</TableCell>
                ))}
              </TableRow>
            </TableHead>
            <TableBody>
              {pe.sections.map((s, i) => (
                <TableRow key={i}>
                  <TableCell sx={{ ...monoSx, fontSize: 11 }}>{s.name}</TableCell>
                  <TableCell sx={{ ...monoSx, fontSize: 11 }}>{s.vaddr}</TableCell>
                  <TableCell sx={{ fontSize: 11 }}>{s.vsize}</TableCell>
                  <TableCell sx={{ fontSize: 11 }}>{s.rsize}</TableCell>
                  <TableCell sx={{ fontSize: 11, color: s.entropy > 7 ? 'error.main' : 'text.primary' }}>
                    {s.entropy}
                  </TableCell>
                  <TableCell sx={{ fontSize: 10, color: 'warning.main' }}>{(s.flags || []).join(', ')}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </MuiTable>
        </Box>
      )}
    </Box>
  );
}

function OfficeDetails({ office }) {
  return (
    <Box>
      <Typography sx={{ fontSize: 12, color: 'text.primary' }}>
        Macros: {office.has_macros ? 'yes' : 'no'}
        {office.auto_exec?.length ? ` · auto-exec: ${office.auto_exec.join(', ')}` : ''}
      </Typography>
      {office.suspicious_patterns?.length > 0 && (
        <Box sx={{ mt: 1 }}>
          {office.suspicious_patterns.map((s, i) => (
            <Typography key={i} sx={{ fontSize: 11, color: 'warning.main', py: 0.25 }}>
              ⚠ {s.pattern}: {s.match}
            </Typography>
          ))}
        </Box>
      )}
      {(office.macros || [])[0]?.code_preview && (
        <Box component="pre" sx={{ ...monoSx, fontSize: 11, m: 0, mt: 1,
          backgroundColor: muiAlpha('#000000', 0.3),
          border: `1px solid ${muiAlpha('#ffffff', 0.06)}`,
          borderRadius: '4px', p: 1, maxHeight: 240, overflow: 'auto',
          color: 'text.primary', whiteSpace: 'pre-wrap',
        }}>{office.macros[0].code_preview}</Box>
      )}
    </Box>
  );
}

function PdfDetails({ pdf }) {
  return (
    <Box>
      <Typography sx={{ fontSize: 12, color: 'text.primary' }}>
        {pdf.pages} pages · encrypted: {pdf.encrypted ? 'yes' : 'no'}
        {pdf.javascript?.length ? ` · JS blocks: ${pdf.javascript.length}` : ''}
        {pdf.launch_actions?.length ? ` · launch actions: ${pdf.launch_actions.length}` : ''}
      </Typography>
      {pdf.javascript?.length > 0 && (
        <Box component="pre" sx={{ ...monoSx, fontSize: 11, m: 0, mt: 1,
          backgroundColor: muiAlpha('#000000', 0.3),
          border: `1px solid ${muiAlpha('#ffffff', 0.06)}`,
          borderRadius: '4px', p: 1, maxHeight: 200, overflow: 'auto',
          color: 'text.primary', whiteSpace: 'pre-wrap',
        }}>{pdf.javascript[0]}</Box>
      )}
    </Box>
  );
}

function ArchiveDetails({ archive }) {
  return (
    <Box>
      <Typography sx={{ fontSize: 12, color: 'text.primary', mb: 1 }}>
        {archive.member_count} members
      </Typography>
      {archive.flags?.length > 0 && archive.flags.slice(0, 5).map((f, i) => (
        <Typography key={i} sx={{ fontSize: 11, color: 'warning.main' }}>⚠ {f}</Typography>
      ))}
      <MuiTable size="small" sx={{ mt: 1 }}>
        <TableBody>
          {(archive.members || []).slice(0, 12).map((m, i) => (
            <TableRow key={i}>
              <TableCell sx={{ ...monoSx, fontSize: 11 }}>{m.name}</TableCell>
              <TableCell sx={{ fontSize: 11 }}>{m.size}</TableCell>
              <TableCell sx={{ fontSize: 10, color: 'warning.main' }}>{(m.flags || []).join(', ')}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </MuiTable>
    </Box>
  );
}

function ScriptDetails({ script }) {
  return (
    <Box>
      <Typography sx={{ fontSize: 12, color: 'text.primary', mb: 1 }}>
        {script.language} · {script.line_count} lines
      </Typography>
      {script.obfuscation_flags?.length > 0 && (
        <Stack direction="row" spacing={0.5} flexWrap="wrap" sx={{ mb: 1 }}>
          {script.obfuscation_flags.map(f => (
            <MuiChip key={f} label={f.replace(/_/g, ' ')} size="small" sx={{
              height: 18, fontSize: 10,
              backgroundColor: muiAlpha('#E6700F', 0.18), color: 'warning.main',
            }}/>
          ))}
        </Stack>
      )}
      <Box component="pre" sx={{ ...monoSx, fontSize: 11, m: 0,
        backgroundColor: muiAlpha('#000000', 0.3),
        border: `1px solid ${muiAlpha('#ffffff', 0.06)}`,
        borderRadius: '4px', p: 1, maxHeight: 220, overflow: 'auto',
        color: 'text.primary', whiteSpace: 'pre-wrap',
      }}>{(script.source_preview || '').slice(0, 1200)}</Box>
    </Box>
  );
}


// ─── 11. Anomalies ───────────────────────────────────────────────────────────
function Anomalies({ result }) {
  const items = result.ai_analyst?.deep?.anomalies || [];
  if (!items.length) return null;
  return (
    <SectionCard id="anomalies" label="Anomalies" accent="#E6700F"
      defaultOpen={false}
      summary={`${items.length} anomal${items.length === 1 ? 'y' : 'ies'}`}>
      {items.map((a, i) => (
        <Box key={i} sx={{
          display: 'grid', gridTemplateColumns: '24px 1fr', gap: 1.25,
          py: 1, borderTop: i > 0 ? `1px solid ${muiAlpha('#ffffff', 0.04)}` : 'none',
        }}>
          <AlertTriangle size={14} color="#E6700F" style={{ marginTop: 2 }}/>
          <Box>
            <Typography sx={{ fontSize: 13, color: 'text.primary', fontWeight: 500 }}>
              {a.observation || a}
            </Typography>
            {a.expected && (
              <Typography sx={{ fontSize: 11, color: 'text.tertiary', mt: 0.25 }}>
                <Box component="span" sx={{ color: 'text.disabled' }}>expected: </Box>
                {a.expected}
              </Typography>
            )}
            {a.implication && (
              <Typography sx={{ fontSize: 11, color: 'warning.main', mt: 0.25 }}>
                → {a.implication}
              </Typography>
            )}
          </Box>
        </Box>
      ))}
    </SectionCard>
  );
}


// ─── 12. Detection Content — now also hosts YARA matches ─────────────────────
function DetectionContent({ result }) {
  const d = result.detections || {};
  const blocks = [
    ['Sigma',          d.sigma?.rule],
    ['KQL · Sentinel', d.kql?.query],
    ['Splunk SPL',     d.spl?.query],
    ['Snort / Suricata', d.suricata?.rules],
    ['Volatility / Rekall', d.volatility?.rule],
  ].filter(([, b]) => b);
  const yaraMatches = (result.yara_matches || []).filter(m => m && !m.error);
  const aiYara = result.ai_yara || {};
  if (!blocks.length && !yaraMatches.length && !aiYara.rule) return null;
  const totalCount = blocks.length + yaraMatches.length + (aiYara.rule ? 1 : 0);
  return (
    <SectionCard id="detect" label="Detection Content" defaultOpen={false}
      summary={`${totalCount} item${totalCount === 1 ? '' : 's'}`}>

      {/* YARA matches first — they're concrete signals on this specific
          sample, while the Sigma/KQL/SPL rules below are generated
          detections to deploy elsewhere. */}
      {yaraMatches.length > 0 && (
        <Box sx={{ mb: blocks.length || aiYara.rule ? 2 : 0 }}>
          <Typography sx={{ fontSize: 11, color: 'primary.main', fontWeight: 600,
            textTransform: 'uppercase', letterSpacing: '0.06em', mb: 0.75 }}>
            YARA matches · {yaraMatches.length}
          </Typography>
          {yaraMatches.map((m, i) => (
            <Box key={i} sx={{
              p: '8px 12px', mb: 0.75, borderRadius: '4px',
              backgroundColor: muiAlpha('#EE3838', 0.05),
              border: `1px solid ${muiAlpha('#EE3838', 0.25)}`,
              borderLeft: `3px solid #EE3838`,
            }}>
              <Stack direction="row" alignItems="center" spacing={1}>
                <Typography sx={{ fontSize: 12.5, fontWeight: 600,
                  color: 'text.primary', ...monoSx }}>
                  {m.rule}
                </Typography>
                {m.source && (
                  <Typography sx={{ fontSize: 10, color: 'text.tertiary' }}>
                    · {m.source}
                  </Typography>
                )}
              </Stack>
              {m.description && (
                <Typography sx={{ fontSize: 11.5, color: 'text.secondary',
                  mt: 0.5, lineHeight: 1.55 }}>
                  {m.description}
                </Typography>
              )}
              {m.matched_strings?.length > 0 && (
                <Box sx={{ mt: 0.75 }}>
                  <Typography sx={{ fontSize: 10, color: 'text.tertiary',
                    textTransform: 'uppercase', letterSpacing: '0.06em',
                    mb: 0.25 }}>
                    Matched strings
                  </Typography>
                  <Box component="pre" sx={{ ...monoSx, fontSize: 11, m: 0,
                    backgroundColor: muiAlpha('#000000', 0.3),
                    border: `1px solid ${muiAlpha('#ffffff', 0.06)}`,
                    borderRadius: '3px', p: '6px 10px', maxHeight: 180,
                    overflow: 'auto', color: 'text.primary',
                    whiteSpace: 'pre-wrap', wordBreak: 'break-all',
                  }}>
                    {m.matched_strings.slice(0, 8).join('\n')}
                  </Box>
                </Box>
              )}
            </Box>
          ))}
        </Box>
      )}

      {/* AI-generated YARA rule (when one was synthesized) */}
      {aiYara.rule && (
        <Box sx={{ mb: blocks.length ? 2 : 0 }}>
          <Stack direction="row" alignItems="center" spacing={1} sx={{ mb: 0.5 }}>
            <Typography sx={{ fontSize: 11, color: 'primary.main', fontWeight: 600,
              textTransform: 'uppercase', letterSpacing: '0.06em' }}>
              AI-generated YARA
              {aiYara.valid === false && (
                <Box component="span" sx={{ color: 'error.main', ml: 1,
                  textTransform: 'none' }}>
                  · invalid
                </Box>
              )}
            </Typography>
            <Box sx={{ ml: 'auto !important' }}>
              <CopyBtn text={aiYara.rule}/>
            </Box>
            <MuiIconButton size="small" title="Download"
              onClick={() => downloadText('recon_ai_yara.yar', aiYara.rule)}
              sx={{ color: 'text.tertiary', '&:hover': { color: 'primary.main' } }}>
              <Download size={12}/>
            </MuiIconButton>
          </Stack>
          <Box component="pre" sx={{ ...monoSx, fontSize: 11, m: 0,
            backgroundColor: muiAlpha('#000000', 0.3),
            border: `1px solid ${muiAlpha('#ffffff', 0.06)}`,
            borderRadius: '4px', p: 1.25, maxHeight: 240, overflow: 'auto',
            color: 'text.primary', whiteSpace: 'pre-wrap',
          }}>{aiYara.rule}</Box>
        </Box>
      )}

      {blocks.map(([title, body], i) => (
        <Box key={title} sx={{ mb: i < blocks.length - 1 ? 1.75 : 0 }}>
          <Stack direction="row" alignItems="center" spacing={1} sx={{ mb: 0.5 }}>
            <Typography sx={{ fontSize: 11, color: 'primary.main', fontWeight: 600,
              textTransform: 'uppercase', letterSpacing: '0.06em' }}>{title}</Typography>
            <Box sx={{ ml: 'auto !important' }}><CopyBtn text={body}/></Box>
            <MuiIconButton size="small" title="Download"
              onClick={() => downloadText(`recon_${title.split(' ')[0].toLowerCase()}.txt`, body)}
              sx={{ color: 'text.tertiary', '&:hover': { color: 'primary.main' } }}>
              <Download size={12}/>
            </MuiIconButton>
          </Stack>
          <Box component="pre" sx={{ ...monoSx, fontSize: 11, m: 0,
            backgroundColor: muiAlpha('#000000', 0.3),
            border: `1px solid ${muiAlpha('#ffffff', 0.06)}`,
            borderRadius: '4px', p: 1.25, maxHeight: 240, overflow: 'auto',
            color: 'text.primary', whiteSpace: 'pre-wrap',
          }}>{body}</Box>
        </Box>
      ))}
    </SectionCard>
  );
}


// ─── 13. Hunting Leads ───────────────────────────────────────────────────────
function HuntingLeads({ result }) {
  const items = result.ai_analyst?.deep?.hunting_leads || [];
  if (!items.length) return null;
  return (
    <SectionCard id="hunting" label="Hunting Leads" defaultOpen={false}
      summary={`${items.length} lead${items.length === 1 ? '' : 's'}`}>
      {items.map((h, i) => (
        <Box key={i} sx={{
          py: 1.25, borderTop: i > 0 ? `1px solid ${muiAlpha('#ffffff', 0.04)}` : 'none',
        }}>
          <Stack direction="row" alignItems="center" spacing={1} sx={{ mb: 0.5 }} flexWrap="wrap">
            <Typography sx={{ fontSize: 13, color: 'text.primary', fontWeight: 600 }}>
              {h.hypothesis}
            </Typography>
            {h.data_source && (
              <MuiChip label={h.data_source} size="small" sx={{ height: 18, fontSize: 9,
                ...monoSx, backgroundColor: muiAlpha('#0fbcff', 0.18),
                color: 'primary.main', fontFamily: '"IBM Plex Mono", monospace',
              }}/>
            )}
          </Stack>
          {h.query_logic && (
            <Typography sx={{ fontSize: 12, color: 'text.tertiary', lineHeight: 1.55 }}>
              {h.query_logic}
            </Typography>
          )}
        </Box>
      ))}
    </SectionCard>
  );
}


// ─── 14. Recommended Actions ─────────────────────────────────────────────────
function ActionsSection({ result }) {
  const all = result.ai_analyst?.deep?.recommended_actions || [];
  if (!all.length) return null;
  const buckets = { IMMEDIATE: [], SHORTTERM: [], LONGTERM: [] };
  all.forEach(a => {
    if (typeof a === 'string') { buckets.SHORTTERM.push({ action: a }); return; }
    const p = (a.priority || 'SHORTTERM').toUpperCase().replace(/\s|-/g, '');
    (buckets[p] || buckets.SHORTTERM).push(a);
  });
  const color = { IMMEDIATE: '#EE3838', SHORTTERM: '#E6700F', LONGTERM: '#E1B823' };
  return (
    <SectionCard id="actions" label="Recommended Actions" defaultOpen={false}
      summary={all.length ? `${all.length} action${all.length === 1 ? '' : 's'}` : null}>
      {Object.entries(buckets).map(([k, items]) => items.length > 0 && (
        <Box key={k} sx={{ mb: 1.75 }}>
          <Typography sx={{ fontSize: 10, color: color[k], fontWeight: 700,
            textTransform: 'uppercase', letterSpacing: '0.1em', mb: 0.75 }}>
            {k.replace('SHORTTERM', 'SHORT TERM').replace('LONGTERM', 'LONG TERM')}
          </Typography>
          {items.map((a, i) => (
            <MuiPaper key={i} elevation={0} sx={{
              backgroundColor: muiAlpha(color[k], 0.04),
              border: `1px solid ${muiAlpha(color[k], 0.2)}`,
              borderLeft: `3px solid ${color[k]}`,
              borderRadius: '4px', p: '8px 12px', mb: 0.75,
            }}>
              <Typography sx={{ fontSize: 13, color: 'text.primary', lineHeight: 1.55 }}>
                {a.action || a}
              </Typography>
              {a.timeframe && (
                <Typography sx={{ fontSize: 10, color: 'text.tertiary', mt: 0.25 }}>
                  by {a.timeframe}
                </Typography>
              )}
            </MuiPaper>
          ))}
        </Box>
      ))}
    </SectionCard>
  );
}


// ─── 15. Analyst Notes + Refinement (clarify + feedback) ─────────────────────
function NotesAndRefinement({ result, onRefreshScan }) {
  const deep = result.ai_analyst?.deep || {};
  const notes = deep.analyst_notes;
  const confAssess = deep.confidence_assessment;
  const questions = deep.clarifying_questions || [];
  const ci = result.ai_analyst?.context_impact || deep.context_impact;
  const sha = result.hashes?.sha256;

  const [answers, setAnswers] = useState({});
  const [submitting, setSubmitting] = useState(false);
  const [refineErr, setRefineErr] = useState(null);

  const refine = async () => {
    if (!sha) return;
    const filled = Object.fromEntries(
      Object.entries(answers).filter(([, v]) => (v || '').trim()),
    );
    if (Object.keys(filled).length === 0) { setRefineErr('Answer at least one question'); return; }
    setSubmitting(true); setRefineErr(null);
    try {
      const r = await fetch('/api/scan/clarify', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scan_id: sha, answers: filled }),
      });
      const d = await r.json();
      if (!r.ok) throw new Error(d.detail || `HTTP ${r.status}`);
      onRefreshScan?.(d);
    } catch (e) { setRefineErr(e.message); }
    finally { setSubmitting(false); }
  };

  if (!notes && !confAssess?.overall_confidence && !questions.length) return null;

  const confPct = Math.round((confAssess?.overall_confidence || 0) * 100);

  return (
    <SectionCard id="notes" label="Notes & Refinement" defaultOpen={false}
      summary={questions.length ? `${questions.length} question${questions.length === 1 ? '' : 's'}` : 'analyst notes'}>
      {ci && (
        <MuiPaper elevation={0} sx={{
          backgroundColor: muiAlpha('#16AD34', 0.06),
          border: `1px solid ${muiAlpha('#16AD34', 0.25)}`,
          borderLeft: '3px solid #16AD34',
          borderRadius: '4px', p: '10px 12px', mb: 1.75,
        }}>
          <Typography sx={{ fontSize: 10, color: 'success.main', fontWeight: 700,
            textTransform: 'uppercase', letterSpacing: '0.06em', mb: 0.5 }}>
            Context impact · re-analysis
          </Typography>
          <Typography sx={{ fontSize: 12, color: 'text.primary', lineHeight: 1.6 }}>
            {ci}
          </Typography>
        </MuiPaper>
      )}

      {notes && (
        <Box sx={{ mb: 1.75 }}>
          <Typography sx={{ fontSize: 11, color: 'text.tertiary', fontWeight: 600,
            textTransform: 'uppercase', letterSpacing: '0.06em', mb: 0.5 }}>
            Analyst notes
          </Typography>
          <Typography sx={{ fontSize: 12, color: 'text.primary', lineHeight: 1.65, fontStyle: 'italic' }}>
            {notes}
          </Typography>
        </Box>
      )}

      {confAssess?.overall_confidence != null && (
        <Box sx={{ mb: 1.75 }}>
          <Stack direction="row" alignItems="baseline" spacing={1} sx={{ mb: 0.5 }}>
            <Typography sx={{ fontSize: 11, color: 'text.tertiary', fontWeight: 600,
              textTransform: 'uppercase', letterSpacing: '0.06em' }}>
              Confidence
            </Typography>
            <Typography sx={{ fontSize: 12, color: 'text.primary' }}>{confPct}%</Typography>
          </Stack>
          <LinearProgress variant="determinate" value={confPct}
            sx={{ height: 6, borderRadius: 99,
              backgroundColor: muiAlpha('#ffffff', 0.06) }}/>
          {confAssess.what_would_help && (
            <Typography sx={{ fontSize: 11, color: 'text.tertiary', mt: 0.5, fontStyle: 'italic' }}>
              What would help: {confAssess.what_would_help}
            </Typography>
          )}
        </Box>
      )}

      {questions.length > 0 && (
        <Box sx={{ mb: 1.75 }}>
          <Typography sx={{ fontSize: 11, color: 'text.tertiary', fontWeight: 600,
            textTransform: 'uppercase', letterSpacing: '0.06em', mb: 0.75 }}>
            Clarifying questions
          </Typography>
          {questions.map((q, i) => {
            const text = typeof q === 'string' ? q : (q.question || `Q${i+1}`);
            return (
              <Box key={i} sx={{ mb: 1 }}>
                <Typography sx={{ fontSize: 12, color: 'text.primary', mb: 0.5 }}>{text}</Typography>
                <MuiTextField size="small" fullWidth
                  value={answers[text] || ''}
                  onChange={e => setAnswers(a => ({ ...a, [text]: e.target.value }))}
                  placeholder="Your answer (plain text)"
                  sx={{ '& .MuiInputBase-input': { fontSize: 12 } }}/>
              </Box>
            );
          })}
          {refineErr && (
            <Typography sx={{ fontSize: 11, color: 'error.main', mb: 0.5 }}>{refineErr}</Typography>
          )}
          <MuiButton size="small" variant="contained"
            disabled={submitting} onClick={refine}
            startIcon={<RotateCcw size={12}/>}>
            {submitting ? 'Re-analyzing…' : 'Refine analysis'}
          </MuiButton>
        </Box>
      )}

    </SectionCard>
  );
}


// ─── Sticky header + section navigator ───────────────────────────────────────
function StickyHeader({ result, scanning }) {
  const theme = useTheme();
  const v = result?.verdict || 'UNKNOWN';
  const conf = Math.round((result?.confidence || 0) * 100);
  const cls = result?.ai_analyst?.deep?.malware_classification?.category
           || result?.ai_analyst?.triage?.classification;
  const c = verdictColor(theme, v);
  return (
    <Box sx={{
      position: 'sticky', top: 0, zIndex: 10,
      backgroundColor: muiAlpha(theme.palette.background.default, 0.92),
      backdropFilter: 'blur(8px)',
      borderBottom: `1px solid ${muiAlpha('#ffffff', 0.08)}`,
      p: '12px 24px',
    }}>
      <Stack direction="row" alignItems="center" spacing={1.5} flexWrap="wrap">
        <FileText size={16} color={c}/>
        <Typography sx={{ ...monoSx, fontSize: 13, color: 'text.primary',
          fontWeight: 600, maxWidth: 360, overflow: 'hidden',
          textOverflow: 'ellipsis', whiteSpace: 'nowrap',
        }}>{result?.filename || 'no file'}</Typography>
        {cls && (
          <MuiChip label={cls} size="small" sx={{
            ...monoSx, height: 22, fontSize: 11,
            backgroundColor: muiAlpha(c, 0.18), color: c, fontWeight: 600,
            fontFamily: '"IBM Plex Mono", monospace',
          }}/>
        )}
        <MuiChip label={v} size="small" sx={{
          height: 22, fontSize: 11, fontWeight: 600,
          backgroundColor: muiAlpha(c, 0.18), color: c,
        }}/>
        {result && (
          <Typography sx={{ fontSize: 11, color: 'text.tertiary' }}>
            confidence {conf}%
          </Typography>
        )}
        {scanning && (
          <Stack direction="row" alignItems="center" spacing={0.75}>
            {/* Pulsing dot replaces the centered spinner — RECON no-spinner rule */}
            <Box sx={{
              width: 8, height: 8, borderRadius: 99,
              backgroundColor: 'primary.main',
              animation: 'pulse 1.2s ease-in-out infinite',
            }}/>
            <Typography sx={{ fontSize: 11, color: 'primary.main', fontWeight: 500 }}>
              analyzing…
            </Typography>
          </Stack>
        )}
      </Stack>
    </Box>
  );
}

function SectionNav({ visibleSections, currentSection, onJump }) {
  return (
    <Box sx={{
      display: { xs: 'none', lg: 'block' },
      position: 'sticky', top: 88, alignSelf: 'flex-start',
      width: 180, ml: 2,
    }}>
      <Typography sx={{ fontSize: 10, color: 'text.disabled', fontWeight: 600,
        textTransform: 'uppercase', letterSpacing: '0.08em', mb: 1 }}>
        On this page
      </Typography>
      <Stack spacing={0.25}>
        {SECTIONS.filter(s => visibleSections.has(s.id)).map(s => (
          <Box key={s.id} onClick={() => onJump(s.id)}
            sx={{
              ...monoSx, fontSize: 11, cursor: 'pointer',
              py: 0.375, pl: 1, borderLeft: '2px solid',
              borderColor: currentSection === s.id ? 'primary.main' : 'transparent',
              color: currentSection === s.id ? 'primary.main' : 'text.tertiary',
              fontWeight: currentSection === s.id ? 600 : 400,
              transition: 'all .15s',
              '&:hover': { color: 'text.primary' },
            }}>
            {s.label}
          </Box>
        ))}
      </Stack>
    </Box>
  );
}


// ─── Progress sidebar (left, only while scanning) ────────────────────────────
function ProgressTimeline({ progressStep }) {
  return (
    <MuiPaper elevation={0} sx={{
      backgroundColor: 'background.paper',
      border: `1px solid ${muiAlpha('#ffffff', 0.08)}`,
      borderRadius: '4px', p: 2, mb: 2,
    }}>
      <Typography sx={{ fontSize: 10, color: 'primary.main', fontWeight: 600,
        textTransform: 'uppercase', letterSpacing: '0.08em', mb: 1.25 }}>
        Analysis pipeline
      </Typography>
      {ANALYSIS_STEPS.map((label, i) => {
        const done    = i < progressStep;
        const current = i === progressStep;
        return (
          <Stack key={label} direction="row" alignItems="center" spacing={1} sx={{ py: 0.25 }}>
            <Box sx={{
              width: 10, height: 10, borderRadius: 99, flexShrink: 0,
              backgroundColor: done ? 'success.main' : current ? 'primary.main' : muiAlpha('#ffffff', 0.08),
              ...(current ? { animation: 'pulse 1.2s ease-in-out infinite' } : {}),
            }}/>
            <Typography sx={{
              fontSize: 11,
              color: done ? 'success.main' : current ? 'primary.main' : 'text.disabled',
              fontWeight: current ? 600 : 400,
            }}>{label}</Typography>
          </Stack>
        );
      })}
      <LinearProgress sx={{ mt: 1.25, height: 3, borderRadius: 99 }}
        variant="determinate" value={(progressStep / ANALYSIS_STEPS.length) * 100}/>
    </MuiPaper>
  );
}

// AI loading row used inside cards still waiting on the AI pipeline.
// Renders shimmer text lines instead of a spinner so the analyst sees
// the shape of what's about to land.
function AILoading({ text }) {
  return (
    <Box sx={{ py: 0.5 }}>
      {text && (
        <Typography sx={{ fontSize: 11, color: 'text.tertiary',
          fontStyle: 'italic', mb: 0.75, letterSpacing: '0.02em' }}>
          {text}
        </Typography>
      )}
      <Stack spacing={0.75}>
        <Skeleton width="88%" height={11}/>
        <Skeleton width="74%" height={11} delayMs={120}/>
        <Skeleton width="62%" height={11} delayMs={240}/>
      </Stack>
    </Box>
  );
}


// ─── Main FileScannerView ────────────────────────────────────────────────────
export default function FileScannerView({ external, onScanFile, onScanHash, onScanUrl }) {
  const [localResult, setLocalResult] = useState(null);
  const [localScanning, setLocalScanning] = useState(false);
  const [localStep, setLocalStep] = useState(0);
  const [localError, setLocalError] = useState(null);
  const progressTimer = useRef(null);
  const containerRef = useRef(null);
  const [currentSection, setCurrentSection] = useState('verdict');

  const result       = external?.result ?? localResult;
  const scanning     = external?.scanning ?? localScanning;
  const progressStep = external?.progressStep ?? localStep;
  const error        = external?.error ?? localError;
  const sidebarDriven = !!external;

  // Self-managed scan handlers (only used when no external props)
  const startProgress = () => {
    setLocalStep(0);
    let step = 0;
    progressTimer.current = setInterval(() => {
      step = Math.min(step + 1, ANALYSIS_STEPS.length - 1);
      setLocalStep(step);
    }, 700);
  };
  const stopProgress = () => {
    if (progressTimer.current) { clearInterval(progressTimer.current); progressTimer.current = null; }
    setLocalStep(ANALYSIS_STEPS.length);
  };
  useEffect(() => () => stopProgress(), []);

  const scanFile = onScanFile || (async (file) => {
    setLocalScanning(true); setLocalError(null); setLocalResult(null);
    startProgress();
    try {
      const form = new FormData();
      form.append('file', file);
      const r = await fetch('/api/scan/file', { method: 'POST', body: form });
      const d = await r.json();
      if (!r.ok) throw new Error(d.detail || `HTTP ${r.status}`);
      setLocalResult(d);
    } catch (e) { setLocalError(e.message); }
    finally { stopProgress(); setLocalScanning(false); }
  });

  // Track which section is currently in view (for the side nav). Sections
  // removed per analyst request (hunting / actions / notes / format / yara)
  // no longer register here.
  const visibleSections = useMemo(() => {
    if (!result) return new Set();
    const has = new Set();
    if (result.ai_analyst) {
      has.add('verdict');
      if (result.ai_analyst.deep?.technical_summary) has.add('technical');
      if (result.ai_analyst.deep?.execution_narrative) has.add('narrative');
      // Anomalies fold into Key Findings; both share the 'findings' anchor.
      if (result.ai_analyst.deep?.key_findings?.length
          || result.ai_analyst.deep?.anomalies?.length) has.add('findings');
    }
    if (result.hashes) has.add('identity');
    if (result.threat_intel && Object.keys(result.threat_intel).length) has.add('ti');
    if (result.capabilities?.tags?.length || result.capabilities?.mitre_techniques?.length) has.add('caps');
    if (result.iocs || result.suspicious_strings?.length) has.add('strings');
    // YARA + AI YARA now live inside Detection Content.
    if ((result.detections && Object.keys(result.detections).length)
        || (result.yara_matches || []).length
        || result.ai_yara?.rule) has.add('detect');
    return has;
  }, [result]);

  useEffect(() => {
    if (!result) return;
    const els = SECTIONS
      .map(s => document.getElementById(`section-${s.id}`))
      .filter(Boolean);
    const observer = new IntersectionObserver(entries => {
      const intersecting = entries.filter(e => e.isIntersecting)
        .sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top);
      if (intersecting[0]) {
        setCurrentSection(intersecting[0].target.id.replace('section-', ''));
      }
    }, { rootMargin: '-100px 0px -60% 0px', threshold: 0 });
    els.forEach(el => observer.observe(el));
    return () => observer.disconnect();
  }, [result]);

  const onJump = (id) => {
    const el = document.getElementById(`section-${id}`);
    if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };

  const onRefreshScan = (updated) => {
    if (sidebarDriven) {
      // The parent owns state — we can't update directly, but the data we
      // received IS the new scan. Push it via local state as override.
      setLocalResult(updated);
    } else {
      setLocalResult(updated);
    }
  };

  return (
    <Box ref={containerRef} sx={{
      flex: 1, minWidth: 0,
      backgroundColor: 'background.default',
      minHeight: '100vh',
      display: 'flex', flexDirection: 'column',
    }}>
      <StickyHeader result={result} scanning={scanning}/>

      <Box sx={{ display: 'flex', flex: 1, p: '20px 24px' }}>
        <Box sx={{ flex: 1, minWidth: 0, maxWidth: 980 }}>
          {/* Pre-scan submission panel (only when standalone use, no external) */}
          {!sidebarDriven && !result && !scanning && (
            <StandaloneSubmission scanFile={scanFile}/>
          )}

          {/* Live progress timeline while scanning */}
          {scanning && <ProgressTimeline progressStep={progressStep}/>}

          {/* Layout-matching skeleton while scanning is running but no result
              has yet populated. Once the backend persists the initial scan
              record, the real cards take over. Replaces the prior centered
              "no result yet" empty state during the scanning window. */}
          {scanning && !result && <SkeletonFileScanner/>}

          {/* Error display */}
          {error && (
            <MuiPaper elevation={0} sx={{
              p: 1.5, mb: 2,
              backgroundColor: muiAlpha('#EE3838', 0.06),
              border: `1px solid ${muiAlpha('#EE3838', 0.3)}`,
              borderLeft: '3px solid #EE3838', borderRadius: '4px',
              color: 'error.main', fontSize: 12,
            }}>{error}</MuiPaper>
          )}

          {!result && !scanning && (
            <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'center',
              height: '60vh', color: 'text.disabled' }}>
              <Shield size={64} color={muiAlpha('#ffffff', 0.08)}/>
            </Box>
          )}

          {result && (() => {
            // URL scan branch — render the dedicated reputation report.
            // The downloaded payload's malware-analysis sections only render
            // when there's a real reason to look at them (YARA matched, AI
            // verdict is MALICIOUS/SUSPICIOUS, or threat-intel cross-refs
            // fired on the file hash). Otherwise the analyst gets a clean
            // URL-reputation view with no irrelevant file-analysis chrome.
            // Toggle below lets them surface the file detail when curious.
            const isUrlScan = !!result.source_url;
            const yaraHits = (result.yara_matches || []).filter(m => m && !m.error).length;
            const ti = result.threat_intel || {};
            const tiHits = ['virustotal','malwarebazaar','hybrid_analysis','anyrun']
              .some(k => ti[k]?.found);
            const fileHasSignal = yaraHits > 0 || tiHits
              || ['MALICIOUS','SUSPICIOUS'].includes(result.verdict);

            if (isUrlScan) {
              // Compact identity banner — Domain registered + Registrar +
              // Last Wayback snapshot. Lives at the very top of the URL
              // scanner so the analyst sees domain age / first-seen
              // before they kick off detonation or scroll through the
              // reputation report.
              let _host = '';
              try { _host = new URL(result.source_url || '').hostname; }
              catch { _host = ''; }
              const _dom    = result?.enrichments?.domains?.[_host] || {};
              const _whois  = _dom.whois || null;
              const _wb     = _dom.wayback || null;
              const _ageDays = _whois?.age_days;
              const _topFactoids = [
                _whois?.created && {
                  label: 'Domain registered',
                  value: _ageDays != null
                    ? `${_formatDate(_whois.created)}  (${_ageDays}d ago)`
                    : _formatDate(_whois.created),
                  accent: _ageDays != null && _ageDays < 30 ? '#E6700F' : null,
                },
                _whois?.registrar && {
                  label: 'Registrar',
                  value: _whois.registrar,
                },
                _wb?.last_snapshot && {
                  label: 'Last Wayback snapshot',
                  value: _formatDate(_wb.last_snapshot),
                },
              ].filter(Boolean);

              return (
                <Stack spacing={3}>
                  {/* Soft-fail download banner — when the remote site
                      refused the GET, we didn't get the file body. URL
                      reputation + WHOIS + Wayback + URLScan submission
                      still ran. Styled as a neutral note (not a warning)
                      because bot-protected HTML pages are the common
                      case here, not a real problem. */}
                  {result.download_warning && (
                    <MuiPaper elevation={0} sx={{
                      backgroundColor: muiAlpha('#0fbcff', 0.05),
                      border: `1px solid ${muiAlpha('#0fbcff', 0.25)}`,
                      borderLeft: '3px solid #0fbcff',
                      borderRadius: '4px', p: '10px 14px',
                    }}>
                      <Typography sx={{ fontSize: 11, color: '#0fbcff',
                        fontWeight: 700, textTransform: 'uppercase',
                        letterSpacing: '0.06em', mb: 0.5 }}>
                        Page not downloadable
                      </Typography>
                      <Typography sx={{ fontSize: 12.5, color: 'text.primary',
                        lineHeight: 1.55 }}>
                        {result.download_warning}
                      </Typography>
                    </MuiPaper>
                  )}

                  {/* URL identity banner — Domain registered / Registrar /
                      Last Wayback snapshot. Pinned at the very top so the
                      analyst sees domain-age signal before doing anything
                      else. Hidden when none of the three factoids has a
                      value. */}
                  {_topFactoids.length > 0 && (
                    <MuiPaper elevation={0} sx={{
                      backgroundColor: '#09253d',
                      border: `1px solid ${muiAlpha('#ffffff', 0.12)}`,
                      borderLeft: '3px solid #0fbcff',
                      borderRadius: '4px', p: '12px 16px',
                    }}>
                      <Typography sx={{ fontSize: 10, color: 'text.disabled',
                        fontWeight: 600, textTransform: 'uppercase',
                        letterSpacing: '0.08em', mb: 1 }}>
                        URL identity · {_host || '(unknown host)'}
                      </Typography>
                      <Box sx={{ display: 'grid',
                        gridTemplateColumns: { xs: '1fr', sm: 'repeat(3, 1fr)' },
                        gap: '6px 18px' }}>
                        {_topFactoids.map((f, i) => (
                          <Box key={i}>
                            <Typography sx={{ fontSize: 10,
                              color: 'text.disabled', fontWeight: 600,
                              textTransform: 'uppercase',
                              letterSpacing: '0.07em' }}>
                              {f.label}
                            </Typography>
                            <Typography sx={{ fontSize: 12.5,
                              color: f.accent || 'text.primary',
                              ...monoSx, wordBreak: 'break-word',
                              fontWeight: f.accent ? 600 : 400 }}>
                              {f.value}
                            </Typography>
                          </Box>
                        ))}
                      </Box>
                    </MuiPaper>
                  )}

                  {/* Live URL detonation pinned near the top — the
                      analyst wants to kick the detonation off and see
                      its progress before scrolling through reputation
                      details. Pre-populated with [source_url] so the
                      Submit button is one click away. */}
                  <URLScanLive result={result} urls={[result.source_url]}/>
                  <UrlReputationReport result={result}/>
                  {fileHasSignal && (
                    <UrlFileAnalysisExpander result={result} onRefreshScan={onRefreshScan}
                      autoOpen={['MALICIOUS','SUSPICIOUS'].includes(result.verdict)}/>
                  )}
                </Stack>
              );
            }
            return (
              <Stack spacing={3}>
                <VerdictBanner result={result}/>
                <TechnicalAssessment result={result}/>
                <ExecutionNarrative result={result}/>
                {/* Anomalies are fused into Key Findings (anomaly-flagged
                    rows) — no separate Anomalies card. */}
                <KeyFindings result={result}/>
                <FileIdentity result={result}/>
                <ThreatIntelSection result={result}/>
                <CapabilitiesSection result={result}/>
                <StringsSection result={result}/>
                {/* Detection Content also hosts YARA matches. */}
                <DetectionContent result={result}/>
              </Stack>
            );
          })()}
        </Box>

        {result && (
          <SectionNav
            visibleSections={visibleSections}
            currentSection={currentSection}
            onJump={onJump}
          />
        )}
      </Box>

    </Box>
  );
}


// Standalone drop zone — only used when the view is opened outside the
// sidebar-driven flow. In the production app this almost never runs.
function StandaloneSubmission({ scanFile }) {
  const [dragOver, setDragOver] = useState(false);
  return (
    <MuiPaper elevation={0} sx={{
      backgroundColor: 'background.paper',
      border: `2px dashed ${dragOver ? '#B286FF' : muiAlpha('#ffffff', 0.12)}`,
      borderRadius: '6px', p: '60px 24px', textAlign: 'center',
      cursor: 'pointer', transition: 'all .15s',
    }}
      onDragOver={e => { e.preventDefault(); setDragOver(true); }}
      onDragLeave={() => setDragOver(false)}
      onDrop={e => {
        e.preventDefault(); setDragOver(false);
        scanFile(e.dataTransfer.files[0]);
      }}
      onClick={() => document.getElementById('fsv-standalone-input').click()}
    >
      <FileSearch size={48} color={dragOver ? '#B286FF' : '#848592'}
        style={{ marginBottom: 12 }}/>
      <Typography sx={{ fontSize: 14, color: 'text.primary', fontWeight: 500 }}>
        Drop a file to analyze
      </Typography>
      <Typography sx={{ fontSize: 11, color: 'text.tertiary', mt: 0.5 }}>
        ≤ 50 MB
      </Typography>
      <input id="fsv-standalone-input" type="file" style={{ display: 'none' }}
        onChange={e => scanFile(e.target.files[0])}/>
    </MuiPaper>
  );
}
