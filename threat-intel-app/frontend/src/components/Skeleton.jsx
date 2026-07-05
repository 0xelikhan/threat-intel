/**
 * Skeleton — RECON-styled loading placeholders.
 *
 * Replaces every centered loading spinner on the platform with a layout-
 * matching skeleton that pulses gently in the RECON cyan accent. Analysts
 * see WHERE results will appear before they arrive, which makes the
 * platform feel meaningfully faster even when load times are the same.
 *
 * Exports:
 *   <Skeleton ...>                   primitive: line | rect | circle shape
 *   <SkeletonLazyFallback height />  generic chunk-loading fallback
 *   <SkeletonAnalyze />              full analyze pipeline preview
 *   <SkeletonFileScanner />          file-scanner preview
 *   <SkeletonHistoryRows count />    history sidebar rows
 *   <SkeletonChart variant />        chart shape (dial | bars | sparkline)
 *
 * Animation: the shimmer is a single global @keyframes rule injected once
 * via a styled tag (MUI's GlobalStyles equivalent — using a one-time
 * useEffect so we don't reach for @emotion/react). The animation runs on
 * background-position so the GPU compositor handles it.
 */
import React, { useEffect, useRef } from 'react';
import { Box, Stack } from '@mui/material';
import { alpha as muiAlpha } from '@mui/material/styles';


// ─── one-time shimmer keyframe injection ─────────────────────────────────────
const _SHIMMER_NAME    = 'recon-skel-shimmer';
const _PULSE_NAME      = 'recon-skel-pulse';
const _ACCENT          = '#0fbcff';
const _DARK_BG         = '#09253d';
const _BORDER          = 'rgba(255,255,255,0.10)';

function _ensureKeyframes() {
  if (typeof document === 'undefined') return;
  if (document.getElementById('recon-skel-style')) return;
  const style = document.createElement('style');
  style.id = 'recon-skel-style';
  style.textContent = `
    @keyframes ${_SHIMMER_NAME} {
      0%   { background-position: -200% 0; }
      100% { background-position:  200% 0; }
    }
    @keyframes ${_PULSE_NAME} {
      0%, 100% { opacity: 0.55; }
      50%      { opacity: 1; }
    }
  `;
  document.head.appendChild(style);
}


// ─── primitive ───────────────────────────────────────────────────────────────
/**
 * Primitive skeleton block. The default behaviour is a labelled rectangle
 * with the shimmer gradient. Override `shape="circle"` for round dots or
 * "line" for a thin text-line placeholder.
 */
export function Skeleton({
  width        = '100%',
  height       = 14,
  shape        = 'rect',          // 'rect' | 'line' | 'circle'
  radius       = 4,
  sx           = {},
  delayMs      = 0,
}) {
  const ref = useRef(null);
  useEffect(() => { _ensureKeyframes(); }, []);

  const resolvedHeight = shape === 'line'   ? 12
                       : shape === 'circle' ? width
                       :                       height;
  const resolvedWidth  = shape === 'circle' ? width : width;
  const resolvedRadius = shape === 'circle' ? '50%' : radius;

  return (
    <Box
      ref={ref}
      sx={{
        display: 'inline-block',
        width:  resolvedWidth,
        height: resolvedHeight,
        borderRadius: resolvedRadius,
        // Base dark surface with a moving cyan-tinted highlight band. The
        // gradient stops are tuned so the highlight is subtle (not a flash).
        background: `linear-gradient(90deg,
            ${muiAlpha('#ffffff', 0.04)} 0%,
            ${muiAlpha(_ACCENT, 0.12)} 20%,
            ${muiAlpha('#ffffff', 0.06)} 40%,
            ${muiAlpha('#ffffff', 0.04)} 100%)`,
        backgroundSize: '200% 100%',
        animation: `${_SHIMMER_NAME} 1.8s linear infinite`,
        animationDelay: `${delayMs}ms`,
        ...sx,
      }}
    />
  );
}


// ─── RECON-styled card wrapper used by every contextual skeleton ─────────────
function SkelCard({ accent = _ACCENT, children, sx = {} }) {
  return (
    <Box sx={{
      backgroundColor: _DARK_BG,
      border: `1px solid ${_BORDER}`,
      borderLeft: `3px solid ${muiAlpha(accent, 0.5)}`,
      borderRadius: '4px',
      p: 2,
      mb: 1.5,
      ...sx,
    }}>
      {children}
    </Box>
  );
}


// ─── generic chunk-loading fallback ──────────────────────────────────────────
/**
 * Drop-in replacement for the old LazyFallback. Renders a card outline
 * with a few shimmer lines so React.lazy chunks have a layout-stable
 * placeholder while the chunk downloads.
 */
export function SkeletonLazyFallback({ height = 200, label }) {
  useEffect(() => { _ensureKeyframes(); }, []);
  return (
    <SkelCard sx={{ minHeight: height, mb: 0 }}>
      <Stack spacing={1.25}>
        <Skeleton width="42%" height={16} radius={3}/>
        <Skeleton width="78%" height={10} radius={3} delayMs={120}/>
        <Skeleton width="65%" height={10} radius={3} delayMs={220}/>
        <Skeleton width="55%" height={10} radius={3} delayMs={320}/>
      </Stack>
      {label && (
        <Box sx={{
          mt: 1, fontSize: 10, color: 'text.disabled', fontFamily: 'monospace',
          letterSpacing: '0.06em', textTransform: 'uppercase',
        }}>
          {label}
        </Box>
      )}
    </SkelCard>
  );
}


// ─── analyze pipeline preview ────────────────────────────────────────────────
/**
 * Layout-matching skeleton for the analyze view: threat banner, IOC verdicts
 * list, key findings list, detection rules. Shown when the pipeline has
 * started but no partial_result event has yet populated the real cards.
 */
export function SkeletonAnalyze() {
  useEffect(() => { _ensureKeyframes(); }, []);
  return (
    <Box>
      {/* "Analyzing" banner — explicit signal that the pipeline is
          running. Sits at the top of the placeholder layout so analysts
          can tell at a glance that the empty cards below are deferred
          rendering, not an empty result. */}
      <Box sx={{
        mb: 1.5, p: '12px 14px', borderRadius: '4px',
        backgroundColor: muiAlpha(_ACCENT, 0.08),
        border: `1px solid ${muiAlpha(_ACCENT, 0.32)}`,
        display: 'flex', alignItems: 'center', gap: 1.25,
      }}>
        <Box sx={{
          width: 9, height: 9, borderRadius: '50%',
          backgroundColor: _ACCENT,
          animation: `${_PULSE_NAME} 1.4s ease-in-out infinite`,
          flexShrink: 0,
        }}/>
        <Box sx={{
          fontSize: 12.5, fontWeight: 600, color: _ACCENT,
          letterSpacing: '0.04em', textTransform: 'uppercase',
        }}>
          Analyzing
        </Box>
        <Box sx={{ fontSize: 11.5, color: 'text.tertiary', ml: 0.5 }}>
          triage → enrichment → investigation → response
        </Box>
      </Box>
      {/* Enrichment summary line (cyan banner) */}
      <Box sx={{
        mb: 1.5, p: '8px 12px', borderRadius: '4px',
        backgroundColor: muiAlpha(_ACCENT, 0.05),
        border: `1px solid ${muiAlpha(_ACCENT, 0.18)}`,
      }}>
        <Skeleton width="62%" height={11}/>
      </Box>

      {/* Threat banner / Summary card */}
      <SkelCard>
        <Stack spacing={1.5}>
          <Stack direction="row" spacing={1.25} alignItems="center">
            <Skeleton width={48} height={20} radius={3}/>
            <Skeleton width="40%" height={14}/>
          </Stack>
          <Skeleton width="92%" height={11} delayMs={100}/>
          <Skeleton width="88%" height={11} delayMs={160}/>
          <Skeleton width="46%" height={11} delayMs={220}/>
        </Stack>
      </SkelCard>

      {/* IOC verdicts list */}
      <SkelCard accent="#ffd700">
        <Skeleton width="34%" height={12} sx={{ mb: 1.5 }}/>
        <Stack spacing={1}>
          {[0, 1, 2, 3].map(i => (
            <Stack key={i} direction="row" spacing={1.25} alignItems="center">
              <Skeleton width={64} height={20} radius={3} delayMs={i * 80}/>
              <Skeleton width="38%" height={12} delayMs={i * 80 + 40}/>
              <Box sx={{ flex: 1 }}/>
              <Skeleton width={56} height={18} radius={3} delayMs={i * 80 + 80}/>
            </Stack>
          ))}
        </Stack>
      </SkelCard>

      {/* Key findings list */}
      <SkelCard accent="#ff8c00">
        <Skeleton width="28%" height={12} sx={{ mb: 1.5 }}/>
        <Stack spacing={1}>
          {[0, 1, 2].map(i => (
            <Stack key={i} direction="row" spacing={1} alignItems="flex-start">
              <Skeleton width={6} height={6} shape="circle" sx={{ mt: '6px' }} delayMs={i * 100}/>
              <Box sx={{ flex: 1 }}>
                <Skeleton width="92%" height={11} delayMs={i * 100 + 30}/>
                <Box sx={{ mt: 0.5 }}>
                  <Skeleton width="74%" height={10} delayMs={i * 100 + 80}/>
                </Box>
              </Box>
            </Stack>
          ))}
        </Stack>
      </SkelCard>

      {/* Detection rules */}
      <SkelCard accent="#17AB1F">
        <Skeleton width="40%" height={12} sx={{ mb: 1.5 }}/>
        <Box sx={{
          backgroundColor: '#070d19',
          border: `1px solid ${muiAlpha('#ffffff', 0.05)}`,
          borderRadius: 1, p: 1.25,
        }}>
          {[0, 1, 2, 3, 4, 5].map(i => (
            <Box key={i} sx={{ mb: i < 5 ? 0.5 : 0 }}>
              <Skeleton width={`${50 + (i * 7) % 35}%`} height={9} radius={2}
                delayMs={i * 60}/>
            </Box>
          ))}
        </Box>
      </SkelCard>
    </Box>
  );
}


// ─── file scanner preview ────────────────────────────────────────────────────
/**
 * Layout-matching skeleton for the file scanner: file identity card,
 * YARA results, threat intelligence section. No centered spinner.
 */
export function SkeletonFileScanner() {
  useEffect(() => { _ensureKeyframes(); }, []);
  return (
    <Box>
      {/* File identity */}
      <SkelCard>
        <Stack spacing={1.25}>
          <Stack direction="row" spacing={1.25} alignItems="center">
            <Skeleton width={32} height={32} shape="circle"/>
            <Box sx={{ flex: 1 }}>
              <Skeleton width="58%" height={14}/>
              <Box sx={{ mt: 0.5 }}>
                <Skeleton width="32%" height={10} delayMs={80}/>
              </Box>
            </Box>
            <Skeleton width={72} height={22} radius={3} delayMs={120}/>
          </Stack>
          <Stack direction="row" spacing={2}>
            {[0, 1, 2, 3].map(i => (
              <Stack key={i} spacing={0.5} sx={{ flex: 1 }}>
                <Skeleton width="60%" height={9} delayMs={i * 70}/>
                <Skeleton width="85%" height={12} delayMs={i * 70 + 50}/>
              </Stack>
            ))}
          </Stack>
        </Stack>
      </SkelCard>

      {/* YARA results */}
      <SkelCard accent="#ff8c00">
        <Skeleton width="28%" height={12} sx={{ mb: 1.5 }}/>
        <Stack spacing={1}>
          {[0, 1, 2].map(i => (
            <Stack key={i} direction="row" spacing={1.25} alignItems="center">
              <Skeleton width={6} height={6} shape="circle" delayMs={i * 80}/>
              <Skeleton width="44%" height={11} delayMs={i * 80 + 30}/>
              <Skeleton width={56} height={16} radius={3} delayMs={i * 80 + 80}/>
            </Stack>
          ))}
        </Stack>
      </SkelCard>

      {/* Threat intelligence sources */}
      <SkelCard accent="#17AB1F">
        <Skeleton width="36%" height={12} sx={{ mb: 1.5 }}/>
        <Box sx={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
          gap: 1.25,
        }}>
          {['VirusTotal', 'MalwareBazaar', 'OTX', 'ThreatFox'].map((src, i) => (
            <Box key={src} sx={{
              p: 1.25, borderRadius: 1,
              border: `1px solid ${_BORDER}`,
              backgroundColor: muiAlpha('#ffffff', 0.02),
            }}>
              <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 0.75 }}>
                <Box sx={{ fontSize: 10, color: 'text.disabled',
                  textTransform: 'uppercase', letterSpacing: '0.06em',
                  fontFamily: 'monospace' }}>
                  {src}
                </Box>
                <Skeleton width={28} height={10} radius={2} delayMs={i * 100}/>
              </Stack>
              <Skeleton width="78%" height={11} delayMs={i * 100 + 40}/>
            </Box>
          ))}
        </Box>
      </SkelCard>
    </Box>
  );
}


// ─── history rows ────────────────────────────────────────────────────────────
/**
 * Replaces the "Loading..." text in the case-history sidebar. Renders the
 * same row shape (label + threat-level badge + IOC count + time) as a
 * real history row so the layout stays put when the data arrives.
 */
export function SkeletonHistoryRows({ count = 5 }) {
  useEffect(() => { _ensureKeyframes(); }, []);
  return (
    <Box>
      {Array.from({ length: count }).map((_, i) => (
        <Box key={i} sx={{
          padding: '10px 14px',
          borderBottom: '1px solid #060d1a',
        }}>
          <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: '4px' }}>
            <Skeleton width={`${55 + (i % 4) * 7}%`} height={12} delayMs={i * 80}/>
            <Skeleton width={48} height={14} radius={3} delayMs={i * 80 + 30}/>
          </Stack>
          <Stack direction="row" justifyContent="space-between" alignItems="center">
            <Skeleton width="38%" height={9} delayMs={i * 80 + 70}/>
            <Skeleton width="20%" height={9} delayMs={i * 80 + 100}/>
          </Stack>
        </Box>
      ))}
    </Box>
  );
}


// ─── chart skeleton ──────────────────────────────────────────────────────────
/**
 * Layout-matching skeleton for charts. `variant`:
 *   'dial'      — circular dial + tier-distribution bars
 *   'bars'      — horizontal bar chart
 *   'sparkline' — single-line sparkline
 */
export function SkeletonChart({ variant = 'dial', height = 180 }) {
  useEffect(() => { _ensureKeyframes(); }, []);
  if (variant === 'dial') {
    return (
      <Box sx={{
        display: 'grid', gridTemplateColumns: 'auto 1fr', gap: 2.5,
        alignItems: 'center', py: 1,
      }}>
        <Stack alignItems="center" spacing={1}>
          <Skeleton width={120} height={120} shape="circle"/>
          <Skeleton width={64} height={16} radius={3} delayMs={120}/>
          <Skeleton width={48} height={9} radius={2} delayMs={180}/>
        </Stack>
        <Stack spacing={0.75}>
          {[0, 1, 2, 3, 4].map(i => (
            <Stack key={i} direction="row" spacing={1.25} alignItems="center">
              <Skeleton width={70} height={10} delayMs={i * 70}/>
              <Box sx={{ flex: 1 }}>
                <Skeleton width={`${30 + ((i * 17) % 60)}%`} height={6} radius={99} delayMs={i * 70 + 40}/>
              </Box>
              <Skeleton width={20} height={10} delayMs={i * 70 + 80}/>
            </Stack>
          ))}
        </Stack>
      </Box>
    );
  }
  if (variant === 'bars') {
    return (
      <Stack direction="row" spacing={1} alignItems="flex-end" sx={{ height, p: 1.5 }}>
        {[0, 1, 2, 3, 4, 5, 6, 7].map(i => {
          const h = 30 + ((i * 23) % 70);
          return <Skeleton key={i} width={28} height={`${h}%`} delayMs={i * 50}/>;
        })}
      </Stack>
    );
  }
  // sparkline
  return (
    <Box sx={{ p: 1.5 }}>
      <Skeleton width="100%" height={height}/>
    </Box>
  );
}


export default Skeleton;
