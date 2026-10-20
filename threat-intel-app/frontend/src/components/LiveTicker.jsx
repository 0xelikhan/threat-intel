/**
 * LiveTicker — horizontal scrolling list of recently-enriched IOCs.
 *
 * Polls /api/recent-iocs every 3 seconds (public endpoint — no auth).
 * The backend's in-memory ring buffer keeps the last 50 IOCs; this
 * component renders the newest 20 as pill chips sliding right-to-left
 * via CSS keyframes. Each pill is colour-coded by verdict.
 *
 * No local state persists across refresh — matches the ethos of
 * "no history, no logs" we agreed on. On backend restart the ticker
 * starts empty and refills within a minute of real traffic.
 */
import React, { useEffect, useRef, useState } from 'react';
import { Box, Typography } from '@mui/material';

const VERDICT_COLOR = {
  MALICIOUS:  '#ef4444',
  SUSPICIOUS: '#e1b823',
  CLEAN:      '#00ff41',
  UNKNOWN:    '#94a3b8',
};

// How many pills to show. Backend caps the deque at 50 — we display
// the most recent 20 so the ticker doesn't get crowded on busy runs.
const SHOW_LAST = 20;
const POLL_MS   = 3000;


function cookieFetch(url, opts = {}) {
  return fetch(url, { credentials: 'include', ...opts });
}


function _formatValue(value, type) {
  if (!value) return '';
  // Truncate long values but keep enough to be recognisable.
  const trimmed = String(value);
  if (trimmed.length <= 28) return trimmed;
  // IPs and hashes read better truncated at the start AND end
  if (type === 'sha256' || type === 'sha1' || type === 'md5') {
    return trimmed.slice(0, 10) + '…' + trimmed.slice(-6);
  }
  if (type === 'url') {
    return trimmed.length <= 36 ? trimmed : trimmed.slice(0, 32) + '…';
  }
  return trimmed.slice(0, 25) + '…';
}


function _timeAgo(iso) {
  if (!iso) return '';
  try {
    const diff = (Date.now() - new Date(iso).getTime()) / 1000;
    if (diff < 60)   return `${Math.max(0, Math.round(diff))}s ago`;
    if (diff < 3600) return `${Math.round(diff / 60)}m ago`;
    return `${Math.round(diff / 3600)}h ago`;
  } catch {
    return '';
  }
}


export default function LiveTicker() {
  const [iocs, setIocs] = useState([]);
  const [reachable, setReachable] = useState(true);
  const containerRef = useRef(null);

  useEffect(() => {
    let cancelled = false;
    const poll = async () => {
      try {
        const r = await cookieFetch('/api/recent-iocs');
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const j = await r.json();
        if (cancelled) return;
        // Newest first — reverse the deque order so the ticker reads
        // "freshest IOC on the left, scrolling right→left".
        const list = Array.isArray(j.iocs) ? [...j.iocs].reverse() : [];
        setIocs(list.slice(0, SHOW_LAST));
        setReachable(true);
      } catch {
        if (!cancelled) setReachable(false);
      }
    };
    poll();
    const id = setInterval(poll, POLL_MS);
    return () => { cancelled = true; clearInterval(id); };
  }, []);

  if (!reachable) {
    // Fail quietly — the ticker is a dashboard accessory, not critical.
    return null;
  }

  return (
    <Box sx={{
      position: 'relative',
      overflow: 'hidden',
      borderBottom: '1px solid rgba(0,147,238,0.15)',
      background: 'linear-gradient(90deg, #060b1c 0%, #0a1628 50%, #060b1c 100%)',
      height: 36,
      display: 'flex',
      alignItems: 'center',
      '&::before': {
        content: '""',
        position: 'absolute', top: 0, left: 0, width: 80, height: '100%',
        background: 'linear-gradient(90deg, #060b1c 0%, transparent 100%)',
        zIndex: 2, pointerEvents: 'none',
      },
      '&::after': {
        content: '""',
        position: 'absolute', top: 0, right: 0, width: 80, height: '100%',
        background: 'linear-gradient(270deg, #060b1c 0%, transparent 100%)',
        zIndex: 2, pointerEvents: 'none',
      },
    }}>
      <Box sx={{
        display: 'flex',
        alignItems: 'center',
        gap: 1,
        pl: 2, pr: 1,
        zIndex: 3,
        background: '#060b1c',
        borderRight: '1px solid rgba(0,147,238,0.2)',
        height: '100%',
      }}>
        <Box className="nc-live-dot" />
        <Typography sx={{
          fontFamily: '"JetBrains Mono", monospace',
          fontSize: 10, fontWeight: 600,
          color: '#00e5ff',
          textTransform: 'uppercase', letterSpacing: '0.1em',
          whiteSpace: 'nowrap',
        }}>
          LIVE · {iocs.length} RECENT
        </Typography>
      </Box>

      <Box ref={containerRef} sx={{
        display: 'flex',
        alignItems: 'center',
        gap: 1,
        flex: 1,
        overflowX: 'auto',
        overflowY: 'hidden',
        pl: 1,
        '&::-webkit-scrollbar': { display: 'none' },
        msOverflowStyle: 'none', scrollbarWidth: 'none',
        animation: iocs.length >= 8 ? 'nc-ticker-scroll 60s linear infinite' : 'none',
        '@keyframes nc-ticker-scroll': {
          '0%':   { transform: 'translateX(0)' },
          '100%': { transform: 'translateX(-50%)' },
        },
      }}>
        {iocs.length === 0 ? (
          <Typography sx={{
            fontFamily: '"JetBrains Mono", monospace',
            fontSize: 10, color: '#5a6b8a',
            whiteSpace: 'nowrap', px: 2,
          }}>
            no recent activity — enrich an IOC to populate
          </Typography>
        ) : (
          // Duplicate the list when it's long enough to animate — gives
          // the marquee a seamless wrap at the halfway point.
          (iocs.length >= 8 ? [...iocs, ...iocs] : iocs).map((ioc, i) => (
            <Box key={`${ioc.at}-${i}`} sx={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 0.75,
              px: 1, py: 0.25,
              borderRadius: 1,
              border: `1px solid ${VERDICT_COLOR[ioc.verdict] || VERDICT_COLOR.UNKNOWN}30`,
              background: `${VERDICT_COLOR[ioc.verdict] || VERDICT_COLOR.UNKNOWN}10`,
              flexShrink: 0,
              fontFamily: '"JetBrains Mono", monospace',
              fontSize: 10,
              lineHeight: 1.4,
              whiteSpace: 'nowrap',
            }}>
              <Box sx={{
                width: 4, height: 4, borderRadius: '50%',
                background: VERDICT_COLOR[ioc.verdict] || VERDICT_COLOR.UNKNOWN,
                flexShrink: 0,
              }} />
              <Typography component="span" sx={{
                fontFamily: 'inherit', fontSize: 'inherit',
                color: '#94a3b8', textTransform: 'uppercase',
              }}>
                {ioc.type}
              </Typography>
              <Typography component="span" sx={{
                fontFamily: 'inherit', fontSize: 'inherit',
                color: '#e6edf3', fontWeight: 500,
              }}>
                {_formatValue(ioc.value, ioc.type)}
              </Typography>
              {ioc.sources > 0 && (
                <Typography component="span" sx={{
                  fontFamily: 'inherit', fontSize: 'inherit',
                  color: '#5a6b8a',
                }}>
                  · {ioc.sources}src
                </Typography>
              )}
              <Typography component="span" sx={{
                fontFamily: 'inherit', fontSize: 9,
                color: '#5a6b8a',
              }}>
                {_timeAgo(ioc.at)}
              </Typography>
            </Box>
          ))
        )}
      </Box>
    </Box>
  );
}
