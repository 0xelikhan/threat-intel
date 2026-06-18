/**
 * URLScan.io live submission block — analyst clicks Submit, we POST to
 * /api/urlscan/submit, then poll /api/urlscan/result/<uuid> every 10s
 * until ready or 3 min elapsed. Renders verdict + screenshot + page
 * metadata + WHOIS registration date + Wayback last-snapshot date.
 *
 * Used in two places:
 *   • Analyze view (Triage card → top section when iocs.urls is non-empty)
 *   • File scanner URL-scan branch (passes [source_url] as the urls prop)
 *
 * Extracted out of App.js so the file scanner can import it without the
 * circular dependency App.js ↔ FileScannerView.jsx that a re-export
 * would have introduced.
 */
import React, { useEffect, useMemo, useState } from 'react';
import { cookieFetch } from '../utils/api';
import {
  Box, Stack, Typography, Paper as MuiPaper,
  Button as MuiButton, TextField as MuiTextField,
} from '@mui/material';
import { alpha as muiAlpha } from '@mui/material/styles';
import { ArrowUpRight } from 'lucide-react';
import { Card as MuiCard, Tag as MuiTag } from './ui';

export default function URLScanLive({ result, bare, urls: urlsProp }) {
  // urlsProp overrides result.iocs.urls so callers that already know the
  // exact URL (the URL scanner passing source_url) don't have to mutate
  // a fake IOC list. Falls back to result.iocs.urls for the analyze flow
  // where multiple URLs may have been extracted from a log.
  // useMemo: holding a stable reference so the useEffect's deps array
  // doesn't see a fresh array identity on every parent render.
  const urls = useMemo(
    () => Array.isArray(urlsProp) ? urlsProp : (result?.iocs?.urls || []),
    [urlsProp, result?.iocs?.urls],
  );
  const [target, setTarget] = useState(urls[0] || '');
  const [submission, setSubmission] = useState(null);

  useEffect(() => {
    if (urls[0] && !target) setTarget(urls[0]);
  }, [urls, target]);

  const submit = async () => {
    if (!target) return;
    setSubmission({ state: 'submitting', url: target });
    try {
      const r = await cookieFetch('/api/urlscan/submit', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: target, visibility: 'unlisted' }),
      });
      const d = await r.json();
      if (!r.ok) throw new Error(d.detail || d.error || `HTTP ${r.status}`);
      setSubmission({ state: 'polling', url: target,
        uuid: d.uuid, result_url: d.result_url });
    } catch (e) {
      setSubmission({ state: 'error', url: target, error: e.message });
    }
  };

  useEffect(() => {
    if (submission?.state !== 'polling' || !submission?.uuid) return;
    let attempts = 0;
    const poll = async () => {
      attempts++;
      try {
        const r = await cookieFetch(`/api/urlscan/result/${submission.uuid}`);
        const d = await r.json();
        if (d.ready) {
          setSubmission(s => ({ ...s, state: 'done', report: d }));
        } else if (attempts > 18) {
          setSubmission(s => ({ ...s, state: 'timeout' }));
        }
      } catch {}
    };
    const interval = setInterval(poll, 10000);
    poll();
    return () => clearInterval(interval);
  }, [submission?.state, submission?.uuid]);

  if (!urls.length) return null;
  const monoSx = { fontFamily: '"IBM Plex Mono", monospace' };
  const busy = submission?.state === 'submitting' || submission?.state === 'polling';

  // WHOIS / Wayback for the current target — populated by both /api/scan/url
  // and the analyze enrichment fan-out. Lets the done-state grid show
  // registration date + last-snapshot alongside the URLScan report.
  let _whoisInfo = null;
  let _waybackInfo = null;
  try {
    const host = target ? new URL(target).hostname : '';
    if (host) {
      const dom = result?.enrichments?.domains?.[host] || {};
      _whoisInfo   = dom.whois || null;
      _waybackInfo = dom.wayback || null;
    }
  } catch {}
  const _fmtDate = (s) => {
    if (!s) return '';
    try {
      const d = new Date(s);
      if (!isNaN(d.getTime())) return d.toISOString().slice(0, 10);
    } catch {}
    return String(s).slice(0, 16);
  };
  const _regLine = _whoisInfo?.created
    ? `${_fmtDate(_whoisInfo.created)}`
      + (_whoisInfo.age_days != null ? ` (${_whoisInfo.age_days}d ago)` : '')
    : '';
  const _lastSnapLine = _waybackInfo?.last_snapshot
    ? _fmtDate(_waybackInfo.last_snapshot) : '';

  const body = (
    <>
      <Stack direction="row" spacing={1} sx={{ mb: 1.5 }}>
        <MuiTextField
          select SelectProps={{ native: true }}
          value={target} onChange={e => setTarget(e.target.value)}
          size="small" fullWidth
          sx={{ '& .MuiInputBase-input': { ...monoSx, fontSize: 12 } }}
        >
          {urls.map(u => (
            <option key={u} value={u}>
              {u.length > 80 ? u.slice(0, 77) + '…' : u}
            </option>
          ))}
        </MuiTextField>
        <MuiButton variant="contained" size="small" onClick={submit}
          disabled={busy} sx={{ minWidth: 100 }}>
          Submit
        </MuiButton>
      </Stack>

      {submission?.state === 'submitting' && (
        <Typography sx={{ fontSize: 12, color: 'text.tertiary' }}>
          Submitting to URLScan…
        </Typography>
      )}
      {submission?.state === 'polling' && (
        <Typography sx={{ fontSize: 12, color: 'primary.main' }}>
          Scan in progress, polling every 10s (typically 30 to 60s)…
        </Typography>
      )}
      {submission?.state === 'timeout' && (
        <Box>
          <Typography sx={{ fontSize: 12, color: 'warning.main', mb: 0.5 }}>
            Scan didn't finish within 3 minutes. URLScan sometimes deletes
            very-short-lived submissions before they complete, especially
            for URLs behind auth gates.
          </Typography>
          <Typography sx={{ fontSize: 11, color: 'text.tertiary' }}>
            Re-submit to try again, or check URLScan directly:{' '}
            <Box component="a"
              href={`https://urlscan.io/search/#${encodeURIComponent(target || '')}`}
              target="_blank" rel="noreferrer"
              sx={{ color: 'primary.main', textDecoration: 'none',
                '&:hover': { textDecoration: 'underline' } }}>
              search urlscan.io for {target}
            </Box>
          </Typography>
        </Box>
      )}
      {submission?.state === 'error' && (
        <Typography sx={{ fontSize: 12, color: 'error.main' }}>
          {submission.error}
        </Typography>
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
            <Box sx={{ display: 'flex',
              justifyContent: 'space-between', alignItems: 'flex-start',
              mb: 1.5, gap: 1.5 }}>
              <Box>
                <Stack direction="row" spacing={1} alignItems="center"
                  sx={{ mb: 0.5 }} flexWrap="wrap">
                  <MuiTag label={`verdict: ${r.verdict}`} color={verdictColor}/>
                  {r.score != null && <MuiTag label={`score ${r.score}`} color="#E6700F"/>}
                  {r.country && <MuiTag label={r.country} color="#848592"/>}
                </Stack>
                {r.page_title && (
                  <Typography sx={{ fontSize: 13, color: 'text.primary',
                    fontWeight: 500, mb: 0.5 }}>{r.page_title}</Typography>
                )}
                <Box sx={{ fontSize: 11, color: 'text.tertiary', ...monoSx,
                  wordBreak: 'break-all' }}>{r.final_url}</Box>
              </Box>
              <Box component="a" href={r.report_url} target="_blank" rel="noreferrer"
                sx={{ fontSize: 11, color: 'primary.main',
                  display: 'inline-flex', alignItems: 'center', gap: 0.375,
                  flexShrink: 0, textDecoration: 'none',
                  '&:hover': { textDecoration: 'underline' } }}>
                full report <ArrowUpRight size={11}/>
              </Box>
            </Box>
            {r.screenshot && (
              <Box component="a" href={r.screenshot} target="_blank" rel="noreferrer">
                <Box component="img" src={r.screenshot} alt="URLScan screenshot"
                  sx={{ width: '100%', maxWidth: 560, borderRadius: '4px',
                    border: `1px solid ${muiAlpha('#ffffff', 0.12)}`,
                    display: 'block', mb: 1.5 }}/>
              </Box>
            )}
            <Box sx={{ display: 'grid',
              gridTemplateColumns: 'repeat(2,1fr)',
              gap: 1, fontSize: 11 }}>
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
              {_regLine && (
                <Box>
                  <Box component="span" sx={{ color: 'text.disabled' }}>Domain registered:</Box>{' '}
                  <Box component="span" sx={{ color: 'text.primary', ...monoSx }}>
                    {_regLine}
                  </Box>
                </Box>
              )}
              {_whoisInfo?.registrar && (
                <Box>
                  <Box component="span" sx={{ color: 'text.disabled' }}>Registrar:</Box>{' '}
                  <Box component="span" sx={{ color: 'text.primary' }}>
                    {_whoisInfo.registrar}
                  </Box>
                </Box>
              )}
              {_lastSnapLine && (
                <Box>
                  <Box component="span" sx={{ color: 'text.disabled' }}>Last Wayback snapshot:</Box>{' '}
                  <Box component="span" sx={{ color: 'text.primary', ...monoSx }}>
                    {_lastSnapLine}
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
    </>
  );
  if (bare) return body;
  return (
    <MuiCard title="Live URL scan · URLScan.io" accent="#0fbcff"
      badge={`${urls.length} URL${urls.length === 1 ? '' : 's'} available`}>
      {body}
    </MuiCard>
  );
}
