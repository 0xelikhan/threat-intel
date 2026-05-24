/**
 * Adapted from OpenCTI (AGPL-3.0) github.com/OpenCTI-Platform/opencti
 * Pipeline visualisation: MUI Box + IconButton + Button, severity colours
 * pulled from theme.palette so it inherits the OpenCTI dark theme.
 */
import React, { useState, useRef } from 'react';
import {
  Box, Stack, Typography, Button, IconButton,
  alpha,
} from '@mui/material';
import {
  Search, Database, Activity, Shield, Check, RotateCw, AlertCircle,
  Trash2, Wrench, ArrowRight,
} from 'lucide-react';

const AGENTS = [
  { id: 'triage',        icon: Search,   label: 'Triage'        },
  { id: 'enrichment',    icon: Database, label: 'Enrichment'    },
  { id: 'investigation', icon: Activity, label: 'Investigation' },
  { id: 'response',      icon: Shield,   label: 'Response'      },
];

// Severity tier → theme palette key (mirrors theme.js palette.severity)
const LEVEL_COLOR = {
  CRITICAL:      'severity.critical',
  HIGH:          'severity.high',
  MEDIUM:        'severity.medium',
  LOW:           'severity.low',
  INFORMATIONAL: 'severity.default',
};

export default function AgentPipeline({ logText, label, onComplete, onStart, onPartial }) {
  const [running, setRunning] = useState(false);
  const [trace, setTrace]     = useState([]);
  const [error, setError]     = useState(null);
  const [done, setDone]       = useState(false);
  const [current, setCurrent] = useState(null);
  const readerRef = useRef(null);

  const run = async () => {
    if (!logText?.trim()) return;
    try { readerRef.current?.cancel(); } catch {}
    readerRef.current = null;
    onStart?.();
    setRunning(true); setTrace([]); setError(null); setDone(false); setCurrent('triage');
    try { document.querySelector('main')?.scrollTo({ top: 0, behavior: 'smooth' }); } catch {}

    try {
      const resp = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ logText, inputType: 'log', label: label || '' }),
      });
      if (!resp.ok) {
        const err = await resp.json().catch(() => ({ error: 'Unknown error' }));
        throw new Error(err.error || `HTTP ${resp.status}`);
      }
      const reader = resp.body.getReader();
      readerRef.current = reader;
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
          if (raw === '[DONE]') { setRunning(false); break; }
          try {
            const ev = JSON.parse(raw);
            if (ev.event === 'agent_update' && ev.trace) {
              setTrace(p => [...p, ev.trace]);
              const idx = AGENTS.findIndex(a => a.id === ev.trace.agent);
              setCurrent(AGENTS[idx + 1]?.id || null);
            }
            if (ev.event === 'partial_result' && ev.result) onPartial?.(ev.result);
            if (ev.event === 'complete') {
              setDone(true); setRunning(false); setCurrent(null);
              onComplete?.(ev.result);
            }
            if (ev.event === 'error') {
              setError(ev.error); setRunning(false); setCurrent(null);
            }
          } catch {}
        }
      }
    } catch (e) {
      setError(e.message); setRunning(false); setCurrent(null);
    }
  };

  const reset = () => { setTrace([]); setError(null); setDone(false); setCurrent(null); };
  const canRun = !!logText?.trim() && !running;
  const buttonLabel = error ? 'Retry analysis' : done ? 'Analyze again' : 'Analyze';

  return (
    <Box>
      {/* Primary action — visible whenever pipeline is not actively streaming */}
      {!running && (
        <Button
          fullWidth
          variant="contained"
          onClick={run}
          disabled={!canRun}
          data-recon-analyze
          sx={{
            height: 36,
            fontSize: 13,
            fontWeight: 600,
            textTransform: 'none',
          }}
        >
          {buttonLabel}
        </Button>
      )}

      {/* Pipeline state */}
      {(running || trace.length > 0 || error) && (
        <Box sx={{
          backgroundColor: 'background.secondary',
          border: theme => `1px solid ${alpha('#ffffff', 0.12)}`,
          borderRadius: '4px',
          p: 1.75,
          mt: running || !done ? 1.25 : 1.75,
        }}>

          {/* Compact horizontal pipeline */}
          <Box sx={{
            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
            mb: trace.length > 0 ? 1.75 : 0,
          }}>
            {AGENTS.map((agent, idx) => {
              const tr      = trace.find(t => t.agent === agent.id);
              const active  = current === agent.id && running;
              const ok      = !!tr && tr.status !== 'dropped';
              const dropped = tr?.status === 'dropped';
              const color   = dropped ? '#F14337'
                             : ok      ? '#17AB1F'
                             : active  ? '#0fbcff'
                             :           '#75829A';
              const Icon    = agent.icon;
              return (
                <React.Fragment key={agent.id}>
                  <Box sx={{ flex: '0 0 auto', display: 'flex', flexDirection: 'column',
                    alignItems: 'center', gap: 0.5 }}>
                    <Box sx={{
                      width: 30, height: 30, borderRadius: '50%',
                      backgroundColor: ok      ? alpha(color, 0.1)
                                      : active ? alpha(color, 0.08)
                                      :          'background.default',
                      border: `1.5px solid ${color}`,
                      display: 'flex', alignItems: 'center', justifyContent: 'center',
                      animation: active ? 'pulse 1.5s ease-in-out infinite' : 'none',
                      transition: 'all .3s',
                    }}>
                      {ok
                        ? <Check size={14} color={color} strokeWidth={2.5}/>
                        : active
                          ? <RotateCw size={13} color={color} style={{ animation: 'spin 1s linear infinite' }}/>
                          : <Icon size={13} color={color} strokeWidth={2}/>}
                    </Box>
                    <Typography sx={{
                      fontSize: 10,
                      color: ok || active ? 'text.primary' : 'text.disabled',
                      fontWeight: ok || active ? 500 : 400,
                    }}>{agent.label}</Typography>
                  </Box>
                  {idx < AGENTS.length - 1 && (
                    <Box sx={{
                      flex: 1, height: '1.5px', mx: 0.5, mb: '14px',
                      backgroundColor: ok ? '#17AB1F' : alpha('#ffffff', 0.06),
                      transition: 'background-color .3s',
                    }}/>
                  )}
                </React.Fragment>
              );
            })}
          </Box>

          {/* Trace log */}
          {trace.length > 0 && (
            <Box sx={{ borderTop: `1px solid ${alpha('#ffffff', 0.06)}`, pt: 1.5, mt: 0.25 }}>
              {trace.map((tr, i) => {
                if (tr.type === 'tool_call') {
                  // Compact tool-call rendering inside an agent block
                  return (
                    <Box key={i} sx={{
                      p: '5px 0 5px 22px', minWidth: 0,
                      borderTop: i > 0 ? `1px solid ${alpha('#ffffff', 0.06)}` : 'none',
                    }}>
                      <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 0.75 }}>
                        <Wrench size={10} color="#0fbcff" style={{ flexShrink: 0, marginTop: 3 }}/>
                        <Box sx={{
                          fontFamily: '"IBM Plex Mono", monospace',
                          color: 'primary.main',
                          fontSize: 10.5,
                          wordBreak: 'break-all', overflowWrap: 'anywhere',
                          minWidth: 0, flex: 1, lineHeight: 1.45,
                        }}>
                          {tr.tool}({Object.entries(tr.args || {}).map(([k, v]) => String(v)).join(', ')})
                        </Box>
                      </Box>
                      {tr.summary && (
                        <Box sx={{
                          fontSize: 11, color: 'text.primary',
                          pl: 2, lineHeight: 1.5,
                          wordBreak: 'break-word', overflowWrap: 'anywhere', mt: 0.25,
                        }}>
                          <ArrowRight size={9} color="#75829A"
                            style={{ verticalAlign: 'middle', marginRight: 4 }}/>
                          {tr.summary}
                        </Box>
                      )}
                    </Box>
                  );
                }
                const A = AGENTS.find(a => a.id === tr.agent);
                if (!A) return null;
                const Icon = A.icon;
                const dropped = tr.status === 'dropped';
                return (
                  <Box key={i} sx={{
                    display: 'flex', gap: 1.25, py: 0.875,
                    borderTop: i > 0 ? `1px solid ${alpha('#ffffff', 0.06)}` : 'none',
                    alignItems: 'flex-start',
                  }}>
                    <Icon size={13} color={dropped ? '#F14337' : '#17AB1F'} strokeWidth={2}
                      style={{ flexShrink: 0, marginTop: 2 }}/>
                    <Box sx={{ flex: 1, minWidth: 0 }}>
                      <Box sx={{ display: 'flex', gap: 0.75, alignItems: 'center',
                        mb: 0.375, flexWrap: 'wrap' }}>
                        <Typography sx={{ fontSize: 11, color: 'text.primary', fontWeight: 600 }}>
                          {A.label}
                        </Typography>
                        {tr.tool_calls > 0 && (
                          <Typography sx={{ fontSize: 10, color: 'primary.main' }}>
                            · {tr.tool_calls} tool call{tr.tool_calls === 1 ? '' : 's'}
                          </Typography>
                        )}
                        {tr.threat_level && (
                          <Box sx={{
                            fontSize: 10,
                            color: theme => {
                              const sevMap = {
                                CRITICAL: theme.palette.severity.critical,
                                HIGH:     theme.palette.severity.high,
                                MEDIUM:   theme.palette.severity.medium,
                                LOW:      theme.palette.severity.low,
                                INFORMATIONAL: theme.palette.severity.default,
                              };
                              return sevMap[tr.threat_level] || theme.palette.text.tertiary;
                            },
                            border: theme => {
                              const sevMap = {
                                CRITICAL: theme.palette.severity.critical,
                                HIGH:     theme.palette.severity.high,
                                MEDIUM:   theme.palette.severity.medium,
                                LOW:      theme.palette.severity.low,
                                INFORMATIONAL: theme.palette.severity.default,
                              };
                              return `1px solid ${alpha(sevMap[tr.threat_level] || theme.palette.text.tertiary, 0.3)}`;
                            },
                            px: 0.625, py: '1px', borderRadius: '3px',
                          }}>
                            {tr.threat_level.toLowerCase()}
                          </Box>
                        )}
                        {tr.confidence !== undefined && (
                          <Typography sx={{ fontSize: 10, color: 'text.tertiary' }}>
                            {Math.round(tr.confidence * 100)}% conf
                          </Typography>
                        )}
                        {tr.score !== undefined && (
                          <Typography sx={{ fontSize: 10, color: 'text.tertiary' }}>
                            score {tr.score}
                          </Typography>
                        )}
                        {tr.elapsed_ms !== undefined && (
                          <Typography sx={{ fontSize: 10, color: 'text.tertiary', ml: 'auto' }}>
                            {tr.elapsed_ms < 1000 ? `${tr.elapsed_ms}ms` : `${(tr.elapsed_ms/1000).toFixed(1)}s`}
                            {tr.ai_skipped && (
                              <Box component="span" sx={{ color: 'success.main', ml: 0.5 }}>· fast-path</Box>
                            )}
                          </Typography>
                        )}
                      </Box>
                      <Typography sx={{ fontSize: 11, color: 'text.tertiary', lineHeight: 1.55 }}>
                        {tr.summary}
                      </Typography>
                      {tr.needs_more && (
                        <Typography sx={{ fontSize: 11, color: 'warning.main', mt: 0.375 }}>
                          ↻ Looping back for additional enrichment
                        </Typography>
                      )}
                    </Box>
                  </Box>
                );
              })}
            </Box>
          )}
        </Box>
      )}

      {/* Error banner */}
      {error && (
        <Box sx={{
          backgroundColor: alpha('#F14337', 0.08),
          border: `1px solid ${alpha('#F14337', 0.4)}`,
          borderRadius: '4px', p: '10px 12px',
          color: 'error.main', fontSize: 12,
          mt: 1.25, display: 'flex', alignItems: 'center', gap: 1,
        }}>
          <AlertCircle size={14}/>{error}
        </Box>
      )}

      {/* Clear-trace link */}
      {(done || error) && !running && trace.length > 0 && (
        <Button onClick={reset} fullWidth
          startIcon={<Trash2 size={11}/>}
          sx={{
            color: 'text.disabled', fontSize: 11, mt: 0.75,
            textTransform: 'none', height: 'auto', py: 0.75,
            '&:hover': { color: 'text.tertiary', backgroundColor: 'transparent' },
          }}>
          Clear previous trace
        </Button>
      )}
    </Box>
  );
}
