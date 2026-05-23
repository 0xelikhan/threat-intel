import React, { useState, useRef } from 'react';

const AGENT_META = {
  triage:        { icon: '⚡', label: 'TRIAGE' },
  enrichment:    { icon: '🔍', label: 'ENRICHMENT' },
  investigation: { icon: '🧠', label: 'INVESTIGATION' },
  response:      { icon: '⚔',  label: 'RESPONSE' },
  dropped:       { icon: '🗑',  label: 'DROPPED' },
};

const LEVEL_C = { CRITICAL: '#ff2d2d', HIGH: '#ff8c00', MEDIUM: '#ffd700', LOW: '#00b4d8', INFORMATIONAL: '#4a5568' };
const AGENT_ORDER = ['triage', 'enrichment', 'investigation', 'response'];

export default function AgentPipeline({ logText, label, onComplete }) {
  const [running, setRunning]     = useState(false);
  const [trace, setTrace]         = useState([]);
  const [error, setError]         = useState(null);
  const [done, setDone]           = useState(false);
  const [currentAgent, setCurrent] = useState(null);
  const readerRef = useRef(null);

  const run = async () => {
    if (!logText?.trim()) return;
    setRunning(true); setTrace([]); setError(null); setDone(false); setCurrent('triage');

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
            const event = JSON.parse(raw);
            if (event.event === 'agent_update' && event.trace) {
              setTrace(prev => [...prev, event.trace]);
              const cur = event.trace.agent;
              const next = AGENT_ORDER[AGENT_ORDER.indexOf(cur) + 1];
              setCurrent(next || null);
            }
            if (event.event === 'complete') {
              setDone(true); setRunning(false); setCurrent(null);
              onComplete?.(event.result);
            }
            if (event.event === 'error') {
              setError(event.error); setRunning(false); setCurrent(null);
            }
          } catch {}
        }
      }
    } catch (e) {
      setError(e.message); setRunning(false); setCurrent(null);
    }
  };

  const reset = () => { setTrace([]); setError(null); setDone(false); setCurrent(null); };

  const isDropped = trace.some(t => t.agent === 'triage' && t.status === 'dropped');

  return (
    <div>
      {/* Run button */}
      {!running && !done && !error && (
        <button onClick={run} disabled={!logText?.trim()} style={{
          width: '100%', padding: '13px',
          background: logText?.trim() ? 'linear-gradient(135deg, #1a3a6e, #0f2751)' : '#1a2744',
          border: `1px solid ${logText?.trim() ? '#4a9eff' : '#2d3748'}`,
          color: logText?.trim() ? '#74c0fc' : '#4a5568',
          borderRadius: '6px', cursor: logText?.trim() ? 'pointer' : 'not-allowed',
          fontSize: '12px', letterSpacing: '3px', fontFamily: 'Courier New',
          display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px',
        }}>
          ⚡ RUN AGENTIC PIPELINE
        </button>
      )}

      {/* Pipeline visualization */}
      {(running || trace.length > 0 || error) && (
        <div style={{ background: '#0d1526', border: '1px solid #1e3a5f', borderRadius: '8px', padding: '16px', marginTop: '10px' }}>
          {/* Agent nodes */}
          <div style={{ display: 'flex', alignItems: 'center', marginBottom: '16px' }}>
            {AGENT_ORDER.map((agent, idx) => {
              const t = trace.find(t => t.agent === agent);
              const isActive = currentAgent === agent && running;
              const isDone = !!t && t.status !== 'dropped';
              const cfg = AGENT_META[agent];
              const c = isDone ? '#51cf66' : isActive ? '#4a9eff' : '#1e3a5f';
              return (
                <React.Fragment key={agent}>
                  <div style={{ flex: 1, textAlign: 'center' }}>
                    <div style={{
                      width: '44px', height: '44px', borderRadius: '50%', margin: '0 auto 4px',
                      background: isDone ? '#0f2751' : isActive ? '#1a3a6e' : '#0d1526',
                      border: `2px solid ${c}`,
                      display: 'flex', alignItems: 'center', justifyContent: 'center',
                      fontSize: '16px', transition: 'all 0.3s',
                      animation: isActive ? 'pulse 1.5s ease-in-out infinite' : 'none',
                    }}>
                      {isDone ? '✓' : isActive ? '⟳' : cfg.icon}
                    </div>
                    <div style={{ fontSize: '9px', color: isDone ? '#51cf66' : isActive ? '#74c0fc' : '#4a5568', letterSpacing: '1px' }}>
                      {cfg.label}
                    </div>
                  </div>
                  {idx < AGENT_ORDER.length - 1 && (
                    <div style={{ width: '32px', height: '2px', background: isDone ? '#51cf66' : '#1e3a5f', flexShrink: 0, transition: 'background 0.3s' }} />
                  )}
                </React.Fragment>
              );
            })}
          </div>

          {/* Trace log */}
          <div style={{ borderTop: '1px solid #1e3a5f', paddingTop: '12px' }}>
            {trace.map((t, i) => {
              const meta = AGENT_META[t.agent] || {};
              return (
                <div key={i} style={{ display: 'flex', gap: '8px', padding: '6px 0', borderBottom: '1px solid #0d1a30', alignItems: 'flex-start' }}>
                  <span style={{ fontSize: '14px', minWidth: '20px' }}>{meta.icon}</span>
                  <div style={{ flex: 1 }}>
                    <div style={{ display: 'flex', gap: '6px', alignItems: 'center', marginBottom: '2px', flexWrap: 'wrap' }}>
                      <span style={{ fontSize: '10px', color: t.status === 'dropped' ? '#fc8181' : '#51cf66', letterSpacing: '1px' }}>
                        {meta.label}
                      </span>
                      {t.threat_level && (
                        <span style={{ fontSize: '9px', color: LEVEL_C[t.threat_level] || '#4a5568', border: `1px solid ${LEVEL_C[t.threat_level] || '#4a5568'}44`, padding: '1px 5px', borderRadius: '3px' }}>
                          {t.threat_level}
                        </span>
                      )}
                      {t.confidence !== undefined && (
                        <span style={{ fontSize: '9px', color: '#4a5568' }}>confidence: {Math.round(t.confidence * 100)}%</span>
                      )}
                      {t.score !== undefined && (
                        <span style={{ fontSize: '9px', color: '#4a5568' }}>score: {t.score}</span>
                      )}
                    </div>
                    <div style={{ fontSize: '11px', color: '#718096', lineHeight: '1.5' }}>{t.summary}</div>
                    {t.needs_more && (
                      <div style={{ fontSize: '10px', color: '#ffa94d', marginTop: '2px' }}>↻ Low confidence — looping back to enrichment</div>
                    )}
                  </div>
                  <div style={{ fontSize: '10px', color: '#2d3748', whiteSpace: 'nowrap' }}>
                    {t.timestamp ? new Date(t.timestamp).toLocaleTimeString() : ''}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Error */}
      {error && (
        <div style={{ background: '#2d0a0a', border: '1px solid #fc8181', borderRadius: '6px', padding: '10px 12px', color: '#fc8181', fontSize: '12px', marginTop: '8px' }}>
          ⚠ {error}
        </div>
      )}

      {/* Reset */}
      {(done || error) && !running && (
        <button onClick={reset} style={{ background: 'none', border: '1px solid #2d3748', color: '#718096', padding: '7px 16px', borderRadius: '4px', cursor: 'pointer', fontSize: '10px', letterSpacing: '2px', fontFamily: 'Courier New', marginTop: '8px' }}>
          ← NEW ANALYSIS
        </button>
      )}
    </div>
  );
}
