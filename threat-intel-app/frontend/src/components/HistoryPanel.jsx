import React, { useState, useEffect } from 'react';

const LEVEL_COLORS = {
  CRITICAL: '#ff2d2d', HIGH: '#ff8c00', MEDIUM: '#ffd700',
  LOW: '#00b4d8', INFORMATIONAL: '#4a5568', UNKNOWN: '#4a5568'
};

export default function HistoryPanel({ onSelect, currentRunId }) {
  const [history, setHistory]   = useState([]);
  const [loading, setLoading]   = useState(true);
  const [expanded, setExpanded] = useState(true);

  const load = () => {
    fetch('/api/history')
      .then(r => r.json())
      .then(d => { setHistory(d.history || []); setLoading(false); })
      .catch(() => setLoading(false));
  };

  useEffect(() => { load(); }, [currentRunId]);

  const handleSelect = async (item) => {
    try {
      const resp = await fetch(`/api/history/${item.runId}`);
      const data = await resp.json();
      onSelect?.(data);
    } catch (e) {
      console.error('Failed to load history item:', e);
    }
  };

  if (!expanded) return (
    <button
      onClick={() => setExpanded(true)}
      style={{ background: '#0d1526', border: '1px solid #1e3a5f', color: '#4a5568', padding: '8px 12px', borderRadius: '6px', cursor: 'pointer', fontSize: '11px', letterSpacing: '1px', fontFamily: 'Courier New', width: '100%', textAlign: 'left' }}
    >
      ▶ HISTORY ({history.length})
    </button>
  );

  return (
    <div style={{ background: '#0d1526', border: '1px solid #1e3a5f', borderRadius: '8px', overflow: 'hidden' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '12px 14px', borderBottom: '1px solid #1e3a5f' }}>
        <div style={{ fontSize: '10px', color: '#4a9eff', letterSpacing: '2px' }}>HISTORY</div>
        <div style={{ display: 'flex', gap: '6px' }}>
          <button onClick={load} style={{ background: 'none', border: 'none', color: '#4a5568', cursor: 'pointer', fontSize: '11px' }} title="Refresh">↻</button>
          <button onClick={() => setExpanded(false)} style={{ background: 'none', border: 'none', color: '#4a5568', cursor: 'pointer', fontSize: '11px' }}>▼</button>
        </div>
      </div>

      <div style={{ maxHeight: '360px', overflowY: 'auto' }}>
        {loading && <div style={{ padding: '16px', color: '#4a5568', fontSize: '12px' }}>Loading...</div>}
        {!loading && history.length === 0 && (
          <div style={{ padding: '16px', color: '#4a5568', fontSize: '12px' }}>No analyses yet. Run something.</div>
        )}
        {[...history].reverse().map((item, i) => {
          const isCurrent = item.runId === currentRunId;
          const c = LEVEL_COLORS[item.threatLevel] || LEVEL_COLORS.UNKNOWN;
          const date = new Date(item.timestamp);
          return (
            <div
              key={item.runId}
              onClick={() => handleSelect(item)}
              style={{
                padding: '10px 14px',
                borderBottom: '1px solid #060d1a',
                cursor: 'pointer',
                background: isCurrent ? '#0f2751' : 'transparent',
                borderLeft: `2px solid ${isCurrent ? '#4a9eff' : 'transparent'}`,
                transition: 'background 0.1s'
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '3px' }}>
                <div style={{ fontSize: '12px', color: '#c8d6e5', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '160px' }}>
                  {item.label || 'Untitled'}
                </div>
                {!item.dropped && (
                  <span style={{ fontSize: '9px', color: c, border: `1px solid ${c}44`, padding: '1px 5px', borderRadius: '3px', flexShrink: 0 }}>
                    {item.threatLevel}
                  </span>
                )}
                {item.dropped && (
                  <span style={{ fontSize: '9px', color: '#4a5568', border: '1px solid #2d374844', padding: '1px 5px', borderRadius: '3px' }}>
                    DROPPED
                  </span>
                )}
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '10px', color: '#4a5568' }}>
                <span>{item.iocCount} IOCs · {item.mitreTechniqueCount} MITRE</span>
                <span>{date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
