import React, { useMemo } from 'react';

// ─── SCORE DIAL SVG ───────────────────────────────────────────────────────────────
function ScoreDial({ score, color, size = 120 }) {
  const cx = size / 2, cy = size / 2, r = size * 0.38;
  const circumference = 2 * Math.PI * r;
  // Arc goes from -210deg to 30deg (240deg sweep = 2/3 of circle)
  const sweep = 240;
  const startAngle = -210;
  const arcLength = (score / 100) * (sweep / 360) * circumference;
  const offset = circumference - arcLength;

  const polarToXY = (deg, radius) => {
    const rad = (deg - 90) * (Math.PI / 180);
    return { x: cx + radius * Math.cos(rad), y: cy + radius * Math.sin(rad) };
  };

  const start = polarToXY(startAngle, r);
  const end   = polarToXY(startAngle + sweep, r);
  const trackPath = `M ${start.x} ${start.y} A ${r} ${r} 0 1 1 ${end.x} ${end.y}`;

  const scoreEnd = polarToXY(startAngle + (score / 100) * sweep, r);
  const largeArc = (score / 100) * sweep > 180 ? 1 : 0;
  const scorePath = score > 0
    ? `M ${start.x} ${start.y} A ${r} ${r} 0 ${largeArc} 1 ${scoreEnd.x} ${scoreEnd.y}`
    : '';

  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} style={{ overflow: 'visible' }}>
      {/* Glow filter */}
      <defs>
        <filter id={`glow-${score}`} x="-50%" y="-50%" width="200%" height="200%">
          <feGaussianBlur stdDeviation="3" result="blur" />
          <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
        </filter>
      </defs>
      {/* Track */}
      <path d={trackPath} fill="none" stroke="#1e3a5f" strokeWidth={size * 0.07} strokeLinecap="round" />
      {/* Score arc */}
      {scorePath && (
        <path
          d={scorePath} fill="none" stroke={color} strokeWidth={size * 0.07}
          strokeLinecap="round" filter={`url(#glow-${score})`}
        />
      )}
      {/* Score number */}
      <text x={cx} y={cy - 4} textAnchor="middle" dominantBaseline="middle"
        fill={color} fontSize={size * 0.28} fontWeight="bold" fontFamily="Courier New">
        {score}
      </text>
      <text x={cx} y={cy + size * 0.16} textAnchor="middle"
        fill="#4a5568" fontSize={size * 0.1} fontFamily="Calibri">
        / 100
      </text>
    </svg>
  );
}

// ─── VERDICT BADGE ────────────────────────────────────────────────────────────────
function VerdictBadge({ verdict, severity }) {
  const colors = {
    MALICIOUS:  { bg: '#2d0a0a', border: '#EA4335', text: '#ff6b6b' },
    SUSPICIOUS: { bg: '#2d1a0a', border: '#FBBC04', text: '#ffe566' },
    UNDETECTED: { bg: '#0d1526', border: '#4a5568', text: '#718096' },
    BENIGN:     { bg: '#0a1f0a', border: '#34A853', text: '#51cf66' },
    UNKNOWN:    { bg: '#0d1526', border: '#2d3748', text: '#4a5568' },
  };
  const sevColors = { HIGH: '#EA4335', MEDIUM: '#FBBC04', LOW: '#4ECDC4', NONE: '#4a5568' };
  const c = colors[verdict] || colors.UNKNOWN;
  return (
    <div style={{ display: 'flex', gap: '8px', alignItems: 'center', flexWrap: 'wrap' }}>
      <span style={{ background: c.bg, border: `1px solid ${c.border}`, color: c.text, padding: '4px 12px', borderRadius: '4px', fontSize: '12px', fontWeight: 'bold', letterSpacing: '2px', fontFamily: 'Courier New' }}>
        {verdict}
      </span>
      {severity && severity !== 'NONE' && (
        <span style={{ background: '#0d1526', border: `1px solid ${sevColors[severity] || '#4a5568'}44`, color: sevColors[severity] || '#4a5568', padding: '4px 10px', borderRadius: '4px', fontSize: '11px', letterSpacing: '1px', fontFamily: 'Courier New' }}>
          {severity} SEVERITY
        </span>
      )}
    </div>
  );
}

// ─── SINGLE IOC SCORE CARD ────────────────────────────────────────────────────────
function IOCScoreCard({ ioc, scoreData }) {
  const { score, verdict, severity, label, color, contributing_factors, ioc_type } = scoreData;
  const typeColors = { ip: '#4a9eff', domain: '#51cf66', hash: '#cc5de8', url: '#ffa94d', file: '#cc5de8' };
  const tc = typeColors[ioc_type] || '#718096';

  return (
    <div style={{ background: '#0a1220', border: '1px solid #1e3a5f', borderRadius: '8px', padding: '14px', marginBottom: '10px' }}>
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: '14px' }}>
        {/* Dial */}
        <div style={{ flexShrink: 0 }}>
          <ScoreDial score={score} color={color} size={90} />
          <div style={{ textAlign: 'center', fontSize: '11px', fontWeight: 'bold', color, letterSpacing: '1px', marginTop: '2px' }}>{label}</div>
        </div>

        {/* Details */}
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: 'flex', gap: '6px', alignItems: 'center', marginBottom: '6px', flexWrap: 'wrap' }}>
            <span style={{ background: `${tc}22`, border: `1px solid ${tc}44`, color: tc, padding: '2px 7px', borderRadius: '3px', fontSize: '9px', letterSpacing: '1px', fontFamily: 'Courier New' }}>
              {ioc_type?.toUpperCase()}
            </span>
          </div>
          <div style={{ fontFamily: 'Courier New', fontSize: '12px', color: '#c8d6e5', wordBreak: 'break-all', marginBottom: '8px' }}>
            {ioc.length > 60 ? ioc.substring(0, 57) + '...' : ioc}
          </div>
          <VerdictBadge verdict={verdict} severity={severity} />

          {contributing_factors?.length > 0 && (
            <div style={{ marginTop: '10px' }}>
              <div style={{ fontSize: '9px', color: '#4a5568', letterSpacing: '2px', marginBottom: '5px' }}>CONTRIBUTING FACTORS</div>
              {contributing_factors.map((f, i) => (
                <div key={i} style={{ display: 'flex', gap: '6px', fontSize: '11px', color: '#718096', padding: '2px 0' }}>
                  <span style={{ color: color, flexShrink: 0 }}>·</span>{f}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ─── MAIN GTI SCORE PANEL ─────────────────────────────────────────────────────────
function GTIScorePanel({ result }) {
  const gtiScores = result?.gti_scores || {};
  const iocs = result?.iocs || {};

  // Sort by score descending
  const sorted = useMemo(() => {
    return Object.entries(gtiScores)
      .sort(([, a], [, b]) => b.score - a.score);
  }, [gtiScores]);

  const highest = sorted[0]?.[1];

  // Score distribution
  const dist = useMemo(() => {
    const counts = { critical: 0, high: 0, elevated: 0, suspicious: 0, low: 0, clean: 0 };
    sorted.forEach(([, d]) => {
      if (d.score >= 85) counts.critical++;
      else if (d.score >= 65) counts.high++;
      else if (d.score >= 45) counts.elevated++;
      else if (d.score >= 25) counts.suspicious++;
      else if (d.score >= 10) counts.low++;
      else counts.clean++;
    });
    return counts;
  }, [sorted]);

  if (!result) {
    return (
      <div style={{ background: '#0d1526', border: '1px solid #1e3a5f', borderRadius: '8px', padding: '40px', textAlign: 'center' }}>
        <div style={{ fontSize: '32px', opacity: 0.3, marginBottom: '10px' }}>🛡</div>
        <div style={{ color: '#4a5568', fontSize: '13px' }}>Run an analysis to see GTI threat scores</div>
      </div>
    );
  }

  if (!sorted.length) {
    return (
      <div style={{ background: '#0d1526', border: '1px solid #1e3a5f', borderRadius: '8px', padding: '24px' }}>
        <div style={{ color: '#718096', fontSize: '12px' }}>No IOC scores available for this analysis.</div>
      </div>
    );
  }

  return (
    <div>
      {/* Summary header */}
      <div style={{ background: '#0d1526', border: '1px solid #1e3a5f', borderRadius: '8px', padding: '20px', marginBottom: '16px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '16px' }}>
          {/* Highest score */}
          {highest && (
            <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
              <ScoreDial score={highest.score} color={highest.color} size={110} />
              <div>
                <div style={{ fontSize: '10px', color: '#4a5568', letterSpacing: '3px', marginBottom: '6px' }}>HIGHEST THREAT SCORE</div>
                <div style={{ fontSize: '20px', fontWeight: 'bold', color: highest.color, fontFamily: 'Courier New', letterSpacing: '2px', marginBottom: '6px' }}>{highest.label}</div>
                <VerdictBadge verdict={highest.verdict} severity={highest.severity} />
                <div style={{ fontSize: '11px', color: '#4a5568', marginTop: '6px' }}>
                  {sorted.length} IOC{sorted.length !== 1 ? 's' : ''} scored
                </div>
              </div>
            </div>
          )}

          {/* Distribution bars */}
          <div>
            <div style={{ fontSize: '10px', color: '#4a5568', letterSpacing: '3px', marginBottom: '10px' }}>SCORE DISTRIBUTION</div>
            {[
              { label: 'CRITICAL (85–100)', count: dist.critical, color: '#EA4335' },
              { label: 'HIGH (65–84)',       count: dist.high,     color: '#FF6B35' },
              { label: 'ELEVATED (45–64)',   count: dist.elevated, color: '#FBBC04' },
              { label: 'SUSPICIOUS (25–44)', count: dist.suspicious, color: '#FFA726' },
              { label: 'LOW (10–24)',         count: dist.low,     color: '#4ECDC4' },
              { label: 'CLEAN (0–9)',         count: dist.clean,   color: '#34A853' },
            ].map(({ label, count, color }) => (
              <div key={label} style={{ display: 'flex', gap: '8px', alignItems: 'center', marginBottom: '5px' }}>
                <div style={{ width: '130px', fontSize: '10px', color: '#4a5568', fontFamily: 'Courier New' }}>{label}</div>
                <div style={{ width: `${Math.max(count * 18, count > 0 ? 18 : 0)}px`, height: '14px', background: color, borderRadius: '2px', transition: 'width 0.3s', minWidth: count > 0 ? '18px' : '0' }} />
                {count > 0 && <span style={{ fontSize: '11px', color, fontWeight: 'bold' }}>{count}</span>}
              </div>
            ))}
          </div>
        </div>

        {/* GTI attribution note */}
        <div style={{ marginTop: '14px', paddingTop: '12px', borderTop: '1px solid #1e3a5f', fontSize: '10px', color: '#4a5568', display: 'flex', gap: '8px', alignItems: 'center' }}>
          <span style={{ color: '#4a9eff', fontWeight: 'bold' }}>GTI</span>
          <span>Scores derived from VirusTotal, MalwareBazaar, ThreatFox, AbuseIPDB, GreyNoise, OTX, URLScan, and WHOIS data — modeled on Google Threat Intelligence scoring methodology (verdict × severity + contributing factors). Scores of 85+ recommend immediate action. Scores of 45+ warrant investigation.</span>
        </div>
      </div>

      {/* Per-IOC score cards */}
      <div style={{ fontSize: '10px', color: '#4a5568', letterSpacing: '3px', marginBottom: '10px' }}>IOC SCORES — RANKED BY THREAT LEVEL</div>
      {sorted.map(([ioc, scoreData]) => (
        <IOCScoreCard key={ioc} ioc={ioc} scoreData={scoreData} />
      ))}
    </div>
  );
}

// Skip re-render when props are shallowly equal — the top-level views all
// receive a heavy `result` / `analysisResult` prop plus stable callbacks.
export default React.memo(GTIScorePanel);
