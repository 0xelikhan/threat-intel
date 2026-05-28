import React, { useEffect, useRef, useState, useCallback } from 'react';
import * as d3 from 'd3';

// ─── NODE TYPE CONFIG ────────────────────────────────────────────────────────────
const NODE_CONFIG = {
  ip:      { color: '#4a9eff', glow: '#4a9eff44', label: 'IP',     radius: 18, shape: 'circle' },
  domain:  { color: '#51cf66', glow: '#51cf6644', label: 'DOMAIN', radius: 16, shape: 'circle' },
  hash:    { color: '#cc5de8', glow: '#cc5de844', label: 'HASH',   radius: 14, shape: 'diamond' },
  url:     { color: '#ffa94d', glow: '#ffa94d44', label: 'URL',    radius: 14, shape: 'circle' },
  email:   { color: '#f06595', glow: '#f0659544', label: 'EMAIL',  radius: 13, shape: 'circle' },
  actor:   { color: '#ff6b6b', glow: '#ff6b6b44', label: 'ACTOR',  radius: 22, shape: 'hexagon' },
  cluster: { color: '#718096', glow: '#71809644', label: 'TAG',    radius: 12, shape: 'circle' },
};

const VERDICT_RING = {
  MALICIOUS:  '#ff2d2d',
  SUSPICIOUS: '#ff8c00',
  CLEAN:      '#51cf66',
  UNKNOWN:    '#4a5568',
};

// ─── BUILD GRAPH DATA FROM ANALYSIS RESULT ───────────────────────────────────────
function buildGraph(result) {
  if (!result) return { nodes: [], links: [] };

  const nodes = [];
  const links = [];
  const nodeMap = new Map();

  const addNode = (id, type, label, meta = {}) => {
    if (nodeMap.has(id)) return nodeMap.get(id);
    const node = { id, type, label, ...meta };
    nodes.push(node);
    nodeMap.set(id, node);
    return node;
  };

  const addLink = (source, target, relation, strength = 1) => {
    if (nodeMap.has(source) && nodeMap.has(target)) {
      links.push({ source, target, relation, strength });
    }
  };

  const { iocs, enrichments, response_summary } = result;

  // Add IOC nodes
  (iocs?.ips || []).forEach(ip => {
    const ipData = enrichments?.ips?.[ip] || {};
    const assessment = response_summary?.ioc_assessments?.find(a => a.ioc === ip);
    const abuseScore = ipData.abuseipdb?.abuseScore || 0;
    const vtMal = ipData.virustotal?.malicious || 0;
    const isTor = ipData.tor?.isExitNode;
    const country = ipData.ipinfo?.country;
    const org = ipData.ipinfo?.org;

    addNode(ip, 'ip', ip, {
      verdict: assessment?.verdict || 'UNKNOWN',
      reason: assessment?.reason,
      abuseScore,
      vtMalicious: vtMal,
      isTor,
      country,
      org,
      otxPulses: ipData.otx?.pulseCount || 0,
    });

    // Link IPs that share country
    if (country) {
      const countryId = `country:${country}`;
      addNode(countryId, 'cluster', country, { isCluster: true });
      addLink(ip, countryId, 'geolocated in', 0.3);
    }

    // Link IPs with Tor flag
    if (isTor) {
      const torId = 'cluster:tor';
      addNode(torId, 'cluster', 'Tor', { isCluster: true });
      addLink(ip, torId, 'tor exit node', 0.5);
    }

    // OTX pulses — shared pulse = shared cluster
    if (ipData.otx?.relatedPulses?.length) {
      ipData.otx.relatedPulses.slice(0, 2).forEach(pulse => {
        const pulseId = `pulse:${pulse.substring(0, 30)}`;
        addNode(pulseId, 'cluster', pulse.substring(0, 24) + '...', { isCluster: true });
        addLink(ip, pulseId, 'in OTX pulse', 0.6);
      });
    }
  });

  (iocs?.domains || []).forEach(domain => {
    const dData = enrichments?.domains?.[domain] || {};
    const assessment = response_summary?.ioc_assessments?.find(a => a.ioc === domain);
    const registrar = dData.whois?.registrar;
    const certCount = dData.certTransparency?.totalCerts || 0;
    const vtMal = dData.virustotal?.malicious || 0;

    addNode(domain, 'domain', domain, {
      verdict: assessment?.verdict || 'UNKNOWN',
      reason: assessment?.reason,
      vtMalicious: vtMal,
      registrar,
      certCount,
      otxPulses: dData.otx?.pulseCount || 0,
      pdRisk: dData.pulsedive?.risk,
    });

    // Domain → registrar cluster
    if (registrar) {
      const regId = `registrar:${registrar.substring(0, 30)}`;
      addNode(regId, 'cluster', registrar.substring(0, 20), { isCluster: true });
      addLink(domain, regId, 'registered via', 0.3);
    }

    // OTX pulses
    if (dData.otx?.relatedPulses?.length) {
      dData.otx.relatedPulses.slice(0, 2).forEach(pulse => {
        const pulseId = `pulse:${pulse.substring(0, 30)}`;
        addNode(pulseId, 'cluster', pulse.substring(0, 24) + '...', { isCluster: true });
        addLink(domain, pulseId, 'in OTX pulse', 0.6);
      });
    }

    // Shared subdomains — cert transparency
    if (dData.certTransparency?.subdomains?.length > 3) {
      const subId = `certs:${domain}`;
      addNode(subId, 'cluster', `${certCount} certs`, { isCluster: true });
      addLink(domain, subId, 'cert transparency', 0.2);
    }
  });

  (iocs?.hashes || []).forEach(hash => {
    const hData = enrichments?.hashes?.[hash] || {};
    const assessment = response_summary?.ioc_assessments?.find(a => a.ioc === hash);
    const malwareName = hData.malwarebazaar?.malwareName || hData.virustotal?.name;
    const vtMal = hData.virustotal?.malicious || 0;
    const fileType = hData.virustotal?.type;

    addNode(hash, 'hash', hash.substring(0, 12) + '...', {
      fullHash: hash,
      verdict: assessment?.verdict || 'UNKNOWN',
      reason: assessment?.reason,
      vtMalicious: vtMal,
      malwareName,
      fileType,
    });

    // Hash → malware family cluster
    if (malwareName) {
      const famId = `malware:${malwareName}`;
      addNode(famId, 'cluster', malwareName, { isCluster: true, isMalwareFamily: true });
      addLink(hash, famId, 'malware family', 0.8);
    }

    // ThreatFox
    if (hData.threatfox?.malware) {
      const tfId = `malware:${hData.threatfox.malware}`;
      addNode(tfId, 'cluster', hData.threatfox.malware, { isCluster: true, isMalwareFamily: true });
      addLink(hash, tfId, 'threatfox', 0.7);
    }
  });

  (iocs?.emails || []).forEach(email => {
    const assessment = response_summary?.ioc_assessments?.find(a => a.ioc === email);
    const domain = email.split('@')[1];
    addNode(email, 'email', email, {
      verdict: assessment?.verdict || 'UNKNOWN',
      reason: assessment?.reason,
    });

    // Email → domain link
    if (domain && nodeMap.has(domain)) {
      addLink(email, domain, 'email domain', 0.9);
    }
  });

  // URLs → domain links
  (iocs?.urls || []).forEach(url => {
    const assessment = response_summary?.ioc_assessments?.find(a => a.ioc === url);
    try {
      const urlObj = new URL(url);
      const urlDomain = urlObj.hostname;
      const displayUrl = url.length > 35 ? url.substring(0, 32) + '...' : url;

      addNode(url, 'url', displayUrl, {
        fullUrl: url,
        verdict: assessment?.verdict || 'UNKNOWN',
        reason: assessment?.reason,
      });

      if (nodeMap.has(urlDomain)) {
        addLink(url, urlDomain, 'hosted on', 0.9);
      }
    } catch {}
  });

  // Threat actor nodes
  (response_summary?.matched_actors || []).slice(0, 3).forEach(actor => {
    const actorId = `actor:${actor.name}`;
    addNode(actorId, 'actor', actor.name, {
      origin: actor.origin,
      sponsor: actor.sponsor,
      score: actor.score,
      matchedTechniques: actor.matchedTechniques,
      isActor: true,
    });

    // Actor → IOCs that triggered the match (connect to highest-verdict IOCs)
    const highValueIocs = response_summary?.ioc_assessments
      ?.filter(a => a.verdict === 'MALICIOUS' || a.verdict === 'SUSPICIOUS')
      ?.slice(0, 3) || [];
    highValueIocs.forEach(ioc => {
      if (nodeMap.has(ioc.ioc)) {
        addLink(actorId, ioc.ioc, 'attributed to', 0.4);
      }
    });
  });

  // Cross-link IPs and domains that share OTX pulses
  const pulseNodes = nodes.filter(n => n.id.startsWith('pulse:'));
  pulseNodes.forEach(pulse => {
    const connected = links.filter(l => l.target === pulse.id || l.source === pulse.id);
    if (connected.length >= 2) {
      // Already connected via pulse cluster — good
    }
  });

  return { nodes, links };
}


// IOC node types — these are the ones a pivot scan makes sense for. Clusters
// (country/registrar/OTX pulse) and actors aren't IOCs themselves.
const PIVOTABLE_TYPES = new Set(['ip', 'domain', 'hash', 'url', 'email']);

// ─── MAIN COMPONENT ──────────────────────────────────────────────────────────────
export default function PivotGraph({ result, onPivot }) {
  const svgRef = useRef(null);
  const simRef = useRef(null);
  const [selected, setSelected] = useState(null);
  const [graphStats, setGraphStats] = useState(null);
  const [filter, setFilter] = useState('all');

  const draw = useCallback(() => {
    if (!svgRef.current || !result) return;

    const { nodes: allNodes, links: allLinks } = buildGraph(result);

    const filteredNodes = filter === 'all'
      ? allNodes
      : allNodes.filter(n => n.type === filter || n.isCluster || n.isActor);

    const nodeIds = new Set(filteredNodes.map(n => n.id));
    const filteredLinks = allLinks.filter(l =>
      nodeIds.has(typeof l.source === 'object' ? l.source.id : l.source) &&
      nodeIds.has(typeof l.target === 'object' ? l.target.id : l.target)
    );

    setGraphStats({ nodes: filteredNodes.length, links: filteredLinks.length });

    const container = svgRef.current.parentElement;
    const W = container.clientWidth || 800;
    const H = 520;

    d3.select(svgRef.current).selectAll('*').remove();

    const svg = d3.select(svgRef.current)
      .attr('width', W)
      .attr('height', H);

    // Defs: arrow markers and filters
    const defs = svg.append('defs');

    defs.append('marker')
      .attr('id', 'arrow')
      .attr('viewBox', '0 0 10 10')
      .attr('refX', 28).attr('refY', 5)
      .attr('markerWidth', 6).attr('markerHeight', 6)
      .attr('orient', 'auto-start-reverse')
      .append('path')
      .attr('d', 'M2 1L8 5L2 9')
      .attr('fill', 'none')
      .attr('stroke', '#2d3748')
      .attr('stroke-width', 1.5)
      .attr('stroke-linecap', 'round');

    // Zoom container
    const g = svg.append('g');
    const zoom = d3.zoom()
      .scaleExtent([0.3, 4])
      .on('zoom', e => g.attr('transform', e.transform));
    svg.call(zoom);

    // Force simulation
    if (simRef.current) simRef.current.stop();

    const sim = d3.forceSimulation(filteredNodes)
      .force('link', d3.forceLink(filteredLinks).id(d => d.id).distance(d => {
        if (d.relation === 'email domain' || d.relation === 'hosted on') return 60;
        if (d.relation === 'malware family' || d.relation === 'threatfox') return 80;
        if (d.relation === 'attributed to') return 140;
        return 110;
      }).strength(d => d.strength || 0.5))
      .force('charge', d3.forceManyBody().strength(d => d.isActor ? -400 : d.isCluster ? -80 : -200))
      .force('center', d3.forceCenter(W / 2, H / 2))
      .force('collision', d3.forceCollide().radius(d => (NODE_CONFIG[d.type]?.radius || 14) + 10));

    simRef.current = sim;

    // Links
    const link = g.append('g').selectAll('line')
      .data(filteredLinks)
      .join('line')
      .attr('stroke', '#1e3a5f')
      .attr('stroke-width', d => Math.max(0.5, d.strength))
      .attr('stroke-opacity', 0.6)
      .attr('marker-end', 'url(#arrow)');

    // Link labels (only for strong relationships)
    const linkLabel = g.append('g').selectAll('text')
      .data(filteredLinks.filter(l => l.strength > 0.7))
      .join('text')
      .attr('font-size', '9px')
      .attr('fill', '#4a5568')
      .attr('text-anchor', 'middle')
      .attr('font-family', 'Courier New')
      .text(d => d.relation);

    // Node groups
    const node = g.append('g').selectAll('g')
      .data(filteredNodes)
      .join('g')
      .attr('cursor', 'pointer')
      .call(d3.drag()
        .on('start', (e, d) => { if (!e.active) sim.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
        .on('drag',  (e, d) => { d.fx = e.x; d.fy = e.y; })
        .on('end',   (e, d) => { if (!e.active) sim.alphaTarget(0); d.fx = null; d.fy = null; })
      )
      .on('click', (e, d) => { e.stopPropagation(); setSelected(d); });

    svg.on('click', () => setSelected(null));

    node.each(function(d) {
      const el = d3.select(this);
      const cfg = NODE_CONFIG[d.type] || NODE_CONFIG.cluster;
      const r = d.isActor ? 22 : d.isCluster ? 10 : cfg.radius;
      const verdictColor = VERDICT_RING[d.verdict] || cfg.color;
      const isCluster = d.isCluster;

      if (!isCluster) {
        // Outer ring (verdict)
        el.append('circle')
          .attr('r', r + 4)
          .attr('fill', 'none')
          .attr('stroke', verdictColor)
          .attr('stroke-width', 2)
          .attr('opacity', 0.5);
      }

      // Main node
      if (d.type === 'hash') {
        // Diamond shape for hashes
        const size = r * 1.3;
        el.append('rect')
          .attr('x', -size / 2).attr('y', -size / 2)
          .attr('width', size).attr('height', size)
          .attr('transform', 'rotate(45)')
          .attr('fill', isCluster ? '#0d1526' : '#0a1220')
          .attr('stroke', cfg.color)
          .attr('stroke-width', isCluster ? 0.5 : 1.5)
          .attr('rx', 2);
      } else if (d.type === 'actor') {
        // Hexagon for threat actors
        const hex = d3.symbol().type(d3.symbolStar).size(r * r * 3);
        el.append('path')
          .attr('d', hex)
          .attr('fill', '#2d0a0a')
          .attr('stroke', cfg.color)
          .attr('stroke-width', 2);
      } else {
        el.append('circle')
          .attr('r', r)
          .attr('fill', isCluster ? '#0a0e1a' : '#0a1220')
          .attr('stroke', cfg.color)
          .attr('stroke-width', isCluster ? 0.5 : 1.5)
          .attr('stroke-dasharray', isCluster ? '3 2' : 'none');
      }

      // Type badge (small dot)
      if (!isCluster) {
        el.append('circle')
          .attr('cx', r - 2).attr('cy', -(r - 2))
          .attr('r', 5)
          .attr('fill', cfg.color);
        el.append('text')
          .attr('x', r - 2).attr('y', -(r - 5))
          .attr('font-size', '6px')
          .attr('fill', '#0a0e1a')
          .attr('text-anchor', 'middle')
          .attr('font-family', 'Courier New')
          .attr('font-weight', 'bold')
          .text(cfg.label[0]);
      }

      // Tor indicator
      if (d.isTor) {
        el.append('circle')
          .attr('cx', -(r - 2)).attr('cy', -(r - 2))
          .attr('r', 5)
          .attr('fill', '#7b2fff');
        el.append('text')
          .attr('x', -(r - 2)).attr('y', -(r - 5))
          .attr('font-size', '6px')
          .attr('fill', '#fff')
          .attr('text-anchor', 'middle')
          .text('T');
      }
    });

    // Labels
    const label = g.append('g').selectAll('text')
      .data(filteredNodes)
      .join('text')
      .attr('font-size', d => d.isActor ? '11px' : d.isCluster ? '9px' : '10px')
      .attr('fill', d => d.isCluster ? '#4a5568' : '#c8d6e5')
      .attr('text-anchor', 'middle')
      .attr('font-family', 'Courier New')
      .attr('pointer-events', 'none')
      .text(d => d.label);

    // Tick
    sim.on('tick', () => {
      link
        .attr('x1', d => d.source.x).attr('y1', d => d.source.y)
        .attr('x2', d => d.target.x).attr('y2', d => d.target.y);

      linkLabel
        .attr('x', d => (d.source.x + d.target.x) / 2)
        .attr('y', d => (d.source.y + d.target.y) / 2 - 4);

      node.attr('transform', d => `translate(${d.x},${d.y})`);

      label
        .attr('x', d => d.x)
        .attr('y', d => {
          const r = NODE_CONFIG[d.type]?.radius || 12;
          return d.y + (d.isActor ? 30 : d.isCluster ? 18 : r + 14);
        });
    });

    // Auto-fit after settling
    setTimeout(() => {
      const bounds = g.node().getBBox();
      if (bounds.width > 0) {
        const scale = Math.min(0.9, Math.min(W / bounds.width, H / bounds.height) * 0.85);
        const tx = W / 2 - scale * (bounds.x + bounds.width / 2);
        const ty = H / 2 - scale * (bounds.y + bounds.height / 2);
        svg.transition().duration(600).call(
          zoom.transform,
          d3.zoomIdentity.translate(tx, ty).scale(scale)
        );
      }
    }, 1500);

  }, [result, filter]);

  useEffect(() => { draw(); }, [draw]);

  const iocTypes = ['all', 'ip', 'domain', 'hash', 'url', 'email'];

  return (
    <div style={{ fontFamily: 'Courier New', fontSize: '13px', color: '#c8d6e5' }}>
      {/* Controls */}
      <div style={{ display: 'flex', gap: '8px', alignItems: 'center', marginBottom: '12px', flexWrap: 'wrap' }}>
        <span style={{ fontSize: '10px', color: '#4a5568', letterSpacing: '2px' }}>FILTER:</span>
        {iocTypes.map(t => (
          <button key={t} onClick={() => setFilter(t)} style={{
            background: filter === t ? '#1a3a6e' : 'none',
            border: `1px solid ${filter === t ? '#4a9eff' : '#1e3a5f'}`,
            color: filter === t ? '#74c0fc' : '#4a5568',
            padding: '4px 10px', borderRadius: '4px', cursor: 'pointer',
            fontSize: '10px', letterSpacing: '1px', fontFamily: 'Courier New'
          }}>{t.toUpperCase()}</button>
        ))}
        {graphStats && (
          <span style={{ marginLeft: 'auto', fontSize: '10px', color: '#4a5568' }}>
            {graphStats.nodes} nodes · {graphStats.links} edges
          </span>
        )}
      </div>

      {/* Legend */}
      <div style={{ display: 'flex', gap: '14px', marginBottom: '10px', flexWrap: 'wrap' }}>
        {Object.entries(NODE_CONFIG).filter(([k]) => !['cluster'].includes(k)).map(([type, cfg]) => (
          <div key={type} style={{ display: 'flex', alignItems: 'center', gap: '5px', fontSize: '10px', color: '#718096' }}>
            <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: cfg.color }} />
            {type.toUpperCase()}
          </div>
        ))}
        <div style={{ display: 'flex', alignItems: 'center', gap: '5px', fontSize: '10px', color: '#718096' }}>
          <div style={{ width: '8px', height: '8px', borderRadius: '50%', border: '1px dashed #4a5568' }} />
          CLUSTER
        </div>
        {Object.entries(VERDICT_RING).map(([v, c]) => (
          <div key={v} style={{ display: 'flex', alignItems: 'center', gap: '5px', fontSize: '10px', color: '#718096' }}>
            <div style={{ width: '8px', height: '8px', borderRadius: '50%', border: `2px solid ${c}` }} />
            {v}
          </div>
        ))}
      </div>

      {/* Graph */}
      <div style={{ position: 'relative', background: '#060d1a', border: '1px solid #1e3a5f', borderRadius: '8px', overflow: 'hidden' }}>
        {!result ? (
          <div style={{ height: '520px', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', color: '#4a5568' }}>
            <div style={{ fontSize: '32px', opacity: 0.3, marginBottom: '12px' }}>⬡</div>
            <div style={{ fontSize: '14px' }}>Run an analysis to build the pivot graph</div>
          </div>
        ) : (
          <svg ref={svgRef} style={{ display: 'block', width: '100%' }} />
        )}

        <div style={{ position: 'absolute', bottom: '10px', left: '12px', fontSize: '10px', color: '#2d3748' }}>
          scroll to zoom · drag to pan · drag nodes to reposition
        </div>
      </div>

      {/* Selected node detail panel */}
      {selected && (
        <div style={{ background: '#0d1526', border: '1px solid #1e3a5f', borderRadius: '8px', padding: '16px', marginTop: '12px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '12px' }}>
            <div>
              <div style={{ display: 'flex', gap: '8px', alignItems: 'center', marginBottom: '4px' }}>
                <span style={{
                  background: `${NODE_CONFIG[selected.type]?.color}22`,
                  border: `1px solid ${NODE_CONFIG[selected.type]?.color}66`,
                  color: NODE_CONFIG[selected.type]?.color,
                  padding: '2px 8px', borderRadius: '3px', fontSize: '10px', letterSpacing: '1px'
                }}>{selected.type?.toUpperCase()}</span>
                {selected.verdict && (
                  <span style={{
                    background: `${VERDICT_RING[selected.verdict]}22`,
                    border: `1px solid ${VERDICT_RING[selected.verdict]}66`,
                    color: VERDICT_RING[selected.verdict],
                    padding: '2px 8px', borderRadius: '3px', fontSize: '10px'
                  }}>{selected.verdict}</span>
                )}
              </div>
              <div style={{ fontSize: '14px', color: '#e2e8f0', fontFamily: 'Courier New', wordBreak: 'break-all' }}>
                {selected.fullHash || selected.fullUrl || selected.label}
              </div>
            </div>
            <button onClick={() => setSelected(null)} style={{ background: 'none', border: 'none', color: '#4a5568', cursor: 'pointer', fontSize: '16px' }}>✕</button>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '8px', fontSize: '12px' }}>
            {selected.abuseScore > 0      && <div><span style={{ color: '#4a5568' }}>Abuse score</span><br /><span style={{ color: '#ffa94d' }}>{selected.abuseScore}%</span></div>}
            {selected.vtMalicious > 0     && <div><span style={{ color: '#4a5568' }}>VT malicious</span><br /><span style={{ color: '#ff6b6b' }}>{selected.vtMalicious} engines</span></div>}
            {selected.country             && <div><span style={{ color: '#4a5568' }}>Country</span><br /><span style={{ color: '#c8d6e5' }}>{selected.country}</span></div>}
            {selected.org                 && <div><span style={{ color: '#4a5568' }}>Org / ASN</span><br /><span style={{ color: '#c8d6e5' }}>{selected.org}</span></div>}
            {selected.isTor               && <div><span style={{ color: '#4a5568' }}>Tor</span><br /><span style={{ color: '#cc5de8' }}>Exit node</span></div>}
            {selected.otxPulses > 0       && <div><span style={{ color: '#4a5568' }}>OTX pulses</span><br /><span style={{ color: '#74c0fc' }}>{selected.otxPulses}</span></div>}
            {selected.malwareName         && <div><span style={{ color: '#4a5568' }}>Malware</span><br /><span style={{ color: '#ff6b6b' }}>{selected.malwareName}</span></div>}
            {selected.registrar           && <div><span style={{ color: '#4a5568' }}>Registrar</span><br /><span style={{ color: '#c8d6e5' }}>{selected.registrar}</span></div>}
            {selected.certCount > 0       && <div><span style={{ color: '#4a5568' }}>SSL certs</span><br /><span style={{ color: '#c8d6e5' }}>{selected.certCount}</span></div>}
            {selected.score               && <div><span style={{ color: '#4a5568' }}>TTP match</span><br /><span style={{ color: '#ff6b6b' }}>{selected.score}%</span></div>}
            {selected.origin              && <div><span style={{ color: '#4a5568' }}>Origin</span><br /><span style={{ color: '#c8d6e5' }}>{selected.origin}</span></div>}
            {selected.sponsor             && <div><span style={{ color: '#4a5568' }}>Sponsor</span><br /><span style={{ color: '#c8d6e5' }}>{selected.sponsor}</span></div>}
          </div>

          {selected.reason && (
            <div style={{ marginTop: '10px', fontSize: '12px', color: '#718096', borderTop: '1px solid #1e3a5f', paddingTop: '10px' }}>
              {selected.reason}
            </div>
          )}
          {/* Pivot-and-investigate — the reason this graph earns its keep.
              Clicking sends the IOC value back to the sidebar Analyze flow
              so the analyst can run a fresh investigation on a neighbor
              without retyping or copy-pasting. */}
          {PIVOTABLE_TYPES.has(selected.type) && onPivot && (
            <div style={{ marginTop: '12px', borderTop: '1px solid #1e3a5f', paddingTop: '10px' }}>
              <button
                onClick={() => {
                  const value = selected.fullUrl || selected.fullHash || selected.id;
                  onPivot(value, selected.type);
                  setSelected(null);
                }}
                style={{
                  background: '#1a3a6e', border: '1px solid #4a9eff',
                  color: '#74c0fc', padding: '6px 14px', borderRadius: '4px',
                  cursor: 'pointer', fontSize: '11px', letterSpacing: '1px',
                  fontFamily: 'Courier New', textTransform: 'uppercase',
                  display: 'flex', alignItems: 'center', gap: '6px',
                }}
              >
                → Pivot scan this {selected.type}
              </button>
              <div style={{ marginTop: '6px', fontSize: '10px', color: '#4a5568' }}>
                Sends the IOC to Analyze and starts a fresh investigation.
              </div>
            </div>
          )}
          {selected.matchedTechniques?.length > 0 && (
            <div style={{ marginTop: '10px', display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
              {selected.matchedTechniques.map(t => (
                <span key={t} style={{ background: '#1a2744', border: '1px solid #2d3f6b', color: '#74c0fc', padding: '2px 6px', borderRadius: '3px', fontSize: '10px' }}>{t}</span>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
