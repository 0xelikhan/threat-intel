import React, { useEffect, useRef, useState } from 'react';
// Bundle Leaflet locally — loading it from a CDN is blocked by the app's
// Content Security Policy (script-src/style-src 'self'). Local import is
// same-origin, synchronous, and removes the async-load timing issues.
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';

const VERDICT_COLORS = { MALICIOUS: '#ff2d2d', SUSPICIOUS: '#ff8c00', CLEAN: '#51cf66', UNKNOWN: '#74c0fc' };

// Approximate country centroids (ISO-3166 alpha-2 → [lat, lng]). Used as a
// fallback when an IP has a country but no precise ipinfo "loc" — otherwise
// that IP silently drops off the map (common for the 2nd IP in an
// impossible-travel pair when one ipinfo lookup returns no coordinates).
const COUNTRY_CENTROIDS = {
  US:[37.1,-95.7], CA:[56.1,-106.3], MX:[23.6,-102.5], BR:[-14.2,-51.9], AR:[-38.4,-63.6],
  GB:[55.4,-3.4], IE:[53.4,-8.2], FR:[46.2,2.2], DE:[51.2,10.4], ES:[40.5,-3.7], PT:[39.4,-8.2],
  IT:[41.9,12.6], NL:[52.1,5.3], BE:[50.5,4.5], CH:[46.8,8.2], AT:[47.5,14.6], SE:[60.1,18.6],
  NO:[60.5,8.5], FI:[61.9,25.7], DK:[56.3,9.5], PL:[51.9,19.1], CZ:[49.8,15.5], UA:[48.4,31.2],
  RU:[61.5,105.3], TR:[39.0,35.2], GR:[39.1,21.8], RO:[45.9,24.9], HU:[47.2,19.5],
  CN:[35.9,104.2], JP:[36.2,138.3], KR:[35.9,127.8], KP:[40.3,127.5], IN:[20.6,79.0],
  PK:[30.4,69.3], BD:[23.7,90.4], VN:[14.1,108.3], TH:[15.9,100.99], ID:[-0.8,113.9],
  PH:[12.9,121.8], MY:[4.2,101.98], SG:[1.35,103.8], HK:[22.4,114.1], TW:[23.7,121.0],
  AU:[-25.3,133.8], NZ:[-40.9,174.9], ZA:[-30.6,22.9], NG:[9.1,8.7], EG:[26.8,30.8],
  KE:[-0.0,37.9], MA:[31.8,-7.1], SA:[23.9,45.1], AE:[23.4,53.8], IL:[31.0,34.9],
  IR:[32.4,53.7], IQ:[33.2,43.7], CO:[4.6,-74.3], CL:[-35.7,-71.5], PE:[-9.2,-75.0],
  VE:[6.4,-66.6],
};

function locFromCountry(cc) {
  if (!cc) return null;
  const hit = COUNTRY_CENTROIDS[cc.toUpperCase()];
  return hit ? `${hit[0]},${hit[1]}` : null;
}

function getIPVerdict(ip, response_summary) {
  if (!response_summary?.ioc_assessments) return 'UNKNOWN';
  const assessment = response_summary.ioc_assessments.find(a => a.ioc === ip);
  return assessment?.verdict || 'UNKNOWN';
}

function getIPDetails(ip, enrichments) {
  const data = enrichments?.ips?.[ip];
  if (!data) return {};
  const country = data.ipinfo?.country || data.abuseipdb?.country
    || data.censys?.country || '';
  return {
    country: country || '??',
    org: data.ipinfo?.org || data.abuseipdb?.isp || 'Unknown',
    city: data.ipinfo?.city || '',
    // Precise coords when ipinfo has them; otherwise fall back to the
    // country centroid so the IP still appears on the map. approxLoc flags
    // that the position is country-level, not exact.
    loc: data.ipinfo?.loc || locFromCountry(country),
    approxLoc: !data.ipinfo?.loc && !!locFromCountry(country),
    abuseScore: data.abuseipdb?.abuseScore,
    vtMalicious: data.virustotal?.malicious,
    isTor: data.tor?.isExitNode,
    isNoise: data.greynoise?.noise,
    greynoiseClass: data.greynoise?.classification,
    ports: data.shodan?.ports?.slice(0, 6),
    otxPulses: data.otx?.pulseCount
  };
}

export default function MapTab({ result }) {
  const mapRef = useRef(null);
  const mapInstanceRef = useRef(null);
  const markersRef = useRef([]);
  const [, setSelectedIP] = useState(null);
  const [leafletReady, setLeafletReady] = useState(false);

  useEffect(() => {
    if (mapInstanceRef.current || !mapRef.current) return;
    try {
      const map = L.map(mapRef.current, {
        center: [25, 10], zoom: 2, zoomControl: true, attributionControl: false,
      });
      L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_nolabels/{z}/{x}/{y}{r}.png', {
        subdomains: 'abcd', maxZoom: 18,
      }).addTo(map);
      L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_only_labels/{z}/{x}/{y}{r}.png', {
        subdomains: 'abcd', maxZoom: 18, opacity: 0.6,
      }).addTo(map);
      mapInstanceRef.current = map;
      setLeafletReady(true);
      // Container is often zero-sized while the parent Collapse expands —
      // re-measure shortly after so tiles paint. Safe to call repeatedly.
      [60, 300, 700].forEach(ms => setTimeout(() => {
        try { map.invalidateSize(); } catch (_) {}
      }, ms));
    } catch (_) { /* never let map init crash the page */ }

    return () => {
      if (mapInstanceRef.current) {
        try { mapInstanceRef.current.remove(); } catch (_) {}
        mapInstanceRef.current = null;
        setLeafletReady(false);
      }
    };
  }, []);

  useEffect(() => {
    if (!leafletReady || !mapInstanceRef.current || !result) return;
    const map = mapInstanceRef.current;

    // Remove old markers
    markersRef.current.forEach(m => m.remove());
    markersRef.current = [];

    if (!result.enrichments?.ips) return;

    const bounds = [];

    Object.keys(result.enrichments.ips).forEach(ip => {
      const details = getIPDetails(ip, result.enrichments);
      const verdict = getIPVerdict(ip, result.response_summary);
      const color = VERDICT_COLORS[verdict] || VERDICT_COLORS.UNKNOWN;

      if (!details.loc) return;
      const [lat, lng] = details.loc.split(',').map(Number);
      if (isNaN(lat) || isNaN(lng)) return;

      bounds.push([lat, lng]);

      // Create custom colored marker
      const markerHtml = `
        <div style="
          width: 24px; height: 24px;
          background: ${color};
          border: 2px solid ${color}aa;
          border-radius: 50%;
          box-shadow: 0 0 12px ${color}66, 0 0 4px ${color};
          display: flex; align-items: center; justify-content: center;
          font-size: 10px; font-weight: bold; color: white;
          font-family: Courier New;
        ">${verdict[0]}</div>`;

      const icon = L.divIcon({ html: markerHtml, className: '', iconSize: [24, 24], iconAnchor: [12, 12] });

      const popupContent = `
        <div style="background:#0d1526;border:1px solid #1e3a5f;border-radius:6px;padding:12px;min-width:200px;font-family:Courier New;font-size:12px;color:#c8d6e5">
          <div style="font-size:14px;color:#e2e8f0;margin-bottom:8px;font-weight:bold">${ip}</div>
          <div style="display:inline-block;background:${color}22;border:1px solid ${color}66;color:${color};padding:2px 8px;border-radius:3px;font-size:10px;letter-spacing:1px;margin-bottom:8px">${verdict}</div>
          ${details.city ? `<div style="color:#718096">${details.city}, ${details.country}</div>` : `<div style="color:#718096">${details.country}</div>`}
          ${details.approxLoc ? `<div style="color:#5a6678;font-size:10px;margin-top:2px">approx — country-level location</div>` : ''}
          ${details.org ? `<div style="color:#718096;margin-top:4px">${details.org}</div>` : ''}
          ${details.abuseScore > 0 ? `<div style="margin-top:6px;color:#ffa94d">Abuse score: ${details.abuseScore}%</div>` : ''}
          ${details.vtMalicious > 0 ? `<div style="color:#ff6b6b">VT: ${details.vtMalicious} malicious engines</div>` : ''}
          ${details.isTor ? `<div style="color:#cc5de8;margin-top:4px">⚠ Tor exit node</div>` : ''}
          ${details.ports?.length > 0 ? `<div style="color:#74c0fc;margin-top:4px">Ports: ${details.ports.join(', ')}</div>` : ''}
          ${details.otxPulses > 0 ? `<div style="color:#ffa94d;margin-top:4px">OTX: ${details.otxPulses} pulses</div>` : ''}
        </div>`;

      const marker = L.marker([lat, lng], { icon })
        .addTo(map)
        .bindPopup(popupContent, { className: 'threat-popup', maxWidth: 280, closeButton: false });

      marker.on('click', () => setSelectedIP(ip));
      markersRef.current.push(marker);
    });

    if (bounds.length > 0) {
      map.fitBounds(bounds, { padding: [60, 60], maxZoom: 6 });
    }
  }, [leafletReady, result]);

  const ips = result?.enrichments?.ips ? Object.keys(result.enrichments.ips) : [];
  const ipsWithLocation = ips.filter(ip => getIPDetails(ip, result?.enrichments)?.loc).length;

  return (
    <div>
      {/* Legend */}
      <div style={{ display: 'flex', gap: '16px', alignItems: 'center', marginBottom: '12px', flexWrap: 'wrap' }}>
        <div style={{ fontSize: '11px', color: '#4a5568', letterSpacing: '2px' }}>LEGEND:</div>
        {Object.entries(VERDICT_COLORS).map(([verdict, color]) => (
          <div key={verdict} style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px', color: '#718096' }}>
            <div style={{ width: '12px', height: '12px', borderRadius: '50%', background: color, boxShadow: `0 0 6px ${color}` }} />
            {verdict}
          </div>
        ))}
        {ipsWithLocation > 0 && <div style={{ marginLeft: 'auto', fontSize: '11px', color: '#4a5568' }}>{ipsWithLocation}/{ips.length} IPs mapped</div>}
      </div>

      {/* Map */}
      <div style={{ position: 'relative', borderRadius: '8px', overflow: 'hidden', border: '1px solid #1e3a5f' }}>
        <div ref={mapRef} style={{ height: '500px', width: '100%', background: '#060d1a' }} />

        {!result && (
          <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', background: '#060d1a', color: '#4a5568' }}>
            <div style={{ fontSize: '32px', marginBottom: '12px', opacity: 0.3 }}>🗺</div>
            <div style={{ fontSize: '14px' }}>Run an analysis to map IP locations</div>
          </div>
        )}

        {result && ipsWithLocation === 0 && ips.length > 0 && (
          <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', background: '#060d1a66', color: '#718096' }}>
            <div style={{ fontSize: '14px' }}>No geolocation data available for extracted IPs</div>
            <div style={{ fontSize: '12px', marginTop: '4px' }}>ipinfo.io enrichment required for mapping</div>
          </div>
        )}
      </div>

      {/* IP Summary Table */}
      {result && ips.length > 0 && (
        <div style={{ background: '#0d1526', border: '1px solid #1e3a5f', borderRadius: '8px', padding: '16px', marginTop: '16px' }}>
          <div style={{ fontSize: '11px', color: '#4a9eff', letterSpacing: '2px', marginBottom: '12px' }}>IP GEOLOCATION SUMMARY</div>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid #1e3a5f' }}>
                {['IP ADDRESS', 'COUNTRY', 'ORGANIZATION', 'VERDICT', 'FLAGS'].map(h => (
                  <th key={h} style={{ textAlign: 'left', padding: '6px 10px', color: '#718096', fontWeight: 'normal', letterSpacing: '1px', fontSize: '10px' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {ips.map((ip, i) => {
                const d = getIPDetails(ip, result.enrichments);
                const verdict = getIPVerdict(ip, result.response_summary);
                const c = VERDICT_COLORS[verdict];
                return (
                  <tr key={ip} style={{ borderBottom: '1px solid #0d1a30', background: i % 2 === 0 ? 'transparent' : '#060d1a' }}>
                    <td style={{ padding: '8px 10px', fontFamily: 'Courier New', color: '#4a9eff' }}>{ip}</td>
                    <td style={{ padding: '8px 10px', color: '#c8d6e5' }}>{d.country || '—'}</td>
                    <td style={{ padding: '8px 10px', color: '#718096', maxWidth: '180px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{d.org || '—'}</td>
                    <td style={{ padding: '8px 10px' }}>
                      <span style={{ background: `${c}22`, border: `1px solid ${c}66`, color: c, padding: '2px 6px', borderRadius: '3px', fontSize: '10px' }}>{verdict}</span>
                    </td>
                    <td style={{ padding: '8px 10px' }}>
                      <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
                        {d.isTor && <span style={{ background: '#2d0a3d', border: '1px solid #cc5de8', color: '#cc5de8', padding: '1px 5px', borderRadius: '2px', fontSize: '9px' }}>TOR</span>}
                        {d.isNoise && <span style={{ background: '#1a1a0a', border: '1px solid #4a5568', color: '#718096', padding: '1px 5px', borderRadius: '2px', fontSize: '9px' }}>NOISE</span>}
                        {d.abuseScore > 50 && <span style={{ background: '#2d1a0a', border: '1px solid #ff8c00', color: '#ffa94d', padding: '1px 5px', borderRadius: '2px', fontSize: '9px' }}>ABUSE {d.abuseScore}%</span>}
                        {d.otxPulses > 0 && <span style={{ background: '#1a1a2d', border: '1px solid #4a9eff', color: '#74c0fc', padding: '1px 5px', borderRadius: '2px', fontSize: '9px' }}>OTX {d.otxPulses}</span>}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      <style>{`
        .threat-popup .leaflet-popup-content-wrapper { background: transparent !important; border: none !important; box-shadow: none !important; padding: 0 !important; }
        .threat-popup .leaflet-popup-content { margin: 0 !important; }
        .threat-popup .leaflet-popup-tip-container { display: none !important; }
      `}</style>
    </div>
  );
}
