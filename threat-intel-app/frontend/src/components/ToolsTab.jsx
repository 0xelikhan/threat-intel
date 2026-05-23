import React, { useState, useCallback } from 'react';

const S = {
  panel: { background: '#0d1526', border: '1px solid #1e3a5f', borderRadius: '8px', padding: '20px' },
  label: { fontSize: '11px', color: '#4a9eff', letterSpacing: '2px', textTransform: 'uppercase', marginBottom: '8px', display: 'block' },
  textarea: { width: '100%', background: '#060d1a', border: '1px solid #1e3a5f', color: '#c8d6e5', padding: '12px', borderRadius: '6px', fontFamily: 'Courier New', fontSize: '13px', resize: 'vertical', outline: 'none', lineHeight: '1.6', minHeight: '100px' },
  input: { width: '100%', background: '#060d1a', border: '1px solid #1e3a5f', color: '#c8d6e5', padding: '10px 14px', borderRadius: '6px', fontFamily: 'Courier New', fontSize: '13px', outline: 'none' },
  btn: (active) => ({ background: active ? '#1a3a6e' : '#0d1526', border: `1px solid ${active ? '#4a9eff' : '#2d3748'}`, color: active ? '#74c0fc' : '#718096', padding: '8px 16px', borderRadius: '4px', cursor: 'pointer', fontSize: '12px', letterSpacing: '1px', fontFamily: 'Courier New', transition: 'all 0.15s' }),
  output: { width: '100%', background: '#060d1a', border: '1px solid #1e3a5f', borderRadius: '6px', padding: '12px', fontFamily: 'Courier New', fontSize: '13px', color: '#51cf66', minHeight: '80px', wordBreak: 'break-all', whiteSpace: 'pre-wrap', lineHeight: '1.6' },
  row: { display: 'flex', gap: '8px', marginBottom: '10px', flexWrap: 'wrap' },
  grid: { display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' },
  title: { fontSize: '13px', color: '#e2e8f0', fontWeight: 'bold', marginBottom: '16px', letterSpacing: '1px' },
  select: { background: '#060d1a', border: '1px solid #1e3a5f', color: '#c8d6e5', padding: '8px 12px', borderRadius: '4px', fontSize: '12px', fontFamily: 'Courier New', outline: 'none' }
};

// ─── DECODER SUITE ──────────────────────────────────────────────────────────────
function DecoderTool() {
  const [input, setInput] = useState('');
  const [output, setOutput] = useState('');
  const [mode, setMode] = useState('base64');
  const [error, setError] = useState('');

  const operations = {
    base64: {
      decode: (v) => { try { return atob(v.trim()); } catch { throw new Error('Invalid Base64'); } },
      encode: (v) => btoa(v)
    },
    hex: {
      decode: (v) => { const clean = v.replace(/\s/g, ''); if (!/^[0-9a-fA-F]+$/.test(clean) || clean.length % 2) throw new Error('Invalid hex'); return clean.match(/.{2}/g).map(b => String.fromCharCode(parseInt(b, 16))).join(''); },
      encode: (v) => Array.from(v).map(c => c.charCodeAt(0).toString(16).padStart(2, '0')).join(' ')
    },
    url: {
      decode: (v) => { try { return decodeURIComponent(v); } catch { throw new Error('Invalid URL encoding'); } },
      encode: (v) => encodeURIComponent(v)
    },
    jwt: {
      decode: (v) => {
        const parts = v.trim().split('.');
        if (parts.length !== 3) throw new Error('JWT must have 3 parts');
        const decode = s => { try { return JSON.parse(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '=='.slice(0, (4 - s.length % 4) % 4))); } catch { return s; } };
        return JSON.stringify({ header: decode(parts[0]), payload: decode(parts[1]), signature: parts[2] }, null, 2);
      },
      encode: () => { throw new Error('JWT signing not supported — use a backend service'); }
    },
    unicode: {
      decode: (v) => v.replace(/\\u([0-9a-fA-F]{4})/g, (_, c) => String.fromCharCode(parseInt(c, 16))),
      encode: (v) => Array.from(v).map(c => c.charCodeAt(0) > 127 ? `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}` : c).join('')
    }
  };

  const run = (dir) => {
    setError('');
    try { setOutput(operations[mode][dir](input)); }
    catch (e) { setError(e.message); setOutput(''); }
  };

  const isJWT = mode === 'jwt';

  return (
    <div style={S.panel}>
      <div style={S.title}>DECODER SUITE</div>
      <div style={S.row}>
        {Object.keys(operations).map(m => (
          <button key={m} style={S.btn(mode === m)} onClick={() => { setMode(m); setOutput(''); setError(''); }}>{m.toUpperCase()}</button>
        ))}
      </div>
      <textarea style={{ ...S.textarea, marginBottom: '10px' }} value={input} onChange={e => setInput(e.target.value)} placeholder={`Paste ${mode.toUpperCase()} encoded string here...`} />
      <div style={S.row}>
        <button style={S.btn(true)} onClick={() => run('decode')}>DECODE →</button>
        {!isJWT && <button style={S.btn(true)} onClick={() => run('encode')}>← ENCODE</button>}
        <button style={S.btn(false)} onClick={() => { setInput(''); setOutput(''); setError(''); }}>CLEAR</button>
        {output && <button style={S.btn(false)} onClick={() => navigator.clipboard.writeText(output)}>COPY OUTPUT</button>}
      </div>
      {error && <div style={{ fontSize: '12px', color: '#fc8181', marginBottom: '8px' }}>⚠ {error}</div>}
      {output && <div style={S.output}>{output}</div>}
    </div>
  );
}

// ─── DEFANG / REFANG ────────────────────────────────────────────────────────────
function DefangTool() {
  const [input, setInput] = useState('');
  const [output, setOutput] = useState('');
  const [mode, setMode] = useState(null);

  const defang = (text) => text
    .split('\n')
    .map(line => line
      .replace(/^(https?):\/\//gi, (_, proto) => `${proto}[://]`)
      .replace(/(?<!\[)\.(?!\])/g, '[.]')
      .replace(/\[:\]\[\/\/\]/g, '[://]')
    ).join('\n');

  const refang = (text) => text
    .split('\n')
    .map(line => line
      .replace(/hxxps?\[\:\/\/\]|https?\[:\/\/\]|hxxps?:\/\/|https?\[://\]/gi, m => m.includes('hxxps') ? 'https://' : m.includes('hxxp') ? 'http://' : m.replace(/\[.*?\]/g, '://'))
      .replace(/\[\.\]/g, '.')
    ).join('\n');

  const run = (fn, m) => { setMode(m); setOutput(fn(input)); };

  return (
    <div style={S.panel}>
      <div style={S.title}>DEFANG / REFANG</div>
      <textarea style={{ ...S.textarea, marginBottom: '10px' }} value={input} onChange={e => setInput(e.target.value)} placeholder={'Paste IOCs here, one per line...\n\nhttps://malware.com/payload.exe\n185.220.101.45\nevil-domain.xyz'} />
      <div style={S.row}>
        <button style={S.btn(mode === 'defang')} onClick={() => run(defang, 'defang')}>DEFANG ↓</button>
        <button style={S.btn(mode === 'refang')} onClick={() => run(refang, 'refang')}>REFANG ↑</button>
        <button style={S.btn(false)} onClick={() => { setInput(''); setOutput(''); setMode(null); }}>CLEAR</button>
        {output && <button style={S.btn(false)} onClick={() => navigator.clipboard.writeText(output)}>COPY</button>}
      </div>
      {output && (
        <div>
          <div style={{ ...S.label, marginTop: '8px' }}>OUTPUT ({mode?.toUpperCase()})</div>
          <div style={S.output}>{output}</div>
        </div>
      )}
      <div style={{ marginTop: '8px', fontSize: '11px', color: '#4a5568' }}>Defanging replaces . with [.] and :// with [://] for safe sharing in tickets and chat.</div>
    </div>
  );
}

// ─── HASH CALCULATOR ────────────────────────────────────────────────────────────
function HashTool() {
  const [input, setInput] = useState('');
  const [hashes, setHashes] = useState(null);
  const [loading, setLoading] = useState(false);
  const [isFile, setIsFile] = useState(false);

  const toHex = buf => Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');

  const calculateHashes = async (data) => {
    setLoading(true);
    try {
      const encoded = typeof data === 'string' ? new TextEncoder().encode(data) : data;
      const [sha1, sha256, sha512] = await Promise.all([
        crypto.subtle.digest('SHA-1', encoded),
        crypto.subtle.digest('SHA-256', encoded),
        crypto.subtle.digest('SHA-512', encoded)
      ]);
      setHashes({ 'SHA-1': toHex(sha1), 'SHA-256': toHex(sha256), 'SHA-512': toHex(sha512) });
    } catch (e) { setHashes({ error: e.message }); }
    setLoading(false);
  };

  const handleFile = (file) => {
    if (!file) return;
    setIsFile(true);
    setInput(file.name);
    const reader = new FileReader();
    reader.onload = e => calculateHashes(e.target.result);
    reader.readAsArrayBuffer(file);
  };

  return (
    <div style={S.panel}>
      <div style={S.title}>HASH CALCULATOR</div>
      <textarea style={{ ...S.textarea, marginBottom: '10px' }} value={input} onChange={e => { setIsFile(false); setInput(e.target.value); setHashes(null); }} placeholder="Paste text to hash, or drop a file below..." />
      <div style={S.row}>
        <button style={S.btn(true)} onClick={() => calculateHashes(input)} disabled={!input.trim() || loading}>
          {loading ? 'CALCULATING...' : 'CALCULATE HASHES'}
        </button>
        <button style={S.btn(true)} onClick={() => document.getElementById('hash-file').click()}>HASH A FILE</button>
        <button style={S.btn(false)} onClick={() => { setInput(''); setHashes(null); setIsFile(false); }}>CLEAR</button>
        <input id="hash-file" type="file" style={{ display: 'none' }} onChange={e => handleFile(e.target.files[0])} />
      </div>
      {hashes && !hashes.error && (
        <div style={{ marginTop: '10px' }}>
          {Object.entries(hashes).map(([algo, hash]) => (
            <div key={algo} style={{ marginBottom: '10px' }}>
              <div style={{ ...S.label, marginBottom: '4px' }}>{algo}</div>
              <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                <div style={{ ...S.output, minHeight: 'auto', padding: '8px 12px', fontSize: '12px', flex: 1 }}>{hash}</div>
                <button style={{ ...S.btn(false), whiteSpace: 'nowrap' }} onClick={() => navigator.clipboard.writeText(hash)}>COPY</button>
              </div>
            </div>
          ))}
        </div>
      )}
      {hashes?.error && <div style={{ color: '#fc8181', fontSize: '12px', marginTop: '8px' }}>⚠ {hashes.error}</div>}
    </div>
  );
}

// ─── REGEX TESTER ───────────────────────────────────────────────────────────────
function RegexTool() {
  const [pattern, setPattern] = useState('');
  const [flags, setFlags] = useState('gmi');
  const [testText, setTestText] = useState('');
  const [error, setError] = useState('');

  const PRESETS = {
    'IPv4': String.raw`\b(?!10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)(\d{1,3}\.){3}\d{1,3}\b`,
    'SHA-256': String.raw`\b[a-fA-F0-9]{64}\b`,
    'MD5': String.raw`\b[a-fA-F0-9]{32}\b`,
    'URL': String.raw`https?:\/\/[^\s"'<>]+`,
    'Email': String.raw`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`,
    'Domain': String.raw`\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|gov)\b`,
    'CVE': String.raw`CVE-\d{4}-\d{4,7}`,
    'Win Event': String.raw`EventID[: ]+(\d+)`,
    'Base64': String.raw`[A-Za-z0-9+/]{20,}={0,2}`
  };

  const getHighlighted = useCallback(() => {
    if (!pattern || !testText) return { html: testText, count: 0 };
    try {
      setError('');
      const regex = new RegExp(pattern, flags);
      const matches = [...testText.matchAll(new RegExp(pattern, 'g'))];
      const html = testText.replace(regex, m => `<mark style="background:#2d5016;color:#51cf66;border-radius:2px;padding:0 2px">${m}</mark>`);
      return { html, count: matches.length };
    } catch (e) { setError(e.message); return { html: testText, count: 0 }; }
  }, [pattern, flags, testText]);

  const { html, count } = getHighlighted();

  return (
    <div style={S.panel}>
      <div style={S.title}>REGEX TESTER</div>
      <div style={{ marginBottom: '8px' }}>
        <div style={{ ...S.label, marginBottom: '6px' }}>PRESETS</div>
        <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
          {Object.entries(PRESETS).map(([name, p]) => (
            <button key={name} style={{ ...S.btn(false), fontSize: '10px', padding: '4px 8px' }} onClick={() => setPattern(p)}>{name}</button>
          ))}
        </div>
      </div>
      <div style={{ display: 'flex', gap: '8px', marginBottom: '10px', alignItems: 'center' }}>
        <div style={{ flex: 1 }}>
          <div style={S.label}>PATTERN</div>
          <input style={S.input} value={pattern} onChange={e => setPattern(e.target.value)} placeholder="Enter regex pattern..." />
        </div>
        <div style={{ width: '80px' }}>
          <div style={S.label}>FLAGS</div>
          <input style={S.input} value={flags} onChange={e => setFlags(e.target.value)} placeholder="gmi" maxLength={5} />
        </div>
      </div>
      {error && <div style={{ color: '#fc8181', fontSize: '12px', marginBottom: '8px' }}>⚠ Regex error: {error}</div>}
      <div style={S.label}>TEST TEXT</div>
      <textarea style={{ ...S.textarea, marginBottom: '10px' }} value={testText} onChange={e => setTestText(e.target.value)} placeholder="Paste log content to test your regex against..." rows={6} />
      {testText && pattern && !error && (
        <div>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
            <div style={S.label}>MATCHES</div>
            <span style={{ fontSize: '12px', color: count > 0 ? '#51cf66' : '#718096' }}>{count} match{count !== 1 ? 'es' : ''}</span>
          </div>
          <div style={{ ...S.output, color: '#c8d6e5', fontSize: '12px', whiteSpace: 'pre-wrap' }} dangerouslySetInnerHTML={{ __html: html }} />
        </div>
      )}
    </div>
  );
}

// ─── MAIN TOOLS TAB ─────────────────────────────────────────────────────────────
export default function ToolsTab() {
  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', alignItems: 'start' }}>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
        <DecoderTool />
        <HashTool />
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
        <DefangTool />
        <RegexTool />
      </div>
    </div>
  );
}
