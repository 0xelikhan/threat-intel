import React, { useState, useEffect } from 'react';

const API = '/api';

const GROUP_ORDER = ['AI', 'Core TI', 'Extended TI'];
const GROUP_DESCRIPTIONS = {
  'AI':          'Required for threat assessment, Sigma/KQL generation, and chain-of-thought analysis.',
  'Core TI':     'Recommended. These APIs provide the most signal — configure as many as possible.',
  'Extended TI': 'Optional but adds depth to domain and URL analysis.',
};

export default function SettingsPage({ onConfigured }) {
  const [settings, setSettings]   = useState(null);
  const [form, setForm]           = useState({});
  const [saving, setSaving]       = useState(false);
  const [testing, setTesting]     = useState(false);
  const [testResult, setTestResult] = useState(null);
  const [saved, setSaved]         = useState(false);
  const [showValues, setShowValues] = useState({});
  const [loading, setLoading]     = useState(true);

  useEffect(() => {
    fetch(`${API}/settings`)
      .then(r => r.json())
      .then(data => {
        setSettings(data);
        // Pre-fill form with raw values
        const initial = {};
        Object.entries(data.keys || {}).forEach(([k, v]) => {
          initial[k] = v.rawValue || '';
        });
        setForm(initial);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, []);

  const handleSave = async () => {
    setSaving(true);
    setSaved(false);
    setTestResult(null);
    try {
      const resp = await fetch(`${API}/settings`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ keys: form })
      });
      const data = await resp.json();
      setSaved(true);
      setTimeout(() => setSaved(false), 3000);
      if (data.configured) onConfigured?.();
      // Refresh settings
      const fresh = await fetch(`${API}/settings`).then(r => r.json());
      setSettings(fresh);
    } catch (e) {
      console.error(e);
    }
    setSaving(false);
  };

  const handleTest = async () => {
    setTesting(true);
    setTestResult(null);
    try {
      const resp = await fetch(`${API}/settings/test`, { method: 'POST' });
      const data = await resp.json();
      setTestResult(data);
    } catch (e) {
      setTestResult({ ok: false, error: e.message });
    }
    setTesting(false);
  };

  if (loading) return (
    <div style={{ display: 'flex', justifyContent: 'center', padding: '60px', color: '#4a5568' }}>
      Loading...
    </div>
  );

  const isConfigured = settings?.configured;
  const keyDefs = settings?.keys || {};

  const groupedKeys = {};
  Object.entries(keyDefs).forEach(([k, v]) => {
    const g = v.group || 'Other';
    groupedKeys[g] = groupedKeys[g] || [];
    groupedKeys[g].push([k, v]);
  });

  return (
    <div style={{ maxWidth: '780px', margin: '0 auto' }}>
      {/* Header */}
      {!isConfigured && (
        <div style={{ background: '#1a1a05', border: '1px solid #ffd700', borderRadius: '8px', padding: '16px 20px', marginBottom: '24px' }}>
          <div style={{ fontSize: '13px', color: '#ffe566', marginBottom: '4px', fontWeight: 'bold' }}>⚡ First time setup</div>
          <div style={{ fontSize: '12px', color: '#a0916a', lineHeight: '1.6' }}>
            Add your API keys below to start using the platform. The OpenAI key and at least one threat intel key are required.
            Keys are saved locally to <code style={{ color: '#ffe566' }}>./data/config.json</code> and never leave your machine.
          </div>
        </div>
      )}

      {GROUP_ORDER.map(group => {
        const keys = groupedKeys[group];
        if (!keys?.length) return null;
        return (
          <div key={group} style={{ marginBottom: '28px' }}>
            <div style={{ marginBottom: '12px' }}>
              <div style={{ fontSize: '13px', color: '#e2e8f0', fontWeight: 'bold', letterSpacing: '1px', marginBottom: '3px' }}>
                {group}
              </div>
              <div style={{ fontSize: '11px', color: '#4a5568' }}>{GROUP_DESCRIPTIONS[group]}</div>
            </div>

            <div style={{ background: '#0d1526', border: '1px solid #1e3a5f', borderRadius: '8px', overflow: 'hidden' }}>
              {keys.map(([key, def], idx) => {
                const currentVal = form[key] || '';
                const isSet = currentVal && currentVal !== (def.default || '');
                const isVisible = showValues[key];

                return (
                  <div key={key} style={{
                    padding: '16px 20px',
                    borderBottom: idx < keys.length - 1 ? '1px solid #0d1a30' : 'none',
                    background: idx % 2 === 0 ? 'transparent' : '#060d1a44'
                  }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '8px' }}>
                      <div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '2px' }}>
                          <span style={{ fontSize: '13px', color: '#e2e8f0', fontWeight: '500' }}>{def.label}</span>
                          {def.required && (
                            <span style={{ fontSize: '9px', color: '#ff6b6b', border: '1px solid #ff6b6b44', padding: '1px 5px', borderRadius: '3px', letterSpacing: '1px' }}>REQUIRED</span>
                          )}
                          {isSet && (
                            <span style={{ fontSize: '9px', color: '#51cf66', border: '1px solid #51cf6644', padding: '1px 5px', borderRadius: '3px', letterSpacing: '1px' }}>✓ SET</span>
                          )}
                        </div>
                        <div style={{ fontSize: '11px', color: '#4a5568', lineHeight: '1.5' }}>{def.description}</div>
                      </div>
                      {def.url && (
                        <a href={def.url} target="_blank" rel="noreferrer" style={{ fontSize: '11px', color: '#4a9eff', textDecoration: 'none', whiteSpace: 'nowrap', marginLeft: '12px' }}>
                          Get key →
                        </a>
                      )}
                    </div>
                    <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                      <input
                        type={isVisible ? 'text' : 'password'}
                        value={currentVal}
                        onChange={e => setForm(prev => ({ ...prev, [key]: e.target.value }))}
                        placeholder={def.placeholder || def.default || ''}
                        style={{
                          flex: 1, background: '#060d1a', border: `1px solid ${isSet ? '#51cf6644' : '#1e3a5f'}`,
                          color: '#c8d6e5', padding: '9px 12px', borderRadius: '5px',
                          fontFamily: 'Courier New', fontSize: '12px', outline: 'none'
                        }}
                      />
                      <button
                        onClick={() => setShowValues(p => ({ ...p, [key]: !p[key] }))}
                        style={{ background: 'none', border: '1px solid #1e3a5f', color: '#4a5568', padding: '8px 10px', borderRadius: '5px', cursor: 'pointer', fontSize: '12px' }}
                        title={isVisible ? 'Hide' : 'Show'}
                      >
                        {isVisible ? '🙈' : '👁'}
                      </button>
                      {currentVal && (
                        <button
                          onClick={() => setForm(prev => ({ ...prev, [key]: '' }))}
                          style={{ background: 'none', border: '1px solid #2d3748', color: '#4a5568', padding: '8px 10px', borderRadius: '5px', cursor: 'pointer', fontSize: '12px' }}
                          title="Clear"
                        >✕</button>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        );
      })}

      {/* Free APIs note */}
      <div style={{ background: '#060d1a', border: '1px solid #1e3a5f', borderRadius: '8px', padding: '14px 18px', marginBottom: '24px' }}>
        <div style={{ fontSize: '11px', color: '#4a9eff', letterSpacing: '2px', marginBottom: '8px' }}>FREE APIS (NO KEY NEEDED)</div>
        <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
          {(settings?.freeApis || []).map(api => (
            <span key={api} style={{ background: '#0d1526', border: '1px solid #1e3a5f', color: '#51cf66', padding: '3px 8px', borderRadius: '4px', fontSize: '11px' }}>
              ✓ {api}
            </span>
          ))}
        </div>
      </div>

      {/* Actions */}
      <div style={{ display: 'flex', gap: '10px', alignItems: 'center', flexWrap: 'wrap' }}>
        <button
          onClick={handleSave}
          disabled={saving}
          style={{
            background: saving ? '#1a2744' : 'linear-gradient(135deg, #1a3a6e, #0f2751)',
            border: '1px solid #4a9eff', color: '#74c0fc',
            padding: '11px 28px', borderRadius: '6px', cursor: saving ? 'not-allowed' : 'pointer',
            fontSize: '12px', letterSpacing: '2px', fontFamily: 'Courier New', fontWeight: 'bold'
          }}
        >
          {saving ? 'SAVING...' : saved ? '✓ SAVED' : 'SAVE SETTINGS'}
        </button>

        <button
          onClick={handleTest}
          disabled={testing || !form['OPENAI_API_KEY']}
          style={{
            background: 'none', border: '1px solid #2d3748',
            color: testing ? '#4a5568' : '#718096',
            padding: '11px 20px', borderRadius: '6px', cursor: 'pointer',
            fontSize: '12px', letterSpacing: '1px', fontFamily: 'Courier New'
          }}
        >
          {testing ? 'TESTING...' : 'TEST AI KEY'}
        </button>

        {testResult && (
          <span style={{ fontSize: '12px', color: testResult.ok ? '#51cf66' : '#ff6b6b' }}>
            {testResult.ok ? '✓ ' + testResult.message : '✗ ' + testResult.error}
          </span>
        )}
      </div>

      <div style={{ marginTop: '16px', fontSize: '11px', color: '#4a5568', lineHeight: '1.7' }}>
        Keys are stored in <code>./data/config.json</code> on your machine. They are never sent anywhere except directly to each API provider when you run an analysis.
        To reset all keys, delete that file and restart the app.
      </div>
    </div>
  );
}
