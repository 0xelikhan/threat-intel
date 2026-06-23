/*
 * Settings page — renders every key registered in
 * backend/config.py::API_KEY_DEFINITIONS, grouped by the `group`
 * field on each definition. Operators can edit + save without
 * shell-editing data/config.json.
 *
 * The backend never returns plaintext key values — every configured
 * key arrives as `"••••••••••"`. To update a key the operator
 * overwrites it (or clears it to revert to default). To LEAVE a key
 * unchanged, we DON'T send it in the POST body.
 *
 * Used keys flow into the active config via /api/settings POST; the
 * backend's ConfigManager._maybe_reload() picks them up on next call.
 */

import React, { useEffect, useState, useMemo } from 'react';
import {
  Box, Stack, Typography, Button, TextField, Tooltip, Alert,
  CircularProgress, IconButton, Divider, Chip, alpha,
} from '@mui/material';
import { Settings as SettingsIcon, ExternalLink, Eye, EyeOff, Save, RotateCcw, Check, X } from 'lucide-react';

import { cookieFetch } from '../utils/api';

const PLACEHOLDER_VALUE = '••••••••';  // backend masks configured keys as bullets

// Tokens for inline section coloring — match the OpenCTI dark theme.
const TIER_COLOR = {
  'API Keys':              '#0fbcff',
  'Outbound Integrations': '#16AD34',
  'Enricher Toggles':      '#E6700F',
  'Other':                 '#848592',
};


export default function SettingsView() {
  const [loading, setLoading]   = useState(true);
  const [saving, setSaving]     = useState(false);
  const [testing, setTesting]   = useState(false);
  const [error, setError]       = useState(null);
  const [data, setData]         = useState(null);
  // Pending edits — keyed by config key name. Anything in here is
  // dirty (overrides the loaded value).
  const [pending, setPending]   = useState({});
  // Per-key visibility — masked by default.
  const [revealed, setRevealed] = useState({});
  const [savedTick, setSavedTick] = useState(0);
  const [testResult, setTestResult] = useState(null);

  // Load on mount
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const resp = await cookieFetch('/api/settings');
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const j = await resp.json();
        if (!cancelled) {
          setData(j);
          setError(null);
        }
      } catch (e) {
        if (!cancelled) setError(e.message || 'Failed to load settings');
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, [savedTick]);

  const grouped = useMemo(() => {
    if (!data?.keys) return [];
    const order = ['API Keys', 'Outbound Integrations', 'Enricher Toggles'];
    const buckets = {};
    Object.entries(data.keys).forEach(([k, defn]) => {
      const g = defn.group || 'Other';
      (buckets[g] ||= []).push({ k, ...defn });
    });
    return Object.keys(buckets)
      .sort((a, b) => (order.indexOf(a) === -1 ? 999 : order.indexOf(a)) -
                       (order.indexOf(b) === -1 ? 999 : order.indexOf(b)))
      .map(g => ({ group: g, items: buckets[g] }));
  }, [data]);

  const dirtyCount = Object.keys(pending).length;

  const onChange = (k, v) => {
    setPending(p => {
      const next = { ...p };
      // If the user typed something that matches the mask, treat that
      // as "no change" — they didn't actually edit.
      if (v === PLACEHOLDER_VALUE || v === '') {
        delete next[k];
      } else {
        next[k] = v;
      }
      return next;
    });
  };

  const onReveal = (k) => setRevealed(r => ({ ...r, [k]: !r[k] }));

  const onSave = async () => {
    if (!dirtyCount) return;
    setSaving(true); setError(null);
    try {
      const resp = await cookieFetch('/api/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ keys: pending }),
      });
      if (!resp.ok) {
        const j = await resp.json().catch(() => ({}));
        throw new Error(j.detail || j.error || `HTTP ${resp.status}`);
      }
      setPending({});
      setRevealed({});
      setSavedTick(t => t + 1);   // forces a re-fetch
    } catch (e) {
      setError(e.message || 'Save failed');
    } finally {
      setSaving(false);
    }
  };

  const onTest = async () => {
    setTesting(true); setTestResult(null);
    try {
      const resp = await cookieFetch('/api/settings/test', { method: 'POST' });
      const j = await resp.json();
      setTestResult(j);
    } catch (e) {
      setTestResult({ ok: false, error: e.message || 'Test failed' });
    } finally {
      setTesting(false);
    }
  };

  if (loading) {
    return (
      <Stack alignItems="center" justifyContent="center" sx={{ p: 4, color: 'text.tertiary' }}>
        <CircularProgress size={20} sx={{ mb: 1.5 }}/>
        <Typography sx={{ fontSize: 12 }}>Loading settings…</Typography>
      </Stack>
    );
  }

  if (error && !data) {
    return (
      <Alert severity="error" sx={{ m: 2 }}>
        {error}
      </Alert>
    );
  }

  return (
    <Box sx={{ p: 0 }}>
      <Stack direction="row" alignItems="center" justifyContent="space-between" sx={{ mb: 3 }}>
        <Stack direction="row" alignItems="center" spacing={1.5}>
          <SettingsIcon size={20} color="#0fbcff"/>
          <Typography sx={{ fontSize: 18, fontWeight: 600, color: 'text.primary' }}>
            Settings
          </Typography>
          {data?.configured && (
            <Chip size="small" label="Configured" color="success" variant="outlined"
              sx={{ fontSize: 10, height: 22 }}/>
          )}
        </Stack>
        <Stack direction="row" spacing={1}>
          <Button onClick={onTest} disabled={testing} variant="outlined" size="small"
            sx={{ textTransform: 'none' }}>
            {testing ? 'Testing…' : 'Test LLM key'}
          </Button>
          <Button onClick={onSave} disabled={!dirtyCount || saving}
            variant="contained" size="small" startIcon={<Save size={14}/>}
            sx={{ textTransform: 'none' }}>
            {saving ? 'Saving…'
              : dirtyCount > 0 ? `Save ${dirtyCount} change${dirtyCount>1?'s':''}`
              : 'Saved'}
          </Button>
        </Stack>
      </Stack>

      {testResult && (
        <Alert
          severity={testResult.ok ? 'success' : 'error'}
          icon={testResult.ok ? <Check size={16}/> : <X size={16}/>}
          onClose={() => setTestResult(null)}
          sx={{ mb: 2 }}>
          {testResult.message || testResult.error}
        </Alert>
      )}

      {error && (
        <Alert severity="error" onClose={() => setError(null)} sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}

      <Typography sx={{ fontSize: 12, color: 'text.tertiary', mb: 3, lineHeight: 1.6, maxWidth: 760 }}>
        Configured values are masked. Type a new value to replace; leave the
        masked field as-is to keep the current value. Empty + Save will not
        clear an existing key (use <code>data/config.json</code> directly for that).
        Most keys also accept the matching env var on the container.
      </Typography>

      {grouped.map(({ group, items }) => (
        <Box key={group} sx={{ mb: 4 }}>
          <Stack direction="row" alignItems="center" spacing={1} sx={{ mb: 1.5 }}>
            <Box sx={{
              width: 4, height: 16,
              backgroundColor: TIER_COLOR[group] || TIER_COLOR.Other,
              borderRadius: 1,
            }}/>
            <Typography sx={{
              fontSize: 13, fontWeight: 600, color: 'text.primary',
              textTransform: 'uppercase', letterSpacing: '0.06em',
            }}>
              {group}
            </Typography>
            <Typography sx={{ fontSize: 11, color: 'text.tertiary' }}>
              {items.length} key{items.length === 1 ? '' : 's'}
            </Typography>
          </Stack>

          <Stack spacing={1.5}>
            {items.map(({ k, label, description, url, placeholder, required, configured, value, default: dflt }) => {
              const pendingValue = pending[k];
              const isDirty      = pendingValue !== undefined;
              const masked       = value && value.startsWith('•');
              const reveal       = !!revealed[k];
              const displayValue = isDirty ? pendingValue
                                   : (masked && !reveal) ? PLACEHOLDER_VALUE
                                   : (value || '');
              return (
                <Box key={k} sx={{
                  p: 2, border: `1px solid ${alpha('#ffffff', 0.08)}`,
                  borderRadius: 1, backgroundColor: alpha('#0C1524', 0.4),
                }}>
                  <Stack direction="row" alignItems="center" spacing={1} sx={{ mb: 0.5 }}>
                    <Typography sx={{ fontSize: 13, fontWeight: 600, color: 'text.primary' }}>
                      {label}
                    </Typography>
                    {required && (
                      <Chip size="small" label="required" color="error" variant="outlined"
                        sx={{ fontSize: 9, height: 18 }}/>
                    )}
                    {configured && (
                      <Chip size="small" label="set" variant="outlined"
                        sx={{ fontSize: 9, height: 18,
                          borderColor: alpha('#16AD34', 0.5), color: '#16AD34' }}/>
                    )}
                    {isDirty && (
                      <Chip size="small" label="pending" variant="outlined"
                        sx={{ fontSize: 9, height: 18,
                          borderColor: alpha('#E6700F', 0.5), color: '#E6700F' }}/>
                    )}
                    <Box sx={{ flex: 1 }}/>
                    <Typography sx={{ fontSize: 10, color: 'text.tertiary',
                      fontFamily: '"IBM Plex Mono", monospace' }}>
                      {k}
                    </Typography>
                  </Stack>

                  <Typography sx={{ fontSize: 12, color: 'text.tertiary', mb: 1.5, lineHeight: 1.6 }}>
                    {description}
                    {url && (
                      <a href={url} target="_blank" rel="noreferrer"
                        style={{ marginLeft: 8, color: '#0fbcff', textDecoration: 'none' }}>
                        <ExternalLink size={10} style={{ display: 'inline', marginRight: 2 }}/>
                        provider
                      </a>
                    )}
                  </Typography>

                  <Stack direction="row" alignItems="center" spacing={1}>
                    <TextField
                      value={displayValue}
                      onChange={(e) => onChange(k, e.target.value)}
                      placeholder={placeholder || ''}
                      type={reveal || isDirty || !masked ? 'text' : 'password'}
                      size="small"
                      fullWidth
                      InputProps={{
                        sx: {
                          fontSize: 12,
                          fontFamily: '"IBM Plex Mono", monospace',
                        },
                      }}
                    />
                    {masked && !isDirty && (
                      <Tooltip title={reveal ? 'Hide' : 'Reveal mask'}>
                        <IconButton size="small" onClick={() => onReveal(k)}>
                          {reveal ? <EyeOff size={14}/> : <Eye size={14}/>}
                        </IconButton>
                      </Tooltip>
                    )}
                    {isDirty && (
                      <Tooltip title="Revert">
                        <IconButton size="small" onClick={() => onChange(k, PLACEHOLDER_VALUE)}>
                          <RotateCcw size={14}/>
                        </IconButton>
                      </Tooltip>
                    )}
                  </Stack>

                  {dflt && (
                    <Typography sx={{ fontSize: 10, color: 'text.tertiary', mt: 0.5 }}>
                      Default: <code>{dflt}</code>
                    </Typography>
                  )}
                </Box>
              );
            })}
          </Stack>
        </Box>
      ))}

      {(data?.freeApis || []).length > 0 && (
        <Box sx={{ mt: 4 }}>
          <Divider sx={{ mb: 2 }}/>
          <Typography sx={{ fontSize: 11, color: 'text.tertiary', mb: 1 }}>
            Free APIs (no key required) — always-on
          </Typography>
          <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
            {data.freeApis.map((src, i) => (
              <Chip key={i} size="small" label={src} variant="outlined"
                sx={{ fontSize: 10, height: 22 }}/>
            ))}
          </Stack>
        </Box>
      )}
    </Box>
  );
}
