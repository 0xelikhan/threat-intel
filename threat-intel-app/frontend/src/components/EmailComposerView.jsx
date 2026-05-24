/**
 * RECON Email Composer — three-step page in the OpenCTI aesthetic.
 *
 *   1. Paste the raw alert log
 *   2. Pick a template + response action (dropdowns)
 *   3. Preview the rendered email with inline Copy buttons
 *
 * Parsing happens automatically when Compose is clicked — analysts don't
 * have to touch the extracted fields. Every chip / paper / select pulls
 * from theme.palette so the page inherits the RECON dark theme. The
 * preview surface is the only white background, so it shows how the
 * customer will actually see the message.
 */
import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  Box, Stack, Typography, Paper as MuiPaper,
  Button as MuiButton, TextField as MuiTextField,
  IconButton as MuiIconButton, CircularProgress, Tooltip,
  ToggleButton, ToggleButtonGroup, MenuItem,
} from '@mui/material';
import { alpha as muiAlpha } from '@mui/material/styles';
import { Mail, Copy, Check, Eye, RefreshCcw, AlertCircle } from 'lucide-react';

const monoSx = { fontFamily: '"IBM Plex Mono", monospace' };

const RESPONSE_OPTIONS = [
  { id: '',                                 label: 'None' },
  { id: 'clearing_alert',                   label: 'Clearing alert' },
  { id: 'escalating',                       label: 'Escalating' },
  { id: 'isolating',                        label: 'Isolating endpoint' },
  { id: 'lockdown',                         label: 'Lockdown' },
  { id: 'lock_account',                     label: 'Lock account' },
  { id: 'lock_account_and_revoke_session',  label: 'Lock account & revoke session' },
];


function CopyBtn({ text, label = 'Copy', size = 'small', variant = 'button' }) {
  const [copied, setCopied] = useState(false);
  const doCopy = (e) => {
    e?.stopPropagation();
    navigator.clipboard.writeText(text || '');
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };
  if (variant === 'icon') {
    return (
      <Tooltip title={copied ? 'Copied' : label}>
        <MuiIconButton size={size} onClick={doCopy}
          sx={{ p: 0.5, color: copied ? 'success.main' : 'text.tertiary' }}>
          {copied ? <Check size={14}/> : <Copy size={14}/>}
        </MuiIconButton>
      </Tooltip>
    );
  }
  return (
    <MuiButton
      size={size} variant="outlined" onClick={doCopy}
      startIcon={copied ? <Check size={14}/> : <Copy size={14}/>}
      sx={{
        textTransform: 'none', fontSize: 12,
        color: copied ? 'success.main' : 'text.primary',
        borderColor: copied ? 'success.main' : muiAlpha('#ffffff', 0.18),
      }}
    >
      {copied ? 'Copied' : label}
    </MuiButton>
  );
}


function SectionHeader({ title, badge, accent = '#0fbcff', right }) {
  return (
    <Stack direction="row" alignItems="center" spacing={1} sx={{ mb: 1.25 }}>
      <Box sx={{ width: 3, height: 14, backgroundColor: accent, borderRadius: 0.5 }}/>
      <Typography sx={{ fontSize: 12, fontWeight: 600, color: 'text.primary',
        textTransform: 'uppercase', letterSpacing: '0.06em' }}>
        {title}
      </Typography>
      {badge && (
        <Typography sx={{ fontSize: 11, color: 'text.tertiary' }}>· {badge}</Typography>
      )}
      {right && <Box sx={{ ml: 'auto !important' }}>{right}</Box>}
    </Stack>
  );
}


export default function EmailComposerView({ initialLog = '', initialParsed = null, onClose }) {
  const [rawLog, setRawLog]               = useState(initialLog);
  const [alertTypes, setAlertTypes]       = useState([]);
  const [selectedType, setSelectedType]   = useState('');
  const [responseAction, setResponseAction] = useState('');
  const [composed, setComposed]           = useState(null);
  const [composing, setComposing]         = useState(false);
  const [composeError, setComposeError]   = useState(null);
  const [previewMode, setPreviewMode]     = useState('rendered'); // 'rendered' | 'html' | 'text'
  // Tracks whether the analyst explicitly chose a template — if so, we
  // stop auto-overriding it with the parser's suggestion on every keystroke.
  const userPickedType = useRef(false);

  // Load alert types once
  useEffect(() => {
    fetch('/api/email/templates')
      .then(r => r.json())
      .then(d => {
        const types = d.alert_types || [];
        setAlertTypes(types);
        if (types.length && !selectedType) {
          const suggested = (initialParsed?.suggested_alert_type || '').toLowerCase();
          const pick = types.find(a => a.id === suggested) || types[0];
          setSelectedType(pick?.id || '');
        }
      })
      .catch(() => {});
  }, []); // eslint-disable-line

  // Auto-detect the alert type as the analyst types/pastes — debounced so
  // we don't hammer the backend on every keystroke. The user's explicit
  // dropdown pick is preserved via the userPickedType ref.
  useEffect(() => {
    if (!rawLog.trim() || userPickedType.current) return;
    const timer = setTimeout(async () => {
      try {
        const r = await fetch('/api/email/parse', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ log_text: rawLog }),
        });
        if (!r.ok) return;
        const parsed = await r.json();
        const suggested = parsed?.suggested_alert_type;
        if (suggested && alertTypes.some(t => t.id === suggested)
            && suggested !== selectedType && !userPickedType.current) {
          setSelectedType(suggested);
        }
      } catch (_) {}
    }, 500);
    return () => clearTimeout(timer);
  }, [rawLog, alertTypes]); // eslint-disable-line

  const doCompose = useCallback(async () => {
    if (!rawLog.trim()) { setComposeError('Paste the alert log first'); return; }
    if (!selectedType)  { setComposeError('Pick a template');           return; }
    setComposing(true); setComposeError(null);
    try {
      // Parse first (silent — fields don't surface in the UI)
      const pr = await fetch('/api/email/parse', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ log_text: rawLog }),
      });
      const parsed = pr.ok ? await pr.json() : (initialParsed || {});

      const r = await fetch('/api/email/compose', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          alert_type: selectedType,
          parsed,
          options: { response_action: responseAction },
        }),
      });
      const d = await r.json();
      if (!r.ok) throw new Error(d.detail || `HTTP ${r.status}`);
      setComposed(d);
    } catch (e) {
      setComposeError(e.message);
    } finally {
      setComposing(false);
    }
  }, [rawLog, selectedType, responseAction, initialParsed]);

  // Auto-compose once when a fresh log is handed in from another view
  useEffect(() => {
    if (initialLog && selectedType && !composed && !composing) {
      doCompose();
    }
  }, [initialLog, selectedType]); // eslint-disable-line

  return (
    <Box sx={{
      flex: 1, minWidth: 0, height: '100vh', overflowY: 'auto',
      p: { xs: 2, md: '24px 28px 48px' },
      backgroundColor: 'background.default',
    }}>
      {/* Header */}
      <Stack direction="row" alignItems="center" spacing={1.5} sx={{ mb: 2.5 }}>
        <Mail size={20} color="#0fbcff"/>
        <Box>
          <Typography sx={{ fontSize: 18, fontWeight: 600, color: 'text.primary' }}>
            Email composer
          </Typography>
          <Typography sx={{ fontSize: 11, color: 'text.tertiary' }}>
            Paste alert log → pick template → copy customer-ready email
          </Typography>
        </Box>
        {onClose && (
          <MuiButton onClick={onClose} size="small" variant="text"
            sx={{ ml: 'auto !important', textTransform: 'none', fontSize: 12 }}>
            Close
          </MuiButton>
        )}
      </Stack>

      {/* ─── 1 · Paste ────────────────────────────────────────────────────── */}
      <MuiPaper elevation={0} sx={{
        backgroundColor: '#09253d',
        border: theme => `1px solid ${muiAlpha('#ffffff', 0.12)}`,
        borderRadius: '4px', p: 2, mb: 2,
      }}>
        <SectionHeader title="1 · Raw alert log" badge="paste below"/>
        <MuiTextField
          value={rawLog}
          onChange={e => setRawLog(e.target.value)}
          placeholder="Paste the raw alert log here (key:value pairs work best). Lines like 'RiskLevel: high', 'UserDisplayName: ...', 'IpAddress: ...' are auto-extracted."
          multiline minRows={6} maxRows={20} fullWidth
          InputProps={{ sx: { ...monoSx, fontSize: 12, lineHeight: 1.55 } }}
        />
      </MuiPaper>

      {/* ─── 2 · Template + response action ─────────────────────────────── */}
      <MuiPaper elevation={0} sx={{
        backgroundColor: '#09253d',
        border: theme => `1px solid ${muiAlpha('#ffffff', 0.12)}`,
        borderRadius: '4px', p: 2, mb: 2,
      }}>
        <SectionHeader title="2 · Template & response action"
          badge={`${alertTypes.length} templates · ${RESPONSE_OPTIONS.length - 1} actions`}/>

        <Box sx={{
          display: 'grid', gridTemplateColumns: { xs: '1fr', md: '2fr 1fr' },
          gap: 1.5, mb: 2,
        }}>
          <Box>
            <Typography sx={{ fontSize: 11, color: 'text.tertiary', mb: 0.5,
              textTransform: 'uppercase', letterSpacing: '0.04em' }}>
              Template
            </Typography>
            <MuiTextField
              select fullWidth size="small"
              value={selectedType}
              onChange={e => {
                userPickedType.current = true;
                setSelectedType(e.target.value);
              }}
              SelectProps={{
                MenuProps: { PaperProps: { sx: { maxHeight: 380 } } },
              }}
              InputProps={{ sx: { fontSize: 13 } }}
            >
              {alertTypes.map(t => (
                <MenuItem key={t.id} value={t.id} sx={{ fontSize: 13 }}>
                  {t.label || t.id}
                  {t.category && (
                    <Box component="span" sx={{ ml: 1, fontSize: 10,
                      color: 'text.disabled', textTransform: 'uppercase',
                      letterSpacing: '0.06em' }}>
                      {t.category}
                    </Box>
                  )}
                </MenuItem>
              ))}
            </MuiTextField>
          </Box>

          <Box>
            <Typography sx={{ fontSize: 11, color: 'text.tertiary', mb: 0.5,
              textTransform: 'uppercase', letterSpacing: '0.04em' }}>
              Response action
            </Typography>
            <MuiTextField
              select fullWidth size="small"
              value={responseAction}
              onChange={e => setResponseAction(e.target.value)}
              InputProps={{ sx: { fontSize: 13 } }}
            >
              {RESPONSE_OPTIONS.map(r => (
                <MenuItem key={r.id || 'none'} value={r.id} sx={{ fontSize: 13 }}>
                  {r.label}
                </MenuItem>
              ))}
            </MuiTextField>
          </Box>
        </Box>

        <Stack direction="row" spacing={1} alignItems="center">
          <MuiButton
            variant="contained" size="small"
            disabled={composing || !rawLog.trim() || !selectedType}
            onClick={doCompose}
            startIcon={composing ? <CircularProgress size={12} sx={{ color: 'inherit' }}/> : <RefreshCcw size={14}/>}
            sx={{ textTransform: 'none' }}
          >
            {composing ? 'Composing…' : (composed ? 'Re-compose' : 'Compose email')}
          </MuiButton>
          {composeError && (
            <Stack direction="row" spacing={0.5} alignItems="center" sx={{ color: 'error.main' }}>
              <AlertCircle size={12}/>
              <Typography sx={{ fontSize: 11 }}>{composeError}</Typography>
            </Stack>
          )}
        </Stack>
      </MuiPaper>

      {/* ─── 3 · Preview ──────────────────────────────────────────────────── */}
      {composed && (
        <MuiPaper elevation={0} sx={{
          backgroundColor: '#09253d',
          border: theme => `1px solid ${muiAlpha('#ffffff', 0.12)}`,
          borderRadius: '4px', p: 2, mb: 2,
        }}>
          <SectionHeader title="3 · Preview" badge={composed.template_used}/>

          <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap"
            useFlexGap sx={{ mb: 1.5, rowGap: 1 }}>
            <CopyBtn text={composed.text || ''} label="Copy text"/>
            <CopyBtn text={composed.html || ''} label="Copy HTML"/>
            <ToggleButtonGroup exclusive size="small" value={previewMode}
              onChange={(_, v) => v && setPreviewMode(v)}>
              <ToggleButton value="rendered" sx={{ textTransform: 'none', fontSize: 11, px: 1.25 }}>
                <Eye size={12} style={{ marginRight: 4 }}/> Rendered
              </ToggleButton>
              <ToggleButton value="html" sx={{ textTransform: 'none', fontSize: 11, px: 1.25 }}>
                HTML
              </ToggleButton>
              <ToggleButton value="text" sx={{ textTransform: 'none', fontSize: 11, px: 1.25 }}>
                Plain
              </ToggleButton>
            </ToggleButtonGroup>
          </Stack>

          {previewMode === 'rendered' && (
            <Box sx={{
              backgroundColor: '#ffffff',
              border: `1px solid ${muiAlpha('#ffffff', 0.12)}`,
              borderRadius: '4px',
              minHeight: 280, maxHeight: 720, overflow: 'auto',
              p: '20px 24px',
            }}>
              <Box dangerouslySetInnerHTML={{ __html: composed.html }} sx={{
                color: '#111', fontFamily: 'Arial, Helvetica, sans-serif',
                fontSize: 14, lineHeight: 1.5,
                '& a': { color: '#2563eb' },
              }}/>
            </Box>
          )}
          {previewMode === 'html' && (
            <Box component="pre" sx={{
              ...monoSx, fontSize: 11, color: 'text.primary',
              backgroundColor: '#070d19',
              border: `1px solid ${muiAlpha('#ffffff', 0.08)}`,
              borderRadius: '4px', p: '12px 14px', m: 0,
              whiteSpace: 'pre-wrap', wordBreak: 'break-word',
              maxHeight: 720, overflow: 'auto',
            }}>{composed.html}</Box>
          )}
          {previewMode === 'text' && (
            <Box component="pre" sx={{
              ...monoSx, fontSize: 12, color: 'text.primary',
              backgroundColor: '#070d19',
              border: `1px solid ${muiAlpha('#ffffff', 0.08)}`,
              borderRadius: '4px', p: '12px 14px', m: 0,
              whiteSpace: 'pre-wrap', wordBreak: 'break-word',
              maxHeight: 720, overflow: 'auto',
            }}>{composed.text}</Box>
          )}
        </MuiPaper>
      )}
    </Box>
  );
}
