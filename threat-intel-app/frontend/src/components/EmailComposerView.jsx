/**
 * RECON Email Composer — AI-only flow in the OpenCTI aesthetic.
 *
 *   1. Paste the raw alert log
 *   2. Pick a response action (optional)
 *   3. Preview the AI-generated email with inline Copy buttons
 *
 * All static templates live on the backend at backend/intel/email_templates/
 * and feed the AI as few-shot style examples. The frontend never picks a
 * template — Compose always calls /api/email/compose-ai, which parses the
 * log, generates a tailored body via OpenAI/Azure, and renders it through
 * the same signature pipeline as static composes.
 */
import React, { useState, useEffect, useCallback } from 'react';
import {
  Box, Stack, Typography, Paper as MuiPaper,
  Button as MuiButton, TextField as MuiTextField,
  IconButton as MuiIconButton, CircularProgress, Tooltip,
  ToggleButton, ToggleButtonGroup, MenuItem,
} from '@mui/material';
import { alpha as muiAlpha } from '@mui/material/styles';
import { Mail, Copy, Check, Eye, RefreshCcw, AlertCircle, Sparkles } from 'lucide-react';

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


function CopyBtn({ text, label = 'Copy', size = 'small' }) {
  const [copied, setCopied] = useState(false);
  return (
    <MuiButton
      size={size} variant="outlined"
      onClick={(e) => {
        e.stopPropagation();
        navigator.clipboard.writeText(text || '');
        setCopied(true);
        setTimeout(() => setCopied(false), 1500);
      }}
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


function SectionHeader({ title, badge, accent = '#0fbcff' }) {
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
    </Stack>
  );
}


export default function EmailComposerView({ initialLog = '', initialParsed = null, onClose }) {
  const [rawLog, setRawLog]                 = useState(initialLog);
  const [responseAction, setResponseAction] = useState('');
  const [composed, setComposed]             = useState(null);
  const [composing, setComposing]           = useState(false);
  const [composeError, setComposeError]     = useState(null);
  const [previewMode, setPreviewMode]       = useState('rendered');

  const doCompose = useCallback(async () => {
    if (!rawLog.trim()) { setComposeError('Paste the alert log first'); return; }
    setComposing(true); setComposeError(null);
    try {
      // Parse silently so the AI gets structured fields alongside the raw log
      const pr = await fetch('/api/email/parse', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ log_text: rawLog }),
      });
      const parsed = pr.ok ? await pr.json() : (initialParsed || {});

      const r = await fetch('/api/email/compose-ai', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          log_text: rawLog,
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
  }, [rawLog, responseAction, initialParsed]);

  // Auto-compose once when a fresh log is handed in from another view
  useEffect(() => {
    if (initialLog && !composed && !composing) {
      doCompose();
    }
  }, [initialLog]); // eslint-disable-line

  return (
    <Box sx={{
      flex: 1, minWidth: 0, minHeight: '100vh',
      p: { xs: 2, md: '24px 28px 48px' },
      backgroundColor: 'background.default',
    }}>
      {/* Header */}
      <Stack direction="row" alignItems="center" spacing={1.5} sx={{ mb: 2.5 }}>
        <Mail size={20} color="#0fbcff"/>
        <Typography sx={{ fontSize: 18, fontWeight: 600, color: 'text.primary' }}>
          Email composer
        </Typography>
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
          placeholder="Paste the raw alert log here. The AI parses key:value lines like 'RiskLevel: high', 'UserDisplayName: ...', 'IpAddress: ...' automatically."
          multiline minRows={6} maxRows={20} fullWidth
          InputProps={{ sx: { ...monoSx, fontSize: 12, lineHeight: 1.55 } }}
        />
      </MuiPaper>

      {/* ─── 2 · Response action + compose button ───────────────────────── */}
      <MuiPaper elevation={0} sx={{
        backgroundColor: '#09253d',
        border: theme => `1px solid ${muiAlpha('#ffffff', 0.12)}`,
        borderRadius: '4px', p: 2, mb: 2,
      }}>
        <SectionHeader title="2 · Response action" badge="optional"/>

        <Box sx={{ maxWidth: 360, mb: 2 }}>
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

        <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
          <MuiButton
            variant="contained" size="small"
            disabled={composing || !rawLog.trim()}
            onClick={doCompose}
            startIcon={composing
              ? <CircularProgress size={12} sx={{ color: 'inherit' }}/>
              : (composed ? <RefreshCcw size={14}/> : <Sparkles size={14}/>)}
            sx={{ textTransform: 'none' }}
          >
            {composing ? 'Generating…' : (composed ? 'Re-generate' : 'Generate email')}
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
          <SectionHeader title="3 · Preview"/>

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
