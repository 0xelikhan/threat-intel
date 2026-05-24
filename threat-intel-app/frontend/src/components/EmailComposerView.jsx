/**
 * RECON Email Composer — single scrollable page in the OpenCTI aesthetic.
 *
 * Flow (top → bottom, no tabs):
 *   1. Header (title + classification + action buttons)
 *   2. Input section — raw alert log paste, Parse Log button
 *   3. Extracted fields — three grouped cards (Incident / Threat Intel / Actions)
 *      with every parsed field editable
 *   4. Template chip selector + Compose button
 *   5. Email preview (subject + rendered HTML on white background — only
 *      surface that breaks the dark theme so analysts see how recipients see it)
 *   6. Action buttons — Copy text, Copy HTML, Open mail client, Send via SMTP
 *
 * Every chip / paper / button is wired to theme.palette so it inherits the
 * RECON / OpenCTI dark theme tokens automatically. No ThreatLocker references
 * anywhere — sender details, team name, and signature all come from the
 * EMAIL_* config keys configured in Settings.
 */
import React, { useState, useEffect, useMemo, useCallback } from 'react';
import {
  Box, Stack, Typography, Paper as MuiPaper,
  Button as MuiButton, Chip as MuiChip, TextField as MuiTextField,
  IconButton as MuiIconButton, CircularProgress, Tooltip,
  ToggleButton, ToggleButtonGroup, Divider,
} from '@mui/material';
import { alpha as muiAlpha } from '@mui/material/styles';
import {
  Mail, Send, Copy, Check, FileText, Eye, RefreshCcw,
  ExternalLink, AlertCircle, ChevronRight, Save, Archive,
} from 'lucide-react';

const monoSx = { fontFamily: '"IBM Plex Mono", monospace' };

// Field groupings — every parsed field surfaces under one of these headings.
// Keys not listed fall through to "More fields" which renders the remaining
// payload as a flat grid so nothing the parser found is hidden.
const FIELD_GROUPS = [
  {
    id: 'incident', label: 'Incident details',
    fields: [
      ['organization_name', 'Organization name'],
      ['hostname',          'Hostname / asset'],
      ['asset_name',        'Asset name'],
      ['user_display_name', 'User display name'],
      ['user_principal_name','User principal name'],
      ['user_domain',       'User domain'],
      ['detected_dt_raw',   'Detected (UTC)'],
      ['activity_dt_raw',   'Activity timestamp'],
      ['detection_timing',  'Detection timing'],
      ['activity',          'Activity / event'],
    ],
  },
  {
    id: 'intel', label: 'Threat intelligence',
    fields: [
      ['ip_address',        'IP address'],
      ['ip_address_2',      'Secondary IP'],
      ['location',          'Location'],
      ['location_2',        'Secondary location'],
      ['risk_level',        'Risk level'],
      ['risk_state',        'Risk state'],
      ['risk_detail',       'Risk detail'],
      ['threat_name',       'Threat name'],
      ['threat_id',         'Threat ID'],
      ['ep_application_name','Application'],
      ['ep_certificate',    'Certificate / publisher'],
      ['ep_cmd_line',       'Command line'],
      ['ep_created_by_process','Created by process'],
      ['client_app_used',   'Client app'],
      ['correlation_id',    'Correlation ID'],
      ['request_id',        'Request ID'],
    ],
  },
  {
    id: 'actions', label: 'Actions & remediation',
    fields: [
      ['action_taken',           'Action taken (free text)'],
      ['response_actions',       'Response actions'],
      ['maintenance_mode',       'Maintenance mode'],
      ['privileged_role_name',   'Privileged role'],
      ['target_user_display_name','Target user'],
      ['target_user_principal_name','Target UPN'],
      ['localgroup_command',     'Local group command'],
    ],
  },
];

const RESPONSE_OPTIONS = [
  { id: '', label: 'None' },
  { id: 'clearing',    label: 'Clearing alert' },
  { id: 'escalating',  label: 'Escalating' },
  { id: 'isolating',   label: 'Isolating endpoint' },
  { id: 'lockdown',    label: 'Lockdown' },
  { id: 'lock_account',label: 'Lock account' },
];


function CopyBtn({ text, label = 'Copy', size = 'small', variant = 'icon' }) {
  const [copied, setCopied] = useState(false);
  const doCopy = (e) => {
    e?.stopPropagation();
    navigator.clipboard.writeText(text || '');
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };
  if (variant === 'button') {
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
  return (
    <Tooltip title={copied ? 'Copied' : label}>
      <MuiIconButton size={size} onClick={doCopy}
        sx={{ p: 0.5, color: copied ? 'success.main' : 'text.tertiary' }}>
        {copied ? <Check size={14}/> : <Copy size={14}/>}
      </MuiIconButton>
    </Tooltip>
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


function FieldGrid({ fields, values, onChange }) {
  return (
    <Box sx={{
      display: 'grid', gridTemplateColumns: { xs: '1fr', sm: '1fr 1fr' },
      gap: 1.25,
    }}>
      {fields.map(([key, label]) => (
        <Box key={key}>
          <Typography sx={{ fontSize: 11, color: 'text.tertiary', mb: 0.375,
            textTransform: 'uppercase', letterSpacing: '0.04em' }}>
            {label}
          </Typography>
          <MuiTextField
            value={values[key] ?? ''}
            onChange={(e) => onChange(key, e.target.value)}
            size="small" fullWidth
            placeholder="—"
            InputProps={{ sx: { ...monoSx, fontSize: 12 } }}
          />
        </Box>
      ))}
    </Box>
  );
}


export default function EmailComposerView({ initialLog = '', initialParsed = null, onClose }) {
  const [rawLog, setRawLog] = useState(initialLog);
  const [parsed, setParsed] = useState(initialParsed || {});
  const [parsing, setParsing] = useState(false);
  const [parseError, setParseError] = useState(null);

  const [alertTypes, setAlertTypes] = useState([]);
  const [selectedType, setSelectedType] = useState(null);
  const [responseAction, setResponseAction] = useState('');
  const [orgName, setOrgName] = useState('');
  const [includeRunbook, setIncludeRunbook] = useState(false);
  const [exclusionAdded, setExclusionAdded] = useState(false);

  const [composed, setComposed] = useState(null);
  const [composing, setComposing] = useState(false);
  const [composeError, setComposeError] = useState(null);

  const [toAddress, setToAddress] = useState('');
  const [ccAddress, setCcAddress] = useState('');
  const [sendStatus, setSendStatus] = useState(null);

  const [previewMode, setPreviewMode] = useState('rendered'); // 'rendered' | 'html' | 'text'

  // Load the list of available alert types on mount
  useEffect(() => {
    fetch('/api/email/templates')
      .then(r => r.json())
      .then(d => {
        setAlertTypes(d.alert_types || []);
        if (!selectedType && (d.alert_types || []).length) {
          // Pre-select based on initialParsed.suggested_alert_type if present,
          // otherwise default to "generic" or first entry.
          const suggested = (initialParsed?.suggested_alert_type || '').toLowerCase();
          const pick = d.alert_types.find(a => a.id === suggested)
            || d.alert_types.find(a => a.id === 'generic')
            || d.alert_types[0];
          setSelectedType(pick?.id || null);
        }
      })
      .catch(() => {});
  }, []); // eslint-disable-line

  // If we were handed an initial log, auto-parse it once
  useEffect(() => {
    if (initialLog && !Object.keys(parsed).length) {
      doParse(initialLog);
    }
  }, []); // eslint-disable-line

  const doParse = useCallback(async (text) => {
    const logText = (text ?? rawLog).trim();
    if (!logText) { setParseError('Paste a log first'); return; }
    setParsing(true); setParseError(null);
    try {
      const r = await fetch('/api/email/parse', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ log_text: logText }),
      });
      const d = await r.json();
      if (!r.ok) throw new Error(d.detail || `HTTP ${r.status}`);
      setParsed(d);
      // Auto-pick alert type from suggestion if backend included one
      if (d.suggested_alert_type) {
        const match = alertTypes.find(a => a.id === d.suggested_alert_type);
        if (match) setSelectedType(match.id);
      }
    } catch (e) { setParseError(e.message); }
    finally { setParsing(false); }
  }, [rawLog, alertTypes]);

  const updateField = useCallback((key, value) => {
    setParsed(p => ({ ...p, [key]: value }));
  }, []);

  const doCompose = useCallback(async () => {
    if (!selectedType) { setComposeError('Pick an alert type first'); return; }
    setComposing(true); setComposeError(null);
    try {
      const body = {
        alert_type: selectedType,
        parsed: { ...parsed, organization_name: orgName || parsed.organization_name },
        options: {
          response_action: responseAction,
          include_runbook: includeRunbook,
          exclusion_added: exclusionAdded,
        },
      };
      const r = await fetch('/api/email/compose', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      const d = await r.json();
      if (!r.ok) throw new Error(d.detail || `HTTP ${r.status}`);
      setComposed(d);
    } catch (e) { setComposeError(e.message); }
    finally { setComposing(false); }
  }, [selectedType, parsed, orgName, responseAction, includeRunbook, exclusionAdded]);

  const doSend = useCallback(async () => {
    if (!composed) return;
    if (!toAddress.trim()) { setSendStatus({ state: 'err', msg: 'Recipient required' }); return; }
    setSendStatus({ state: 'sending' });
    try {
      const r = await fetch('/api/email/send', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          subject: composed.subject, body_text: composed.text, body_html: composed.html,
          to: toAddress, cc: ccAddress,
        }),
      });
      const d = await r.json();
      if (!r.ok) throw new Error(d.detail || d.error || `HTTP ${r.status}`);
      if (d.sent === false && d.error) {
        setSendStatus({ state: 'err', msg: d.error });
      } else {
        setSendStatus({ state: 'ok', msg: 'Sent' });
      }
    } catch (e) { setSendStatus({ state: 'err', msg: e.message }); }
  }, [composed, toAddress, ccAddress]);

  const openMailClient = () => {
    if (!composed) return;
    const url = `mailto:${encodeURIComponent(toAddress || '')}`
      + `?subject=${encodeURIComponent(composed.subject || '')}`
      + (ccAddress ? `&cc=${encodeURIComponent(ccAddress)}` : '')
      + `&body=${encodeURIComponent(composed.text || '')}`;
    window.location.href = url;
  };

  const doSaveDraft = useCallback(async () => {
    if (!composed) return;
    setSendStatus({ state: 'sending', msg: 'Saving…' });
    try {
      const r = await fetch('/api/email/drafts', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          alert_type: selectedType,
          subject: composed.subject,
          text:    composed.text,
          html:    composed.html,
          to:      toAddress,
          cc:      ccAddress,
          parsed,
          options: { response_action: responseAction, include_runbook: includeRunbook,
                     exclusion_added: exclusionAdded, organization_name: orgName },
        }),
      });
      const d = await r.json();
      if (!r.ok) throw new Error(d.detail || `HTTP ${r.status}`);
      setSendStatus({ state: 'ok', msg: 'Draft saved' });
    } catch (e) { setSendStatus({ state: 'err', msg: e.message }); }
  }, [composed, selectedType, toAddress, ccAddress, parsed, responseAction,
      includeRunbook, exclusionAdded, orgName]);

  const moreFieldKeys = useMemo(() => {
    const known = new Set(FIELD_GROUPS.flatMap(g => g.fields.map(([k]) => k)));
    return Object.keys(parsed)
      .filter(k => !known.has(k) && parsed[k] != null && parsed[k] !== '')
      .sort();
  }, [parsed]);

  const parsedFieldCount = Object.values(parsed).filter(v => v != null && v !== '').length;

  return (
    <Box sx={{
      flex: 1, minWidth: 0, height: '100vh', overflowY: 'auto',
      p: { xs: 2, md: '24px 28px 48px' },
      backgroundColor: 'background.default',
    }}>
      {/* ─── Header ───────────────────────────────────────────────────────── */}
      <Stack direction="row" alignItems="center" spacing={1.5} sx={{ mb: 2.5 }}>
        <Mail size={20} color="#0fbcff"/>
        <Box>
          <Typography sx={{ fontSize: 18, fontWeight: 600, color: 'text.primary' }}>
            Email composer
          </Typography>
          <Typography sx={{ fontSize: 11, color: 'text.tertiary' }}>
            Paste alert log → extract fields → render notification → send or copy
          </Typography>
        </Box>
        {onClose && (
          <MuiButton onClick={onClose} size="small" variant="text"
            sx={{ ml: 'auto !important', textTransform: 'none', fontSize: 12 }}>
            Close
          </MuiButton>
        )}
      </Stack>

      {/* ─── 1. Input section ────────────────────────────────────────────── */}
      <MuiPaper elevation={0} sx={{
        backgroundColor: '#09253d',
        border: theme => `1px solid ${muiAlpha('#ffffff', 0.12)}`,
        borderRadius: '4px', p: 2, mb: 2,
      }}>
        <SectionHeader title="1 · Raw alert log" badge={parsedFieldCount
          ? `${parsedFieldCount} fields extracted` : 'paste below'}/>
        <MuiTextField
          value={rawLog}
          onChange={e => setRawLog(e.target.value)}
          placeholder="Paste the raw alert log here (key:value pairs work best). Lines like 'RiskLevel: high', 'UserDisplayName: ...', 'IpAddress: ...' are auto-extracted."
          multiline minRows={6} maxRows={20} fullWidth
          InputProps={{ sx: { ...monoSx, fontSize: 12, lineHeight: 1.55 } }}
          sx={{ mb: 1.5 }}
        />
        <Stack direction="row" spacing={1} alignItems="center">
          <MuiButton
            variant="contained" size="small"
            disabled={parsing || !rawLog.trim()}
            onClick={() => doParse()}
            startIcon={parsing ? <CircularProgress size={12}/> : <FileText size={14}/>}
            sx={{ textTransform: 'none' }}
          >
            {parsing ? 'Parsing…' : 'Parse log'}
          </MuiButton>
          {parseError && (
            <Stack direction="row" spacing={0.5} alignItems="center" sx={{ color: 'error.main' }}>
              <AlertCircle size={12}/>
              <Typography sx={{ fontSize: 11 }}>{parseError}</Typography>
            </Stack>
          )}
        </Stack>
      </MuiPaper>

      {/* ─── 2. Extracted / editable fields ──────────────────────────────── */}
      <MuiPaper elevation={0} sx={{
        backgroundColor: '#09253d',
        border: theme => `1px solid ${muiAlpha('#ffffff', 0.12)}`,
        borderRadius: '4px', p: 2, mb: 2,
      }}>
        <SectionHeader title="2 · Extracted fields"
          badge="all values editable"
          right={parsedFieldCount > 0 && (
            <Typography sx={{ fontSize: 11, color: 'text.tertiary' }}>
              {parsedFieldCount} populated
            </Typography>
          )}/>

        {/* Organization-level inputs */}
        <Box sx={{
          display: 'grid', gridTemplateColumns: { xs: '1fr', sm: '2fr 1fr 1fr' },
          gap: 1.25, mb: 2,
        }}>
          <Box>
            <Typography sx={{ fontSize: 11, color: 'text.tertiary', mb: 0.375,
              textTransform: 'uppercase', letterSpacing: '0.04em' }}>
              Organization name
            </Typography>
            <MuiTextField size="small" fullWidth
              value={orgName} onChange={e => setOrgName(e.target.value)}
              placeholder="Acme Corp" InputProps={{ sx: { ...monoSx, fontSize: 12 } }}/>
          </Box>
          <Box>
            <Typography sx={{ fontSize: 11, color: 'text.tertiary', mb: 0.375,
              textTransform: 'uppercase', letterSpacing: '0.04em' }}>
              Include runbook
            </Typography>
            <ToggleButtonGroup exclusive size="small" value={includeRunbook ? 'yes' : 'no'}
              onChange={(_, v) => v && setIncludeRunbook(v === 'yes')}>
              <ToggleButton value="no" sx={{ textTransform: 'none', fontSize: 12 }}>No</ToggleButton>
              <ToggleButton value="yes" sx={{ textTransform: 'none', fontSize: 12 }}>Yes</ToggleButton>
            </ToggleButtonGroup>
          </Box>
          <Box>
            <Typography sx={{ fontSize: 11, color: 'text.tertiary', mb: 0.375,
              textTransform: 'uppercase', letterSpacing: '0.04em' }}>
              Exclusion added
            </Typography>
            <ToggleButtonGroup exclusive size="small" value={exclusionAdded ? 'yes' : 'no'}
              onChange={(_, v) => v && setExclusionAdded(v === 'yes')}>
              <ToggleButton value="no" sx={{ textTransform: 'none', fontSize: 12 }}>No</ToggleButton>
              <ToggleButton value="yes" sx={{ textTransform: 'none', fontSize: 12 }}>Yes</ToggleButton>
            </ToggleButtonGroup>
          </Box>
        </Box>

        {FIELD_GROUPS.map((g, idx) => (
          <Box key={g.id} sx={{ mb: idx === FIELD_GROUPS.length - 1 && !moreFieldKeys.length ? 0 : 2 }}>
            <Typography sx={{ fontSize: 11, color: 'text.tertiary', fontWeight: 600,
              textTransform: 'uppercase', letterSpacing: '0.06em', mb: 1 }}>
              {g.label}
            </Typography>
            <FieldGrid fields={g.fields} values={parsed} onChange={updateField}/>
            {idx < FIELD_GROUPS.length - 1 && (
              <Divider sx={{ mt: 2, borderColor: muiAlpha('#ffffff', 0.06) }}/>
            )}
          </Box>
        ))}

        {moreFieldKeys.length > 0 && (
          <>
            <Divider sx={{ my: 2, borderColor: muiAlpha('#ffffff', 0.06) }}/>
            <Typography sx={{ fontSize: 11, color: 'text.tertiary', fontWeight: 600,
              textTransform: 'uppercase', letterSpacing: '0.06em', mb: 1 }}>
              More fields ({moreFieldKeys.length})
            </Typography>
            <FieldGrid
              fields={moreFieldKeys.map(k => [k, k.replace(/_/g, ' ')])}
              values={parsed} onChange={updateField}/>
          </>
        )}
      </MuiPaper>

      {/* ─── 3. Template + response action ───────────────────────────────── */}
      <MuiPaper elevation={0} sx={{
        backgroundColor: '#09253d',
        border: theme => `1px solid ${muiAlpha('#ffffff', 0.12)}`,
        borderRadius: '4px', p: 2, mb: 2,
      }}>
        <SectionHeader title="3 · Template" badge={`${alertTypes.length} alert types`}/>

        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.75, mb: 2 }}>
          {alertTypes.map(t => {
            const active = selectedType === t.id;
            return (
              <MuiChip
                key={t.id}
                label={t.label || t.id}
                onClick={() => setSelectedType(t.id)}
                size="small"
                sx={{
                  fontSize: 11, height: 26, cursor: 'pointer',
                  backgroundColor: active ? muiAlpha('#0fbcff', 0.18) : muiAlpha('#ffffff', 0.04),
                  border: `1px solid ${active ? '#0fbcff' : muiAlpha('#ffffff', 0.12)}`,
                  color: active ? '#0fbcff' : 'text.primary',
                  fontWeight: active ? 600 : 400,
                  '&:hover': {
                    backgroundColor: active ? muiAlpha('#0fbcff', 0.22) : muiAlpha('#0fbcff', 0.08),
                  },
                }}
              />
            );
          })}
        </Box>

        <Typography sx={{ fontSize: 11, color: 'text.tertiary', mb: 0.75,
          textTransform: 'uppercase', letterSpacing: '0.04em' }}>
          Response action
        </Typography>
        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.75, mb: 2 }}>
          {RESPONSE_OPTIONS.map(r => {
            const active = responseAction === r.id;
            return (
              <MuiChip
                key={r.id || 'none'}
                label={r.label}
                onClick={() => setResponseAction(r.id)}
                size="small"
                sx={{
                  fontSize: 11, height: 26, cursor: 'pointer',
                  backgroundColor: active ? muiAlpha('#16AD34', 0.15) : muiAlpha('#ffffff', 0.04),
                  border: `1px solid ${active ? '#16AD34' : muiAlpha('#ffffff', 0.12)}`,
                  color: active ? 'success.main' : 'text.primary',
                  fontWeight: active ? 600 : 400,
                }}
              />
            );
          })}
        </Box>

        <Stack direction="row" spacing={1} alignItems="center">
          <MuiButton
            variant="contained" size="small"
            disabled={composing || !selectedType}
            onClick={doCompose}
            startIcon={composing ? <CircularProgress size={12}/> : <RefreshCcw size={14}/>}
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

      {/* ─── 4. Preview ───────────────────────────────────────────────────── */}
      {composed && (
        <MuiPaper elevation={0} sx={{
          backgroundColor: '#09253d',
          border: theme => `1px solid ${muiAlpha('#ffffff', 0.12)}`,
          borderRadius: '4px', p: 2, mb: 2,
        }}>
          <SectionHeader title="4 · Preview"
            badge={composed.template_used}
            right={
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
            }/>

          {/* Subject line */}
          <Box sx={{
            display: 'flex', alignItems: 'center', gap: 1,
            backgroundColor: muiAlpha('#ffffff', 0.03),
            border: `1px solid ${muiAlpha('#ffffff', 0.08)}`,
            borderRadius: '4px', p: '8px 12px', mb: 1.5,
          }}>
            <Typography sx={{ fontSize: 10, color: 'text.tertiary',
              textTransform: 'uppercase', letterSpacing: '0.06em' }}>Subject</Typography>
            <Typography sx={{ ...monoSx, fontSize: 12, color: 'text.primary', flex: 1 }}>
              {composed.subject}
            </Typography>
            <CopyBtn text={composed.subject} label="Copy subject"/>
          </Box>

          {/* Body — rendered on white, raw on dark */}
          {previewMode === 'rendered' && (
            <Box sx={{
              backgroundColor: '#ffffff',
              border: `1px solid ${muiAlpha('#ffffff', 0.12)}`,
              borderRadius: '4px',
              minHeight: 280, maxHeight: 600, overflow: 'auto',
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
              maxHeight: 600, overflow: 'auto',
            }}>{composed.html}</Box>
          )}
          {previewMode === 'text' && (
            <Box component="pre" sx={{
              ...monoSx, fontSize: 12, color: 'text.primary',
              backgroundColor: '#070d19',
              border: `1px solid ${muiAlpha('#ffffff', 0.08)}`,
              borderRadius: '4px', p: '12px 14px', m: 0,
              whiteSpace: 'pre-wrap', wordBreak: 'break-word',
              maxHeight: 600, overflow: 'auto',
            }}>{composed.text}</Box>
          )}
        </MuiPaper>
      )}

      {/* ─── 5. Recipients + send ─────────────────────────────────────────── */}
      {composed && (
        <MuiPaper elevation={0} sx={{
          backgroundColor: '#09253d',
          border: theme => `1px solid ${muiAlpha('#ffffff', 0.12)}`,
          borderRadius: '4px', p: 2, mb: 2,
        }}>
          <SectionHeader title="5 · Send" badge="copy, mail client, or SMTP"/>
          <Box sx={{
            display: 'grid', gridTemplateColumns: { xs: '1fr', sm: '1fr 1fr' },
            gap: 1.25, mb: 2,
          }}>
            <Box>
              <Typography sx={{ fontSize: 11, color: 'text.tertiary', mb: 0.375,
                textTransform: 'uppercase', letterSpacing: '0.04em' }}>To</Typography>
              <MuiTextField size="small" fullWidth value={toAddress}
                onChange={e => setToAddress(e.target.value)}
                placeholder="customer@example.com"
                InputProps={{ sx: { ...monoSx, fontSize: 12 } }}/>
            </Box>
            <Box>
              <Typography sx={{ fontSize: 11, color: 'text.tertiary', mb: 0.375,
                textTransform: 'uppercase', letterSpacing: '0.04em' }}>Cc</Typography>
              <MuiTextField size="small" fullWidth value={ccAddress}
                onChange={e => setCcAddress(e.target.value)}
                placeholder="(optional)"
                InputProps={{ sx: { ...monoSx, fontSize: 12 } }}/>
            </Box>
          </Box>

          <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
            <CopyBtn text={composed.text || ''} label="Copy plain text" variant="button"/>
            <CopyBtn text={composed.html || ''} label="Copy HTML"        variant="button"/>
            <MuiButton size="small" variant="outlined" onClick={openMailClient}
              startIcon={<ExternalLink size={14}/>}
              sx={{ textTransform: 'none', fontSize: 12 }}>
              Open mail client
            </MuiButton>
            <MuiButton size="small" variant="outlined" onClick={doSaveDraft}
              startIcon={<Save size={14}/>}
              sx={{ textTransform: 'none', fontSize: 12 }}>
              Save draft
            </MuiButton>
            <MuiButton size="small" variant="contained" onClick={doSend}
              disabled={sendStatus?.state === 'sending'}
              startIcon={sendStatus?.state === 'sending'
                ? <CircularProgress size={12} sx={{ color: 'inherit' }}/>
                : <Send size={14}/>}
              sx={{ textTransform: 'none', fontSize: 12 }}>
              Send via SMTP
            </MuiButton>
            {sendStatus && (
              <Stack direction="row" spacing={0.5} alignItems="center" sx={{
                color: sendStatus.state === 'ok' ? 'success.main'
                  : sendStatus.state === 'err' ? 'error.main' : 'text.tertiary',
                ml: 1,
              }}>
                {sendStatus.state === 'ok' && <Check size={14}/>}
                {sendStatus.state === 'err' && <AlertCircle size={14}/>}
                <Typography sx={{ fontSize: 11 }}>
                  {sendStatus.state === 'sending' ? 'Sending…' : sendStatus.msg}
                </Typography>
              </Stack>
            )}
          </Stack>
        </MuiPaper>
      )}
    </Box>
  );
}
