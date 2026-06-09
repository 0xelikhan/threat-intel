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
import React, { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import {
  Box, Stack, Typography, Paper as MuiPaper,
  Button as MuiButton, TextField as MuiTextField,
  CircularProgress,
  ToggleButton, ToggleButtonGroup, MenuItem, Chip as MuiChip,
} from '@mui/material';
import { alpha as muiAlpha } from '@mui/material/styles';
import { Mail, Copy, Check, Eye, RefreshCcw, AlertCircle, Sparkles, Zap, Wand2, ChevronRight } from 'lucide-react';

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

// ─── Custom email templates (spec §8) ───────────────────────────────────────
// Templates control which email body fields are included when the AI builds
// the message. Disabled fields are completely excluded from the rendered
// body AND from the AI prompt — the model never sees them, so it can't
// hallucinate content for fields the analyst chose to suppress.
//
// Built-in templates ("All Details", "Minimal") cannot be deleted; the
// analyst can save additional named templates (stored in localStorage
// under `recon.email_templates`).
const TEMPLATE_FIELDS = [
  { id: 'alert_summary',       label: 'Alert summary' },
  { id: 'severity',            label: 'Severity' },
  { id: 'malware_name',        label: 'Malware / threat name' },
  { id: 'affected_host',       label: 'Affected host' },
  { id: 'username',            label: 'Username' },
  { id: 'source_ip',           label: 'Source IP' },
  { id: 'destination_ip',      label: 'Destination IP' },
  { id: 'file_path',           label: 'File path / artifact' },
  { id: 'process_name',        label: 'Process name' },
  { id: 'process_path',        label: 'Process path' },
  { id: 'action_taken',        label: 'Action taken' },
  { id: 'detection_source',    label: 'Detection source' },
  { id: 'timeline',            label: 'Timeline' },
  { id: 'mitre_techniques',    label: 'MITRE techniques' },
  { id: 'enrichment_summary',  label: 'Enrichment summary' },
  { id: 'recommended_actions', label: 'Recommended actions' },
  { id: 'technical_details',   label: 'Technical details' },
];
const ALL_FIELD_IDS     = TEMPLATE_FIELDS.map(f => f.id);
const MINIMAL_FIELD_IDS = [
  'alert_summary', 'severity', 'malware_name', 'affected_host', 'recommended_actions',
];

// The per-field TEMPLATE_FIELD_TO_KEYS map and availableTemplateFields()
// helper used to power a per-field checkbox grid; replaced by the
// category-toggle UI (CATEGORY_ORDER + the backend's _categorized
// breakdown). The backend's intel/email_composer.TEMPLATE_FIELD_TO_KEYS
// stays as the canonical mapping consumed by enabled_categories
// filtering on compose.

const BUILT_IN_TEMPLATES = [
  {
    id: '__all_details',
    name: 'All Details',
    description: 'Every email field included — full triage hand-off.',
    enabled_fields: ALL_FIELD_IDS,
    builtIn: true,
  },
  {
    id: '__minimal',
    name: 'Minimal',
    description: 'Alert summary, severity, malware name, affected host, and recommended actions.',
    enabled_fields: MINIMAL_FIELD_IDS,
    builtIn: true,
  },
];

const TEMPLATES_KEY = 'recon.email_templates';
const SELECTED_TEMPLATE_KEY = 'recon.email_templates.selected';

function loadStoredTemplates() {
  try {
    const raw = localStorage.getItem(TEMPLATES_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(t => t && t.id && t.name && Array.isArray(t.enabled_fields));
  } catch { return []; }
}
function saveStoredTemplates(arr) {
  try { localStorage.setItem(TEMPLATES_KEY, JSON.stringify(arr || [])); } catch {}
}

// Display order for the dynamic category toggles. Categories not present
// in the parsed log are filtered out before rendering.
const CATEGORY_ORDER = [
  'Identity', 'Network', 'Process', 'File',
  'Detection', 'Time', 'Action', 'Other',
];
// Persistence key for the analyst's last category-toggle choices so the
// UI doesn't reset every paste.
const CATS_KEY = 'recon.email_enabled_categories';


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


// SectionHeader removed — replaced by PanelCard's built-in collapsible
// header. Kept as a comment marker so the diff history reads cleanly.

// AI remediation section labels — module scope so callers can pass it to
// useCallback / useEffect deps arrays without a stale-reference warning.
const REM_SECTIONS = [
  { key: 'executive_summary',    label: 'Executive summary' },
  { key: 'immediate_actions',    label: 'Immediate actions (next 15 minutes)' },
  { key: 'investigation_steps',  label: 'Investigation steps' },
  { key: 'containment_guidance', label: 'Containment' },
  { key: 'recovery_guidance',    label: 'Recovery' },
  { key: 'detection_guidance',   label: 'Detection hardening' },
];


/* PanelCard — chevron-toggled collapsible wrapper. Mirrors the file
   analyzer's SectionCard pattern: header click toggles open/closed,
   chevron rotates 90° when expanded, optional right-aligned summary
   indicator next to the title. State is local per card.            */
function PanelCard({ title, accent = '#0fbcff', badge, summary,
                     defaultOpen = false, children }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <MuiPaper elevation={0} sx={{
      backgroundColor: '#09253d',
      border: theme => `1px solid ${muiAlpha('#ffffff', 0.12)}`,
      borderRadius: '4px', mb: 2,
    }}>
      <Box
        onClick={() => setOpen(o => !o)}
        sx={{
          display: 'flex', alignItems: 'center', gap: 1,
          cursor: 'pointer', userSelect: 'none',
          p: '12px 16px',
          borderBottom: open ? `1px solid ${muiAlpha('#ffffff', 0.08)}` : 'none',
        }}>
        <Box sx={{
          color: accent,
          transform: open ? 'rotate(90deg)' : 'rotate(0deg)',
          transition: 'transform 0.18s ease',
          display: 'flex', alignItems: 'center',
        }}>
          <ChevronRight size={14}/>
        </Box>
        <Box sx={{ width: 3, height: 14, backgroundColor: accent, borderRadius: 0.5 }}/>
        <Typography sx={{ fontSize: 12, fontWeight: 600, color: 'text.primary',
          textTransform: 'uppercase', letterSpacing: '0.06em' }}>
          {title}
        </Typography>
        {badge && (
          <Typography sx={{ fontSize: 11, color: 'text.tertiary' }}>· {badge}</Typography>
        )}
        {summary && (
          <Typography sx={{ ml: 'auto !important', fontSize: 11,
            color: 'text.tertiary', textTransform: 'none' }}>
            {summary}
          </Typography>
        )}
      </Box>
      {open && (
        <Box sx={{ p: 2 }}>
          {children}
        </Box>
      )}
    </MuiPaper>
  );
}


export default function EmailComposerView({ initialLog = '', initialParsed = null, onClose }) {
  const [rawLog, setRawLog]                 = useState(initialLog);
  const [responseAction, setResponseAction] = useState('');
  const [composed, setComposed]             = useState(null);
  const [composing, setComposing]           = useState(false);
  const [composeError, setComposeError]     = useState(null);
  const [previewMode, setPreviewMode]       = useState('rendered');
  // Auto-classification — populated as the analyst pastes. The detected
  // alert type drives template selection in /api/email/compose-ai; the
  // Response Action dropdown is intentionally manual (analyst picks what
  // actually happened, not what the AI guesses).
  const [detected, setDetected]             = useState(null);   // {alert_type, alert_label}
  const parseTimer                          = useRef(null);
  // Parsed fields stash — populated by the debounced auto-classify. Kept in
  // state so compose can send the structured fields alongside the raw log,
  // and so the AI Remediation panel can render the structured guidance the
  // analyst sees the email being built from.
  const [parsedFields, setParsedFields] = useState(initialParsed || {});

  // AI Remediation panel — DISPLAY-ONLY view of the structured guidance the
  // compose_ai prompt weaves into the email body. The panel lets analysts
  // verify where the recommendations are coming from without parsing the
  // rendered email. The email itself still gets the remediation woven in
  // automatically by the backend prompt — the panel doesn't change the body.
  const [remediation, setRemediation] = useState(null);
  const [remLoading, setRemLoading]   = useState(false);
  const [remError, setRemError]       = useState(null);

  // ─── Custom email templates state (spec §8) ──────────────────────────────
  // Templates are stored in localStorage so they persist across sessions and
  // are available to every analyst using this browser. Built-in templates
  // (All Details, Minimal) are merged in at load time and cannot be deleted.
  const [customTemplates, setCustomTemplates] = useState(() => loadStoredTemplates());
  // useMemo: keeps the array reference stable across renders so the
  // deleteTemplate useCallback's deps array doesn't see a new identity
  // every paint.
  const allTemplates = useMemo(
    () => [...BUILT_IN_TEMPLATES, ...customTemplates],
    [customTemplates],
  );
  const [selectedTemplateId, setSelectedTemplateId] = useState(() => {
    try { return localStorage.getItem(SELECTED_TEMPLATE_KEY) || '__all_details'; }
    catch { return '__all_details'; }
  });
  const selectedTemplate = allTemplates.find(t => t.id === selectedTemplateId)
                            || BUILT_IN_TEMPLATES[0];
  const [enabledFields, setEnabledFields] = useState(() => selectedTemplate.enabled_fields);
  const [templateMode, setTemplateMode] = useState('idle'); // 'idle' | 'create' | 'edit'
  const [draftName, setDraftName] = useState('');
  const [draftDescription, setDraftDescription] = useState('');
  // Dynamic category toggles — replaces the old fixed 17-field grid.
  // Categories present in the parsed log become checkboxes; the analyst
  // turns whole groups on/off. Defaults to "everything on" so a fresh
  // paste produces the full email, and the analyst trims down from there.
  const [enabledCategories, setEnabledCategories] = useState(() => {
    try {
      const raw = localStorage.getItem(CATS_KEY);
      const arr = raw ? JSON.parse(raw) : null;
      if (Array.isArray(arr) && arr.length) return arr;
    } catch {}
    return [...CATEGORY_ORDER];
  });
  // Categories start COLLAPSED by default — analyst expands the ones
  // they want to inspect. Mirrors the file-analyzer card pattern.
  const [expandedCategories, setExpandedCategories] = useState([]);
  const toggleExpanded = useCallback((cat) => {
    setExpandedCategories(curr => curr.includes(cat)
      ? curr.filter(c => c !== cat)
      : [...curr, cat]);
  }, []);
  // Within an expanded category, we cap the visible fields at 12 to keep
  // huge categories scannable. Clicking the "+ N more" line opts that
  // category in to a full render. Tracked separately so collapsing /
  // re-expanding doesn't reset the show-all choice.
  const [showAllCategories, setShowAllCategories] = useState([]);
  const toggleShowAll = useCallback((cat) => {
    setShowAllCategories(curr => curr.includes(cat)
      ? curr.filter(c => c !== cat)
      : [...curr, cat]);
  }, []);

  // Sync enabled_fields whenever the selected template changes.
  useEffect(() => {
    setEnabledFields(selectedTemplate.enabled_fields);
    try { localStorage.setItem(SELECTED_TEMPLATE_KEY, selectedTemplateId); } catch {}
  }, [selectedTemplateId]); // eslint-disable-line

  const toggleCategory = useCallback((cat) => {
    setEnabledCategories(curr => {
      const next = curr.includes(cat)
        ? curr.filter(c => c !== cat)
        : [...curr, cat];
      try { localStorage.setItem(CATS_KEY, JSON.stringify(next)); } catch {}
      return next;
    });
  }, []);

  const saveAsTemplate = useCallback(() => {
    const name = (draftName || '').trim();
    if (!name) return;
    const editing = templateMode === 'edit';
    const baseId = editing ? selectedTemplateId : `custom_${Date.now()}`;
    const next = {
      id: baseId,
      name,
      description: (draftDescription || '').trim(),
      enabled_fields: [...enabledFields],
      builtIn: false,
    };
    let updated;
    if (editing) {
      updated = customTemplates.map(t => t.id === baseId ? next : t);
    } else {
      updated = [...customTemplates, next];
    }
    setCustomTemplates(updated);
    saveStoredTemplates(updated);
    setSelectedTemplateId(baseId);
    setTemplateMode('idle');
    setDraftName(''); setDraftDescription('');
  }, [draftName, draftDescription, enabledFields, templateMode,
      customTemplates, selectedTemplateId]);

  const deleteTemplate = useCallback((tid) => {
    const tpl = allTemplates.find(t => t.id === tid);
    if (!tpl || tpl.builtIn) return;
    const updated = customTemplates.filter(t => t.id !== tid);
    setCustomTemplates(updated);
    saveStoredTemplates(updated);
    if (selectedTemplateId === tid) setSelectedTemplateId('__all_details');
  }, [customTemplates, selectedTemplateId, allTemplates]);

  const startEdit = useCallback(() => {
    if (selectedTemplate.builtIn) return;
    setTemplateMode('edit');
    setDraftName(selectedTemplate.name);
    setDraftDescription(selectedTemplate.description || '');
  }, [selectedTemplate]);

  // REM_SECTIONS moved to module scope (REM_SECTIONS, declared above) so
  // the useCallback below doesn't list it as a missing dep.

  const generateRemediation = useCallback(async () => {
    if (!rawLog.trim()) { setRemError('Paste the alert log first'); return; }
    setRemLoading(true); setRemError(null);
    try {
      const r = await fetch('/api/email/remediate', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          parsed:           parsedFields || {},
          log_text:         rawLog,
          alert_type:       detected?.alert_type || parsedFields?.suggested_alert_type || '',
          threat_level:     '',
          severity:         '',
          mitre_techniques: [],
        }),
      });
      const d = await r.json();
      if (!r.ok) throw new Error(d.detail || d.error || `HTTP ${r.status}`);
      setRemediation(d);
    } catch (e) {
      setRemError(e.message);
    } finally {
      setRemLoading(false);
    }
  }, [rawLog, parsedFields, detected]);

  const copyAllRemediation = useCallback(() => {
    if (!remediation) return;
    const lines = [];
    for (const s of REM_SECTIONS) {
      const v = remediation[s.key];
      if (!v) continue;
      lines.push(`# ${s.label}`);
      if (Array.isArray(v)) {
        for (const item of v) {
          if (typeof item === 'string') lines.push(`  - ${item}`);
          else if (item && typeof item === 'object') {
            lines.push(`  - ${item.title || ''}`);
            if (item.description) lines.push(`      ${item.description}`);
          }
        }
      } else {
        lines.push(String(v));
      }
      lines.push('');
    }
    navigator.clipboard.writeText(lines.join('\n'));
  }, [remediation]);

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
          options: {
            response_action:     responseAction,
            enabled_fields:      enabledFields,
            // Category toggles — only categories present in the parsed
            // log AND turned on by the analyst land in the email body.
            enabled_categories:  enabledCategories,
          },
        }),
      });
      const d = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(d.detail || d.error || `HTTP ${r.status}`);
      // The AI guidance is woven into the body by compose_ai's prompt
      // (see backend/intel/email_composer.py::_AI_SYSTEM — four-part
      // structure: details, action taken, recommended next steps,
      // closing). Nothing to append here.
      setComposed(d);
    } catch (e) {
      setComposeError(e.message || 'compose failed');
    } finally {
      setComposing(false);
    }
  }, [rawLog, responseAction, enabledFields, enabledCategories, initialParsed]);

  // Debounced auto-classify: as the analyst pastes, hit /api/email/parse to
  // learn the alert type. The compose-ai backend uses this to pick the right
  // template for the client communication. We do NOT auto-pick the response
  // action dropdown — that's the analyst's deliberate choice based on what
  // they actually did, not what the AI guesses.
  useEffect(() => {
    if (parseTimer.current) clearTimeout(parseTimer.current);
    if (!rawLog || rawLog.trim().length < 20) {
      setDetected(null);
      return;
    }
    parseTimer.current = setTimeout(async () => {
      try {
        const r = await fetch('/api/email/parse', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ log_text: rawLog }),
        });
        if (!r.ok) return;
        const p = await r.json();
        // Stash the parsed fields so compose_ai gets structured data.
        setParsedFields(p);
        const at = p.suggested_alert_type;
        if (!at) { setDetected(null); return; }
        setDetected({
          alert_type: at,
          alert_label: (p._alert_label || at).replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase()),
        });
      } catch { /* parse failure is silent — analyst can still compose */ }
    }, 400);
    return () => { if (parseTimer.current) clearTimeout(parseTimer.current); };
  }, [rawLog]);

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
          Email Composer
        </Typography>
        {onClose && (
          <MuiButton onClick={onClose} size="small" variant="text"
            sx={{ ml: 'auto !important', textTransform: 'none', fontSize: 12 }}>
            Close
          </MuiButton>
        )}
      </Stack>

      {/* ─── 1 · Paste ────────────────────────────────────────────────────── */}
      <PanelCard
        title="1 · Raw alert log"
        defaultOpen
        summary={rawLog ? `${rawLog.length.toLocaleString()} chars` : 'empty'}>
        <MuiTextField
          value={rawLog}
          onChange={e => setRawLog(e.target.value)}
          multiline minRows={6} maxRows={20} fullWidth
          InputProps={{ sx: { ...monoSx, fontSize: 12, lineHeight: 1.55 } }}
        />
        {detected && (
          <Stack direction="row" alignItems="center" spacing={1} sx={{ mt: 1.25 }} flexWrap="wrap" useFlexGap>
            <Zap size={12} color="#0fbcff"/>
            <Typography sx={{ fontSize: 11, color: 'text.tertiary' }}>
              Detected · template will match
            </Typography>
            <MuiChip
              label={detected.alert_label}
              size="small"
              sx={{
                height: 20, fontSize: 11,
                backgroundColor: muiAlpha('#0fbcff', 0.16),
                color: '#0fbcff', fontWeight: 500,
                borderRadius: '3px',
              }}
            />
          </Stack>
        )}
      </PanelCard>

      {/* ─── 2 · Response action + compose button ───────────────────────── */}
      <PanelCard
        title="2 · Response action"
        summary={(() => {
          const r = RESPONSE_OPTIONS.find(o => o.id === responseAction);
          return r && r.id ? r.label : 'none selected';
        })()}>
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
      </PanelCard>

      {/* ─── Templates panel (spec §8) ────────────────────────────────────
          Lets the analyst pick which email body fields are included. The
          enabled_fields list is sent to the backend with compose-ai so
          disabled fields are excluded from the rendered email AND from the
          AI prompt (the model never sees them and can't hallucinate them).
          Built-in "All Details" and "Minimal" templates are merged with
          custom analyst-saved templates from localStorage.                */}
      <PanelCard
        title="Template"
        summary={selectedTemplate?.name || ''}>

        <Stack direction="row" spacing={1} alignItems="flex-end" flexWrap="wrap"
          useFlexGap sx={{ mb: 1.5 }}>
          <Box sx={{ minWidth: 280, flex: '1 1 auto' }}>
            <MuiTextField
              select fullWidth size="small"
              value={selectedTemplateId}
              onChange={e => {
                const v = e.target.value;
                if (v === '__create_new') {
                  setTemplateMode('create');
                  setDraftName(''); setDraftDescription('');
                } else {
                  setSelectedTemplateId(v);
                  setTemplateMode('idle');
                }
              }}
              InputProps={{ sx: { fontSize: 13 } }}
            >
              {allTemplates.map(t => (
                <MenuItem key={t.id} value={t.id} sx={{ fontSize: 13 }}>
                  {t.name}
                </MenuItem>
              ))}
              <MenuItem value="__create_new"
                sx={{ fontSize: 13, color: 'primary.main', fontWeight: 500 }}>
                + Create new template…
              </MenuItem>
            </MuiTextField>
          </Box>
          <MuiButton variant="outlined" size="small"
            onClick={() => {
              setTemplateMode('create');
              setDraftName(''); setDraftDescription('');
            }}
            sx={{ textTransform: 'none', fontSize: 12 }}>
            Save as template
          </MuiButton>
          {!selectedTemplate.builtIn && (
            <>
              <MuiButton variant="outlined" size="small"
                onClick={startEdit}
                sx={{ textTransform: 'none', fontSize: 12 }}>
                Edit
              </MuiButton>
              <MuiButton variant="outlined" size="small" color="error"
                onClick={() => {
                  if (window.confirm(`Delete template "${selectedTemplate.name}"?`)) {
                    deleteTemplate(selectedTemplate.id);
                  }
                }}
                sx={{ textTransform: 'none', fontSize: 12 }}>
                Delete
              </MuiButton>
            </>
          )}
        </Stack>

        {/* Dynamic category toggles — one per category the parser actually
            extracted from THIS log. Hidden until the log is parsed. Each
            toggle expands to show the labels + values it controls so the
            analyst sees what's about to land in the email. */}
        {(() => {
          const categorized = parsedFields?._categorized || {};
          const presentCats = CATEGORY_ORDER.filter(c =>
            Array.isArray(categorized[c]) && categorized[c].length > 0);
          if (Object.keys(parsedFields || {}).length === 0 || presentCats.length === 0) {
            return (
              <Typography sx={{ fontSize: 11, color: 'text.tertiary',
                fontStyle: 'italic', mt: 0.5 }}>
                Paste the alert log first — category toggles will appear here
                based on what the log actually contains.
              </Typography>
            );
          }
          return (
            <Stack spacing={1}>
              {presentCats.map(cat => {
                const items = categorized[cat] || [];
                const on = enabledCategories.includes(cat);
                const expanded = expandedCategories.includes(cat);
                return (
                  <Box key={cat} sx={{
                    p: '8px 12px', borderRadius: '4px',
                    backgroundColor: on
                      ? muiAlpha('#0fbcff', 0.08)
                      : muiAlpha('#ffffff', 0.02),
                    border: `1px solid ${on
                      ? muiAlpha('#0fbcff', 0.35)
                      : muiAlpha('#ffffff', 0.08)}`,
                  }}>
                    <Box sx={{
                      display: 'flex', alignItems: 'center', gap: 1,
                      userSelect: 'none',
                    }}>
                      {/* Checkbox toggles inclusion; clicking the label
                          area expands/collapses the field preview. */}
                      <Box
                        onClick={() => toggleCategory(cat)}
                        sx={{
                          width: 14, height: 14, borderRadius: '3px',
                          border: `1px solid ${on ? '#0fbcff' : muiAlpha('#ffffff', 0.3)}`,
                          backgroundColor: on ? '#0fbcff' : 'transparent',
                          display: 'flex', alignItems: 'center', justifyContent: 'center',
                          flexShrink: 0, cursor: 'pointer',
                        }}>
                        {on && <Check size={10} color="#0a1929"/>}
                      </Box>
                      <Box
                        onClick={() => toggleExpanded(cat)}
                        sx={{ display: 'flex', alignItems: 'center', gap: 0.75,
                          cursor: 'pointer', flex: 1, minWidth: 0 }}>
                        <Box sx={{
                          color: 'text.tertiary',
                          transform: expanded ? 'rotate(90deg)' : 'rotate(0deg)',
                          transition: 'transform 0.18s ease',
                          display: 'flex', alignItems: 'center',
                        }}>
                          <ChevronRight size={12}/>
                        </Box>
                        <Typography sx={{
                          fontSize: 12.5,
                          fontWeight: 600,
                          color: on ? 'text.primary' : 'text.tertiary',
                        }}>
                          {cat}
                        </Typography>
                        <Typography sx={{ fontSize: 11, color: 'text.tertiary' }}>
                          · {items.length} field{items.length === 1 ? '' : 's'}
                        </Typography>
                      </Box>
                    </Box>
                    {expanded && (() => {
                      const showAll = showAllCategories.includes(cat);
                      const visible = showAll ? items : items.slice(0, 12);
                      return (
                        <Box sx={{ mt: 0.75, pl: 3 }}>
                          {visible.map((it, i) => (
                            <Typography key={i} sx={{ fontSize: 11,
                              color: 'text.tertiary', lineHeight: 1.55,
                              wordBreak: 'break-word' }}>
                              <Box component="span" sx={{ color: 'text.primary' }}>
                                {it.label}:
                              </Box>{' '}{String(it.value).slice(0, 120)}
                            </Typography>
                          ))}
                          {items.length > 12 && (
                            <Typography
                              onClick={(e) => { e.stopPropagation(); toggleShowAll(cat); }}
                              sx={{ fontSize: 10, color: 'primary.main',
                                mt: 0.25, cursor: 'pointer', userSelect: 'none',
                                '&:hover': { textDecoration: 'underline' },
                              }}>
                              {showAll
                                ? `− show fewer`
                                : `+ ${items.length - 12} more (click to expand)`}
                            </Typography>
                          )}
                        </Box>
                      );
                    })()}
                  </Box>
                );
              })}
            </Stack>
          );
        })()}

        {/* Save-as / Edit modal-ish inline form */}
        {(templateMode === 'create' || templateMode === 'edit') && (
          <Box sx={{
            mt: 2, p: 1.5, borderRadius: '4px',
            backgroundColor: muiAlpha('#B286FF', 0.06),
            border: `1px solid ${muiAlpha('#B286FF', 0.3)}`,
            borderLeft: `3px solid #B286FF`,
          }}>
            <Typography sx={{ fontSize: 11, color: '#B286FF', fontWeight: 600,
              textTransform: 'uppercase', letterSpacing: '0.06em', mb: 1 }}>
              {templateMode === 'edit' ? 'Edit template' : 'New template'}
            </Typography>
            <Stack spacing={1}>
              <MuiTextField size="small" fullWidth
                value={draftName}
                onChange={e => setDraftName(e.target.value)}
                placeholder="Template name (e.g. Defender Alerts)"
                InputProps={{ sx: { fontSize: 13 } }}/>
              <Stack direction="row" spacing={1}>
                <MuiButton size="small" variant="contained"
                  disabled={!draftName.trim()}
                  onClick={saveAsTemplate}
                  sx={{ textTransform: 'none', fontSize: 12 }}>
                  {templateMode === 'edit' ? 'Save changes' : 'Save template'}
                </MuiButton>
                <MuiButton size="small" variant="text"
                  onClick={() => {
                    setTemplateMode('idle');
                    setDraftName(''); setDraftDescription('');
                  }}
                  sx={{ textTransform: 'none', fontSize: 12,
                    color: 'text.tertiary' }}>
                  Cancel
                </MuiButton>
              </Stack>
            </Stack>
          </Box>
        )}
      </PanelCard>

      {/* ─── AI Remediation reference panel ──────────────────────────────
          Display-only view of the structured guidance the AI uses to weave
          the email body. Generated on demand so the analyst can see WHERE
          the email's recommendations came from. The email itself ALREADY
          contains this guidance as flowing prose — this panel doesn't
          change the body; it only surfaces the structured source.        */}
      <PanelCard
        title="AI Remediation"
        summary={remediation ? 'ready' : 'not generated'}>
        <Stack direction="row" spacing={1} alignItems="center"
          flexWrap="wrap" useFlexGap sx={{ mb: remediation ? 1.5 : 0 }}>
          <MuiButton
            variant={remediation ? 'outlined' : 'contained'}
            size="small"
            disabled={remLoading || !rawLog.trim()}
            onClick={generateRemediation}
            startIcon={remLoading
              ? <CircularProgress size={12} sx={{ color: 'inherit' }}/>
              : (remediation ? <RefreshCcw size={14}/> : <Wand2 size={14}/>)}
            sx={{ textTransform: 'none' }}
          >
            {remLoading
              ? 'Generating…'
              : (remediation ? 'Regenerate' : 'Show AI remediation')}
          </MuiButton>
          {remediation && (
            <MuiButton size="small" variant="outlined"
              onClick={copyAllRemediation}
              startIcon={<Copy size={14}/>}
              sx={{ textTransform: 'none' }}>
              Copy all
            </MuiButton>
          )}
          {remError && (
            <Stack direction="row" spacing={0.5} alignItems="center" sx={{ color: 'error.main' }}>
              <AlertCircle size={12}/>
              <Typography sx={{ fontSize: 11 }}>{remError}</Typography>
            </Stack>
          )}
        </Stack>

        {remediation && REM_SECTIONS.map(s => {
          const v = remediation[s.key];
          if (!v) return null;
          return (
            <Box key={s.key} sx={{
              mt: 1.25, p: 1.25, borderRadius: '4px',
              backgroundColor: muiAlpha('#0fbcff', 0.05),
              border: `1px solid ${muiAlpha('#0fbcff', 0.18)}`,
              borderLeft: `3px solid ${muiAlpha('#0fbcff', 0.6)}`,
            }}>
              <Typography sx={{ mb: 0.75, fontSize: 11, fontWeight: 600,
                color: '#0fbcff', textTransform: 'uppercase',
                letterSpacing: '0.06em' }}>
                {s.label}
              </Typography>
              {Array.isArray(v) ? (
                <Stack spacing={0.75}>
                  {v.map((item, i) => (
                    <Stack key={i} direction="row" spacing={1} alignItems="flex-start">
                      <Box sx={{ width: 4, height: 4, borderRadius: 99,
                        backgroundColor: '#0fbcff', mt: '7px', flexShrink: 0 }}/>
                      <Box>
                        {typeof item === 'string' ? (
                          <Typography sx={{ fontSize: 12.5, color: 'text.primary',
                            lineHeight: 1.55 }}>{item}</Typography>
                        ) : (
                          <>
                            <Typography sx={{ fontSize: 12.5, fontWeight: 600,
                              color: 'text.primary', lineHeight: 1.55 }}>
                              {item?.title || ''}
                            </Typography>
                            {item?.description && (
                              <Typography sx={{ fontSize: 12, color: 'text.secondary',
                                lineHeight: 1.55, mt: 0.25 }}>
                                {item.description}
                              </Typography>
                            )}
                          </>
                        )}
                      </Box>
                    </Stack>
                  ))}
                </Stack>
              ) : (
                <Typography sx={{ fontSize: 12.5, color: 'text.primary',
                  lineHeight: 1.6, whiteSpace: 'pre-wrap' }}>{String(v)}</Typography>
              )}
            </Box>
          );
        })}
      </PanelCard>

      {/* ─── 3 · Preview ──────────────────────────────────────────────────── */}
      {composed && (
        <PanelCard
          title="3 · Preview"
          defaultOpen
          summary={composed.subject ? `subject: ${composed.subject.slice(0, 60)}` : ''}>

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
        </PanelCard>
      )}
    </Box>
  );
}
