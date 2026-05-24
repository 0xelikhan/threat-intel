/**
 * Adapted from OpenCTI (AGPL-3.0) github.com/OpenCTI-Platform/opencti
 *
 * RECON File Scanner — comprehensive malware analysis workstation view.
 * Spec §7 of the all-in-one scanner plan.
 *
 * Layout: left column = submission + progress + summary, right column = tabs:
 *   Overview / Hashes / File Details / Strings / Threat Intel / MITRE /
 *   YARA / Detection Content
 */
import React, { useState, useRef, useEffect, useMemo } from 'react';
import {
  Box, Stack, Typography, Paper as MuiPaper,
  Button as MuiButton, Chip as MuiChip, TextField as MuiTextField,
  IconButton as MuiIconButton, Table as MuiTable, TableHead, TableBody,
  TableRow, TableCell, Tooltip, LinearProgress,
} from '@mui/material';
import { alpha as muiAlpha } from '@mui/material/styles';
import {
  Upload, FileSearch, Hash, Copy, Check, Search, Download, Trash2,
  ArrowUpRight, AlertTriangle, AlertCircle, Shield,
} from 'lucide-react';

const VERDICT_COLOR = {
  MALICIOUS:  '#EE3838',
  SUSPICIOUS: '#E6700F',
  LOW:        '#E1B823',
  CLEAN:      '#16AD34',
  UNKNOWN:    '#848592',
};
const SEV_COLOR = VERDICT_COLOR;
const monoSx = { fontFamily: '"IBM Plex Mono", monospace' };

const ANALYSIS_STEPS = [
  'Receiving file',
  'Detecting file type',
  'Computing hashes',
  'Extracting strings',
  'Analyzing structure',
  'Running YARA rules',
  'Correlating threat intel',
  'Checking similarity database',
  'Generating detection content',
  'Building report',
];


// ─── Copy-to-clipboard button ──────────────────────────────────────────────────
function CopyBtn({ text, label = 'Copy' }) {
  const [copied, setCopied] = useState(false);
  return (
    <Tooltip title={copied ? 'Copied' : label}>
      <MuiIconButton size="small" onClick={() => {
        navigator.clipboard.writeText(text || '');
        setCopied(true);
        setTimeout(() => setCopied(false), 1500);
      }} sx={{ p: 0.5, color: copied ? 'success.main' : 'text.tertiary',
        '&:hover': { color: 'primary.main' } }}>
        {copied ? <Check size={12}/> : <Copy size={12}/>}
      </MuiIconButton>
    </Tooltip>
  );
}


// ─── Submission column ─────────────────────────────────────────────────────────
function SubmissionPanel({ onScanFile, onScanHash, onScanUrl, scanning, progressStep }) {
  const [dragOver, setDragOver] = useState(false);
  const [hashInput, setHashInput] = useState('');
  const [urlInput, setUrlInput]   = useState('');

  const handleFile = (file) => {
    if (!file || scanning) return;
    onScanFile(file);
  };

  return (
    <Stack spacing={2}>
      {/* Drop zone */}
      <Box
        onDragOver={e => { e.preventDefault(); setDragOver(true); }}
        onDragLeave={() => setDragOver(false)}
        onDrop={e => {
          e.preventDefault(); setDragOver(false);
          handleFile(e.dataTransfer.files[0]);
        }}
        onClick={() => !scanning && document.getElementById('fsv-file-input').click()}
        sx={{
          border: `2px dashed ${dragOver ? '#B286FF' : muiAlpha('#ffffff', 0.18)}`,
          backgroundColor: dragOver ? muiAlpha('#B286FF', 0.08) : 'background.secondary',
          borderRadius: '6px', p: '36px 20px',
          textAlign: 'center', cursor: scanning ? 'wait' : 'pointer',
          transition: 'all .15s',
          '&:hover': scanning ? undefined : { borderColor: muiAlpha('#B286FF', 0.5) },
        }}
      >
        <FileSearch size={40} color={dragOver ? '#B286FF' : '#848592'}
          style={{ marginBottom: 10 }}/>
        <Typography sx={{ fontSize: 14, color: 'text.primary', fontWeight: 500, mb: 0.5 }}>
          {scanning ? 'Analyzing…' : 'Drop a file or click to upload'}
        </Typography>
        <Typography sx={{ fontSize: 11, color: 'text.tertiary' }}>
          any format · 50 MB max · static + sandbox + YARA + TI
        </Typography>
        <input id="fsv-file-input" type="file" style={{ display: 'none' }}
          onChange={e => handleFile(e.target.files[0])} disabled={scanning}/>
      </Box>

      {/* Hash lookup */}
      <Box>
        <Typography sx={{ fontSize: 11, color: 'text.tertiary', fontWeight: 600,
          textTransform: 'uppercase', letterSpacing: '0.06em', mb: 0.75 }}>
          Look up by hash
        </Typography>
        <Stack direction="row" spacing={1}>
          <MuiTextField size="small" fullWidth
            value={hashInput} onChange={e => setHashInput(e.target.value)}
            placeholder="MD5 / SHA1 / SHA256"
            sx={{ '& .MuiInputBase-input': { ...monoSx, fontSize: 12 } }}/>
          <MuiButton variant="outlined" size="small"
            disabled={!hashInput.trim() || scanning}
            onClick={() => onScanHash(hashInput.trim())}>
            Lookup
          </MuiButton>
        </Stack>
      </Box>

      {/* URL fetch */}
      <Box>
        <Typography sx={{ fontSize: 11, color: 'text.tertiary', fontWeight: 600,
          textTransform: 'uppercase', letterSpacing: '0.06em', mb: 0.75 }}>
          Fetch + scan URL
        </Typography>
        <Stack direction="row" spacing={1}>
          <MuiTextField size="small" fullWidth
            value={urlInput} onChange={e => setUrlInput(e.target.value)}
            placeholder="https://…"
            sx={{ '& .MuiInputBase-input': { ...monoSx, fontSize: 12 } }}/>
          <MuiButton variant="outlined" size="small"
            disabled={!urlInput.trim() || scanning}
            onClick={() => onScanUrl(urlInput.trim())}>
            Fetch
          </MuiButton>
        </Stack>
      </Box>

      {/* Progress stepper while scanning */}
      {scanning && (
        <MuiPaper elevation={0} sx={{
          backgroundColor: '#0C1524',
          border: `1px solid ${muiAlpha('#ffffff', 0.12)}`,
          borderRadius: '4px', p: 1.5,
        }}>
          <Typography sx={{ fontSize: 11, color: 'primary.main', fontWeight: 600,
            textTransform: 'uppercase', letterSpacing: '0.06em', mb: 1 }}>
            Analysis in progress
          </Typography>
          {ANALYSIS_STEPS.map((label, i) => {
            const done    = i < progressStep;
            const current = i === progressStep;
            return (
              <Stack key={label} direction="row" alignItems="center" spacing={1} sx={{ py: 0.25 }}>
                <Box sx={{
                  width: 12, height: 12, borderRadius: 99,
                  backgroundColor: done ? 'success.main' : current ? 'primary.main' : muiAlpha('#ffffff', 0.1),
                  ...(current ? { animation: 'pulse 1.2s ease-in-out infinite' } : {}),
                }}/>
                <Typography sx={{
                  fontSize: 11,
                  color: done ? 'success.main' : current ? 'primary.main' : 'text.disabled',
                  fontWeight: current ? 600 : 400,
                }}>{label}</Typography>
              </Stack>
            );
          })}
          <LinearProgress sx={{ mt: 1, height: 3, borderRadius: 99 }}
            variant="determinate" value={(progressStep / ANALYSIS_STEPS.length) * 100}/>
        </MuiPaper>
      )}
    </Stack>
  );
}


// ─── Hashes tab ────────────────────────────────────────────────────────────────
function HashesTab({ result }) {
  const h = result.hashes || {};
  const sh = result.threat_intel?.scan_history || {};
  const rows = [
    ['MD5',     h.md5],
    ['SHA-1',   h.sha1],
    ['SHA-256', h.sha256],
    ['SHA-512', h.sha512],
    ['TLSH',    h.tlsh],
    ['ssdeep',  h.ssdeep],
    ['imphash', result.format_specific?.pe?.imphash],
  ].filter(([, v]) => v);
  return (
    <Stack spacing={2}>
      <MuiTable size="small">
        <TableBody>
          {rows.map(([label, val]) => (
            <TableRow key={label}>
              <TableCell sx={{ width: 100, color: 'text.tertiary',
                fontSize: 11, textTransform: 'uppercase' }}>{label}</TableCell>
              <TableCell sx={{ ...monoSx, fontSize: 12, color: 'text.primary',
                wordBreak: 'break-all' }}>{val}</TableCell>
              <TableCell sx={{ width: 40 }}><CopyBtn text={val}/></TableCell>
            </TableRow>
          ))}
        </TableBody>
      </MuiTable>

      {/* Similar-file matches */}
      {sh && (sh.exact?.length || sh.imphash?.length || sh.tlsh_similar?.length || sh.ssdeep_similar?.length) ? (
        <MuiPaper elevation={0} sx={{ backgroundColor: '#0C1524',
          border: `1px solid ${muiAlpha('#ffffff', 0.12)}`,
          borderRadius: '4px', p: 1.5 }}>
          <Typography sx={{ fontSize: 11, color: 'primary.main', fontWeight: 600,
            textTransform: 'uppercase', letterSpacing: '0.06em', mb: 1 }}>
            Similar files in scan history
          </Typography>
          {sh.exact?.length > 0 && <SimList title="exact SHA-256 match" rows={sh.exact}/>}
          {sh.imphash?.length > 0 && <SimList title="same imphash" rows={sh.imphash}/>}
          {sh.tlsh_similar?.length > 0 && <SimList title="TLSH similar (distance ≤ 60)" rows={sh.tlsh_similar}/>}
          {sh.ssdeep_similar?.length > 0 && <SimList title="ssdeep similar (score > 50)" rows={sh.ssdeep_similar}/>}
        </MuiPaper>
      ) : null}
    </Stack>
  );
}

function SimList({ title, rows }) {
  return (
    <Box sx={{ mb: 1 }}>
      <Typography sx={{ fontSize: 10, color: 'text.tertiary',
        textTransform: 'uppercase', letterSpacing: '0.05em', mb: 0.5 }}>
        {title}
      </Typography>
      {rows.slice(0, 5).map((r, i) => (
        <Box key={i} sx={{ display: 'grid', gridTemplateColumns: '1fr auto auto',
          gap: 1, fontSize: 11, py: 0.25 }}>
          <Box sx={{ ...monoSx, color: 'text.primary', wordBreak: 'break-all' }}>
            {r.sha256?.slice(0, 16)}…
          </Box>
          <Box sx={{ color: 'text.tertiary' }}>{r.filename || ''}</Box>
          <Box sx={{ color: VERDICT_COLOR[r.verdict] || 'text.disabled', fontWeight: 600 }}>
            {r.verdict}{r.tlsh_distance != null ? ` · d=${r.tlsh_distance}` : ''}
            {r.ssdeep_score != null ? ` · ${r.ssdeep_score}%` : ''}
          </Box>
        </Box>
      ))}
    </Box>
  );
}


// ─── File Details tab ─────────────────────────────────────────────────────────
function FileDetailsTab({ result }) {
  const t   = result.type || {};
  const ent = result.entropy || {};
  const pe  = result.format_specific?.pe;
  const off = result.format_specific?.office;
  const pdf = result.format_specific?.pdf;
  const ar  = result.format_specific?.archive;
  const sc  = result.format_specific?.script;

  return (
    <Stack spacing={2}>
      {/* Type mismatch */}
      {t.mismatch && (
        <MuiPaper elevation={0} sx={{
          backgroundColor: muiAlpha('#EE3838', 0.08),
          border: `1px solid ${muiAlpha('#EE3838', 0.4)}`,
          borderLeft: '3px solid #EE3838', borderRadius: '4px', p: '10px 12px',
        }}>
          <Stack direction="row" alignItems="center" spacing={1}>
            <AlertTriangle size={14} color="#EE3838"/>
            <Typography sx={{ fontSize: 12, color: 'error.main', fontWeight: 600 }}>
              File-type mismatch
            </Typography>
          </Stack>
          <Typography sx={{ fontSize: 11, color: 'text.primary', mt: 0.5 }}>
            {t.mismatch_summary}
          </Typography>
        </MuiPaper>
      )}

      {/* Type table */}
      <MuiTable size="small">
        <TableBody>
          <TableRow><TableCell sx={{ width: 140, color: 'text.tertiary', fontSize: 11 }}>Detected MIME</TableCell>
            <TableCell sx={{ fontSize: 12, ...monoSx }}>{t.detected_mime}</TableCell></TableRow>
          <TableRow><TableCell sx={{ color: 'text.tertiary', fontSize: 11 }}>Detected description</TableCell>
            <TableCell sx={{ fontSize: 12 }}>{t.detected_desc}</TableCell></TableRow>
          <TableRow><TableCell sx={{ color: 'text.tertiary', fontSize: 11 }}>Claimed (extension)</TableCell>
            <TableCell sx={{ fontSize: 12, ...monoSx }}>.{t.claimed_ext} · {t.claimed_mime}</TableCell></TableRow>
          <TableRow><TableCell sx={{ color: 'text.tertiary', fontSize: 11 }}>Category</TableCell>
            <TableCell sx={{ fontSize: 12 }}>{t.category}</TableCell></TableRow>
        </TableBody>
      </MuiTable>

      {/* Entropy viz */}
      <Box>
        <Typography sx={{ fontSize: 11, color: 'text.tertiary', fontWeight: 600,
          textTransform: 'uppercase', letterSpacing: '0.06em', mb: 0.5 }}>
          Entropy ({ent.overall} / 8 · {ent.band?.replace(/_/g, ' ')})
        </Typography>
        <Stack direction="row" alignItems="end" spacing={0.25} sx={{
          height: 60, p: 1,
          backgroundColor: '#0C1524',
          border: `1px solid ${muiAlpha('#ffffff', 0.12)}`,
          borderRadius: '4px',
        }}>
          {(ent.windows || []).slice(0, 200).map((w, i) => (
            <Box key={i} sx={{
              flex: '1 1 0', minWidth: 1,
              height: `${(w.entropy / 8) * 100}%`,
              backgroundColor: w.entropy > 7.0 ? '#EE3838'
                : w.entropy > 6.0 ? '#E6700F' : '#0fbcff',
            }}/>
          ))}
        </Stack>
        {ent.flag && (
          <Typography sx={{ fontSize: 11, color: 'warning.main', mt: 0.5 }}>
            ⚠ {ent.flag.replace(/_/g, ' ')}
          </Typography>
        )}
      </Box>

      {pe && <PESection pe={pe}/>}
      {off && <OfficeSection office={off}/>}
      {pdf && <PdfSection pdf={pdf}/>}
      {ar  && <ArchiveSection archive={ar}/>}
      {sc  && <ScriptSection script={sc}/>}
    </Stack>
  );
}

function PESection({ pe }) {
  return (
    <Box>
      <Typography sx={{ fontSize: 11, color: 'text.tertiary', fontWeight: 600,
        textTransform: 'uppercase', letterSpacing: '0.06em', mb: 0.75 }}>
        PE structure
      </Typography>
      <MuiTable size="small">
        <TableBody>
          <TableRow><TableCell sx={{ color: 'text.tertiary', fontSize: 11, width: 140 }}>Compiled</TableCell>
            <TableCell sx={{ fontSize: 12 }}>{pe.timestamp?.iso}{pe.timestamp?.flags?.length ? ` ⚠ ${pe.timestamp.flags.join(', ')}` : ''}</TableCell></TableRow>
          <TableRow><TableCell sx={{ color: 'text.tertiary', fontSize: 11 }}>Machine</TableCell>
            <TableCell sx={{ fontSize: 12 }}>{pe.machine_name} · subsystem {pe.subsystem}</TableCell></TableRow>
          <TableRow><TableCell sx={{ color: 'text.tertiary', fontSize: 11 }}>Linker</TableCell>
            <TableCell sx={{ fontSize: 12 }}>{pe.linker_version}</TableCell></TableRow>
          <TableRow><TableCell sx={{ color: 'text.tertiary', fontSize: 11 }}>imphash</TableCell>
            <TableCell sx={{ fontSize: 12, ...monoSx }}>{pe.imphash}</TableCell></TableRow>
          <TableRow><TableCell sx={{ color: 'text.tertiary', fontSize: 11 }}>Imports</TableCell>
            <TableCell sx={{ fontSize: 12 }}>{pe.import_count} functions across {Object.keys(pe.imports || {}).length} DLLs</TableCell></TableRow>
          <TableRow><TableCell sx={{ color: 'text.tertiary', fontSize: 11 }}>Signature</TableCell>
            <TableCell sx={{ fontSize: 12 }}>{pe.signature?.present ? 'Authenticode present' : 'unsigned'}</TableCell></TableRow>
          <TableRow><TableCell sx={{ color: 'text.tertiary', fontSize: 11 }}>Mitigations</TableCell>
            <TableCell sx={{ fontSize: 12 }}>
              {Object.entries(pe.mitigations || {}).map(([k, v]) => (
                <MuiChip key={k} size="small" label={k}
                  sx={{ mr: 0.5, mb: 0.5, height: 20, fontSize: 10,
                    backgroundColor: v ? muiAlpha('#16AD34', 0.2) : muiAlpha('#EE3838', 0.2),
                    color: v ? 'success.main' : 'error.main' }}/>
              ))}
            </TableCell></TableRow>
        </TableBody>
      </MuiTable>

      {/* Flagged imports grouped */}
      {pe.flagged_imports && Object.keys(pe.flagged_imports).length > 0 && (
        <Box sx={{ mt: 1.5 }}>
          <Typography sx={{ fontSize: 11, color: 'warning.main', fontWeight: 600,
            textTransform: 'uppercase', letterSpacing: '0.06em', mb: 0.5 }}>
            High-risk imports
          </Typography>
          {Object.entries(pe.flagged_imports).map(([cat, fns]) => (
            <Box key={cat} sx={{ mb: 0.5, fontSize: 11 }}>
              <Box component="span" sx={{ color: 'warning.main', fontWeight: 600 }}>{cat}:</Box>{' '}
              <Box component="span" sx={{ ...monoSx, color: 'text.primary' }}>{fns.join(', ')}</Box>
            </Box>
          ))}
        </Box>
      )}

      {/* Sections */}
      <Box sx={{ mt: 1.5 }}>
        <Typography sx={{ fontSize: 11, color: 'text.tertiary', fontWeight: 600,
          textTransform: 'uppercase', letterSpacing: '0.06em', mb: 0.5 }}>
          Sections ({(pe.sections || []).length})
        </Typography>
        <MuiTable size="small">
          <TableHead>
            <TableRow>
              {['Name', 'VAddr', 'VSize', 'RSize', 'Entropy', 'Flags'].map(h => (
                <TableCell key={h} sx={{ fontSize: 10, color: 'text.disabled' }}>{h}</TableCell>
              ))}
            </TableRow>
          </TableHead>
          <TableBody>
            {(pe.sections || []).map((s, i) => (
              <TableRow key={i}>
                <TableCell sx={{ ...monoSx, fontSize: 11 }}>{s.name}</TableCell>
                <TableCell sx={{ ...monoSx, fontSize: 11 }}>{s.vaddr}</TableCell>
                <TableCell sx={{ fontSize: 11 }}>{s.vsize}</TableCell>
                <TableCell sx={{ fontSize: 11 }}>{s.rsize}</TableCell>
                <TableCell sx={{ fontSize: 11, color: s.entropy > 7 ? 'error.main' : 'text.primary' }}>
                  {s.entropy}
                </TableCell>
                <TableCell sx={{ fontSize: 10 }}>{(s.flags || []).join(', ')}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </MuiTable>
      </Box>
    </Box>
  );
}

function OfficeSection({ office }) {
  return (
    <Box>
      <Typography sx={{ fontSize: 11, color: 'text.tertiary', fontWeight: 600,
        textTransform: 'uppercase', letterSpacing: '0.06em', mb: 0.5 }}>
        Office document
      </Typography>
      <Typography sx={{ fontSize: 12, color: 'text.primary' }}>
        Macros: {office.has_macros ? 'yes' : 'no'}{office.auto_exec?.length ? ` · auto-exec: ${office.auto_exec.join(', ')}` : ''}
      </Typography>
      {office.suspicious_patterns?.length > 0 && (
        <Box sx={{ mt: 0.5 }}>
          {office.suspicious_patterns.map((s, i) => (
            <Box key={i} sx={{ fontSize: 11, color: 'warning.main', py: 0.25 }}>
              ⚠ {s.pattern}: {s.match}
            </Box>
          ))}
        </Box>
      )}
      {office.urls?.length > 0 && (
        <Box sx={{ mt: 0.5, fontSize: 11, ...monoSx, color: 'text.tertiary' }}>
          URLs: {office.urls.slice(0, 5).join(', ')}
        </Box>
      )}
    </Box>
  );
}

function PdfSection({ pdf }) {
  return (
    <Box>
      <Typography sx={{ fontSize: 11, color: 'text.tertiary', fontWeight: 600,
        textTransform: 'uppercase', letterSpacing: '0.06em', mb: 0.5 }}>
        PDF
      </Typography>
      <Typography sx={{ fontSize: 12, color: 'text.primary' }}>
        Pages: {pdf.pages} · encrypted: {pdf.encrypted ? 'yes' : 'no'}
        {pdf.javascript?.length ? ` · JavaScript blocks: ${pdf.javascript.length}` : ''}
        {pdf.launch_actions?.length ? ` · launch actions: ${pdf.launch_actions.length}` : ''}
        {pdf.embedded_count ? ` · embedded files: ${pdf.embedded_count}` : ''}
      </Typography>
      {pdf.javascript?.length > 0 && (
        <Box sx={{ ...monoSx, fontSize: 11, mt: 0.5,
          color: 'text.primary', backgroundColor: '#070d19',
          border: `1px solid ${muiAlpha('#ffffff', 0.12)}`,
          borderRadius: '4px', p: 1, maxHeight: 200, overflow: 'auto',
          whiteSpace: 'pre-wrap', wordBreak: 'break-all',
        }}>{pdf.javascript[0]}</Box>
      )}
    </Box>
  );
}

function ArchiveSection({ archive }) {
  return (
    <Box>
      <Typography sx={{ fontSize: 11, color: 'text.tertiary', fontWeight: 600,
        textTransform: 'uppercase', letterSpacing: '0.06em', mb: 0.5 }}>
        Archive · {archive.member_count} members
      </Typography>
      {archive.flags?.length > 0 && archive.flags.slice(0, 5).map((f, i) => (
        <Typography key={i} sx={{ fontSize: 11, color: 'warning.main' }}>⚠ {f}</Typography>
      ))}
      <MuiTable size="small">
        <TableBody>
          {(archive.members || []).slice(0, 15).map((m, i) => (
            <TableRow key={i}>
              <TableCell sx={{ ...monoSx, fontSize: 11 }}>{m.name}</TableCell>
              <TableCell sx={{ fontSize: 11 }}>{m.size}</TableCell>
              <TableCell sx={{ fontSize: 10, color: 'warning.main' }}>{(m.flags || []).join(', ')}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </MuiTable>
    </Box>
  );
}

function ScriptSection({ script }) {
  return (
    <Box>
      <Typography sx={{ fontSize: 11, color: 'text.tertiary', fontWeight: 600,
        textTransform: 'uppercase', letterSpacing: '0.06em', mb: 0.5 }}>
        Script · {script.language}
      </Typography>
      {script.obfuscation_flags?.length > 0 && (
        <Box sx={{ mb: 1 }}>
          {script.obfuscation_flags.map(f => (
            <MuiChip key={f} size="small" label={f.replace(/_/g, ' ')}
              sx={{ mr: 0.5, mb: 0.5, height: 20, fontSize: 10,
                backgroundColor: muiAlpha('#E6700F', 0.2), color: 'warning.main' }}/>
          ))}
        </Box>
      )}
      <Box component="pre" sx={{ ...monoSx, fontSize: 11, m: 0,
        backgroundColor: '#070d19',
        border: `1px solid ${muiAlpha('#ffffff', 0.12)}`,
        borderRadius: '4px', p: 1, maxHeight: 240, overflow: 'auto',
        color: 'text.primary', whiteSpace: 'pre-wrap',
      }}>{(script.source_preview || '').slice(0, 1200)}</Box>
    </Box>
  );
}


// ─── Strings tab ──────────────────────────────────────────────────────────────
function StringsTab({ result }) {
  const [query, setQuery] = useState('');
  const iocs = result.iocs || {};
  const sus  = result.suspicious_strings || [];
  const ascii = result.strings?.ascii_sample || [];
  const uni   = result.strings?.unicode_sample || [];

  const categories = useMemo(() => ({
    'Network Indicators':
      [...(iocs.ips || []).map(v => ({ v, t: 'ip' })),
       ...(iocs.domains || []).map(v => ({ v, t: 'domain' })),
       ...(iocs.urls || []).map(v => ({ v, t: 'url' })),
       ...(iocs.emails || []).map(v => ({ v, t: 'email' }))],
    'File System Paths':    (iocs.paths || []).map(v => ({ v, t: 'path' })),
    'Hashes (in file)':     (iocs.hashes || []).map(v => ({ v, t: 'hash' })),
    'Suspicious Patterns':  sus.map(s => ({ v: s.match, t: s.pattern })),
    'Decoded Payloads':     (iocs.decoded_payloads || []).map(v => ({ v, t: 'decoded' })),
    'All ASCII Strings':    ascii.map(v => ({ v, t: 'ascii' })),
    'All Unicode Strings':  uni.map(v => ({ v, t: 'unicode' })),
  }), [iocs, sus, ascii, uni]);

  const q = query.trim().toLowerCase();

  return (
    <Stack spacing={2}>
      <MuiTextField size="small" fullWidth
        value={query} onChange={e => setQuery(e.target.value)}
        placeholder="Filter strings…"
        InputProps={{ startAdornment: <Search size={14} style={{ marginRight: 6 }}/> }}
        sx={{ '& .MuiInputBase-input': { fontSize: 12 } }}/>
      {Object.entries(categories).map(([title, items]) => {
        const filtered = q
          ? items.filter(i => i.v?.toLowerCase().includes(q))
          : items;
        if (!filtered.length) return null;
        return (
          <Box key={title}>
            <Typography sx={{ fontSize: 11, color: 'text.tertiary', fontWeight: 600,
              textTransform: 'uppercase', letterSpacing: '0.06em', mb: 0.5 }}>
              {title} · {filtered.length}
            </Typography>
            <MuiPaper elevation={0} sx={{ backgroundColor: '#0C1524',
              border: `1px solid ${muiAlpha('#ffffff', 0.12)}`,
              borderRadius: '4px', maxHeight: 240, overflow: 'auto',
            }}>
              {filtered.slice(0, 80).map((item, i) => (
                <Box key={i} sx={{ display: 'grid', gridTemplateColumns: 'auto 1fr auto',
                  gap: 1, p: '4px 10px', alignItems: 'baseline',
                  borderTop: i > 0 ? `1px solid ${muiAlpha('#ffffff', 0.04)}` : 'none',
                }}>
                  <Box sx={{ fontSize: 9, color: 'text.disabled',
                    textTransform: 'uppercase' }}>{item.t}</Box>
                  <Box sx={{ ...monoSx, fontSize: 11, color: 'text.primary',
                    wordBreak: 'break-all' }}>{item.v}</Box>
                  <CopyBtn text={item.v}/>
                </Box>
              ))}
            </MuiPaper>
          </Box>
        );
      })}
    </Stack>
  );
}


// ─── Threat Intel tab ─────────────────────────────────────────────────────────
function ThreatIntelTab({ result }) {
  const ti = result.threat_intel || {};
  return (
    <Stack spacing={2}>
      {ti.virustotal && <VTPanel vt={ti.virustotal}/>}
      {ti.malwarebazaar && <MBPanel mb={ti.malwarebazaar}/>}
      {ti.hybrid_analysis && <SandboxPanel name="Hybrid Analysis" report={ti.hybrid_analysis}/>}
      {ti.anyrun && <SandboxPanel name="ANY.RUN" report={ti.anyrun}/>}
      {ti.case_history?.cases?.length > 0 && (
        <Box>
          <Typography sx={{ fontSize: 11, color: 'text.tertiary', fontWeight: 600,
            textTransform: 'uppercase', letterSpacing: '0.06em', mb: 0.5 }}>
            Related cases ({ti.case_history.related_cases})
          </Typography>
          {ti.case_history.cases.map((c, i) => (
            <MuiPaper key={i} elevation={0} sx={{ backgroundColor: '#0C1524',
              border: `1px solid ${muiAlpha('#ffffff', 0.12)}`,
              borderRadius: '4px', p: 1, mb: 0.5,
            }}>
              <Typography sx={{ fontSize: 12, color: 'text.primary', fontWeight: 600 }}>
                {c.label || c.runId}
                <Box component="span" sx={{ ml: 1, fontSize: 11, color: VERDICT_COLOR[c.threat_level] || 'text.disabled' }}>
                  {c.threat_level}
                </Box>
              </Typography>
              <Typography sx={{ fontSize: 11, color: 'text.tertiary' }}>{c.summary}</Typography>
            </MuiPaper>
          ))}
        </Box>
      )}
      {ti.feed_cache?.hit_count > 0 && (
        <Box>
          <Typography sx={{ fontSize: 11, color: 'warning.main', fontWeight: 600,
            textTransform: 'uppercase', letterSpacing: '0.06em', mb: 0.5 }}>
            Feed cache hits ({ti.feed_cache.hit_count})
          </Typography>
          {ti.feed_cache.hits.slice(0, 10).map((h, i) => (
            <Box key={i} sx={{ fontSize: 11, ...monoSx, color: 'text.primary', py: 0.25 }}>
              {h.ioc} <Box component="span" sx={{ color: 'text.tertiary' }}>· {h.source}</Box>
            </Box>
          ))}
        </Box>
      )}
      {ti.domain_intel?.domains?.length > 0 && (
        <Box>
          <Typography sx={{ fontSize: 11, color: 'text.tertiary', fontWeight: 600,
            textTransform: 'uppercase', letterSpacing: '0.06em', mb: 0.5 }}>
            Domain pivots
          </Typography>
          {ti.domain_intel.domains.map((d, i) => (
            <MuiPaper key={i} elevation={0} sx={{ backgroundColor: '#0C1524',
              border: `1px solid ${muiAlpha('#ffffff', 0.12)}`,
              borderLeft: d.nrd_flag ? '3px solid #E6700F' : undefined,
              borderRadius: '4px', p: 1, mb: 0.5,
            }}>
              <Typography sx={{ ...monoSx, fontSize: 12, color: 'text.primary' }}>{d.domain}</Typography>
              <Typography sx={{ fontSize: 11, color: 'text.tertiary' }}>
                {d.whois_created ? `created ${d.whois_created}` : ''}
                {d.age_days != null ? ` · age ${d.age_days}d` : ''}
                {d.cert_count != null ? ` · ${d.cert_count} certs` : ''}
                {d.nrd_flag ? ` · ⚠ ${d.nrd_flag}` : ''}
              </Typography>
            </MuiPaper>
          ))}
        </Box>
      )}
    </Stack>
  );
}

function VTPanel({ vt }) {
  if (vt.error || !vt.found) return null;
  return (
    <MuiPaper elevation={0} sx={{ backgroundColor: '#0C1524',
      border: `1px solid ${muiAlpha('#ffffff', 0.12)}`,
      borderLeft: vt.malicious > 5 ? '3px solid #EE3838' : '3px solid #848592',
      borderRadius: '4px', p: 1.5 }}>
      <Stack direction="row" alignItems="center" spacing={1}>
        <Typography sx={{ fontSize: 12, fontWeight: 600, color: 'text.primary' }}>
          VirusTotal · {vt.detection_ratio}
        </Typography>
        {vt.malware_family && <MuiChip size="small" label={vt.malware_family}
          sx={{ height: 20, fontSize: 10, backgroundColor: muiAlpha('#EE3838', 0.2), color: 'error.main' }}/>}
      </Stack>
      {vt.tags?.length > 0 && (
        <Typography sx={{ fontSize: 11, color: 'text.tertiary', mt: 0.5 }}>
          Tags: {vt.tags.slice(0, 6).join(', ')}
        </Typography>
      )}
      {vt.engine_verdicts?.length > 0 && (
        <Box sx={{ mt: 1, display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 0.5 }}>
          {vt.engine_verdicts.slice(0, 16).map((e, i) => (
            <Box key={i} sx={{ fontSize: 10, ...monoSx,
              backgroundColor: muiAlpha('#EE3838', 0.06),
              borderLeft: '2px solid #EE3838', p: '2px 6px',
            }}>
              <Box sx={{ color: 'text.disabled' }}>{e.engine}</Box>
              <Box sx={{ color: 'error.main' }}>{e.result}</Box>
            </Box>
          ))}
        </Box>
      )}
    </MuiPaper>
  );
}

function MBPanel({ mb }) {
  if (mb.error || !mb.found) return null;
  return (
    <MuiPaper elevation={0} sx={{ backgroundColor: '#0C1524',
      border: `1px solid ${muiAlpha('#ffffff', 0.12)}`,
      borderLeft: '3px solid #EE3838', borderRadius: '4px', p: 1.5 }}>
      <Typography sx={{ fontSize: 12, fontWeight: 600, color: 'text.primary' }}>
        MalwareBazaar · {mb.malware_family || 'matched'}
      </Typography>
      <Typography sx={{ fontSize: 11, color: 'text.tertiary' }}>
        {mb.file_type} · {mb.file_size} bytes · first seen {mb.first_seen}
        {mb.delivery_method ? ` · delivery: ${mb.delivery_method}` : ''}
      </Typography>
      {mb.yara_rules?.length > 0 && (
        <Typography sx={{ fontSize: 11, color: 'text.tertiary', mt: 0.5 }}>
          YARA: {mb.yara_rules.join(', ')}
        </Typography>
      )}
    </MuiPaper>
  );
}

function SandboxPanel({ name, report }) {
  if (!report || report.error || !report.found) return null;
  return (
    <MuiPaper elevation={0} sx={{ backgroundColor: '#0C1524',
      border: `1px solid ${muiAlpha('#ffffff', 0.12)}`,
      borderLeft: '3px solid #E6700F', borderRadius: '4px', p: 1.5 }}>
      <Stack direction="row" alignItems="center" spacing={1}>
        <Typography sx={{ fontSize: 12, fontWeight: 600, color: 'text.primary' }}>
          {name} sandbox
        </Typography>
        {report.malware_family && <MuiChip size="small" label={report.malware_family}
          sx={{ height: 20, fontSize: 10, backgroundColor: muiAlpha('#EE3838', 0.2), color: 'error.main' }}/>}
        {report.threat_score != null && (
          <Box component="span" sx={{ fontSize: 11, color: 'warning.main' }}>
            score {report.threat_score}
          </Box>
        )}
      </Stack>
      <Typography sx={{ fontSize: 11, color: 'text.tertiary', mt: 0.5 }}>
        verdict {report.verdict} · {report.environment}
      </Typography>
      {report.report_url && (
        <Box component="a" href={report.report_url} target="_blank" rel="noreferrer"
          sx={{ fontSize: 11, color: 'primary.main', textDecoration: 'none',
            display: 'inline-flex', alignItems: 'center', gap: 0.25, mt: 0.5,
            '&:hover': { textDecoration: 'underline' } }}>
          full report <ArrowUpRight size={11}/>
        </Box>
      )}
    </MuiPaper>
  );
}


// ─── MITRE tab ────────────────────────────────────────────────────────────────
function MitreTab({ result }) {
  const cap = result.capabilities || {};
  const techs = cap.mitre_techniques || [];
  if (!techs.length) {
    return (
      <Typography sx={{ fontSize: 12, color: 'text.tertiary' }}>
        No high-confidence MITRE techniques identified from static analysis.
      </Typography>
    );
  }
  // Group by tactic
  const byTactic = {};
  techs.forEach(t => {
    const tac = t.tactic || 'Other';
    (byTactic[tac] = byTactic[tac] || []).push(t);
  });
  return (
    <Stack spacing={2}>
      {Object.entries(byTactic).map(([tactic, items]) => (
        <Box key={tactic}>
          <Typography sx={{ fontSize: 11, color: 'text.tertiary', fontWeight: 600,
            textTransform: 'uppercase', letterSpacing: '0.06em', mb: 0.75 }}>
            {tactic}
          </Typography>
          {items.map((t, i) => (
            <MuiPaper key={i} elevation={0} sx={{ backgroundColor: '#0C1524',
              border: `1px solid ${muiAlpha('#ffffff', 0.12)}`,
              borderLeft: '3px solid #B286FF',
              borderRadius: '4px', p: '10px 12px', mb: 0.75 }}>
              <Stack direction="row" alignItems="center" spacing={1}>
                <Box component="a" href={t.attack_url} target="_blank" rel="noreferrer"
                  sx={{ ...monoSx, fontSize: 12, color: 'primary.main',
                    textDecoration: 'none', '&:hover': { textDecoration: 'underline' } }}>
                  {t.id}
                </Box>
                <Typography sx={{ fontSize: 12, color: 'text.primary', fontWeight: 600 }}>
                  {t.label || t.name}
                </Typography>
              </Stack>
              <Typography sx={{ fontSize: 11, color: 'text.tertiary', mt: 0.5 }}>
                {t.explanation}
              </Typography>
            </MuiPaper>
          ))}
        </Box>
      ))}
    </Stack>
  );
}


// ─── YARA tab ─────────────────────────────────────────────────────────────────
function YaraTab({ result }) {
  const matches = result.yara_matches || [];
  const ai      = result.ai_yara || {};
  const valid   = matches.filter(m => m && !m.error);
  return (
    <Stack spacing={2}>
      <Box>
        <Typography sx={{ fontSize: 11, color: 'text.tertiary', fontWeight: 600,
          textTransform: 'uppercase', letterSpacing: '0.06em', mb: 0.75 }}>
          Matched rules ({valid.length})
        </Typography>
        {valid.length === 0 && (
          <Typography sx={{ fontSize: 12, color: 'text.tertiary' }}>
            No YARA rules matched this file.
          </Typography>
        )}
        {valid.map((m, i) => (
          <MuiPaper key={i} elevation={0} sx={{ backgroundColor: '#0C1524',
            border: `1px solid ${muiAlpha('#ffffff', 0.12)}`,
            borderRadius: '4px', p: '10px 12px', mb: 0.5 }}>
            <Stack direction="row" alignItems="center" spacing={1}>
              <Typography sx={{ ...monoSx, fontSize: 12, color: 'text.primary', fontWeight: 600 }}>
                {m.rule}
              </Typography>
              {m.source && <MuiChip size="small" label={m.source}
                sx={{ height: 18, fontSize: 10, backgroundColor: muiAlpha('#848592', 0.2) }}/>}
            </Stack>
            {m.description && (
              <Typography sx={{ fontSize: 11, color: 'text.tertiary', mt: 0.5 }}>{m.description}</Typography>
            )}
            {m.author && (
              <Typography sx={{ fontSize: 10, color: 'text.disabled' }}>by {m.author}</Typography>
            )}
            {m.matched_strings?.length > 0 && (
              <Box sx={{ ...monoSx, fontSize: 10, color: 'text.primary', mt: 0.5,
                backgroundColor: '#070d19',
                border: `1px solid ${muiAlpha('#ffffff', 0.06)}`,
                borderRadius: '3px', p: '4px 8px',
              }}>
                {m.matched_strings.map((s, j) => (
                  <Box key={j}>
                    <Box component="span" sx={{ color: 'primary.main' }}>{s.id}</Box>
                    {s.offset != null ? ` @ ${s.offset.toString(16)}: ` : ': '}
                    {s.matched}
                  </Box>
                ))}
              </Box>
            )}
          </MuiPaper>
        ))}
      </Box>

      {/* AI-generated rule */}
      {ai.rule && (
        <Box>
          <Stack direction="row" alignItems="center" spacing={1} sx={{ mb: 0.75 }}>
            <Typography sx={{ fontSize: 11, color: 'text.tertiary', fontWeight: 600,
              textTransform: 'uppercase', letterSpacing: '0.06em' }}>
              AI-generated rule for this file
            </Typography>
            <Box component="span" sx={{ fontSize: 10,
              color: ai.valid ? 'success.main' : 'error.main' }}>
              {ai.valid ? '✓ validated' : `✗ ${(ai.errors || []).join('; ').slice(0, 100)}`}
            </Box>
            <Box component="span" sx={{ ml: 'auto !important', fontSize: 10, color: 'text.disabled' }}>
              {ai.attempts} attempt{ai.attempts === 1 ? '' : 's'}
            </Box>
          </Stack>
          <Box component="pre" sx={{ ...monoSx, fontSize: 11, m: 0,
            backgroundColor: '#070d19',
            border: `1px solid ${muiAlpha('#ffffff', 0.12)}`,
            borderRadius: '4px', p: 1, maxHeight: 320, overflow: 'auto',
            color: 'text.primary', whiteSpace: 'pre-wrap',
          }}>{ai.rule}</Box>
          <Stack direction="row" spacing={1} sx={{ mt: 0.75 }}>
            <CopyBtn text={ai.rule}/>
            <MuiButton size="small" variant="outlined"
              onClick={() => downloadText(`recon_${(result.hashes?.sha256 || 'sample').slice(0,8)}.yar`, ai.rule)}>
              Download .yar
            </MuiButton>
          </Stack>
        </Box>
      )}
    </Stack>
  );
}


// ─── Detection content tab ────────────────────────────────────────────────────
function DetectionTab({ result }) {
  const d = result.detections || {};
  const blocks = [
    ['Sigma',     d.sigma?.rule,    d.sigma?.id    ? `id: ${d.sigma.id}` : null],
    ['KQL · Sentinel',  d.kql?.query,   d.kql?.note],
    ['Splunk SPL', d.spl?.query,   d.spl?.note],
    ['Suricata / Snort', d.suricata?.rules, d.suricata?.note],
    ['Volatility / Rekall', d.volatility?.rule,
      d.volatility?.volatility_cmd ? `cmd: ${d.volatility.volatility_cmd}` : null],
  ].filter(([, body]) => body);

  return (
    <Stack spacing={2}>
      {blocks.length === 0 && (
        <Typography sx={{ fontSize: 12, color: 'text.tertiary' }}>
          No detection content generated — IOCs may be missing.
        </Typography>
      )}
      {blocks.map(([title, body, note]) => (
        <Box key={title}>
          <Stack direction="row" alignItems="center" spacing={1} sx={{ mb: 0.5 }}>
            <Typography sx={{ fontSize: 11, color: 'text.tertiary', fontWeight: 600,
              textTransform: 'uppercase', letterSpacing: '0.06em' }}>{title}</Typography>
            {note && <Box component="span" sx={{ fontSize: 10, color: 'text.disabled' }}>{note}</Box>}
            <Box sx={{ ml: 'auto !important' }}><CopyBtn text={body}/></Box>
          </Stack>
          <Box component="pre" sx={{ ...monoSx, fontSize: 11, m: 0,
            backgroundColor: '#070d19',
            border: `1px solid ${muiAlpha('#ffffff', 0.12)}`,
            borderRadius: '4px', p: 1, maxHeight: 260, overflow: 'auto',
            color: 'text.primary', whiteSpace: 'pre-wrap',
          }}>{body}</Box>
        </Box>
      ))}
    </Stack>
  );
}


// ─── Overview tab ─────────────────────────────────────────────────────────────
function OverviewTab({ result }) {
  const cap = result.capabilities || {};
  const v = result.verdict || 'UNKNOWN';
  const conf = result.confidence || 0;
  const vt = result.threat_intel?.virustotal;
  const ti = result.threat_intel || {};
  return (
    <Stack spacing={2}>
      <MuiPaper elevation={0} sx={{ p: 2,
        backgroundColor: muiAlpha(VERDICT_COLOR[v], 0.1),
        border: `1px solid ${muiAlpha(VERDICT_COLOR[v], 0.4)}`,
        borderLeft: `4px solid ${VERDICT_COLOR[v]}`,
        borderRadius: '4px',
      }}>
        <Stack direction="row" alignItems="center" spacing={2}>
          <Typography sx={{ fontSize: 24, fontWeight: 700, color: VERDICT_COLOR[v] }}>
            {v}
          </Typography>
          <Typography sx={{ fontSize: 14, color: 'text.tertiary' }}>
            confidence {conf}%
          </Typography>
        </Stack>
        {cap.plain_english_summary && (
          <Typography sx={{ fontSize: 13, color: 'text.primary', mt: 1, lineHeight: 1.55 }}>
            {cap.plain_english_summary}
          </Typography>
        )}
      </MuiPaper>

      {/* Metric cards */}
      <Box sx={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: 1 }}>
        <MetricCard label="File type" value={result.type?.category} accent="#0fbcff"/>
        <MetricCard label="Size" value={`${((result.size || 0) / 1024).toFixed(1)} KB`}/>
        <MetricCard label="Entropy" value={`${result.entropy?.overall} / 8`}
          accent={result.entropy?.flag === 'high_entropy_packed' ? '#EE3838' : undefined}/>
        <MetricCard label="YARA matches" value={(result.yara_matches || []).filter(m => !m.error).length}
          accent="#B286FF"/>
        <MetricCard label="VT detections"
          value={vt?.detection_ratio || '—'}
          accent={vt?.malicious > 5 ? '#EE3838' : undefined}/>
        <MetricCard label="MITRE techs" value={cap.technique_count || 0} accent="#0fbcff"/>
      </Box>

      {/* Capability badges */}
      {cap.tags?.length > 0 && (
        <Box>
          <Typography sx={{ fontSize: 11, color: 'text.tertiary', fontWeight: 600,
            textTransform: 'uppercase', letterSpacing: '0.06em', mb: 0.75 }}>
            Capabilities identified
          </Typography>
          <Stack direction="row" spacing={0.75} flexWrap="wrap">
            {cap.tags.map(t => (
              <MuiChip key={t} label={t} size="small"
                sx={{ mb: 0.5, backgroundColor: muiAlpha('#EE3838', 0.15),
                  color: 'error.main', fontWeight: 500 }}/>
            ))}
          </Stack>
        </Box>
      )}
    </Stack>
  );
}

function MetricCard({ label, value, accent }) {
  return (
    <MuiPaper elevation={0} sx={{
      backgroundColor: '#0C1524',
      border: `1px solid ${muiAlpha('#ffffff', 0.12)}`,
      borderLeft: accent ? `3px solid ${accent}` : undefined,
      borderRadius: '4px', p: '10px 12px',
    }}>
      <Typography sx={{ fontSize: 10, color: 'text.disabled',
        textTransform: 'uppercase', letterSpacing: '0.05em' }}>{label}</Typography>
      <Typography sx={{ fontSize: 16, color: 'text.primary', fontWeight: 600 }}>
        {value ?? '—'}
      </Typography>
    </MuiPaper>
  );
}


// ─── helpers ──────────────────────────────────────────────────────────────────
function downloadText(name, text) {
  const blob = new Blob([text], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = name; a.click();
  URL.revokeObjectURL(url);
}

function downloadJson(name, obj) {
  downloadText(name, JSON.stringify(obj, null, 2));
}


// ─── main view ────────────────────────────────────────────────────────────────
// Accepts an `external` scan state from App so the sidebar can drive scans
// and have the results render here. When no external props are passed, falls
// back to self-managed state.
export default function FileScannerView({ external, onScanFile, onScanHash, onScanUrl }) {
  const [localResult, setLocalResult] = useState(null);
  const [localScanning, setLocalScanning] = useState(false);
  const [localStep, setLocalStep] = useState(0);
  const [localError, setLocalError] = useState(null);
  const progressTimer = useRef(null);

  // Either consume from props (sidebar-driven) or own state (standalone use)
  const result       = external?.result ?? localResult;
  const scanning     = external?.scanning ?? localScanning;
  const progressStep = external?.progressStep ?? localStep;
  const error        = external?.error ?? localError;

  const startProgress = () => {
    setLocalStep(0);
    let step = 0;
    progressTimer.current = setInterval(() => {
      step = Math.min(step + 1, ANALYSIS_STEPS.length - 1);
      setLocalStep(step);
    }, 700);
  };
  const stopProgress = () => {
    if (progressTimer.current) {
      clearInterval(progressTimer.current);
      progressTimer.current = null;
    }
    setLocalStep(ANALYSIS_STEPS.length);
  };
  useEffect(() => () => stopProgress(), []);

  const scanFile = onScanFile || (async (file) => {
    setLocalScanning(true); setLocalError(null); setLocalResult(null);
    startProgress();
    try {
      const form = new FormData();
      form.append('file', file);
      const r = await fetch('/api/scan/file', { method: 'POST', body: form });
      const d = await r.json();
      if (!r.ok) throw new Error(d.detail || `HTTP ${r.status}`);
      setLocalResult(d);
    } catch (e) {
      setLocalError(e.message);
    } finally {
      stopProgress();
      setLocalScanning(false);
    }
  });

  const scanHash = onScanHash || (async (hash) => {
    setLocalScanning(true); setLocalError(null); setLocalResult(null);
    startProgress();
    try {
      const r = await fetch('/api/scan/hash', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ hash }),
      });
      const d = await r.json();
      if (!r.ok) throw new Error(d.detail || `HTTP ${r.status}`);
      setLocalResult(d);
    } catch (e) {
      setLocalError(e.message);
    } finally {
      stopProgress();
      setLocalScanning(false);
    }
  });

  const scanUrl = onScanUrl || (async (url) => {
    setLocalScanning(true); setLocalError(null); setLocalResult(null);
    startProgress();
    try {
      const r = await fetch('/api/scan/url', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
      });
      const d = await r.json();
      if (!r.ok) throw new Error(d.detail || `HTTP ${r.status}`);
      setLocalResult(d);
    } catch (e) {
      setLocalError(e.message);
    } finally {
      stopProgress();
      setLocalScanning(false);
    }
  });

  // In external mode the sidebar drives submission — show only progress + export
  const sidebarDriven = !!external;

  // Single-column layout when sidebar-driven (no left submission panel needed)
  const gridCols = sidebarDriven ? '1fr' : '320px 1fr';

  return (
    <Box sx={{ display: 'grid', gridTemplateColumns: gridCols, gap: 2, p: 2,
      minHeight: '100vh', backgroundColor: 'background.default' }}>
      {/* Left submission column — hidden when sidebar provides the inputs */}
      {!sidebarDriven && (
        <Box>
          <SubmissionPanel
            onScanFile={scanFile}
            onScanHash={scanHash}
            onScanUrl={scanUrl}
            scanning={scanning}
            progressStep={progressStep}
          />
          {result && (
            <Stack spacing={1} sx={{ mt: 2 }}>
              <MuiButton size="small" variant="outlined"
                onClick={() => downloadJson(`recon_scan_${(result.hashes?.sha256 || 'result').slice(0,8)}.json`, result)}>
                <Download size={12} style={{ marginRight: 6 }}/> Export JSON
              </MuiButton>
            </Stack>
          )}
          {error && (
            <MuiPaper elevation={0} sx={{ mt: 2, p: 1.5,
              backgroundColor: muiAlpha('#EE3838', 0.08),
              border: `1px solid ${muiAlpha('#EE3838', 0.4)}`,
              borderRadius: '4px', color: 'error.main', fontSize: 12,
            }}>{error}</MuiPaper>
          )}
        </Box>
      )}

      {/* Results column */}
      <Box>
        {/* Sidebar-driven progress stepper — shows while scanning */}
        {sidebarDriven && scanning && (
          <MuiPaper elevation={0} sx={{
            backgroundColor: '#0C1524',
            border: `1px solid ${muiAlpha('#ffffff', 0.12)}`,
            borderRadius: '4px', p: 2, mb: 2, maxWidth: 520,
          }}>
            <Typography sx={{ fontSize: 11, color: 'primary.main', fontWeight: 600,
              textTransform: 'uppercase', letterSpacing: '0.06em', mb: 1 }}>
              Analysis in progress
            </Typography>
            {ANALYSIS_STEPS.map((label, i) => {
              const done    = i < progressStep;
              const current = i === progressStep;
              return (
                <Stack key={label} direction="row" alignItems="center" spacing={1} sx={{ py: 0.25 }}>
                  <Box sx={{
                    width: 12, height: 12, borderRadius: 99,
                    backgroundColor: done ? 'success.main' : current ? 'primary.main' : muiAlpha('#ffffff', 0.1),
                    ...(current ? { animation: 'pulse 1.2s ease-in-out infinite' } : {}),
                  }}/>
                  <Typography sx={{
                    fontSize: 11,
                    color: done ? 'success.main' : current ? 'primary.main' : 'text.disabled',
                    fontWeight: current ? 600 : 400,
                  }}>{label}</Typography>
                </Stack>
              );
            })}
            <LinearProgress sx={{ mt: 1, height: 3, borderRadius: 99 }}
              variant="determinate" value={(progressStep / ANALYSIS_STEPS.length) * 100}/>
          </MuiPaper>
        )}
        {/* Sidebar-driven export button — shows when there's a result */}
        {sidebarDriven && result && (
          <Stack direction="row" justifyContent="flex-end" sx={{ mb: 1.5 }}>
            <MuiButton size="small" variant="outlined"
              onClick={() => downloadJson(`recon_scan_${(result.hashes?.sha256 || 'result').slice(0,8)}.json`, result)}>
              <Download size={12} style={{ marginRight: 6 }}/> Export JSON
            </MuiButton>
          </Stack>
        )}
        {/* Sidebar-driven error display */}
        {sidebarDriven && error && (
          <MuiPaper elevation={0} sx={{ p: 1.5, mb: 1.5,
            backgroundColor: muiAlpha('#EE3838', 0.08),
            border: `1px solid ${muiAlpha('#EE3838', 0.4)}`,
            borderRadius: '4px', color: 'error.main', fontSize: 12,
          }}>{error}</MuiPaper>
        )}
        {!result && !scanning && (
          <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'center',
            height: '60vh', color: 'text.disabled' }}>
            <Shield size={64} color="#252A35"/>
          </Box>
        )}
        {result && (
          <Stack spacing={4}>
            {[
              { id: 'overview', label: 'Overview',          Comp: OverviewTab },
              { id: 'hashes',   label: 'Hashes',            Comp: HashesTab },
              { id: 'details',  label: 'File Details',      Comp: FileDetailsTab },
              { id: 'strings',  label: 'Strings',           Comp: StringsTab },
              { id: 'ti',       label: 'Threat Intel',      Comp: ThreatIntelTab },
              { id: 'mitre',    label: 'MITRE ATT&CK',      Comp: MitreTab },
              { id: 'yara',     label: 'YARA',              Comp: YaraTab },
              { id: 'detect',   label: 'Detection Content', Comp: DetectionTab },
            ].map(({ id, label, Comp }) => (
              <Box key={id}>
                <Typography sx={{
                  fontSize: 11, color: 'text.tertiary', fontWeight: 600,
                  textTransform: 'uppercase', letterSpacing: '0.08em',
                  mb: 1.5, pb: 1,
                  borderBottom: `1px solid ${muiAlpha('#ffffff', 0.12)}`,
                }}>{label}</Typography>
                <Comp result={result}/>
              </Box>
            ))}
          </Stack>
        )}
      </Box>
    </Box>
  );
}
