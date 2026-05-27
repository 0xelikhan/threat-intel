/**
 * Adapted from OpenCTI (AGPL-3.0) github.com/OpenCTI-Platform/opencti
 *
 * Reusable MUI-based primitives used across every RECON view.
 * Inherits styling from theme.js (which is itself ported from OpenCTI's
 * ThemeDark.ts + AppThemeProvider.tsx), so every component automatically
 * matches the OpenCTI look — paper colour, border, chip alpha background,
 * lowercase casing, IBM Plex Sans typography.
 *
 * Reference: opencti-front/src/components/common/tag/Tag.tsx
 *            opencti-front/src/components/ItemSeverity.tsx
 *            opencti-front/src/components/ItemConfidence.tsx
 */

import React, { useState } from 'react';
import {
  Card as MuiCard,
  CardHeader,
  CardContent,
  Chip as MuiChip,
  Box,
  Stack,
  Typography,
  IconButton,
  Tooltip,
  alpha,
  useTheme,
  Collapse,
} from '@mui/material';
import {
  ContentCopyOutlined,
  CheckOutlined,
  ExpandMoreOutlined,
  ChevronRightOutlined,
} from '@mui/icons-material';

// ─── Tag — ported from OpenCTI's Tag.tsx ────────────────────────────────────
// Soft alpha background of the chip color (severity / verdict / type indicator)
export const Tag = ({
  label,
  color,
  icon,
  onClick,
  onDelete,
  size = 'small',
  sx = {},
  ...rest
}) => {
  const theme = useTheme();
  const fallback = theme.palette.severity?.default ?? '#1C2F49';
  const bgColor = color ? alpha(color, 0.2) : fallback;
  return (
    <MuiChip
      label={label}
      icon={icon}
      onClick={onClick}
      onDelete={onDelete}
      size={size}
      sx={{
        borderRadius: '4px',
        fontSize: 12,
        fontWeight: 400,
        height: 25,
        backgroundColor: bgColor,
        color: color || theme.palette.text.primary,
        '& .MuiChip-label': {
          paddingLeft: '8px',
          paddingRight: '12px',
          textTransform: 'lowercase',
          '&::first-letter': { textTransform: 'uppercase' },
        },
        ...sx,
      }}
      {...rest}
    />
  );
};

// ─── Severity chip — adapted from ItemSeverity.tsx ──────────────────────────
export const SeverityTag = ({ severity, label }) => {
  const theme = useTheme();
  if (!severity) return null;
  const colorMap = {
    critical: theme.palette.severity.critical,
    high:     theme.palette.severity.high,
    medium:   theme.palette.severity.medium,
    low:      theme.palette.severity.low,
    info:     theme.palette.severity.info,
  };
  const color = colorMap[severity?.toLowerCase()] || theme.palette.severity.default;
  return <Tag label={label || severity} color={color}/>;
};

// ─── Verdict chip — for MALICIOUS / SUSPICIOUS / CLEAN / UNKNOWN ────────────
export const VerdictTag = ({ verdict, size }) => {
  const theme = useTheme();
  if (!verdict) return null;
  const colorMap = {
    MALICIOUS:  theme.palette.severity.critical,
    SUSPICIOUS: theme.palette.severity.high,
    CLEAN:      theme.palette.severity.low,
    BENIGN:     theme.palette.severity.low,
    UNKNOWN:    theme.palette.text.tertiary,
    UNDETECTED: theme.palette.text.tertiary,
  };
  return <Tag label={verdict} color={colorMap[verdict] || theme.palette.severity.default} size={size}/>;
};

// ─── IOC type tag — IP / DOMAIN / HASH / URL / EMAIL ────────────────────────
const IOC_TYPE_COLOR = {
  ips:     '#0fbcff',  // primary
  domains: '#17AB1F',  // success
  hashes:  '#B286FF',  // ai purple
  urls:    '#E6700F',  // high orange
  emails:  '#F14337',  // error red
};
const IOC_TYPE_LABEL = {
  ips: 'ip', domains: 'domain', hashes: 'hash', urls: 'url', emails: 'email',
  files: 'file', paths: 'path',
};
export const TypeTag = ({ type }) => (
  <Tag
    label={IOC_TYPE_LABEL[type] || type}
    color={IOC_TYPE_COLOR[type] || '#848592'}
  />
);

// Lets a parent set the default open/closed state for every Card beneath it
// (e.g. collapse all analysis sections on completion) without each Card needing
// an explicit prop. An explicit `defaultOpen` on a Card still wins.
export const CardDefaultOpenContext = React.createContext(true);

// ─── Card — collapsible MUI Card matching OpenCTI's panel pattern ───────────
export const Card = ({
  title,
  accent,
  badge = null,
  children,
  defaultOpen,
  noPad = false,
  collapsible = true,
}) => {
  const ctxDefaultOpen = React.useContext(CardDefaultOpenContext);
  const [open, setOpen] = useState(defaultOpen ?? ctxDefaultOpen);
  const theme = useTheme();
  return (
    <MuiCard
      sx={{
        marginBottom: '10px',
        // Subtle left-border accent stripe on hover (OpenCTI pattern)
        position: 'relative',
        '&:hover': accent
          ? { borderLeftColor: accent, borderLeftWidth: '3px', paddingLeft: '0' }
          : undefined,
      }}
    >
      <CardHeader
        title={title}
        action={badge !== null && (
          <Typography variant="caption" sx={{ color: 'text.tertiary', fontSize: 12, paddingRight: 1.5 }}>
            {badge}
          </Typography>
        )}
        onClick={collapsible ? () => setOpen(o => !o) : undefined}
        avatar={collapsible
          ? (open ? <ExpandMoreOutlined sx={{ fontSize: 16, color: accent || 'text.tertiary' }}/>
                  : <ChevronRightOutlined sx={{ fontSize: 16, color: accent || 'text.tertiary' }}/>)
          : null}
        sx={{
          padding: '10px 16px',
          cursor: collapsible ? 'pointer' : 'default',
          borderBottom: open ? `1px solid ${alpha('#ffffff', 0.12)}` : 'none',
          '& .MuiCardHeader-avatar': { marginRight: 1 },
          '& .MuiCardHeader-title': {
            fontSize: 12,
            fontWeight: 500,
            textTransform: 'uppercase',
            letterSpacing: '0.06em',
            color: accent || 'text.tertiary',
          },
        }}
      />
      <Collapse in={open} unmountOnExit>
        <CardContent sx={noPad ? { padding: '0 !important' } : { padding: 2 }}>
          {children}
        </CardContent>
      </Collapse>
    </MuiCard>
  );
};

// ─── Block — inner section panel inside a Card ──────────────────────────────
export const Block = ({ title, children, accent }) => {
  const theme = useTheme();
  return (
    <Box sx={{ marginBottom: 1.5 }}>
      {title && (
        <Typography variant="caption" sx={{
          display: 'block', marginBottom: 1,
          fontSize: 11, fontWeight: 500,
          color: accent || 'text.tertiary',
          textTransform: 'uppercase', letterSpacing: '0.06em',
        }}>
          {title}
        </Typography>
      )}
      <Box sx={{
        backgroundColor: theme.palette.background.secondary,
        border: `1px solid ${alpha('#ffffff', 0.12)}`,
        borderRadius: '4px',
        padding: '8px 12px',
      }}>
        {children}
      </Box>
    </Box>
  );
};

// ─── Row — flex row with subtle top divider, used inside Blocks ─────────────
export const Row = ({ children, sx = {} }) => {
  const theme = useTheme();
  return (
    <Box sx={{
      display: 'flex', gap: 1, padding: '5px 0',
      borderTop: `1px solid ${alpha('#ffffff', 0.06)}`,
      fontSize: 13, color: 'text.primary',
      alignItems: 'flex-start',
      '&:first-of-type': { borderTop: 'none' },
      ...sx,
    }}>
      {children}
    </Box>
  );
};

// ─── CodeBlock — pre block for Sigma/KQL/JSON ──────────────────────────────
export const CodeBlock = ({ children, maxHeight = 300 }) => {
  const theme = useTheme();
  return (
    <Box component="pre" sx={{
      backgroundColor: theme.palette.background.default,
      border: `1px solid ${alpha('#ffffff', 0.12)}`,
      borderRadius: '4px',
      padding: '12px 14px',
      fontSize: 12,
      fontFamily: '"IBM Plex Mono", Consolas, monospace',
      color: 'text.primary',
      overflow: 'auto',
      whiteSpace: 'pre-wrap',
      wordBreak: 'break-word',
      maxHeight,
      margin: 0,
      lineHeight: 1.65,
    }}>
      {children}
    </Box>
  );
};

// ─── CopyBtn — small copy-to-clipboard button ──────────────────────────────
export const CopyBtn = ({ text, label = 'Copy' }) => {
  const [copied, setCopied] = useState(false);
  return (
    <Tooltip title={copied ? 'Copied' : 'Copy to clipboard'}>
      <IconButton
        size="small"
        onClick={() => {
          navigator.clipboard.writeText(text);
          setCopied(true);
          setTimeout(() => setCopied(false), 2000);
        }}
        sx={{
          padding: '4px',
          color: copied ? 'success.main' : 'text.tertiary',
          '&:hover': { color: 'primary.main' },
        }}
      >
        {copied ? <CheckOutlined sx={{ fontSize: 16 }}/> : <ContentCopyOutlined sx={{ fontSize: 16 }}/>}
      </IconButton>
    </Tooltip>
  );
};

// ─── SectionHeader — small uppercase label inside a card ────────────────────
export const SectionLabel = ({ children, color = 'text.tertiary', sx = {} }) => (
  <Typography variant="caption" sx={{
    fontSize: 11, fontWeight: 500,
    color, textTransform: 'uppercase', letterSpacing: '0.06em',
    display: 'block', marginBottom: 0.5,
    ...sx,
  }}>
    {children}
  </Typography>
);
