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
  crypto:  '#E1B823',  // warning yellow — crypto payment address (BTC/ETH/XMR)
};
const IOC_TYPE_LABEL = {
  ips: 'ip', domains: 'domain', hashes: 'hash', urls: 'url', emails: 'email',
  files: 'file', paths: 'path', crypto: 'crypto',
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
// Visual identity is the always-on accent left border; on hover the card gains
// a subtle background tint and the title brightens, but layout never shifts
// (the old hover handler bumped the border from 1px to 3px which caused a
// 2px content-jitter every time the cursor crossed the card edge).
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
  const titleColor = accent || 'text.tertiary';
  return (
    <MuiCard
      sx={{
        marginBottom: '12px',
        position: 'relative',
        overflow: 'hidden',
        // Persistent accent stripe — gives each card a visual identity
        // when scanning the page without needing a hover state.
        borderLeft: accent
          ? `3px solid ${accent}`
          : `1px solid ${alpha('#ffffff', 0.12)}`,
        transition: 'background-color 0.15s ease, border-color 0.15s ease',
        '&:hover': {
          backgroundColor: alpha('#ffffff', 0.015),
          '& .recon-card-title': {
            color: accent || '#F2F2F3',
          },
        },
      }}
    >
      <CardHeader
        title={title}
        action={badge !== null && (
          <Typography variant="caption" sx={{
            color: accent ? alpha(accent, 0.85) : 'text.tertiary',
            fontSize: 11,
            fontWeight: 500,
            paddingRight: 1.5,
            textTransform: 'lowercase',
            letterSpacing: '0.04em',
          }}>
            {badge}
          </Typography>
        )}
        onClick={collapsible ? () => setOpen(o => !o) : undefined}
        avatar={collapsible
          ? (open
              ? <ExpandMoreOutlined sx={{ fontSize: 16, color: titleColor,
                  opacity: 0.75, transition: 'opacity 0.15s ease' }}/>
              : <ChevronRightOutlined sx={{ fontSize: 16, color: titleColor,
                  opacity: 0.75, transition: 'opacity 0.15s ease' }}/>)
          : null}
        sx={{
          padding: '11px 16px',
          cursor: collapsible ? 'pointer' : 'default',
          borderBottom: open ? `1px solid ${alpha('#ffffff', 0.08)}` : 'none',
          userSelect: 'none',
          '& .MuiCardHeader-avatar': { marginRight: 1 },
          '& .MuiCardHeader-title': {
            fontSize: 12,
            fontWeight: 600,
            textTransform: 'uppercase',
            letterSpacing: '0.08em',
            color: titleColor,
            transition: 'color 0.15s ease',
          },
        }}
        titleTypographyProps={{ className: 'recon-card-title' }}
      />
      <Collapse in={open} unmountOnExit>
        <CardContent sx={noPad
          ? { padding: '0 !important' }
          : { padding: '14px 16px 16px 16px',
              '&:last-child': { paddingBottom: '16px' } }}>
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
    <Box sx={{ marginBottom: 1.75 }}>
      {title && (
        <Typography variant="caption" sx={{
          display: 'block', marginBottom: 0.75,
          fontSize: 10.5, fontWeight: 600,
          color: accent || 'text.tertiary',
          textTransform: 'uppercase', letterSpacing: '0.08em',
        }}>
          {title}
        </Typography>
      )}
      <Box sx={{
        backgroundColor: theme.palette.background.secondary,
        border: `1px solid ${alpha('#ffffff', 0.08)}`,
        borderLeft: accent ? `2px solid ${alpha(accent, 0.6)}`
                            : `1px solid ${alpha('#ffffff', 0.08)}`,
        borderRadius: '4px',
        padding: '10px 14px',
      }}>
        {children}
      </Box>
    </Box>
  );
};

// ─── Row — flex row with subtle top divider, used inside Blocks ─────────────
export const Row = ({ children, sx = {} }) => {
  return (
    <Box sx={{
      display: 'flex', gap: 1.25, padding: '6px 0',
      borderTop: `1px solid ${alpha('#ffffff', 0.05)}`,
      fontSize: 13, color: 'text.primary', lineHeight: 1.5,
      alignItems: 'flex-start',
      '&:first-of-type': { borderTop: 'none', paddingTop: 0 },
      '&:last-of-type':  { paddingBottom: 0 },
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
