/**
 * Adapted from OpenCTI (AGPL-3.0) github.com/OpenCTI-Platform/opencti
 *
 * Direct port of ThemeDark.ts + AppThemeProvider.tsx token values and
 * MuiComponent overrides. Every value in this file is copied from the OpenCTI
 * source so RECON inherits the exact OpenCTI dark-theme look across all MUI
 * components automatically.
 *
 * Reference files studied:
 *   opencti-platform/opencti-front/src/components/ThemeDark.ts
 *   opencti-platform/opencti-front/src/components/AppThemeProvider.tsx
 *   opencti-platform/opencti-front/src/components/common/tag/Tag.tsx
 *   opencti-platform/opencti-front/src/private/components/nav/LeftBar.jsx
 *
 * To use: wrap the app in <ThemeProvider theme={theme}> and add <CssBaseline/>.
 * Inline-styled legacy components keep working — only MUI components inherit.
 */

import { createTheme } from '@mui/material/styles';

// ─── Hex → rgba helper (matches OpenCTI's hexToRGB) ─────────────────────────
const hexToRGB = (hex, opacity = 1) => {
  const h = hex.replace('#', '');
  const r = parseInt(h.length === 3 ? h[0] + h[0] : h.slice(0, 2), 16);
  const g = parseInt(h.length === 3 ? h[1] + h[1] : h.slice(2, 4), 16);
  const b = parseInt(h.length === 3 ? h[2] + h[2] : h.slice(4, 6), 16);
  return `rgba(${r}, ${g}, ${b}, ${opacity})`;
};

// ─── Exact colour tokens copied from ThemeDark.ts ───────────────────────────
export const THEME_DARK_DEFAULT_BACKGROUND = '#070d19';
export const THEME_DARK_DEFAULT_PRIMARY    = '#0fbcff';
export const THEME_DARK_DEFAULT_SECONDARY  = '#00f18d';
export const THEME_DARK_DEFAULT_ACCENT     = '#0f1e38';
export const THEME_DARK_DEFAULT_PAPER      = '#09101e';
export const THEME_DARK_DEFAULT_TEXT       = '#F2F2F3';
export const THEME_DARK_DEFAULT_NAV        = '#070d19';
export const THEME_DARK_DIALOG_BACKGROUND  = '#0F1D34';
const EE_COLOR = '#00f18d';

const background = THEME_DARK_DEFAULT_BACKGROUND;
const paper      = THEME_DARK_DEFAULT_PAPER;
const nav        = THEME_DARK_DEFAULT_NAV;
const accent     = THEME_DARK_DEFAULT_ACCENT;
const primary    = THEME_DARK_DEFAULT_PRIMARY;
const secondary  = THEME_DARK_DEFAULT_SECONDARY;
const text_color = THEME_DARK_DEFAULT_TEXT;

// ─── MUI theme — every override below ported from OpenCTI ───────────────────
const theme = createTheme({
  borderRadius: 4,
  palette: {
    mode: 'dark',
    common: { white: '#ffffff', grey: '#95969D', lightGrey: '#E4E5E7' },
    error:   { main: '#F14337', dark: '#881106' },
    success: { main: '#17AB1F', dark: '#094E0B' },
    warning: { main: '#E6700F' },
    primary: {
      main:  primary,
      light: '#B2ECFF',
      dark:  '#007399',
    },
    secondary: { main: secondary },
    background: {
      default:   background,
      paper:     paper,
      nav:       nav,
      accent:    accent,
      shadow:    'rgba(200, 200, 200, 0.15)',
      secondary: '#0C1524',
      drawer:    '#0f1d34',
      disabled:  '#363B46',
    },
    text: {
      primary:   text_color,
      secondary: text_color,
      tertiary:  '#848592',
      disabled:  '#75829A',
    },
    border: {
      main:       '#252A35',
      primary:    hexToRGB(primary, 0.3),
      secondary:  '#424751',
      paper:      hexToRGB('#ffffff', 0.12),
      pagination: hexToRGB('#ffffff', 0.5),
    },
    severity: {
      critical: '#EE3838',
      high:     '#E6700F',
      medium:   '#E1B823',
      low:      '#16AD34',
      info:     '#1565c0',
      none:     '#424242',
      default:  '#1C2F49',
    },
    leftBar: {
      header:        { itemBackground: '#253348' },
      popoverItem:   '#070D19',
      hover:         '#253348',
      text:          text_color,
    },
    chip: { main: '#ffffff' },
    ai: {
      main:    '#B286FF',
      light:   '#D6C2FA',
      dark:    '#5E1AD5',
      contrastText: '#000000',
      background: 'rgba(28, 47, 73, 0.94)',
    },
    ee: {
      main: EE_COLOR,
      contrastText: text_color,
      background:   hexToRGB(EE_COLOR, 0.2),
    },
  },

  // Typography — IBM Plex Sans body, fallbacks for headings (we don't ship Geologica)
  typography: {
    fontFamily: '"IBM Plex Sans", -apple-system, BlinkMacSystemFont, sans-serif',
    body1:    { fontSize: '0.9rem', color: text_color },
    body2:    { fontSize: '0.8rem', lineHeight: '1.2rem', color: text_color },
    overline: { fontWeight: 500, color: text_color },
    h1: { margin: '0 0 10px 0', padding: 0, fontWeight: 400, fontSize: 22, color: text_color },
    h2: { margin: '0 0 10px 0', padding: 0, fontWeight: 500, fontSize: 16, color: text_color },
    h3: { margin: '0 0 10px 0', padding: 0, fontWeight: 400, fontSize: 13, color: text_color },
    h4: { height: 15, margin: '0 0 10px 0', padding: 0, fontSize: 12, fontWeight: 500, color: text_color },
    h5: { fontWeight: 700, fontSize: 16, color: text_color },
    h6: { fontWeight: 600, fontSize: 14, color: text_color },
    subtitle2: { fontWeight: 400, fontSize: 18, color: text_color },
  },

  components: {
    // ─── Cards / Paper ────────────────────────────────────────────────────
    MuiCard: {
      styleOverrides: {
        root: {
          backgroundColor: paper,
          backgroundImage: 'none',
          color: text_color,
          borderRadius: 4,
          border: `1px solid ${hexToRGB('#ffffff', 0.12)}`,
          boxShadow: 'none',
        },
      },
    },
    MuiPaper: {
      styleOverrides: {
        root: {
          backgroundColor: paper,
          backgroundImage: 'none',
          color: text_color,
        },
      },
    },
    MuiCardHeader: {
      styleOverrides: {
        root: {
          padding: '12px 16px',
          borderBottom: `1px solid ${hexToRGB('#ffffff', 0.12)}`,
        },
        title: {
          fontSize: 12,
          fontWeight: 500,
          textTransform: 'uppercase',
          letterSpacing: '0.06em',
          color: '#848592',
        },
      },
    },
    MuiCardContent: {
      styleOverrides: {
        root: { padding: 16, '&:last-child': { paddingBottom: 16 } },
      },
    },

    // ─── Chip — adapted from Tag.tsx (lowercase, soft alpha bg) ──────────
    MuiChip: {
      styleOverrides: {
        root: {
          height: 25,
          borderRadius: 4,
          fontSize: 12,
          fontWeight: 400,
          paddingLeft: 8,
          color: text_color,
          textTransform: 'lowercase',
          '&::first-letter': { textTransform: 'uppercase' },
        },
        label: {
          paddingLeft: 4,
          paddingRight: 12,
          textTransform: 'lowercase',
          '&::first-letter': { textTransform: 'uppercase' },
        },
      },
    },

    // ─── Buttons ─────────────────────────────────────────────────────────
    MuiButton: {
      styleOverrides: {
        root: {
          borderRadius: 4,
          textTransform: 'none',
          fontWeight: 600,
          fontSize: 14,
          height: 36,
          padding: '8px 16px',
          minWidth: 36,
          '&.MuiButton-outlinedSizeSmall': { padding: '4px 9px' },
          '&.icon-outlined': {
            borderColor: hexToRGB('#ffffff', 0.15),
            padding: 7,
            minWidth: 0,
            '&:hover': {
              borderColor: hexToRGB('#ffffff', 0.15),
              backgroundColor: hexToRGB('#ffffff', 0.05),
            },
          },
        },
        sizeSmall: {
          height: 26,
          padding: '4px 12px',
          minWidth: 26,
          fontSize: 13,
        },
      },
    },
    MuiIconButton: {
      styleOverrides: {
        root: {
          borderRadius: 4,
          color: text_color,
          '&:hover': { backgroundColor: hexToRGB('#ffffff', 0.05) },
        },
      },
    },

    // ─── Drawer (sidebar) ────────────────────────────────────────────────
    MuiDrawer: {
      styleOverrides: {
        paper: {
          backgroundColor: nav,
          backgroundImage: 'none',
          borderRight: `1px solid ${hexToRGB('#ffffff', 0.12)}`,
        },
      },
    },

    // ─── Tabs / Tab ──────────────────────────────────────────────────────
    MuiTab: {
      styleOverrides: {
        root: {
          textTransform: 'lowercase',
          fontSize: 13,
          fontWeight: 500,
          minHeight: 40,
          '&::first-letter': { textTransform: 'uppercase' },
          '&.Mui-selected': { color: primary },
        },
      },
    },
    MuiTabs: {
      styleOverrides: {
        indicator: { backgroundColor: primary, height: 2 },
      },
    },

    // ─── Form / inputs (standard variant per OpenCTI) ───────────────────
    MuiFormControl:  { defaultProps: { variant: 'standard' }, styleOverrides: { root: { color: text_color } } },
    MuiTextField: {
      defaultProps: { variant: 'standard' },
      styleOverrides: {
        root: {
          color: text_color,
          '& .MuiFormLabel-root:not(.MuiInputLabel-shrink):not(.Mui-error)': { color: '#AFB0B6' },
        },
      },
    },
    MuiSelect: {
      defaultProps: { variant: 'standard' },
      styleOverrides: {
        root: { color: text_color, '& fieldset': { border: 'none' } },
        outlined: { backgroundColor: '#0C1524' },
      },
    },
    MuiInputBase: { styleOverrides: { root: { color: text_color } } },
    MuiOutlinedInput: {
      styleOverrides: {
        root: {
          backgroundColor: '#0d2137',
          borderRadius: 4,
          '& .MuiOutlinedInput-notchedOutline': { borderColor: '#252A35' },
          '&:hover .MuiOutlinedInput-notchedOutline': { borderColor: hexToRGB(primary, 0.5) },
          '&.Mui-focused .MuiOutlinedInput-notchedOutline': { borderColor: primary },
        },
      },
    },

    // ─── Dialogs ─────────────────────────────────────────────────────────
    MuiDialog: {
      styleOverrides: {
        paper: { backgroundImage: 'none', backgroundColor: THEME_DARK_DIALOG_BACKGROUND, borderRadius: 4 },
      },
    },
    MuiDialogTitle:   { defaultProps: { variant: 'h5' } },
    MuiDialogActions: {
      styleOverrides: {
        root: ({ theme }) => ({
          gap: theme.spacing(1), padding: 0,
          marginTop: theme.spacing(4), marginLeft: 0,
          '& .MuiButton-root': { textTransform: 'none' },
          '& > :not(style) ~ :not(style)': { marginLeft: 0 },
        }),
      },
    },

    // ─── Lists / Menus ──────────────────────────────────────────────────
    MuiList: {
      styleOverrides: {
        root: { paddingTop: 0, paddingBottom: 0 },
      },
    },
    MuiListItemButton: {
      styleOverrides: {
        root: {
          height: 35,
          fontWeight: 500,
          fontSize: 14,
          borderRadius: 0,
          '&:hover': { backgroundColor: '#253348' },
          '&.Mui-selected': {
            boxShadow: `2px 0 ${primary} inset`,
            backgroundColor: hexToRGB(primary, 0.24),
            '&:hover': {
              boxShadow: `2px 0 ${primary} inset`,
              backgroundColor: hexToRGB(primary, 0.32),
            },
          },
        },
      },
    },
    MuiListItemIcon: {
      styleOverrides: {
        root: { color: text_color, minWidth: 32 },
      },
    },
    MuiListItemText: {
      styleOverrides: {
        primary:   { fontSize: 14, fontWeight: 500 },
        secondary: { fontSize: 12, color: '#848592' },
      },
    },
    MuiMenuItem: {
      styleOverrides: {
        root: {
          '&.Mui-selected': {
            boxShadow: `2px 0 ${primary} inset`,
            backgroundColor: hexToRGB(primary, 0.24),
          },
          '&.Mui-selected:hover': {
            boxShadow: `2px 0 ${primary} inset`,
            backgroundColor: hexToRGB(primary, 0.32),
          },
        },
      },
    },

    // ─── Tooltips ────────────────────────────────────────────────────────
    MuiTooltip: {
      styleOverrides: {
        tooltip: { backgroundColor: 'rgba(0,0,0,0.7)', fontSize: 12 },
        arrow:   { color: 'rgba(0,0,0,0.7)' },
      },
    },

    // ─── Tables — compact, 1px border lines, no whitespace ───────────────
    MuiTable: {
      styleOverrides: {
        root: { borderCollapse: 'separate' },
      },
    },
    MuiTableCell: {
      styleOverrides: {
        root: { fontSize: 13, padding: '8px 12px' },
        head: { borderBottom: `1px solid ${hexToRGB('#ffffff', 0.15)}`, color: '#848592',
                fontWeight: 500, fontSize: 12, textTransform: 'uppercase', letterSpacing: '0.04em' },
        body: { borderTop: `1px solid ${hexToRGB('#ffffff', 0.15)}`,
                borderBottom: `1px solid ${hexToRGB('#ffffff', 0.15)}` },
      },
    },
    MuiTableRow: {
      styleOverrides: {
        root: {
          '&:hover': { backgroundColor: hexToRGB('#ffffff', 0.03) },
          '&.MuiTableRow-hover:hover': { backgroundColor: hexToRGB('#ffffff', 0.04) },
        },
      },
    },

    // ─── ToggleButtonGroup (view toggles) ────────────────────────────────
    MuiToggleButtonGroup: {
      defaultProps: { size: 'small' },
      styleOverrides: {
        root: {
          height: 36,
          '& .MuiTouchRipple-root': { display: 'none' },
          '& .MuiToggleButton-root': {
            border: '1px solid #2B3447',
            color: primary,
            textTransform: 'none',
            '&:focus-visible': { outline: 'none', boxShadow: '0 0 0 2px #BDFFED' },
            '&.Mui-selected':   { backgroundColor: hexToRGB(primary, 0.25) },
            '&:hover:not(.Mui-selected)': { backgroundColor: hexToRGB(primary, 0.15) },
          },
        },
      },
    },

    // ─── Accordions ──────────────────────────────────────────────────────
    MuiAccordion: {
      defaultProps: { slotProps: { transition: { unmountOnExit: true } } },
      styleOverrides: {
        root: {
          backgroundImage: 'none',
          backgroundColor: paper,
          borderRadius: 4,
          border: `1px solid ${hexToRGB('#ffffff', 0.12)}`,
          '&::before': { display: 'none' },
        },
      },
    },

    // ─── Divider ─────────────────────────────────────────────────────────
    MuiDivider: {
      styleOverrides: {
        root: { borderColor: hexToRGB('#ffffff', 0.12) },
      },
    },

    // ─── Typography — lowercase global ──────────────────────────────────
    MuiTypography: {
      styleOverrides: {
        root: { color: text_color, textTransform: 'none' },
      },
    },

    // ─── Autocomplete ────────────────────────────────────────────────────
    MuiAutocomplete: {
      styleOverrides: {
        root: {
          '& .MuiFormLabel-root:not(.MuiInputLabel-shrink):not(.Mui-error)': { color: '#AFB0B6' },
          '& .MuiOutlinedInput-root': {
            backgroundColor: '#0C1524',
            '& fieldset': { borderColor: 'transparent' },
          },
        },
      },
    },

    // ─── CssBaseline — global body / scrollbar / code blocks ────────────
    MuiCssBaseline: {
      styleOverrides: {
        html: {
          scrollbarColor: `${background} ${accent}`,
          scrollbarWidth: 'thin',
          backgroundColor: background,
        },
        body: {
          background: `linear-gradient(100deg, ${background} 0%, #08101D 100%)`,
          backgroundAttachment: 'fixed',
          backgroundColor: background,
          scrollbarColor: `${background} ${accent}`,
          scrollbarWidth: 'thin',
          color: text_color,
          a: { color: primary },
          pre: {
            fontFamily: '"IBM Plex Mono", Consolas, monospace',
            color: `${text_color} !important`,
            background: `${accent} !important`,
            borderRadius: 4,
          },
          code: {
            fontFamily: '"IBM Plex Mono", Consolas, monospace',
            color: `${text_color} !important`,
            background: `${accent} !important`,
            padding: 3,
            fontSize: 12,
            fontWeight: 400,
            borderRadius: 4,
          },
          '.leaflet-container': { backgroundColor: `${paper} !important` },
        },
      },
    },
  },
});

export default theme;
