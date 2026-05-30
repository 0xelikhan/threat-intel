/**
 * ErrorBoundary — catches unhandled errors in a subtree and renders a
 * friendly recovery panel matching the RECON dark/cyan aesthetic.
 *
 * Usage (wrap a top-level view OR a major panel within a view):
 *   <ErrorBoundary label="File Scanner">
 *     <FileScannerView ... />
 *   </ErrorBoundary>
 *
 * The boundary surfaces three actions to the analyst:
 *   1. Retry — resets the boundary so the child re-renders fresh.
 *   2. Copy Error — copies error + componentStack to clipboard for reporting.
 *   3. Continue Without — hides the broken panel so the rest of the page works.
 *
 * Section 1 requirement: every top-level view wraps its own ErrorBoundary,
 * every major panel within a view wraps its own ErrorBoundary, so a crash
 * in one place never blanks the whole platform.
 */
import React from 'react';
import { Box, Stack, Typography, Button as MuiButton } from '@mui/material';
import { alpha as muiAlpha } from '@mui/material/styles';
import { AlertTriangle, RefreshCcw, Copy, X } from 'lucide-react';


class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { error: null, info: null, hidden: false, copied: false };
  }

  static getDerivedStateFromError(error) {
    return { error };
  }

  componentDidCatch(error, info) {
    this.setState({ info });
    try {
      // eslint-disable-next-line no-console
      console.error(`[ErrorBoundary:${this.props.label || 'unnamed'}]`, error, info?.componentStack);
    } catch { /* console may be locked down */ }
  }

  retry = () => this.setState({ error: null, info: null, hidden: false, copied: false });
  hide  = () => this.setState({ hidden: true });

  copyError = () => {
    const { error, info } = this.state;
    const text = [
      `[RECON ErrorBoundary] ${this.props.label || 'unnamed'}`,
      `Error: ${error?.name || 'Error'}: ${error?.message || String(error)}`,
      'Stack:',
      String(error?.stack || '(no stack)'),
      'Component stack:',
      String(info?.componentStack || '(no component stack)'),
      `Time: ${new Date().toISOString()}`,
      `Path: ${typeof window !== 'undefined' ? window.location.pathname : '?'}`,
    ].join('\n');
    try {
      navigator.clipboard.writeText(text);
      this.setState({ copied: true });
      setTimeout(() => this.setState({ copied: false }), 2000);
    } catch { /* clipboard not available */ }
  };

  render() {
    if (this.state.hidden) return null;
    if (!this.state.error) return this.props.children;

    const accent = '#ff8c00';
    const label  = this.props.label || 'this section';
    const msg    = this.state.error?.message || String(this.state.error);

    return (
      <Box sx={{
        m: 1.5,
        backgroundColor: muiAlpha(accent, 0.05),
        border: `1px solid ${muiAlpha(accent, 0.35)}`,
        borderLeft: `4px solid ${accent}`,
        borderRadius: '4px',
        p: '14px 16px',
      }}>
        <Stack direction="row" alignItems="center" spacing={1} sx={{ mb: 1 }}>
          <AlertTriangle size={16} color={accent}/>
          <Typography sx={{ fontSize: 13, fontWeight: 700, color: accent,
            textTransform: 'uppercase', letterSpacing: '0.06em' }}>
            {label} crashed
          </Typography>
        </Stack>

        <Typography sx={{ fontSize: 13, color: 'text.primary',
          lineHeight: 1.55, mb: 1, fontFamily: '"IBM Plex Mono", monospace' }}>
          {msg}
        </Typography>

        <Typography sx={{ fontSize: 12, color: 'text.tertiary',
          mb: 1.5, lineHeight: 1.5 }}>
          The rest of the platform is still working. You can retry this
          section, copy the technical details for a bug report, or continue
          without it.
        </Typography>

        <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
          <MuiButton
            size="small" variant="contained"
            onClick={this.retry}
            startIcon={<RefreshCcw size={13}/>}
            sx={{ textTransform: 'none' }}>
            Retry
          </MuiButton>
          <MuiButton
            size="small" variant="outlined"
            onClick={this.copyError}
            startIcon={<Copy size={13}/>}
            sx={{ textTransform: 'none' }}>
            {this.state.copied ? 'Copied' : 'Copy error'}
          </MuiButton>
          <MuiButton
            size="small" variant="text"
            onClick={this.hide}
            startIcon={<X size={13}/>}
            sx={{ textTransform: 'none', color: 'text.tertiary' }}>
            Continue without this section
          </MuiButton>
        </Stack>
      </Box>
    );
  }
}


export default ErrorBoundary;
