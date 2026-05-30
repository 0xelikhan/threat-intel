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
 * Special handling for ChunkLoadError (React.lazy chunk fetches that 404
 * after a redeploy invalidated the chunk hashes referenced by the old
 * cached index.html): switches to a "reload page" recovery path and
 * auto-reloads after a short delay since retrying without a fresh
 * index.html is guaranteed to fail again.
 *
 * Section 1 requirement: every top-level view wraps its own ErrorBoundary,
 * every major panel within a view wraps its own ErrorBoundary, so a crash
 * in one place never blanks the whole platform.
 */
import React from 'react';
import { Box, Stack, Typography, Button as MuiButton } from '@mui/material';
import { alpha as muiAlpha } from '@mui/material/styles';
import { AlertTriangle, RefreshCcw, Copy, X, RotateCw } from 'lucide-react';


// Module-level guard — make sure we only auto-reload ONCE per session so
// a chunk that's genuinely 404ing on the server doesn't put us in a
// reload loop. sessionStorage is checked before triggering.
const _RELOAD_KEY = 'recon:chunkloaderr:reloaded';


// ChunkLoadError detection. webpack throws errors with name "ChunkLoadError"
// and messages like "Loading chunk 633 failed". Match either name OR
// message so we catch the case across bundler versions.
function _isChunkLoadError(err) {
  if (!err) return false;
  const name = String(err.name || '');
  const msg  = String(err.message || err);
  return (
    name === 'ChunkLoadError'
    || /loading chunk\s+\S+\s+failed/i.test(msg)
    || /loading css chunk\s+\S+\s+failed/i.test(msg)
    || /failed to fetch dynamically imported module/i.test(msg)
  );
}


class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { error: null, info: null, hidden: false, copied: false };
    this._reloadTimer = null;
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

    // ChunkLoadError auto-reload: the browser is holding a stale index.html
    // that references a chunk hash the new deployment no longer has. The
    // only fix is to fetch the new index.html, so trigger a hard reload —
    // but only ONCE per session (guarded by sessionStorage) so we don't
    // loop if the chunk is genuinely missing on the server.
    if (_isChunkLoadError(error)) {
      try {
        const alreadyReloaded = sessionStorage.getItem(_RELOAD_KEY) === '1';
        if (!alreadyReloaded) {
          sessionStorage.setItem(_RELOAD_KEY, '1');
          // Brief delay so the analyst can see what happened, then reload.
          this._reloadTimer = setTimeout(() => this._hardReload(), 2500);
        }
      } catch { /* sessionStorage may be locked */ }
    }
  }

  componentWillUnmount() {
    if (this._reloadTimer) clearTimeout(this._reloadTimer);
  }

  retry = () => {
    if (this._reloadTimer) { clearTimeout(this._reloadTimer); this._reloadTimer = null; }
    // For ChunkLoadError, "Retry" means reload the page — no other path
    // can succeed when index.html is stale.
    if (_isChunkLoadError(this.state.error)) {
      this._hardReload();
      return;
    }
    this.setState({ error: null, info: null, hidden: false, copied: false });
  };

  _hardReload = () => {
    try {
      // Cache-bust the index.html itself by adding a noise param.
      const u = new URL(window.location.href);
      u.searchParams.set('_recon_reload', Date.now().toString(36));
      window.location.replace(u.toString());
    } catch {
      window.location.reload();
    }
  };

  hide = () => {
    if (this._reloadTimer) { clearTimeout(this._reloadTimer); this._reloadTimer = null; }
    this.setState({ hidden: true });
  };

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
      `UA: ${typeof navigator !== 'undefined' ? navigator.userAgent : '?'}`,
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

    const isChunk = _isChunkLoadError(this.state.error);
    const accent = isChunk ? '#0fbcff' : '#ff8c00';   // cyan for "stale build", orange for real crash
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
          {isChunk
            ? <RotateCw size={16} color={accent}/>
            : <AlertTriangle size={16} color={accent}/>}
          <Typography sx={{ fontSize: 13, fontWeight: 700, color: accent,
            textTransform: 'uppercase', letterSpacing: '0.06em' }}>
            {isChunk ? 'RECON was updated — reloading' : `${label} crashed`}
          </Typography>
        </Stack>

        {isChunk ? (
          <>
            <Typography sx={{ fontSize: 13, color: 'text.primary',
              lineHeight: 1.55, mb: 1 }}>
              A new version of RECON was deployed since you opened this tab,
              so the browser tried to load a file that no longer exists.
              The page will reload automatically with the latest version
              in a moment.
            </Typography>
            <Typography sx={{ fontSize: 11, color: 'text.tertiary',
              lineHeight: 1.5, mb: 1.5,
              fontFamily: '"IBM Plex Mono", monospace' }}>
              {msg}
            </Typography>
            <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
              <MuiButton
                size="small" variant="contained"
                onClick={this._hardReload}
                startIcon={<RefreshCcw size={13}/>}
                sx={{ textTransform: 'none' }}>
                Reload now
              </MuiButton>
              <MuiButton
                size="small" variant="text"
                onClick={this.hide}
                startIcon={<X size={13}/>}
                sx={{ textTransform: 'none', color: 'text.tertiary' }}>
                Stay on this page
              </MuiButton>
            </Stack>
          </>
        ) : (
          <>
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
          </>
        )}
      </Box>
    );
  }
}


export default ErrorBoundary;
