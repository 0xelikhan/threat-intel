/**
 * Toast notifications subscribed to the API-client error bus.
 *
 * Subscribes to `onApiError` from utils/api.js. Each API failure that
 * doesn't pass `suppressToast: true` appears as a dismissible card in
 * the bottom-right corner with:
 *   * the human-readable error message
 *   * the X-Request-ID for log correlation (when present)
 *   * a Retry button (re-fires the original request callback when
 *     supplied via err._retry — most call sites don't set this and
 *     the button is omitted)
 *   * a fix hint when the backend included one (Section 5 registry)
 *
 * Mount once at the App root. Auto-stacks up to 4 toasts; older ones
 * fall off when newer ones arrive.
 */
import React, { useEffect, useState, useCallback } from 'react';
import { Box, Stack, Typography, IconButton as MuiIconButton, Button as MuiButton } from '@mui/material';
import { alpha as muiAlpha } from '@mui/material/styles';
import { AlertCircle, X, RefreshCcw } from 'lucide-react';

import { onApiError } from '../utils/api';


const _MAX_TOASTS = 4;
const _AUTO_DISMISS_MS = 12_000;


export default function ToastHost() {
  const [toasts, setToasts] = useState([]);

  const dismiss = useCallback((id) => {
    setToasts(p => p.filter(t => t.id !== id));
  }, []);

  useEffect(() => {
    const off = onApiError(err => {
      const id = Math.random().toString(36).slice(2);
      const t = {
        id,
        message:   err.message || 'API request failed',
        requestId: err.requestId,
        status:    err.status,
        fixHint:   err.fixHint,
        retry:     err._retry || null,
      };
      setToasts(p => [...p, t].slice(-_MAX_TOASTS));
      setTimeout(() => dismiss(id), _AUTO_DISMISS_MS);
    });
    return off;
  }, [dismiss]);

  if (!toasts.length) return null;

  return (
    <Box sx={{
      position: 'fixed',
      bottom: 16,
      right: 16,
      zIndex: 9999,
      display: 'flex',
      flexDirection: 'column',
      gap: 1.25,
      maxWidth: 'min(420px, calc(100vw - 32px))',
      pointerEvents: 'none',
    }}>
      {toasts.map(t => {
        const accent = (t.status || 0) >= 500 ? '#ff8c00' : '#ff6b6b';
        return (
          <Box key={t.id} sx={{
            pointerEvents: 'auto',
            backgroundColor: '#0d1f30',
            border: `1px solid ${muiAlpha(accent, 0.4)}`,
            borderLeft: `4px solid ${accent}`,
            borderRadius: '4px',
            boxShadow: '0 8px 24px rgba(0,0,0,0.4)',
            p: '12px 14px',
          }}>
            <Stack direction="row" alignItems="flex-start" spacing={1.25}>
              <AlertCircle size={16} color={accent} style={{ marginTop: 2, flexShrink: 0 }}/>
              <Box sx={{ flex: 1, minWidth: 0 }}>
                <Typography sx={{ fontSize: 13, fontWeight: 600,
                  color: accent, mb: 0.25 }}>
                  Request failed{t.status ? ` · ${t.status}` : ''}
                </Typography>
                <Typography sx={{ fontSize: 12.5, color: 'text.primary',
                  lineHeight: 1.5, wordBreak: 'break-word' }}>
                  {t.message}
                </Typography>
                {t.fixHint && (
                  <Typography sx={{ fontSize: 11.5, color: 'text.tertiary',
                    lineHeight: 1.5, mt: 0.5 }}>
                    {t.fixHint}
                  </Typography>
                )}
                {t.requestId && (
                  <Typography sx={{ fontSize: 10.5, color: 'text.tertiary',
                    fontFamily: '"IBM Plex Mono", monospace', mt: 0.75,
                    opacity: 0.7 }}>
                    rid: {t.requestId.slice(0, 12)}
                  </Typography>
                )}
                {t.retry && (
                  <MuiButton size="small" variant="text"
                    onClick={() => { t.retry(); dismiss(t.id); }}
                    startIcon={<RefreshCcw size={11}/>}
                    sx={{ textTransform: 'none', fontSize: 11.5, mt: 0.5,
                      color: accent }}>
                    Retry
                  </MuiButton>
                )}
              </Box>
              <MuiIconButton
                onClick={() => dismiss(t.id)}
                size="small"
                sx={{ p: 0.25, color: 'text.tertiary',
                  '&:hover': { color: 'text.primary' } }}>
                <X size={14}/>
              </MuiIconButton>
            </Stack>
          </Box>
        );
      })}
    </Box>
  );
}
