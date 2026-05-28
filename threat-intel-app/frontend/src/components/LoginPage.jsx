/**
 * Full-screen login gate. Renders BEFORE the main App when /api/auth/me
 * returns 401. Submits username + password to /api/auth/login (cookie auth,
 * so credentials: 'include' on every fetch).
 *
 * Layout: dead-centered card with the RECON logo above the form. Same OpenCTI
 * dark palette as the rest of the app (cyan accent + Plex Mono inputs) so the
 * login screen doesn't feel like a different product.
 */
import React, { useState, useRef, useEffect } from 'react';
import {
  Box, Stack, Typography, TextField as MuiTextField,
  Button as MuiButton, CircularProgress, Paper as MuiPaper,
} from '@mui/material';
import { alpha as muiAlpha } from '@mui/material/styles';
import { AlertCircle } from 'lucide-react';

export default function LoginPage({ onAuthed }) {
  const [username, setUsername]   = useState('');
  const [password, setPassword]   = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError]         = useState(null);
  const userRef = useRef(null);

  useEffect(() => { userRef.current?.focus(); }, []);

  const submit = async (e) => {
    e?.preventDefault?.();
    if (!username.trim() || !password) {
      setError('Username and password are required.');
      return;
    }
    setSubmitting(true); setError(null);
    try {
      const r = await fetch('/api/auth/login', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: username.trim(), password }),
      });
      if (!r.ok) {
        const d = await r.json().catch(() => ({}));
        if (r.status === 401) throw new Error('Invalid username or password.');
        if (r.status === 503) throw new Error('Authentication is not configured on this deployment.');
        throw new Error(d.detail || `HTTP ${r.status}`);
      }
      const d = await r.json();
      onAuthed?.(d.user || username.trim());
    } catch (err) {
      setError(err.message || 'Login failed.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Box sx={{
      minHeight: '100vh', width: '100vw',
      backgroundColor: 'background.default',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      p: 2,
    }}>
      <MuiPaper elevation={0} sx={{
        width: '100%', maxWidth: 420,
        backgroundColor: 'background.paper',
        border: theme => `1px solid ${muiAlpha('#ffffff', 0.12)}`,
        borderRadius: '6px',
        p: { xs: 3, sm: '36px 40px 32px' },
      }}>
        {/* Logo */}
        <Box sx={{ display: 'flex', justifyContent: 'center', mb: 3 }}>
          <Box component="img" src="/logo.png" alt="RECON"
            sx={{ width: '100%', maxWidth: 260, height: 'auto', display: 'block',
              filter: 'drop-shadow(0 0 18px rgba(15,188,255,0.35))' }}/>
        </Box>

        {/* Form */}
        <Box component="form" onSubmit={submit}>
          <Stack spacing={1.75}>
            <Box>
              <Typography sx={{ fontSize: 10, color: 'text.tertiary',
                fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em',
                mb: 0.5,
              }}>
                Username
              </Typography>
              <MuiTextField
                inputRef={userRef}
                value={username}
                onChange={e => setUsername(e.target.value)}
                placeholder="username"
                fullWidth
                size="small"
                autoComplete="username"
                InputProps={{ sx: { fontFamily: '"IBM Plex Mono", monospace', fontSize: 13 } }}
                disabled={submitting}
              />
            </Box>
            <Box>
              <Typography sx={{ fontSize: 10, color: 'text.tertiary',
                fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em',
                mb: 0.5,
              }}>
                Password
              </Typography>
              <MuiTextField
                value={password}
                onChange={e => setPassword(e.target.value)}
                type="password"
                placeholder="••••••••"
                fullWidth
                size="small"
                autoComplete="current-password"
                InputProps={{ sx: { fontFamily: '"IBM Plex Mono", monospace', fontSize: 13 } }}
                disabled={submitting}
              />
            </Box>

            {error && (
              <Stack direction="row" alignItems="center" spacing={0.75}
                sx={{ color: 'error.main', fontSize: 12, mt: 0.5 }}>
                <AlertCircle size={13}/>
                <Typography sx={{ fontSize: 12 }}>{error}</Typography>
              </Stack>
            )}

            <MuiButton
              type="submit"
              variant="contained"
              fullWidth
              disabled={submitting}
              startIcon={submitting ? <CircularProgress size={14} sx={{ color: 'inherit' }}/> : null}
              sx={{ textTransform: 'none', fontSize: 13, fontWeight: 600,
                py: 1.25, mt: 0.5 }}
            >
              {submitting ? 'Signing in…' : 'Sign in'}
            </MuiButton>
          </Stack>
        </Box>
      </MuiPaper>
    </Box>
  );
}
