/**
 * Full-screen login gate. Renders BEFORE the main App when /api/auth/me
 * returns 401. Submits username + password to /api/auth/login (cookie auth,
 * so credentials: 'include' on every fetch).
 *
 * Layout: dead-centered card with a prominent RECON logo above the form. A
 * soft radial cyan glow on the background pulls focus toward the card, and
 * the card itself uses a subtle gradient border so it doesn't feel like a
 * flat rectangle floating on the dark canvas.
 */
import React, { useState, useRef, useEffect } from 'react';
import {
  Box, Stack, Typography, TextField as MuiTextField,
  Button as MuiButton, CircularProgress, Paper as MuiPaper,
} from '@mui/material';
import { alpha as muiAlpha } from '@mui/material/styles';
import { AlertCircle, Lock } from 'lucide-react';
import { cookieFetch } from '../utils/api';

export default function LoginPage({ onAuthed }) {
  const [username, setUsername]     = useState('');
  const [password, setPassword]     = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError]           = useState(null);
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
      const r = await cookieFetch('/api/auth/login', {
        method: 'POST',
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
      // Soft cyan glow behind the card. Two radial gradients (one centred,
      // one offset bottom-right) give the canvas depth without distracting
      // from the form. Pure CSS — no extra DOM, no asset cost.
      backgroundImage: `
        radial-gradient(ellipse at 50% 35%, ${muiAlpha('#0fbcff', 0.10)} 0%, transparent 55%),
        radial-gradient(ellipse at 80% 90%, ${muiAlpha('#0fbcff', 0.06)} 0%, transparent 60%)
      `,
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      p: 2,
    }}>
      <MuiPaper elevation={0} sx={{
        width: '100%', maxWidth: 500,
        backgroundColor: 'background.paper',
        position: 'relative',
        border: theme => `1px solid ${muiAlpha('#ffffff', 0.10)}`,
        borderRadius: '8px',
        p: { xs: '32px 28px 28px', sm: '44px 52px 36px' },
        // Subtle layered shadows + a hairline cyan accent above the card so it
        // reads as "lifted" not "stamped on."
        boxShadow: `
          0 0 0 1px ${muiAlpha('#0fbcff', 0.06)},
          0 20px 60px -20px rgba(0, 0, 0, 0.6),
          0 0 80px -40px ${muiAlpha('#0fbcff', 0.4)}
        `,
        '&::before': {
          content: '""',
          position: 'absolute', top: 0, left: '15%', right: '15%', height: '1px',
          background: `linear-gradient(90deg, transparent, ${muiAlpha('#0fbcff', 0.6)}, transparent)`,
        },
      }}>
        {/* Logo — significantly larger than before so it owns the upper half
            of the card. Soft cyan drop-shadow ties it to the background glow. */}
        <Box sx={{ display: 'flex', justifyContent: 'center', mb: 4.5 }}>
          <Box component="img" src="/logo.png" alt="RECON"
            sx={{
              width: '100%',
              maxWidth: { xs: 320, sm: 400 },
              height: 'auto', display: 'block',
              filter: 'drop-shadow(0 0 28px rgba(15, 188, 255, 0.45))',
            }}/>
        </Box>

        {/* Form */}
        <Box component="form" onSubmit={submit}>
          <Stack spacing={2.25}>
            <Box>
              <Typography sx={{
                fontSize: 10, color: 'text.tertiary',
                fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.1em',
                mb: 0.75,
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
                InputProps={{
                  sx: {
                    fontFamily: '"IBM Plex Mono", monospace',
                    fontSize: 13,
                    transition: 'all .15s ease',
                  },
                }}
                disabled={submitting}
              />
            </Box>
            <Box>
              <Typography sx={{
                fontSize: 10, color: 'text.tertiary',
                fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.1em',
                mb: 0.75,
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
                InputProps={{
                  sx: {
                    fontFamily: '"IBM Plex Mono", monospace',
                    fontSize: 13,
                    transition: 'all .15s ease',
                  },
                }}
                disabled={submitting}
              />
            </Box>

            {error && (
              <Stack direction="row" alignItems="flex-start" spacing={1}
                sx={{
                  color: 'error.main',
                  backgroundColor: muiAlpha('#EE3838', 0.08),
                  border: theme => `1px solid ${muiAlpha('#EE3838', 0.25)}`,
                  borderRadius: '4px',
                  px: 1.25, py: 0.875,
                }}>
                <AlertCircle size={13} style={{ marginTop: 2, flexShrink: 0 }}/>
                <Typography sx={{ fontSize: 12, lineHeight: 1.45 }}>{error}</Typography>
              </Stack>
            )}

            <MuiButton
              type="submit"
              variant="contained"
              fullWidth
              disabled={submitting}
              startIcon={submitting
                ? <CircularProgress size={14} sx={{ color: 'inherit' }}/>
                : <Lock size={14}/>}
              sx={{
                textTransform: 'none',
                fontSize: 13,
                fontWeight: 600,
                letterSpacing: '0.04em',
                py: 1.4,
                mt: 0.75,
                boxShadow: `0 6px 20px -10px ${muiAlpha('#0fbcff', 0.6)}`,
                '&:hover': {
                  boxShadow: `0 8px 24px -10px ${muiAlpha('#0fbcff', 0.75)}`,
                },
              }}
            >
              {submitting ? 'Signing in…' : 'Sign in'}
            </MuiButton>
          </Stack>
        </Box>
      </MuiPaper>
    </Box>
  );
}
