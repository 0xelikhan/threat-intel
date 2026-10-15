/**
 * Theme bootstrap. Fonts bundled via @fontsource — no Google Fonts CDN.
 * Current theme (Nucleon Cyber aesthetic) uses Inter + JetBrains Mono.
 * IBM Plex is kept as a fallback for the OpenCTI-ported MUI overrides
 * until all component CSS has migrated.
 */
import React from 'react';
import ReactDOM from 'react-dom/client';

// Inter — UI / body / headings
import '@fontsource/inter/300.css';
import '@fontsource/inter/400.css';
import '@fontsource/inter/500.css';
import '@fontsource/inter/600.css';
import '@fontsource/inter/700.css';
import '@fontsource/inter/800.css';
import '@fontsource/inter/900.css';

// JetBrains Mono — code / data / IPs / hashes / timestamps
import '@fontsource/jetbrains-mono/400.css';
import '@fontsource/jetbrains-mono/500.css';
import '@fontsource/jetbrains-mono/600.css';

// IBM Plex (legacy fallback — ported OpenCTI overrides still name it)
import '@fontsource/ibm-plex-sans/300.css';
import '@fontsource/ibm-plex-sans/400.css';
import '@fontsource/ibm-plex-sans/500.css';
import '@fontsource/ibm-plex-sans/600.css';
import '@fontsource/ibm-plex-sans/700.css';
import '@fontsource/ibm-plex-mono/400.css';
import '@fontsource/ibm-plex-mono/500.css';

import { ThemeProvider } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';

import './index.css';
import theme from './theme';
import App from './App';

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
  <React.StrictMode>
    <ThemeProvider theme={theme}>
      <CssBaseline/>
      <App/>
    </ThemeProvider>
  </React.StrictMode>
);
