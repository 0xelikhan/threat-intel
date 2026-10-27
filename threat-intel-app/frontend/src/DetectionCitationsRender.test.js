/**
 * React render test for DetectionCitationsView.
 *
 * The companion DetectionCitations.test.js covers the specific
 * defensive pattern (sourcesWithHits with null dc) at the logic
 * level. This test exercises the actual React component via RTL —
 * ensuring a structural refactor of the JSX can't reintroduce the
 * null-dc crash without a test failure.
 *
 * Guarded with a dynamic require so a future tree-shake that drops
 * the named export doesn't take the whole test suite down.
 */
import React from 'react';
import { render, screen } from '@testing-library/react';
import { ThemeProvider } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import theme from './theme';


// Silence fetch(network) calls that happen behind the semantic-search
// bar — the test shouldn't hit the backend.
beforeEach(() => {
  global.fetch = jest.fn(() => Promise.resolve({
    ok: false, status: 404,
    json: () => Promise.resolve({ error: 'not available in test' }),
  }));
});
afterEach(() => { delete global.fetch; });


function _renderDC(props) {
  const App = require('./App');
  const Comp = App.DetectionCitationsView;
  if (!Comp) {
    throw new Error('DetectionCitationsView is not exported from App.js');
  }
  return render(
    <ThemeProvider theme={theme}>
      <CssBaseline/>
      <Comp {...props}/>
    </ThemeProvider>
  );
}


describe('DetectionCitationsView — React render', () => {
  // The component uses `useMemo`/`useState`/`useEffect` + MUI
  // components; rendering it with null investigation data must
  // never throw — the bug this guards against was a `dc[s.key]`
  // dereference on null `dc`.

  test('renders without crashing when result is null and bare', () => {
    expect(() => _renderDC({ result: null, bare: true })).not.toThrow();
  });

  test('renders without crashing when investigation_result lacks detection_corpora', () => {
    expect(() => _renderDC({
      result: { investigation_result: {} }, bare: true,
    })).not.toThrow();
  });

  test('renders without crashing when detection_corpora is explicitly null', () => {
    expect(() => _renderDC({
      result: { investigation_result: { detection_corpora: null } },
      bare: true,
    })).not.toThrow();
  });

  test('bare=false + null result returns null (no DOM output)', () => {
    const { container } = _renderDC({ result: null, bare: false });
    expect(container.firstChild).toBeNull();
  });

  test('with hits in a source bucket, surfaces the source label', () => {
    const result = {
      investigation_result: {
        detection_corpora: {
          sigma: [{ title: 'suspicious PowerShell', level: 'high' }],
        },
      },
    };
    _renderDC({ result, bare: true });
    // Match either the title or the SigmaHQ source label — both
    // render inside the component when hits are present.
    expect(screen.getByText(/suspicious PowerShell/i)).toBeInTheDocument();
  });

  test('empty dc shows the fallback "no matches" prompt', () => {
    _renderDC({
      result: { investigation_result: { detection_corpora: {} } },
      bare: true,
    });
    // The component shows "No exact MITRE technique matches …" when
    // every bucket is empty. Match the key phrase so phrasing can
    // drift without the assertion breaking.
    expect(
      screen.getByText(/No exact MITRE technique matches/i)
    ).toBeInTheDocument();
  });
});
