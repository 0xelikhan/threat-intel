"""
trickest/cve PoC index loader.

Source: https://github.com/trickest/cve (MIT). A community-maintained
catalog of CVEs with public proof-of-concept exploit links. Each CVE
is a markdown file at `<YYYY>/CVE-YYYY-XXXX.md` containing references
to GitHub repos, exploit-db entries, gist URLs, and articles
demonstrating exploitation.

This index gives RECON a much sharper "weaponisation" signal than
EPSS alone — "EPSS = X%" is probability, but "5 public PoCs exist on
GitHub today" is reality.

We walk the cloned repo at `vendor/trickest-cve/`, parse each markdown
for URLs in the `## Github` and `## References` sections, and build:

  by_cve: {CVE-2023-1234: [{url, source: "github"|"reference"}, ...]}
"""

from __future__ import annotations

import logging
import re
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

_log = logging.getLogger("recon.intel.cve_pocs")

_TRICKEST_ROOT = (Path(__file__).parent.parent.parent
                  / "vendor" / "trickest-cve")

_CVE_FILENAME_RE = re.compile(r"^(CVE-\d{4}-\d{4,7})\.md$", re.IGNORECASE)
_URL_RE          = re.compile(r"https?://[^\s\)\]\"']+", re.IGNORECASE)

_lock  = threading.Lock()
_state: Dict[str, Any] = {
    "loaded":   False,
    "by_cve":   {},
    "total":    0,
    "error":    None,
}


def _classify_source(url: str) -> str:
    u = url.lower()
    if "github.com" in u:    return "github"
    if "gitlab.com" in u:    return "gitlab"
    if "exploit-db.com" in u or "exploitdb" in u: return "exploitdb"
    if "packetstormsecurity" in u: return "packetstorm"
    if "gist.github" in u:   return "gist"
    return "reference"


def _build_index() -> None:
    if not _TRICKEST_ROOT.exists():
        _state["error"]  = f"trickest-cve dir not present at {_TRICKEST_ROOT}"
        _state["loaded"] = True
        return

    by_cve: Dict[str, List[Dict[str, str]]] = {}
    total = 0

    # Layout is <year>/CVE-YYYY-XXXX.md
    for year_dir in _TRICKEST_ROOT.iterdir():
        if not year_dir.is_dir() or not year_dir.name.isdigit():
            continue
        for path in year_dir.iterdir():
            if not path.is_file():
                continue
            m = _CVE_FILENAME_RE.match(path.name)
            if not m:
                continue
            cve_id = m.group(1).upper()
            try:
                if path.stat().st_size > 256_000:
                    continue
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            urls: List[Dict[str, str]] = []
            seen: set = set()
            for um in _URL_RE.finditer(text):
                u = um.group(0).rstrip(".,);]")
                if u in seen or len(u) > 240:
                    continue
                seen.add(u)
                urls.append({"url": u, "source": _classify_source(u)})
                if len(urls) >= 12:
                    break
            if urls:
                by_cve[cve_id] = urls
                total += 1

    _state["by_cve"] = by_cve
    _state["total"]  = total
    _state["loaded"] = True
    _state["error"]  = None
    _log.info("trickest-cve PoC index loaded: %d CVEs", total)


def _ensure_loaded() -> None:
    if _state["loaded"]:
        return
    with _lock:
        if not _state["loaded"]:
            _build_index()


def lookup(cve_id: str, max_results: int = 8) -> List[Dict[str, str]]:
    _ensure_loaded()
    if not cve_id:
        return []
    rows = (_state.get("by_cve") or {}).get(cve_id.upper().strip(), [])
    return rows[:max_results]


def stats() -> Dict[str, Any]:
    _ensure_loaded()
    return {
        "loaded": bool(_state["loaded"]),
        "cves":   _state.get("total", 0),
        "error":  _state.get("error"),
    }
