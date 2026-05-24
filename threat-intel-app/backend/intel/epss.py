"""
EPSS — Exploit Prediction Scoring System (FIRST.org).
Daily-updated score per CVE: probability of exploitation in next 30 days.
Pairs perfectly with CISA KEV — KEV tells you it IS exploited,
EPSS tells you HOW LIKELY others will be exploited.
"""
import csv
from pathlib import Path
from functools import lru_cache

EPSS_CSV = Path(__file__).parent.parent.parent / "vendor" / "epss_scores.csv"


@lru_cache(maxsize=1)
def _index() -> dict:
    """Load EPSS CSV → {CVE-XXXX-YYYY: {epss, percentile, date}}."""
    if not EPSS_CSV.exists():
        return {}
    out: dict = {}
    try:
        with EPSS_CSV.open("r", encoding="utf-8", errors="ignore") as f:
            # Skip metadata header (first line starts with #model_version)
            first = f.readline()
            if not first.startswith("cve"):
                pass  # the # line — header is next
            reader = csv.DictReader(f)
            # The reader's first record might be the header again if we mis-skipped
            for row in reader:
                cve = (row.get("cve") or "").strip().upper()
                if not cve.startswith("CVE-"):
                    continue
                try:
                    out[cve] = {
                        "epss":       float(row.get("epss") or 0),
                        "percentile": float(row.get("percentile") or 0),
                    }
                except (TypeError, ValueError):
                    continue
    except Exception:
        return {}
    return out


def get(cve: str) -> dict | None:
    """Return {epss, percentile} for a CVE, or None if unknown."""
    e = _index().get(cve.upper().strip())
    if not e:
        return None
    score = e["epss"]
    return {
        "epss":           round(score, 4),
        "epss_percent":   round(score * 100, 1),
        "percentile":     round(e["percentile"] * 100, 1),
        "tier":           ("critical" if score >= 0.7
                            else "high" if score >= 0.3
                            else "medium" if score >= 0.05
                            else "low"),
    }


def enrich_kev_entries(kev_hits: list[dict]) -> list[dict]:
    """Add EPSS data to each KEV entry in-place + return."""
    for k in kev_hits:
        e = get(k.get("cve", ""))
        if e:
            k["epss"] = e
    return kev_hits


def stats() -> dict:
    idx = _index()
    return {"epss_count": len(idx), "epss_loaded": EPSS_CSV.exists()}
