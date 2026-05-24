"""
CISA Known Exploited Vulnerabilities catalog.
1,600+ CVEs that are CONFIRMED actively exploited in the wild — when one
shows up in an alert, it's not theoretical.
"""
import json
from pathlib import Path
from functools import lru_cache

KEV_FILE = Path(__file__).parent.parent.parent / "vendor" / "cisa-kev.json"
CVE_RE   = r"CVE-\d{4}-\d{4,7}"


@lru_cache(maxsize=1)
def _index() -> dict:
    """Build CVE → KEV entry index."""
    if not KEV_FILE.exists():
        return {}
    try:
        data = json.loads(KEV_FILE.read_text(encoding="utf-8"))
        return {v["cveID"]: v for v in data.get("vulnerabilities", [])}
    except Exception:
        return {}


def lookup(cve: str) -> dict | None:
    """Return KEV metadata if the CVE is in the catalog, else None."""
    entry = _index().get(cve.upper().strip())
    if not entry:
        return None
    return {
        "cve":              entry.get("cveID"),
        "vendor":           entry.get("vendorProject"),
        "product":          entry.get("product"),
        "name":             entry.get("vulnerabilityName"),
        "description":      (entry.get("shortDescription") or "")[:280],
        "date_added":       entry.get("dateAdded"),
        "due_date":         entry.get("dueDate"),
        "required_action":  entry.get("requiredAction"),
        "ransomware_use":   entry.get("knownRansomwareCampaignUse") == "Known",
    }


def extract_and_check(text: str) -> list[dict]:
    """Pull every CVE from text, return those that are in KEV."""
    import re
    found = set(re.findall(CVE_RE, text or "", flags=re.IGNORECASE))
    return [hit for cve in found if (hit := lookup(cve))]


def stats() -> dict:
    return {"kev_count": len(_index()), "kev_loaded": KEV_FILE.exists()}
