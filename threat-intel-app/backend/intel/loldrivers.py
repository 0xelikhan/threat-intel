"""
LOLDrivers — catalog of vulnerable/malicious Windows drivers used in
Bring-Your-Own-Vulnerable-Driver (BYOVD) attacks.

Two lookup paths:
  - by hash (when an analyst pastes a sample hash, match against 600+ known driver hashes)
  - by filename (e.g. an alert mentions "driver_xxx.sys", flag known vulnerable drivers)
"""
import re
from pathlib import Path
from functools import lru_cache

VENDOR = Path(__file__).parent.parent.parent / "vendor" / "loldrivers"
YAML_DIR = VENDOR / "yaml"


@lru_cache(maxsize=1)
def _catalog() -> dict:
    """Build dual-indexed catalog: by filename + by hash."""
    out = {"by_name": {}, "by_hash": {}, "all": []}
    if not YAML_DIR.exists():
        return out
    try:
        import yaml
    except ImportError:
        return out

    for f in YAML_DIR.glob("*.yaml"):
        try:
            entry = yaml.safe_load(f.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not entry:
            continue
        category = entry.get("Category", "")
        mitre    = entry.get("MitreID", "")
        tags     = entry.get("Tags") or []
        resources = entry.get("Resources") or []
        compact = {
            "id":       entry.get("Id", ""),
            "category": category,
            "mitre":    mitre,
            "tags":     tags[:5],
            "ref":      resources[0] if resources else "",
        }
        out["all"].append(compact)
        for tag in tags:
            if tag and isinstance(tag, str):
                out["by_name"][tag.lower()] = compact
        for sample in (entry.get("KnownVulnerableSamples") or []):
            for hkey in ("MD5", "SHA1", "SHA256"):
                h = sample.get(hkey)
                if h and isinstance(h, str) and h.strip():
                    out["by_hash"][h.lower().strip()] = compact
    return out


def lookup_hash(h: str) -> dict | None:
    return _catalog()["by_hash"].get((h or "").lower().strip())


def lookup_name(name: str) -> dict | None:
    if not name:
        return None
    n = name.lower().strip()
    return _catalog()["by_name"].get(n)


_DRIVER_RE = re.compile(r"\b([a-zA-Z0-9_\-]{3,40}\.sys)\b", re.IGNORECASE)


def extract_and_check(text: str, hashes: list[str] | None = None) -> list[dict]:
    """Scan text for .sys filenames AND check hash list against the catalog."""
    seen, hits = set(), []
    for m in _DRIVER_RE.finditer(text or ""):
        n = m.group(1).lower()
        if n in seen:
            continue
        seen.add(n)
        entry = lookup_name(n)
        if entry:
            hits.append({**entry, "match_type": "filename", "value": n})
    for h in (hashes or []):
        entry = lookup_hash(h)
        if entry:
            hits.append({**entry, "match_type": "hash", "value": h})
    return hits


def stats() -> dict:
    cat = _catalog()
    return {
        "loldrivers_total": len(cat["all"]),
        "loldrivers_named": len(cat["by_name"]),
        "loldrivers_hashed": len(cat["by_hash"]),
    }
