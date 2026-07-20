"""
LOLDrivers — catalog of vulnerable/malicious Windows drivers used in
Bring-Your-Own-Vulnerable-Driver (BYOVD) attacks.

Two lookup paths:
  - by hash (when an analyst pastes a sample hash, match against 600+ known driver hashes)
  - by filename (e.g. an alert mentions "driver_xxx.sys", flag known vulnerable drivers)

Perf: the upstream feed ships as ~623 separate YAML files. Parsing them
with pyyaml costs ~38 s per process cold-start (see cProfile scan
2026-07). That warm-up serialises pipeline startup and pays the cost
again on every fresh dev process. We cache the parsed catalog to a
JSON side-file next to the YAML dir on first build; subsequent starts
read the JSON in ~50 ms. The JSON is invalidated whenever the source
directory's mtime is newer.
"""
import json
import logging
import re
import time
from pathlib import Path
from functools import lru_cache

_log = logging.getLogger("recon.intel.loldrivers")

VENDOR = Path(__file__).parent.parent.parent / "vendor" / "loldrivers"
YAML_DIR = VENDOR / "yaml"
CACHE_JSON = VENDOR / "catalog.cache.json"


def _dir_mtime(p: Path) -> float:
    try:
        return max((f.stat().st_mtime for f in p.glob("*.yaml")), default=0.0)
    except Exception:
        return 0.0


def _load_from_json() -> dict | None:
    """Return the cached catalog if the JSON file exists AND is at least
    as new as the newest YAML source. None otherwise."""
    try:
        if not CACHE_JSON.exists():
            return None
        if CACHE_JSON.stat().st_mtime < _dir_mtime(YAML_DIR):
            return None
        out = json.loads(CACHE_JSON.read_text(encoding="utf-8"))
        if not isinstance(out, dict) or "by_hash" not in out:
            return None
        return out
    except Exception as e:
        _log.debug("loldrivers JSON cache load failed: %s", e)
        return None


def _write_json_cache(catalog: dict) -> None:
    try:
        CACHE_JSON.write_text(json.dumps(catalog, separators=(",", ":")),
                              encoding="utf-8")
    except Exception as e:
        _log.debug("loldrivers JSON cache write failed: %s", e)


@lru_cache(maxsize=1)
def _catalog() -> dict:
    """Build dual-indexed catalog: by filename + by hash.
    Prefers the pre-built JSON cache when available."""
    out = {"by_name": {}, "by_hash": {}, "all": []}
    if not YAML_DIR.exists():
        return out

    _t0 = time.perf_counter()
    cached = _load_from_json()
    if cached is not None:
        _log.info("loldrivers loaded from JSON cache: %d hashes, %d names (%.2fs)",
                  len(cached.get("by_hash") or {}),
                  len(cached.get("by_name") or {}),
                  time.perf_counter() - _t0)
        return cached

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
    _write_json_cache(out)
    _log.info("loldrivers built from %d YAMLs: %d hashes, %d names (%.2fs; cache written)",
              len(out["all"]), len(out["by_hash"]), len(out["by_name"]),
              time.perf_counter() - _t0)
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
