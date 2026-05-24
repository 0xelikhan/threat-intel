"""
LOLBAS — Living Off The Land Binaries, Scripts and Libraries.
Catalog of legitimate Windows binaries adversaries abuse.
"""
import re
from pathlib import Path
from functools import lru_cache

VENDOR = Path(__file__).parent.parent.parent / "vendor" / "lolbas"
DIRS   = [VENDOR / "yml" / d for d in ("OSBinaries", "OSLibraries", "OSScripts", "OtherMSBinaries")]


@lru_cache(maxsize=1)
def _catalog() -> dict:
    """Build {binary_name_lower: { name, paths, categories, descriptions }}."""
    out: dict[str, dict] = {}
    try:
        import yaml  # PyYAML; ships as dep of mitreattack-python / sigma-cli
    except ImportError:
        return out

    for d in DIRS:
        if not d.exists():
            continue
        for f in d.glob("*.yml"):
            try:
                entry = yaml.safe_load(f.read_text(encoding="utf-8"))
            except Exception:
                continue
            if not entry or not entry.get("Name"):
                continue
            name = entry["Name"]
            categories = sorted({c.get("Category", "") for c in entry.get("Commands", []) if c.get("Category")})
            descriptions = [c.get("Description", "")[:140] for c in entry.get("Commands", [])[:3]]
            out[name.lower()] = {
                "name":         name,
                "categories":   [c for c in categories if c],
                "description":  (entry.get("Description") or "")[:200],
                "examples":     [d_ for d_ in descriptions if d_],
                "url":          entry.get("Url", ""),
            }
    return out


def lookup(binary: str) -> dict | None:
    """Return LOLBAS entry for a binary name (case-insensitive, .exe optional)."""
    if not binary:
        return None
    n = binary.lower().strip()
    n = n[:-4] if n.endswith(".exe") else n
    return _catalog().get(n) or _catalog().get(n + ".exe")


# Match bare Windows binaries (cmd.exe, powershell.exe, certutil.exe...)
_BIN_RE = re.compile(
    r"\b([a-zA-Z0-9_\-]{2,40})\.exe\b", re.IGNORECASE
)


def extract_and_check(text: str) -> list[dict]:
    """Scan text for Windows binaries that appear in the LOLBAS catalog."""
    seen, hits = set(), []
    for m in _BIN_RE.finditer(text or ""):
        b = m.group(1).lower()
        if b in seen:
            continue
        seen.add(b)
        entry = lookup(b)
        if entry:
            hits.append(entry)
    return hits


def stats() -> dict:
    return {"lolbas_count": len(_catalog())}
