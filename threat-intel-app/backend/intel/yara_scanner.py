"""
YARA file scanner — uses the 8,000+ rules across vendor/ to identify
malware families, packers, exploit shellcode, and APT tooling.

Lazy-loads compiled rulesets on first call; precompiles to a single
in-memory ruleset for fast scanning thereafter.
"""
from pathlib import Path
from functools import lru_cache

VENDOR = Path(__file__).parent.parent.parent / "vendor"

# Rule sources, in priority order — early hits get cited first
RULE_SOURCES = [
    ("Florian Roth signature-base", VENDOR / "signature-base" / "yara"),
    ("Yara-Rules community",        VENDOR / "yara-rules"),
    ("Mandiant RTC",                VENDOR / "mandiant-rtc"),
]


_STATE = {"file_count": 0, "skipped": 0}


@lru_cache(maxsize=1)
def _ruleset():
    """Compile all available YARA rules into one ruleset. Skips broken rules."""
    try:
        import yara
    except ImportError:
        return None

    # Folders to skip — utility rules (IOC-pattern extractors) and deprecated rules
    # that match too broadly and produce false positives on virtually every file.
    skip_path_parts = {
        "utils",           # yara-rules/utils — IP/domain/URL extractors
        "deprecated",      # old / unmaintained rules
        "obsolete",
        "tests",
        "test",
        "examples",
        "experimental",
        "legacy",
    }
    # Individual file names that are known noise
    skip_filenames = {
        "domain.yar", "ip.yar", "url.yar",
        "general_cloaking.yar",
    }

    rule_files = {}
    for label, root in RULE_SOURCES:
        if not root.exists():
            continue
        for f in root.rglob("*.yar*"):
            if not f.is_file() or f.stat().st_size >= 200_000:
                continue
            # Skip noisy folders + filenames
            if any(part.lower() in skip_path_parts for part in f.parts):
                continue
            if f.name.lower() in skip_filenames:
                continue
            key = f"{label.split()[0]}_{f.stem}_{f.stat().st_size}"
            rule_files[key] = str(f)

    if not rule_files:
        return None

    # Compile one file at a time; drop any that fail to parse
    compiled = {}
    skipped = 0
    for ns, path in rule_files.items():
        try:
            yara.compile(filepath=path)
            compiled[ns] = path
        except Exception:
            skipped += 1
            continue

    _STATE["file_count"] = len(compiled)
    _STATE["skipped"]    = skipped

    if not compiled:
        return None
    try:
        return yara.compile(filepaths=compiled)
    except Exception:
        try:
            small = dict(list(compiled.items())[:200])
            _STATE["file_count"] = len(small)
            return yara.compile(filepaths=small)
        except Exception:
            return None


def scan_bytes(data: bytes, timeout: int = 8) -> list[dict]:
    """Scan a byte blob and return matched rules."""
    rules = _ruleset()
    if not rules or not data:
        return []
    try:
        matches = rules.match(data=data, timeout=timeout)
    except Exception:
        return []
    out = []
    for m in matches[:30]:
        meta = m.meta or {}
        # Surface the actual matched strings so the frontend can show
        # WHERE in the file the rule fired. Field names mirror the custom-
        # rule scanner output ({id, offset, matched}) so the FileScannerView
        # renderer (which reads s.id / s.offset / s.matched) treats both
        # paths identically. yara-python ≥4.3 uses StringMatch objects with
        # .identifier + .instances; older tuple-based API is
        # (offset, identifier, data). Handle both without crashing.
        matched_strings: list = []
        for s in (m.strings or [])[:6]:
            ident = getattr(s, "identifier", None)
            if ident is not None:
                for inst in (getattr(s, "instances", None) or [])[:2]:
                    raw = getattr(inst, "matched_data", b"") or b""
                    try:
                        snippet = raw[:80].decode("utf-8", errors="replace")
                    except Exception:
                        snippet = repr(raw[:80])
                    matched_strings.append({
                        "id":      ident,
                        "offset":  getattr(inst, "offset", 0),
                        "matched": snippet,
                    })
            elif isinstance(s, tuple) and len(s) >= 3:
                # legacy (offset, identifier, data)
                offset, ident2, raw = s[0], s[1], s[2]
                try:
                    snippet = raw[:80].decode("utf-8", errors="replace") if isinstance(raw, (bytes, bytearray)) else str(raw)[:80]
                except Exception:
                    snippet = repr(raw)[:80]
                matched_strings.append({
                    "id":      ident2,
                    "offset":  offset,
                    "matched": snippet,
                })
        out.append({
            "rule":            m.rule,
            "namespace":       m.namespace,
            "tags":            list(m.tags or [])[:6],
            "description":     str(meta.get("description") or meta.get("desc") or "")[:200],
            "author":          str(meta.get("author") or "")[:80],
            "reference":       str(meta.get("reference") or meta.get("ref") or "")[:200],
            "score":           meta.get("score") or meta.get("threat_level"),
            "strings_hit":     len(matched_strings),
            "matched_strings": matched_strings[:10],
        })
    return out


def stats() -> dict:
    rs = _ruleset()
    return {
        "yara_loaded":      rs is not None,
        "yara_rule_files":  _STATE.get("file_count", 0),
        "yara_skipped":     _STATE.get("skipped", 0),
    }
