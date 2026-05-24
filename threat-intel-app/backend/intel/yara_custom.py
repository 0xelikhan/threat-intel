"""
Custom-rule management for the file scanner — spec §5.

Loads user rules from backend/intel/yara_rules/, exposes save/delete/validate
helpers, and watches for changes with watchdog so new rules show up in
subsequent scans without a backend restart.

The vendor packs (signature-base, yara-rules, mandiant-rtc) are still loaded
by intel.yara_scanner; this module *additionally* compiles the custom rules
and exposes them as a second ruleset that the file scanner combines with the
vendor one.

Public API:
  load_custom_rules()             -> compiled yara.Rules or None
  scan_with_custom(bytes, timeout) -> list[match dict]
  scan_combined(bytes, timeout)    -> vendor matches + custom matches
  validate_rule(text)              -> (ok, errors)
  save_rule(name, text)            -> dict
  delete_rule(name)                -> bool
  list_rules()                     -> list of {name, source, size, modified}
  start_hot_reload()               -> idempotent; spawns watchdog observer
"""

from __future__ import annotations
import re
import time
import threading
from pathlib import Path
from typing import Optional, List, Tuple, Dict

_CUSTOM_DIR = Path(__file__).resolve().parent / "yara_rules"
_CUSTOM_DIR.mkdir(parents=True, exist_ok=True)

_STATE: Dict = {
    "compiled":       None,    # yara.Rules object
    "loaded_at":      0.0,
    "files":          [],
    "errors":         [],
    "observer":       None,
}
_LOCK = threading.Lock()


def _safe_name(name: str) -> str:
    """Sanitize a rule name for filesystem use."""
    safe = re.sub(r"[^A-Za-z0-9_\-]", "_", name)[:80]
    return safe or "untitled"


def validate_rule(text: str) -> Tuple[bool, List[str]]:
    """Try to compile a YARA rule. Returns (ok, errors)."""
    try:
        import yara
    except ImportError:
        return False, ["yara-python not installed"]
    try:
        yara.compile(source=text)
        return True, []
    except yara.SyntaxError as e:
        return False, [str(e)]
    except yara.Error as e:
        return False, [str(e)]
    except Exception as e:
        return False, [f"{type(e).__name__}: {e}"]


def save_rule(name: str, text: str) -> Dict:
    """Validate + write to backend/intel/yara_rules/<name>.yar."""
    ok, errs = validate_rule(text)
    if not ok:
        return {"saved": False, "errors": errs}
    safe = _safe_name(name)
    path = _CUSTOM_DIR / f"{safe}.yar"
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
    except Exception as e:
        return {"saved": False, "errors": [str(e)]}
    # Force immediate reload so the new rule is available right away
    _STATE["compiled"] = None
    load_custom_rules()
    return {"saved": True, "path": str(path.relative_to(_CUSTOM_DIR.parent)),
            "name": safe, "errors": []}


def delete_rule(name: str) -> bool:
    safe = _safe_name(name)
    path = _CUSTOM_DIR / f"{safe}.yar"
    if not path.exists():
        return False
    try:
        path.unlink()
    except Exception:
        return False
    _STATE["compiled"] = None
    load_custom_rules()
    return True


def list_rules() -> List[Dict]:
    out = []
    for p in sorted(_CUSTOM_DIR.glob("*.yar*")):
        try:
            st = p.stat()
        except Exception:
            continue
        out.append({
            "name":     p.stem,
            "filename": p.name,
            "size":     st.st_size,
            "modified": st.st_mtime,
            "source":   "custom",
        })
    return out


def load_custom_rules():
    """Compile all custom rules into a single yara.Rules object. Cached."""
    with _LOCK:
        if _STATE["compiled"] is not None:
            return _STATE["compiled"]
        try:
            import yara
        except ImportError:
            return None
        files = sorted(_CUSTOM_DIR.glob("*.yar*"))
        if not files:
            _STATE["compiled"] = None
            _STATE["files"] = []
            _STATE["loaded_at"] = time.time()
            return None
        filepaths = {}
        errors = []
        for f in files:
            try:
                yara.compile(filepath=str(f))
                filepaths[f.stem] = str(f)
            except Exception as e:
                errors.append({"file": f.name, "error": str(e)[:200]})
        try:
            compiled = yara.compile(filepaths=filepaths) if filepaths else None
        except Exception as e:
            errors.append({"file": "all", "error": str(e)})
            compiled = None
        _STATE["compiled"]  = compiled
        _STATE["files"]     = list(filepaths.values())
        _STATE["errors"]    = errors
        _STATE["loaded_at"] = time.time()
        return compiled


def scan_with_custom(data: bytes, timeout: int = 8) -> List[Dict]:
    rules = load_custom_rules()
    if not rules or not data:
        return []
    try:
        matches = rules.match(data=data, timeout=timeout)
    except Exception:
        return []
    out = []
    for m in matches[:30]:
        meta = m.meta or {}
        out.append({
            "rule":        m.rule,
            "namespace":   m.namespace,
            "tags":        list(m.tags or [])[:6],
            "description": str(meta.get("description") or "")[:200],
            "author":      str(meta.get("author") or "")[:80],
            "reference":   str(meta.get("reference") or "")[:200],
            "source":      "custom",
            "strings_hit": len(m.strings or []),
            "matched_strings": [
                {"id": s.identifier, "offset": s.instances[0].offset if s.instances else None,
                 "matched": (s.instances[0].matched_data[:80].decode("latin-1", "ignore")
                             if s.instances else None)}
                for s in (m.strings or [])[:5]
            ],
        })
    return out


def scan_combined(data: bytes, timeout: int = 8) -> List[Dict]:
    """Vendor rules (intel.yara_scanner) + custom rules — single combined list
    with source tagged on each entry."""
    out = []
    try:
        from intel.yara_scanner import scan_bytes
        for m in scan_bytes(data, timeout=timeout):
            m.setdefault("source", "vendor")
            out.append(m)
    except Exception:
        pass
    out.extend(scan_with_custom(data, timeout=timeout))
    return out


# ─── hot-reload via watchdog ──────────────────────────────────────────────────
def start_hot_reload():
    """Watch _CUSTOM_DIR for changes and invalidate the compiled cache. Safe
    to call multiple times — second call is a no-op."""
    if _STATE.get("observer"):
        return
    try:
        from watchdog.observers import Observer
        from watchdog.events import FileSystemEventHandler
    except ImportError:
        return

    class _H(FileSystemEventHandler):
        def on_any_event(self, event):
            if event.is_directory:
                return
            if not str(event.src_path).endswith((".yar", ".yara")):
                return
            with _LOCK:
                _STATE["compiled"] = None
            print(f"[yara] custom rule change: {event.src_path} — reloading on next scan")

    obs = Observer()
    obs.schedule(_H(), str(_CUSTOM_DIR), recursive=False)
    obs.daemon = True
    obs.start()
    _STATE["observer"] = obs


def stats() -> Dict:
    return {
        "custom_rule_files": len(_STATE.get("files") or []),
        "compile_errors":    _STATE.get("errors") or [],
        "loaded_at":         _STATE.get("loaded_at"),
        "hot_reload_active": _STATE.get("observer") is not None,
    }
