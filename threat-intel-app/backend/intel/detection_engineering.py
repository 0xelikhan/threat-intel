"""
Detection-engineering helpers — spec §6.

  - validate_sigma(yaml_text)  -> (ok, errors)
  - convert_sigma_to_spl(yt)   -> str  (Splunk)
  - convert_sigma_to_kql(yt)   -> str  (Microsoft 365 Defender / Sentinel)
  - validate_yara(rule_text)   -> (ok, errors)
  - search_existing_sigma(techniques) -> list of matching rule files from
      vendor/sigma/rules
  - search_existing_elastic(techniques) -> list from vendor/elastic-rules
  - search_existing_yara(family)        -> list from vendor/signature-base

All functions are best-effort: if a vendor dir is missing or a backend isn't
installed they return empty / a clear error rather than raising.
"""

from __future__ import annotations
import re
from pathlib import Path
from typing import List, Tuple, Optional

_REPO_ROOT  = Path(__file__).resolve().parents[3]
_VENDOR     = _REPO_ROOT / "threat-intel-app" / "vendor"
_SIGMA_DIR  = _VENDOR / "sigma" / "rules"
_ELASTIC_DIR= _VENDOR / "elastic-rules" / "rules"
_SIGBASE    = _VENDOR / "signature-base" / "yara"


# ─── Sigma validation + conversion ──────────────────────────────────────────────
def validate_sigma(yaml_text: str) -> Tuple[bool, List[str]]:
    """Returns (ok, errors). errors is a list of human-readable strings."""
    try:
        from sigma.collection import SigmaCollection
        from sigma.exceptions import SigmaError
        try:
            SigmaCollection.from_yaml(yaml_text)
            return True, []
        except SigmaError as e:
            return False, [str(e)]
        except Exception as e:
            return False, [f"{type(e).__name__}: {e}"]
    except Exception as e:
        return False, [f"sigma library unavailable: {e}"]


def convert_sigma_to_spl(yaml_text: str) -> Tuple[Optional[str], Optional[str]]:
    """Returns (spl_text, error). On success error is None; on failure spl_text is None."""
    try:
        from sigma.collection import SigmaCollection
        from sigma.backends.splunk import SplunkBackend
        collection = SigmaCollection.from_yaml(yaml_text)
        backend = SplunkBackend()
        out = backend.convert(collection)
        return ("\n".join(out) if isinstance(out, list) else str(out)), None
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"


def convert_sigma_to_kql(yaml_text: str) -> Tuple[Optional[str], Optional[str]]:
    """Microsoft 365 Defender / Kusto. Returns (kql, error)."""
    try:
        from sigma.collection import SigmaCollection
        from sigma.backends.kusto import KustoBackend
        collection = SigmaCollection.from_yaml(yaml_text)
        backend = KustoBackend()
        out = backend.convert(collection)
        return ("\n".join(out) if isinstance(out, list) else str(out)), None
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"


# ─── YARA validation ────────────────────────────────────────────────────────────
def validate_yara(rule_text: str) -> Tuple[bool, List[str]]:
    """Compile the rule with yara-python. Returns (ok, errors)."""
    try:
        import yara
        try:
            yara.compile(source=rule_text)
            return True, []
        except yara.SyntaxError as e:
            return False, [str(e)]
        except yara.Error as e:
            return False, [str(e)]
        except Exception as e:
            return False, [f"{type(e).__name__}: {e}"]
    except Exception as e:
        return False, [f"yara-python unavailable: {e}"]


# ─── Existing-rule search ──────────────────────────────────────────────────────
_TID_RE = re.compile(r"T\d{4}(?:\.\d{3})?", re.IGNORECASE)


def _technique_set(techniques) -> set:
    """Normalize a list like ['T1059.001 - PowerShell', 'T1566'] -> {'t1059.001', 't1566'}."""
    out = set()
    for t in techniques or []:
        for m in _TID_RE.findall(str(t)):
            out.add(m.lower())
    return out


def search_existing_sigma(techniques) -> List[dict]:
    """Walk vendor/sigma/rules looking for files whose 'tags' include any technique.
    Returns at most 20 hits."""
    targets = _technique_set(techniques)
    if not targets or not _SIGMA_DIR.exists():
        return []
    hits = []
    for f in _SIGMA_DIR.rglob("*.yml"):
        if len(hits) >= 20:
            break
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        # Tags appear as "attack.t1059.001" — cheap substring scan first to skip parsing
        if not any(f"attack.{t}" in text.lower() for t in targets):
            continue
        title = _scrape_yaml_field(text, "title")
        descr = _scrape_yaml_field(text, "description")
        level = _scrape_yaml_field(text, "level")
        matched = [t for t in targets if f"attack.{t}" in text.lower()]
        hits.append({
            "path":         str(f.relative_to(_VENDOR)),
            "title":        title or f.stem,
            "description":  (descr or "")[:240],
            "level":        level,
            "techniques":   matched,
            "source":       "SigmaHQ",
        })
    return hits


def search_existing_elastic(techniques) -> List[dict]:
    """Walk vendor/elastic-rules/rules — TOML files with [[rule.threat]] sections.
    Best-effort substring match on technique IDs."""
    targets = _technique_set(techniques)
    if not targets or not _ELASTIC_DIR.exists():
        return []
    hits = []
    for f in _ELASTIC_DIR.rglob("*.toml"):
        if len(hits) >= 20:
            break
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        text_lower = text.lower()
        matched = [t for t in targets if f'id = "{t}"' in text_lower or f"id = '{t}'" in text_lower]
        if not matched:
            continue
        name = _scrape_toml_field(text, "name") or _scrape_toml_field(text, "rule_name")
        descr = _scrape_toml_field(text, "description")
        sev = _scrape_toml_field(text, "severity")
        hits.append({
            "path":         str(f.relative_to(_VENDOR)),
            "title":        name or f.stem,
            "description":  (descr or "")[:240],
            "level":        sev,
            "techniques":   matched,
            "source":       "Elastic",
        })
    return hits


def search_existing_yara(family: Optional[str], hash_value: Optional[str] = None) -> List[dict]:
    """Search vendor/signature-base/yara for rule files matching a malware family
    or hash. Family is a substring match on filename + content."""
    if not _SIGBASE.exists():
        return []
    needles = []
    if family:
        needles.append(family.lower().replace(" ", "_"))
        needles.append(family.lower().replace(" ", ""))
    if hash_value:
        needles.append(hash_value.lower())
    if not needles:
        return []
    hits = []
    for f in _SIGBASE.rglob("*.yar*"):
        if len(hits) >= 10:
            break
        name = f.stem.lower()
        try:
            text = f.read_text(encoding="utf-8", errors="ignore").lower()
        except Exception:
            continue
        matched_on = []
        for n in needles:
            if n in name:
                matched_on.append(f"filename:{n}")
            elif n in text:
                matched_on.append(f"content:{n}")
        if matched_on:
            hits.append({
                "path":       str(f.relative_to(_VENDOR)),
                "filename":   f.name,
                "matched_on": matched_on,
                "source":     "Neo23x0/signature-base",
            })
    return hits


# ─── Sigma+YARA generation loops (with validation + retry) ─────────────────────
async def generate_validated_sigma(
    ai_call,                # async (prompt: str) -> str
    base_prompt: str,
    max_retries: int = 3,
) -> dict:
    """Ask the AI for a Sigma rule, validate with sigma-cli logic, retry on failure.
    Returns {'rule': yaml_text, 'valid': bool, 'errors': [...], 'attempts': N}."""
    prompt = base_prompt
    last_text = ""
    last_errors: List[str] = []
    for attempt in range(1, max_retries + 1):
        text = await ai_call(prompt)
        text = _strip_yaml_fences(text)
        ok, errs = validate_sigma(text)
        if ok:
            return {"rule": text, "valid": True, "errors": [], "attempts": attempt}
        last_text, last_errors = text, errs
        prompt = (
            f"Your previous Sigma rule failed validation with these errors:\n"
            f"  {chr(10).join(errs)}\n\n"
            f"Here is the rule you produced:\n{text}\n\n"
            f"Fix the errors and output ONLY the corrected Sigma YAML. "
            f"No markdown fences, no commentary."
        )
    return {"rule": last_text, "valid": False, "errors": last_errors, "attempts": max_retries}


async def generate_validated_yara(
    ai_call,
    base_prompt: str,
    max_retries: int = 3,
) -> dict:
    """Ask the AI for a YARA rule, compile with yara-python, retry on syntax errors."""
    prompt = base_prompt
    last_text = ""
    last_errors: List[str] = []
    for attempt in range(1, max_retries + 1):
        text = await ai_call(prompt)
        text = _strip_yara_fences(text)
        ok, errs = validate_yara(text)
        if ok:
            return {"rule": text, "valid": True, "errors": [], "attempts": attempt}
        last_text, last_errors = text, errs
        prompt = (
            f"Your previous YARA rule failed to compile:\n"
            f"  {chr(10).join(errs)}\n\n"
            f"Here is the rule:\n{text}\n\n"
            f"Fix the syntax and output ONLY the corrected YARA rule. "
            f"No markdown fences, no commentary."
        )
    return {"rule": last_text, "valid": False, "errors": last_errors, "attempts": max_retries}


# ─── helpers ───────────────────────────────────────────────────────────────────
def _scrape_yaml_field(text: str, field: str) -> Optional[str]:
    for line in text.splitlines():
        s = line.strip()
        if s.lower().startswith(f"{field}:"):
            val = s.split(":", 1)[1].strip().strip("'\"")
            return val or None
    return None


def _scrape_toml_field(text: str, field: str) -> Optional[str]:
    for line in text.splitlines():
        s = line.strip()
        if s.lower().startswith(f"{field} ="):
            val = s.split("=", 1)[1].strip().strip("'\"")
            return val or None
    return None


def _strip_yaml_fences(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        # ```yaml\n…\n```
        parts = text.split("```")
        if len(parts) >= 3:
            body = parts[1]
            if body.startswith(("yaml", "yml")):
                body = body.split("\n", 1)[1] if "\n" in body else ""
            return body.strip()
    return text


def _strip_yara_fences(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        parts = text.split("```")
        if len(parts) >= 3:
            body = parts[1]
            if body.startswith(("yara",)):
                body = body.split("\n", 1)[1] if "\n" in body else ""
            return body.strip()
    return text
