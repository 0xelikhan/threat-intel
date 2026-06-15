"""
Atomic Red Team — for each MITRE technique, a library of small, reproducible
attack tests with example commands. Used to enrich AI investigation prompts
with REAL attack examples per technique, not just abstract descriptions.
"""
import re
from pathlib import Path
from functools import lru_cache

VENDOR = Path(__file__).parent.parent.parent / "vendor" / "atomic-red-team" / "atomics"

# MITRE technique IDs are shaped like Txxxx or Txxxx.yyy. Validating against
# this exact pattern means a malicious caller (or an LLM coerced into emitting
# "../../etc/passwd" as a technique) can't traverse out of the atomics
# directory via the f"{tid}.yaml" path interpolation below.
_TID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")


@lru_cache(maxsize=512)
def get_tests(technique_id: str) -> list[dict]:
    """Return Atomic Red Team tests for a MITRE technique ID (e.g. 'T1059.001')."""
    if not technique_id:
        return []
    tid = technique_id.strip().split(" ")[0]  # accept "T1059.001 - PowerShell"
    if not _TID_RE.match(tid):
        return []
    folder = VENDOR / tid
    if not folder.exists():
        return []
    try:
        import yaml
    except ImportError:
        return []
    f = folder / f"{tid}.yaml"
    if not f.exists():
        return []
    try:
        data = yaml.safe_load(f.read_text(encoding="utf-8"))
    except Exception:
        return []
    out = []
    for test in (data.get("atomic_tests") or [])[:4]:
        cmd = ((test.get("executor") or {}).get("command") or "").strip()
        out.append({
            "name":        test.get("name", ""),
            "description": (test.get("description") or "")[:200],
            "platforms":   test.get("supported_platforms", []),
            "command":     cmd[:400],
        })
    return out


def get_examples_summary(technique_ids: list[str], max_chars: int = 1500) -> str:
    """Compact attack-example block for AI prompts."""
    chunks = []
    for tid in technique_ids:
        tests = get_tests(tid)
        if not tests:
            continue
        chunks.append(f"\n[{tid}]")
        for t in tests[:2]:
            line = f"  • {t['name']}"
            if t["command"]:
                cmd = t["command"].split("\n")[0][:140]
                line += f" — `{cmd}`"
            chunks.append(line)
        if len("\n".join(chunks)) > max_chars:
            break
    return "\n".join(chunks)[:max_chars]


def stats() -> dict:
    return {"atomic_technique_folders": len(list(VENDOR.glob("T*"))) if VENDOR.exists() else 0}
