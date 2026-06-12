"""
AI-generated YARA rule per analyzed file — spec §5.

Picks the most unique/stable indicators from a file_analyzer result and asks
the AI to produce a tight YARA rule. Validates by compiling with yara-python
and by matching the rule against the original sample. Retries up to 3 times
with the validation error fed back into the prompt.

Uses the same Azure-aware OpenAI client pattern as the rest of the codebase.
"""

from __future__ import annotations
from typing import Dict, Tuple, List


_BASE_PROMPT = """Generate a single YARA rule for the malware sample whose
static analysis is below. Output ONLY the YARA rule. No markdown fences.
No commentary.

REQUIREMENTS - these are not negotiable:
  - Start with `rule <CamelCaseName> {{` on the first line. Do NOT omit
    the `rule` keyword or the name.
  - Use ONLY the literal strings provided under "Unique strings to consider"
    and "Mutex candidates" below. Copy them verbatim into the strings
    block. Do NOT invent placeholder strings like "unique_string_1",
    "another_unique_string", "third_unique_string", "example_string",
    or "{{placeholder}}". A rule that does not match the actual file is
    worthless and will be rejected.
  - Prefer mutex names and unique multi-byte strings over common API names
    that appear in every legitimate binary.
  - Prefer combinations of 3 or more indicators over single indicators.
  - Use a condition requiring at least N of M strings (e.g. "2 of ($s*)"),
    never "all of them".
  - Include a complete meta block:
      description, author = "RECON Platform", date = "{date}",
      hash = "{sha256}", reference (URL if family known), mitre_attack
  - Include a filesize condition appropriate to the malware type.
  - Add a one-line comment on each string explaining why it is unique enough
    to be a good signal and unlikely to appear in legitimate software.

CONTEXT
File type:         {file_type}
File size:         {size} bytes
SHA-256:           {sha256}
PE imphash:        {imphash}
Malware family:    {family}
Suspicious tags:   {tags}
Unique strings to consider:
{unique_strings}
Mutex candidates:
{mutexes}
"""

# Strings that indicate the AI ignored the provided indicators and emitted
# a template/placeholder rule. Any rule containing one of these is rejected
# before the slow yara.compile + match step.
_PLACEHOLDER_TELLS = (
    "unique_string_1", "unique_string_2", "unique_string_3",
    "another_unique_string", "third_unique_string",
    "example_string", "example_mutex",
    "placeholder", "PLACEHOLDER",
    "<insert ", "your_string_here", "string_here",
    "specific_string_from_sample",
)


def _looks_like_placeholder_rule(text: str) -> bool:
    """Cheap pre-check before the yara compile + match. The AI sometimes
    emits literal template strings instead of using the unique_strings we
    passed it; those rules compile but never match the sample, so the
    expensive validation path eventually rejects them. Failing fast here
    saves a yara.compile + retry roundtrip."""
    low = text.lower()
    return any(tell.lower() in low for tell in _PLACEHOLDER_TELLS)


def _pick_unique_strings(result: Dict, limit: int = 12) -> List[str]:
    """Strings that are long enough + diverse enough to be good signatures."""
    sample = (result.get("strings") or {}).get("ascii_sample") or []
    common_lib_names = {
        "kernel32.dll", "ntdll.dll", "user32.dll", "advapi32.dll",
        "ws2_32.dll", "wininet.dll", "shell32.dll", "ole32.dll",
        "msvcrt.dll", "gdi32.dll",
    }
    picked = []
    for s in sample:
        if not isinstance(s, str) or len(s) < 14 or len(s) > 90:
            continue
        if s.lower() in common_lib_names:
            continue
        # Want some character diversity — not just A-Z
        if not any(c in s for c in (":", "\\", "{", "/", "@", ".", "_", "-")):
            continue
        picked.append(s)
        if len(picked) >= limit:
            break
    return picked


def _pick_mutexes(result: Dict, limit: int = 5) -> List[str]:
    sample = (result.get("strings") or {}).get("ascii_sample") or []
    out = []
    for s in sample:
        if isinstance(s, str) and (s.startswith(("Global\\", "Local\\")) or "Mutex" in s):
            if 6 <= len(s) <= 80:
                out.append(s)
        if len(out) >= limit:
            break
    return out


async def generate_yara_for_file(result: Dict, ai_call) -> Dict:
    """ai_call: async (prompt: str) -> str — same shape as main._ai_gen."""
    from datetime import datetime, timezone
    sha256 = (result.get("hashes") or {}).get("sha256") or ""
    pe     = (result.get("format_specific") or {}).get("pe") or {}
    family = (result.get("threat_intel") or {}).get("malware_family_consensus") or "unknown"
    tags   = (result.get("capabilities") or {}).get("tags") or []
    uniq   = _pick_unique_strings(result)
    mut    = _pick_mutexes(result)

    # Skip the AI call entirely when we have no real indicators to anchor
    # the rule on. With "(none extracted)" in the prompt the model
    # invariably hallucinates template strings ("unique_string_1") that
    # can't possibly match the sample, then the validator rejects them.
    # Better to honestly report "insufficient indicators" than to ship a
    # broken rule labeled "invalid".
    if not uniq and not mut:
        return {
            "rule":     "",
            "valid":    False,
            "errors":   ["No unique strings or mutex candidates were "
                         "extracted from this file; YARA generation "
                         "would not produce a useful signature."],
            "attempts": 0,
            "skipped":  True,
        }

    base = _BASE_PROMPT.format(
        # UTC so two containers in different timezones produce identical
        # YARA rule metadata for the same sample (rule.date inconsistency
        # was the deduplication-by-content failure the SOC team hit when
        # the same hash analyzed twice produced "different" rules).
        date=datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        sha256=sha256,
        imphash=pe.get("imphash") or "n/a",
        file_type=(result.get("type") or {}).get("detected_mime", "unknown"),
        size=result.get("size", 0),
        family=family,
        tags=", ".join(tags) or "none",
        unique_strings="\n".join(f"  - {s}" for s in uniq) or "  (none extracted)",
        mutexes="\n".join(f"  - {m}" for m in mut) or "  (none extracted)",
    )

    # Validation loop — up to 3 attempts
    prompt = base
    last_text = ""
    last_errors: List[str] = []
    # 2 attempts max — previous 3-attempt loop pushed scans over a minute
    # when the small model produced bad YARA syntax. The validation+retry is
    # still here to catch the common case; pathologically broken rules just
    # ship as 'valid: false' and the analyst sees the error inline.
    for attempt in range(1, 3):
        text = await ai_call(prompt)
        text = _strip_fences(text)
        # Cheap pre-check: reject placeholder/template rules BEFORE the
        # slow yara compile + match. Saves a roundtrip on the common
        # failure mode where the AI emits "unique_string_1" rather than
        # the actual strings we provided in the prompt.
        if _looks_like_placeholder_rule(text):
            last_text = text
            last_errors = ["rule used placeholder strings instead of the "
                           "unique indicators provided in the prompt"]
            prompt = (
                f"Your previous YARA rule was rejected: it contained "
                f"placeholder strings (like 'unique_string_1') instead of "
                f"the actual indicators provided in the prompt. Re-read "
                f"the 'Unique strings to consider' and 'Mutex candidates' "
                f"sections and use those EXACT strings verbatim. Output "
                f"ONLY the corrected YARA rule. No markdown fences. "
                f"No commentary."
            )
            continue
        ok, errs = _validate_and_test(text, result.get("_file_bytes"))
        if ok:
            return {"rule": text, "valid": True, "errors": [], "attempts": attempt}
        last_text, last_errors = text, errs
        prompt = (
            f"Your previous YARA rule was rejected:\n"
            f"  {chr(10).join(errs)}\n\n"
            f"Here is the rule you produced:\n{text}\n\n"
            f"Fix the issue and output ONLY the corrected YARA rule. "
            f"No markdown fences. No commentary."
        )

    return {"rule": last_text, "valid": False, "errors": last_errors, "attempts": 2}


def _validate_and_test(text: str, file_bytes) -> Tuple[bool, List[str]]:
    try:
        import yara
    except ImportError:
        return False, ["yara-python not installed"]
    try:
        compiled = yara.compile(source=text)
    except yara.SyntaxError as e:
        return False, [f"syntax: {e}"]
    except yara.Error as e:
        return False, [f"compile: {e}"]
    if not file_bytes:
        # No bytes to verify against — accept on compile success
        return True, []
    try:
        matches = compiled.match(data=file_bytes, timeout=5)
        if not matches:
            return False, ["rule compiled but did not match the analyzed sample"]
    except Exception as e:
        return False, [f"match: {e}"]
    return True, []


def _strip_fences(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        parts = text.split("```")
        if len(parts) >= 3:
            body = parts[1]
            if body.lower().startswith(("yara", "yar")):
                body = body.split("\n", 1)[1] if "\n" in body else ""
            return body.strip()
    return text
