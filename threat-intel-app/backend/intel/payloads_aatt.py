"""
swisskyrepo/PayloadsAllTheThings loader.

Source: https://github.com/swisskyrepo/PayloadsAllTheThings (MIT).
Curated reference of offensive payloads grouped by attack class:
SQL Injection, XSS, XXE, SSRF, RCE, LFI, RFI, NoSQL, GraphQL, LDAP,
JWT, OAuth Misconfiguration, Subdomain Takeover, Type Juggling,
Insecure Deserialization, Prototype Pollution, etc.

The repo is mostly markdown — each attack-class folder has a README.md
with payload listings, references, and detection signatures. We
extract the per-class metadata (title, payload-count rough estimate,
references) so the hypothesis-generator and response agent can:

  * cite "PayloadsAllTheThings has 47 documented SQL-injection
    payloads — common ones include …"
  * inject specific payload patterns as detection-signature inspiration
"""

from __future__ import annotations

import logging
import re
import threading
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

_log = logging.getLogger("recon.intel.payloads_aatt")

_PAATT_ROOT = (Path(__file__).parent.parent.parent
               / "vendor" / "payloadsallthethings")

# Map a markdown section heading to a canonical attack class so the
# routing key matches OWASP CRS + CodeQL CWE buckets where possible.
_HEADING_TO_CLASS = {
    "sql injection":               "SQL Injection",
    "xss injection":               "Cross-Site Scripting",
    "xxe injection":               "XML External Entity",
    "command injection":           "Command Injection",
    "directory traversal":         "Path Traversal",
    "file inclusion":              "Local File Inclusion",
    "ssrf":                        "Server-Side Request Forgery",
    "server side request forgery": "Server-Side Request Forgery",
    "nosql injection":             "NoSQL Injection",
    "graphql injection":           "GraphQL Injection",
    "ldap injection":              "LDAP Injection",
    "json web token":              "JWT",
    "oauth misconfiguration":      "OAuth Misconfiguration",
    "subdomain takeover":          "Subdomain Takeover",
    "insecure deserialization":    "Insecure Deserialization",
    "prototype pollution":         "Prototype Pollution",
    "type juggling":               "Type Juggling",
    "csv injection":               "CSV Injection",
    "csrf injection":              "Cross-Site Request Forgery",
    "request smuggling":           "HTTP Request Smuggling",
    "open redirect":               "Open Redirect",
    "saml injection":              "SAML Injection",
    "race condition":              "Race Condition",
}

# Lines that contain a payload — typically inside a fenced code block or
# bullet list. We don't extract individual payloads (the repo has tens
# of thousands); we just count them to give the analyst a sense of
# breadth.
_PAYLOAD_LINE_RE = re.compile(r"^\s*(?:`|```|\*|-)\s", re.MULTILINE)

_lock  = threading.Lock()
_state: Dict[str, Any] = {
    "loaded":   False,
    "classes":  {},   # dict[class_label, {dir, payload_estimate, references}]
    "error":    None,
}


def _classify_dir_name(name: str) -> Optional[str]:
    n = name.lower().replace("_", " ").replace("-", " ").strip()
    if n in _HEADING_TO_CLASS:
        return _HEADING_TO_CLASS[n]
    # Loose match: any heading-key contained in the dir name.
    for k, v in _HEADING_TO_CLASS.items():
        if k in n:
            return v
    return None


def _build_index() -> None:
    if not _PAATT_ROOT.exists():
        _state["error"]  = f"PayloadsAllTheThings dir not present at {_PAATT_ROOT}"
        _state["loaded"] = True
        return

    classes: Dict[str, Dict[str, Any]] = {}
    for child in _PAATT_ROOT.iterdir():
        if not child.is_dir() or child.name.startswith("."):
            continue
        cls = _classify_dir_name(child.name)
        if not cls:
            continue
        readme = next((p for p in child.iterdir()
                        if p.is_file() and p.name.lower() in
                        ("readme.md", "readme.txt", "readme")), None)
        payload_count = 0
        references:   List[str] = []
        if readme:
            try:
                text = readme.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                text = ""
            if text:
                payload_count = len(_PAYLOAD_LINE_RE.findall(text))
                # Pull external references (markdown links to non-repo URLs).
                for m in re.finditer(r"\[([^\]]{3,80})\]\((https?://[^\)]+)\)",
                                      text):
                    label = m.group(1).strip()
                    url   = m.group(2).strip()
                    if "github.com/swisskyrepo" in url.lower():
                        continue
                    references.append(f"{label[:60]} :: {url[:160]}")
                    if len(references) >= 10:
                        break

        classes.setdefault(cls, {
            "class":            cls,
            "dir":              child.name,
            "payload_estimate": payload_count,
            "references":       references,
            "source":           "PayloadsAllTheThings",
        })

    _state["classes"] = classes
    _state["loaded"]  = True
    _state["error"]   = None
    _log.info("PayloadsAllTheThings loaded: %d attack classes",
              len(classes))


def _ensure_loaded() -> None:
    if _state["loaded"]:
        return
    with _lock:
        if not _state["loaded"]:
            _build_index()


def lookup_class(attack_class: str) -> Optional[Dict[str, Any]]:
    _ensure_loaded()
    if not attack_class:
        return None
    return (_state.get("classes") or {}).get(attack_class)


def classes_for_keywords(text: str) -> List[Dict[str, Any]]:
    """Match free-form alert text against the heading map and return
    payload-corpus entries for the implied attack classes."""
    _ensure_loaded()
    if not text:
        return []
    t = text.lower()
    matched_classes: Dict[str, Dict[str, Any]] = {}
    classes = _state.get("classes") or {}
    for kw, cls in _HEADING_TO_CLASS.items():
        if kw in t and cls in classes:
            matched_classes.setdefault(cls, classes[cls])
    return list(matched_classes.values())


def stats() -> Dict[str, Any]:
    _ensure_loaded()
    return {
        "loaded":  bool(_state["loaded"]),
        "classes": len(_state.get("classes") or {}),
        "error":   _state.get("error"),
    }
